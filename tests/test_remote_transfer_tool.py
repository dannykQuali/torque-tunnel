"""The remote-to-remote transfer tools, driven through the real MCP dispatch.

A fake TorqueClient keeps a small "world" of environments, each with scripted grain-log
frames (one more frame per log read) and statuses, on whichever Torque instance the
client was created for. That lets the tests check the ORDER of things (the receiver is
never launched before the sender is ready), which Torque each environment lands on,
and what the status/cancel tools do from the two ids alone.
"""

import itertools
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, mcp_tool, remote_transfer


ALPHA = "https://alpha.example.com"
BETA = "https://beta.example.com"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----"
MD5 = "0123456789abcdef0123456789abcdef"


def sender_ready_log(name="_croc_rl_0_image.vmdk", size=104857600, md5=MD5, is_dir=False):
    lines = []
    if is_dir:
        lines.append(f"{croc_manager.CROC_SENTINEL_DIR} {name}")
    lines += [f"{croc_manager.CROC_SENTINEL_SIZE} {size} {name}",
              f"{croc_manager.CROC_SENTINEL_MD5} {md5} {name}",
              croc_manager.CROC_SENTINEL_READY]
    return "\n".join(lines) + "\n"


class World:
    """Environments by id: url, space, start kwargs, log frames, status frames."""

    def __init__(self):
        self.envs = {}
        self.events = []            # ("start", role) / ("log", env_id) / ("end", env_id)...
        self.ids = (f"env-{n}" for n in itertools.count(1))
        self.next_logs = []         # log frames for the next started environments, in order
        self.next_statuses = []
        self.fail_start = set()     # roles ("send"/"receive"/"copy") whose start raises
        self.containers = {}        # env_id -> current_state of persistent containers
        self.env_errors = []        # Torque's state.errors messages, for every environment

    def start(self, url, space, kw):
        role = kw["command_description"].rsplit("(", 1)[-1].rstrip(")")
        self.events.append(("start", role))
        if role in self.fail_start:
            raise RuntimeError(f"cannot start {role}")
        env_id = next(self.ids)
        self.envs[env_id] = {
            "url": url, "space": space, "kw": kw, "role": role,
            "logs": self.next_logs.pop(0) if self.next_logs else [""],
            "statuses": self.next_statuses.pop(0) if self.next_statuses else ["Deploying"],
            "reads": 0, "ended": False,
        }
        return env_id

    def by_role(self, role):
        return [e for e in self.envs.values() if e["role"] == role]


WORLD = World()


class FakeTorque:
    def __init__(self, base_url=None, token=None, space=None, **kw):
        self.base_url, self.space = base_url, space

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def start_environment(self, **kw):
        return WORLD.start(self.base_url, self.space, kw)

    def _env(self, env_id):
        env = WORLD.envs.get(env_id)
        if env is None or env["url"] != self.base_url:
            import httpx
            raise httpx.HTTPStatusError("not found", request=httpx.Request("GET", "x"),
                                        response=httpx.Response(404))
        return env

    async def get_environment_status(self, env_id, retry=True):
        if env_id in WORLD.containers:
            return {"details": {"state": {"current_state": WORLD.containers[env_id]}}}
        env = self._env(env_id)
        frames = env["statuses"]
        status = "Ended" if env["ended"] else frames[min(env["reads"], len(frames) - 1)]
        errors = [{"message": m} for m in WORLD.env_errors] + [{"message": None}]
        return {"details": {"computed_status": status, "state": {"errors": errors}}}

    async def get_grain_log(self, env_id):
        env = self._env(env_id)
        WORLD.events.append(("log", env_id))
        frames = env["logs"]
        frame = frames[min(env["reads"], len(frames) - 1)]
        env["reads"] += 1
        return frame

    async def get_persistent_container_info(self, env_id):
        return {"container_ip": "172.17.0.9", "container_id": "c", "private_key": KEY}

    async def end_environment(self, env_id, force=False):
        WORLD.events.append(("end", env_id))
        self._env(env_id)["ended"] = True

    async def release_environment(self, env_id, force=False):
        WORLD.events.append(("release", env_id))
        self._env(env_id)["ended"] = True

    async def delete_environment(self, env_id):
        pass

    async def set_scheduled_end_time(self, env_id, end):
        WORLD.events.append(("extend", env_id))


@pytest.fixture(autouse=True)
def world(monkeypatch):
    global WORLD
    WORLD = World()
    monkeypatch.setattr(mcp_tool, "TorqueClient", FakeTorque)
    monkeypatch.setattr(mcp_tool, "TRANSFER_POLL_SECONDS", 0)
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {})
    monkeypatch.setattr(mcp_tool, "_persistent_containers", {})
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config,
        torque_url=ALPHA, torque_token="a-token", torque_space="SpaceA", default_agent="agent-a",
        default_ssh_key=None, default_ssh_password=None, default_target_ip=None,
        default_ssh_user=None, init_commands=None, finally_commands=None,
        auto_delete_environments=False, croc_relay=None, croc_relay_password=None,
        croc_transfers=None,
    ))
    monkeypatch.setattr(mcp_tool, "_loaded_config", {"profiles": {
        "alpha": {"torque_url": ALPHA, "torque_token": "a-token", "torque_space": "SpaceA",
                  "torque_agent": "agent-a"},
        "beta": {"torque_url": BETA, "torque_token": "b-token", "torque_space": "SpaceB",
                 "torque_agent": "agent-b"},
        "beta-relay": {"extends": "beta", "croc_relay": "relay.beta.example:9009"},
    }})
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    return WORLD


def _text(result):
    return "\n".join(getattr(c, "text", "") for c in (result or []))


def _ssh(host, profile=None, **extra):
    spec = {"type": "ssh", "host": host, "user": "root", "private_key": KEY, **extra}
    if profile:
        spec["profile"] = profile
    return spec


async def _transfer(source, destination, files=None, **extra):
    args = {"command_description": "copy image", "source": source, "destination": destination,
            "files": files or [{"source_path": "/data/image.vmdk", "destination_path": "/dst/image.vmdk"}],
            **extra}
    return _text(await mcp_tool.call_tool("transfer_files_between_tunneled_hosts_async", args))


async def _status(sender, receiver, **extra):
    args = {"sender_environment_id": sender, "receiver_environment_id": receiver, "wait": 0, **extra}
    return _text(await mcp_tool.call_tool("get_transfer_status", args))


# ============================================================================
# Starting a transfer
# ============================================================================

@pytest.mark.asyncio
async def test_the_receiver_is_launched_only_after_the_sender_is_ready():
    WORLD.next_logs = [["", "staging...", sender_ready_log()]]
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    sender_reads = [e for e in WORLD.events if e == ("log", "env-1")]
    receive_start = WORLD.events.index(("start", "receive"))
    assert len(sender_reads) == 3, WORLD.events
    assert WORLD.events.index(sender_reads[-1]) < receive_start
    assert 'sender_environment_id="env-1", receiver_environment_id="env-2"' in text, text


@pytest.mark.asyncio
async def test_the_receiver_carries_the_senders_manifest_and_relay():
    WORLD.next_logs = [[sender_ready_log(size=104857600, md5=MD5)]]
    await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    receiver = WORLD.by_role("receive")[0]["kw"]
    commands = receiver["container_pre_commands"]
    assert MD5 in commands and "104857600" in commands
    assert f"--relay {croc_manager.DEFAULT_CROC_RELAY}" in commands
    assert receiver["target_ip"] == "10.9.9.9"
    sender = WORLD.by_role("send")[0]["kw"]
    assert sender["target_ip"] == "10.0.0.1"
    assert "cat " in sender["download_commands"] and "/data/image.vmdk" in sender["download_commands"]


@pytest.mark.asyncio
async def test_a_directory_reported_by_the_sender_is_extracted_by_the_receiver():
    name = remote_transfer.croc_filename(0, "/etc/app/")
    WORLD.next_logs = [[sender_ready_log(name=name, is_dir=True)]]
    await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"),
                    files=[{"source_path": "/etc/app/", "destination_path": "/opt/app"}])

    assert "tar xzf - -C" in WORLD.by_role("receive")[0]["kw"]["container_pre_commands"]


@pytest.mark.asyncio
async def test_each_side_runs_on_its_own_profiles_torque():
    WORLD.next_logs = [[sender_ready_log()]]
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    assert WORLD.by_role("send")[0]["url"] == ALPHA
    assert WORLD.by_role("receive")[0]["url"] == BETA
    assert WORLD.by_role("receive")[0]["kw"]["agent"] == "agent-b"
    assert 'sender_profile="alpha"' in text and 'receiver_profile="beta"' in text


@pytest.mark.asyncio
async def test_a_sender_failure_before_ready_ends_it_and_launches_nothing_else():
    WORLD.next_logs = [["", f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=stage reason=could not read /data/image.vmdk on the source"]]
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    assert "could not read /data/image.vmdk" in text
    assert ("start", "receive") not in WORLD.events
    assert WORLD.envs["env-1"]["ended"]


@pytest.mark.asyncio
async def test_a_sender_environment_ending_without_ready_is_a_failure():
    WORLD.next_logs = [["", "ssh: connect to host 10.0.0.1 port 22: No route to host"]]
    WORLD.next_statuses = [["Deploying", "Active"]]
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    assert "before its croc sender was ready" in text
    assert "No route to host" in text
    assert ("start", "receive") not in WORLD.events


@pytest.mark.asyncio
async def test_torques_own_error_is_reported_when_the_sender_never_ran():
    """Seen live: 'runner is in error state' - the grain never started, the log is
    empty, and only the environment's errors say why."""
    WORLD.next_logs = [[None]]
    WORLD.next_statuses = [["Active With Error"]]
    WORLD.env_errors = ["operation shell-grain-deploy failed since runner is in error state"]
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    assert "runner is in error state" in text, text
    assert ("start", "receive") not in WORLD.events


@pytest.mark.asyncio
async def test_torques_own_error_is_reported_when_the_receiver_never_ran():
    s, r = await _started_pair([""], ["Deploying"], [None], ["Active With Error"])
    WORLD.env_errors = ["operation shell-grain-deploy failed since runner is in error state"]
    WORLD.envs[r]["logs"] = [""]
    text = await _status(s, r)

    assert "**Status:** FAILED" in text
    assert "runner is in error state" in text, text
    assert WORLD.envs[s]["ended"]


@pytest.mark.asyncio
async def test_waiting_for_the_sender_is_bounded(monkeypatch):
    monkeypatch.setattr(mcp_tool, "TRANSFER_STAGE_TIMEOUT_SECONDS", 0)
    WORLD.next_logs = [["still staging"]]
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    assert "timed out" in text
    assert WORLD.envs["env-1"]["ended"]
    assert ("start", "receive") not in WORLD.events


@pytest.mark.asyncio
async def test_an_abandoned_call_ends_the_sender(monkeypatch):
    import asyncio
    WORLD.next_logs = [["still staging"]]
    real_sleep = asyncio.sleep
    monkeypatch.setattr(mcp_tool, "TRANSFER_POLL_SECONDS", 0.01)

    task = asyncio.ensure_future(_transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta")))
    while not WORLD.envs:
        await real_sleep(0.01)
    await real_sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert WORLD.envs["env-1"]["ended"]
    assert ("start", "receive") not in WORLD.events


@pytest.mark.asyncio
async def test_a_receiver_that_cannot_start_ends_the_sender():
    WORLD.next_logs = [[sender_ready_log()]]
    WORLD.fail_start = {"receive"}
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))

    assert "Error starting the receiving environment" in text
    assert WORLD.envs["env-1"]["ended"]


@pytest.mark.asyncio
async def test_different_relays_use_the_sources_on_both_sides():
    WORLD.next_logs = [[sender_ready_log()]]
    text = await _transfer(_ssh("10.0.0.1", "beta-relay"), _ssh("10.9.9.9", "alpha"))

    assert "--relay relay.beta.example:9009" in WORLD.by_role("send")[0]["kw"]["download_commands"]
    assert "--relay relay.beta.example:9009" in WORLD.by_role("receive")[0]["kw"]["container_pre_commands"]
    assert "different croc relays" in text


@pytest.mark.asyncio
async def test_endpoints_behind_the_same_agent_copy_directly_in_one_environment():
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.0.0.2", "alpha"))

    assert [e for e in WORLD.events if e[0] == "start"] == [("start", "copy")]
    commands = WORLD.by_role("copy")[0]["kw"]["container_pre_commands"]
    assert "direct copy" in commands and "croc" not in commands.replace("croc_rl", "")
    assert 'sender_environment_id="env-1", receiver_environment_id="env-1"' in text


@pytest.mark.asyncio
async def test_the_same_machine_twice_is_refused():
    text = await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.0.0.1", "alpha"))
    assert "same machine" in text
    assert WORLD.envs == {}


@pytest.mark.asyncio
async def test_a_persistent_container_that_is_gone_is_an_error_not_a_new_container():
    WORLD.containers["pc-1"] = "ended"
    text = await _transfer({"type": "persistent_container", "environment_id": "pc-1", "profile": "alpha"},
                           _ssh("10.9.9.9", "beta"))
    assert "not running" in text
    assert WORLD.envs == {}


@pytest.mark.asyncio
async def test_a_running_persistent_container_is_a_valid_source():
    WORLD.containers["pc-1"] = "deploying"
    WORLD.next_logs = [[sender_ready_log()]]
    await _transfer({"type": "persistent_container", "environment_id": "pc-1", "profile": "alpha"},
                    _ssh("10.9.9.9", "beta"))

    sender = WORLD.by_role("send")[0]["kw"]
    assert sender["target_ip"] == "172.17.0.9" and sender["parent_env_id"] == "pc-1"


@pytest.mark.parametrize("files,expected", [
    ([], "non-empty"),
    ([{"destination_path": "/x"}], "source_path"),
    ([{"source_path": "/x"}], "destination_path"),
    ([{"source_path": "/x", "destination_path": "/y", "mode": "rwx"}], "invalid mode"),
])
@pytest.mark.asyncio
async def test_bad_file_specs_are_rejected_before_anything_starts(files, expected):
    args = {"command_description": "x", "source": _ssh("10.0.0.1", "alpha"),
            "destination": _ssh("10.9.9.9", "beta"), "files": files}
    text = _text(await mcp_tool.call_tool("transfer_files_between_tunneled_hosts_async", args))
    assert expected in text
    assert WORLD.envs == {}


@pytest.mark.asyncio
async def test_an_unknown_endpoint_profile_is_an_error():
    text = await _transfer(_ssh("10.0.0.1", "nope"), _ssh("10.9.9.9", "beta"))
    assert "nope" in text
    assert WORLD.envs == {}


# ============================================================================
# Status and cancel, from the two ids
# ============================================================================

async def _started_pair(sender_logs, sender_statuses, receiver_logs, receiver_statuses):
    """Start a transfer whose environments then play the given frames."""
    WORLD.next_logs = [[sender_ready_log()] + sender_logs, receiver_logs]
    WORLD.next_statuses = [["Deploying"] + sender_statuses, receiver_statuses]
    await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.9.9.9", "beta"))
    return "env-1", "env-2"


@pytest.mark.asyncio
async def test_still_running_while_the_receiver_works_even_after_the_sender_finished():
    s, r = await _started_pair([sender_ready_log() + croc_manager.CROC_SENTINEL_DONE + " exit_code=0"],
                               ["Active"], ["[croc receive] x  42% |##  |"], ["Deploying"])
    text = await _status(s, r)

    assert "**Status:** RUNNING" in text
    assert "42%" in text
    assert not WORLD.envs[s]["ended"] and not WORLD.envs[r]["ended"]
    assert 'sender_profile="alpha"' in text


@pytest.mark.asyncio
async def test_completed_when_the_receiver_has_placed_everything_and_then_both_are_ended():
    done = f"{croc_manager.CROC_RX_SENTINEL_PLACED} /dst/image.vmdk\n{croc_manager.CROC_RX_SENTINEL_DONE}\n"
    s, r = await _started_pair([croc_manager.CROC_SENTINEL_DONE], ["Active"], [done], ["Active"])
    text = await _status(s, r)

    assert "**Status:** COMPLETED" in text
    assert "/dst/image.vmdk" in text
    assert WORLD.envs[s]["ended"] and WORLD.envs[r]["ended"]


@pytest.mark.asyncio
async def test_not_completed_while_the_receiving_environment_is_still_finishing():
    done = f"{croc_manager.CROC_RX_SENTINEL_DONE}\n"
    s, r = await _started_pair([croc_manager.CROC_SENTINEL_DONE], ["Active"], [done], ["Deploying"])
    text = await _status(s, r)
    assert "**Status:** RUNNING" in text
    assert not WORLD.envs[r]["ended"]


@pytest.mark.asyncio
async def test_a_receiver_failure_is_reported_and_ends_the_sender():
    failed = f"{croc_manager.CROC_RX_SENTINEL_FAILED} exit_code=1 reason=croc file receive failed: x is corrupt"
    s, r = await _started_pair([""], ["Deploying"], [failed], ["Active"])
    text = await _status(s, r)

    assert "**Status:** FAILED" in text and "corrupt" in text
    assert WORLD.envs[s]["ended"]


@pytest.mark.asyncio
async def test_a_sender_failure_after_launch_ends_the_receiver():
    failed = f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=1 reason=could not connect to : could not connect"
    s, r = await _started_pair([failed], ["Active"], ["[croc receive] waiting for data (30s)"], ["Deploying"])
    text = await _status(s, r)

    assert "**Status:** FAILED" in text
    assert "500 ms" in text     # the plain-words explanation of the blank relay
    assert WORLD.envs[r]["ended"]


@pytest.mark.asyncio
async def test_a_receiver_that_ended_silently_is_a_failure():
    s, r = await _started_pair([""], ["Deploying"], ["something else"], ["Active"])
    text = await _status(s, r)
    assert "**Status:** FAILED" in text and "without reporting a result" in text
    assert WORLD.envs[s]["ended"]


@pytest.mark.asyncio
async def test_status_works_from_the_ids_and_profiles_alone():
    """No in-memory state (e.g. after an MCP server restart)."""
    done = f"{croc_manager.CROC_RX_SENTINEL_DONE}\n"
    s, r = await _started_pair([croc_manager.CROC_SENTINEL_DONE], ["Active"], [done], ["Active"])
    mcp_tool._async_env_connections.clear()

    text = await _status(s, r, sender_profile="alpha", receiver_profile="beta")
    assert "**Status:** COMPLETED" in text


@pytest.mark.asyncio
async def test_without_memory_or_profiles_the_other_torque_is_not_found():
    s, r = await _started_pair([""], ["Deploying"], [""], ["Deploying"])
    mcp_tool._async_env_connections.clear()
    text = await _status(s, r)
    assert "not found" in text


@pytest.mark.asyncio
async def test_an_unreadable_log_is_not_a_failure(monkeypatch):
    s, r = await _started_pair([""], ["Deploying"], [None], ["Active"])
    text = await _status(s, r)
    assert "**Status:** RUNNING" in text
    assert not WORLD.envs[s]["ended"]


@pytest.mark.asyncio
async def test_a_direct_copy_is_read_from_its_one_environment():
    WORLD.next_logs = [[f"{croc_manager.CROC_RX_SENTINEL_DONE}\n"]]
    WORLD.next_statuses = [["Active"]]
    await _transfer(_ssh("10.0.0.1", "alpha"), _ssh("10.0.0.2", "alpha"))
    text = await _status("env-1", "env-1")
    assert "**Status:** COMPLETED" in text
    assert WORLD.envs["env-1"]["ended"]


@pytest.mark.asyncio
async def test_cancel_ends_both_environments_on_their_own_torques():
    s, r = await _started_pair([""], ["Deploying"], [""], ["Deploying"])
    text = _text(await mcp_tool.call_tool("cancel_transfer",
                                          {"sender_environment_id": s, "receiver_environment_id": r}))
    assert WORLD.envs[s]["ended"] and WORLD.envs[r]["ended"]
    assert "Sender" in text and "Receiver" in text


@pytest.mark.asyncio
async def test_cancel_tolerates_an_environment_that_already_ended():
    s, r = await _started_pair([croc_manager.CROC_SENTINEL_DONE], ["Ended"], [""], ["Deploying"])
    text = _text(await mcp_tool.call_tool("cancel_transfer",
                                          {"sender_environment_id": s, "receiver_environment_id": r}))
    assert "already ended" in text
    assert WORLD.envs[r]["ended"]


@pytest.mark.asyncio
async def test_the_three_transfer_tools_are_listed():
    names = {t.name for t in await mcp_tool.list_tools()}
    assert {"transfer_files_between_tunneled_hosts_async", "get_transfer_status", "cancel_transfer"} <= names


# ============================================================================
# CLI: torque-tunnel transfer
# ============================================================================

def _cli_args(*argv):
    return mcp_tool.build_parser().parse_args(["transfer", *argv])


def test_the_cli_parses_both_endpoints_and_files():
    args = _cli_args("--from-host", "10.0.0.1", "--from-user", "root", "--from-key", "k.pem",
                     "--from-profile", "alpha", "--to-persistent-container", "pc-1",
                     "--to-profile", "beta", "--file", "/a:/b", "--file", "/c:/d:644", "--json")
    assert mcp_tool._cli_transfer_endpoint(args, "from") == {
        "type": "ssh", "host": "10.0.0.1", "user": "root", "private_key": "k.pem", "profile": "alpha"}
    assert mcp_tool._cli_transfer_endpoint(args, "to") == {
        "type": "persistent_container", "environment_id": "pc-1", "profile": "beta"}
    assert mcp_tool._parse_transfer_files(args.file) == [
        {"source_path": "/a", "destination_path": "/b"},
        {"source_path": "/c", "destination_path": "/d", "mode": "644"}]


@pytest.mark.parametrize("spec", ["/only-one", "/a:/b:/c", ":/b", "/a:"])
def test_the_cli_rejects_a_malformed_file_spec(spec):
    with pytest.raises(ValueError):
        mcp_tool._parse_transfer_files([spec])


def _run_cli(capsys, *argv):
    import asyncio
    with pytest.raises(SystemExit) as exit_info:
        asyncio.run(mcp_tool.cli_dispatch(_cli_args(*argv)))
    return exit_info.value.code, capsys.readouterr()


def test_the_cli_follows_the_transfer_to_completion(capsys):
    done = f"{croc_manager.CROC_RX_SENTINEL_PLACED} /dst/image.vmdk\n{croc_manager.CROC_RX_SENTINEL_DONE}\n"
    WORLD.next_logs = [[sender_ready_log()], ["[croc receive] x  50% |##  |", done]]
    WORLD.next_statuses = [["Deploying"], ["Deploying", "Active"]]
    code, out = _run_cli(capsys, "--from-host", "10.0.0.1", "--from-user", "root", "--from-key", KEY,
                         "--from-profile", "alpha", "--to-host", "10.9.9.9", "--to-user", "root",
                         "--to-key", KEY, "--to-profile", "beta",
                         "--file", "/data/image.vmdk:/dst/image.vmdk", "--json")

    assert code == 0, out.err
    import json
    result = json.loads(out.out)
    assert result["status"] == "COMPLETED" and result["path"] == "croc"
    assert result["placed"] == ["/dst/image.vmdk"]
    assert WORLD.envs["env-1"]["ended"] and WORLD.envs["env-2"]["ended"]


def test_the_cli_exits_non_zero_when_the_transfer_fails(capsys):
    failed = f"{croc_manager.CROC_RX_SENTINEL_FAILED} exit_code=1 reason=croc file receive failed: corrupt"
    WORLD.next_logs = [[sender_ready_log()], [failed]]
    WORLD.next_statuses = [["Deploying"], ["Active"]]
    code, out = _run_cli(capsys, "--from-host", "10.0.0.1", "--from-user", "root", "--from-key", KEY,
                         "--from-profile", "alpha", "--to-host", "10.9.9.9", "--to-user", "root",
                         "--to-key", KEY, "--to-profile", "beta", "--file", "/data/image.vmdk:/b")

    assert code == 1
    assert "TRANSFER FAILED" in out.err and "corrupt" in out.err


# ============================================================================
# Log parsing
# ============================================================================

def test_ready_means_the_latest_registration_was_not_followed_by_a_retry():
    R, T = croc_manager.CROC_SENTINEL_READY, croc_manager.CROC_SENTINEL_RETRY
    assert remote_transfer.parse_sender_log(f"{R}\n").ready
    assert not remote_transfer.parse_sender_log(f"{R}\n{T} (retrying)\n").ready
    assert remote_transfer.parse_sender_log(f"{R}\n{T} (retrying)\n{R}\n").ready


def test_a_sentinel_inside_a_shown_command_is_ignored():
    log = f'  echo "{croc_manager.CROC_RX_SENTINEL_DONE}"\n'
    assert not remote_transfer.parse_receiver_log(log).done
    assert remote_transfer.parse_receiver_log(f"[12:00:00.000] {croc_manager.CROC_RX_SENTINEL_DONE}\n").done


def test_the_manifest_needs_a_size_for_every_file():
    report = remote_transfer.parse_sender_log(sender_ready_log(name="_croc_rl_0_a"))
    files = [{"source_path": "/a", "destination_path": "/x/a", "croc_filename": "_croc_rl_0_a"},
             {"source_path": "/b", "destination_path": "/x/b", "croc_filename": "_croc_rl_1_b"}]
    manifest, errors = remote_transfer.build_manifest(files, report)
    assert [m["croc_filename"] for m in manifest] == ["_croc_rl_0_a"]
    assert errors and "/b" in errors[0]
