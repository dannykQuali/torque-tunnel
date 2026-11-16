"""Transfers must not leave their temp folders behind.

Reported 2026-11-16 from wt-agent-dannyk (the worktogether broker's VM): 50
torque_croc_* staging folders (2.2 GB) and 50 croc send logs in /tmp, every one from an
async run. Three causes, each covered here:

1. An async run's local side was cleaned up only when someone polled it to its end
   (get_execution_status) or cancelled it. A caller that moved on, or a restart of the
   MCP server, left it all behind. Now the background streamer finishes the run when it
   sees it end, and a sweep removes what a dead process left (torque_tunnel.leftovers).
2. Early returns skipped the clean-up: a failed download preparation came after the
   upload was staged but before the try/finally; the async tools' own early returns sat
   in a try without a finally; an archive that could not be built returned without
   removing the folder.
3. A cancelled request's clean-up stopped at its first await (anyio's cancellation is
   level-triggered), before deleting anything.

Plus: croc's send log held the transfer's code in plain text.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time

import anyio
import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import croc_manager, leftovers, mcp_tool

# asyncio.sleep before the `torque` fixture shortens every sleep
_REAL_SLEEP = asyncio.sleep
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dead_pid():
    """The PID of a process that has exited."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


def _sleeper():
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


def _make_dir(parent, name, owners=None, age_seconds=0.0):
    path = os.path.join(str(parent), name)
    os.makedirs(path)
    with open(os.path.join(path, "_croc_0_payload.bin"), "wb") as f:
        f.write(b"x" * 100)
    if owners is not None:
        with open(os.path.join(path, leftovers.OWNER_FILE), "w") as f:
            json.dump({"processes": owners}, f)
    if age_seconds:
        old = time.time() - age_seconds
        os.utime(path, (old, old))
    return path


def _transfer_dirs(parent):
    return sorted(n for n in os.listdir(str(parent)) if n.startswith(leftovers.DIR_PREFIXES))


async def _drain_detached():
    """Wait for clean-ups that run on in their own task."""
    for _ in range(200):
        pending = [t for t in getattr(mcp_tool, "_detached_cleanups", ()) if not t.done()]
        if not pending:
            return
        await asyncio.wait(pending, timeout=5)


class FakeCrocProcess:
    """What start_croc_send returns: a live croc that exits shortly after it is
    terminated, as a real one does (so a clean-up has to wait for it)."""

    EXIT_SECONDS = 0.1

    def __init__(self, pid=4242):
        self.pid = pid
        self.returncode = None
        self.terminated = False
        self._exit_at = None

    def terminate(self):
        self.terminated = True
        if self._exit_at is None:
            self._exit_at = time.monotonic() + self.EXIT_SECONDS

    def kill(self):
        self.terminate()

    async def wait(self):
        while self.returncode is None:
            if self._exit_at is not None and time.monotonic() >= self._exit_at:
                self.returncode = -15
                break
            await asyncio.sleep(0.01)
        return self.returncode


# ---------------------------------------------------------------------------
# leftovers: whose folder is it, and is anyone still using it?
# ---------------------------------------------------------------------------

def test_this_process_is_seen_running():
    assert leftovers.process_started(os.getpid())


def test_an_exited_process_is_not():
    assert leftovers.process_started(_dead_pid()) is None


@pytest.mark.parametrize("pid", [None, 0, -5, "123", True, 1.5])
def test_something_that_is_not_a_pid_is_not_running(pid):
    assert leftovers.process_started(pid) is None


def test_a_folder_claimed_by_this_process_is_kept(tmp_path):
    path = _make_dir(tmp_path, "torque_croc_live")
    leftovers.claim(path)
    assert not leftovers.is_stale(path)
    assert leftovers.sweep(str(tmp_path)) == []
    assert os.path.isdir(path)


def test_a_folder_whose_owner_died_is_removed(tmp_path):
    path = _make_dir(tmp_path, "torque_croc_dead", owners=[[_dead_pid(), "1"]])
    assert leftovers.sweep(str(tmp_path)) == [path]
    assert not os.path.exists(path)


def test_a_download_folder_whose_owner_died_is_removed_too(tmp_path):
    path = _make_dir(tmp_path, "torque_dl_dead", owners=[[_dead_pid(), "1"]])
    assert leftovers.sweep(str(tmp_path)) == [path]


def test_a_croc_that_outlived_its_owner_keeps_the_folder_until_it_exits(tmp_path):
    """A restarted MCP server's croc sender still completes its upload: its folder
    must stay while it runs, and go once it is done."""
    croc = _sleeper()
    try:
        path = _make_dir(tmp_path, "torque_croc_orphan", owners=[
            [_dead_pid(), "1"], [croc.pid, leftovers.process_started(croc.pid)]])
        assert leftovers.sweep(str(tmp_path)) == []
        assert os.path.isdir(path)
    finally:
        croc.kill()
        croc.wait()
    assert leftovers.sweep(str(tmp_path)) == [path]


def test_a_reused_pid_is_not_the_owner(tmp_path):
    """Same PID, other start time: another process got the PID."""
    path = _make_dir(tmp_path, "torque_croc_reused", owners=[[os.getpid(), "not-its-start-time"]])
    assert leftovers.sweep(str(tmp_path)) == [path]


def test_a_folder_from_before_owner_files_goes_only_after_a_day(tmp_path):
    young = _make_dir(tmp_path, "torque_croc_young", age_seconds=3600)
    old = _make_dir(tmp_path, "torque_croc_old", age_seconds=2 * 86400)
    assert leftovers.sweep(str(tmp_path)) == [old]
    assert os.path.isdir(young)


def test_old_croc_send_logs_and_piping_archives_go_after_a_day(tmp_path):
    names = ["torque_croc_send_old.log", "torque_croc_send_new.log", "tt_piping_old.enc"]
    for name in names:
        (tmp_path / name).write_text("x")
    old = time.time() - 2 * 86400
    for name in ("torque_croc_send_old.log", "tt_piping_old.enc"):
        os.utime(tmp_path / name, (old, old))
    removed = leftovers.sweep(str(tmp_path))
    assert sorted(os.path.basename(p) for p in removed) == ["torque_croc_send_old.log", "tt_piping_old.enc"]
    assert (tmp_path / "torque_croc_send_new.log").exists()


def test_nothing_else_in_the_temp_dir_is_touched(tmp_path):
    other_dir = _make_dir(tmp_path, "someone_elses_dir", owners=[[_dead_pid(), "1"]], age_seconds=9 * 86400)
    other_file = tmp_path / "torque_croc_notes.txt"
    other_file.write_text("x")
    old = time.time() - 9 * 86400
    os.utime(other_file, (old, old))
    link_target = _make_dir(tmp_path, "target", age_seconds=9 * 86400)
    try:
        os.symlink(link_target, str(tmp_path / "torque_croc_link"), target_is_directory=True)
    except (OSError, NotImplementedError):
        pass
    assert leftovers.sweep(str(tmp_path)) == []
    assert os.path.isdir(other_dir) and other_file.exists() and os.path.isdir(link_target)


def test_a_missing_temp_dir_is_not_an_error(tmp_path):
    assert leftovers.sweep(str(tmp_path / "nope")) == []


# ---------------------------------------------------------------------------
# The folders are claimed, and the croc processes recorded, as they are made
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    """The system temp dir, for the code under test: a fresh one per test."""
    root = tmp_path / "systemp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def _big_file(tmp_path, name="big.bin"):
    path = tmp_path / name
    path.write_bytes(os.urandom(500_000))   # incompressible: above the inline budget
    return str(path)


def _upload_spec(tmp_path):
    return [{"local_source_path": _big_file(tmp_path), "remote_destination_path": "/tmp/big.bin"}]


def _download_spec(tmp_path):
    return [{"remote_source_path": "/etc/hostname", "local_destination_path": str(tmp_path / "out" / "hostname")}]


def test_a_staging_folder_is_claimed_when_made(tmp_path, temp_root):
    plan = mcp_tool.prepare_files_with_croc(_upload_spec(tmp_path), transfer_mode="container")
    try:
        assert plan.croc_staging_dir.startswith(str(temp_root))
        assert not leftovers.is_stale(plan.croc_staging_dir, legacy_age=0)
    finally:
        asyncio.run(mcp_tool.cleanup_croc_resources(None, plan.croc_staging_dir))


def test_a_receive_folder_is_claimed_when_made(tmp_path, temp_root):
    plan = mcp_tool.prepare_download_with_croc(_download_spec(tmp_path), transfer_mode="container")
    try:
        assert plan.croc_receive_dir.startswith(str(temp_root))
        assert not leftovers.is_stale(plan.croc_receive_dir, legacy_age=0)
    finally:
        asyncio.run(mcp_tool.cleanup_download_resources(None, plan.croc_receive_dir))


def test_the_owner_file_is_not_uploaded(tmp_path, temp_root, monkeypatch):
    """The Piping Server archive is a tar of the staging folder: this machine's
    bookkeeping must not travel with the files."""
    monkeypatch.setattr(mcp_tool, "_local_transports", lambda settings: (["croc", "piping"], []))
    plan = mcp_tool.prepare_files_with_croc(_upload_spec(tmp_path), transfer_mode="container")
    try:
        assert os.path.exists(os.path.join(plan.croc_staging_dir, leftovers.OWNER_FILE))
        out = tmp_path / "unpacked"
        out.mkdir()
        mcp_tool.piping.extract_archive(plan.piping_archive_path, str(out), plan.croc_code, plan.piping_archive[1])
        assert sorted(os.listdir(str(out))) == ["_croc_0_big.bin"]
    finally:
        asyncio.run(mcp_tool.cleanup_croc_resources(None, plan.croc_staging_dir))


def test_the_croc_sender_is_recorded_so_its_folder_outlives_this_process(tmp_path, temp_root, monkeypatch):
    croc = _sleeper()
    try:
        async def fake_ensure():
            return "croc"

        async def fake_start(**kw):
            return FakeCrocProcess(pid=croc.pid)

        monkeypatch.setattr(croc_manager, "ensure_local_croc", fake_ensure)
        monkeypatch.setattr(croc_manager, "start_croc_send", fake_start)
        plan = mcp_tool.prepare_files_with_croc(_upload_spec(tmp_path), transfer_mode="container")
        asyncio.run(mcp_tool.execute_with_croc(plan))
        # This process is gone (as after a restart): its croc still holds the folder
        monkeypatch.setattr(leftovers, "process_started",
                            lambda pid, real=leftovers.process_started: None if pid == os.getpid() else real(pid))
        assert not leftovers.is_stale(plan.croc_staging_dir)
    finally:
        croc.kill()
        croc.wait()
    assert leftovers.is_stale(plan.croc_staging_dir)


# ---------------------------------------------------------------------------
# 1. An async run is finished when it ends, polled or not
# ---------------------------------------------------------------------------

class FakeTorque:
    status = "active"
    exit_code = "0"
    grain_log = ""
    missing = False
    start_forever = False

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_environment_status(self, env_id):
        if FakeTorque.missing:
            raise httpx.HTTPStatusError("nf", request=httpx.Request("GET", "x"), response=httpx.Response(404))
        return {"details": {"computed_status": FakeTorque.status}}

    async def get_grain_log(self, env_id):
        return FakeTorque.grain_log

    def _extract_outputs(self, env_data):
        return {"command_output": "", "exit_code": FakeTorque.exit_code}

    async def _start(self):
        if FakeTorque.start_forever:
            await _REAL_SLEEP(3600)
        return "env-1"

    async def start_environment(self, **kw):
        return await self._start()

    async def start_local_environment(self, **kw):
        return await self._start()

    async def execute_remote_command(self, **kw):
        await self._start()
        raise AssertionError("the test never lets a blocking command finish")

    async def execute_local_command(self, **kw):
        await self._start()
        raise AssertionError("the test never lets a blocking command finish")

    async def set_scheduled_end_time(self, *a, **kw):
        pass

    async def end_environment(self, env_id, force=False):
        pass

    async def release_environment(self, env_id, force=False):
        pass

    async def delete_environment(self, env_id):
        pass

    async def fetch_credentials(self):
        return []


@pytest.fixture
def torque(monkeypatch):
    FakeTorque.status, FakeTorque.exit_code, FakeTorque.grain_log = "active", "0", ""
    FakeTorque.missing = FakeTorque.start_forever = False
    monkeypatch.setattr(mcp_tool, "TorqueClient", FakeTorque)
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config, torque_url="https://t.example", torque_token="t", torque_space="S",
        default_agent="agent", default_ssh_key=None, default_ssh_password=None,
        default_target_ip=None, default_ssh_user=None, init_commands=None,
        finally_commands=None, auto_delete_environments=False))
    monkeypatch.setattr(mcp_tool, "_loaded_config", {"profiles": {}})
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {})
    monkeypatch.setattr(mcp_tool, "_streamer_cache", {})
    monkeypatch.setattr(mcp_tool, "_croc_async_state", {})
    monkeypatch.setattr(mcp_tool, "_download_results", {})
    real_sleep = asyncio.sleep

    async def quick_sleep(seconds):
        await real_sleep(min(seconds, 0.01))

    monkeypatch.setattr(mcp_tool.asyncio, "sleep", quick_sleep)
    return FakeTorque


async def _run_streamer(env_id="env-1"):
    mcp_tool._start_background_streamer(env_id)
    task = mcp_tool._background_streamers.get(env_id)
    assert task is not None
    await asyncio.wait_for(task, timeout=30)
    await _finished(env_id)


async def _finished(env_id):
    for _ in range(3000):
        if env_id not in getattr(mcp_tool, "_async_finish_tasks", {}):
            return
        await asyncio.sleep(0.01)


def _status(env_id="env-1"):
    return mcp_tool.handle_get_execution_status({"environment_id": env_id, "wait": 0})


@pytest.mark.asyncio
async def test_an_async_upload_is_cleaned_up_when_it_ends_without_a_poll(tmp_path, torque):
    staging = _make_dir(tmp_path, "torque_croc_async")
    croc = FakeCrocProcess()
    mcp_tool._croc_async_state["env-1"] = {"process": croc, "upload": True, "staging_dir": staging}

    await _run_streamer()

    assert not os.path.exists(staging)
    assert croc.terminated
    assert "env-1" not in mcp_tool._croc_async_state


@pytest.mark.asyncio
async def test_a_later_poll_still_reports_the_upload_failure(tmp_path, torque):
    staging = _make_dir(tmp_path, "torque_croc_failed")
    log = os.path.join(staging, "croc.log")
    with open(log, "w") as f:
        f.write("could not connect to relay: dial tcp: i/o timeout\n")
    croc = FakeCrocProcess()
    croc.returncode, croc.croc_log_path, croc.croc_secret = 1, log, "code"
    mcp_tool._croc_async_state["env-1"] = {"process": croc, "upload": True, "staging_dir": staging}
    torque.exit_code = "1"

    await _run_streamer()
    text = (await _status())[0].text

    assert "- UPLOAD FAILED: this machine's croc send failed (exit code 1)" in text, text
    assert "i/o timeout" in text


@pytest.mark.asyncio
async def test_an_async_download_is_placed_when_it_ends_without_a_poll(tmp_path, torque):
    receive = _make_dir(tmp_path, "torque_dl_async")
    with open(os.path.join(receive, "_croc_dl_0_hostname"), "w") as f:
        f.write("agent-host\n")
    dest = tmp_path / "out" / "hostname"
    plan = mcp_tool.DownloadPlan(croc_receive_dir=receive, needs_download=True,
                                 file_mappings=[{"croc_filename": "_croc_dl_0_hostname",
                                                 "local_destination_path": str(dest)}])
    plan.send_ready_seen = plan.send_done_seen = True
    mcp_tool._croc_async_state["env-1"] = {"dl_process": None, "dl_plan": plan}

    await _run_streamer()

    assert dest.read_text() == "agent-host\n"
    assert not os.path.exists(receive)
    text = (await _status())[0].text
    assert f"Downloaded: {dest}" in text, text


@pytest.mark.asyncio
async def test_a_deleted_environment_is_finished_too(tmp_path, torque):
    """Someone deleted it: the streamer used to poll its 404 forever."""
    staging = _make_dir(tmp_path, "torque_croc_gone")
    mcp_tool._croc_async_state["env-1"] = {"process": None, "upload": True, "staging_dir": staging}
    torque.missing = True

    await _run_streamer()

    assert not os.path.exists(staging)


@pytest.mark.asyncio
async def test_a_poll_racing_the_streamer_reports_once_and_cleans_up_once(tmp_path, torque):
    staging = _make_dir(tmp_path, "torque_croc_race")
    croc = FakeCrocProcess()
    mcp_tool._croc_async_state["env-1"] = {"process": croc, "upload": True, "staging_dir": staging}
    mcp_tool._start_background_streamer("env-1")

    results = await asyncio.gather(*(_status() for _ in range(3)))

    await _finished("env-1")
    assert all("COMPLETED" in r[0].text for r in results), [r[0].text for r in results]
    assert not os.path.exists(staging) and croc.terminated


# ---------------------------------------------------------------------------
# 2. Every early exit of every tool cleans up what it made
# ---------------------------------------------------------------------------

UPLOAD_TOOLS = [
    ("run_on_tunneled_ssh", {"host": "10.0.0.1", "user": "root", "private_key": KEY}),
    ("run_on_tunneled_disposable_container", {}),
    ("run_on_tunneled_persistent_container", {}),
    ("run_on_tunneled_ssh_async", {"host": "10.0.0.1", "user": "root", "private_key": KEY}),
    ("run_on_tunneled_disposable_container_async", {}),
    ("run_on_tunneled_persistent_container_async", {}),
]


@pytest.fixture
def tools(torque, temp_root, monkeypatch):
    async def fake_container(**kw):
        return {"container_ip": "172.17.0.5", "private_key": KEY, "environment_id": "container-env",
                "container_id": "abc", "agent": "agent"}

    started = []

    async def fake_send(plan):
        mcp_tool.leftovers.add_process(plan.croc_staging_dir, os.getpid())
        proc = FakeCrocProcess()
        started.append(proc)
        return proc

    monkeypatch.setattr(mcp_tool, "_ensure_persistent_container", fake_container)
    monkeypatch.setattr(mcp_tool, "execute_with_croc", fake_send)

    async def call(tool, extra, **arguments):
        args = dict(extra, command="echo hi", command_description="test", **arguments)
        return "\n".join(c.text for c in await mcp_tool.call_tool(tool, args))

    call.started = started
    return call


def _no_transfer_dirs_left(temp_root):
    left = _transfer_dirs(temp_root)
    assert left == [], f"left behind: {left}"


@pytest.mark.parametrize("tool,extra", UPLOAD_TOOLS)
@pytest.mark.asyncio
async def test_a_failed_download_preparation_removes_the_staged_upload(tool, extra, tools, temp_root, tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_tool, "prepare_download_with_croc",
                        lambda *a, **kw: mcp_tool.DownloadPlan(errors=["no transport"]))
    text = await tools(tool, extra, upload_files=_upload_spec(tmp_path), download_files=_download_spec(tmp_path))
    await _drain_detached()
    assert "Error preparing downloads" in text, text
    _no_transfer_dirs_left(temp_root)


@pytest.mark.parametrize("tool,extra", UPLOAD_TOOLS)
@pytest.mark.asyncio
async def test_a_receiver_that_fails_to_start_stops_the_sender_and_removes_both_folders(
        tool, extra, tools, temp_root, tmp_path, monkeypatch):
    async def failing_receive(*a, **kw):
        raise RuntimeError("croc receive would not start")

    monkeypatch.setattr(mcp_tool, "execute_download_receive", failing_receive)
    text = await tools(tool, extra, upload_files=_upload_spec(tmp_path), download_files=_download_spec(tmp_path))
    await _drain_detached()
    assert "would not start" in text, text
    assert tools.started and all(p.terminated for p in tools.started)
    _no_transfer_dirs_left(temp_root)


@pytest.mark.parametrize("tool,extra", UPLOAD_TOOLS)
@pytest.mark.asyncio
async def test_a_sender_that_fails_to_start_removes_the_staged_upload(tool, extra, tools, temp_root, tmp_path, monkeypatch):
    async def failing_send(plan):
        raise RuntimeError("croc send would not start")

    monkeypatch.setattr(mcp_tool, "execute_with_croc", failing_send)
    text = await tools(tool, extra, upload_files=_upload_spec(tmp_path))
    await _drain_detached()
    assert "would not start" in text, text
    _no_transfer_dirs_left(temp_root)


@pytest.mark.parametrize("tool,extra", UPLOAD_TOOLS)
@pytest.mark.asyncio
async def test_a_cancelled_call_stops_the_sender_and_removes_its_folders(tool, extra, tools, temp_root, tmp_path, torque):
    """The MCP SDK cancels a request with anyio: every later await in it is cancelled
    too, the clean-up's own included."""
    torque.start_forever = True
    with anyio.move_on_after(0.5):
        await tools(tool, extra, upload_files=_upload_spec(tmp_path), download_files=_download_spec(tmp_path))
    await _drain_detached()
    assert tools.started and all(p.terminated for p in tools.started)
    _no_transfer_dirs_left(temp_root)


def test_an_archive_that_cannot_be_built_removes_its_folder(tmp_path, temp_root, monkeypatch):
    """Only the Piping Server offered, and its archive fails: nothing is left."""
    monkeypatch.setattr(mcp_tool, "_local_transports", lambda settings: (["piping"], ["croc: blocked"]))

    def broken(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(mcp_tool.piping, "build_archive", broken)
    plan = mcp_tool.prepare_files_with_croc(_upload_spec(tmp_path), transfer_mode="container")
    assert plan.errors and "disk full" in plan.errors[0]
    assert os.listdir(str(temp_root)) == []


@pytest.mark.asyncio
async def test_an_async_download_through_the_piping_server_alone_is_tracked(tools, tmp_path, monkeypatch):
    """No local croc: execute_download_receive returns no process. The run must still be
    tracked, or its receive never starts (the streamer feeds it the agent's offer)
    and its folder is never removed."""
    monkeypatch.setattr(mcp_tool, "_local_transports", lambda settings: (["piping"], ["croc: blocked"]))
    await tools("run_on_tunneled_disposable_container_async", {}, download_files=_download_spec(tmp_path))
    state = mcp_tool._croc_async_state.get("env-1") or {}
    assert state.get("dl_plan") is not None
    await mcp_tool.handle_cancel_execution({"environment_id": "env-1"})


# ---------------------------------------------------------------------------
# 3. A cancelled request's clean-up still finishes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cleanup_in_a_cancelled_scope_still_stops_croc_and_removes_the_folder(tmp_path):
    staging = _make_dir(tmp_path, "torque_croc_cancel")
    croc = FakeCrocProcess()

    async def request():
        try:
            await anyio.sleep_forever()
        finally:
            await mcp_tool.cleanup_croc_resources(croc, staging)

    async with anyio.create_task_group() as tg:
        tg.start_soon(request)
        await anyio.sleep(0.05)
        tg.cancel_scope.cancel()
    await _drain_detached()

    assert croc.terminated
    assert not os.path.exists(staging)


@pytest.mark.asyncio
async def test_download_cleanup_in_a_cancelled_scope_still_removes_the_folder(tmp_path):
    receive = _make_dir(tmp_path, "torque_dl_cancel")
    receiver = FakeCrocProcess()

    async def request():
        try:
            await anyio.sleep_forever()
        finally:
            await mcp_tool.cleanup_download_resources(receiver, receive)

    async with anyio.create_task_group() as tg:
        tg.start_soon(request)
        await anyio.sleep(0.05)
        tg.cancel_scope.cancel()
    await _drain_detached()

    assert receiver.terminated
    assert not os.path.exists(receive)


# ---------------------------------------------------------------------------
# 4. croc's send log does not keep the code
# ---------------------------------------------------------------------------

def test_the_send_log_keeps_crocs_words_but_not_the_code(tmp_path, monkeypatch):
    code = "7731-correct-horse-battery"
    printed = (f"Sending 'big.bin' (500 kB)\nCode is: {code}\nOn the other computer run:\n"
               f"(For Linux/macOS)\n    CROC_SECRET=\"{code}\" croc\n").encode()
    proc = FakeCrocProcess()
    monkeypatch.setattr(croc_manager, "CROC_SEND_STARTUP_SECONDS", 0)
    monkeypatch.setattr(croc_manager, "warm_dns_cache", lambda *a, **kw: None)
    monkeypatch.setattr(croc_manager, "process_tcp_established", lambda pid: True)

    async def spawn(*args, **kwargs):
        kwargs["stdout"].write(printed)
        kwargs["stdout"].flush()
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    result = asyncio.run(croc_manager.start_croc_send(
        croc_path="croc", code=code, files=["f"], relay="relay.example:9009", log_dir=str(tmp_path)))

    assert os.path.dirname(result.croc_log_path) == str(tmp_path)
    with open(result.croc_log_path, "rb") as f:
        kept = f.read()
    assert code.encode() not in kept
    assert b"Sending 'big.bin' (500 kB)" in kept and b"Code is: " in kept
    assert len(kept) == len(printed)   # same length: croc keeps writing at its own offset
