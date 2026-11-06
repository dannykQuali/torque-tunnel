"""The raw Torque log is exposed only as the --raw-log command-line flag allows.

Torque echoes the whole rendered grain script before running it, and that script holds
the SSH private key and every other input. That echo (the raw log) must not reach a
caller unless the user started torque-tunnel with --raw-log:

  off       (default) the echo never leaves the process: not in tool results, not in
            MCP log notifications, not in CLI output. The job's own setup output (croc
            uploads, the transfer tool's work, their errors) still comes back while the
            command has not started, so failures there stay diagnosable.
  fallback  the behavior before the flag existed: the whole raw log is returned
            whenever the "=== Beginning of execution ===" marker is missing.
  always    the raw log everywhere, streaming included.

The flag is the ONLY way to set this: not the config file, not a profile, not an
environment variable, not a tool argument.

These tests drive the real MCP dispatch (`call_tool`), the real TorqueClient wait loop
and the real log streamer, with only the Torque API faked.
"""

import os
import sys

import httpx
import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import mcp_tool, raw_log
from torque_tunnel import torque_client as tc
from torque_tunnel.torque_client import EnvironmentResult, TorqueClient


SECRET = "RkFLRS1QUklWQVRFLUtFWS1NQVRFUklBTA"  # body of the fake key in the preamble
KEY = f"-----BEGIN RSA PRIVATE KEY-----\n{SECRET}\n-----END RSA PRIVATE KEY-----"

# What Torque's log looks like (taken from a real remote-shell-executor log): the runner
# echoes the rendered script - the key templated in, and the blueprint's marker lines
# inside `echo "..."` - then the script's own output: setup, then the command.
ECHO = (
    "[11:13:55.417] >> Running on ccb766c752c1. Storage: . Task Id: XMW6523\n"
    "[11:13:55.697] Executing command: # Disable exit on error\n"
    "[11:13:55.698] set +e\n"
    '[11:13:55.699]   echo "=== Running container pre-commands ==="\n'
    "[11:13:55.699]   SSH_PRIVATE_KEY='-----BEGIN RSA PRIVATE KEY-----\n"
    f"[11:13:55.699] {SECRET}\n"
    "[11:13:55.699] -----END RSA PRIVATE KEY-----'\n"
    '[11:13:55.699] echo "=== Commands (decoded for visibility) ' + "=" * 106 + '"\n'
    '[11:13:55.699] echo "=== Beginning of execution ' + "=" * 117 + '"\n'
)
SETUP = (
    "[11:13:55.732] === Running container pre-commands ===\n"
    "[11:13:58.101] Receiving 'files.tar' (31 files)\n"
    "[11:14:07.970] ssh: connect to host 10.0.0.1 port 22: No route to host\n"
)
# The decoded command can carry secrets of its own (the transfer tool writes keys into it)
DUMP_SECRET = "Q09NTUFORC1URVhULVNFQ1JFVA"
DUMP = (
    "[11:14:25.155] === Commands (decoded for visibility) " + "=" * 106 + "\n"
    "[11:14:25.160] ----- command -----\n"
    f"[11:14:25.162] echo {DUMP_SECRET}\n"
)
MARKER = "[11:14:25.162] === Beginning of execution " + "=" * 117 + "\n"
AFTER = (
    "[11:14:25.176] === Connecting to root@10.0.0.1 ===\n"
    "[11:14:25.176] === Output (streaming) " + "=" * 121 + "\n"
    "[11:14:29.068] hello from the command\n"
)
PREAMBLE = ECHO + SETUP          # a job still in (or that died in) its setup
FULL_LOG = ECHO + SETUP + DUMP + MARKER + AFTER

MODES = ["off", "fallback", "always"]


@pytest.fixture(autouse=True)
def default_mode():
    """Every test starts (and leaves the process) in the default mode."""
    raw_log.set_mode("off")
    yield
    raw_log.set_mode("off")


# --- fake Torque for the MCP tools ----------------------------------------------------

class _FakeTorque:
    status = "deploying"
    log = ""
    result = None

    def __init__(self, base_url=None, token=None, space=None, **kw):
        self.base_url = base_url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_environment_status(self, env_id, **kw):
        return {"details": {"computed_status": _FakeTorque.status, "state": {"errors": []}}}

    async def get_grain_log(self, env_id):
        return _FakeTorque.log

    async def execute_remote_command(self, **kw):
        return _FakeTorque.result

    async def execute_local_command(self, **kw):
        return _FakeTorque.result

    async def end_environment(self, env_id, force=False):
        pass

    async def release_environment(self, env_id, force=False):
        pass

    async def delete_environment(self, env_id):
        pass

    def _extract_outputs(self, env_data):
        return {}

    async def fetch_credentials(self):
        return []


@pytest.fixture
def torque(monkeypatch):
    _FakeTorque.status = "deploying"
    _FakeTorque.log = ""
    _FakeTorque.result = None
    monkeypatch.setattr(mcp_tool, "TorqueClient", _FakeTorque)
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config,
        torque_url="https://torque.example", torque_token="tok", torque_space="Space",
        default_agent="agent", default_ssh_key=None, default_ssh_password=None,
        default_target_ip=None, default_ssh_user=None, init_commands=None,
        finally_commands=None, auto_delete_environments=False,
    ))
    monkeypatch.setattr(mcp_tool, "_loaded_config", {})
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    monkeypatch.setattr(mcp_tool, "_start_background_streamer", lambda *a, **kw: None)
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {}, raising=False)
    monkeypatch.setattr(mcp_tool, "_streamer_cache", {})

    async def _fake_container(**kw):
        return {"container_ip": "172.17.0.5", "private_key": KEY, "environment_id": "c-env",
                "container_id": "abc", "agent": "agent"}
    monkeypatch.setattr(mcp_tool, "_ensure_persistent_container", _fake_container)
    return _FakeTorque


def _text(result):
    return "\n".join(getattr(c, "text", "") for c in (result or []))


async def _status(**extra):
    args = {"environment_id": "env-1", "wait": 0, **extra}
    return _text(await mcp_tool.call_tool("get_execution_status", args))


# --- get_execution_status -------------------------------------------------------------

# (Torque status, a label for the test id)
PRE_MARKER_STATES = [
    ("deploying", "still-running"),       # the case behind the leaks: polled during setup
    ("released", "cancelled"),
    ("ended_with_error", "failed"),
]


@pytest.mark.parametrize("status", [s for s, _ in PRE_MARKER_STATES],
                         ids=[i for _, i in PRE_MARKER_STATES])
@pytest.mark.asyncio
async def test_status_off_never_returns_the_preamble(torque, status):
    torque.status, torque.log = status, PREAMBLE
    text = await _status()
    assert SECRET not in text
    assert "Executing command" not in text


@pytest.mark.parametrize("status", [s for s, _ in PRE_MARKER_STATES],
                         ids=[i for _, i in PRE_MARKER_STATES])
@pytest.mark.asyncio
async def test_status_off_still_returns_the_setup_output(torque, status):
    """Uploads and transfers run before the command; their output and errors are the
    job's own and stay visible."""
    torque.status, torque.log = status, PREAMBLE
    text = await _status()
    assert "Receiving 'files.tar'" in text
    assert "No route to host" in text


@pytest.mark.asyncio
async def test_status_off_setup_output_stops_before_the_commands_dump(torque):
    """Polled in the instant between the dump and the marker."""
    torque.status, torque.log = "deploying", ECHO + SETUP + DUMP
    text = await _status()
    assert "No route to host" in text
    assert DUMP_SECRET not in text
    assert SECRET not in text


@pytest.mark.parametrize("mode", ["off", "fallback"])
@pytest.mark.asyncio
async def test_commands_dump_is_not_returned_once_the_command_runs(torque, mode):
    raw_log.set_mode(mode)
    torque.status, torque.log = "deploying", FULL_LOG
    assert DUMP_SECRET not in await _status()


@pytest.mark.asyncio
async def test_status_off_says_why_there_is_no_output_yet(torque):
    torque.status, torque.log = "deploying", ECHO  # the job has printed nothing yet
    text = await _status()
    assert "RUNNING" in text
    assert SECRET not in text
    assert "--raw-log" in text  # tells the user how to see the log when they need it


@pytest.mark.parametrize("mode", ["fallback", "always"])
@pytest.mark.parametrize("status", [s for s, _ in PRE_MARKER_STATES],
                         ids=[i for _, i in PRE_MARKER_STATES])
@pytest.mark.asyncio
async def test_status_raw_log_modes_return_the_preamble_when_no_marker(torque, mode, status):
    raw_log.set_mode(mode)
    torque.status, torque.log = status, PREAMBLE
    assert SECRET in await _status()


@pytest.mark.parametrize("mode", ["off", "fallback"])
@pytest.mark.asyncio
async def test_status_after_marker_shows_only_command_output(torque, mode):
    raw_log.set_mode(mode)
    torque.status, torque.log = "deploying", FULL_LOG
    text = await _status()
    assert "hello from the command" in text
    assert SECRET not in text


@pytest.mark.asyncio
async def test_status_always_shows_the_preamble_even_after_marker(torque):
    raw_log.set_mode("always")
    torque.status, torque.log = "deploying", FULL_LOG
    text = await _status()
    assert "hello from the command" in text
    assert SECRET in text


@pytest.mark.parametrize("extra", [
    {"verbose": True}, {"raw_log": "always"}, {"raw-log": "always"}, {"debug": True},
])
@pytest.mark.asyncio
async def test_no_tool_argument_turns_raw_logs_on(torque, extra):
    torque.status, torque.log = "deploying", PREAMBLE
    assert SECRET not in await _status(**extra)


@pytest.mark.asyncio
async def test_no_tool_schema_offers_a_raw_log_or_verbose_argument():
    for tool in await mcp_tool.list_tools():
        props = (tool.inputSchema or {}).get("properties", {})
        for name in props:
            assert "verbose" not in name.lower(), (tool.name, name)
            assert "raw" not in name.lower(), (tool.name, name)


# --- synchronous run tools: failure without command output ----------------------------

SYNC_TOOLS = [
    ("run_on_tunneled_ssh",
     {"command": "echo hi", "command_description": "t", "host": "10.0.0.1", "user": "root",
      "private_key": KEY}),
    ("run_on_tunneled_disposable_container", {"command": "echo hi", "command_description": "t"}),
    ("run_on_tunneled_persistent_container", {"command": "echo hi", "command_description": "t"}),
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("tool,args", SYNC_TOOLS, ids=[t for t, _ in SYNC_TOOLS])
@pytest.mark.asyncio
async def test_sync_failure_before_marker(torque, tool, args, mode):
    raw_log.set_mode(mode)
    torque.result = EnvironmentResult(environment_id="env-1", status="failed", error="boom")
    torque.log = PREAMBLE
    text = _text(await mcp_tool.call_tool(tool, dict(args)))
    assert "boom" in text
    assert "No route to host" in text  # the reason it failed, in every mode
    if mode == "off":
        assert SECRET not in text
    else:
        assert SECRET in text


# --- TorqueClient.wait_for_environment: timeout before the command started ------------

def _client(log):
    client = TorqueClient(base_url="https://torque.example", token="tok", space="sp",
                          default_agent="agent", poll_interval=1)
    client._client = httpx.AsyncClient(
        base_url="https://torque.example/api",
        transport=httpx.MockTransport(lambda r: httpx.Response(
            200, json={"details": {"computed_status": "Deploying"}})))

    async def _log(env_id):
        return log
    client.get_grain_log = _log
    return client


@pytest.fixture
def fake_clock(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(tc.time, "monotonic", lambda: clock["t"])

    async def _advancing_sleep(seconds):
        clock["t"] += seconds
    monkeypatch.setattr(tc.asyncio, "sleep", _advancing_sleep)
    return clock


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.asyncio
async def test_timeout_partial_output_before_marker(fake_clock, mode):
    raw_log.set_mode(mode)
    result = await _client(PREAMBLE).wait_for_environment("env-1", timeout=5)
    assert result.status == "timeout"
    assert "No route to host" in result.command_output
    if mode == "off":
        assert SECRET not in (result.command_output or "")
    else:
        assert SECRET in result.command_output


@pytest.mark.parametrize("mode", ["off", "fallback"])
@pytest.mark.asyncio
async def test_timeout_partial_output_after_marker_is_command_output(fake_clock, mode):
    raw_log.set_mode(mode)
    result = await _client(FULL_LOG).wait_for_environment("env-1", timeout=5)
    assert result.status == "timeout"
    assert "hello from the command" in result.command_output
    assert SECRET not in result.command_output


# --- streaming to the MCP client ------------------------------------------------------

class _Session:
    def __init__(self):
        self.sent = []

    def send_log_message(self, level, data, logger=None):
        self.sent.append(data)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.asyncio
async def test_streamed_log(mode, capsys):
    raw_log.set_mode(mode)
    session = _Session()
    stream = mcp_tool.create_log_streamer(session)
    # Torque hands the log over in chunks; split inside the key and inside the marker.
    cut1, cut2 = FULL_LOG.index(SECRET) + 5, FULL_LOG.index(MARKER) + 20
    for chunk in (FULL_LOG[:cut1], FULL_LOG[cut1:cut2], FULL_LOG[cut2:]):
        await stream(chunk, "env-1")
    sent = "".join(session.sent)
    printed = capsys.readouterr().err
    assert "hello from the command" in sent
    assert "Running on ccb766c752c1" in sent  # the header line is not the raw log
    for out in (sent, printed):
        if mode == "always":
            assert SECRET in out
        else:
            assert SECRET not in out


# --- the flag is the only way to set it -----------------------------------------------

def _clear_env(monkeypatch):
    for var in ["TORQUE_TUNNEL_CONFIG", "TORQUE_TUNNEL_PROFILE", "TORQUE_URL", "TORQUE_TOKEN",
                "TORQUE_SPACE", "TORQUE_AGENT", "SSH_KEY", "SSH_PASSWORD", "TARGET_HOST",
                "SSH_USER", "INIT_COMMANDS", "FINALLY_COMMANDS", "AUTO_DELETE_ENVIRONMENTS",
                "CONTAINER_IDLE_TIMEOUT"]:
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize("argv", [[], ["ssh", "echo hi"], ["serve"]])
def test_default_is_off(monkeypatch, argv):
    _clear_env(monkeypatch)
    assert mcp_tool.build_parser().parse_args(argv).raw_log == "off"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("argv", [
    lambda m: ["--raw-log", m, "ssh", "echo hi"],
    lambda m: ["ssh", "--raw-log", m, "echo hi"],
    lambda m: [f"--raw-log={m}"],
    lambda m: ["serve", "--raw-log", m],
], ids=["before-subcommand", "after-subcommand", "equals-form", "serve"])
def test_flag_parses_anywhere(monkeypatch, mode, argv):
    _clear_env(monkeypatch)
    assert mcp_tool.build_parser().parse_args(argv(mode)).raw_log == mode


@pytest.mark.parametrize("argv", [
    ["--raw-log", "on"], ["--raw-log", "verbose"], ["--raw-log"], ["--verbose"], ["-v"],
])
def test_bad_or_removed_flags_are_rejected(monkeypatch, argv, capsys):
    _clear_env(monkeypatch)
    with pytest.raises(SystemExit):
        mcp_tool.build_parser().parse_args(argv)


@pytest.mark.parametrize("var,value", [
    ("VERBOSE", "true"), ("RAW_LOG", "always"), ("TORQUE_TUNNEL_RAW_LOG", "always"),
    ("TORQUE_TUNNEL_VERBOSE", "true"),
])
def test_no_environment_variable_sets_it(monkeypatch, var, value):
    _clear_env(monkeypatch)
    monkeypatch.setenv(var, value)
    assert mcp_tool.build_parser().parse_args([]).raw_log == "off"


def _write_config(path, **top):
    path.write_text(yaml.dump({
        "torque_url": "https://file.example", "torque_token": "t", "torque_space": "s",
        **top,
        "default_profile": "p",
        "profiles": {"p": {"description": "x", "verbose": True, "raw_log": "always"}},
    }), encoding="utf-8")


@pytest.mark.parametrize("top", [{"verbose": True}, {"raw_log": "always"}, {"raw-log": "always"}])
def test_config_file_cannot_turn_it_on(tmp_path, monkeypatch, top, capsys):
    cfg = tmp_path / "config.yaml"
    _write_config(cfg, **top)
    monkeypatch.setattr(mcp_tool, "_config", dict(mcp_tool._config))
    monkeypatch.setattr(mcp_tool, "_config_explicit_path", str(cfg))
    monkeypatch.setattr(mcp_tool, "_cli_overrides", set())
    monkeypatch.setattr(mcp_tool, "_loaded_config", {})
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    mcp_tool._reload_config()
    assert raw_log.get_mode() == "off"


def test_config_file_with_the_removed_verbose_key_warns(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    _write_config(cfg, verbose=True)
    monkeypatch.setattr(mcp_tool, "_config", dict(mcp_tool._config))
    monkeypatch.setattr(mcp_tool, "_config_explicit_path", str(cfg))
    monkeypatch.setattr(mcp_tool, "_cli_overrides", set())
    monkeypatch.setattr(mcp_tool, "_loaded_config", {})
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    mcp_tool._reload_config()
    err = capsys.readouterr().err
    assert "verbose" in err and "--raw-log" in err


@pytest.mark.parametrize("mode", MODES)
def test_main_applies_the_flag(tmp_path, monkeypatch, mode, capsys):
    """End to end through main(): the flag on the command line sets the mode."""
    _clear_env(monkeypatch)
    cfg = tmp_path / "config.yaml"
    _write_config(cfg)
    for name in ("_config", "_loaded_config"):
        monkeypatch.setattr(mcp_tool, name, dict(getattr(mcp_tool, name)))
    for name in ("_config_error", "_default_profile_warning", "_config_explicit_path",
                 "_config_file_path", "_config_file_mtime", "_cli_profile"):
        monkeypatch.setattr(mcp_tool, name, getattr(mcp_tool, name), raising=False)
    monkeypatch.setattr(mcp_tool, "_cli_overrides", set())
    monkeypatch.setattr(sys, "argv", ["torque-tunnel", "--config", str(cfg),
                                      "--raw-log", mode, "profiles"])
    try:
        mcp_tool.main()
    except SystemExit:
        pass
    assert raw_log.get_mode() == mode
