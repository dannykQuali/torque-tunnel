"""get_execution_status / cancel_execution must reach the Torque that ran the command.

The async run tools start their environment with the call's profile, which can point at
another Torque instance or space than the default profile. The status and cancel tools
used to have no `profile` argument and always used the default profile's connection, so
such an environment was polled (and cancelled) on the wrong Torque. For a download this
also meant the gated local receiver never saw the sender's READY sentinel.

These tests drive the real MCP dispatch (`call_tool`) with a fake TorqueClient that
records which Torque each call was made against.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import mcp_tool


DEFAULT_URL = "https://default.example.com"
BETA_URL = "https://beta.example.com"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----"

# The fixture stubs the streamer out; the streamer test puts the real one back.
_REAL_START_STREAMER = mcp_tool._start_background_streamer


class _FakeTorque:
    """Records (base_url, space, method, environment_id) for every API call."""

    calls: list = []
    status = "deploying"

    def __init__(self, base_url=None, token=None, space=None, **kw):
        self.base_url = base_url
        self.token = token
        self.space = space

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _record(self, method, env_id=None):
        _FakeTorque.calls.append((self.base_url, self.space, method, env_id))

    async def start_environment(self, **kw):
        self._record("start_environment")
        return "env-1"

    async def start_local_environment(self, **kw):
        self._record("start_local_environment")
        return "env-1"

    async def set_scheduled_end_time(self, env_id, *a, **kw):
        self._record("set_scheduled_end_time", env_id)

    async def get_environment_status(self, env_id):
        self._record("get_environment_status", env_id)
        return {"details": {"computed_status": _FakeTorque.status}}

    async def get_grain_log(self, env_id):
        self._record("get_grain_log", env_id)
        return ""

    async def end_environment(self, env_id, force=False):
        self._record("end_environment", env_id)

    async def release_environment(self, env_id, force=False):
        self._record("release_environment", env_id)

    async def delete_environment(self, env_id):
        self._record("delete_environment", env_id)

    def _extract_outputs(self, env_data):
        return {"command_output": "", "exit_code": "0"}

    async def fetch_credentials(self):
        return []


@pytest.fixture(autouse=True)
def torque_world(monkeypatch):
    """A default profile and a 'beta' profile on a different Torque instance."""
    _FakeTorque.calls = []
    _FakeTorque.status = "deploying"
    monkeypatch.setattr(mcp_tool, "TorqueClient", _FakeTorque)
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config,
        torque_url=DEFAULT_URL, torque_token="default-token", torque_space="DefaultSpace",
        default_agent="default-agent", default_ssh_key=None, default_ssh_password=None,
        default_target_ip=None, default_ssh_user=None, init_commands=None,
        finally_commands=None, auto_delete_environments=False,
    ))
    monkeypatch.setattr(mcp_tool, "_loaded_config", {
        "profiles": {
            "beta": {
                "torque_url": BETA_URL,
                "torque_token": "beta-token",
                "torque_space": "BetaSpace",
                "torque_agent": "beta-agent",
            },
        },
    })
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    # Background streaming is covered by its own test; elsewhere it would only leave
    # a polling task behind.
    monkeypatch.setattr(mcp_tool, "_start_background_streamer", lambda *a, **kw: None)
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {}, raising=False)
    monkeypatch.setattr(mcp_tool, "_streamer_cache", {})
    yield


def _urls(method, env_id="env-1"):
    return {url for url, _, m, e in _FakeTorque.calls if m == method and e == env_id}


def _text(result):
    return "\n".join(getattr(c, "text", "") for c in (result or []))


async def _fake_container(**kw):
    return {
        "container_ip": "172.17.0.5",
        "private_key": KEY,
        "environment_id": "container-env",
        "container_id": "abc123",
        "agent": "beta-agent",
    }


ASYNC_TOOLS = [
    ("run_on_tunneled_ssh_async",
     {"command": "echo hi", "command_description": "test", "host": "10.0.0.1",
      "user": "root", "private_key": KEY}),
    ("run_on_tunneled_disposable_container_async",
     {"command": "echo hi", "command_description": "test"}),
    ("run_on_tunneled_persistent_container_async",
     {"command": "echo hi", "command_description": "test"}),
]


async def _start(tool, args, monkeypatch, profile=None):
    monkeypatch.setattr(mcp_tool, "_ensure_persistent_container", _fake_container)
    call_args = dict(args)
    if profile:
        call_args["profile"] = profile
    return _text(await mcp_tool.call_tool(tool, call_args))


# --- explicit profile ---------------------------------------------------------------

@pytest.mark.asyncio
async def test_status_with_profile_polls_that_profiles_torque():
    await mcp_tool.call_tool(
        "get_execution_status", {"environment_id": "env-1", "profile": "beta", "wait": 0})
    assert _urls("get_environment_status") == {BETA_URL}


@pytest.mark.asyncio
async def test_cancel_with_profile_cancels_on_that_profiles_torque():
    _FakeTorque.status = "active"
    await mcp_tool.call_tool("cancel_execution", {"environment_id": "env-1", "profile": "beta"})
    assert _urls("end_environment") == {BETA_URL}


@pytest.mark.asyncio
async def test_status_with_unknown_profile_is_an_error_not_a_default_profile_poll():
    result = _text(await mcp_tool.call_tool(
        "get_execution_status", {"environment_id": "env-1", "profile": "nope", "wait": 0}))
    assert "nope" in result
    assert _urls("get_environment_status") == set()


@pytest.mark.asyncio
async def test_status_result_links_to_the_profiles_torque():
    result = _text(await mcp_tool.call_tool(
        "get_execution_status", {"environment_id": "env-1", "profile": "beta", "wait": 0}))
    assert f"{BETA_URL}/BetaSpace/environments/env-1" in result


# --- no profile: the environment's own connection is remembered ---------------------

@pytest.mark.parametrize("tool,args", ASYNC_TOOLS)
@pytest.mark.asyncio
async def test_status_without_profile_polls_where_the_command_was_started(tool, args, monkeypatch):
    await _start(tool, args, monkeypatch, profile="beta")
    _FakeTorque.calls.clear()

    await mcp_tool.call_tool("get_execution_status", {"environment_id": "env-1", "wait": 0})

    assert _urls("get_environment_status") == {BETA_URL}


@pytest.mark.parametrize("tool,args", ASYNC_TOOLS)
@pytest.mark.asyncio
async def test_cancel_without_profile_cancels_where_the_command_was_started(tool, args, monkeypatch):
    await _start(tool, args, monkeypatch, profile="beta")
    _FakeTorque.status = "active"
    _FakeTorque.calls.clear()

    await mcp_tool.call_tool("cancel_execution", {"environment_id": "env-1"})

    assert _urls("end_environment") == {BETA_URL}


@pytest.mark.asyncio
async def test_status_of_an_unknown_environment_uses_the_default_profile():
    await mcp_tool.call_tool("get_execution_status", {"environment_id": "env-1", "wait": 0})
    assert _urls("get_environment_status") == {DEFAULT_URL}


@pytest.mark.asyncio
async def test_remembered_connection_survives_a_hot_reload_of_the_default_profile(monkeypatch):
    """A command started without a profile belongs to the Torque it was started on, even
    if the default profile is switched to another instance before the poll."""
    tool, args = ASYNC_TOOLS[0]
    await _start(tool, args, monkeypatch)
    mcp_tool._config["torque_url"] = "https://switched.example.com"
    _FakeTorque.calls.clear()

    await mcp_tool.call_tool("get_execution_status", {"environment_id": "env-1", "wait": 0})

    assert _urls("get_environment_status") == {DEFAULT_URL}


@pytest.mark.asyncio
async def test_terminal_status_forgets_the_connection(monkeypatch):
    tool, args = ASYNC_TOOLS[0]
    await _start(tool, args, monkeypatch, profile="beta")
    _FakeTorque.status = "active"
    await mcp_tool.call_tool("get_execution_status", {"environment_id": "env-1", "wait": 0})
    assert "env-1" not in mcp_tool._async_env_connections


# --- the messages that tell the caller how to poll ---------------------------------

@pytest.mark.parametrize("tool,args", ASYNC_TOOLS)
@pytest.mark.asyncio
async def test_start_message_names_the_profile_for_the_follow_up_calls(tool, args, monkeypatch):
    text = await _start(tool, args, monkeypatch, profile="beta")
    lines = [l for l in text.splitlines() if "get_execution_status" in l or "cancel_execution" in l]
    assert len(lines) == 2, text
    assert all('profile="beta"' in l for l in lines), lines


@pytest.mark.parametrize("tool,args", ASYNC_TOOLS)
@pytest.mark.asyncio
async def test_start_message_without_a_profile_does_not_invent_one(tool, args, monkeypatch):
    text = await _start(tool, args, monkeypatch)
    assert "profile=" not in text


@pytest.mark.asyncio
async def test_still_running_message_names_the_profile(monkeypatch):
    tool, args = ASYNC_TOOLS[0]
    await _start(tool, args, monkeypatch, profile="beta")
    result = _text(await mcp_tool.call_tool(
        "get_execution_status", {"environment_id": "env-1", "wait": 0}))
    again = [l for l in result.splitlines() if "get_execution_status" in l]
    assert again and 'profile="beta"' in again[0], result


@pytest.mark.asyncio
async def test_status_and_cancel_schemas_accept_a_profile():
    tools = {t.name: t for t in await mcp_tool.list_tools()}
    for name in ("get_execution_status", "cancel_execution"):
        assert "profile" in tools[name].inputSchema["properties"], name


# --- background streaming ------------------------------------------------------------

@pytest.mark.asyncio
async def test_background_streamer_polls_the_torque_the_command_was_started_on(monkeypatch):
    real_sleep = mcp_tool.asyncio.sleep

    async def no_wait(seconds):
        await real_sleep(0)

    monkeypatch.setattr(mcp_tool, "_start_background_streamer", _REAL_START_STREAMER)
    monkeypatch.setattr(mcp_tool.asyncio, "sleep", no_wait)
    _FakeTorque.status = "active"   # terminal: the streamer stops after one poll
    tool, args = ASYNC_TOOLS[0]
    await _start(tool, args, monkeypatch, profile="beta")
    task = mcp_tool._background_streamers.get("env-1")
    assert task is not None
    await task

    assert _urls("get_environment_status") == {BETA_URL}
    assert _urls("get_grain_log") == {BETA_URL}
