"""A per-call `profile` decides the croc relay, as it decides everything else.

`_croc_relay_settings()` used to read the global config (the default profile) instead of
the call's effective config, so a profile's own `croc_relay` was silently ignored by
uploads and downloads while its `init_commands` (the proxy) were applied. Both sides of
a transfer must name the same relay, so the local croc process is checked as well as the
remote commands.
"""

import os
import secrets
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, mcp_tool


BETA_RELAY = "relay.beta.example:9009"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----"
REACHED = "__reached_torque__"


class _CapturingTorque:
    """Captures what each environment would have been started with."""

    started: list = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def _start(self, **kw):
        _CapturingTorque.started.append(kw)
        return "env-1"

    async def _run(self, **kw):
        _CapturingTorque.started.append(kw)
        raise RuntimeError(REACHED)

    start_environment = _start
    start_local_environment = _start
    execute_remote_command = _run
    execute_local_command = _run

    async def set_scheduled_end_time(self, *a, **kw):
        return None

    async def get_grain_log(self, *a, **kw):
        return None

    async def fetch_credentials(self):
        return []


@pytest.fixture(autouse=True)
def world(monkeypatch):
    _CapturingTorque.started = []
    local = {"send": [], "receive": []}

    async def fake_send(plan):
        local["send"].append(plan.croc_relay)
        return SimpleNamespace(returncode=0)

    async def fake_receive(plan, command_timeout=None):
        local["receive"].append(plan.croc_relay)
        return SimpleNamespace(returncode=0)

    async def fake_container(**kw):
        return {"container_ip": "172.17.0.5", "private_key": KEY,
                "environment_id": "container-env", "container_id": "c", "agent": "a"}

    monkeypatch.setattr(mcp_tool, "TorqueClient", _CapturingTorque)
    monkeypatch.setattr(mcp_tool, "execute_with_croc", fake_send)
    monkeypatch.setattr(mcp_tool, "execute_download_receive", fake_receive)
    monkeypatch.setattr(mcp_tool, "_ensure_persistent_container", fake_container)
    monkeypatch.setattr(mcp_tool, "_start_background_streamer", lambda *a, **kw: None)
    monkeypatch.setattr(mcp_tool, "_croc_async_state", {})
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {})
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config,
        torque_url="https://default.example.com", torque_token="t", torque_space="S",
        default_agent="agent", default_ssh_key=None, default_ssh_password=None,
        default_target_ip=None, default_ssh_user=None, init_commands=None,
        finally_commands=None, croc_relay=None, croc_relay_password=None,
        croc_transfers=None,
    ))
    monkeypatch.setattr(mcp_tool, "_loaded_config", {
        "profiles": {"beta": {"torque_url": "https://beta.example.com",
                              "croc_relay": BETA_RELAY}},
    })
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    return local


TOOLS = [
    ("run_on_tunneled_ssh", {"host": "10.0.0.1", "user": "root", "private_key": KEY}),
    ("run_on_tunneled_ssh_async", {"host": "10.0.0.1", "user": "root", "private_key": KEY}),
    ("run_on_tunneled_disposable_container", {}),
    ("run_on_tunneled_disposable_container_async", {}),
    ("run_on_tunneled_persistent_container", {}),
    ("run_on_tunneled_persistent_container_async", {}),
]


def _remote_commands() -> str:
    assert _CapturingTorque.started, "no environment was started"
    return "\n".join(str(v) for kw in _CapturingTorque.started for v in kw.values() if v)


async def _call(tool, extra, profile=None, **transfer):
    args = {"command": "true", "command_description": "relay check", **extra, **transfer}
    if profile:
        args["profile"] = profile
    return await mcp_tool.call_tool(tool, args)


@pytest.mark.parametrize("tool,extra", TOOLS)
@pytest.mark.asyncio
async def test_download_uses_the_profiles_relay_on_both_sides(tool, extra, world):
    await _call(tool, extra, profile="beta", download_files=[
        {"remote_source_path": "/tmp/x", "local_destination_path": "C:\\tmp\\x"}])

    assert f"--relay {BETA_RELAY}" in _remote_commands()
    assert world["receive"] == [BETA_RELAY]


@pytest.mark.parametrize("tool,extra", TOOLS)
@pytest.mark.asyncio
async def test_upload_uses_the_profiles_relay_on_both_sides(tool, extra, world):
    # Incompressible enough to exceed the inline budget, so croc is used.
    big = secrets.token_hex(400_000)
    await _call(tool, extra, profile="beta", upload_files=[
        {"content": big, "remote_destination_path": "/tmp/big.txt"}])

    assert f"--relay {BETA_RELAY}" in _remote_commands()
    assert world["send"] == [BETA_RELAY]


@pytest.mark.asyncio
async def test_without_a_profile_the_default_relay_is_used(world):
    tool, extra = TOOLS[1]
    await _call(tool, extra, download_files=[
        {"remote_source_path": "/tmp/x", "local_destination_path": "C:\\tmp\\x"}])

    assert f"--relay {croc_manager.DEFAULT_CROC_RELAY}" in _remote_commands()
    assert BETA_RELAY not in _remote_commands()
    assert world["receive"] == [""]
