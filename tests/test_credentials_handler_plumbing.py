"""Every run_* handler must reach Torque, with and without a credential.

The credential plumbing was threaded into six handlers by hand, and they do not all name
their config local the same way — handle_run_on_tunneled_ssh rebinds the `config` parameter
while the other five use `cfg`. That produced a NameError on *every* SSH call, including
ones passing no credential at all, because the argument is evaluated before the function
body can return early.

Schema and unit tests could not see it: only actually invoking a handler can. These tests
drive each handler far enough to prove the credential step executes and hands control on.
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import mcp_tool


#: Raised by the stubbed client so a handler that got all the way to Torque is
#: distinguishable from one that fell over earlier.
REACHED_TORQUE = "__reached_torque__"


class _StubClient:
    """Stands in for TorqueClient: accepts the plumbing, then signals it was reached."""

    def __init__(self, *a, **kw):
        self.base_url = "https://torque.example.com"
        self.space = "SpaceA"
        self.default_agent = "agent-1"

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def close(self):
        return None

    async def _fail(self, *a, **kw):
        raise RuntimeError(REACHED_TORQUE)

    execute_remote_command = _fail
    execute_local_command = _fail
    start_environment = _fail
    start_local_environment = _fail

    async def get_grain_log(self, *a, **kw):
        return None

    async def fetch_credentials(self):
        return []


BASE_CONFIG = {
    "torque_url": "https://torque.example.com",
    "torque_token": "tok",
    "torque_space": "SpaceA",
    "default_agent": "agent-1",
    "default_ssh_key": None,
    "default_ssh_password": None,
    "default_target_ip": "10.0.0.1",
    "default_ssh_user": "root",
    "init_commands": None,
    "finally_commands": None,
    "auto_delete_environments": False,
    "verbose": False,
    "container_idle_timeout": 86400,
    "retry_enabled": True,
    "retry_budget_seconds": 600,
    "create_retry_budget_seconds": 600,
    "retry_max_backoff_seconds": 15,
    "credentials_enabled": False,
    "credentials_space_policy": "preconfigured",
}


#: The persistent-container handlers stand up a container before touching Torque for the
#: command itself, so they are covered separately below.
DIRECT_HANDLERS = [
    ("run_on_tunneled_ssh", "handle_run_on_tunneled_ssh"),
    ("run_on_tunneled_disposable_container", "handle_run_on_tunneled_disposable_container"),
    ("run_on_tunneled_ssh_async", "handle_run_on_tunneled_ssh_async"),
    ("run_on_tunneled_disposable_container_async",
     "handle_run_on_tunneled_disposable_container_async"),
]

PERSISTENT_HANDLERS = [
    ("run_on_tunneled_persistent_container", "handle_run_on_tunneled_persistent_container"),
    ("run_on_tunneled_persistent_container_async",
     "handle_run_on_tunneled_persistent_container_async"),
]


def _arguments(extra=None):
    args = {
        "command": "echo ok",
        "command_description": "plumbing check",
        "host": "10.0.0.1",
        "user": "root",
        "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----",
        "timeout": 60,
    }
    args.update(extra or {})
    return args


def _text(result):
    return "\n".join(getattr(c, "text", "") for c in (result or []))


@pytest.mark.parametrize("tool_name,handler_name", DIRECT_HANDLERS)
@pytest.mark.asyncio
async def test_handler_reaches_torque_without_a_credential(tool_name, handler_name):
    """A call with no credential must be unaffected by the credential plumbing."""
    handler = getattr(mcp_tool, handler_name)
    with patch.object(mcp_tool, "TorqueClient", _StubClient), \
         patch.object(mcp_tool, "get_torque_client", lambda *a, **kw: _StubClient()):
        result = await handler(_arguments(), dict(BASE_CONFIG))

    text = _text(result)
    assert REACHED_TORQUE in text, f"{tool_name} did not reach Torque: {text[:400]}"
    assert "is not defined" not in text, f"{tool_name} raised a NameError: {text[:400]}"


@pytest.mark.parametrize("tool_name,handler_name", DIRECT_HANDLERS)
@pytest.mark.asyncio
async def test_handler_refuses_a_credential_when_not_enabled(tool_name, handler_name):
    """The opt-in gate has to hold in the handler itself, not only in the MCP dispatch."""
    handler = getattr(mcp_tool, handler_name)
    with patch.object(mcp_tool, "TorqueClient", _StubClient), \
         patch.object(mcp_tool, "get_torque_client", lambda *a, **kw: _StubClient()):
        result = await handler(
            _arguments({"credential": "some-cred"}), dict(BASE_CONFIG)
        )

    text = _text(result)
    assert "credentials_enabled" in text, f"{tool_name}: {text[:400]}"
    assert REACHED_TORQUE not in text, f"{tool_name} ran the command anyway: {text[:400]}"
    assert "is not defined" not in text


@pytest.mark.parametrize("tool_name,handler_name", DIRECT_HANDLERS)
@pytest.mark.asyncio
async def test_handler_resolves_a_credential_when_enabled(tool_name, handler_name):
    """With credentials on, an unknown name must produce the credential error rather than a
    plumbing error - proving the config actually reached prepare_credential."""
    handler = getattr(mcp_tool, handler_name)
    cfg = dict(BASE_CONFIG, credentials_enabled=True)
    with patch.object(mcp_tool, "TorqueClient", _StubClient), \
         patch.object(mcp_tool, "get_torque_client", lambda *a, **kw: _StubClient()):
        result = await handler(
            _arguments({"credential": "no-such-cred"}), cfg
        )

    text = _text(result)
    assert "no-such-cred" in text, f"{tool_name}: {text[:400]}"
    assert "is not defined" not in text
    assert REACHED_TORQUE not in text


@pytest.mark.parametrize("tool_name,handler_name", PERSISTENT_HANDLERS)
@pytest.mark.asyncio
async def test_persistent_handler_credential_plumbing_is_wired(tool_name, handler_name):
    """These reach the credential step only after a container exists, so the container
    setup is stubbed out and the credential step is what is under test."""
    handler = getattr(mcp_tool, handler_name)
    cfg = dict(BASE_CONFIG, credentials_enabled=True)

    async def fake_container(**kw):
        return {
            "container_ip": "172.17.0.5",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----",
            "environment_id": "env-1",
            "container_id": "abc123",
            "agent": "agent-1",
        }

    with patch.object(mcp_tool, "TorqueClient", _StubClient), \
         patch.object(mcp_tool, "get_torque_client", lambda *a, **kw: _StubClient()), \
         patch.object(mcp_tool, "_ensure_persistent_container", fake_container):
        result = await handler(_arguments({"credential": "no-such-cred"}), cfg)

    text = _text(result)
    assert "is not defined" not in text, f"{tool_name} raised a NameError: {text[:400]}"
    assert "no-such-cred" in text, f"{tool_name}: {text[:400]}"


@pytest.mark.asyncio
async def test_every_run_tool_is_covered_by_this_file():
    """A seventh execution tool added later must not silently escape this check."""
    tools = await mcp_tool.list_tools()
    run_tools = {t.name for t in tools if t.name.startswith("run_on_tunneled_")}
    covered = {name for name, _ in DIRECT_HANDLERS + PERSISTENT_HANDLERS}
    assert run_tools == covered, f"uncovered execution tools: {run_tools - covered}"
