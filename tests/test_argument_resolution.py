"""Where every connection/target value of the run tools comes from, end to end.

Each value can come from three levels, highest first:
  1. the tool argument;
  2. the call's `profile` (call_tool injects its tool-mappable keys into the arguments and
     overlays the rest onto the config);
  3. the base config (`_config`: the config file's top level / default profile, CLI flags
     and environment variables all end up there before any tool runs - how they get there
     is covered by test_config.py and test_hot_reload.py).

These tests drive the real MCP dispatch (`call_tool`) and record what actually reaches
Torque: the client's connection and default agent, and the target/auth/agent of the
environment.

The same cases run for both endpoints of a remote-to-remote transfer ("transfer-sender",
"transfer-receiver"): each endpoint object must resolve exactly like the arguments of a
run_on_tunneled_ssh call (docs/design-remote-to-remote-transfer.md, "Endpoint
resolution"). The endpoint under test gets the case's values; the other side is fixed
and explicit, on another agent, so the transfer takes the croc path and starts both.
"""

import base64
import itertools
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import mcp_tool


def _key(tag: str) -> str:
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{tag}\n-----END OPENSSH PRIVATE KEY-----"


def _normalized(key: str) -> str:
    return mcp_tool.normalize_ssh_key(key)


REACHED = "__reached_torque__"


class Recorder:
    """What the last environment was started with, and on which client."""
    clients: list = []
    starts: list = []
    containers: list = []


class FakeTorque:
    def __init__(self, base_url=None, token=None, space=None, default_agent=None, **kw):
        self.base_url, self.token, self.space, self.default_agent = base_url, token, space, default_agent
        Recorder.clients.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def _record(self, kw):
        Recorder.starts.append({
            "url": self.base_url, "token": self.token, "space": self.space,
            "agent": kw.get("agent") or self.default_agent,
            "host": kw.get("target_ip"), "user": kw.get("ssh_user"),
            "key": kw.get("ssh_private_key") or "", "password": kw.get("ssh_password") or "",
            "role": (kw.get("command_description") or "").rsplit("(", 1)[-1].rstrip(")"),
        })

    # A transfer's sender reports at once that it staged the file and is ready; that is
    # all the transfer tool needs to go on and start the receiver.
    async def get_environment_status(self, env_id, retry=True):
        if env_id in CONTAINERS:
            return {"details": {"state": {"current_state": "deploying"}}}
        return {"details": {"computed_status": "Deploying"}}

    async def get_persistent_container_info(self, env_id):
        return {"container_ip": "172.17.0.9", "container_id": "c", "private_key": _key("container")}

    async def start_environment(self, **kw):
        self._record(kw)
        return "env-1"

    async def start_local_environment(self, **kw):
        self._record(kw)
        return "env-1"

    async def execute_remote_command(self, **kw):
        self._record(kw)
        raise RuntimeError(REACHED)

    async def execute_local_command(self, **kw):
        self._record(kw)
        raise RuntimeError(REACHED)

    async def set_scheduled_end_time(self, *a, **kw):
        pass

    async def get_grain_log(self, *a, **kw):
        return SENDER_READY_LOG

    async def fetch_credentials(self):
        return []


CONTAINERS = {"pc-1"}
TRANSFER_FILE = {"source_path": "/data/f", "destination_path": "/dst/f"}
SENDER_READY_LOG = (
    "__CROC_DL_SIZE__ 5 _croc_rl_0_f\n"
    "__CROC_DL_MD5__ 0123456789abcdef0123456789abcdef _croc_rl_0_f\n"
    "__CROC_SEND_READY__\n")


BASE = {
    "torque_url": "https://base.example.com", "torque_token": "base-token", "torque_space": "BaseSpace",
    "default_agent": "base-agent", "default_target_ip": "10.0.0.3", "default_ssh_user": "base-user",
    "default_ssh_key": _key("base"), "default_ssh_password": None,
}
PROFILE = {
    "torque_url": "https://profile.example.com", "torque_token": "profile-token", "torque_space": "ProfileSpace",
    "torque_agent": "profile-agent", "host": "10.0.0.2", "ssh_user": "profile-user",
}
ARGS = {
    "torque_url": "https://arg.example.com", "torque_token": "arg-token", "torque_space": "ArgSpace",
    "torque_agent": "arg-agent", "host": "10.0.0.1", "user": "arg-user",
}

# value name in the recording -> (tool argument, profile YAML key, base _config key)
FIELDS = {
    "url": ("torque_url", "torque_url", "torque_url"),
    "token": ("torque_token", "torque_token", "torque_token"),
    "space": ("torque_space", "torque_space", "torque_space"),
    "agent": ("torque_agent", "torque_agent", "default_agent"),
    "host": ("host", "host", "default_target_ip"),
    "user": ("user", "ssh_user", "default_ssh_user"),
}

SSH_TOOLS = ["run_on_tunneled_ssh", "run_on_tunneled_ssh_async"]
CONTAINER_TOOLS = ["run_on_tunneled_persistent_container", "run_on_tunneled_persistent_container_async",
                   "run_on_tunneled_disposable_container", "run_on_tunneled_disposable_container_async"]
# The two endpoints of a transfer, each resolved like a run_on_tunneled_ssh call.
TRANSFER_ENDPOINTS = ["transfer-sender", "transfer-receiver"]
SSH_LIKE = SSH_TOOLS + TRANSFER_ENDPOINTS

# The side of a transfer that is NOT under test: explicit at every level that matters, on
# another agent, so it never depends on the case and the transfer takes the croc path.
OTHER_ENDPOINT = {
    # Its own (empty) profile, so a broken DEFAULT profile refuses only the side under test.
    "profile": "other-profile",
    "host": "10.8.8.8", "user": "other-user", "private_key": _key("other"),
    "torque_agent": "other-agent", "torque_url": "https://other.example.com",
    "torque_token": "other-token", "torque_space": "OtherSpace",
}
_ROLE_OF = {"transfer-sender": "send", "transfer-receiver": "receive"}

# Every non-empty set of levels a value is given at.
LEVEL_SETS = [s for n in (1, 2, 3) for s in itertools.combinations(("arg", "profile", "base"), n)]


@pytest.fixture(autouse=True)
def world(monkeypatch):
    Recorder.clients, Recorder.starts, Recorder.containers = [], [], []

    async def fake_container(**kw):
        Recorder.containers.append(kw)
        return {"container_ip": "172.17.0.5", "private_key": _key("container"),
                "environment_id": "pc-1", "container_id": "c", "agent": kw.get("agent")}

    monkeypatch.setattr(mcp_tool, "TorqueClient", FakeTorque)
    monkeypatch.setattr(mcp_tool, "_ensure_persistent_container", fake_container)
    monkeypatch.setattr(mcp_tool, "_start_background_streamer", lambda *a, **kw: None)
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {})
    monkeypatch.setattr(mcp_tool, "_croc_async_state", {})
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)
    monkeypatch.setattr(mcp_tool, "_loaded_config", {"profiles": {"other-profile": {}}})
    monkeypatch.setattr(mcp_tool, "TRANSFER_POLL_SECONDS", 0)
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config, init_commands=None, finally_commands=None,
        torque_url=None, torque_token=None, torque_space=None, default_agent=None,
        default_target_ip=None, default_ssh_user=None, default_ssh_key=None, default_ssh_password=None))


def _setup(base=None, profile=None):
    """Base config values, and a profile named 'p' (None: the call names no profile)."""
    mcp_tool._config.update(base or {})
    if profile is not None:
        mcp_tool._loaded_config["profiles"]["p"] = dict(profile)


async def _call(tool, args, profile=False):
    if tool in TRANSFER_ENDPOINTS:
        endpoint = dict(args, profile="p") if profile else dict(args)
        sides = ({"sender": endpoint, "receiver": dict(OTHER_ENDPOINT)} if tool == "transfer-sender"
                 else {"sender": dict(OTHER_ENDPOINT), "receiver": endpoint})
        result = await mcp_tool.call_tool("transfer_files_between_tunneled_hosts_async", {
            "command_description": "resolution", "files": [dict(TRANSFER_FILE)], **sides})
        return "\n".join(getattr(c, "text", "") for c in result or [])
    call_args = {"command": "true", "command_description": "resolution", **args}
    if profile:
        call_args["profile"] = "p"
    result = await mcp_tool.call_tool(tool, call_args)
    return "\n".join(getattr(c, "text", "") for c in result or [])


def _start_of(tool):
    """What the environment for `tool` was started with (for a transfer endpoint: that
    side's environment)."""
    assert Recorder.starts, f"{tool} never started an environment"
    if tool in TRANSFER_ENDPOINTS:
        mine = [s for s in Recorder.starts if s["role"] == _ROLE_OF[tool]]
        assert mine, f"{tool}: no {_ROLE_OF[tool]} environment in {Recorder.starts}"
        return mine[-1]
    return Recorder.starts[-1]


def _case(field, levels):
    arg_key, profile_key, base_key = FIELDS[field]
    base, profile, args = {}, None, {}
    expected = None
    for level in ("base", "profile", "arg"):            # lowest first: the last one set wins
        if level not in levels:
            continue
        if level == "base":
            base[base_key] = BASE[base_key]
            expected = BASE[base_key]
        elif level == "profile":
            profile = {profile_key: PROFILE[profile_key]}
            expected = PROFILE[profile_key]
        else:
            args[arg_key] = ARGS[arg_key]
            expected = ARGS[arg_key]
    if "base" not in levels:
        base[base_key] = None                           # really absent at the base level
    if profile is None and "profile" not in levels:
        profile = {}                                    # the call still names a profile
    return base, profile, args, expected


def _apply_case(base, profile, args, field):
    """`_complete` without overriding the field under test's base value."""
    base_key = FIELDS[field][2]
    for key, value in BASE.items():
        if key != base_key:
            base.setdefault(key, value)
    return base


# ============================================================================
# Connection, agent, host, user: argument > profile > base config
# ============================================================================

RESOLUTION_CASES = [
    (tool, field, levels, named)
    for tool in SSH_LIKE + CONTAINER_TOOLS
    for field in FIELDS
    if tool in SSH_LIKE or field not in ("host", "user")     # container tools have no SSH target
    for levels in LEVEL_SETS
    for named in ((True, False) if "profile" not in levels else (True,))
]


@pytest.mark.parametrize("tool,field,levels,named", RESOLUTION_CASES,
                         ids=[f"{t}-{f}-{'+'.join(l)}-{'profile' if n else 'no profile'}"
                              for t, f, l, n in RESOLUTION_CASES])
@pytest.mark.asyncio
async def test_each_value_comes_from_the_highest_level_that_gives_it(tool, field, levels, named):
    base, profile, args, expected = _case(field, levels)
    _setup(_apply_case(base, profile, args, field), profile if named else None)

    await _call(tool, args, profile=named)

    start = _start_of(tool)
    assert start[field] == expected, start


@pytest.mark.parametrize("tool", SSH_LIKE + CONTAINER_TOOLS)
@pytest.mark.asyncio
async def test_a_profile_with_no_config_file_loaded_is_ignored(tool, monkeypatch):
    monkeypatch.setattr(mcp_tool, "_loaded_config", {})
    _setup(dict(BASE))
    await _call(tool, {}, profile=True)
    assert _start_of(tool)["url"] == BASE["torque_url"]
    assert _start_of(tool)["agent"] == BASE["default_agent"]


@pytest.mark.parametrize("tool", SSH_LIKE + CONTAINER_TOOLS)
@pytest.mark.asyncio
async def test_an_unknown_profile_is_an_error_before_anything_starts(tool):
    _setup(dict(BASE))
    text = await _call(tool, {"profile": "nope"})
    assert "nope" in text
    assert Recorder.starts == []


@pytest.mark.parametrize("tool", SSH_LIKE + CONTAINER_TOOLS)
@pytest.mark.asyncio
async def test_a_broken_default_profile_refuses_a_call_without_a_profile(tool, monkeypatch):
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", "Profile 'gone' not found.")
    _setup(dict(BASE))
    text = await _call(tool, {})
    assert "gone" in text
    assert Recorder.starts == []


@pytest.mark.parametrize("tool", SSH_LIKE)
@pytest.mark.asyncio
async def test_a_profile_extending_another_resolves_through_the_chain(tool):
    _setup(dict(BASE))
    mcp_tool._loaded_config["profiles"]["parent"] = {"host": "10.9.9.9", "torque_agent": "parent-agent"}
    mcp_tool._loaded_config["profiles"]["p"] = {"extends": "parent", "ssh_user": "child-user"}
    await _call(tool, {}, profile=True)
    start = _start_of(tool)
    assert (start["host"], start["user"], start["agent"]) == ("10.9.9.9", "child-user", "parent-agent")


# ============================================================================
# SSH authentication: the arguments' pair, else the configured pair - never mixed
# ============================================================================

AUTH_CASES = [
    # (name, base key/password, profile key/password, argument key/password, expected key/password)
    ("arg key wins over everything", ("base", None), ("profile", None), ("arg", None), ("arg", "")),
    ("arg password drops every key", ("base", None), ("profile", None), (None, "arg-pw"), ("", "arg-pw")),
    ("arg key drops a profile password", (None, None), (None, "profile-pw"), ("arg", None), ("arg", "")),
    ("arg key drops a base password", (None, "base-pw"), (None, None), ("arg", None), ("arg", "")),
    ("profile key over base key", ("base", None), ("profile", None), (None, None), ("profile", "")),
    ("profile key clears a base password", (None, "base-pw"), ("profile", None), (None, None), ("profile", "")),
    ("profile password clears a base key", ("base", None), (None, "profile-pw"), (None, None), ("", "profile-pw")),
    ("base key alone", ("base", None), (None, None), (None, None), ("base", "")),
    ("base password alone", (None, "base-pw"), (None, None), (None, None), ("", "base-pw")),
]


@pytest.mark.parametrize("tool", SSH_LIKE)
@pytest.mark.parametrize("name,base_auth,profile_auth,arg_auth,expected", AUTH_CASES,
                         ids=[c[0] for c in AUTH_CASES])
@pytest.mark.asyncio
async def test_ssh_auth_resolution(tool, name, base_auth, profile_auth, arg_auth, expected):
    base = dict(BASE, default_ssh_key=_key(base_auth[0]) if base_auth[0] else None,
                default_ssh_password=base_auth[1])
    profile = {}
    if profile_auth[0]:
        profile["ssh_key"] = _key(profile_auth[0])
    if profile_auth[1]:
        profile["ssh_password"] = profile_auth[1]
    args = {}
    if arg_auth[0]:
        args["private_key"] = _key(arg_auth[0])
    if arg_auth[1]:
        args["password"] = arg_auth[1]
    _setup(base, profile)

    await _call(tool, args, profile=True)

    start = _start_of(tool)
    expected_key = _normalized(_key(expected[0])) if expected[0] else ""
    assert (start["key"], start["password"]) == (expected_key, expected[1])


@pytest.mark.parametrize("tool", SSH_LIKE)
@pytest.mark.asyncio
async def test_no_auth_anywhere_is_refused(tool):
    _setup(dict(BASE, default_ssh_key=None, default_ssh_password=None), {})
    text = await _call(tool, {}, profile=True)
    assert "Missing authentication" in text
    assert Recorder.starts == []


@pytest.mark.parametrize("tool", SSH_LIKE)
@pytest.mark.asyncio
async def test_no_host_anywhere_is_refused(tool):
    _setup(dict(BASE, default_target_ip=None), {})
    text = await _call(tool, {}, profile=True)
    assert "Need host and user" in text
    assert Recorder.starts == []


# ============================================================================
# The three forms of a key, at each level
# ============================================================================

def _key_forms(tmp_path):
    content = _key("formtest")
    path = tmp_path / "id_test"
    path.write_text(content + "\n", encoding="utf-8")
    return {
        "content": content,
        "single-line content": content.replace("\n", " "),
        "base64": base64.b64encode(content.encode()).decode(),
        "path": str(path),
        "~ path": None,          # filled per test (needs a HOME)
    }


@pytest.mark.parametrize("form", ["content", "single-line content", "base64", "path", "~ path"])
@pytest.mark.parametrize("level", ["arg", "profile", "base"])
@pytest.mark.parametrize("tool", SSH_LIKE)
@pytest.mark.asyncio
async def test_a_key_in_any_form_at_any_level_resolves_to_the_same_key(tool, level, form, tmp_path, monkeypatch):
    forms = _key_forms(tmp_path)
    if form == "~ path":
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        forms[form] = "~/id_test"
    value = forms[form]
    base = dict(BASE, default_ssh_key=value if level == "base" else None)
    profile = {"ssh_key": value} if level == "profile" else {}
    args = {"private_key": value} if level == "arg" else {}
    _setup(base, profile)

    await _call(tool, args, profile=True)

    assert _start_of(tool)["key"] == _normalized(_key("formtest"))


@pytest.mark.parametrize("tool", SSH_LIKE)
@pytest.mark.asyncio
async def test_a_value_that_is_no_key_in_any_form_is_refused(tool):
    _setup(dict(BASE), {})
    text = await _call(tool, {"private_key": "not-a-key-and-no-such-file"}, profile=True)
    assert "Invalid private_key" in text
    assert Recorder.starts == []


# ============================================================================
# Persistent-container tools: the container is chosen with the same connection
# ============================================================================

@pytest.mark.parametrize("tool", ["run_on_tunneled_persistent_container",
                                  "run_on_tunneled_persistent_container_async"])
@pytest.mark.asyncio
async def test_the_persistent_container_is_looked_up_with_the_resolved_values(tool):
    _setup(dict(BASE), dict(PROFILE))
    await _call(tool, {"environment_id": "pc-1", "torque_agent": "arg-agent"}, profile=True)

    looked_up = Recorder.containers[-1]
    assert looked_up["agent"] == "arg-agent"
    assert looked_up["environment_id"] == "pc-1"
    assert looked_up["config"]["torque_url"] == PROFILE["torque_url"]
    # The command runs SSH'd into that container, as root, with its key
    start = Recorder.starts[-1]
    assert (start["host"], start["user"]) == ("172.17.0.5", "root")
    assert start["key"].startswith("-----BEGIN") and "container" in start["key"]


@pytest.mark.parametrize("tool", TRANSFER_ENDPOINTS)
@pytest.mark.parametrize("levels", [("base",), ("profile", "base"), ("arg", "profile", "base")],
                         ids=lambda s: "+".join(s))
@pytest.mark.asyncio
async def test_a_persistent_container_endpoint_resolves_agent_and_connection_like_the_tools(tool, levels):
    """Only finding the container differs (it must exist and run: a transfer never creates
    one); the agent and the Torque connection resolve exactly as for the other tools."""
    for field in ("agent", "url"):
        Recorder.starts.clear()
        base, profile, args, expected = _case(field, levels)
        _setup(_apply_case(base, profile, args, field), profile)
        await _call(tool, dict(args, type="persistent_container", environment_id="pc-1"), profile=True)
        start = _start_of(tool)
        assert start[field] == expected, (field, start)
        assert (start["host"], start["user"]) == ("172.17.0.9", "root")
