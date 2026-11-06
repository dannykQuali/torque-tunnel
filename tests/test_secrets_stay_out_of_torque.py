"""Secrets reach the grain only through sensitive inputs and `env-vars`, never through text.

Torque echoes a grain's whole rendered script into its log ("Executing command: ...")
and shows every input that is not `sensitive: true` to anyone who can read the space.
So a secret written into the script, or into a command carried by an ordinary input
(container_pre_commands_b64, download_commands_b64, ...), is stored in Torque for anyone
in the space to read. That is how SSH keys ended up in Torque logs.

The rule these tests pin down: every secret torque-tunnel hands to an environment - the
target's SSH key or password, a second machine's (the transfer tool's direct copy), the
croc codes and the croc relay password - is sent ONLY as a sensitive input that the
grain's `env-vars` turns into an environment variable. Torque was verified (2026-11-06)
to keep such a value, multi-line or not, out of both its log and its API.

The checks look at what Torque would actually store and print: the create payload the
real TorqueClient sends, with the blueprint rendered the way Torque renders it.
"""

import base64
import gzip
import itertools
import os
import re
import secrets
import sys
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, mcp_tool
from torque_tunnel.torque_client import EnvironmentResult, TorqueClient

import _bash_harness as bh
from _bash_harness import needs_bash


def _key(tag):
    body = [base64.b64encode(f"{tag}-key-line-{n}-".encode() * 2).decode() for n in (1, 2)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(body) + "\n-----END OPENSSH PRIVATE KEY-----\n"


KEY = _key("target")
AUX_KEY = _key("second-machine")
CONTAINER_KEY = _key("persistent-container")
PASSWORD = "target-password-Zx81"
AUX_PASSWORD = "second-password-Qq40"
RELAY_PASSWORD = "relay-password-Kk27"


def _pieces(secret: str) -> list[str]:
    """What must not leak: the value, and for a key each of its body lines (a log shows
    a multi-line value line by line). The BEGIN/END armour lines are not secret."""
    lines = [l for l in secret.splitlines() if l and not l.startswith("-----")]
    return [secret.strip()] + lines


# --- how Torque sees a create payload ---------------------------------------------------

_INPUT_REF = re.compile(r"\{\{\s*\.inputs\.(\w+)\s*\}\}")


def _decode(value: str) -> str:
    try:
        return gzip.decompress(base64.b64decode(value)).decode("utf-8", "replace")
    except Exception:
        return ""


def torque_view(payload: dict) -> SimpleNamespace:
    """The blueprint, the rendered script Torque echoes, the env-vars it sets, and the
    texts anyone in the space can read (non-sensitive inputs, decoded too)."""
    text = base64.b64decode(payload["base64_standalone_blueprint"]).decode("utf-8")
    blueprint = yaml.safe_load(text)
    inputs = payload["inputs"]
    sensitive = {n for n, spec in blueprint["inputs"].items() if (spec or {}).get("sensitive")}

    def render(template):
        return _INPUT_REF.sub(lambda m: str(inputs.get(m.group(1), "")), template)

    spec = next(iter(blueprint["grains"].values()))["spec"]
    script = render(spec["activities"]["deploy"]["commands"][0]["command"])
    env = {k: render(v) for entry in spec.get("env-vars") or [] for k, v in entry.items()}
    public = []
    for name, value in inputs.items():
        if name not in sensitive:
            public += [str(value), _decode(str(value))]
    return SimpleNamespace(text=text, blueprint=blueprint, inputs=inputs, sensitive=sensitive,
                           script=script, env=env, public=public)


def assert_kept_out(payload: dict, *values: str) -> None:
    view = torque_view(payload)
    for value in values:
        for piece in _pieces(value):
            assert piece not in view.script, f"a secret is in the script Torque echoes: {piece[:20]}"
            assert piece not in view.text, f"a secret is in the blueprint: {piece[:20]}"
            for text in view.public:
                assert piece not in text, f"a secret is in an input anyone can read: {piece[:20]}"


def assert_delivered(payload: dict, *values: str) -> None:
    env = torque_view(payload).env.values()
    for value in values:
        assert value in env, f"a secret the script needs is not delivered: {value[:20]}"


# --- 1. the blueprint contract ------------------------------------------------------------

BLUEPRINTS = [("remote-shell-executor", False), ("remote-shell-executor", True),
              ("local-shell-executor", False), ("local-shell-executor", True)]


@pytest.mark.parametrize("name,credential", BLUEPRINTS)
def test_every_sensitive_input_reaches_the_grain_only_through_env_vars(name, credential):
    text = base64.b64decode(TorqueClient._load_standalone_blueprint(name, credential)).decode()
    blueprint = yaml.safe_load(text)
    sensitive = [n for n, s in blueprint["inputs"].items() if (s or {}).get("sensitive")]
    assert sensitive
    spec = next(iter(blueprint["grains"].values()))["spec"]
    env_values = [v for entry in spec.get("env-vars") or [] for v in entry.values()]
    for name_ in sensitive:
        refs = re.findall(r"\{\{\s*\.inputs\." + name_ + r"\s*\}\}", text)
        assert len(refs) == 1, f"{name_} is referenced {len(refs)} times; only env-vars may use it"
        assert any(_INPUT_REF.fullmatch(v.strip()) and name_ in v for v in env_values), name_


@pytest.mark.parametrize("name", ["remote-shell-executor", "local-shell-executor"])
def test_croc_secrets_are_sensitive_inputs(name):
    blueprint = yaml.safe_load(base64.b64decode(TorqueClient._load_standalone_blueprint(name, False)))
    inputs = blueprint["inputs"]
    for name_ in ("croc_receive_code", "croc_send_code", "croc_relay_password"):
        assert inputs[name_].get("sensitive") is True
        assert inputs[name_].get("default") == ""


def test_ssh_secrets_of_both_machines_are_sensitive_inputs():
    inputs = yaml.safe_load(base64.b64decode(
        TorqueClient._load_standalone_blueprint("remote-shell-executor", False)))["inputs"]
    for name in ("ssh_private_key", "ssh_password", "aux_ssh_private_key", "aux_ssh_password"):
        assert inputs[name].get("sensitive") is True
        assert inputs[name].get("default") == ""


# --- 2. what the real TorqueClient sends ------------------------------------------------

class CapturingClient(TorqueClient):
    """The real client, with environment creation captured instead of sent."""

    payloads: list = []
    logs: dict = {}

    def __init__(self, base_url="https://torque.example", token="t", space="S", **kw):
        super().__init__(base_url=base_url, token=token, space=space, **kw)

    async def _create_environment_idempotent(self, payload, key):
        CapturingClient.payloads.append(payload)
        return f"env-{len(CapturingClient.payloads)}"

    async def wait_for_environment(self, environment_id, timeout=None, log_callback=None):
        return EnvironmentResult(environment_id=environment_id, status="completed",
                                 command_output="", exit_code=0)

    async def get_environment_status(self, environment_id, retry=True):
        return {"details": {"computed_status": "Deploying", "state": {"errors": []}}}

    async def get_grain_log(self, environment_id):
        return CapturingClient.logs.get(environment_id, "")

    async def set_scheduled_end_time(self, *a, **kw):
        return None

    async def end_environment(self, *a, **kw):
        return None

    async def release_environment(self, *a, **kw):
        return None

    async def delete_environment(self, *a, **kw):
        return None

    async def fetch_credentials(self):
        return []


@pytest.mark.asyncio
async def test_ssh_environment_payload_keeps_every_secret_out():
    CapturingClient.payloads = []
    client = CapturingClient(default_agent="agent")
    await client.start_environment(
        target_ip="10.0.0.1", ssh_user="root", ssh_private_key=KEY, command="true",
        container_pre_commands="echo pre", download_commands="echo dl",
        aux_ssh_private_key=AUX_KEY, aux_ssh_password=AUX_PASSWORD,
        croc_receive_code="receive-code-1234", croc_send_code="send-code-5678",
        croc_relay_password=RELAY_PASSWORD)
    payload = CapturingClient.payloads[0]
    secrets_ = (KEY, AUX_KEY, AUX_PASSWORD, "receive-code-1234", "send-code-5678", RELAY_PASSWORD)
    assert_kept_out(payload, *secrets_)
    assert_delivered(payload, *secrets_)


@pytest.mark.asyncio
async def test_ssh_environment_payload_keeps_a_password_out():
    CapturingClient.payloads = []
    client = CapturingClient(default_agent="agent")
    await client.start_environment(target_ip="10.0.0.1", ssh_user="root",
                                   ssh_password=PASSWORD, command="true")
    assert_kept_out(CapturingClient.payloads[0], PASSWORD)
    assert_delivered(CapturingClient.payloads[0], PASSWORD)


@pytest.mark.asyncio
async def test_container_environment_payload_keeps_every_secret_out():
    CapturingClient.payloads = []
    client = CapturingClient(default_agent="agent")
    await client.start_local_environment(
        command="true", download_commands="echo dl",
        croc_receive_code="receive-code-1234", croc_send_code="send-code-5678",
        croc_relay_password=RELAY_PASSWORD)
    payload = CapturingClient.payloads[0]
    secrets_ = ("receive-code-1234", "send-code-5678", RELAY_PASSWORD)
    assert_kept_out(payload, *secrets_)
    assert_delivered(payload, *secrets_)


@pytest.mark.asyncio
async def test_multi_line_values_are_delivered_byte_for_byte():
    """Torque passes multi-line sensitive inputs through env-vars unchanged (verified with
    LF, CRLF and a trailing newline); the client must not alter them either."""
    CapturingClient.payloads = []
    crlf_key = KEY.replace("\n", "\r\n")
    await CapturingClient(default_agent="agent").start_environment(
        target_ip="10.0.0.1", ssh_user="root", ssh_private_key=crlf_key, command="true")
    assert crlf_key in torque_view(CapturingClient.payloads[0]).env.values()


# --- 3. every tool, end to end ------------------------------------------------------------

CODES: list = []


@pytest.fixture
def tools(monkeypatch):
    CapturingClient.payloads = []
    CapturingClient.logs = {}
    CODES.clear()
    counter = itertools.count(1)

    def fake_code():
        code = f"{next(counter)}-croc-code-{secrets.token_hex(8)}"
        CODES.append(code)
        return code

    async def fake_send(plan):
        return SimpleNamespace(returncode=0)

    async def fake_receive(plan, command_timeout=None):
        return SimpleNamespace(returncode=0)

    async def fake_container(**kw):
        return {"container_ip": "172.17.0.5", "private_key": CONTAINER_KEY,
                "environment_id": "container-env", "container_id": "c", "agent": "agent"}

    monkeypatch.setattr(croc_manager, "generate_croc_code", fake_code)
    monkeypatch.setattr(mcp_tool, "TorqueClient", CapturingClient)
    monkeypatch.setattr(mcp_tool, "execute_with_croc", fake_send)
    monkeypatch.setattr(mcp_tool, "execute_download_receive", fake_receive)
    monkeypatch.setattr(mcp_tool, "_ensure_persistent_container", fake_container)
    monkeypatch.setattr(mcp_tool, "_start_background_streamer", lambda *a, **kw: None)
    monkeypatch.setattr(mcp_tool, "_croc_async_state", {})
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {})
    monkeypatch.setattr(mcp_tool, "_persistent_containers", {})
    monkeypatch.setattr(mcp_tool, "TRANSFER_POLL_SECONDS", 0)
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config,
        torque_url="https://torque.example", torque_token="t", torque_space="S",
        default_agent="agent", default_ssh_key=None, default_ssh_password=None,
        default_target_ip=None, default_ssh_user=None, init_commands=None,
        finally_commands=None, croc_relay="relay.example:9009",
        croc_relay_password=RELAY_PASSWORD, croc_transfers=None,
        auto_delete_environments=False,
    ))
    monkeypatch.setattr(mcp_tool, "_loaded_config", {})
    monkeypatch.setattr(mcp_tool, "_config_error", None)
    monkeypatch.setattr(mcp_tool, "_default_profile_warning", None)


TRANSFERS = {
    # Incompressible enough to exceed the inline budget, so croc is used.
    "upload_files": [{"content": secrets.token_hex(400_000), "remote_destination_path": "/tmp/big"}],
    "download_files": [{"remote_source_path": "/tmp/x", "local_destination_path": "C:\\tmp\\x"}],
}

RUN_TOOLS = [
    ("run_on_tunneled_ssh", {"host": "10.0.0.1", "user": "root", "private_key": KEY}, KEY),
    ("run_on_tunneled_ssh_async", {"host": "10.0.0.1", "user": "root", "private_key": KEY}, KEY),
    ("run_on_tunneled_ssh", {"host": "10.0.0.1", "user": "root", "password": PASSWORD}, PASSWORD),
    ("run_on_tunneled_ssh_async", {"host": "10.0.0.1", "user": "root", "password": PASSWORD}, PASSWORD),
    ("run_on_tunneled_persistent_container", {}, CONTAINER_KEY),
    ("run_on_tunneled_persistent_container_async", {}, CONTAINER_KEY),
    ("run_on_tunneled_disposable_container", {}, None),
    ("run_on_tunneled_disposable_container_async", {}, None),
]


@pytest.mark.parametrize("tool,extra,auth", RUN_TOOLS,
                         ids=[f"{t}-{'password' if a == PASSWORD else 'key' if a else 'none'}"
                              for t, _, a in RUN_TOOLS])
@pytest.mark.asyncio
async def test_run_tools_with_uploads_and_downloads_keep_every_secret_out(tools, tool, extra, auth):
    await mcp_tool.call_tool(tool, {"command": "echo hi", "command_description": "secrets check",
                                    **extra, **TRANSFERS})
    assert CapturingClient.payloads, "no environment was created"
    assert len(CODES) == 2, "expected one croc code for the upload and one for the download"
    secrets_ = [*CODES, RELAY_PASSWORD] + ([auth] if auth else [])
    for payload in CapturingClient.payloads:
        assert_kept_out(payload, *secrets_)
    assert_delivered(CapturingClient.payloads[-1], *secrets_)


def _sender_ready_log():
    return "\n".join([f"{croc_manager.CROC_SENTINEL_SIZE} 10 _croc_rl_0_f",
                      f"{croc_manager.CROC_SENTINEL_MD5} {'0' * 32} _croc_rl_0_f",
                      croc_manager.CROC_SENTINEL_READY]) + "\n"


def _endpoint(host, **auth):
    return {"type": "ssh", "host": host, "user": "root", **auth}


@pytest.mark.parametrize("auth,aux", [
    ({"private_key": KEY}, {"private_key": AUX_KEY}),
    ({"password": PASSWORD}, {"password": AUX_PASSWORD}),
], ids=["keys", "passwords"])
@pytest.mark.asyncio
async def test_transfer_between_machines_keeps_every_secret_out(tools, monkeypatch, auth, aux):
    """Two agents: a sender environment and a receiver environment, linked by croc."""
    monkeypatch.setattr(mcp_tool, "_loaded_config", {"profiles": {
        "a": {"torque_url": "https://torque.example", "torque_space": "S", "torque_agent": "agent-a"},
        "b": {"torque_url": "https://torque.example", "torque_space": "S", "torque_agent": "agent-b"},
    }})
    CapturingClient.logs = {"env-1": _sender_ready_log()}
    sender = {**_endpoint("10.0.0.1", **aux), "profile": "a"}
    receiver = {**_endpoint("10.9.9.9", **auth), "profile": "b"}
    await mcp_tool.call_tool("transfer_files_between_tunneled_hosts_async", {
        "command_description": "copy", "sender": sender, "receiver": receiver,
        "files": [{"source_path": "/data/f", "destination_path": "/dst/f"}]})

    assert len(CapturingClient.payloads) == 2, "expected a sender and a receiver environment"
    secrets_ = [*CODES, RELAY_PASSWORD, *auth.values(), *aux.values()]
    for payload in CapturingClient.payloads:
        assert_kept_out(payload, *secrets_)
    send_env, receive_env = CapturingClient.payloads
    assert_delivered(send_env, *aux.values(), *CODES)
    assert_delivered(receive_env, *auth.values(), *CODES)


@pytest.mark.parametrize("auth,aux", [
    ({"private_key": KEY}, {"private_key": AUX_KEY}),
    ({"password": PASSWORD}, {"password": AUX_PASSWORD}),
], ids=["keys", "passwords"])
@pytest.mark.asyncio
async def test_direct_copy_keeps_both_machines_secrets_out(tools, auth, aux):
    """One agent: one environment that reaches both machines over SSH."""
    await mcp_tool.call_tool("transfer_files_between_tunneled_hosts_async", {
        "command_description": "copy", "sender": _endpoint("10.0.0.1", **aux),
        "receiver": _endpoint("10.0.0.2", **auth),
        "files": [{"source_path": "/data/f", "destination_path": "/dst/f"}]})

    assert len(CapturingClient.payloads) == 1, "expected one direct-copy environment"
    payload = CapturingClient.payloads[0]
    assert_kept_out(payload, *auth.values(), *aux.values())
    assert_delivered(payload, *auth.values(), *aux.values())


# --- 4. the rendered script still works, with its secrets from the environment ---------

# The target: consume the remote script without running it, record how ssh was called.
FAKE_SSH = r"""#!/bin/bash
echo "ssh $*" >> "$FAKE_DIR/ssh_calls"
for a in "$@"; do
  if [ "$prev" = "-i" ]; then cat "$a" > "$FAKE_DIR/key_used"; fi
  prev="$a"
done
printf '%s' "${SSHPASS:-}" > "$FAKE_DIR/sshpass_env"
cat > /dev/null
echo "remote said: $(echo "$REMOTE_ECHO")"
exit 0
"""

FAKE_SSHPASS = r"""#!/bin/bash
echo "sshpass $*" >> "$FAKE_DIR/sshpass_calls"
shift  # -e
exec "$@"
"""

FAKE_TIMEOUT_FUNC = r"""timeout() {
  shift 1
  "$@"
}
"""


@needs_bash
class TestTheRenderedScriptRuns:
    @pytest.fixture
    def run(self, tmp_path):
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        bh.make_executable(fake_bin / "ssh", FAKE_SSH)
        bh.make_executable(fake_bin / "sshpass", FAKE_SSHPASS)

        async def run(command="true", pre="", **kw):
            CapturingClient.payloads = []
            await CapturingClient(default_agent="agent").start_environment(
                target_ip="10.9.9.9", ssh_user="root", command=command,
                container_pre_commands=pre or None, **kw)
            view = torque_view(CapturingClient.payloads[0])
            script = tmp_path / "grain.sh"
            bh.write_text(script, f'export PATH="{bh.shell_path(fake_bin)}:$PATH"\n'
                                  + FAKE_TIMEOUT_FUNC + view.script + "\n")
            proc = bh.run_script(script, env={"FAKE_DIR": control, **view.env})
            return proc, control

        return run

    @pytest.mark.asyncio
    async def test_key_auth_uses_the_key_from_the_environment(self, run):
        proc, control = await run(ssh_private_key=KEY)
        assert "Command completed with exit code: 0" in proc.stdout, proc.stdout + proc.stderr
        assert (control / "key_used").read_text().replace("\r\n", "\n") == KEY

    @pytest.mark.asyncio
    async def test_a_key_without_its_final_newline_gets_one(self, run):
        """ssh rejects some key formats without the final newline; the old heredoc
        always added one."""
        proc, control = await run(ssh_private_key=KEY.rstrip("\n"))
        assert (control / "key_used").read_text().replace("\r\n", "\n") == KEY

    @pytest.mark.asyncio
    async def test_password_auth_passes_the_password_through_the_environment(self, run):
        proc, control = await run(ssh_password=PASSWORD)
        assert "Command completed with exit code: 0" in proc.stdout, proc.stdout + proc.stderr
        assert PASSWORD not in (control / "sshpass_calls").read_text()  # not in argv
        assert (control / "sshpass_env").read_text() == PASSWORD

    @pytest.mark.asyncio
    async def test_no_key_and_no_password_is_an_error(self, run):
        proc, control = await run()
        assert "Command completed with exit code: 1" in proc.stdout, proc.stdout + proc.stderr
        assert not (control / "ssh_calls").exists()

    @pytest.mark.asyncio
    async def test_the_persistent_container_blueprint_still_prints_its_key(self, run):
        """By design: later clients read the container's key from that environment's
        log. Only the executor blueprints changed."""
        text = base64.b64decode(TorqueClient._load_standalone_blueprint(
            TorqueClient.PERSISTENT_CONTAINER_BLUEPRINT, False)).decode()
        assert "TORQUE_TUNNEL::KEY_START" in text
        assert "__TT_OWN_SECRETS" not in text and "__tt_filter" not in text

    @pytest.mark.asyncio
    async def test_secrets_printed_by_setup_or_command_are_masked(self, run):
        """A command that prints a secret the environment holds must not put it in the
        log: setup output, command output and the returned output are all masked."""
        body_line = [l for l in KEY.splitlines() if not l.startswith("-----")][0]
        proc, control = await run(
            ssh_private_key=KEY, croc_relay_password=RELAY_PASSWORD,
            pre='echo "pre: $TT_CROC_RELAY_PASSWORD"; printf "%s\\n" "$TT_SSH_PRIVATE_KEY"')
        out = proc.stdout + proc.stderr
        assert "pre: ***" in out, out
        assert RELAY_PASSWORD not in out
        assert body_line not in out
        assert "-----BEGIN OPENSSH PRIVATE KEY-----" in out  # the armour is not secret


# --- 5. the masking filter streams ---------------------------------------------------------

def _redactor(name):
    command = torque_view({"inputs": {}, "base64_standalone_blueprint":
                           TorqueClient._load_standalone_blueprint(name, False)}).script
    _, _, rest = command.partition("<<'__TT_REDACT_EOF'\n")
    return rest.partition("\n__TT_REDACT_EOF")[0]


SECRET = "SECRET-VALUE-0123456789"


@needs_bash
@pytest.mark.parametrize("name", ["remote-shell-executor", "local-shell-executor"])
class TestTheMaskingFilterStreams:
    """It runs on every command now, not only with a credential, so it must not hold
    back output that has no line break yet (croc's progress bars redraw with \\r)."""

    def _run(self, tmp_path, name, producer):
        py = tmp_path / "redact.py"
        bh.write_text(py, _redactor(name))
        out = tmp_path / "out.txt"
        script = tmp_path / "run.sh"
        # `seen <text>`: wait (at most 2s) for the filter to pass <text> on while the
        # producer is still running, and report whether it did.
        bh.write_text(script, f"""
OUT={bh.shell_path(out)}
: > "$OUT"
seen() {{ for i in $(seq 1 40); do grep -q -- "$1" "$OUT" && {{ echo "SEEN $1" >&2; return; }}; sleep 0.05; done; echo "MISSED $1" >&2; }}
{{ {producer}; }} | python3 -u {bh.shell_path(py)} > "$OUT"
cat "$OUT"
""")
        return bh.run_script(script, env={"__TT_OWN_SECRETS": "TT_CROC_RELAY_PASSWORD",
                                          "TT_CROC_RELAY_PASSWORD": SECRET})

    def test_a_progress_bar_and_a_prompt_pass_through_at_once(self, tmp_path, name):
        proc = self._run(tmp_path, name,
                         "printf 'x  50%% |##  |\\r'; seen '50%'; printf 'Password: '; seen 'Password'; echo")
        assert "SEEN 50%" in proc.stderr, proc.stderr
        assert "SEEN Password" in proc.stderr, proc.stderr

    def test_a_secret_split_across_writes_is_still_masked(self, tmp_path, name):
        proc = self._run(tmp_path, name,
                         "printf 'abc-SECRET-VAL'; sleep 0.4; printf 'UE-0123456789 end\\n'")
        assert proc.stdout.strip() == "abc-*** end", proc.stdout
        assert "SECRET-VAL" not in proc.stdout
