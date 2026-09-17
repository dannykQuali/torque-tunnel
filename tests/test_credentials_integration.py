"""Credential support end-to-end-ish tests: blueprints, redactor, and orchestration.

These exercise the real artifacts — the shipped blueprint YAML and the redactor script that
actually runs in the grain — rather than reimplementations of them.
"""

import base64
import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import credentials as creds
from torque_tunnel.torque_client import TorqueClient, _interpret_discovery_outputs


REPO = Path(__file__).resolve().parent.parent
BLUEPRINTS = REPO / "blueprints"
EXECUTORS = ["local-shell-executor", "remote-shell-executor"]

GRAIN_OF = {
    "local-shell-executor": "local_executor",
    "remote-shell-executor": "remote_executor",
}


def load_blueprint(name: str, with_credential: bool) -> dict:
    encoded = TorqueClient._load_standalone_blueprint(name, with_credential)
    return yaml.safe_load(base64.b64decode(encoded).decode("utf-8"))


def grain_command(name: str, with_credential: bool) -> str:
    d = load_blueprint(name, with_credential)
    spec = d["grains"][GRAIN_OF[name]]["spec"]
    return spec["activities"]["deploy"]["commands"][0]["command"]


# ============================================================================
# Blueprint anchors
# ============================================================================

@pytest.mark.parametrize("name", EXECUTORS)
def test_blueprint_is_valid_yaml_with_and_without_a_credential(name):
    assert load_blueprint(name, False)
    assert load_blueprint(name, True)


@pytest.mark.parametrize("name", EXECUTORS)
def test_no_credential_means_no_input_and_no_authentication(name):
    """Torque rejects an authentication entry that resolves to empty, so with no credential
    both the input and the block must be absent rather than blank."""
    d = load_blueprint(name, False)
    assert "credential" not in d["inputs"]
    assert "authentication" not in d["grains"][GRAIN_OF[name]]["spec"]


@pytest.mark.parametrize("name", EXECUTORS)
def test_credential_emits_a_credentials_typed_input_and_authentication(name):
    d = load_blueprint(name, True)
    assert d["inputs"]["credential"]["type"] == "credentials"
    assert d["grains"][GRAIN_OF[name]]["spec"]["authentication"] == [
        "{{ .inputs.credential }}"
    ]


@pytest.mark.parametrize("name", EXECUTORS)
def test_anchor_comments_never_survive_into_the_sent_yaml(name):
    for with_cred in (False, True):
        raw = base64.b64decode(
            TorqueClient._load_standalone_blueprint(name, with_cred)
        ).decode("utf-8")
        assert "__TT_CREDENTIAL_INPUT__" not in raw
        assert "__TT_CREDENTIAL_AUTH__" not in raw


@pytest.mark.parametrize("name", EXECUTORS)
def test_credential_context_input_is_always_present(name):
    """It is always sent (possibly empty), like ssh_private_key/ssh_password, so it must be
    declared whether or not a credential is attached."""
    for with_cred in (False, True):
        assert "credential_context_b64" in load_blueprint(name, with_cred)["inputs"]


@pytest.mark.parametrize("name", EXECUTORS)
def test_substitution_changes_nothing_else_in_the_file(name):
    """Anchor substitution is line-based text replacement; it must not disturb the several
    hundred lines of shell in the block scalars."""
    original = (BLUEPRINTS / f"{name}.yaml").read_text(encoding="utf-8")
    stripped = base64.b64decode(
        TorqueClient._load_standalone_blueprint(name, False)
    ).decode("utf-8")
    expected = "\n".join(
        l for l in original.split("\n")
        if l.strip() not in ("# __TT_CREDENTIAL_INPUT__", "# __TT_CREDENTIAL_AUTH__")
    )
    assert stripped == expected


# ============================================================================
# Blueprint wiring: redaction and forwarding
# ============================================================================

@pytest.mark.parametrize("name", EXECUTORS)
def test_execution_stream_goes_through_the_redaction_filter(name):
    """Redaction has to happen before `tee`, or the Torque UI log keeps the secret even
    though the returned output does not."""
    cmd = grain_command(name, True)
    assert "| __tt_filter | tee" in cmd
    assert "| tee \"$OUTPUT_FILE\"" not in cmd.replace("| __tt_filter | tee \"$OUTPUT_FILE\"", "")


@pytest.mark.parametrize("name", EXECUTORS)
def test_filter_degrades_to_cat_without_a_credential_or_python(name):
    cmd = grain_command(name, True)
    assert "__tt_filter() { cat; }" in cmd
    assert "command -v python3" in cmd


def test_remote_blueprint_forwards_named_vars_and_mgmt_server():
    cmd = grain_command("remote-shell-executor", True)
    # Values are read from the container's own environment, never sent by the caller.
    assert 'printf \'export %s=%q\\n\' "$__v" "${!__v}"' in cmd
    # MGMT_SERVER_* is forwarded by design - the existing blueprint contract.
    assert "grep '^MGMT_SERVER_'" in cmd


def test_local_blueprint_does_not_forward_anything():
    """The command runs in the same container, so there is nothing to forward - and no
    forwarding code means no chance of forwarding the wrong thing."""
    cmd = grain_command("local-shell-executor", True)
    assert "__TT_FORWARD_VARS" not in cmd


@pytest.mark.parametrize("name", EXECUTORS)
def test_temp_files_holding_credential_context_are_cleaned_up(name):
    cmd = grain_command(name, True)
    assert '"$__TT_CRED_CTX"' in cmd.split("rm -f")[-1]
    assert '"$__TT_REDACT_PY"' in cmd.split("rm -f")[-1]


# ============================================================================
# The redactor, run for real
# ============================================================================

def extract_redactor(name: str) -> str:
    """Pull the redactor out of the blueprint exactly as the grain writes it to disk."""
    cmd = grain_command(name, True)
    _, _, rest = cmd.partition("<<'__TT_REDACT_EOF'\n")
    body, _, _ = rest.partition("\n__TT_REDACT_EOF")
    assert body.strip(), "redactor heredoc not found"
    return body


def run_redactor(script: str, stdin: bytes, env: dict, ctx: dict, tmp_path: Path) -> bytes:
    ctx_file = tmp_path / "ctx.json"
    ctx_file.write_text(json.dumps(ctx), encoding="utf-8")
    py = tmp_path / "redact.py"
    py.write_text(script, encoding="utf-8")
    full_env = dict(os.environ)
    full_env.update(env)
    full_env["__TT_CRED_CTX"] = str(ctx_file)
    proc = subprocess.run(
        [sys.executable, "-u", str(py)], input=stdin, capture_output=True, env=full_env
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    return proc.stdout


@pytest.fixture(params=EXECUTORS)
def redactor(request):
    return extract_redactor(request.param)


VSPHERE_CTX = {
    "name": "vCenter-MX",
    "type": "vsphere__basic",
    "vars": ["VSPHERE_USER", "VSPHERE_PASSWORD", "VSPHERE_SERVER",
             "VSPHERE_ALLOW_UNVERIFIED_SSL"],
    "public_values": ["administrator@vsphere.local", "mx-lab-hxvcenter.cisco.com",
                      "false", "False"],
    "min_len": 8,
    "forward": [],
}
VSPHERE_ENV = {
    "VSPHERE_USER": "administrator@vsphere.local",
    "VSPHERE_PASSWORD": "sup3rSecretPassw0rd",
    "VSPHERE_SERVER": "mx-lab-hxvcenter.cisco.com",
    "VSPHERE_ALLOW_UNVERIFIED_SSL": "false",
}


def test_redactor_masks_the_secret(redactor, tmp_path):
    out = run_redactor(
        redactor, b"connecting with sup3rSecretPassw0rd now\n",
        VSPHERE_ENV, VSPHERE_CTX, tmp_path)
    assert b"sup3rSecretPassw0rd" not in out
    assert b"***" in out


def test_redactor_keeps_non_secret_values_readable(redactor, tmp_path):
    """The server and user come back from the API populated, so they are not secrets and
    masking them would make output useless for debugging."""
    out = run_redactor(
        redactor,
        b"host=mx-lab-hxvcenter.cisco.com user=administrator@vsphere.local\n",
        VSPHERE_ENV, VSPHERE_CTX, tmp_path)
    assert b"mx-lab-hxvcenter.cisco.com" in out
    assert b"administrator@vsphere.local" in out


def test_redactor_does_not_mangle_short_boolean_values(redactor, tmp_path):
    """`validate_certificate=false` must not turn every 'false' in the output into ***."""
    out = run_redactor(
        redactor, b"ssl_verify=false and other=false\n",
        VSPHERE_ENV, VSPHERE_CTX, tmp_path)
    assert out.count(b"false") == 2


def test_redactor_masks_every_occurrence_across_lines(redactor, tmp_path):
    payload = b"a sup3rSecretPassw0rd\nb sup3rSecretPassw0rd sup3rSecretPassw0rd\n"
    out = run_redactor(redactor, payload, VSPHERE_ENV, VSPHERE_CTX, tmp_path)
    assert b"sup3rSecretPassw0rd" not in out
    assert out.count(b"***") == 3


def test_redactor_warns_and_does_not_redact_when_the_cache_is_stale(redactor, tmp_path):
    """A stale variable list must be a visible error, not a silent pass-through."""
    ctx = dict(VSPHERE_CTX, vars=["VSPHERE_RENAMED_PASSWORD"])
    out = run_redactor(redactor, b"nothing secret here\n", VSPHERE_ENV, ctx, tmp_path)
    assert b"WARNING" in out
    assert b"NOT redacted" in out


def test_redactor_reports_values_it_skipped_for_length(redactor, tmp_path):
    ctx = dict(VSPHERE_CTX, vars=["VSPHERE_PASSWORD", "SHORTY"])
    env = dict(VSPHERE_ENV, SHORTY="abc")
    out = run_redactor(redactor, b"x\n", env, ctx, tmp_path)
    assert b"SHORTY" in out
    assert b"not redacted" in out


def test_redactor_passes_binary_through_without_crashing(redactor, tmp_path):
    """Command output is arbitrary bytes; a decoding error must not break execution."""
    payload = b"\xff\xfe not utf-8 sup3rSecretPassw0rd \x00\x01\n"
    out = run_redactor(redactor, payload, VSPHERE_ENV, VSPHERE_CTX, tmp_path)
    assert b"sup3rSecretPassw0rd" not in out
    assert b"\xff\xfe" in out


def test_redactor_masks_the_longest_secret_first(redactor, tmp_path):
    """A secret containing another must be masked whole, not left with a visible remainder."""
    ctx = dict(VSPHERE_CTX, vars=["A_SHORT", "B_LONG"], public_values=[])
    env = {"A_SHORT": "abcdefgh", "B_LONG": "abcdefgh-plus-more"}
    out = run_redactor(redactor, b"value=abcdefgh-plus-more\n", env, ctx, tmp_path)
    assert b"abcdefgh" not in out


def test_redactor_is_a_no_op_with_an_empty_context(redactor, tmp_path):
    out = run_redactor(redactor, b"hello sup3rSecretPassw0rd\n", VSPHERE_ENV, {}, tmp_path)
    assert out == b"hello sup3rSecretPassw0rd\n"


# ============================================================================
# Discovery
# ============================================================================

def make_client(**kw):
    c = TorqueClient("https://torque.example.com", "tok", kw.pop("space", "VMaaS"),
                     default_agent=kw.pop("agent", "agent-1"))
    return c


def test_discovery_blueprint_has_two_baselines_and_one_grain_per_type():
    c = make_client()
    text, slugs = c._build_discovery_blueprint(
        {"vsphere__basic": "vCenter-MX", "foo__new": "foo-cred"})
    d = yaml.safe_load(text)
    assert set(d["grains"]) == {"baseline_a", "baseline_b", *slugs.values()}
    for slug in slugs.values():
        assert d["grains"][slug]["spec"]["authentication"] == [f"{{{{ .inputs.{slug} }}}}"]
    assert "authentication" not in d["grains"]["baseline_a"]["spec"]


def test_a_small_discovery_run_is_fully_parallel():
    c = make_client()
    text, _ = c._build_discovery_blueprint({"a__t": "a", "b__t": "b"})
    d = yaml.safe_load(text)
    for grain in d["grains"].values():
        assert "depends-on" not in grain


def test_a_large_discovery_run_is_chained_into_waves():
    """An agent's runner pool is finite: launching eight grains at once left two wedged in
    Preparation on a live agent, so the run is capped at DISCOVERY_MAX_PARALLEL_GRAINS."""
    from torque_tunnel.torque_client import DISCOVERY_MAX_PARALLEL_GRAINS

    c = make_client()
    text, slugs = c._build_discovery_blueprint({f"t{i}__type": f"c{i}" for i in range(6)})
    d = yaml.safe_load(text)

    # Walk the dependency chain to work out how many grains can be running at once.
    waves: dict[str, int] = {}
    for name, grain in d["grains"].items():
        dep = grain.get("depends-on")
        waves[name] = dep
    depth = {}

    def wave_of(name):
        if name not in depth:
            dep = waves[name]
            depth[name] = 0 if not dep else wave_of(dep) + 1
        return depth[name]

    sizes = {}
    for name in d["grains"]:
        sizes[wave_of(name)] = sizes.get(wave_of(name), 0) + 1
    assert max(sizes.values()) <= DISCOVERY_MAX_PARALLEL_GRAINS
    # Both baselines are in the first wave: a missing baseline invalidates everything, so
    # they run where contention is lowest.
    assert wave_of("baseline_a") == 0 and wave_of("baseline_b") == 0


def test_discovery_grains_print_names_never_values():
    c = make_client()
    text, _ = c._build_discovery_blueprint({"a__t": "a"})
    d = yaml.safe_load(text)
    cmd = d["grains"]["baseline_a"]["spec"]["activities"]["deploy"]["commands"][0]["command"]
    assert "compgen -e" in cmd
    assert "printenv" not in cmd and "env |" not in cmd


def test_discovery_subtracts_the_baseline():
    slugs = {"vsphere__basic": "t0"}
    out = _interpret_discovery_outputs(
        {"baseline_a": "HOME PATH PWD SHLVL", "baseline_b": "HOME PATH PWD SHLVL",
         "t0": "HOME PATH PWD SHLVL VSPHERE_USER VSPHERE_PASSWORD"},
        slugs)
    assert out["vsphere__basic"] == {"status": creds.STATUS_OK,
                                     "vars": ["VSPHERE_PASSWORD", "VSPHERE_USER"]}


def test_discovery_excludes_names_that_differ_between_identical_baselines():
    """Two baselines exist precisely so per-grain noise — a RUNNER_INPUTS member, say —
    cannot be mistaken for a credential variable."""
    out = _interpret_discovery_outputs(
        {"baseline_a": "HOME NOISE_1", "baseline_b": "HOME NOISE_2",
         "t0": "HOME NOISE_3 REAL_VAR_NAME"},
        {"x__t": "t0"})
    assert out["x__t"]["vars"] == ["NOISE_3", "REAL_VAR_NAME"] or \
           out["x__t"]["vars"] == ["REAL_VAR_NAME", "NOISE_3"]
    # NOISE_1/NOISE_2 are gone because only the intersection counts as baseline.
    assert "NOISE_1" not in out["x__t"]["vars"]


def test_discovery_never_attributes_mgmt_server_or_api_token_to_a_credential():
    out = _interpret_discovery_outputs(
        {"baseline_a": "HOME", "baseline_b": "HOME",
         "t0": "HOME MGMT_SERVER_SSH_PRIVATE_KEY API_TOKEN FOO_KEY"},
        {"x__t": "t0"})
    assert out["x__t"]["vars"] == ["FOO_KEY"]


def test_a_failed_grain_is_never_recorded_as_unsupported():
    """A failed grain looks identical whether Torque cannot inject the type or the runner
    merely wedged — and the result is cached permanently. Observed live: vsphere__basic,
    used successfully all session, would have been branded unusable by its grain wedging."""
    out = _interpret_discovery_outputs(
        {"baseline_a": "HOME", "baseline_b": "HOME",
         "t0": "{{ .grains.t0.activities.deploy.commands.probe.outputs.env_names }}"},
        {"vsphere__basic": "t0"},
        {"baseline_a": "Deployed", "baseline_b": "Deployed", "t0": "DeployFailed"})
    assert "vsphere__basic" not in out


def test_partial_results_are_kept_when_one_grain_produces_nothing():
    out = _interpret_discovery_outputs(
        {"baseline_a": "HOME", "baseline_b": "HOME", "t0": "", "t1": "HOME NEW_VAR"},
        {"redhat": "t0", "other__type": "t1"},
        {"baseline_a": "Deployed", "baseline_b": "Deployed",
         "t0": "Deploying", "t1": "Deployed"})
    assert "redhat" not in out                     # retried next time
    assert out["other__type"]["vars"] == ["NEW_VAR"]   # the rest is still kept


def test_types_torque_cannot_inject_come_from_the_seed_not_from_inference():
    """The known-unsupported list is knowledge, not a conclusion drawn from a failure."""
    assert creds.SEED_TYPE_ENV_VARS["github"]["status"] == creds.STATUS_UNSUPPORTED


def test_discovery_marks_a_type_that_injects_nothing_as_no_env_vars():
    out = _interpret_discovery_outputs(
        {"baseline_a": "HOME", "baseline_b": "HOME", "t0": "HOME"},
        {"kubernetes_service_account": "t0"})
    assert out["kubernetes_service_account"]["status"] == creds.STATUS_NO_ENV_VARS


@pytest.mark.asyncio
async def test_discovery_stops_early_when_a_grain_wedges(monkeypatch):
    """A runner stuck in Preparation would otherwise cost the whole timeout for a result
    that is already as complete as it will get."""
    from torque_tunnel import torque_client as tc

    monkeypatch.setattr(tc, "DISCOVERY_STALL_SECONDS", 0.05)
    client = make_client()
    client.poll_interval = 0.01

    frozen = {
        "details": {
            "computed_status": "Launching",
            "state": {"grains": [
                {"name": "baseline_a", "state": {"current_state": "Deployed"}},
                {"name": "baseline_b", "state": {"current_state": "Deployed"}},
                {"name": "t0", "state": {"current_state": "Deployed"}},
                {"name": "t1", "state": {"current_state": "Deploying"}},
            ]},
        }
    }

    async def fake_status(env_id, retry=True):
        return frozen

    monkeypatch.setattr(client, "get_environment_status", fake_status)
    settled = await client._wait_for_discovery("env", timeout_seconds=300)
    assert settled is False  # gave up early rather than waiting out the deadline


@pytest.mark.asyncio
async def test_discovery_keeps_waiting_while_grains_are_still_progressing(monkeypatch):
    from torque_tunnel import torque_client as tc

    # Deliberately huge: this test asserts that progress PREVENTS the early exit, so the
    # threshold must be unreachable no matter how starved the machine is.
    monkeypatch.setattr(tc, "DISCOVERY_STALL_SECONDS", 3600)
    client = make_client()
    client.poll_interval = 0.01
    calls = {"n": 0}

    async def fake_status(env_id, retry=True):
        calls["n"] += 1
        if calls["n"] >= 4:
            return {"details": {"computed_status": "Active", "state": {"grains": []}}}
        return {"details": {"computed_status": "Launching", "state": {"grains": [
            {"name": "baseline_a", "state": {"current_state": "Deployed"}},
            {"name": "baseline_b", "state": {"current_state": "Deployed"}},
            {"name": f"t{calls['n']}", "state": {"current_state": "Deploying"}},
        ]}}}

    monkeypatch.setattr(client, "get_environment_status", fake_status)
    assert await client._wait_for_discovery("env", timeout_seconds=300) is True


def test_discovery_fails_loudly_when_the_baselines_are_missing():
    """Without a baseline there is nothing to subtract, so a guess would be the only
    alternative — fail instead."""
    with pytest.raises(RuntimeError):
        _interpret_discovery_outputs({"baseline_a": "", "baseline_b": "HOME", "t0": "HOME X"},
                                     {"x__t": "t0"})


# ============================================================================
# Orchestration against a stub Torque
# ============================================================================

class StubClient:
    """Just enough Torque for the orchestration functions.

    `credentials` is what the SPACE-scoped listing returns; `account_credentials` is the
    account-wide view, which includes ones this space may not use. Torque really does hide
    the latter from the former, and that difference is load-bearing.
    """

    def __init__(self, credentials, discovery=None, space="VMaaS",
                 account_credentials=None):
        self.base_url = "https://torque.example.com"
        self.space = space
        self._credentials = credentials
        self._account_credentials = account_credentials
        self._discovery = discovery or {}
        self.fetch_calls = 0
        self.discover_calls = []
        self.authorized = []

    async def fetch_credentials(self):
        self.fetch_calls += 1
        return list(self._credentials)

    async def fetch_account_credentials(self):
        # None models a token without Account.ManageCredentials.
        if self._account_credentials is None:
            return None
        return list(self._account_credentials)

    async def discover_credential_types(self, type_to_credential, agent=None):
        self.discover_calls.append(dict(type_to_credential))
        return {t: self._discovery[t] for t in type_to_credential if t in self._discovery}

    async def authorize_credential_for_space(self, name, allowed):
        self.authorized.append((name, list(allowed)))


RAW_VSPHERE = {
    "name": "vCenter-MX", "all_spaces_allowed": False,
    "allowed_space_names": ["VMaaS"], "cloud_type": "vsphere",
    "cloud_identifier": "mx-lab-hxvcenter.cisco.com",
    "credential_data": {"user": "administrator@vsphere.local", "password": None,
                        "server": "mx-lab-hxvcenter.cisco.com",
                        "validate_certificate": False, "type": "vsphere__basic"},
}
RAW_GITHUB = {
    "name": "ServiceCatalog", "all_spaces_allowed": True, "allowed_space_names": [],
    "credential_data": {"token": None, "type": "github"},
}
RAW_NEW = {
    "name": "future-cred", "all_spaces_allowed": True, "allowed_space_names": [],
    "credential_data": {"url": "https://api.example.com", "key": None,
                        "type": "future__type"},
}


@pytest.fixture
def cache_path(tmp_path):
    return tmp_path / "cache.json"


@pytest.mark.asyncio
async def test_prepare_credential_builds_a_context_with_names_and_public_values(cache_path):
    client = StubClient([RAW_VSPHERE])
    prep = await creds.prepare_credential(
        client, name="vCenter-MX", space="VMaaS", forward=True, cache_path=cache_path)
    ctx = prep["context"]
    assert "VSPHERE_PASSWORD" in ctx["vars"]
    assert "mx-lab-hxvcenter.cisco.com" in ctx["public_values"]
    assert "VSPHERE_PASSWORD" in ctx["forward"]


@pytest.mark.asyncio
async def test_context_never_carries_a_secret(cache_path):
    """The whole design rests on this: the blob is a blueprint input, so anything in it is
    visible in Torque."""
    client = StubClient([RAW_VSPHERE])
    prep = await creds.prepare_credential(
        client, name="vCenter-MX", space="VMaaS", forward=True, cache_path=cache_path)
    blob = json.dumps(prep["context"])
    assert "password" not in blob.lower() or "VSPHERE_PASSWORD" in blob
    # Only the *name* may appear, never a value from a null-valued field.
    assert prep["credential"]["public_fields"].get("password") is None


@pytest.mark.asyncio
async def test_forward_false_yields_an_empty_forward_list(cache_path):
    client = StubClient([RAW_VSPHERE])
    prep = await creds.prepare_credential(
        client, name="vCenter-MX", space="VMaaS", forward=False, cache_path=cache_path)
    assert prep["context"]["forward"] == []


@pytest.mark.asyncio
async def test_unknown_name_refetches_once_then_reports_what_is_available(cache_path):
    client = StubClient([RAW_VSPHERE])
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="nope", space="VMaaS", cache_path=cache_path)
    assert "vCenter-MX" in str(e.value)
    assert client.fetch_calls == 2  # cached list, then a forced refresh


@pytest.mark.asyncio
async def test_a_credential_added_since_the_last_fetch_is_found_on_refresh(cache_path):
    client = StubClient([RAW_VSPHERE])
    await creds.get_credentials(client, "VMaaS", cache_path=cache_path)
    client._credentials.append(RAW_NEW)
    client._discovery["future__type"] = {"status": creds.STATUS_OK, "vars": ["FUTURE_KEY"]}

    prep = await creds.prepare_credential(
        client, name="future-cred", space="VMaaS", cache_path=cache_path)
    assert prep["credential"]["name"] == "future-cred"


@pytest.mark.asyncio
async def test_unsupported_type_is_refused_before_any_launch(cache_path):
    client = StubClient([RAW_GITHUB])
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="ServiceCatalog", space="VMaaS", cache_path=cache_path)
    assert "github" in str(e.value)
    assert client.discover_calls == []  # seeded as unsupported, so never probed


@pytest.mark.asyncio
async def test_space_restricted_credential_is_refused_and_names_where_it_is_allowed(cache_path):
    """Torque's space listing hides it entirely, so without the account-level lookup this
    would read as "no such credential" and the user would have no idea what to fix."""
    client = StubClient([], space="AI-Studio", account_credentials=[RAW_VSPHERE])
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="vCenter-MX", space="AI-Studio", cache_path=cache_path)
    msg = str(e.value)
    assert "VMaaS" in msg and "AI-Studio" in msg and "authorize" in msg
    assert client.authorized == []


@pytest.mark.asyncio
async def test_a_genuinely_missing_credential_still_reads_as_missing(cache_path):
    client = StubClient([RAW_VSPHERE], account_credentials=[RAW_VSPHERE])
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="never-existed", space="VMaaS", cache_path=cache_path)
    assert "No credential named" in str(e.value)


@pytest.mark.asyncio
async def test_without_admin_rights_the_message_falls_back_gracefully(cache_path):
    """A non-admin token cannot read the account list; that must degrade, not explode."""
    client = StubClient([], space="AI-Studio", account_credentials=None)
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="vCenter-MX", space="AI-Studio", cache_path=cache_path)
    assert "is available in space 'AI-Studio'" in str(e.value)


@pytest.mark.asyncio
async def test_authorize_policy_finds_it_account_wide_widens_and_proceeds(cache_path):
    client = StubClient([], space="AI-Studio", account_credentials=[RAW_VSPHERE])
    prep = await creds.prepare_credential(
        client, name="vCenter-MX", space="AI-Studio",
        space_policy=creds.SPACE_POLICY_AUTHORIZE, cache_path=cache_path)
    assert prep["credential"]["name"] == "vCenter-MX"
    assert client.authorized == [("vCenter-MX", ["VMaaS"])]


@pytest.mark.asyncio
async def test_authorize_failure_explains_the_admin_requirement(cache_path):
    class Failing(StubClient):
        async def authorize_credential_for_space(self, name, allowed):
            raise RuntimeError("HTTP 403")

    client = Failing([], space="AI-Studio", account_credentials=[RAW_VSPHERE])
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="vCenter-MX", space="AI-Studio",
            space_policy=creds.SPACE_POLICY_AUTHORIZE, cache_path=cache_path)
    assert "account-admin" in str(e.value)


@pytest.mark.asyncio
async def test_a_disabled_profile_cannot_attach_a_credential(cache_path):
    """The opt-in gate lives in prepare_credential, so it holds for the CLI as well as the
    MCP tool - not only where the tool layer happens to check."""
    client = StubClient([RAW_VSPHERE])
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="vCenter-MX", space="VMaaS", enabled=False,
            cache_path=cache_path)
    assert "credentials_enabled" in str(e.value)
    assert client.fetch_calls == 0  # refused before touching Torque at all


@pytest.mark.asyncio
async def test_a_new_type_is_measured_once_and_then_cached_forever(cache_path):
    client = StubClient(
        [RAW_NEW], discovery={"future__type": {"status": creds.STATUS_OK,
                                               "vars": ["FUTURE_KEY", "FUTURE_URL"]}})
    first = await creds.prepare_credential(
        client, name="future-cred", space="VMaaS", cache_path=cache_path)
    assert first["type_entry"]["vars"] == ["FUTURE_KEY", "FUTURE_URL"]
    assert len(client.discover_calls) == 1

    second = await creds.prepare_credential(
        client, name="future-cred", space="VMaaS", cache_path=cache_path)
    assert second["type_entry"]["vars"] == ["FUTURE_KEY", "FUTURE_URL"]
    assert len(client.discover_calls) == 1  # not measured again


@pytest.mark.asyncio
async def test_seeded_types_are_never_probed(cache_path):
    client = StubClient([RAW_VSPHERE])
    await creds.prepare_credential(
        client, name="vCenter-MX", space="VMaaS", cache_path=cache_path)
    assert client.discover_calls == []


@pytest.mark.asyncio
async def test_a_measured_type_discovered_to_be_unsupported_is_then_refused(cache_path):
    client = StubClient(
        [RAW_NEW], discovery={"future__type": {"status": creds.STATUS_UNSUPPORTED,
                                               "vars": []}})
    with pytest.raises(creds.CredentialError):
        await creds.prepare_credential(
            client, name="future-cred", space="VMaaS", cache_path=cache_path)

    # And it is remembered, so the next call fails immediately instead of probing again.
    with pytest.raises(creds.CredentialError):
        await creds.prepare_credential(
            client, name="future-cred", space="VMaaS", cache_path=cache_path)
    assert len(client.discover_calls) == 1


@pytest.mark.asyncio
async def test_space_is_authorized_before_the_type_is_measured(cache_path):
    """The probe environment launches in this space, so a credential not yet allowed here
    could not be attached to a probe grain either — authorization has to come first."""
    order = []

    class Ordered(StubClient):
        async def authorize_credential_for_space(self, name, allowed):
            order.append("authorize")
            await super().authorize_credential_for_space(name, allowed)

        async def discover_credential_types(self, type_to_credential, agent=None):
            order.append("discover")
            return await super().discover_credential_types(type_to_credential, agent=agent)

    restricted_new = dict(RAW_NEW, all_spaces_allowed=False,
                          allowed_space_names=["SomewhereElse"])
    client = Ordered(
        [], space="AI-Studio", account_credentials=[restricted_new],
        discovery={"future__type": {"status": creds.STATUS_OK, "vars": ["FUTURE_KEY"]}})

    prep = await creds.prepare_credential(
        client, name="future-cred", space="AI-Studio",
        space_policy=creds.SPACE_POLICY_AUTHORIZE, cache_path=cache_path)

    assert order == ["authorize", "discover"]
    assert prep["type_entry"]["vars"] == ["FUTURE_KEY"]


@pytest.mark.asyncio
async def test_an_unusable_type_is_refused_without_authorizing_anything(cache_path):
    """No point widening a credential's allowed spaces for a type that can never work."""
    restricted_github = dict(RAW_GITHUB, all_spaces_allowed=False,
                             allowed_space_names=["SomewhereElse"])
    client = StubClient([], space="AI-Studio", account_credentials=[restricted_github])
    with pytest.raises(creds.CredentialError):
        await creds.prepare_credential(
            client, name="ServiceCatalog", space="AI-Studio",
            space_policy=creds.SPACE_POLICY_AUTHORIZE, cache_path=cache_path)
    assert client.authorized == []


@pytest.mark.asyncio
async def test_an_unmeasurable_type_is_refused_rather_than_run_without_redaction(cache_path):
    """If we do not know a type's variables we cannot redact them, and running anyway would
    silently drop the protection the feature exists to provide."""
    client = StubClient([RAW_NEW], discovery={})  # discovery returns nothing for the type
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="future-cred", space="VMaaS", cache_path=cache_path)
    assert "redact" in str(e.value)


@pytest.mark.asyncio
async def test_a_failed_measurement_is_reported_as_a_credential_problem(cache_path):
    class Broken(StubClient):
        async def discover_credential_types(self, type_to_credential, agent=None):
            raise RuntimeError("no agent available")

    client = Broken([RAW_NEW])
    with pytest.raises(creds.CredentialError) as e:
        await creds.prepare_credential(
            client, name="future-cred", space="VMaaS", cache_path=cache_path)
    assert "no agent available" in str(e.value)


@pytest.mark.asyncio
async def test_cached_list_avoids_a_second_fetch(cache_path):
    client = StubClient([RAW_VSPHERE])
    await creds.get_credentials(client, "VMaaS", cache_path=cache_path)
    await creds.get_credentials(client, "VMaaS", cache_path=cache_path)
    assert client.fetch_calls == 1


@pytest.mark.asyncio
async def test_force_refresh_always_refetches(cache_path):
    client = StubClient([RAW_VSPHERE])
    await creds.get_credentials(client, "VMaaS", cache_path=cache_path)
    await creds.get_credentials(client, "VMaaS", force_refresh=True, cache_path=cache_path)
    assert client.fetch_calls == 2


# ============================================================================
# Tool surface
# ============================================================================

def test_every_run_tool_accepts_a_single_credential_string():
    """A list would let a caller ask for two, which Torque would silently resolve to one."""
    import asyncio as _asyncio
    from torque_tunnel import mcp_tool

    tools = _asyncio.run(mcp_tool.list_tools())
    run_tools = [t for t in tools if t.name.startswith("run_on_tunneled_")]
    assert len(run_tools) == 6
    for t in run_tools:
        prop = t.inputSchema["properties"]["credential"]
        assert prop["type"] == "string"


def test_only_the_tools_that_leave_the_container_offer_forwarding():
    import asyncio as _asyncio
    from torque_tunnel import mcp_tool

    tools = {t.name: t for t in _asyncio.run(mcp_tool.list_tools())}
    for name in ("run_on_tunneled_ssh", "run_on_tunneled_ssh_async",
                 "run_on_tunneled_persistent_container",
                 "run_on_tunneled_persistent_container_async"):
        assert "credential_env_forward" in tools[name].inputSchema["properties"], name
    for name in ("run_on_tunneled_disposable_container",
                 "run_on_tunneled_disposable_container_async"):
        assert "credential_env_forward" not in tools[name].inputSchema["properties"], name


def test_list_credentials_tool_is_exposed():
    import asyncio as _asyncio
    from torque_tunnel import mcp_tool

    names = {t.name for t in _asyncio.run(mcp_tool.list_tools())}
    assert "list_credentials" in names


def test_credential_config_keys_are_ordinary_profile_overridable_values():
    from torque_tunnel import config as config_module

    for key in ("credentials_enabled", "credentials_space_policy"):
        assert key in config_module.CONFIG_KEY_MAP
        # Metadata keys do not inherit through `extends`; these must.
        assert key not in config_module._PROFILE_META_KEYS


def test_credentials_are_off_unless_enabled():
    from torque_tunnel import mcp_tool

    assert mcp_tool._credentials_disabled_message({}) is not None
    assert mcp_tool._credentials_disabled_message({"credentials_enabled": True}) is None


def test_bad_space_policy_falls_back_to_the_non_mutating_one():
    from torque_tunnel import mcp_tool

    assert mcp_tool._credentials_space_policy(
        {"credentials_space_policy": "nonsense"}) == creds.SPACE_POLICY_PRECONFIGURED
    assert mcp_tool._credentials_space_policy(
        {"credentials_space_policy": "authorize"}) == creds.SPACE_POLICY_AUTHORIZE


def test_encoded_context_roundtrips_through_the_blueprint_input():
    from torque_tunnel.torque_client import _encode_credential_context

    assert _encode_credential_context(None) == ""
    encoded = _encode_credential_context({"vars": ["A"], "min_len": 8})
    assert json.loads(gzip.decompress(base64.b64decode(encoded)).decode()) == {
        "vars": ["A"], "min_len": 8}
