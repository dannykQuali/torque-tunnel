"""Torque credential support: type→env-var map, on-disk cache, and pre-flight validation.

torque-tunnel never handles a credential's secret. It passes a credential *name* to Torque,
which resolves the secrets inside the agent container and injects them as environment
variables. What this module owns is the bookkeeping around that:

* which environment variables a given ``credential_data_type`` produces (there is no Torque
  API for this — see docs/design-credentials.md §3),
* a cache of that mapping plus the account's credential list,
* the pre-flight checks that turn Torque's opaque launch errors into useful messages.

Everything here is pure or filesystem-local; nothing in this module talks to Torque.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

# --- Type status ------------------------------------------------------------------

#: The type injects environment variables.
STATUS_OK = "ok"
#: The type resolves fine but produces no environment variables (nothing to use).
STATUS_NO_ENV_VARS = "no_env_vars"
#: Torque has no env-var creator registered for the type; attaching it kills the grain.
STATUS_UNSUPPORTED = "unsupported"

#: Where an entry came from. A measurement always wins over the shipped seed.
SOURCE_SEED = "seed"
SOURCE_MEASURED = "measured"


# --- Seed -------------------------------------------------------------------------
# Transcribed from cs2018 Quali.Colony.Services.Environments.Grains/CredentialEnvsCreators/
# and the DI registrations in Modules/GrainCommonModule.cs, as of 2026-09.
#
# This is only the *initial shape* of the cache: a type absent from here is measured on
# first use and then cached permanently. Seed entries never overwrite a measurement.
#
# The `unsupported` entries matter as much as the others - without them we would send a
# discovery probe at a credential we already know will kill its grain.

SEED_TYPE_ENV_VARS: dict[str, dict[str, Any]] = {
    "aws__basic": {
        "status": STATUS_OK,
        "vars": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
    },
    "aws__role_arn": {
        "status": STATUS_OK,
        "vars": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
    },
    "azure__basic": {
        "status": STATUS_OK,
        "vars": ["ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET"],
    },
    "vsphere__basic": {
        "status": STATUS_OK,
        "vars": [
            "VSPHERE_USER", "VSPHERE_PASSWORD", "VSPHERE_SERVER", "VSPHERE_ALLOW_UNVERIFIED_SSL",
            "VMWARE_USER", "VMWARE_PASSWORD", "VMWARE_HOST", "VMWARE_VALIDATE_CERTS",
        ],
    },
    "intersight__basic": {
        "status": STATUS_OK,
        "vars": [
            "INTERSIGHT_API_KEY", "INTERSIGHT_SECRET_KEY", "INTERSIGHT_REGION",
            "TF_VAR_INTERSIGHT_API_KEY", "TF_VAR_INTERSIGHT_SECRET_KEY", "TF_VAR_INTERSIGHT_REGION",
        ],
    },
    "nexus_dashboard": {
        "status": STATUS_OK,
        "vars": [
            "NEXUS_DASHBOARD_API_KEY", "NEXUS_DASHBOARD_API_URL",
            "NEXUS_DASHBOARD_API_USER", "NEXUS_DASHBOARD_SKIP_VERIFICATION",
        ],
    },
    "nvaie": {"status": STATUS_OK, "vars": ["NVAIE_API_KEY"]},
    "redhat": {"status": STATUS_OK, "vars": ["REDHAT_PULL_SECRET"]},

    # Resolves through EmptyCredentialEnvsCreator: the namespace and service account are
    # applied to the grain host directly, so nothing lands in the environment.
    "kubernetes_service_account": {"status": STATUS_NO_ENV_VARS, "vars": []},

    # No ICredentialsCreator is registered for these, so the grain dies at deploy with
    # "unexpected error has occurred". Reproduced live with a github credential.
    "github": {"status": STATUS_UNSUPPORTED, "vars": []},
    "github_enterprise": {"status": STATUS_UNSUPPORTED, "vars": []},
    "gitlab": {"status": STATUS_UNSUPPORTED, "vars": []},
    "gitlab_enterprise": {"status": STATUS_UNSUPPORTED, "vars": []},
    "gitlab_secrets_manager": {"status": STATUS_UNSUPPORTED, "vars": []},
    "bitbucket": {"status": STATUS_UNSUPPORTED, "vars": []},
    "bitbucket_server": {"status": STATUS_UNSUPPORTED, "vars": []},
    "azure": {"status": STATUS_UNSUPPORTED, "vars": []},
    "azure_enterprise": {"status": STATUS_UNSUPPORTED, "vars": []},
    "codecommit": {"status": STATUS_UNSUPPORTED, "vars": []},
    "cloudshell": {"status": STATUS_UNSUPPORTED, "vars": []},
    "artifactory": {"status": STATUS_UNSUPPORTED, "vars": []},
}


# --- Variables that are never forwarded to a remote host --------------------------

#: Runner-only, and unusable downstream. Our blueprints declare no `api_access` so it is
#: never even present, but the guard costs nothing.
NEVER_FORWARD = frozenset({"API_TOKEN"})

#: Injected by Torque's InjectManagementServerContext for mgmt-attached compute services.
#: Forwarded to SSH targets on purpose - that is the existing blueprint contract.
MGMT_SERVER_PREFIX = "MGMT_SERVER_"

#: A value shorter than this is never redacted from output: a credential field like
#: `validate_certificate=false` would otherwise turn every "false" in the output into ***.
MIN_REDACTABLE_VALUE_LEN = 8


# --- Space policy -----------------------------------------------------------------

SPACE_POLICY_PRECONFIGURED = "preconfigured"
SPACE_POLICY_AUTHORIZE = "authorize"
SPACE_POLICIES = (SPACE_POLICY_PRECONFIGURED, SPACE_POLICY_AUTHORIZE)

#: How long a fetched credential list stays usable without a refresh.
CREDENTIAL_LIST_TTL_SECONDS = 24 * 60 * 60

# Bumped to 2: version 1 could contain a `unsupported` entry inferred from a failed
# discovery grain, which a wedged runner produced for a perfectly usable type. Those
# entries are permanent, so the old caches are discarded rather than carried forward.
CACHE_VERSION = 2


# --- Cache file -------------------------------------------------------------------


def cache_dir() -> Path:
    """Directory holding torque-tunnel's local state. Created if missing."""
    d = Path.home() / ".torque-tunnel"
    d.mkdir(exist_ok=True)
    return d


def cache_file_path() -> Path:
    """Path to the credential cache file."""
    return cache_dir() / "credentials-cache.json"


def _empty_cache() -> dict:
    return {"version": CACHE_VERSION, "instances": {}}


def load_cache(path: Optional[Path] = None) -> dict:
    """Read the cache, returning an empty one when absent, unreadable or of a future version.

    A cache is disposable by definition, so every failure mode degrades to "empty" rather
    than raising - a corrupt file must never break a run.
    """
    p = path or cache_file_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return _empty_cache()
    if not isinstance(data, dict) or data.get("version") != CACHE_VERSION:
        return _empty_cache()
    if not isinstance(data.get("instances"), dict):
        return _empty_cache()
    return data


#: os.replace over an existing file intermittently fails on Windows with a sharing
#: violation when something else (an indexer, a virus scanner, another torque-tunnel
#: process) has the target open for a moment. Observed at roughly a 4% rate in a 100-run
#: loop, which silently lost the write and made a permanent measurement non-permanent.
_REPLACE_ATTEMPTS = 6
_REPLACE_BACKOFF_SECONDS = 0.02


def save_cache(cache: dict, path: Optional[Path] = None) -> None:
    """Write the cache atomically.

    The CLI flavour runs a fresh process per command and several can overlap, so a partial
    file must never be observable. Failures are swallowed after the retries: losing a cache
    write costs a re-measurement, it does not make anything incorrect.
    """
    p = path or cache_file_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".credentials-cache-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
            for attempt in range(_REPLACE_ATTEMPTS):
                try:
                    os.replace(tmp, p)
                    break
                except OSError:
                    if attempt == _REPLACE_ATTEMPTS - 1:
                        raise
                    time.sleep(_REPLACE_BACKOFF_SECONDS * (attempt + 1))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass


def _instance(cache: dict, torque_url: str) -> dict:
    """Get (creating if needed) the per-Torque-instance section of the cache."""
    key = (torque_url or "").rstrip("/")
    inst = cache.setdefault("instances", {}).setdefault(key, {})
    inst.setdefault("types", {})
    inst.setdefault("spaces", {})
    return inst


# --- Type → env vars --------------------------------------------------------------


def effective_type_map(cache: dict, torque_url: str) -> dict[str, dict]:
    """The type map this instance should use: seed filled in, measurements winning.

    A seed entry only ever fills a gap, so types added to the seed in a later release show
    up automatically for existing users while nothing measured on their own instance is
    overwritten.
    """
    merged: dict[str, dict] = {}
    for ctype, entry in SEED_TYPE_ENV_VARS.items():
        merged[ctype] = {**entry, "source": SOURCE_SEED}
    measured = _instance(cache, torque_url).get("types", {})
    for ctype, entry in measured.items():
        if isinstance(entry, dict):
            merged[ctype] = entry
    return merged


def get_type_entry(cache: dict, torque_url: str, credential_type: str) -> Optional[dict]:
    """The entry for one credential type, or None when it has never been seen."""
    return effective_type_map(cache, torque_url).get(credential_type)


def put_type_entry(
    cache: dict,
    torque_url: str,
    credential_type: str,
    *,
    status: str,
    variables: Optional[list[str]] = None,
    agent: Optional[str] = None,
) -> None:
    """Record a measured type entry. Measurements are permanent (see design doc §4)."""
    _instance(cache, torque_url)["types"][credential_type] = {
        "status": status,
        "vars": sorted(set(variables or [])),
        "source": SOURCE_MEASURED,
        "measured_at": _now_iso(),
        "measured_on_agent": agent,
    }


def drop_measured_types(cache: dict, torque_url: str) -> None:
    """Forget every measurement for an instance, so the next use re-measures.

    Backs `force_rediscover`, for the rare case where a Torque upgrade changed a type's
    variables - the permanent cache would otherwise never notice.
    """
    _instance(cache, torque_url)["types"] = {}


def unmeasured_types(cache: dict, torque_url: str, credential_types: list[str]) -> list[str]:
    """Which of these types have no entry at all, and so need discovery."""
    known = effective_type_map(cache, torque_url)
    seen: list[str] = []
    for t in credential_types:
        if t and t not in known and t not in seen:
            seen.append(t)
    return seen


# --- Credential list --------------------------------------------------------------


def get_credential_list(
    cache: dict, torque_url: str, space: str, *, now: Optional[float] = None
) -> Optional[list[dict]]:
    """The cached credential list for a space, or None when absent or past its TTL."""
    entry = _instance(cache, torque_url).get("spaces", {}).get(space)
    if not isinstance(entry, dict):
        return None
    fetched = entry.get("fetched_at_epoch")
    if not isinstance(fetched, (int, float)):
        return None
    if (now if now is not None else time.time()) - fetched > CREDENTIAL_LIST_TTL_SECONDS:
        return None
    creds = entry.get("credentials")
    return creds if isinstance(creds, list) else None


def put_credential_list(
    cache: dict, torque_url: str, space: str, credentials: list[dict], *, now: Optional[float] = None
) -> None:
    """Store a freshly fetched credential list for a space."""
    _instance(cache, torque_url)["spaces"][space] = {
        "fetched_at_epoch": (now if now is not None else time.time()),
        "fetched_at": _now_iso(),
        "credentials": credentials,
    }


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


# --- Parsing Torque's credential list ---------------------------------------------

#: Fields we never echo, even though Torque returns them non-null. `key` is an AWS access
#: key id / Intersight API key id: not the secret, but not something to spray into a chat
#: transcript either. Everything else in credential_data is descriptive.
_OPAQUE_DATA_FIELDS = frozenset({"key"})


def parse_credential(raw: dict) -> dict:
    """Normalise one credential from Torque's list response.

    Torque returns secret fields as null and descriptive ones populated, which is what lets
    redaction work without a per-type table of which field is secret.
    """
    data = raw.get("credential_data") or {}
    public: dict[str, Any] = {}
    for k, v in data.items():
        if k == "type" or v is None:
            continue
        public[k] = v
    return {
        "name": raw.get("name"),
        "type": data.get("type"),
        "description": raw.get("description") or "",
        "cloud_type": raw.get("cloud_type"),
        "cloud_identifier": raw.get("cloud_identifier"),
        "all_spaces_allowed": bool(raw.get("all_spaces_allowed")),
        "allowed_space_names": list(raw.get("allowed_space_names") or []),
        "public_fields": public,
    }


def displayable_fields(credential: dict) -> dict:
    """The non-secret fields safe to show in tool output."""
    return {
        k: v for k, v in (credential.get("public_fields") or {}).items()
        if k not in _OPAQUE_DATA_FIELDS
    }


def public_values(credential: dict) -> list[str]:
    """Non-secret credential values, as strings.

    Redaction uses these as the allow-list: any injected variable whose value is *not* one
    of these came from a field Torque returned as null, i.e. a secret.
    """
    out: list[str] = []
    for v in (credential.get("public_fields") or {}).values():
        if isinstance(v, bool):
            out.append("true" if v else "false")
            out.append("True" if v else "False")
        else:
            out.append(str(v))
    return out


# --- Pre-flight validation --------------------------------------------------------


class CredentialError(Exception):
    """A credential request that cannot proceed, with a message meant for the caller."""


def find_credential(credentials: list[dict], name: str) -> Optional[dict]:
    """Look a credential up by name, case-insensitively (Torque's names are)."""
    lowered = (name or "").lower()
    for c in credentials:
        if (c.get("name") or "").lower() == lowered:
            return c
    return None


def validate_credential_usable(
    credential: dict,
    type_entry: Optional[dict],
    space: str,
    space_policy: str,
) -> Optional[str]:
    """Why this credential cannot be used, or None when it can.

    Covers the failures Torque reports badly or not at all: a space restriction it calls
    "does not exist", and a credential type whose grain dies with "unexpected error has
    occurred".
    """
    name = credential.get("name")
    ctype = credential.get("type")

    if not credential.get("all_spaces_allowed"):
        allowed = credential.get("allowed_space_names") or []
        in_space = any(s.lower() == (space or "").lower() for s in allowed)
        if allowed and not in_space and space_policy != SPACE_POLICY_AUTHORIZE:
            return (
                f"Credential '{name}' is not allowed in space '{space}'. "
                f"It is allowed in: {', '.join(allowed)}. "
                f"Either switch this profile to one of those spaces, or set "
                f"credentials_space_policy: authorize to let torque-tunnel add '{space}' "
                f"to the credential's allowed spaces (requires account admin)."
            )

    if type_entry is None:
        return None  # never seen; discovery decides

    status = type_entry.get("status")
    if status == STATUS_UNSUPPORTED:
        return (
            f"Credential '{name}' has type '{ctype}', which Torque cannot inject as "
            f"environment variables - attaching it makes the grain fail with 'unexpected "
            f"error has occurred'. Use a credential of a supported type."
        )
    if status == STATUS_NO_ENV_VARS:
        return (
            f"Credential '{name}' has type '{ctype}', which produces no environment "
            f"variables (Torque applies it to the grain host instead), so it cannot be "
            f"used this way."
        )
    return None


def build_context(
    credential: dict,
    type_entry: Optional[dict],
    *,
    forward: bool,
    extra_forward: Optional[list[str]] = None,
) -> dict:
    """The blob handed to the grain as `credential_context_b64`.

    Carries variable **names** and **non-secret values** only. The grain reads the secret
    values out of its own environment; nothing secret is ever put in here, so this travels
    as an ordinary blueprint input.
    """
    variables = list((type_entry or {}).get("vars") or [])
    return {
        "name": credential.get("name"),
        "type": credential.get("type"),
        "vars": variables,
        "public_values": public_values(credential),
        "min_len": MIN_REDACTABLE_VALUE_LEN,
        "forward": forwardable_vars(type_entry, extra_forward) if forward else [],
    }


def forwardable_vars(type_entry: Optional[dict], extra: Optional[list[str]] = None) -> list[str]:
    """Variable names to forward to a remote host over SSH.

    An allow-list, never a deny-list: the container also holds MGMT_SERVER_* (handled
    separately and deliberately) and potentially compute-service variables we cannot
    enumerate, so anything not explicitly named stays in the container.
    """
    names: list[str] = []
    if type_entry and type_entry.get("status") == STATUS_OK:
        names.extend(type_entry.get("vars") or [])
    names.extend(extra or [])
    out: list[str] = []
    for n in names:
        if n and n not in out and n not in NEVER_FORWARD:
            out.append(n)
    return out


# --- Discovery lock ---------------------------------------------------------------

#: A discovery run launches a Torque environment. The CLI flavour runs a fresh process per
#: command and several can overlap, so the lock keeps ten concurrent calls from launching
#: ten probe environments.
DISCOVERY_LOCK_STALE_SECONDS = 15 * 60


class _DiscoveryLock:
    """Best-effort inter-process lock around discovery.

    Failing to take it is never fatal: the caller proceeds and at worst duplicates a probe.
    A lock left behind by a killed process goes stale and is reclaimed.
    """

    def __init__(self, path: Optional[Path] = None):
        self.path = path or (cache_dir() / "credentials-discovery.lock")
        self.acquired = False

    def __enter__(self) -> "_DiscoveryLock":
        try:
            if self.path.exists():
                age = time.time() - self.path.stat().st_mtime
                if age > DISCOVERY_LOCK_STALE_SECONDS:
                    self.path.unlink(missing_ok=True)
            fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode("ascii"))
            os.close(fd)
            self.acquired = True
        except (OSError, ValueError):
            self.acquired = False
        return self

    def __exit__(self, *exc) -> None:
        if self.acquired:
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                pass
        return None


# --- Orchestration ----------------------------------------------------------------
#
# These take a Torque client rather than importing one, so they can be exercised against a
# stub. Nothing below reaches Torque except through that client.


async def get_credentials(
    client,
    space: str,
    *,
    force_refresh: bool = False,
    cache: Optional[dict] = None,
    cache_path: Optional[Path] = None,
) -> tuple[dict, list[dict]]:
    """The credential list for a space, from cache or freshly fetched.

    Refreshed when forced (every explicit query is), when the 24h TTL has passed, or when a
    caller asked for a name the cached list does not contain.
    """
    cache = cache if cache is not None else load_cache(cache_path)
    url = client.base_url

    if not force_refresh:
        cached = get_credential_list(cache, url, space)
        if cached is not None:
            return cache, cached

    raw = await client.fetch_credentials()
    parsed = [parse_credential(item) for item in raw]
    put_credential_list(cache, url, space, parsed)
    save_cache(cache, cache_path)
    return cache, parsed


async def ensure_types_measured(
    client,
    cache: dict,
    credentials_by_type: dict[str, str],
    *,
    agent: Optional[str] = None,
    cache_path: Optional[Path] = None,
    force: bool = False,
) -> dict:
    """Measure any credential type this instance has never seen, and cache it permanently.

    `credentials_by_type` maps a type to the name of a credential of that type to probe
    with. Types already known (seeded or measured) are skipped, so the steady state is no
    probe at all - unless `force`, which re-measures everything given, seeded types
    included, for the "Torque was upgraded and I do not trust the cache" case.
    """
    if force:
        todo = dict(credentials_by_type)
    else:
        todo = {
            t: name for t, name in credentials_by_type.items()
            if t in unmeasured_types(cache, client.base_url, list(credentials_by_type))
        }
    if not todo:
        return cache

    with _DiscoveryLock() as lock:
        if not lock.acquired and not force:
            # Someone else is probing. Re-read: they may have finished already.
            cache = load_cache(cache_path)
            todo = {
                t: n for t, n in todo.items()
                if t in unmeasured_types(cache, client.base_url, list(todo))
            }
            if not todo:
                return cache

        measured = await client.discover_credential_types(todo, agent=agent)
        for ctype, entry in measured.items():
            put_type_entry(
                cache, client.base_url, ctype,
                status=entry.get("status", STATUS_UNSUPPORTED),
                variables=entry.get("vars") or [],
                agent=agent,
            )
        save_cache(cache, cache_path)
    return cache


async def _find_account_credential(client, name: str) -> Optional[dict]:
    """Look a credential up account-wide, ignoring space restrictions.

    Returns None when the token cannot read the account list (no admin rights) or the
    credential genuinely does not exist.
    """
    getter = getattr(client, "fetch_account_credentials", None)
    if getter is None:
        return None
    try:
        raw = await getter()
    except Exception:
        return None
    if not raw:
        return None
    return find_credential([parse_credential(item) for item in raw], name)


async def prepare_credential(
    client,
    *,
    name: str,
    space: str,
    space_policy: str = SPACE_POLICY_PRECONFIGURED,
    agent: Optional[str] = None,
    forward: bool = False,
    extra_forward: Optional[list[str]] = None,
    cache_path: Optional[Path] = None,
    enabled: bool = True,
) -> dict:
    """Resolve a credential name into everything a run_* call needs.

    Raises CredentialError with a message meant for the caller when the credential cannot
    be used - covering the cases Torque reports badly (a space restriction it calls "does
    not exist") or not at all until the grain dies.

    Returns ``{"credential", "type_entry", "context"}``.
    """
    if not enabled:
        # The gate lives here, not only at the tool layer, so no caller - MCP, CLI, or a
        # future one - can attach a credential to a profile that has not opted in.
        raise CredentialError(
            "Torque credentials are not enabled for this profile. Set "
            "`credentials_enabled: true` in the config file (top level or inside the "
            "profile), or re-run `setup` and tick \"Allow using Torque credentials\"."
        )
    cache, creds_list = await get_credentials(client, space, cache_path=cache_path)
    credential = find_credential(creds_list, name)
    if credential is None:
        # The list may simply be stale - a credential added since the last fetch.
        cache, creds_list = await get_credentials(
            client, space, force_refresh=True, cache=cache, cache_path=cache_path
        )
        credential = find_credential(creds_list, name)
    if credential is None:
        # The space-scoped listing hides credentials this space may not use, so a name that
        # is missing from it might still exist at account level. Distinguishing the two is
        # the difference between "there is no such credential" and "it exists but is
        # restricted to other spaces" - and only the latter is fixable.
        elsewhere = await _find_account_credential(client, name)
        if elsewhere is not None:
            allowed = elsewhere.get("allowed_space_names") or []
            if space_policy == SPACE_POLICY_AUTHORIZE:
                credential = elsewhere
            else:
                where = ", ".join(allowed) if allowed else "no spaces"
                raise CredentialError(
                    f"Credential '{elsewhere['name']}' exists but is not allowed in space "
                    f"'{space}' (it is allowed in: {where}). Either point this profile at "
                    f"one of those spaces, or set credentials_space_policy: authorize to "
                    f"let torque-tunnel add '{space}' to its allowed spaces (needs an "
                    f"account-admin token)."
                )
    if credential is None:
        available = ", ".join(sorted(c["name"] for c in creds_list if c.get("name"))) or "(none)"
        raise CredentialError(
            f"No credential named '{name}' is available in space '{space}'. "
            f"Available: {available}."
        )

    ctype = credential.get("type")

    # What we already know about the type, before spending anything. Refusing here keeps a
    # credential Torque cannot inject from triggering either an authorization write or a
    # pointless probe.
    type_entry = get_type_entry(cache, client.base_url, ctype) if ctype else None
    if type_entry is not None:
        problem = validate_credential_usable(credential, type_entry, space, space_policy)
        if problem:
            raise CredentialError(problem)

    # Authorization comes BEFORE measurement: the probe environment launches in this space,
    # so a credential not yet allowed here could not be attached to a probe grain either.
    needs_authorization = (
        not credential.get("all_spaces_allowed")
        and credential.get("allowed_space_names")
        and not any(s.lower() == (space or "").lower()
                    for s in credential["allowed_space_names"])
    )
    if needs_authorization and space_policy == SPACE_POLICY_AUTHORIZE:
        try:
            await client.authorize_credential_for_space(
                credential["name"], credential["allowed_space_names"]
            )
        except Exception as e:
            raise CredentialError(
                f"Could not authorize space '{space}' for credential "
                f"'{credential['name']}': {e}. This needs an account-admin token; "
                f"otherwise set credentials_space_policy: preconfigured and use a space "
                f"the credential already allows."
            ) from e
        # The stored list is now wrong; force a refetch next time.
        _instance(cache, client.base_url).get("spaces", {}).pop(space, None)
        save_cache(cache, cache_path)

    if ctype and type_entry is None:
        try:
            cache = await ensure_types_measured(
                client, cache, {ctype: credential["name"]}, agent=agent,
                cache_path=cache_path,
            )
        except Exception as e:
            raise CredentialError(
                f"Could not determine which environment variables credential type "
                f"'{ctype}' injects: {e}. Without that, its secrets could not be redacted "
                f"from the output, so the call was not made."
            ) from e
        type_entry = get_type_entry(cache, client.base_url, ctype)

    if ctype and type_entry is None:
        # Measured and still nothing - a wedged runner, typically. Proceeding would mean no
        # redaction and no forwarding, silently; refuse instead.
        raise CredentialError(
            f"Credential type '{ctype}' has not been measured on this Torque account yet, "
            f"so torque-tunnel does not know which environment variables it injects and "
            f"could not redact them from the output. Run list_credentials to retry the "
            f"measurement."
        )

    problem = validate_credential_usable(credential, type_entry, space, space_policy)
    if problem:
        raise CredentialError(problem)

    return {
        "credential": credential,
        "type_entry": type_entry,
        "context": build_context(
            credential, type_entry, forward=forward, extra_forward=extra_forward
        ),
    }
