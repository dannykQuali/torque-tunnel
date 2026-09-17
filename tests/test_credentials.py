"""Tests for the credentials module — seed/cache merge, TTL, parsing, and pre-flight checks."""

import json
import os
import sys
import time
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import credentials as creds


URL = "https://torque.example.com"


@pytest.fixture
def cache_path(tmp_path):
    return tmp_path / "credentials-cache.json"


@pytest.fixture
def empty_cache():
    return creds.load_cache(Path("/nonexistent/definitely-not-here.json"))


# ============================================================================
# Seed integrity
# ============================================================================

def test_seed_entries_all_have_status_and_vars():
    for ctype, entry in creds.SEED_TYPE_ENV_VARS.items():
        assert entry["status"] in (
            creds.STATUS_OK, creds.STATUS_NO_ENV_VARS, creds.STATUS_UNSUPPORTED
        ), ctype
        assert isinstance(entry["vars"], list), ctype


def test_seed_ok_types_have_variables_and_others_do_not():
    """An 'ok' type without variables would be a transcription slip, and a non-ok type
    with variables would mean we both reject it and claim it injects things."""
    for ctype, entry in creds.SEED_TYPE_ENV_VARS.items():
        if entry["status"] == creds.STATUS_OK:
            assert entry["vars"], f"{ctype} is ok but injects nothing"
        else:
            assert entry["vars"] == [], f"{ctype} is {entry['status']} but lists variables"


def test_seed_covers_the_types_seen_on_a_real_account():
    """Types actually present on the Cisco production account during design."""
    for ctype in ("vsphere__basic", "intersight__basic", "aws__basic", "nvaie",
                  "redhat", "github"):
        assert ctype in creds.SEED_TYPE_ENV_VARS


def test_api_token_is_never_forwardable():
    entry = {"status": creds.STATUS_OK, "vars": ["FOO"]}
    assert creds.forwardable_vars(entry, extra=["API_TOKEN"]) == ["FOO"]


# ============================================================================
# Cache load/save
# ============================================================================

def test_load_missing_cache_returns_empty(cache_path):
    c = creds.load_cache(cache_path)
    assert c["version"] == creds.CACHE_VERSION
    assert c["instances"] == {}


def test_load_corrupt_cache_returns_empty_rather_than_raising(cache_path):
    cache_path.write_text("{ this is not json", encoding="utf-8")
    c = creds.load_cache(cache_path)
    assert c["instances"] == {}


def test_load_future_version_cache_is_discarded(cache_path):
    cache_path.write_text(json.dumps({"version": 999, "instances": {"x": {}}}), encoding="utf-8")
    assert creds.load_cache(cache_path)["instances"] == {}


def test_save_then_load_roundtrip(cache_path):
    c = creds.load_cache(cache_path)
    creds.put_type_entry(c, URL, "foo__type", status=creds.STATUS_OK, variables=["FOO_KEY"])
    creds.save_cache(c, cache_path)

    reloaded = creds.load_cache(cache_path)
    entry = creds.get_type_entry(reloaded, URL, "foo__type")
    assert entry["vars"] == ["FOO_KEY"]
    assert entry["source"] == creds.SOURCE_MEASURED


def test_save_leaves_no_temp_files_behind(cache_path):
    c = creds.load_cache(cache_path)
    creds.put_type_entry(c, URL, "foo", status=creds.STATUS_OK, variables=["A"])
    creds.save_cache(c, cache_path)
    leftovers = [p.name for p in cache_path.parent.iterdir() if p.name.startswith(".credentials-cache-")]
    assert leftovers == []


def test_save_retries_a_transient_replace_failure(cache_path, monkeypatch):
    """os.replace intermittently hits a sharing violation on Windows (an indexer or virus
    scanner holding the target for a moment). Swallowing that lost the write silently and
    made a "permanent" measurement non-permanent — caught at ~4% in a 100-run loop."""
    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst):
        calls["n"] += 1
        if calls["n"] <= 3:
            raise PermissionError(32, "The process cannot access the file")
        return real_replace(src, dst)

    monkeypatch.setattr(creds.os, "replace", flaky_replace)

    c = creds.load_cache(cache_path)
    creds.put_type_entry(c, URL, "survives", status=creds.STATUS_OK, variables=["X"])
    creds.save_cache(c, cache_path)

    assert calls["n"] == 4
    assert "survives" in creds.load_cache(cache_path)["instances"][URL]["types"]


def test_save_gives_up_quietly_and_leaves_no_debris(cache_path, monkeypatch):
    """A cache write that cannot succeed costs a re-measurement; it must not raise, and it
    must not leave temp files piling up next to the cache."""
    def always_fails(src, dst):
        raise PermissionError(32, "nope")

    monkeypatch.setattr(creds.os, "replace", always_fails)

    c = creds.load_cache(cache_path)
    creds.put_type_entry(c, URL, "lost", status=creds.STATUS_OK, variables=["X"])
    creds.save_cache(c, cache_path)  # must not raise

    leftovers = [p.name for p in cache_path.parent.iterdir()
                 if p.name.startswith(".credentials-cache-")]
    assert leftovers == []


def test_save_is_atomic_no_partial_file_observed(cache_path):
    """os.replace means a reader either sees the old file or the new one, never a partial."""
    c = creds.load_cache(cache_path)
    creds.put_type_entry(c, URL, "a", status=creds.STATUS_OK, variables=["A"])
    creds.save_cache(c, cache_path)
    first = cache_path.read_text(encoding="utf-8")

    creds.put_type_entry(c, URL, "b", status=creds.STATUS_OK, variables=["B"])
    creds.save_cache(c, cache_path)
    second = cache_path.read_text(encoding="utf-8")

    assert json.loads(first)  # both are complete, parseable documents
    assert json.loads(second)
    assert "b" in json.loads(second)["instances"][URL]["types"]


# ============================================================================
# Seed / measurement merge rule
# ============================================================================

def test_seed_fills_gaps(empty_cache):
    entry = creds.get_type_entry(empty_cache, URL, "vsphere__basic")
    assert entry["source"] == creds.SOURCE_SEED
    assert "VSPHERE_PASSWORD" in entry["vars"]


def test_measurement_wins_over_seed(empty_cache):
    creds.put_type_entry(empty_cache, URL, "vsphere__basic",
                         status=creds.STATUS_OK, variables=["VSPHERE_ONLY_THIS"])
    entry = creds.get_type_entry(empty_cache, URL, "vsphere__basic")
    assert entry["vars"] == ["VSPHERE_ONLY_THIS"]
    assert entry["source"] == creds.SOURCE_MEASURED


def test_measurements_are_per_instance(empty_cache):
    creds.put_type_entry(empty_cache, URL, "vsphere__basic",
                         status=creds.STATUS_OK, variables=["ONLY_HERE"])
    other = creds.get_type_entry(empty_cache, "https://other.example.com", "vsphere__basic")
    assert other["source"] == creds.SOURCE_SEED


def test_trailing_slash_in_url_is_the_same_instance(empty_cache):
    creds.put_type_entry(empty_cache, URL + "/", "foo", status=creds.STATUS_OK, variables=["X"])
    assert creds.get_type_entry(empty_cache, URL, "foo")["vars"] == ["X"]


def test_unmeasured_types_ignores_seeded_and_deduplicates(empty_cache):
    out = creds.unmeasured_types(
        empty_cache, URL, ["vsphere__basic", "brand__new", "brand__new", "github", None, ""]
    )
    assert out == ["brand__new"]


def test_force_rediscover_drops_measurements_but_not_the_seed(empty_cache):
    creds.put_type_entry(empty_cache, URL, "vsphere__basic",
                         status=creds.STATUS_OK, variables=["MEASURED"])
    creds.put_type_entry(empty_cache, URL, "brand__new",
                         status=creds.STATUS_OK, variables=["NEW"])

    creds.drop_measured_types(empty_cache, URL)

    assert creds.get_type_entry(empty_cache, URL, "vsphere__basic")["source"] == creds.SOURCE_SEED
    assert creds.get_type_entry(empty_cache, URL, "brand__new") is None


# ============================================================================
# Credential list TTL
# ============================================================================

def test_credential_list_roundtrip(empty_cache):
    creds.put_credential_list(empty_cache, URL, "VMaaS", [{"name": "a"}])
    assert creds.get_credential_list(empty_cache, URL, "VMaaS") == [{"name": "a"}]


def test_credential_list_expires_after_ttl(empty_cache):
    t0 = 1_000_000.0
    creds.put_credential_list(empty_cache, URL, "VMaaS", [{"name": "a"}], now=t0)

    just_inside = t0 + creds.CREDENTIAL_LIST_TTL_SECONDS - 1
    assert creds.get_credential_list(empty_cache, URL, "VMaaS", now=just_inside) is not None

    just_outside = t0 + creds.CREDENTIAL_LIST_TTL_SECONDS + 1
    assert creds.get_credential_list(empty_cache, URL, "VMaaS", now=just_outside) is None


def test_credential_list_absent_space_is_none(empty_cache):
    assert creds.get_credential_list(empty_cache, URL, "NoSuchSpace") is None


def test_credential_list_is_per_space(empty_cache):
    creds.put_credential_list(empty_cache, URL, "A", [{"name": "in-a"}])
    assert creds.get_credential_list(empty_cache, URL, "B") is None


# ============================================================================
# Parsing Torque's response
# ============================================================================

#: Shape taken verbatim from a live GET .../credentialstore/overridden_values response.
LIVE_VSPHERE = {
    "allowed_space_names": ["Applications", "VMaaS"],
    "all_spaces_allowed": False,
    "name": "vCenter-MX",
    "description": "",
    "cloud_type": "vsphere",
    "cloud_identifier": "mx-lab-hxvcenter.cisco.com",
    "credential_data": {
        "user": "administrator@vsphere.local",
        "password": None,
        "server": "mx-lab-hxvcenter.cisco.com",
        "validate_certificate": False,
        "type": "vsphere__basic",
    },
}

LIVE_AWS = {
    "allowed_space_names": [],
    "all_spaces_allowed": True,
    "name": "aws-cred",
    "cloud_type": "aws",
    "cloud_identifier": "111265209152",
    "credential_data": {"key": "AKIARTZ7MLNACYMN6NOG", "secret": None, "type": "aws__basic"},
}


def test_parse_extracts_type_and_public_fields():
    c = creds.parse_credential(LIVE_VSPHERE)
    assert c["name"] == "vCenter-MX"
    assert c["type"] == "vsphere__basic"
    assert c["allowed_space_names"] == ["Applications", "VMaaS"]
    assert c["public_fields"]["server"] == "mx-lab-hxvcenter.cisco.com"


def test_parse_drops_null_secret_fields():
    """Null is exactly how Torque marks a secret, and it is what redaction keys off."""
    c = creds.parse_credential(LIVE_VSPHERE)
    assert "password" not in c["public_fields"]


def test_parse_keeps_false_valued_fields():
    """`validate_certificate: False` is a real value, not a missing one."""
    c = creds.parse_credential(LIVE_VSPHERE)
    assert c["public_fields"]["validate_certificate"] is False


def test_displayable_fields_hides_access_key_id():
    c = creds.parse_credential(LIVE_AWS)
    assert "key" in c["public_fields"]
    assert "key" not in creds.displayable_fields(c)


def test_public_values_are_strings_with_both_boolean_spellings():
    """Torque renders booleans as 'true'/'false' or C#'s 'True'/'False' depending on the
    creator, so both must be treated as non-secret."""
    vals = creds.public_values(creds.parse_credential(LIVE_VSPHERE))
    assert "mx-lab-hxvcenter.cisco.com" in vals
    assert "false" in vals and "False" in vals


def test_parse_tolerates_missing_credential_data():
    c = creds.parse_credential({"name": "bare"})
    assert c["type"] is None
    assert c["public_fields"] == {}


# ============================================================================
# Lookup and pre-flight validation
# ============================================================================

def test_find_credential_is_case_insensitive():
    lst = [creds.parse_credential(LIVE_VSPHERE)]
    assert creds.find_credential(lst, "vcenter-mx")["name"] == "vCenter-MX"
    assert creds.find_credential(lst, "nope") is None


def test_space_restricted_credential_is_rejected_with_the_allowed_spaces_named():
    c = creds.parse_credential(LIVE_VSPHERE)
    entry = creds.SEED_TYPE_ENV_VARS["vsphere__basic"]
    err = creds.validate_credential_usable(c, entry, "AI-Studio", creds.SPACE_POLICY_PRECONFIGURED)
    assert err is not None
    assert "AI-Studio" in err and "VMaaS" in err
    assert "authorize" in err


def test_space_restricted_credential_is_allowed_in_a_listed_space():
    c = creds.parse_credential(LIVE_VSPHERE)
    entry = creds.SEED_TYPE_ENV_VARS["vsphere__basic"]
    assert creds.validate_credential_usable(
        c, entry, "VMaaS", creds.SPACE_POLICY_PRECONFIGURED) is None


def test_space_check_is_case_insensitive():
    c = creds.parse_credential(LIVE_VSPHERE)
    entry = creds.SEED_TYPE_ENV_VARS["vsphere__basic"]
    assert creds.validate_credential_usable(
        c, entry, "vmaas", creds.SPACE_POLICY_PRECONFIGURED) is None


def test_authorize_policy_does_not_reject_a_space_restricted_credential():
    c = creds.parse_credential(LIVE_VSPHERE)
    entry = creds.SEED_TYPE_ENV_VARS["vsphere__basic"]
    assert creds.validate_credential_usable(
        c, entry, "AI-Studio", creds.SPACE_POLICY_AUTHORIZE) is None


def test_all_spaces_allowed_credential_passes_anywhere():
    c = creds.parse_credential(LIVE_AWS)
    entry = creds.SEED_TYPE_ENV_VARS["aws__basic"]
    assert creds.validate_credential_usable(
        c, entry, "AnySpace", creds.SPACE_POLICY_PRECONFIGURED) is None


def test_unsupported_type_is_rejected_before_launch():
    """Torque accepts the launch and then kills the grain with 'unexpected error has
    occurred' — reproduced live with a github credential."""
    c = creds.parse_credential({
        "name": "ServiceCatalog", "all_spaces_allowed": True,
        "credential_data": {"token": None, "type": "github"},
    })
    err = creds.validate_credential_usable(
        c, creds.SEED_TYPE_ENV_VARS["github"], "VMaaS", creds.SPACE_POLICY_PRECONFIGURED)
    assert err is not None and "github" in err


def test_type_producing_no_env_vars_is_rejected():
    c = creds.parse_credential({
        "name": "k8s-sa", "all_spaces_allowed": True,
        "credential_data": {"service_account": "sa", "namespace": "ns",
                            "type": "kubernetes_service_account"},
    })
    err = creds.validate_credential_usable(
        c, creds.SEED_TYPE_ENV_VARS["kubernetes_service_account"],
        "VMaaS", creds.SPACE_POLICY_PRECONFIGURED)
    assert err is not None and "no environment variables" in err


def test_never_measured_type_is_not_rejected_so_discovery_can_run():
    c = creds.parse_credential({
        "name": "future", "all_spaces_allowed": True,
        "credential_data": {"type": "brand__new"},
    })
    assert creds.validate_credential_usable(
        c, None, "VMaaS", creds.SPACE_POLICY_PRECONFIGURED) is None


# ============================================================================
# Forwarding allow-list
# ============================================================================

def test_forwardable_vars_come_from_the_type_entry():
    entry = creds.SEED_TYPE_ENV_VARS["vsphere__basic"]
    out = creds.forwardable_vars(entry)
    assert "VSPHERE_PASSWORD" in out and "VMWARE_HOST" in out


def test_forwardable_vars_empty_for_unsupported_or_missing_type():
    assert creds.forwardable_vars(None) == []
    assert creds.forwardable_vars(creds.SEED_TYPE_ENV_VARS["github"]) == []
    assert creds.forwardable_vars(creds.SEED_TYPE_ENV_VARS["kubernetes_service_account"]) == []


def test_forwardable_vars_accepts_explicit_extras_and_deduplicates():
    entry = {"status": creds.STATUS_OK, "vars": ["A", "B"]}
    assert creds.forwardable_vars(entry, extra=["B", "C"]) == ["A", "B", "C"]


def test_forwardable_vars_never_includes_api_token_even_when_asked():
    assert "API_TOKEN" not in creds.forwardable_vars(
        {"status": creds.STATUS_OK, "vars": ["API_TOKEN", "OK_VAR"]}, extra=["API_TOKEN"])
