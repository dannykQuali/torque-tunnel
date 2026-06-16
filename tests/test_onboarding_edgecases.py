"""Edge-case regressions mined from mature JSON / round-trip test suites
(microsoft/node-jsonc-parser, nst/JSONTestSuite "Parsing JSON is a Minefield",
json5, CPython Lib/test/test_json, python-poetry/tomlkit, nlohmann/json,
serde_json). Each pins behavior on an input shape our property/fuzz generators
structurally cannot reach.

Marquee cases: lone-surrogate / NUL escapes and big / high-precision numbers in
UNRELATED keys+values. They round-trip correctly ONLY because minimal-edit never
decodes/re-encodes untouched spans — a reparse+reserialize implementation would
mangle the numbers or crash (UnicodeEncodeError) on the unrelated surrogate.
"""

import os
import sys

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import onboarding
import _onboarding_invariants as inv

_SLOW = [HealthCheck.too_slow]


def _entry(fam):
    return onboarding.server_entry(fam, python="/x/py")


def _assert_safe(before, after, res, *, family, entry):
    assert res.status in {"created", "added", "unchanged", "aborted"}, f"bad status {res.status}"
    if res.status == "aborted":
        inv.assert_aborted_untouched(before, after, res)
    elif res.status == "added":
        inv.assert_added(before, after, res, family=family, entry=entry)
    elif res.status == "unchanged":
        assert after == before
    else:
        assert before.strip() == ""


# ===========================================================================
# Preservation of bytes our generators never emit (the design's whole point)
# ===========================================================================

_BS = chr(92)   # a single backslash, built unambiguously (avoids escape mangling)


@pytest.mark.parametrize("token", [
    _BS + "uDFAA",                  # lone low surrogate escape
    _BS + "uD800",                  # lone high surrogate escape
    _BS + "uD83D" + _BS + "uDE00",  # valid surrogate pair
    _BS + "u0000",                  # escaped NUL
], ids=["lone-low-surrogate", "lone-high-surrogate", "surrogate-pair", "escaped-NUL"])
def test_surrogate_or_nul_escape_in_value_preserved(tmp_path, token):
    text = '{"k": "X' + token + 'Y", "mcpServers": {"a": {}}}'
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_added(text, after, res, family="mcpServers", entry=_entry("mcpServers"))
    assert token in after                       # escape sequence preserved verbatim


def test_lone_surrogate_escape_in_key_preserved(tmp_path):
    text = '{"' + r"\uDFAA" + '": 0, "mcpServers": {"a": {}}}'
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_added(text, after, res, family="mcpServers", entry=_entry("mcpServers"))
    assert r"\uDFAA" in after


def test_high_precision_and_bigint_siblings_preserved(tmp_path):
    text = '{"f": 1.000000000000000005, "big": 10000000000000000999, "mcpServers": {"a": {}}}'
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_added(text, after, res, family="mcpServers", entry=_entry("mcpServers"))
    # exact digit strings survive — a parse->float->reserialize would destroy these
    assert "1.000000000000000005" in after
    assert "10000000000000000999" in after


def test_infinity_nan_siblings_preserved(tmp_path):
    # stdlib json.loads ACCEPTS Infinity/NaN (unlike hex), so this ADDS rather than aborts.
    text = '{"x": Infinity, "y": NaN, "mcpServers": {"a": {}}}'
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_added(text, after, res, family="mcpServers", entry=_entry("mcpServers"))
    assert "Infinity" in after and "NaN" in after


def test_leading_trailing_whitespace_around_root_preserved(tmp_path):
    text = '  {"mcpServers": {"a": {}}}  \n'
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_added(text, after, res, family="mcpServers", entry=_entry("mcpServers"))
    assert after.startswith("  {") and after.endswith("}  \n")   # padding intact


def test_no_trailing_newline_single_line(tmp_path):
    text = '{"mcpServers": {"foo": 10}}'
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_added(text, after, res, family="mcpServers", entry=_entry("mcpServers"))


# Structurally-safe (we insert as FIRST member) — guards against a future append-mode.
@pytest.mark.parametrize("text", [
    '{\n  "mcpServers": {\n    "a": 1 // trailing line comment\n  }\n}',
    '{"mcpServers": {"a": 1 /* trailing block comment */}}',
])
def test_comments_around_last_member_preserved(tmp_path, text):
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_added(text, after, res, family="mcpServers", entry=_entry("mcpServers"))


# ===========================================================================
# JSON5-only syntax → safe abort untouched (the JSONC-not-JSON5 boundary)
# ===========================================================================

@pytest.mark.parametrize("text", [
    "{'mcpServers': {'a': 1}}",                 # single-quoted keys/strings
    "{mcpServers: {a: 1}}",                      # bare/unquoted identifier keys
    '{"x": 0xFF, "mcpServers": {"a": {}}}',      # hex number literal
    '{"x": .5, "mcpServers": {"a": {}}}',        # leading-decimal number
    '{"x": +1, "mcpServers": {"a": {}}}',        # explicit plus sign
], ids=["single-quotes", "bare-keys", "hex", "leading-decimal", "plus-sign"])
def test_json5_only_syntax_aborts_untouched(tmp_path, text):
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_aborted_untouched(text, after, res)


# ===========================================================================
# Non-object family values → explicit abort untouched
# ===========================================================================

@pytest.mark.parametrize("text", [
    '{"mcpServers": null}',
    '{"mcpServers": 123}',
    '{"mcpServers": [1, 2]}',
    '{"mcpServers": true}',
    '{"mcpServers": "oops"}',
], ids=["null", "number", "array", "bool", "string"])
def test_non_object_family_aborts_untouched(tmp_path, text):
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    inv.assert_aborted_untouched(text, after, res)
    assert "not an object" in res.reason            # explicit, not accidental


def test_duplicate_root_family_null_and_object_safe(tmp_path):
    text = '{"mcpServers": null, "mcpServers": {"a": {}}}'
    res, after = inv.run_merge(tmp_path / "c.json", text, family="mcpServers", entry=_entry("mcpServers"))
    _assert_safe(text, after, res, family="mcpServers", entry=_entry("mcpServers"))


# ===========================================================================
# Property: broaden generation toward the mined gaps (whitespace/BOM/numbers,
# and JSON5 noise) — assert the safe-outcome dichotomy on every input.
# ===========================================================================

_BASES = [
    '{"servers": {"a": {"command": "x"}}}',
    '{"mcpServers": {}}',
    '{"other": 1, "servers": {"a": {}}}',
    '{}',
]
_PAD = st.sampled_from(["", " ", "  \n", "\t", "\r\n"])
_NUMSIB = st.sampled_from(["", '"n": 1e400,', '"n": 1.000000000000000005,',
                           '"n": 100000000000000000009,', '"n": Infinity,', '"s": "\\uD800",'])


@settings(max_examples=400, deadline=None, suppress_health_check=_SLOW)
@given(base=st.sampled_from(_BASES), lead=_PAD, trail=_PAD, bom=st.booleans(),
       numsib=_NUMSIB, family=st.sampled_from(["mcpServers", "servers"]))
def test_property_wrapped_and_numbers_safe(tmp_path_factory, base, lead, trail, bom, numsib, family):
    doc = base
    if numsib and doc.startswith("{") and doc != "{}":
        doc = "{" + numsib + doc[1:]            # inject a number/escape sibling after the root brace
    text = ("\ufeff" if bom else "") + lead + doc + trail
    path = tmp_path_factory.mktemp("e") / "c.json"
    res, after = inv.run_merge(path, text, family=family, entry=_entry(family))
    _assert_safe(text, after, res, family=family, entry=_entry(family))


_J5NOISE = st.sampled_from(["'", "0x1F", "//\n", "/*", ",}", "NaN", "Infinity",
                            "\\uD800", "{a:1}", "\t", "\ufeff"])


@settings(max_examples=400, deadline=None, suppress_health_check=_SLOW)
@given(base=st.sampled_from(_BASES),
       inserts=st.lists(st.tuples(st.integers(min_value=0, max_value=80), _J5NOISE), max_size=6),
       family=st.sampled_from(["mcpServers", "servers"]))
def test_property_json5_noise_safe(tmp_path_factory, base, inserts, family):
    s = list(base)
    for pos, tok in inserts:
        s.insert(pos % (len(s) + 1), tok)
    text = "".join(s)
    path = tmp_path_factory.mktemp("e") / "c.json"
    res, after = inv.run_merge(path, text, family=family, entry=_entry(family))
    _assert_safe(text, after, res, family=family, entry=_entry(family))
