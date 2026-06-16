"""Fuzz tests for the parser/locator and merge_entry.

Safety contract under ANY input (random structural noise, mutated valid docs,
arbitrary unicode):
  - the helper scanners never raise and return the right types;
  - merge_entry never raises; it returns one of the known statuses;
  - if it ABORTS, the file is left byte-for-byte untouched (no corruption);
  - if it ACTS ("added"), the result satisfies the full invariant oracle.

i.e. a malformed input can only ever produce "safe abort" or "correct insert",
never a damaged file or an exception.
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

# Structural characters that exercise the scanners' state machine, plus a few
# letters so fragments like mcpServers/servers/comments can occasionally form.
_STRUCT = list('{}[]":,:/*\\ \t\n\r01abcmMsServ')


def _assert_safe_outcome(before, after, res, *, family, entry):
    assert res.status in {"created", "added", "unchanged", "aborted"}, f"bad status {res.status}"
    if res.status == "aborted":
        inv.assert_aborted_untouched(before, after, res)
    elif res.status == "added":
        inv.assert_added(before, after, res, family=family, entry=entry)
    elif res.status == "unchanged":
        assert after == before
    elif res.status == "created":
        assert before.strip() == ""          # fresh write only for blank input


@settings(max_examples=1000, deadline=None, suppress_health_check=_SLOW)
@given(text=st.text(alphabet=st.sampled_from(_STRUCT), max_size=90),
       family=st.sampled_from(["mcpServers", "servers"]))
def test_fuzz_structural_noise_never_corrupts(tmp_path_factory, text, family):
    entry = onboarding.server_entry(family, python="/x/py")
    path = tmp_path_factory.mktemp("f") / "c.json"
    res, after = inv.run_merge(path, text, family=family, entry=entry)
    _assert_safe_outcome(text, after, res, family=family, entry=entry)


_BASES = [
    '{\n  "servers": {\n    "a": {"command": "x"}\n  }\n}\n',
    '{\n  // c\n  "mcpServers": {}\n}\n',
    "{}",
    '{"mcpServers": {"a": 1, "torque-tunnel": {"command": "old"}}}',
    '{\n  "servers": {\n    /* only a comment */\n  },\n}\n',
]


@settings(max_examples=1000, deadline=None, suppress_health_check=_SLOW)
@given(base=st.sampled_from(_BASES),
       ops=st.lists(st.tuples(st.sampled_from(["del", "ins", "dup"]),
                              st.integers(min_value=0, max_value=300),
                              st.sampled_from(list('{}[]":,/* \n\t'))),
                    max_size=10),
       family=st.sampled_from(["mcpServers", "servers"]))
def test_fuzz_mutated_valid_never_corrupts(tmp_path_factory, base, ops, family):
    s = list(base)
    for op, pos, ch in ops:
        if not s:
            break
        i = pos % len(s)
        if op == "del":
            del s[i]
        elif op == "ins":
            s.insert(i, ch)
        else:  # dup
            s.insert(i, s[i])
    text = "".join(s)
    entry = onboarding.server_entry(family, python="/x/py")
    path = tmp_path_factory.mktemp("f") / "c.json"
    res, after = inv.run_merge(path, text, family=family, entry=entry)
    _assert_safe_outcome(text, after, res, family=family, entry=entry)


@settings(max_examples=1500, deadline=None, suppress_health_check=_SLOW)
@given(text=st.text(st.characters(blacklist_categories=("Cs",)), max_size=200),
       key=st.sampled_from(["mcpServers", "servers", "x", '"', ""]))
def test_fuzz_helpers_never_raise(text, key):
    assert isinstance(onboarding._strip_jsonc(text), str)
    assert isinstance(onboarding._remove_trailing_commas(text), str)
    data, ok = onboarding._load_lenient(text)
    assert isinstance(ok, bool) and (data is None or isinstance(data, (dict, list, str, int, float, bool)))
    assert isinstance(onboarding._skip_ws_comments(text, 0), int)
    assert isinstance(onboarding._parses_strict(text), bool)
    r1 = onboarding._find_root_object_brace(text)
    assert r1 is None or (isinstance(r1, int) and 0 <= r1 < len(text))
    r2 = onboarding._find_member_object_brace(text, key)
    assert r2 is None or (isinstance(r2, int) and 0 <= r2 < len(text))


# Full unicode incl. astral planes (no surrogates → always utf-8 encodable),
# plus multi-char tokens that create unterminated comments/strings & lone escapes.
_UNI = st.characters(blacklist_categories=("Cs",))
_TOKENS = st.sampled_from(["\\", '"', "/*", "*/", "//", "\n", "\r\n", "\t", "}", "{", ",", ":"])


@settings(max_examples=1200, deadline=None, suppress_health_check=_SLOW)
@given(base=st.sampled_from(_BASES),
       inserts=st.lists(st.tuples(st.integers(min_value=0, max_value=400),
                                  st.one_of(_UNI, _TOKENS)), max_size=14),
       family=st.sampled_from(["mcpServers", "servers"]))
def test_fuzz_unicode_and_unterminated_never_corrupts(tmp_path_factory, base, inserts, family):
    s = list(base)
    for pos, ch in inserts:
        s.insert(pos % (len(s) + 1), ch)
    text = "".join(s)
    entry = onboarding.server_entry(family, python="/x/py")
    path = tmp_path_factory.mktemp("f") / "c.json"
    res, after = inv.run_merge(path, text, family=family, entry=entry)
    _assert_safe_outcome(text, after, res, family=family, entry=entry)


@pytest.mark.parametrize("text", [
    '{"servers": {"a": {}}} // trailing comment no newline',
    '{"servers": {"a": {}',                       # unterminated object
    '{"servers": {"a": "\\',                      # trailing backslash inside an unterminated string
    '{ /* never closed',                          # unterminated block comment
    '{"servers": {"a": {}} /* tail comment never closed',
    '{"servers": {"a": "unterminated string }',
    '{"servers": {"a": {} ' + "\\" * 7 + '}}',    # lone backslash run
    '\ufeff{ /* bom then unterminated',            # BOM + unterminated
])
def test_unterminated_and_escape_inputs_are_safe(tmp_path, text):
    entry = onboarding.server_entry("servers", python="/x/py")
    res, after = inv.run_merge(tmp_path / "c.json", text, family="servers", entry=entry)
    _assert_safe_outcome(text, after, res, family="servers", entry=entry)
