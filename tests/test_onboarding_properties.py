"""Property-based tests (Hypothesis) for merge_entry.

Generates a broad space of JSON / JSONC config documents (nested objects/arrays,
unicode, escaped quotes, comments, trailing commas, varying indent, LF/CRLF) and
asserts the invariant oracle holds for EVERY generated input — far wider coverage
than hand-written examples.

Core invariants (see _onboarding_invariants):
  - add  → result is a *pure single insertion* of the original (nothing removed),
           semantically original+entry, strict-stays-strict, line endings kept.
  - present → byte-identical no-op.
  - any outcome that isn't "added"/"created"/"unchanged" must be "aborted", and
    an abort never changes the file.
"""

import os
import sys

import pytest
from hypothesis import given, settings, strategies as st, assume, HealthCheck

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import onboarding
import _onboarding_invariants as inv


# --- strategies ------------------------------------------------------------

# JSON-safe key/string text (printable, no control chars; json.dumps handles escaping)
_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), min_codepoint=32, max_codepoint=0x2FFF),
    max_size=12,
)

_json_scalar = st.one_of(
    st.none(), st.booleans(),
    st.integers(min_value=-10_000, max_value=10_000),
    _text,
)

_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(_text, children, max_size=3),
    ),
    max_leaves=6,
)

# Other top-level keys must not collide with the family key (added separately).
_other_keys = st.dictionaries(
    _text.filter(lambda k: k not in ("mcpServers", "servers")),
    _json_value, max_size=3,
)

# A server map (object of name -> server config). May or may not contain torque-tunnel.
_servers = st.dictionaries(_text, _json_value, max_size=3)

_family = st.sampled_from(["mcpServers", "servers"])
_indent = st.sampled_from([2, 4, "\t", None])
_eol = st.sampled_from(["\n", "\r\n"])


def _render(other, family, servers_or_none, indent, eol, add_comment):
    """Build a JSON/JSONC document string from parts."""
    import json
    doc = dict(other)
    if servers_or_none is not None:
        doc[family] = servers_or_none
    text = json.dumps(doc, indent=indent, ensure_ascii=False)
    if add_comment and text.startswith("{"):
        # inject a line + block comment right after the root brace (valid JSONC)
        text = text[:1] + "\n  // generated note\n  /* block */\n" + text[1:]
    if eol == "\r\n":
        text = text.replace("\n", "\r\n")
    return text


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    other=_other_keys,
    family=_family,
    servers=st.one_of(st.none(), _servers),
    indent=_indent,
    eol=_eol,
    add_comment=st.booleans(),
    has_tt=st.booleans(),
    data=st.data(),
)
def test_merge_invariants(tmp_path_factory, other, family, servers, indent, eol, add_comment, has_tt, data):
    entry = onboarding.server_entry(family, python="/x/py")

    # Optionally pre-place torque-tunnel so we also exercise the no-op path.
    if servers is not None and has_tt:
        servers = dict(servers)
        servers["torque-tunnel"] = {"command": "/preexisting/py", "args": []}

    text = _render(other, family, servers, indent, eol, add_comment)
    bdata, ok = onboarding._load_lenient(text)
    assume(ok and isinstance(bdata, dict))                 # discard malformed generations
    # _render put `text` together; confirm the family slot is what we think
    fam_present = isinstance(bdata.get(family), dict)
    tt_present = fam_present and "torque-tunnel" in bdata[family]

    path = tmp_path_factory.mktemp("p") / "cfg.json"
    res, after = inv.run_merge(path, text, family=family, entry=entry)

    # An abort is always acceptable IF the file is left untouched.
    if res.status == "aborted":
        inv.assert_aborted_untouched(text, after, res)
        return

    if tt_present:
        inv.assert_noop(text, after, res)
    else:
        inv.assert_added(text, after, res, family=family, entry=entry)


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(other=_other_keys, family=_family, servers=st.one_of(st.none(), _servers),
       indent=_indent, eol=_eol, add_comment=st.booleans())
def test_idempotent(tmp_path_factory, other, family, servers, indent, eol, add_comment):
    """After a successful add, a second run is a byte-identical no-op."""
    entry = onboarding.server_entry(family, python="/x/py")
    text = _render(other, family, servers, indent, eol, add_comment)
    bdata, ok = onboarding._load_lenient(text)
    assume(ok and isinstance(bdata, dict))
    assume(not (isinstance(bdata.get(family), dict) and "torque-tunnel" in bdata[family]))

    path = tmp_path_factory.mktemp("p") / "cfg.json"
    res1, after1 = inv.run_merge(path, text, family=family, entry=entry)
    assume(res1.status == "added")              # only continue from a successful add
    res2, after2 = inv.run_merge(path, None, family=family, entry=entry)  # re-run on the now-existing file
    inv.assert_noop(after1, after2, res2)
