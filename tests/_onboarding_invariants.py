"""Shared invariant oracle for the onboarding merge_entry suites.

Not a test module (leading underscore → pytest won't collect it). Property,
corpus, and fuzz suites all import these helpers so "correct" and "safe" mean
exactly one thing across the board.

The strongest invariant here is `is_pure_single_insertion`: it proves, without
knowing anything about merge_entry's internals, that the result is the original
text with exactly ONE contiguous block inserted — i.e. nothing the user had was
removed, reordered, or rewritten.
"""

import json
import math
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import onboarding


# --------------------------------------------------------------------------
# Driving merge_entry on raw text (bytes preserved exactly — no newline xlat)
# --------------------------------------------------------------------------

class MemoryPath:
    """A config file held in memory instead of on disk, for the property suites.

    Opening a file costs ~5 ms on the Windows dev machine (each new file is scanned),
    and every example opened four, so disk I/O was ~80% of those suites' runtime.
    They test merge_entry's TEXT logic, which runs unchanged here: run_merge points
    its two file helpers at this object. Its disk side (atomic replace, lock retries,
    backup, verify-or-restore, real CRLF/BOM round-trips) is covered by the real-file
    tests in test_onboarding_hardening, test_onboarding and the corpus.

    Text is stored as decoded exactly as merge_entry reads a file (UTF-8, no newline
    translation, a BOM kept as U+FEFF).
    """

    def __init__(self, name="c.json", files=None):
        self.name = name
        self._files = {} if files is None else files

    def exists(self):
        return self.name in self._files

    def read_bytes(self):
        return self._files[self.name].encode("utf-8")

    def write_bytes(self, data):
        self._files[self.name] = data.decode("utf-8")

    def with_name(self, name):
        return MemoryPath(name, self._files)

    @property
    def parent(self):
        return self

    def mkdir(self, parents=False, exist_ok=False):
        pass

    # Stand-ins for onboarding._read_text_keep_newlines / _write_text_exact
    def _read_text(self):
        try:
            return self._files[self.name]
        except KeyError:
            raise FileNotFoundError(self.name) from None

    def _write_text(self, text):
        self._files[self.name] = text

    def __repr__(self):
        return f"MemoryPath({self.name!r})"


def memory_path(filename):
    """A fresh, empty in-memory file named `filename` - one per Hypothesis example."""
    return MemoryPath(filename)


def run_merge(path, before_text, *, family, entry, server_name="torque-tunnel", make_backup=False):
    """Write `before_text` (or leave absent if None) to `path`, run merge_entry,
    return (result, after_text or None). Bytes are written/read verbatim.
    `path` is a real path or a MemoryPath."""
    if before_text is not None:
        path.write_bytes(before_text.encode("utf-8"))
    if isinstance(path, MemoryPath):
        with mock.patch.object(onboarding, "_read_text_keep_newlines", MemoryPath._read_text), \
             mock.patch.object(onboarding, "_write_text_exact", MemoryPath._write_text):
            res = onboarding.merge_entry(path, family, entry, server_name=server_name,
                                         make_backup=make_backup)
    else:
        res = onboarding.merge_entry(path, family, entry, server_name=server_name,
                                     make_backup=make_backup)
    after = path.read_bytes().decode("utf-8") if path.exists() else None
    return res, after


# --------------------------------------------------------------------------
# Pure structural invariants
# --------------------------------------------------------------------------

def is_pure_single_insertion(before: str, after: str) -> bool:
    """True iff `after` equals `before` with exactly one contiguous block
    inserted somewhere (nothing removed/altered/reordered)."""
    if after == before:
        return False  # an insertion of *something* is expected; use == checks for no-op
    # longest common prefix
    p = 0
    while p < len(before) and p < len(after) and before[p] == after[p]:
        p += 1
    # longest common suffix that doesn't overlap the matched prefix
    s = 0
    while s < (len(before) - p) and s < (len(after) - p) and before[-1 - s] == after[-1 - s]:
        s += 1
    return p + s == len(before)


def line_ending_style(text: str) -> str:
    has_crlf = "\r\n" in text
    has_bare_lf = "\n" in text.replace("\r\n", "")
    if has_crlf and not has_bare_lf:
        return "crlf"
    if has_bare_lf and not has_crlf:
        return "lf"
    if not has_crlf and not has_bare_lf:
        return "none"
    return "mixed"


# --------------------------------------------------------------------------
# Outcome assertions
# --------------------------------------------------------------------------

def _strip_bom(t: str) -> str:
    return t[1:] if t.startswith("\ufeff") else t


def _deep_eq(a, b) -> bool:
    """Structural equality that treats NaN == NaN (so a preserved NaN sibling
    doesn't false-fail the value cross-check; byte-preservation already proved
    the content is identical)."""
    if isinstance(a, float) and isinstance(b, float):
        return a == b or (math.isnan(a) and math.isnan(b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_deep_eq(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_deep_eq(x, y) for x, y in zip(a, b))
    return a == b


def assert_added(before: str, after: str, res, *, family, entry, server_name="torque-tunnel"):
    """Full invariant set for a successful ADD into an existing file."""
    assert res.status == "added", f"expected added, got {res.status} ({res.reason})"
    assert after is not None

    # 0) A BOM, if present, is preserved exactly.
    assert before.startswith("\ufeff") == after.startswith("\ufeff"), "BOM presence changed"

    # 1) Only inserted — nothing of the user's content removed/altered.
    assert is_pure_single_insertion(before, after), "result is not a pure single insertion of the original"

    # 2) Result parses and is semantically original + our entry (BOM stripped for parsing).
    adata, aok = onboarding._load_lenient(_strip_bom(after))
    bdata, bok = onboarding._load_lenient(_strip_bom(before))
    assert aok and bok and isinstance(adata, dict) and isinstance(bdata, dict)
    assert _deep_eq(adata.get(family, {}).get(server_name), entry), "entry missing or wrong"
    # every prior top-level key preserved with identical value
    for k, v in bdata.items():
        if k == family:
            continue
        assert _deep_eq(adata.get(k), v), f"top-level key {k!r} changed"
    # no surprise extra top-level keys
    assert set(adata.keys()) <= set(bdata.keys()) | {family}
    # every prior server preserved with identical value; only our entry added
    bservers = bdata.get(family, {}) if isinstance(bdata.get(family), dict) else {}
    for s, v in bservers.items():
        assert _deep_eq(adata[family].get(s), v), f"server {s!r} changed"
    assert set(adata[family].keys()) <= set(bservers.keys()) | {server_name}

    # 3) strict-stays-strict (on BOM-stripped content)
    if onboarding._parses_strict(_strip_bom(before)):
        assert onboarding._parses_strict(_strip_bom(after)), "strict-JSON input produced non-strict output"

    # 4) line endings not flipped. Introducing the first newline (as LF) into a
    #    newline-less document is fine; flipping existing LF<->CRLF is not.
    b_style = line_ending_style(before)
    if b_style == "crlf":
        assert "\n" not in after.replace("\r\n", ""), "CRLF file gained a bare LF"
    elif b_style == "lf":
        assert "\r\n" not in after, "LF file gained CRLF"


def assert_noop(before: str, after: str, res):
    """Already-present → file byte-identical, no write."""
    assert res.status == "unchanged", f"expected unchanged, got {res.status} ({res.reason})"
    assert after == before, "file changed on a no-op"
    assert res.backup is None


def assert_aborted_untouched(before: str, after: str, res):
    """Abort (incl. post-write restore) → file byte-identical to original."""
    assert res.status == "aborted", f"expected aborted, got {res.status}"
    assert after == before, "aborted run still changed the file!"


def assert_created(after: str, res, *, family, entry, server_name="torque-tunnel"):
    """Fresh/blank file → clean JSON with our entry."""
    assert res.status == "created", f"expected created, got {res.status} ({res.reason})"
    data = json.loads(after)   # fresh write is always strict JSON
    assert data[family][server_name] == entry
