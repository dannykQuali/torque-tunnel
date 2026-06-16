"""Regression/hardening tests driven by the adversarial red-team + completeness
critic findings:

  - deep nesting must abort (not raise RecursionError)            [confirmed defect]
  - write / backup / restore I/O failures must abort, never raise [critic G1]
  - make_backup=True (the PRODUCTION default) backup behavior      [critic G2]
  - UTF-8 BOM files are onboarded and the BOM is preserved         [critic G3]
  - created / blank / dry_run branches                            [critic G4]
  - duplicate root family key is handled safely                   [critic G8]
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import onboarding
import _onboarding_invariants as inv

BOM = "\ufeff"
ENTRY = onboarding.server_entry  # convenience


# ---- confirmed defect: deep nesting must not raise -------------------------

def test_deep_nesting_aborts_without_raising(tmp_path):
    depth = 20000
    text = '{\n  "k": ' + ('{"a":' * depth) + '0' + ('}' * depth) + '\n}'
    path = tmp_path / "c.json"
    path.write_bytes(text.encode("utf-8"))
    res = onboarding.merge_entry(path, "mcpServers", ENTRY("mcpServers", python="/x/py"), make_backup=False)
    assert res.status == "aborted"
    assert path.read_bytes().decode("utf-8") == text       # untouched


def test_deep_nesting_helpers_dont_raise():
    deep = "[" * 30000 + "]" * 30000
    data, ok = onboarding._load_lenient(deep)
    assert ok is False and data is None                    # safe-abort signal, no raise
    assert onboarding._parses_strict(deep) is False


# ---- G1: I/O failures abort, never raise -----------------------------------

def test_main_write_failure_aborts_untouched(tmp_path, monkeypatch):
    text = '{"servers": {"a": {"command": "x"}}}'
    path = tmp_path / "c.json"
    path.write_bytes(text.encode("utf-8"))
    monkeypatch.setattr(onboarding, "_write_text_exact",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    res = onboarding.merge_entry(path, "servers", ENTRY("servers"), make_backup=False)
    assert res.status == "aborted"
    assert path.read_bytes().decode("utf-8") == text       # nothing written


def test_backup_write_failure_aborts_untouched(tmp_path, monkeypatch):
    text = '{"servers": {"a": {"command": "x"}}}'
    path = tmp_path / "c.json"
    path.write_bytes(text.encode("utf-8"))
    monkeypatch.setattr(onboarding, "_write_text_exact",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("locked")))
    res = onboarding.merge_entry(path, "servers", ENTRY("servers"), make_backup=True)
    assert res.status == "aborted"
    assert path.read_bytes().decode("utf-8") == text


def test_restore_failure_never_raises(tmp_path, monkeypatch):
    """If the main write corrupts AND the restore write also fails, merge_entry
    must still NOT raise — it returns aborted (best-effort restore)."""
    text = '{"servers": {"a": {"command": "x"}}}'
    path = tmp_path / "c.json"
    path.write_bytes(text.encode("utf-8"))
    real = onboarding._write_text_exact
    state = {"n": 0}

    def flaky(p, t):
        state["n"] += 1
        if state["n"] == 1:
            real(p, "garbage not json")     # main write → corrupt on disk
        else:
            raise OSError("restore failed")  # restore write fails
    monkeypatch.setattr(onboarding, "_write_text_exact", flaky)
    res = onboarding.merge_entry(path, "servers", ENTRY("servers"), make_backup=False)
    assert res.status == "aborted"           # no exception propagated


# ---- G2: make_backup=True (production default) -----------------------------

def test_backup_contains_original_bytes(tmp_path):
    text = '{\n  "servers": {\n    "a": {"command": "x"}\n  }\n}\n'
    path = tmp_path / "mcp.json"
    res, after = inv.run_merge(path, text, family="servers", entry=ENTRY("servers", python="/x/py"), make_backup=True)
    assert res.status == "added"
    bak = path.with_name(path.name + ".bak")
    assert bak.exists()
    assert bak.read_bytes().decode("utf-8") == text          # exact original
    assert res.backup == bak


def test_backup_overwrites_preexisting_bak(tmp_path):
    """Documents behavior: an existing <file>.bak is replaced by the current original."""
    text = '{"servers": {"a": {"command": "x"}}}'
    path = tmp_path / "mcp.json"
    path.write_bytes(text.encode("utf-8"))
    bak = path.with_name(path.name + ".bak")
    bak.write_bytes(b"STALE PRIOR BACKUP")
    onboarding.merge_entry(path, "servers", ENTRY("servers"), make_backup=True)
    assert bak.read_bytes().decode("utf-8") == text          # replaced with the real original


# ---- G3: UTF-8 BOM ---------------------------------------------------------

def test_bom_preserved_on_add(tmp_path):
    text = BOM + '{\n  "servers": {\n    "a": {"command": "x"}\n  }\n}\n'
    path = tmp_path / "c.json"
    res, after = inv.run_merge(path, text, family="servers", entry=ENTRY("servers", python="/x/py"))
    assert res.status == "added"
    assert after.startswith(BOM)                              # BOM kept
    inv.assert_added(text, after, res, family="servers", entry=ENTRY("servers", python="/x/py"))
    data, _ = onboarding._load_lenient(after[1:])
    assert data["servers"]["torque-tunnel"]["command"] == "/x/py"
    assert data["servers"]["a"] == {"command": "x"}


def test_bom_present_is_byte_identical_noop(tmp_path):
    text = BOM + '{"servers": {"torque-tunnel": {"x": 1}, "a": {}}}'
    path = tmp_path / "c.json"
    res, after = inv.run_merge(path, text, family="servers", entry=ENTRY("servers"))
    inv.assert_noop(text, after, res)


def test_bom_strict_file_stays_strict(tmp_path):
    text = BOM + '{"mcpServers": {"a": {"command": "x"}}}'
    path = tmp_path / "c.json"
    res, after = inv.run_merge(path, text, family="mcpServers", entry=ENTRY("mcpServers", python="/x/py"))
    assert res.status == "added"
    assert onboarding._parses_strict(after[1:])               # inner content still strict JSON


# ---- G4: created / blank / dry-run -----------------------------------------

def test_created_on_missing_path(tmp_path):
    path = tmp_path / "new.json"            # does not exist
    res, after = inv.run_merge(path, None, family="mcpServers", entry=ENTRY("mcpServers", python="/x/py"))
    inv.assert_created(after, res, family="mcpServers", entry=ENTRY("mcpServers", python="/x/py"))


def test_blank_file_created(tmp_path):
    path = tmp_path / "c.json"
    res, after = inv.run_merge(path, "   \n\t\n", family="servers", entry=ENTRY("servers", python="/x/py"))
    inv.assert_created(after, res, family="servers", entry=ENTRY("servers", python="/x/py"))


def test_dry_run_existing_untouched(tmp_path):
    text = '{"servers": {"a": {}}}'                          # tt absent → would add
    path = tmp_path / "c.json"
    path.write_bytes(text.encode("utf-8"))
    res = onboarding.merge_entry(path, "servers", ENTRY("servers"), dry_run=True, make_backup=False)
    assert res.status == "dry-run"
    assert path.read_bytes().decode("utf-8") == text       # untouched


def test_dry_run_missing_not_created(tmp_path):
    path = tmp_path / "x.json"
    res = onboarding.merge_entry(path, "servers", ENTRY("servers"), dry_run=True)
    assert res.status == "dry-run"
    assert not path.exists()


# ---- G8: duplicate root family key -----------------------------------------

def test_duplicate_root_family_key_is_safe(tmp_path):
    text = '{"servers": {"a": {}}, "servers": {"b": {}}}'   # duplicate root key
    path = tmp_path / "c.json"
    res, after = inv.run_merge(path, text, family="servers", entry=ENTRY("servers"))
    # Must be safe: either a correct add (pure insertion) or an untouched abort.
    if res.status == "added":
        inv.assert_added(text, after, res, family="servers", entry=ENTRY("servers"))
    else:
        inv.assert_aborted_untouched(text, after, res)
