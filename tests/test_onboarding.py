"""Tests for the cross-platform onboarding/configure logic.

These exercise the real production code in torque_tunnel.onboarding. Filesystem
locations are redirected with monkeypatch (Path.home + APPDATA), so no real user
config is touched. platform.system() is overridden to test all three OS layouts.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import onboarding


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """Redirect Path.home() and %APPDATA% into a temp dir."""
    home = tmp_path / "home"
    home.mkdir()
    appdata = home / "AppData" / "Roaming"
    appdata.mkdir(parents=True)
    monkeypatch.setattr(onboarding.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("APPDATA", str(appdata))
    return home


# ---------------------------------------------------------------------------
# config_path: per-OS locations
# ---------------------------------------------------------------------------

def test_claude_code_path_is_home_dotclaude_json(fake_home):
    assert onboarding.config_path("claude-code") == fake_home / ".claude.json"


def test_copilot_path_windows(fake_home):
    p = onboarding.config_path("copilot", system="Windows")
    assert p == fake_home / "AppData" / "Roaming" / "Code" / "User" / "mcp.json"


def test_copilot_path_linux(fake_home):
    p = onboarding.config_path("copilot", system="Linux")
    assert p == fake_home / ".config" / "Code" / "User" / "mcp.json"


def test_copilot_path_macos(fake_home):
    p = onboarding.config_path("copilot", system="Darwin")
    assert p == fake_home / "Library" / "Application Support" / "Code" / "User" / "mcp.json"


def test_cursor_and_windsurf_paths(fake_home):
    assert onboarding.config_path("cursor") == fake_home / ".cursor" / "mcp.json"
    assert onboarding.config_path("windsurf") == fake_home / ".codeium" / "windsurf" / "mcp_config.json"


def test_unknown_client_raises(fake_home):
    with pytest.raises(KeyError):
        onboarding.config_path("notaclient")


# ---------------------------------------------------------------------------
# server_entry: schema families
# ---------------------------------------------------------------------------

def test_server_entry_mcpservers_family():
    entry = onboarding.server_entry("mcpServers", python="/x/py")
    assert entry == {"command": "/x/py", "args": ["-m", "torque_tunnel.mcp_tool"]}
    assert "type" not in entry


def test_server_entry_servers_family_has_stdio_type():
    entry = onboarding.server_entry("servers", python="/x/py")
    assert entry["type"] == "stdio"
    assert entry["command"] == "/x/py"
    assert entry["args"] == ["-m", "torque_tunnel.mcp_tool"]


def test_server_entry_defaults_to_current_interpreter():
    entry = onboarding.server_entry("mcpServers")
    assert entry["command"] == sys.executable


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------

def test_detect_none_when_nothing_present(fake_home):
    assert onboarding.detect_clients(system="Linux") == []


def test_detect_claude_code_via_claude_json(fake_home):
    (fake_home / ".claude.json").write_text("{}", encoding="utf-8")
    assert "claude-code" in onboarding.detect_clients(system="Linux")


def test_detect_claude_code_via_claude_dir(fake_home):
    (fake_home / ".claude").mkdir()
    assert "claude-code" in onboarding.detect_clients(system="Linux")


def test_detect_copilot_via_user_dir(fake_home):
    (fake_home / ".config" / "Code" / "User").mkdir(parents=True)
    assert "copilot" in onboarding.detect_clients(system="Linux")


def test_detect_cursor(fake_home):
    (fake_home / ".cursor").mkdir()
    assert "cursor" in onboarding.detect_clients(system="Linux")


# ---------------------------------------------------------------------------
# merge_entry: create
# ---------------------------------------------------------------------------

def test_merge_creates_new_file(fake_home):
    path = fake_home / ".claude.json"
    entry = onboarding.server_entry("mcpServers", python="/x/py")
    res = onboarding.merge_entry(path, "mcpServers", entry)
    assert res.status == "created"
    assert res.backup is None
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["mcpServers"]["torque-tunnel"] == entry


def test_merge_creates_parent_dirs(fake_home):
    path = fake_home / ".cursor" / "mcp.json"
    entry = onboarding.server_entry("mcpServers", python="/x/py")
    res = onboarding.merge_entry(path, "mcpServers", entry)
    assert res.status == "created"
    assert path.exists()


# ---------------------------------------------------------------------------
# merge_entry: preserve existing content
# ---------------------------------------------------------------------------

def test_merge_preserves_other_servers_and_keys(fake_home):
    path = fake_home / ".claude.json"
    original = {
        "someTopLevelState": {"a": 1},
        "mcpServers": {"intersight": {"command": "x", "args": ["y"]}},
    }
    path.write_text(json.dumps(original), encoding="utf-8")
    entry = onboarding.server_entry("mcpServers", python="/x/py")

    res = onboarding.merge_entry(path, "mcpServers", entry)
    assert res.status == "updated"
    assert res.backup is not None and res.backup.exists()

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["someTopLevelState"] == {"a": 1}            # untouched
    assert data["mcpServers"]["intersight"] == {"command": "x", "args": ["y"]}  # untouched
    assert data["mcpServers"]["torque-tunnel"] == entry     # added


def test_merge_creates_family_when_absent(fake_home):
    path = fake_home / ".claude.json"
    path.write_text(json.dumps({"other": True}), encoding="utf-8")
    entry = onboarding.server_entry("mcpServers", python="/x/py")
    onboarding.merge_entry(path, "mcpServers", entry)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["other"] is True
    assert data["mcpServers"]["torque-tunnel"] == entry


# ---------------------------------------------------------------------------
# merge_entry: idempotency
# ---------------------------------------------------------------------------

def test_merge_idempotent_second_run_unchanged(fake_home):
    path = fake_home / ".claude.json"
    entry = onboarding.server_entry("mcpServers", python="/x/py")
    onboarding.merge_entry(path, "mcpServers", entry)
    first = path.read_text(encoding="utf-8")

    res2 = onboarding.merge_entry(path, "mcpServers", entry)
    assert res2.status == "unchanged"
    assert res2.backup is None
    assert path.read_text(encoding="utf-8") == first       # byte-identical, no rewrite


def test_merge_updates_when_entry_changes(fake_home):
    path = fake_home / ".claude.json"
    onboarding.merge_entry(path, "mcpServers", onboarding.server_entry("mcpServers", python="/old/py"))
    res = onboarding.merge_entry(path, "mcpServers", onboarding.server_entry("mcpServers", python="/new/py"))
    assert res.status == "updated"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["mcpServers"]["torque-tunnel"]["command"] == "/new/py"


# ---------------------------------------------------------------------------
# merge_entry: JSONC and abort safety
# ---------------------------------------------------------------------------

def test_merge_handles_jsonc_with_comments(fake_home):
    path = fake_home / "mcp.json"
    jsonc = """{
        // a line comment with // and a "fake string"
        "servers": {
            /* block comment */
            "existing": {"command": "c", "args": []}
        }
    }"""
    path.write_text(jsonc, encoding="utf-8")
    entry = onboarding.server_entry("servers", python="/x/py")

    res = onboarding.merge_entry(path, "servers", entry)
    assert res.status == "updated"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["servers"]["existing"] == {"command": "c", "args": []}
    assert data["servers"]["torque-tunnel"] == entry


def test_strip_jsonc_does_not_touch_comment_markers_inside_strings():
    src = '{"url": "http://x//y", "p": "/* not a comment */"}'
    assert json.loads(onboarding._strip_jsonc(src)) == {
        "url": "http://x//y", "p": "/* not a comment */"
    }


def test_merge_handles_trailing_commas(fake_home):
    path = fake_home / "mcp.json"
    jsonc = """{
        "servers": {
            "existing": {"command": "c", "args": [],},
        },
    }"""
    path.write_text(jsonc, encoding="utf-8")
    entry = onboarding.server_entry("servers", python="/x/py")
    res = onboarding.merge_entry(path, "servers", entry)
    assert res.status == "updated"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["servers"]["existing"] == {"command": "c", "args": []}
    assert data["servers"]["torque-tunnel"] == entry


def test_remove_trailing_commas_preserves_commas_in_strings():
    src = '{"a": "x,}", "b": [1, 2,], "c": {"d": 3,},}'
    assert json.loads(onboarding._remove_trailing_commas(src)) == {
        "a": "x,}", "b": [1, 2], "c": {"d": 3}
    }


def test_merge_aborts_on_unparseable_file_without_overwriting(fake_home):
    path = fake_home / ".claude.json"
    broken = '{ "mcpServers": { this is not valid json ,,, }'
    path.write_text(broken, encoding="utf-8")
    entry = onboarding.server_entry("mcpServers", python="/x/py")

    res = onboarding.merge_entry(path, "mcpServers", entry)
    assert res.status == "aborted"
    assert not res.ok
    assert path.read_text(encoding="utf-8") == broken      # left untouched
    assert not (fake_home / ".claude.json.bak").exists()   # no backup written


def test_merge_aborts_when_family_is_not_object(fake_home):
    path = fake_home / ".claude.json"
    path.write_text(json.dumps({"mcpServers": "oops"}), encoding="utf-8")
    res = onboarding.merge_entry(path, "mcpServers", onboarding.server_entry("mcpServers"))
    assert res.status == "aborted"


def test_merge_handles_empty_file_as_created(fake_home):
    path = fake_home / ".claude.json"
    path.write_text("   \n", encoding="utf-8")
    res = onboarding.merge_entry(path, "mcpServers", onboarding.server_entry("mcpServers"))
    assert res.status in ("created", "updated")            # empty -> writes fresh content
    assert json.loads(path.read_text(encoding="utf-8"))["mcpServers"]["torque-tunnel"]


# ---------------------------------------------------------------------------
# merge_entry: dry-run
# ---------------------------------------------------------------------------

def test_dry_run_does_not_write(fake_home):
    path = fake_home / ".claude.json"
    res = onboarding.merge_entry(path, "mcpServers", onboarding.server_entry("mcpServers"), dry_run=True)
    assert res.status == "dry-run"
    assert not path.exists()


# ---------------------------------------------------------------------------
# orchestrator: configure()
# ---------------------------------------------------------------------------

def test_configure_explicit_clients(fake_home):
    results = onboarding.configure(["claude-code", "cursor"], python="/x/py", system="Linux")
    assert {r.client for r in results} == {"claude-code", "cursor"}
    assert all(r.status == "created" for r in results)
    assert (fake_home / ".claude.json").exists()
    assert (fake_home / ".cursor" / "mcp.json").exists()


def test_configure_auto_detect_only_present(fake_home):
    (fake_home / ".claude.json").write_text("{}", encoding="utf-8")
    results = onboarding.configure(system="Linux", python="/x/py")
    assert [r.client for r in results] == ["claude-code"]


def test_configure_all_clients(fake_home):
    results = onboarding.configure(all_clients=True, python="/x/py", system="Linux")
    assert {r.client for r in results} == set(onboarding.CLIENTS)


def test_configure_dry_run_writes_nothing(fake_home):
    results = onboarding.configure(["claude-code"], python="/x/py", system="Linux", dry_run=True)
    assert results[0].status == "dry-run"
    assert not (fake_home / ".claude.json").exists()


def test_configure_correct_family_per_client(fake_home):
    onboarding.configure(["claude-code", "copilot"], python="/x/py", system="Linux")
    claude = json.loads((fake_home / ".claude.json").read_text(encoding="utf-8"))
    copilot = json.loads((fake_home / ".config" / "Code" / "User" / "mcp.json").read_text(encoding="utf-8"))
    assert "type" not in claude["mcpServers"]["torque-tunnel"]
    assert copilot["servers"]["torque-tunnel"]["type"] == "stdio"


# ---------------------------------------------------------------------------
# CLI subcommand: parsing + handler dispatch (exercises mcp_tool.build_parser
# and _handle_configure_cli end-to-end)
# ---------------------------------------------------------------------------

from torque_tunnel import mcp_tool


def test_configure_subcommand_parses_flags():
    args = mcp_tool.build_parser().parse_args(
        ["configure", "--client", "claude-code", "--client", "cursor", "--dry-run"]
    )
    assert args.command == "configure"
    assert args.client == ["claude-code", "cursor"]
    assert args.dry_run is True


def test_configure_subcommand_rejects_unknown_client():
    with pytest.raises(SystemExit):
        mcp_tool.build_parser().parse_args(["configure", "--client", "nope"])


def test_handle_configure_cli_writes_selected_client(fake_home, capsys):
    args = mcp_tool.build_parser().parse_args(
        ["configure", "--client", "claude-code", "--python", "/x/py"]
    )
    mcp_tool._handle_configure_cli(args)
    out = capsys.readouterr().out
    assert "claude-code" in out
    data = json.loads((fake_home / ".claude.json").read_text(encoding="utf-8"))
    assert data["mcpServers"]["torque-tunnel"]["command"] == "/x/py"


def test_handle_configure_cli_list_exits_cleanly(fake_home, capsys):
    args = mcp_tool.build_parser().parse_args(["configure", "--list"])
    mcp_tool._handle_configure_cli(args)        # must not raise / exit
    out = capsys.readouterr().out
    assert "claude-code" in out and "copilot" in out


def test_handle_configure_cli_no_detection_exits_1(fake_home):
    # empty fake home → nothing detected, no --client/--all → exit 1
    args = mcp_tool.build_parser().parse_args(["configure"])
    with pytest.raises(SystemExit) as exc:
        mcp_tool._handle_configure_cli(args)
    assert exc.value.code == 1
