"""Corpus tests: run the invariant oracle over representative real-world client
configs (sanitized — no secrets) and, opt-in, over the user's ACTUAL live config
files if present on this machine.

These complement the property tests with realistic shapes: comment-heavy VS Code
mcp.json, strict ~/.claude.json with lots of state, nested look-alike keys, etc.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import onboarding
import _onboarding_invariants as inv


# Each entry: (id, family, document_text). Mirrors real client formats, sanitized.
CORPUS = [
    ("claude_code_strict", "mcpServers", """{
  "numStartups": 207,
  "installMethod": "vscode",
  "mcpServers": {
    "intersight": {
      "command": "node",
      "args": ["C:\\\\ZeroTouch\\\\Intersight_MCP\\\\build\\\\index.js"],
      "env": { "INTERSIGHT_API_KEY_ID": "REDACTED", "INTERSIGHT_TOOL_MODE": "all" }
    },
    "MasterSeeker": { "command": "C:\\\\MasterSeeker\\\\MasterSeekerMCP.exe", "args": [] }
  },
  "tipsHistory": { "a": 1, "b": 2 }
}
"""),

    ("vscode_copilot_jsonc", "servers", """{
  "servers": {
    "torque-tunnel-placeholder": null,
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp/",
      "headers": { "X-MCP-Toolsets": "default,actions" }
    },
    /* Alternative configs kept for reference:
       "--torque-url", "https://REDACTED",
       "--torque-token", "REDACTED",
       "--torque-space", "shell-cmd" */
    "intersight": {
      "command": "node",
      "args": ["C:\\\\x\\\\index.js"]  // inline note with // and "quotes"
    },
  }
}
"""),

    ("cursor_minimal", "mcpServers", """{
  "mcpServers": {
    "some-server": { "command": "uvx", "args": ["some-mcp"] }
  }
}
"""),

    ("empty_object", "mcpServers", "{}\n"),

    ("empty_with_comment", "servers", "{\n  // nothing yet\n}\n"),

    ("family_absent", "mcpServers", """{
  "editor.fontSize": 13,
  "someOtherTool": { "command": "x" }
}
"""),

    ("family_empty_object", "servers", """{
  "servers": {
  }
}
"""),

    ("family_empty_with_comment", "servers", """{
  "servers": {
    /* add servers here */
  }
}
"""),

    ("already_present", "servers", """{
  // user notes
  "servers": {
    "torque-tunnel": {
      "type": "stdio",
      "command": "C:\\\\old\\\\python.exe",
      "args": ["-m", "torque_tunnel.mcp_tool"]
    },
    "other": { "command": "x" }
  }
}
"""),

    # Adversarial: a NESTED object also has a "servers" key — the depth-1 locator
    # must target the ROOT servers object, not the nested one.
    ("nested_lookalike", "servers", """{
  "servers": {
    "wrapper": { "servers": { "decoy": { "command": "no" } } },
    "real": { "command": "yes" }
  }
}
"""),

    # A value string contains the family name and JSON syntax — must not confuse the scanner.
    ("family_name_in_string", "mcpServers", """{
  "note": "set mcpServers: { } in your config // not a comment",
  "mcpServers": { "x": { "command": "c" } }
}
"""),
]


@pytest.mark.parametrize("cid,family,text", CORPUS, ids=[c[0] for c in CORPUS])
@pytest.mark.parametrize("eol", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_corpus(tmp_path, cid, family, text, eol):
    doc = text.replace("\n", eol) if eol == "\r\n" else text
    entry = onboarding.server_entry(family, python="/x/py")
    bdata, ok = onboarding._load_lenient(doc)
    assert ok, f"corpus item {cid} should parse"
    tt_present = isinstance(bdata.get(family), dict) and "torque-tunnel" in bdata[family]

    path = tmp_path / "cfg.json"
    res, after = inv.run_merge(path, doc, family=family, entry=entry)

    if res.status == "aborted":
        inv.assert_aborted_untouched(doc, after, res)
        pytest.fail(f"{cid}: unexpected abort: {res.reason}")
    if tt_present:
        inv.assert_noop(doc, after, res)
    else:
        inv.assert_added(doc, after, res, family=family, entry=entry)


def test_nested_lookalike_targets_root_not_nested(tmp_path):
    """Regression: torque-tunnel lands in the ROOT servers object."""
    item = dict((c[0], c) for c in CORPUS)["nested_lookalike"]
    _, family, text = item
    path = tmp_path / "cfg.json"
    res, after = inv.run_merge(path, text, family="servers", entry=onboarding.server_entry("servers", python="/x/py"))
    assert res.status == "added"
    data, _ = onboarding._load_lenient(after)
    assert "torque-tunnel" in data["servers"]                       # root
    assert "torque-tunnel" not in data["servers"]["wrapper"]["servers"]   # nested untouched


# --------------------------------------------------------------------------
# Opt-in: run the invariants against the user's ACTUAL config files (copied to a
# temp dir — the real files are never modified). Skips if a file isn't present.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("client", list(onboarding.CLIENTS))
def test_live_user_configs(tmp_path, client):
    real = onboarding.config_path(client)
    if not real.exists():
        pytest.skip(f"{client}: {real} not present on this machine")
    raw = real.read_bytes().decode("utf-8")
    bdata, ok = onboarding._load_lenient(raw)
    if not ok:
        pytest.skip(f"{client}: live file is not parseable JSONC (out of scope)")
    family = onboarding.CLIENTS[client].family
    entry = onboarding.server_entry(family, python="/x/py")
    tt_present = isinstance(bdata.get(family), dict) and "torque-tunnel" in bdata[family]

    work = tmp_path / real.name
    res, after = inv.run_merge(work, raw, family=family, entry=entry)

    if res.status == "aborted":
        inv.assert_aborted_untouched(raw, after, res)
    elif tt_present:
        inv.assert_noop(raw, after, res)
    else:
        inv.assert_added(raw, after, res, family=family, entry=entry)
