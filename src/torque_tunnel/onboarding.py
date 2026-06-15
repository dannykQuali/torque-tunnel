"""Cross-platform onboarding helpers: register the torque-tunnel MCP server
with AI clients (Claude Code, Copilot, Cursor, Windsurf, Claude Desktop).

The heavy lifting lives here (rather than in shell scripts) so a single,
unit-tested Python implementation works on Windows, Linux, and macOS. Thin
bootstrap scripts (onboard.ps1 / onboard.sh) only build the venv and then call
the `configure` CLI subcommand, which delegates to the functions below.

The CLI exposes these as the `register-mcp-client` subcommand.

Two config schema families cover every supported client:
  - "mcpServers": Claude Code, Cursor, Windsurf, Claude Desktop
  - "servers":    Copilot / VS Code native MCP
"""

import json
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# The MCP server name written into each client's config.
SERVER_NAME = "torque-tunnel"

# How the server is launched. We invoke the venv interpreter with the module
# form (`-m torque_tunnel.mcp_tool`) rather than the generated .exe — the .exe
# is just a console-script shim and the module form is more portable and works
# from any CWD because the package is installed (editable or not) on sys.path.
LAUNCH_ARGS = ["-m", "torque_tunnel.mcp_tool"]


@dataclass(frozen=True)
class ClientSpec:
    """Describes one supported AI client and where/how it stores MCP config."""

    name: str          # stable id used on the CLI (--client <name>)
    display: str       # human-readable name
    family: str        # "mcpServers" or "servers"
    note: str = ""     # short note shown to the user (e.g. "untested")
    tested: bool = True


# Registry of supported clients. Order matters for display.
CLIENTS: dict[str, ClientSpec] = {
    "claude-code": ClientSpec(
        "claude-code", "Claude Code", "mcpServers",
        note="VS Code extension / CLI - reads ~/.claude.json",
    ),
    "copilot": ClientSpec(
        "copilot", "GitHub Copilot (VS Code)", "servers",
        note="VS Code native MCP - User/mcp.json",
    ),
    "cursor": ClientSpec(
        "cursor", "Cursor", "mcpServers",
        note="~/.cursor/mcp.json (untested)", tested=False,
    ),
    "windsurf": ClientSpec(
        "windsurf", "Windsurf", "mcpServers",
        note="~/.codeium/windsurf/mcp_config.json (untested)", tested=False,
    ),
    "claude-desktop": ClientSpec(
        "claude-desktop", "Claude Desktop", "mcpServers",
        note="claude_desktop_config.json (untested)", tested=False,
    ),
}


def _appdata() -> Path:
    """Windows %APPDATA% (Roaming), with a sensible fallback."""
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata)
    return Path.home() / "AppData" / "Roaming"


def config_path(client: str, system: Optional[str] = None) -> Path:
    """Return the MCP config file path for a client on the current OS.

    `system` overrides platform.system() (Windows/Darwin/Linux) — mainly for tests.
    Raises KeyError for an unknown client.
    """
    if client not in CLIENTS:
        raise KeyError(f"Unknown client: {client}")
    system = system or platform.system()
    home = Path.home()

    if client == "claude-code":
        return home / ".claude.json"
    if client == "cursor":
        return home / ".cursor" / "mcp.json"
    if client == "windsurf":
        return home / ".codeium" / "windsurf" / "mcp_config.json"
    if client == "claude-desktop":
        if system == "Windows":
            return _appdata() / "Claude" / "claude_desktop_config.json"
        if system == "Darwin":
            return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        return home / ".config" / "Claude" / "claude_desktop_config.json"
    if client == "copilot":
        if system == "Windows":
            return _appdata() / "Code" / "User" / "mcp.json"
        if system == "Darwin":
            return home / "Library" / "Application Support" / "Code" / "User" / "mcp.json"
        return home / ".config" / "Code" / "User" / "mcp.json"
    raise KeyError(f"Unknown client: {client}")  # pragma: no cover


def is_client_present(client: str, system: Optional[str] = None) -> bool:
    """Best-effort detection: is this client installed / has it ever run?

    We look for the config file or a well-known marker directory. Detection is a
    convenience for auto-configuration; users can always force a client with
    --client even if detection says no.
    """
    home = Path.home()
    if client == "claude-code":
        return (home / ".claude.json").exists() or (home / ".claude").is_dir()
    if client == "cursor":
        return (home / ".cursor").is_dir()
    if client == "windsurf":
        return (home / ".codeium" / "windsurf").is_dir() or (home / ".codeium").is_dir()
    # claude-desktop / copilot: the parent (app user dir) existing means the app is installed
    return config_path(client, system).parent.is_dir()


def detect_clients(system: Optional[str] = None) -> list[str]:
    """Return the list of client ids detected as present, in registry order."""
    return [name for name in CLIENTS if is_client_present(name, system)]


def server_entry(family: str, python: Optional[str] = None) -> dict:
    """Build the MCP server entry dict for the given schema family.

    `python` defaults to the current interpreter (sys.executable), which — when
    this runs through the venv created by the bootstrap — is exactly the venv
    interpreter we want clients to launch.
    """
    command = python or sys.executable
    entry: dict = {"command": command, "args": list(LAUNCH_ARGS)}
    if family == "servers":
        # VS Code native MCP expects a transport type.
        return {"type": "stdio", **entry}
    return entry


def _strip_jsonc(text: str) -> str:
    """Remove // line comments and /* */ block comments from JSONC text.

    String-aware (won't strip // or /* that appear inside a JSON string) so it
    can salvage a VS Code mcp.json that contains comments.
    """
    out = []
    i, n = 0, len(text)
    in_string = False
    escape = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                i += 1
            i += 2  # skip closing */
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _remove_trailing_commas(text: str) -> str:
    """Remove trailing commas before } or ] (legal in JSONC, illegal in JSON).

    String-aware so a comma inside a string value is never removed. Run after
    comment stripping. VS Code configs frequently contain trailing commas, so
    handling them avoids falsely refusing to merge a perfectly valid file.
    """
    out = []
    i, n = 0, len(text)
    in_string = False
    escape = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
            continue
        if c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # drop the trailing comma
                continue
        out.append(c)
        i += 1
    return "".join(out)


def _load_lenient(text: str) -> tuple[Optional[dict], bool]:
    """Parse JSON, retrying with JSONC handling (comments + trailing commas).

    Returns (data, ok). On unparseable input returns (None, False) so the caller
    can refuse to overwrite rather than risk corrupting the user's file. An
    empty / whitespace-only file parses as ({}, True).
    """
    if not text.strip():
        return {}, True
    try:
        return json.loads(text), True
    except json.JSONDecodeError:
        pass
    try:
        return json.loads(_remove_trailing_commas(_strip_jsonc(text))), True
    except json.JSONDecodeError:
        return None, False


@dataclass
class MergeResult:
    """Outcome of merging the server entry into one client's config file."""

    client: str
    path: Path
    status: str               # created | updated | unchanged | aborted | dry-run
    backup: Optional[Path] = None
    reason: str = ""
    entry: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status != "aborted"


def merge_entry(
    path: Path,
    family: str,
    entry: dict,
    *,
    server_name: str = SERVER_NAME,
    dry_run: bool = False,
    make_backup: bool = True,
) -> MergeResult:
    """Insert/replace `entry` under `<family>.<server_name>` in the JSON file.

    Preserves all other content. Backs up an existing file before writing.
    Refuses to write (status="aborted") if an existing file can't be parsed, so
    a user's hand-maintained config is never clobbered.
    """
    existed = path.exists()
    if existed:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            return MergeResult("", path, "aborted", reason=f"cannot read file: {e}")
        data, ok = _load_lenient(text)
        if not ok:
            return MergeResult(
                "", path, "aborted",
                reason="existing file is not valid JSON/JSONC; not overwriting",
            )
    else:
        data = {}

    if not isinstance(data, dict):
        return MergeResult("", path, "aborted", reason="top-level JSON is not an object")

    servers = data.get(family)
    if servers is None:
        servers = {}
        data[family] = servers
    elif not isinstance(servers, dict):
        return MergeResult(
            "", path, "aborted",
            reason=f"'{family}' exists but is not an object",
        )

    previous = servers.get(server_name)
    if previous == entry:
        return MergeResult("", path, "unchanged", entry=entry)

    status = "updated" if existed else "created"

    if dry_run:
        return MergeResult("", path, "dry-run", reason=status, entry=entry)

    backup_path = None
    if existed and make_backup:
        backup_path = path.with_name(path.name + ".bak")
        backup_path.write_text(text, encoding="utf-8")

    servers[server_name] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    return MergeResult("", path, status, backup=backup_path, entry=entry)


def register_client(
    client: str,
    *,
    python: Optional[str] = None,
    dry_run: bool = False,
    system: Optional[str] = None,
) -> MergeResult:
    """Register the MCP server with a single client. Raises KeyError if unknown."""
    spec = CLIENTS[client]
    path = config_path(client, system)
    entry = server_entry(spec.family, python)
    result = merge_entry(path, spec.family, entry, dry_run=dry_run)
    result.client = client
    return result


def register_clients(
    clients: Optional[list[str]] = None,
    *,
    all_clients: bool = False,
    python: Optional[str] = None,
    dry_run: bool = False,
    system: Optional[str] = None,
) -> list[MergeResult]:
    """Register the MCP server with one or more clients.

    Target selection:
      - explicit `clients` list  → exactly those
      - `all_clients=True`       → every client in the registry
      - otherwise                → auto-detected present clients
    """
    if clients:
        targets = clients
    elif all_clients:
        targets = list(CLIENTS)
    else:
        targets = detect_clients(system)

    results = []
    for name in targets:
        results.append(register_client(name, python=python, dry_run=dry_run, system=system))
    return results
