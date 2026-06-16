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
import time
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
    # Catch RecursionError too: CPython's json scanner is recursive, so a
    # pathologically deep document raises RecursionError (not JSONDecodeError).
    # Treat anything unparseable — for any reason — as a safe "abort" signal.
    try:
        return json.loads(text), True
    except (ValueError, RecursionError):
        pass
    try:
        return json.loads(_remove_trailing_commas(_strip_jsonc(text))), True
    except (ValueError, RecursionError):
        return None, False


def _parses_strict(text: str) -> bool:
    """True if `text` is valid *strict* JSON (no comments, no trailing commas)."""
    try:
        json.loads(text)
        return True
    except (ValueError, RecursionError):
        return False


def _skip_ws_comments(text: str, i: int) -> int:
    """Advance past whitespace and // and /* */ comments; return next significant index."""
    n = len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
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
            i += 2
            continue
        break
    return i


def _find_root_object_brace(text: str) -> Optional[int]:
    """Index of the root object's opening '{' (skipping leading ws/comments)."""
    i = _skip_ws_comments(text, 0)
    if i < len(text) and text[i] == "{":
        return i
    return None


def _find_member_object_brace(text: str, key: str) -> Optional[int]:
    """Index of the '{' opening the object value of a root-level `key`.

    String/comment-aware scan that only matches `key` when it is a property name
    directly inside the root object (depth 1) whose value is an object. Returns
    None if not found. Used to locate where to insert a new server entry without
    reparsing/reformatting the file.
    """
    i, n = 0, len(text)
    stack: list[str] = []
    in_str = esc = False
    while i < n:
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
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
            i += 2
            continue
        if c == '"':
            start = i
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
            s = text[start + 1:i]
            i += 1  # past closing quote
            # A property name directly inside the root object, value is an object?
            if len(stack) == 1 and stack[-1] == "{" and s == key:
                j = _skip_ws_comments(text, i)
                if j < n and text[j] == ":":
                    j = _skip_ws_comments(text, j + 1)
                    if j < n and text[j] == "{":
                        return j
            continue
        if c in "{[":
            stack.append(c)
        elif c in "}]":
            if stack:
                stack.pop()
        i += 1
    return None


def _insert_first_member(text: str, brace_idx: int, member: str, newline: str = "\n") -> str:
    """Insert `member` (e.g. '"name": {...}') as the first member of the object
    whose opening brace is at `brace_idx`, preserving every other byte verbatim.

    A separating comma is added only when a real member already follows (the next
    significant token is a string key); when the object has no members — even if
    it contains only comments — no comma is added (which would be a trailing
    comma) and the existing bytes (including those comments) are kept.
    """
    j = _skip_ws_comments(text, brace_idx + 1)
    has_member = j < len(text) and text[j] == '"'
    sep = "," if has_member else ""
    # The new member is indented a fixed 4 spaces (not inferred from the file's
    # own indent unit). This is intentional and cosmetic only — the result is
    # still valid and a pure single insertion; matching sibling indentation is out
    # of scope for an onboarding tool.
    return text[:brace_idx + 1] + newline + "    " + member + sep + text[brace_idx + 1:]


def _single_insertion_span(before: str, after: str) -> Optional[str]:
    """If `after` is `before` with exactly ONE contiguous block inserted, return
    that inserted block; otherwise None.

    This is computed by diffing the two strings (longest common prefix + suffix),
    so it is independent of *how* the insertion was produced — a future refactor
    of the splice logic can't slip a non-pure edit past it.
    """
    if len(after) <= len(before):
        return None
    p = 0
    while p < len(before) and before[p] == after[p]:
        p += 1
    s = 0
    while s < (len(before) - p) and before[-1 - s] == after[-1 - s]:
        s += 1
    if p + s == len(before):
        return after[p:len(after) - s]
    return None


def _read_text_keep_newlines(path: Path) -> str:
    """Read a file without newline translation (preserves CRLF vs LF)."""
    with open(path, "r", encoding="utf-8", newline="") as f:
        return f.read()


def _write_text_exact(path: Path, text: str) -> None:
    """Atomically write text with no newline translation.

    Writes to a sibling temp file then os.replace()s it into place, so a failure
    mid-write can never leave a half-written (corrupt) config: either the old
    file or the complete new file is present, never a partial one.
    """
    tmp = path.with_name(path.name + ".tt-tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    # os.replace is atomic, but on Windows an antivirus scanner or search indexer
    # can briefly hold the destination open, making the rename fail with a
    # transient ERROR_ACCESS_DENIED (PermissionError). Retry a few times; the lock
    # almost always clears within tens of ms. The original file is untouched until
    # the replace succeeds, so a permanent failure is a safe (non-corrupting) abort.
    last_err = None
    for attempt in range(10):
        try:
            os.replace(tmp, path)
            return
        except PermissionError as e:
            last_err = e
            time.sleep(0.02 * (attempt + 1))
    try:
        os.remove(tmp)            # don't leave a stray temp file behind
    except OSError:
        pass
    raise last_err


@dataclass
class MergeResult:
    """Outcome of merging the server entry into one client's config file."""

    client: str
    path: Path
    status: str               # created | added | unchanged | aborted | dry-run
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
    """Register `<family>.<server_name>` in the client's config file.

    This is an ONBOARDING action and is deliberately conservative — it is the
    user's file:
      - If `server_name` is ALREADY present, the file is left completely
        untouched (status "unchanged"). We do not re-format, re-point, or
        "upgrade" an existing entry — that is the user's responsibility beyond
        first onboarding.
      - When adding, we only INSERT; every comment, key, and byte of the
        existing file is preserved (surgical text insertion, not a reparse +
        reformat).
      - A brand-new (or blank) file is written as clean JSON.
      - If the existing file can't be parsed, or we can't safely locate the
        insertion point, we ABORT without writing.

    Strictness note: some families are consumed by strict-JSON readers (e.g.
    mcpServers in ~/.claude.json, which is machine-managed strict JSON). The
    strict-stays-strict guard guarantees we never turn a strict file into
    non-strict; we do not convert an already-JSONC file to strict (JSONC in,
    JSONC out). A UTF-8 BOM and LF/CRLF line endings are preserved verbatim.
    """
    existed = path.exists()

    # Fresh file → write clean JSON (nothing to preserve).
    if not existed:
        if dry_run:
            return MergeResult("", path, "dry-run", reason="create", entry=entry)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_text_exact(path, json.dumps({family: {server_name: entry}}, indent=2) + "\n")
        except OSError as e:
            return MergeResult("", path, "aborted", reason=f"cannot write file: {e}")
        return MergeResult("", path, "created", entry=entry)

    try:
        raw = _read_text_keep_newlines(path)
    except OSError as e:
        return MergeResult("", path, "aborted", reason=f"cannot read file: {e}")

    # Preserve a UTF-8 BOM (common on Windows-authored files): strip it for
    # parsing and insertion, re-attach it verbatim on every write.
    bom = ""
    text = raw
    if text.startswith("\ufeff"):
        bom = "\ufeff"
        text = text[1:]

    # Blank file → write clean JSON (preserving any BOM).
    if not text.strip():
        if dry_run:
            return MergeResult("", path, "dry-run", reason="create", entry=entry)
        try:
            _write_text_exact(path, bom + json.dumps({family: {server_name: entry}}, indent=2) + "\n")
        except OSError as e:
            return MergeResult("", path, "aborted", reason=f"cannot write file: {e}")
        return MergeResult("", path, "created", entry=entry)

    data, ok = _load_lenient(text)
    if not ok:
        return MergeResult("", path, "aborted",
                           reason="existing file is not valid JSON/JSONC; not overwriting")
    if not isinstance(data, dict):
        return MergeResult("", path, "aborted", reason="top-level JSON is not an object")

    # If the family key exists but isn't an object (null, string, number, array,
    # bool), abort explicitly — don't fall through to the "family absent" path and
    # synthesize a duplicate key. (Symmetric handling for all non-object values.)
    if family in data and not isinstance(data[family], dict):
        return MergeResult("", path, "aborted", reason=f"'{family}' exists but is not an object")
    servers = data.get(family)

    # Already configured → do not touch the file at all.
    if isinstance(servers, dict) and server_name in servers:
        return MergeResult("", path, "unchanged", entry=servers.get(server_name) or {})

    if dry_run:
        return MergeResult("", path, "dry-run", reason="add", entry=entry)

    # Surgically insert, preserving the whole file verbatim (BOM re-attached later).
    member = f'"{server_name}": {json.dumps(entry)}'
    if isinstance(servers, dict):
        brace = _find_member_object_brace(text, family)          # insert into existing family object
    else:
        brace = _find_root_object_brace(text)                    # add family object to the root
        if brace is not None:
            member = f'"{family}": {{{member}}}'

    if brace is None:
        return MergeResult("", path, "aborted",
                           reason="could not locate insertion point; add the entry manually")

    newline = "\r\n" if "\r\n" in text else "\n"
    new_text = _insert_first_member(text, brace, member, newline)

    # ---- Gated validation: a bug here ABORTS, it never corrupts the file ----

    # (A1) Byte-preservation, computed INDEPENDENTLY of the splice: `new_text`
    # must be `text` with exactly one contiguous block inserted — nothing else
    # altered or removed. (A diff-based check, so a future refactor of the
    # insertion can't sneak a non-pure edit through.)
    if _single_insertion_span(text, new_text) is None:
        return MergeResult("", path, "aborted", reason="byte-preservation check failed; not writing")

    # (A2-keys) Still parses, contains our entry, and preserves prior keys/servers.
    new_data, new_ok = _load_lenient(new_text)
    if not new_ok or not isinstance(new_data, dict):
        return MergeResult("", path, "aborted", reason="insertion produced invalid JSON; not writing")
    new_family = new_data.get(family)
    if not isinstance(new_family, dict) or server_name not in new_family:
        return MergeResult("", path, "aborted", reason="insertion did not register the server; not writing")
    if not set(data.keys()).issubset(new_data.keys()):
        return MergeResult("", path, "aborted", reason="insertion would drop existing keys; not writing")
    if isinstance(servers, dict) and not set(servers).issubset(new_family):
        return MergeResult("", path, "aborted", reason="insertion would drop existing servers; not writing")

    # (A2-strict) Strict-stays-strict: if the original was strict JSON, the result
    # must be too. Catches accidental introduction of JSON5-only syntax (e.g. a
    # trailing comma) that the lenient parse above would silently tolerate but a
    # strict consumer (like ~/.claude.json) would reject.
    if _parses_strict(text) and not _parses_strict(new_text):
        return MergeResult("", path, "aborted", reason="insertion would break strict-JSON validity; not writing")

    final_text = bom + new_text          # re-attach the original BOM (if any)

    # Back up the EXACT original bytes (incl. BOM) before writing.
    backup_path = None
    if make_backup:
        backup_path = path.with_name(path.name + ".bak")
        try:
            _write_text_exact(backup_path, raw)
        except OSError as e:
            return MergeResult("", path, "aborted", reason=f"cannot write backup: {e}")

    try:
        _write_text_exact(path, final_text)
    except OSError as e:
        return MergeResult("", path, "aborted", reason=f"cannot write file: {e}")

    # (A3) Post-write verify-or-restore: re-read what actually landed on disk; if
    # it doesn't parse or lost our entry, roll back to the original bytes. The
    # restore is best-effort and must NEVER raise (it runs when things already
    # went wrong).
    try:
        written = _read_text_keep_newlines(path)
        wtext = written[1:] if written.startswith("\ufeff") else written
        wdata, wok = _load_lenient(wtext)
        on_disk_ok = (wok and isinstance(wdata, dict)
                      and isinstance(wdata.get(family), dict)
                      and server_name in wdata[family])
    except OSError:
        on_disk_ok = False
    if not on_disk_ok:
        try:
            _write_text_exact(path, raw)   # restore exact original bytes
        except OSError:
            pass                           # best-effort; never raise from the restore
        return MergeResult("", path, "aborted",
                           reason="post-write verification failed; original restored")

    return MergeResult("", path, "added", backup=backup_path, entry=entry)


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
