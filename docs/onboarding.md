# Onboarding

This guide gets a new user from a fresh clone to a working torque-tunnel MCP
server registered with their AI client(s).

## TL;DR — one command

From the repo root:

**Windows (PowerShell):**
```powershell
.\scripts\onboard.ps1
```

**Linux / macOS:**
```bash
./scripts/onboard.sh
```

This will:
1. Create a `.venv` and install torque-tunnel into it.
2. Auto-detect installed AI clients (Claude Code, Copilot, Cursor, Windsurf, Claude Desktop).
3. Register the MCP server in each detected client's config (with a backup of any existing file).
4. Launch the interactive Torque **setup** in your browser to populate connection settings.

Then **restart your AI client** so it picks up the new MCP server.

## What each step does

### 1. Build

The bootstrap scripts only locate Python (3.10+) and build the virtual
environment, then hand off to the packaged `register-mcp-client` subcommand — so all the
real logic is one cross-platform, tested Python implementation rather than
duplicated shell code.

You can run the build/install by itself with plain `pip` if you prefer:
```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .     # Windows
.venv/bin/python    -m pip install -e .      # Linux/macOS
```

### 2. Configure clients

The `register-mcp-client` subcommand writes the MCP server entry into each client's
config file. It is **safe and idempotent**:
- It preserves all other content (other MCP servers, unrelated settings).
- It backs up any existing file to `<file>.bak` before writing.
- It refuses to overwrite a config it cannot parse (you'll get a `[SKIP]` and a
  pointer to the file).
- Re-running reports `already configured` and changes nothing.

```bash
# See what's supported and what's detected on this machine
torque-tunnel register-mcp-client --list

# Auto-detect and register (no setup)
torque-tunnel register-mcp-client

# Configure specific clients
torque-tunnel register-mcp-client --client claude-code --client copilot

# Configure everything, but only preview the changes
torque-tunnel register-mcp-client --all --dry-run

# Configure and immediately run the browser setup
torque-tunnel register-mcp-client --run-setup
```

> When invoked through the venv interpreter (as the bootstrap does), the server
> entry uses that interpreter and `-m torque_tunnel.mcp_tool`, so the client
> launches the exact environment you just built. Override with `--python` if
> needed.

### 3. Setup (Torque connection)

`setup` opens a browser window to authenticate with Torque (email/password or a
pasted token), pick the account/space/agent, and saves everything to
`~/.torque-tunnel/config.yaml`. Run it standalone any time:

```bash
torque-tunnel setup
```

See [configuration.md](configuration.md) for the config file format, profiles,
and resolution order.

## Supported clients and config locations

| Client | Schema | Config file |
|--------|--------|-------------|
| Claude Code | `mcpServers` | `~/.claude.json` |
| GitHub Copilot (VS Code) | `servers` | `%APPDATA%\Code\User\mcp.json` · `~/.config/Code/User/mcp.json` · `~/Library/Application Support/Code/User/mcp.json` |
| Cursor | `mcpServers` | `~/.cursor/mcp.json` |
| Windsurf | `mcpServers` | `~/.codeium/windsurf/mcp_config.json` |
| Claude Desktop | `mcpServers` | `%APPDATA%\Claude\claude_desktop_config.json` (+ macOS/Linux equivalents) |

> Only Claude Code and Copilot are actively tested here; the others use the same
> two schema families and are best-effort. `register-mcp-client --list` always prints the
> exact path it will touch on your machine.

## Troubleshooting

- **`[SKIP] ... existing file is not valid JSON/JSONC`** — the target config has
  a syntax error. Fix it (or move it aside) and re-run; we won't overwrite a
  file we can't parse.
- **Client doesn't show the tools** — restart the client; MCP servers are loaded
  at startup.
- **`No AI clients auto-detected`** — pass `--client <name>` or `--all`, or run
  `register-mcp-client --list` to see the supported set.
- **Headless server** — `--run-setup` opens a browser. On a server, register the
  client(s) without it and run `setup` from a machine with a browser, or paste a token.
