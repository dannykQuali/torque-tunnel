# torque-tunnel

An MCP server that lets an AI assistant execute commands on remote servers by
tunneling through Torque agent infrastructure — useful when the targets are only
reachable from inside a network the AI client cannot reach directly.

Works with **Claude Code**, **GitHub Copilot**, **Cursor**, **Windsurf**, and
**Claude Desktop** (any MCP-capable client).

## Overview

```
AI client → MCP server (local) → Torque REST API → Shell Grain Blueprint → SSH / container → Target Host
```

The MCP server runs locally, calls Torque's REST API to launch a shell blueprint
on a chosen agent, and that agent runs the command — either over SSH to a target
host or inside a Torque-managed container.

## Quick start

From the repo root:

```powershell
# Windows (PowerShell)
.\scripts\onboard.ps1
```
```bash
# Linux / macOS
./scripts/onboard.sh
```

This builds the virtual environment, registers the MCP server with your detected
AI client(s), and launches the interactive Torque setup. Then **restart your AI
client**. See [docs/onboarding.md](docs/onboarding.md) for details and options.

## Prerequisites

1. **Python 3.10+** installed locally
2. A **Torque account** with access to the target space
3. A **Torque Docker agent** running on a host that can reach the target server
4. **SSH access** to the target server (private key or password) — for the SSH tools

## Manual installation

If you'd rather not use the onboarding script:

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .     # Windows
.venv/bin/python    -m pip install -e .      # Linux/macOS
```

Then register the server with your client(s) and configure the connection:

```bash
torque-tunnel register-mcp-client --run-setup
```

- `register-mcp-client` writes the MCP server entry into each client's config (safe,
  idempotent, backs up existing files). See [docs/onboarding.md](docs/onboarding.md).
- `setup` (or `register-mcp-client --run-setup`) opens a browser to authenticate with
  Torque and save settings to `~/.torque-tunnel/config.yaml`. See
  [docs/configuration.md](docs/configuration.md).

For a hand-edited MCP config, see the annotated [`mcp.json`](mcp.json) template.

## Configuration

Connection settings live in `~/.torque-tunnel/config.yaml` (created by `setup`),
not in each client's MCP config — so the MCP entry stays minimal and the same
config serves the CLI and every client. The file supports named **profiles** for
multiple environments/agents/targets.

Full reference: [docs/configuration.md](docs/configuration.md).

## Available tools

### Execution — synchronous (blocking)

| Tool | Description |
|------|-------------|
| `run_on_tunneled_ssh` | Execute a command on a remote server via SSH through the Torque agent |
| `run_on_tunneled_persistent_container` | Execute on a persistent Torque agent container (state preserved across calls) |
| `run_on_tunneled_disposable_container` | Execute on a fresh container spawned by the Torque agent (nothing persists) |

### Execution — asynchronous (non-blocking)

| Tool | Description |
|------|-------------|
| `run_on_tunneled_ssh_async` | Start an SSH command asynchronously; returns an execution ID |
| `run_on_tunneled_persistent_container_async` | Start a persistent-container command asynchronously |
| `run_on_tunneled_disposable_container_async` | Start a disposable-container command asynchronously |
| `get_execution_status` | Check the status/output of an async execution by ID |
| `cancel_execution` | Cancel a running async execution |

### Configuration

| Tool | Description |
|------|-------------|
| `setup` | Interactively set up or add a Torque connection profile (opens a browser) |
| `list_profiles` | List available configuration profiles and base configuration |

## CLI usage

The same entry point is a CLI outside of any AI client:

```bash
# Onboarding / config
torque-tunnel register-mcp-client --list          # show supported clients + detection
torque-tunnel setup                      # interactive Torque login (browser)
torque-tunnel profiles                   # list configured profiles
torque-tunnel serve                      # run as an MCP server (stdio)

# Run commands
torque-tunnel ssh "uname -a"
torque-tunnel ssh --host 10.0.0.1 --user root "df -h"
torque-tunnel ssh --upload ./script.sh:/tmp/script.sh:755 "bash /tmp/script.sh"
torque-tunnel persistent-container "curl https://example.com"
torque-tunnel disposable-container "curl https://example.com"

# Read/list remote files
torque-tunnel read /etc/hostname
torque-tunnel list /var/log

# Use a profile / override at runtime
torque-tunnel --profile lab-server-1 ssh "uname -a"
```

## How it works

1. The AI client sends a command via the MCP tool.
2. The MCP server calls Torque's REST API to launch a shell blueprint on the specified agent.
3. The blueprint runs as a Shell Grain on the Torque agent.
4. For SSH commands the grain SSHs to the target host and executes the command; for container tools it runs inside a Torque-managed container.
5. Output is streamed back and returned to the AI client.
6. Large file transfers use [croc](docs/croc-file-transfer.md) automatically.

## Security notes

- SSH private keys are base64-encoded before transmission and written to
  temporary files with 600 permissions during execution.
- All execution is audited in Torque's environment logs.
- Dangerous commands (reboot, shutdown, `docker restart`, etc.) are blocked by
  default; pass `allow_dangerous_commands` / `--allow-dangerous-commands` to override.
- `register-mcp-client` backs up any client config before modifying it and never
  overwrites a config it cannot parse.

## Troubleshooting

- **AI client doesn't show the tools** — restart the client (MCP servers load at startup).
- **"Torque ... not configured"** — run `torque-tunnel setup` (or `register-mcp-client --run-setup`).
- **"Environment did not complete within X seconds"** — the command may be slow; check the Torque UI and use `--timeout` to extend.
- **SSH connection refused** — ensure the Torque agent can reach the target on port 22.

More: [docs/onboarding.md](docs/onboarding.md#troubleshooting).

## Project structure

```
torque-tunnel/
├── scripts/
│   ├── onboard.ps1                       # Windows one-command onboarding
│   └── onboard.sh                        # Linux/macOS one-command onboarding
├── mcp.json                              # Annotated manual MCP config template
├── blueprints/
│   ├── remote-shell-executor.yaml        # SSH-to-target blueprint
│   ├── persistent-container.yaml         # Persistent container blueprint
│   └── local-shell-executor.yaml         # Disposable container blueprint
├── src/torque_tunnel/
│   ├── mcp_tool.py                       # MCP server + CLI (tools, subcommands, register-mcp-client)
│   ├── torque_client.py                  # Torque API client
│   ├── config.py                         # Config file loading + profile resolution
│   ├── auth.py                           # Browser-based interactive login/setup
│   ├── onboarding.py                     # Client detection + MCP config registration
│   ├── croc_manager.py                   # Large-file transfer via croc
│   └── login_page.html                   # Setup UI
├── docs/
│   ├── onboarding.md                     # Onboarding guide
│   ├── configuration.md                  # Config file & profiles reference
│   ├── croc-file-transfer.md             # Large-file transfer design
│   └── design-login-flow.md              # Login/setup design notes
├── tests/
├── pyproject.toml
└── README.md
```
