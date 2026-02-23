# torque-tunnel

An MCP tool that enables Copilot to execute commands on remote servers by tunneling through Torque agent infrastructure.

## Overview

This tool creates a bridge between Copilot and remote servers by leveraging Torque's infrastructure:

```
Copilot → MCP Tool (local) → Torque REST API → Shell Grain Blueprint → SSH → Target Host
```

## Prerequisites

1. **Torque Account** with access to the target space
2. **Torque Docker Agent** running on a host that can reach the target server
3. **SSH Access** to the target server (private key)
4. **Python 3.10+** installed locally

## Installation

### 1. Install the MCP Tool

```bash
cd torque-tunnel
pip install -r requirements.txt
pip install -e .
```

### 2. Configure VS Code

See [`mcp.json`](mcp.json) for the full annotated configuration template with all available options and detailed instructions on how to obtain a long-lived API token.

**Quick start:**

1. Open `mcp.json` in this repo and follow the setup instructions in the comments
2. Copy/merge the `"torque-tunnel"` server entry into `%APPDATA%\Code\User\mcp.json`
   (typically `C:\Users\<USERNAME>\AppData\Roaming\Code\User\mcp.json`)
3. If you already have other MCP servers configured there, just add `"torque-tunnel"` to the existing `"servers"` object

The minimum required settings are `--torque-url`, `--torque-token`, `--torque-space`, and `--torque-agent`. All other options (SSH target, command hooks, behavior flags) can be supplied by the AI agent at runtime or pre-configured for convenience.

## Available Tools

### Synchronous (blocking)

| Tool | Description |
|------|-------------|
| `run_on_tunneled_ssh` | Execute a command on a remote server via SSH through the Torque agent |
| `run_on_tunneled_persistent_container` | Execute a command on a persistent Torque agent container (state preserved across calls) |
| `run_on_tunneled_disposable_container` | Execute a command on a fresh container spawned by Torque agent (nothing persists) |

### Asynchronous (non-blocking)

| Tool | Description |
|------|-------------|
| `run_on_tunneled_ssh_async` | Start an SSH command asynchronously, returns immediately with an execution ID |
| `run_on_tunneled_persistent_container_async` | Start a persistent container command asynchronously |
| `run_on_tunneled_disposable_container_async` | Start a disposable container command asynchronously |
| `get_execution_status` | Check the status/output of an async execution by ID |
| `cancel_execution` | Cancel a running async execution |

## CLI Usage

The tool also supports direct CLI usage outside of VS Code:

```bash
# Run a command on a remote server via SSH
torque-tunnel ssh "uname -a"
torque-tunnel ssh --host 10.0.0.1 --user root "df -h"

# Upload files and run a command
torque-tunnel ssh --upload ./script.sh:/tmp/script.sh:755 "bash /tmp/script.sh"

# Run on the Torque agent container directly
torque-tunnel container "curl https://example.com"

# Read/list remote files
torque-tunnel read /etc/hostname
torque-tunnel list /var/log
```

## How It Works

1. Copilot sends a command via the MCP tool
2. The MCP tool calls Torque's REST API to launch a shell blueprint on the specified agent
3. The blueprint runs as a Shell Grain on the Torque agent
4. For SSH commands: the grain SSHs to the target host and executes the command
5. Output is streamed back and returned to Copilot
6. The Torque environment can be auto-cleaned (see `--auto-delete-environments`)

## Security Notes

- SSH private keys are base64 encoded before transmission
- Keys are stored in temporary files with 600 permissions during execution
- All execution is audited in Torque's environment logs
- Dangerous commands (docker restart, reboot, shutdown, etc.) are blocked by default

## Troubleshooting

### "Agent name must be provided"
Set `--torque-agent` in your mcp.json config or pass it at runtime.

### "Environment did not complete within X seconds"
The command may be taking too long. Check Torque UI for environment status. Use `--timeout` to extend.

### SSH Connection Refused
Ensure the Torque agent can reach the target server on port 22.

## Project Structure

```
torque-tunnel/
├── mcp.json                          # Annotated config template — copy to %APPDATA%\Code\User\mcp.json
├── blueprints/
│   ├── remote-shell-executor.yaml    # SSH-to-target blueprint
│   ├── persistent-container.yaml     # Persistent container blueprint
│   └── local-shell-executor.yaml     # Disposable container blueprint
├── src/
│   └── torque_tunnel/
│       ├── __init__.py
│       ├── mcp_tool.py               # MCP tool + CLI implementation
│       └── torque_client.py          # Torque API client
├── pyproject.toml
├── requirements.txt
└── README.md
```
