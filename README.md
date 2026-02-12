# ShellAgent

An MCP tool that enables Copilot to execute commands on remote servers via Torque Shell Grains.

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
cd ShellAgent
pip install -r requirements.txt
pip install -e .
```

### 2. Deploy the Blueprint to Torque

Upload the blueprint file `blueprints/remote-shell-executor.yaml` to your Torque space's blueprint repository.

### 3. Configure Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:
```
TORQUE_URL=https://review1.qualilabs.net
TORQUE_TOKEN=your-api-token-here
TORQUE_SPACE=BMaaS
TORQUE_AGENT=dannyk-revertable-alma2
```

To get a Torque API token:
1. Go to Torque UI → Settings → Integrations
2. Click on any CI tool → New Token
3. Copy the generated token

### 4. Configure VS Code MCP

Add to your VS Code settings (`settings.json`):

```json
{
  "mcp": {
    "servers": {
      "shellagent": {
        "command": "python",
        "args": ["-m", "shellagent.mcp_tool"],
        "cwd": "c:\\ZeroTouch\\ShellAgent\\src",
        "env": {
          "TORQUE_URL": "https://review1.qualilabs.net",
          "TORQUE_TOKEN": "your-token-here",
          "TORQUE_SPACE": "BMaaS",
          "TORQUE_AGENT": "dannyk-revertable-alma2"
        }
      }
    }
  }
}
```

Or using command-line arguments:

```json
{
  "mcp": {
    "servers": {
      "shellagent": {
        "command": "python",
        "args": [
          "-m", "shellagent.mcp_tool",
          "--torque-url", "https://review1.qualilabs.net",
          "--torque-token", "your-token-here",
          "--torque-space", "BMaaS",
          "--torque-agent", "dannyk-revertable-alma2"
        ],
        "cwd": "c:\\ZeroTouch\\ShellAgent\\src"
      }
    }
  }
}
```

## Available Tools

### `run_remote_command`

Execute any shell command on a remote server.

**Parameters:**
- `target_ip` (required): IP address or hostname of the remote server
- `ssh_user` (required): SSH username
- `ssh_private_key` (required): SSH private key content
- `command` (required): Shell command to execute
- `agent` (optional): Torque agent name (uses default if not specified)

## Usage Example

Once configured, you can ask Copilot things like:

> "Check the disk space on server 192.168.1.100 using SSH user admin"

Copilot will use the `run_remote_command` tool to execute `df -h` on the remote server via Torque.

## How It Works

1. You provide Copilot with SSH credentials and a command
2. The MCP tool calls Torque's REST API to launch the `remote-shell-executor` blueprint
3. The blueprint runs as a Shell Grain on the specified Torque agent
4. The Shell Grain SSHs to the target host and executes the command
5. Output is captured and returned to Copilot
6. The Torque environment is automatically cleaned up

## Security Notes

- SSH private keys are base64 encoded before transmission
- Keys are stored in temporary files with 600 permissions during execution
- Torque environments are short-lived (10 minutes max) and auto-cleaned
- All execution is audited in Torque's environment logs

## Troubleshooting

### "Agent name must be provided"
Set the `TORQUE_AGENT` environment variable or pass `--torque-agent`.

### "Environment did not complete within X seconds"
The command may be taking too long. Check Torque UI for environment status.

### SSH Connection Refused
Ensure the Torque agent can reach the target server on port 22.

## Project Structure

```
ShellAgent/
├── blueprints/
│   └── remote-shell-executor.yaml  # Torque blueprint
├── src/
│   └── shellagent/
│       ├── __init__.py
│       ├── mcp_tool.py            # MCP tool implementation
│       └── torque_client.py       # Torque API client
├── .env.example
├── requirements.txt
└── README.md
```
