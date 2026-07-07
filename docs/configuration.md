# Configuration & Profiles

## Config File

torque-tunnel loads settings from a YAML config file, auto-discovered in this order:

1. `--config <path>` explicit CLI argument
2. `TORQUE_TUNNEL_CONFIG` environment variable
3. `~/.torque-tunnel/config.yaml` (default location)

### Structure

```yaml
# ── Top-level defaults ───────────────────────────────────────────────
# These apply to all invocations unless overridden by a profile or
# runtime argument.

torque_url: https://your-torque-domain.com
torque_token: your-long-token
torque_space: your-space
torque_agent: your-agent
ssh_user: root
ssh_key: "C:\\path\\to\\key.pem"
host: 10.0.0.1
init_commands: "export HTTP_PROXY=http://proxy:80"
# finally_commands: ""
# auto_delete_environments: false
# verbose: false
# container_idle_timeout: 7200

# ── Default profile ─────────────────────────────────────────────────
# Automatically applied at startup when no --profile is specified.
# Omit or leave empty to use only top-level defaults.
default_profile: my-profile

# ── Display control ─────────────────────────────────────────────────
# Controls whether the list_profiles tool/command shows values or just
# key names at this level. Default: false.
# expose_values: true

# ── Named profiles ──────────────────────────────────────────────────
# Each profile overrides only the keys it specifies, on top of the
# top-level defaults.
profiles:
  lab-base:
    description: "Common settings for lab machines"
    torque_agent: lab-agent
    init_commands: "export PROXY=http://proxy:80"

  lab-server-1:
    description: "Lab server 10.0.0.10"
    extends: lab-base
    host: 10.0.0.10

  lab-server-2:
    description: "Lab server 10.0.0.20"
    extends: lab-base
    host: 10.0.0.20
    ssh_user: admin

  review2:
    description: "Different Torque environment"
    torque_url: https://review2.example.com
    torque_token: different-token
    torque_space: different-space
    torque_agent: review2-agent
    # Show this profile's values in list_profiles output
    expose_values: true
```

## Available Keys

### Configuration keys

These can appear at the top level and/or inside any profile:

| Key | Description |
|-----|-------------|
| `torque_url` | Torque base URL |
| `torque_token` | Torque API token |
| `torque_space` | Torque space name |
| `torque_agent` | Torque agent name |
| `ssh_key` | SSH private key (file path or content) |
| `ssh_password` | SSH password (mutually exclusive with `ssh_key`) |
| `host` | Target server IP/hostname |
| `ssh_user` | SSH username |
| `init_commands` | Commands to run before every SSH command |
| `finally_commands` | Commands to run after every SSH command |
| `auto_delete_environments` | Auto-delete environments after completion |
| `verbose` | Show full unfiltered output |
| `container_idle_timeout` | Idle timeout for persistent containers (seconds) |
| `retry_enabled` | Master switch for transient-error retries + idempotent creates (default `true`) |
| `retry_budget_seconds` | Max consecutive outage tolerated while polling/monitoring, in seconds (default `600`, sized for a ~10-min Torque redeploy) |
| `create_retry_budget_seconds` | Budget for idempotent environment create + reconcile, in seconds (default `600`) |
| `retry_max_backoff_seconds` | Exponential-backoff cap between retries, in seconds (default `15`) |

### Top-level-only keys

| Key | Default | Description |
|-----|---------|-------------|
| `default_profile` | *(none)* | Profile to apply automatically at startup when no `--profile` is given |
| `expose_values` | `false` | Whether `list_profiles` shows values or just key names for the base configuration |

### Profile metadata keys

These are recognized inside profiles but are not configuration values:

| Key | Description |
|-----|-------------|
| `description` | Human-readable description (shown in `list_profiles` output) |
| `extends` | Parent profile name for single inheritance |
| `expose_values` | Whether `list_profiles` shows this profile's values or just key names (default: `false`) |

> **Note:** `expose_values` is **not** inherited through `extends`. Each level (top-level and each profile) independently controls whether its own values are exposed.

## Resolution Order

From highest to lowest precedence:

1. **Runtime arguments** — CLI flags (`--host`) or MCP tool parameters from the AI
2. **Profile values** — from `--profile <name>` (CLI), `profile` tool parameter (MCP), or `default_profile` in config
3. **Top-level defaults** — keys at the root of the config file
4. **Environment variables** — `TORQUE_URL`, `SSH_KEY`, etc.

## Profiles

### Inheritance

Profiles can extend another profile with `extends: <parent-name>`. The child's values override the parent's. Chains work to any depth (but circular references are rejected).

```yaml
profiles:
  base:
    torque_agent: lab-agent
    init_commands: "export PROXY=http://proxy:80"
  
  server-a:
    extends: base
    host: 10.0.0.10
    # Inherits torque_agent and init_commands from base
```

### SSH auth mutual exclusion

`ssh_key` and `ssh_password` are mutually exclusive at each level. When a more concrete level sets one, the other is automatically cleared:

- Profile sets `ssh_password` → any inherited `ssh_key` is cleared
- Runtime args pass `private_key` → profile's `ssh_password` is not injected

### Default profile

Set `default_profile` at the top level to auto-apply a profile at startup:

```yaml
default_profile: my-profile
```

This is equivalent to always passing `--profile my-profile`, but can still be overridden by an explicit `--profile` on the CLI or a `profile` parameter in an MCP tool call.

## Usage

### CLI

```bash
# Use default config (applies default_profile if set)
torque-tunnel ssh "uname -a"

# Use a specific profile (overrides default_profile)
torque-tunnel --profile lab-server-1 ssh "uname -a"

# Profile + runtime override
torque-tunnel --profile lab-server-1 ssh --host 10.0.0.99 "df -h"

# List available profiles
torque-tunnel profiles
```

### MCP (AI tool calls)

The AI can use profiles by passing the `profile` parameter:

```
run_on_tunneled_ssh(command="uname -a", profile="lab-server-1")
```

Or discover profiles first:

```
list_profiles()
```

### Simplified MCP server config

With a config file, the client's MCP entry shrinks to just how to launch the
server. There are two schema families depending on the client (let
`torque-tunnel register-mcp-client` write the right one automatically — see
[onboarding.md](onboarding.md)).

**`mcpServers` family** — Claude Code (`~/.claude.json`), Cursor, Windsurf, Claude Desktop:

```jsonc
{
  "mcpServers": {
    "torque-tunnel": {
      "command": "C:\\ZeroTouch\\torque-tunnel\\.venv\\Scripts\\python.exe",
      "args": ["-m", "torque_tunnel.mcp_tool"]
    }
  }
}
```

**`servers` family** — GitHub Copilot / VS Code (`%APPDATA%\Code\User\mcp.json`); note `"type": "stdio"`:

```jsonc
{
  "servers": {
    "torque-tunnel": {
      "type": "stdio",
      "command": "C:\\ZeroTouch\\torque-tunnel\\.venv\\Scripts\\python.exe",
      "args": ["-m", "torque_tunnel.mcp_tool"]
    }
  }
}
```

Optionally override the default profile by appending to `args`: `"args": ["-m", "torque_tunnel.mcp_tool", "--profile", "lab-server-1"]`
