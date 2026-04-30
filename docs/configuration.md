# Configuration & Profiles

## Config File

torque-tunnel loads settings from a YAML config file, auto-discovered in this order:

1. `--config <path>` explicit CLI argument
2. `TORQUE_TUNNEL_CONFIG` environment variable
3. `~/.torque-tunnel/config.yaml` (default location)

### Structure

```yaml
# Default values — apply to all invocations unless overridden
default:
  torque_url: https://your-torque-domain.com
  torque_token: your-long-token
  torque_space: your-space
  torque_agent: your-agent
  ssh_user: root
  ssh_key: "C:\\path\\to\\key.pem"
  host: 10.0.0.1
  init_commands: "export HTTP_PROXY=http://proxy:80"
  finally_commands: ""
  auto_delete_environments: false
  verbose: false
  container_idle_timeout: 7200

# Named profiles — each overrides only the keys it specifies
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
```

## Resolution Order

From highest to lowest precedence:

1. **Runtime arguments** — CLI flags (`--host`) or MCP tool parameters from the AI
2. **Profile values** — from `--profile <name>` (CLI) or `profile` tool parameter (MCP)
3. **Config file defaults** — the `default:` section
4. **Environment variables** — `TORQUE_URL`, `SSH_KEY`, etc.

## Profiles

### What a profile can set

Any key from the `default` section:

| Key | Description |
|-----|-------------|
| `torque_url` | Torque base URL |
| `torque_token` | Torque API token |
| `torque_space` | Torque space name |
| `torque_agent` | Torque agent name |
| `ssh_key` | SSH private key (file path or content) |
| `ssh_password` | SSH password |
| `host` | Target server IP/hostname |
| `ssh_user` | SSH username |
| `init_commands` | Commands to run before every SSH command |
| `finally_commands` | Commands to run after every SSH command |
| `auto_delete_environments` | Auto-delete environments after completion |
| `verbose` | Show full unfiltered output |
| `container_idle_timeout` | Idle timeout for persistent containers (seconds) |

### Profile metadata

| Key | Description |
|-----|-------------|
| `description` | Human-readable description (shown in `list_profiles` / `profiles` command) |
| `extends` | Optional parent profile name (single inheritance) |

### Inheritance

Profiles can extend another profile with `extends: <parent-name>`. The child's values override the parent's. Chains work up to any depth (but no circular references).

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

## Usage

### CLI

```bash
# Use default config (no profile)
torque-tunnel ssh "uname -a"

# Use a specific profile
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

### Simplified MCP server config (mcp.json)

With a config file, `mcp.json` shrinks to:

```jsonc
{
  "servers": {
    "torque-tunnel": {
      "command": "C:\\ZeroTouch\\torque-tunnel\\.venv\\Scripts\\torque-tunnel.exe",
      "args": []
    }
  }
}
```

Optionally set a default profile: `"args": ["--profile", "lab-server-1"]`
