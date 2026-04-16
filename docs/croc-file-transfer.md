# Croc File Transfer Integration

## Overview

torque-tunnel uses [croc](https://github.com/schollz/croc) for transferring files that exceed the Torque API's inline payload limits. Croc provides peer-to-peer encrypted file transfer via a public relay server.

## When Croc is Used

Files are automatically routed through croc when their **compressed size** exceeds **300KB** (~307,200 bytes). Files below this threshold continue to use the existing inline base64 approach via Torque API payloads.

This threshold was determined empirically:
- Torque API returns HTTP 413 at ~600KB payloads
- Shell grain hangs at ~450KB payloads
- 300KB provides a safe margin

## Architecture

### Transfer Modes

**Container targets** (disposable/persistent):
```
Local machine --[croc relay]--> Agent container (receives directly)
```
Croc install + receive commands are included in `init_commands`, which run on the container.

**SSH targets**:
```
Local machine --[croc relay]--> Agent container --[SCP]--> SSH target
```
Croc install + receive + SCP commands run on the agent container via the `container_pre_commands` blueprint mechanism, before the SSH connection to the target.

### Flow

1. `prepare_files_with_croc()` splits files into inline (small) and croc (large) groups
2. For croc files: creates a staging directory with uniquely-named copies/tars
3. Generates a 2048-bit cryptographic code for the transfer
4. `execute_with_croc()` starts `croc send` locally in background
5. The Torque environment starts, and the remote side runs `croc receive`
6. After execution, the croc process and staging directory are cleaned up

### Async Handlers

For async tools (`run_on_tunneled_ssh_async`, etc.), the croc send process is tracked in `_croc_async_state[environment_id]` and cleaned up when:
- `get_execution_status` detects a terminal status
- `cancel_execution` is called
- An error occurs during environment startup

## Security

### Transfer Code
- Generated via `secrets.token_urlsafe(256)` → 2048-bit entropy (~342 characters)
- Passed via `CROC_SECRET` environment variable on both send and receive sides (not visible in process list)
- Used as the PAKE password for end-to-end encryption

### Shell Command Safety
- File permissions (`mode`) are validated against `^[0-7]{3,4}$`
- Filenames and paths are shell-escaped using single-quote escaping
- SSH credentials (keys, passwords) are handled with proper quoting

## Performance

### Remote croc Installation
- Uses 7 parallel `curl` chunks for downloading the croc binary (~2.1 seconds on tested network)
- Falls back to single-stream download if chunk detection fails
- Skipped entirely if croc is already installed

### Local croc Binary
- Automatically downloaded from GitHub releases on first use
- Cached in platform-specific directory:
  - Windows: `%LOCALAPPDATA%\torque-tunnel\bin\croc.exe`
  - macOS: `~/Library/Caches/torque-tunnel/bin/croc`
  - Linux: `~/.cache/torque-tunnel/bin/croc`
- Also checks system PATH for pre-installed croc

## Configuration

| Constant | Value | Description |
|---|---|---|
| `CROC_VERSION` | v10.4.2 | Pinned croc version |
| `CROC_THRESHOLD_BYTES` | 307,200 | Compressed size threshold for croc vs inline |
| `REMOTE_INSTALL_CHUNKS` | 7 | Parallel download chunks for remote install |
| `CROC_SEND_STARTUP_SECONDS` | 3 | Wait time for croc to register with relay |

## Files

| File | Purpose |
|---|---|
| `src/torque_tunnel/croc_manager.py` | Cross-platform croc binary management, code generation, shell command generation |
| `src/torque_tunnel/mcp_tool.py` | `FileDeploymentPlan`, `prepare_files_with_croc()`, `execute_with_croc()`, handler integration |
| `blueprints/remote-shell-executor.yaml` | Added `container_pre_commands_b64` input for pre-SSH croc transfers |
| `src/torque_tunnel/torque_client.py` | Added `container_pre_commands` parameter to `start_environment()` and `execute_remote_command()` |

## Testing

```bash
python -m pytest tests/ -v
```

Tests cover:
- Platform detection and asset naming
- Code generation (length, uniqueness, entropy)
- Mode validation
- Shell escaping
- Remote install script generation
- Receive command generation (files, directories, modes, error handling)
- SCP command generation (key auth, password auth, directory tar piping)
- `prepare_files_with_croc()` (inline decisions, croc decisions, mixed, staging dir)
- Cleanup functions (process termination, staging dir removal)
- Edge cases (empty files, missing paths, duplicate basenames, special characters)
