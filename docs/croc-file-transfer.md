# Croc File Transfer Integration

## Overview

torque-tunnel uses [croc](https://github.com/schollz/croc) for transferring files that exceed the Torque API's inline payload limits. Croc provides peer-to-peer encrypted file transfer via a public relay server.

## When Croc is Used

### Uploads
Files are automatically routed through croc when their **compressed size** exceeds **300KB** (~307,200 bytes). Files below this threshold continue to use the existing inline base64 approach via Torque API payloads.

This threshold was determined empirically:
- Torque API returns HTTP 413 at ~600KB payloads
- Shell grain hangs at ~450KB payloads
- 300KB provides a safe margin

### Downloads
Downloads **always** use croc regardless of file size. There is no inline alternative for downloads since the remote file content cannot be embedded in API responses reliably.

## Architecture

### Upload Transfer Modes

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

### Upload Flow

1. `prepare_files_with_croc()` splits files into inline (small) and croc (large) groups
2. For croc files: creates a staging directory with uniquely-named copies/tars
3. Generates a 2048-bit cryptographic code for the transfer
4. `execute_with_croc()` starts `croc send` locally in background
5. The Torque environment starts, and the remote side runs `croc receive`
6. After execution, the croc process and staging directory are cleaned up

### Download Transfer Modes

**Container targets** (disposable/persistent):
```
Agent container --[croc relay]--> Local machine
```
Container stages files with `cp -r` to a temp dir, then runs `croc send`. Local machine runs `croc receive` in background.

**SSH targets**:
```
SSH target --[SCP]--> Agent container --[croc relay]--> Local machine
```
Container SCPs files from SSH target to a temp dir, then runs `croc send`. Local machine runs `croc receive` in background.

### Download Flow

1. `prepare_download_with_croc()` creates a `DownloadPlan` with croc code, receive dir, and file mappings
2. Generates shell commands for the remote side (croc install + `cp -r`/SCP + `croc send`)
3. `execute_download_receive()` starts `croc receive` locally in background (connects to relay, waits for sender)
4. The Torque environment runs the main command, then finally commands, then download commands
5. After the environment completes, `finalize_download()` moves received files from temp dir to final local destinations
6. `cleanup_download_resources()` removes the temp receive dir and kills the croc process

### Async Handlers

For async tools (`run_on_tunneled_ssh_async`, etc.), the croc send process (uploads) and croc receive process (downloads) are tracked in `_croc_async_state[environment_id]` and cleaned up when:
- `get_execution_status` detects a terminal status (also finalizes downloads and includes results in output)
- `cancel_execution` is called
- An error occurs during environment startup

Download results for async executions are stored in `_download_results[environment_id]` and included in the `get_execution_status` response.

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
| `src/torque_tunnel/croc_manager.py` | Cross-platform croc binary management, code generation, shell command generation (upload + download) |
| `src/torque_tunnel/mcp_tool.py` | `FileDeploymentPlan`, `DownloadPlan`, prepare/execute/finalize/cleanup helpers, handler integration |
| `blueprints/remote-shell-executor.yaml` | `container_pre_commands_b64` for pre-SSH croc uploads, `download_commands_b64` for post-SSH croc downloads |
| `blueprints/local-shell-executor.yaml` | `download_commands_b64` for post-command croc downloads on containers |
| `src/torque_tunnel/torque_client.py` | `container_pre_commands` and `download_commands` parameters |

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
- Upload: receive command generation (files, directories, modes, error handling)
- Upload: SCP command generation (key auth, password auth, directory tar piping)
- Upload: `prepare_files_with_croc()` (inline decisions, croc decisions, mixed, staging dir)
- Download: `generate_croc_send_commands()` (staging, cleanup, error handling)
- Download: `generate_croc_scp_download_commands()` (key/password auth, staging, cleanup)
- Download: `prepare_download_with_croc()` (container/ssh modes, file mappings, unique codes/dirs)
- Download: `finalize_download()` (move files/dirs, create parent dirs, overwrite, missing files)
- Download: `cleanup_download_resources()` (cleanup process and temp dir)
- Download: `parse_downloads()` (CLI arg parsing, Windows drive letters)
- Edge cases (empty files, missing paths, duplicate basenames, special characters)
