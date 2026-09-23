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

The decision is made on **compressed** size, so a large but highly compressible
file still goes inline. Deciding it never loads the file into memory:

1. `os.path.getsize()` first — DEFLATE cannot beat 1032:1, so anything above
   `300KB * 1032` (~317 MB) provably cannot fit inline and is routed to croc
   without reading a byte.
2. Otherwise the file is gzipped in 1 MB chunks into a buffer that stops storing
   once it passes 300KB.

Before this, the check was `gzip.compress(open(path).read())` — which held the
whole file *and* its compressed copy in RAM just to compare against 300KB
(~2.5 GB for a 1.27 GB upload; a `MemoryError` for a 15.7 GB image).

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
Container stages files with `ln` (hardlink; `cp -r` fallback for directories or cross-device sources) to a temp dir, then runs `croc send`. Local machine runs `croc receive` in background.

**SSH targets** (also used for persistent containers — the runner container SCPs from the persistent container):
```
SSH target --[SCP]--> Agent container --[croc relay]--> Local machine
```
Container SCPs files from SSH target to a temp dir, then runs `croc send`. Local machine runs `croc receive` in background.

### Download Coordination Protocol (sender-first handshake)

A receiver that hammers the relay room with retries can cross the sender's room
registration mid-handshake and kill it with `could not secure channel` (PAKE
failure). This bit hard on 2026-07-28 with a 2.2 GB VMDK: long staging + hashing
guaranteed many receiver attempts were in flight when the sender finally
registered; the failure was then converted to exit 0 and the receiver silently
burned its 30-minute deadline. The download path is therefore coordinated so the
receiver only connects AFTER the sender's room exists:

The remote croc-send wrapper (`_generate_croc_send_core`) emits sentinel lines
on stdout, which reach the local machine through the streamed grain log:

| Sentinel | Meaning |
|---|---|
| `__CROC_DL_SIZE__ <bytes> <croc_filename>` | Staged file size (one per regular file) |
| `__CROC_DL_MD5__ <md5hex> <croc_filename>` | Staged file content hash (one per regular file) |
| `__CROC_SEND_READY__` | croc printed `Code is:` — the relay room is registered |
| `__CROC_SEND_RETRY__` | send failed; the wrapper restarts croc send once |
| `__CROC_DL_DONE__ exit_code=N` | send finished (rc 0/124/137/143) |
| `__CROC_DL_FAILED__ exit_code=N` | send failed after the retry; wrapper exits 1 |

**Why a content hash and not just size:** croc pre-sizes the destination file
and writes ranges over parallel connections, so a transfer that dies mid-flight
leaves a file with the CORRECT byte length full of holes. The 2026-07-29
incident delivered a 2.3 GB VMDK that was 72.8% zeros with a matching size —
every size-based check passed. Both the receive wrapper and
`finalize_download()` therefore verify MD5 (when the sentinel was observed)
before a file is accepted or placed; a corrupt file is reported as
`DOWNLOAD FAILED: ... content corruption ...` and never reaches the
destination path.

Locally, `DownloadPlan.observe_output()` (wired into every log stream via
`make_download_watch_callback`, and into `_background_stream_grain_log` for
async executions) parses the sentinels and relays them to the receive wrapper
through dot-files in the receive dir:

| Signal file | Effect on the receive wrapper |
|---|---|
| `.croc_send_ready` | allows croc attempts (removed while the sender retries) |
| `.croc_abort` | stop immediately, killing any in-flight croc attempt |
| `.croc_expected_manifest.json` | `{name: {size, md5}}` — success requires every expected file at its exact size AND content hash (rejects partial and hole-riddled transfers) |
| `.croc_receive.log` | attempt log + croc output written by the wrapper (diagnostics) |

Other properties of the send wrapper:
- The croc-send timeout scales with the staged payload size (assumes ≥1 MB/s
  through the relay, +120s base; the `timeout` argument is only a floor) so
  multi-GB transfers are not SIGTERMed mid-flight.
- Croc reliably hangs after 100% through proxy relays; the monitor kills it
  once its progress line has sat unchanged at 100% for ~45s
  (`CROC_SEND_STALL_CHECKS`), so the hang costs seconds instead of the
  remaining size-scaled timeout budget. Exit codes 124/137/143 are treated as
  this hang; the local size verification is the real completeness check.
- A transfer can also freeze MID-flight (observed live 2026-08-03: 25 minutes
  at 87% — the proxy silently killed the long-lived relay tunnel). If a
  below-100% progress line is unchanged for ~120s
  (`CROC_SEND_MIDSTALL_CHECKS`), croc is killed and the send is retried —
  croc can usually resume from the receiver's partial file. Only lines with a
  percentage count, so the pre-transfer "Sending ..." wait (which can
  legitimately last minutes while sentinels travel through the log stream)
  never trips it. A stall on the retry too is reported as FAILED, not as a
  whitelisted hang.
- One full retry on failure (relay flakes), with a delay so the local watcher
  can pull the ready signal first.
- A final failure exits non-zero and is machine-readable — never a warning.
- Croc's own output (which includes the transfer code) goes to a local file,
  and only filtered progress lines are echoed — the secret no longer lands in
  the persisted grain log at all (the old code streamed croc's raw output,
  code included).
- Progress lines are echoed only when they change, with a ~30s heartbeat while
  unchanged — a liveness signal that also keeps the runner shipping log chunks
  (the gated receiver depends on sentinels arriving through that stream, and a
  fully quiet log was observed to sit in the runner's buffer for minutes).

### Download Flow

1. `prepare_download_with_croc()` creates a `DownloadPlan` with croc code, receive dir, and file mappings
2. Generates shell commands for the remote side (croc install + `ln`/`cp -r`/SCP staging + monitored `croc send`)
3. `execute_download_receive()` starts the gated `croc receive` wrapper locally in background (idle until the READY sentinel arrives)
4. The caller wires `make_download_watch_callback(dl_plan, log_callback)` into the environment's log stream
5. The Torque environment runs the main command, then finally commands, then download commands
6. After the environment completes, `complete_download()` winds the receiver down:
   - remote send failed / never registered → abort the receiver immediately (no 30-minute burn)
   - otherwise → bounded grace period (`CROC_DOWNLOAD_RECEIVE_WAIT_SECONDS`)
   - then `finalize_download()` verifies sizes and moves files to their destinations
7. `cleanup_download_resources()` removes the temp receive dir and stops the receiver —
   abort-signal first (so the wrapper kills its in-flight croc child — tree-kill on
   Windows — and exits cleanly), then terminate as fallback, then delete with one
   retry. Terminating the wrapper directly used to orphan croc, whose open handle
   on the partial file made the receive dir undeletable (observed live: a partial
   still being written 11 minutes after the CLI exited, and dozens of stale
   `torque_dl_*` dirs accumulated since June).

**Failure propagation:** a requested download that did not complete makes the
CLI exit non-zero (even if the remote command exited 0) and prints
`DOWNLOAD FAILED: ...` lines to stderr; MCP responses include
`DOWNLOAD FAILED` entries in the Files Downloaded section. Callers no longer
need out-of-band file-existence checks.

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

## Relay rate limiting

The public relay (`croc.schollz.com`, currently `142.132.189.179:9009`) runs a
newer croc than the pinned client and enforces an admission limiter the pinned
client knows nothing about — so the client only ever sees the rejection.

From croc `master`, `src/tcp/defaults.go`:

```go
DEFAULT_SOURCE_JOIN_LIMIT = 30
DEFAULT_ROOM_JOIN_LIMIT   = 30
DEFAULT_JOIN_LIMIT_WINDOW = time.Minute
```

`canonicalSource()` keys the limiter on the sender's **exact IP** (not a subnet),
over a rolling 60 seconds. Over the limit, the relay replies with the literal
string `rate limited` and croc exits 1 after printing:

```
could not connect to 142.132.189.179:9009: got bad response: rate limited
```

**Measured 2026-09-17** (laptop, one public IP, sends 3s apart): sends 1-8 from a
cold window succeeded, the 9th was rejected. One `croc send` therefore costs
about **four admissions** — the control connection plus the `--transfers`
parallel streams, all opened when the room is registered, before any receiver
shows up. That budget is **~7-8 transfers per minute per public IP**, shared by
every session behind it, and a *failed* attempt spends its admissions too.

This is not size-dependent. A 400KB file is rejected exactly as often as a 30MB
one; size only decides whether croc is used at all. The symptom looked
size-dependent only because files under the threshold never touch croc.

### How this is handled

1. **croc's output is captured, not discarded.** `start_croc_send()` sends
   stdout and stderr to a temp file (not a pipe — nothing drains it while croc
   runs, and croc's progress output would eventually deadlock on a full pipe
   buffer, which is why this was `DEVNULL` and why the failure said nothing).
   The tail is quoted in the `RuntimeError`, scrubbed of the transfer code.
   `cleanup_croc_send()` removes the file — after the process exits, because
   Windows will not unlink a file croc still holds open.
2. **Rate-limited sends retry with backoff** — `CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS`
   = `(20, 45, 70)`, four attempts in total, the last wait outlasting the relay's
   rolling minute. Any other failure raises immediately: it would fail the same
   way on a retry, and a retry would spend admissions for nothing.
3. **The receiving side retries too.** The limiter applies to the agent
   container as well, keyed on *its* egress IP — which behind a corporate NAT is
   shared with everything else on it. `generate_croc_receive_attempt()` wraps the
   receive in the same bounded loop (`CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS`),
   retrying only when croc's output contains `rate limited`. Output goes through
   `tee`, so transfer progress is still streamed live while the loop keeps a copy
   to grep; the exit code travels through a small file because a pipeline would
   swallow it and `PIPESTATUS` is not portable to a plain `sh` grain. Without
   this, one rejection failed the whole upload with nothing but
   `croc file receive failed (exit code: 1)`.
4. **The relay is configurable** — see `croc_relay` in
   [configuration.md](configuration.md). A private relay (`croc relay` on any host
   both sides can reach) has its own budget and is the real fix for heavy use.
5. **`croc_transfers` trades throughput for admissions** — each stream costs one
   admission, so `croc_transfers: 1` gives roughly four times as many transfers
   per minute at the price of single-stream speed. Left unset, croc's default
   (4) applies. On high-latency paths (e.g. through `proxy.esl.cisco.com`)
   parallel streams matter a great deal, so do not lower this by reflex.

### What is *not* a problem

Reaching the relay from inside Cisco's network. croc has HTTP-proxy support
(`--connect`, which defaults from `$HTTP_PROXY`), and the agent container already
has `HTTP_PROXY` exported by the profile's `init_commands`. Verified 2026-09-17
from the tunnel container: `CONNECT 142.132.189.179:9009` through
`proxy.esl.cisco.com:80` returns `200 Connection established`, and `croc send`
registers its room normally. Note the receiving side is the **agent container**,
not the SSH target — croc is never installed on the target, so `command -v croc`
there is empty by design.

## Performance

### Remote croc Installation
- Uses 7 parallel `curl` chunks for downloading the croc binary (~2.1 seconds on tested network)
- Falls back to single-stream download if chunk detection fails
- Skipped entirely if croc is already installed

### Local croc Binary
- Automatically downloaded from GitHub releases on first use
- Cached under a **versioned filename** so bumping `CROC_VERSION` can never
  serve a stale binary (both sides must run the same version or the PAKE
  handshake fails with `could not secure channel`); stale versions are cleaned
  up on the next lookup:
  - Windows: `%LOCALAPPDATA%\torque-tunnel\bin\croc-v10.4.2.exe`
  - macOS: `~/Library/Caches/torque-tunnel/bin/croc-v10.4.2`
  - Linux: `~/.cache/torque-tunnel/bin/croc-v10.4.2`
- Also checks system PATH for pre-installed croc (used only if `--version` matches)

## Configuration

| Constant | Value | Description |
|---|---|---|
| `CROC_VERSION` | v10.4.2 | Pinned croc version |
| `CROC_THRESHOLD_BYTES` | 307,200 | Compressed size threshold for croc vs inline |
| `REMOTE_INSTALL_CHUNKS` | 7 | Parallel download chunks for remote install |
| `CROC_SEND_STARTUP_SECONDS` | 3 | Wait time for croc to register with relay (uploads) |
| `CROC_SEND_RETRY_DELAY_SECONDS` | 8 | Delay before the remote sender's single retry |
| `CROC_SEND_MIN_RATE_BYTES_PER_SEC` | 1,000,000 | Assumed relay rate for scaling the send timeout |
| `CROC_RATE_LIMIT_MARKER` | `rate limited` | The relay's literal rejection string |
| `CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS` | (20, 45, 70) | Waits between rate-limit retries (local send) |
| `CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS` | (20, 45, 70) | Waits between rate-limit retries (remote receive) |
| `CROC_OUTPUT_TAIL_BYTES` | 4,096 | How much croc output is quoted back in an error |
| `MAX_GZIP_RATIO` (mcp_tool) | 1032 | DEFLATE's best possible ratio; bounds the inline check |
| `CROC_DOWNLOAD_RECEIVE_WAIT_SECONDS` | 120 | Post-command grace for the receiver to flush |
| `CROC_DOWNLOAD_ABORT_WAIT_SECONDS` | 10 | Post-abort wait for the receiver to exit |

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
- Download: `finalize_download()` (move files/dirs, create parent dirs, overwrite, missing files, size verification)
- Download: `cleanup_download_resources()` (cleanup process and temp dir)
- Download: `parse_downloads()` (CLI arg parsing, Windows drive letters)
- Edge cases (empty files, missing paths, duplicate basenames, special characters)
- Race fix (`tests/test_download_race_fix.py`): the generated send commands are
  executed under bash (Git Bash on Windows) with a fake croc, verifying the
  READY/SIZE/RETRY/DONE/FAILED sentinel behavior, size-scaled timeouts, one-shot
  retry, and non-zero exit on failure; the receive wrapper is exercised with a
  fake croc binary verifying gating, abort, size-verified completion (partial
  files rejected), and attempt logging; `complete_download()` is verified to
  return promptly on remote failure instead of waiting out the deadline
