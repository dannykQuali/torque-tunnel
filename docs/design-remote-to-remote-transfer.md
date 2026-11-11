# Design: remote-to-remote file transfer

**Status:** implemented 2026-11-03. *As built* notes where the code differs from the
original plan. Code:
- `src/torque_tunnel/remote_transfer.py`: log parsing, manifest, relay choice, and the
  pair's state; no Torque access.
- `croc_manager.generate_croc_relay_send_commands` / `generate_croc_relay_receive_commands` /
  `generate_direct_copy_commands`: the shell for each side.
- `mcp_tool`, section "Remote-to-remote transfer": the three tools and the CLI.

## Goal

Copy files or directories from machine **A** to machine **B**. torque-tunnel can reach
both, but A and B cannot reach each other. A and B may sit behind different agents,
spaces, or Torque instances (different profiles). The machine running torque-tunnel
(the MCP server or CLI) **only orchestrates**. The data goes from A's side to B's side
through the croc relay and never passes through the caller. Target size: single files
around **15.4 GB**.

## Why a new tool

| Approach with the existing tools | What goes wrong |
|---|---|
| `download_files` from A, then `upload_files` to B (two calls) | Works, but every byte crosses the caller's link (usually a VPN) twice, and the caller needs room for the whole payload. At 15.4 GB that means two full transfers. |
| The LLM runs its own `croc send` / `croc receive` in two `_async` calls | Puts the transfer code in the commands, and loses everything the existing code took many iterations to get right: install fallback, explicit `--relay`, DNS warm-up, sender-first gating, MD5 verification, stall detection, rate-limit retries, and error reporting. |

The real problem is that one operation needs **two Torque environments, coordinated
with each other**. Environment B can only start receiving after A's sender has
registered, and B needs the sizes and hashes that A reports. A tool call today maps to
exactly one environment, and there's nowhere to describe two endpoints.

## Decisions

| Question | Decision |
|---|---|
| Where croc runs | On the agent containers, the same as today's upload and download. Never on the targets. |
| Same-agent case | Supported. It doesn't use croc (see *Same-agent shortcut*). |
| Blocking or async | **Async from the start**. A blocking variant isn't planned. Polled with the dedicated `get_transfer_status` / `cancel_transfer`, which take `sender_environment_id` and `receiver_environment_id`. |
| Relay | Resolved the same way as today, from each endpoint's profile. No new config key (see *Relay resolution*). |
| Security review | Not needed (per DannyK, 2026-11-03). |

## The tool

`transfer_files_between_tunneled_hosts_async`. It returns once the receiver
environment exists, with both environment ids. The caller then polls
`get_transfer_status` and aborts with `cancel_transfer` (see *Async*).

```jsonc
{
  "command_description": "copy ova to esxi host",   // required, like every other tool
  "sender": {                        // an "endpoint"
    "type": "ssh",                   // "ssh" | "persistent_container"
    "host": "10.91.36.240", "user": "root",
    "private_key": "C:\\...\\key.pem",   // or "password"
    "profile": "cisco-jarvis",       // optional, per endpoint
    "torque_agent": null              // optional, per endpoint (DO-NOT-SET-unless-asked rule)
  },
  "receiver": { "type": "persistent_container", "environment_id": "abc123", "profile": "laptop-local" },
  "files": [
    { "source_path": "/data/image.vmdk", "destination_path": "/vmfs/tmp/image.vmdk", "mode": "644" },
    { "source_path": "/etc/app/",        "destination_path": "/opt/app-config" }
  ],
  "timeout": 21600
}
```

*As built:* `sender` / `receiver` were called `source` / `destination` until
2026-11-03. They were renamed to match `get_transfer_status`'s
`sender_environment_id` / `receiver_environment_id`, before anyone used the tool.

- **Each endpoint resolves exactly like a run_* tool call** (see *Endpoint resolution*
  below). Each side's `init_commands`, where the proxy settings live, come from **its
  own** profile.
- If both endpoints resolve to the same host on the same agent, the call is refused,
  since that's almost certainly two omitted `host` fields.
- `persistent_container` endpoints run in SSH mode against `container_ip` as `root`, as
  the persistent-container tools do. Finding the container is the one exception to the
  shared resolution (see below).
- The call-level `profile` handling in `call_tool` is skipped for the three transfer
  tools. Each endpoint applies it itself, through the same function.

### Endpoint resolution (2026-11-03)

DannyK asked that each value in `sender` / `receiver` resolve exactly as in the other
tools, through the same code. Four functions in `mcp_tool` ("Argument resolution,
shared by every tool") do it, and every caller uses them:

| Function | What it resolves | Used by |
|---|---|---|
| `_resolve_call_profile` | `profile`: inject its tool-mappable values into the arguments, overlay the rest onto the config; refuse an unknown profile, or a missing one while the default profile is broken | `call_tool` (every tool), each transfer endpoint |
| `_resolve_agent` | `torque_agent`, else the config's agent | all six run_* tools, each endpoint |
| `_resolve_connection` | `torque_url` / `torque_token` / `torque_space`, else the config's | all six run_* tools, each endpoint |
| `_resolve_ssh_target` | `host`, `user`, and exactly one auth pair (`private_key` via `resolve_ssh_private_key`: a path, the key's content, or base64; or `password`) | both SSH tools, each SSH endpoint |

The schema descriptions of those arguments are also defined once (`_ARG_SCHEMAS`) and
used by the six run_* tools and the endpoint schema, so each field reads the same
everywhere.

**Not through the shared code, and why:**
- **`type`** (ssh / persistent_container) and **`environment_id`** belong to the
  transfer alone.
- **Finding a persistent container.** The tools use `_ensure_persistent_container`:
  without an `environment_id` it takes the default container, and when the given one is
  gone it **creates a new, empty one**. A transfer endpoint uses
  `_attach_persistent_container` instead, which requires a named, running container
  and never creates one. An empty new container is never what a transfer means: as a
  sender it has nothing to send, and as a receiver the files would land where nobody
  looks. The agent and Torque connection used to reach it still go through the shared
  code.
- **The CLI's `--from-*` / `--to-*` options** keep those names. They build the
  `sender` / `receiver` objects, which then resolve like any MCP call.
- **`setup`'s `torque_url`** is the URL to log in to, not a connection, so it keeps its
  own handling.

**Behaviour change in the SSH tools:** the key is now resolved together with host, user
and auth. Before, it was resolved after the Torque-configuration and dangerous-command
checks. So a call that is wrong in several ways at once reports a bad key first.
Nothing else changed: `tests/test_argument_resolution.py` was written **before** the
refactoring, as characterization tests, and passed unchanged after it.

`tests/test_argument_resolution.py` checks every value at every level:
- **Fields:** url, token, space, agent, host, user.
- **Levels:** every non-empty combination of argument, profile and base config, with
  and without a profile named.
- **Profiles:** a missing config file, an unknown profile, a broken default profile, an
  `extends` chain.
- **Auth:** nine cases of the auth pair, plus no auth and no host at all.
- **Key forms:** content, single-line, base64, path and `~` path, at each level.

It runs these for the six run_* tools, and the same cases for `transfer-sender` and
`transfer-receiver`. Mutation checks confirmed it fails when the precedence breaks, in
a tool or in an endpoint.
- Disposable containers are not endpoints. As a source they start empty, and as a
  destination their files are thrown away.
- **The result names both environments and both profiles**, and spells out the exact
  `get_transfer_status` call to make.

## Data path (croc)

```
 A (ssh target)          agent-A container          croc relay          agent-B container         B (ssh target)
 ─────────────           ─────────────────          ──────────          ─────────────────         ──────────────
  /data/x  ──scp/tar──▶  $__DL_DIR/_croc_0_x ──croc send──▶ room ◀──croc receive── $__CROC_DIR ──scp/tar──▶ /dst/x
                         (env A: download slot)                         (env B: container_pre_commands)
```

This is exactly today's SSH download (target → container → relay) joined to today's SSH
upload (relay → container → target). Only the caller's end is replaced, on both sides.

*As built:* the hops between a target and its agent container use **ssh pipes**, not
scp:
- sender: `ssh A 'cat P' > staged` (`tar czf -` for a directory);
- receiver: `ssh B 'cat > P.tt-partial' < received`, then an MD5 check on B, then `mv`.

scp's remote-path quoting differs between its legacy and SFTP protocols, which made
paths with spaces or quotes unreliable. Every remote command is quoted with
`shlex.quote` (`croc_manager._q`). An existing **directory** at a file's
`destination_path` is refused, because `mv` would otherwise drop the copy inside it
under its temporary name. A failed copy removes its `.tt-partial`.

## Orchestration (sender-first, across two environments)

```
tool call (caller)                env A (sender)                         env B (receiver)
──────────────────                ──────────────                         ────────────────
launch env A ───────────────────▶ main cmd: no-op
                                  download slot:
                                    install croc (FAILED sentinel on error)
                                    scp/tar files from A → $__DL_DIR
                                    __CROC_DL_SIZE__ / __CROC_DL_MD5__ per file
                                    croc send (existing monitored wrapper)
watch A's log ◀────────────────── __CROC_SEND_READY__
manifest complete; extend A's
end time to fit the size; build
B's commands (code + manifest)
launch env B ─────────────────────────────────────────────────────────▶ container_pre_commands:
                                                                          install croc
                                                                          monitored croc receive
                                                                          verify size+md5 vs manifest
                                                                          place / scp / tar-x on B
                                                                          md5 on B after scp
                                                                          __CROC_RX_DONE__ | __CROC_RX_FAILED__
tool returns both ids
─── from here on, only get_transfer_status / cancel_transfer ───
read both logs ◀───────────────── __CROC_DL_DONE__ ◀── croc ──▶ receiving
on A FAILED → end env B
on B FAILED → end env A
```

1. **B starts only after A's READY.** That keeps the sender-first guarantee from the
   download protocol (`could not secure channel` came from receivers hammering a
   half-registered room). The tool call does the gating. It doesn't use signal files,
   because nothing local is receiving.
2. **The manifest is baked into B's commands.** The SIZE/MD5 sentinels come out before
   `croc send` starts, and log order is preserved, so the manifest is complete when
   READY arrives. B checks every file's size **and** MD5 before placing it (the
   hole-riddled 2.3 GB VMDK lesson), then checks MD5 again on target B after the SCP.
3. **Directories are tarred on the sender side** (`ssh A 'tar cz -C dir .' > staged.tar.gz`)
   instead of `scp -r`'d. Today, download integrity covers regular files only (`[ -f ]`
   in the sentinel loop). Tarring gives directories the same MD5 protection. B then
   extracts them exactly as the upload path does (`is_dir_tar`).
4. **The sender's croc-send timeout has to cover B's startup.** Its clock starts before
   any receiver exists. The floor passed to `_generate_croc_send_core` becomes
   `300 + RELAY_RECEIVER_LAUNCH_BUDGET_SECONDS` (proposed: 600). The size-scaled part
   (`bytes / 1 MB/s + 120`) is unchanged. Waiting for a receiver prints no percentage
   lines, so the mid-stall detector won't fire. The existing 30 s heartbeat keeps A's
   log flowing. *As built:* if B never connects, A's croc send times out on its own,
   and `get_transfer_status` then reports the pair FAILED and ends B.
5. **The receiver needs its own stall monitor.** Today's upload receive
   (`generate_croc_receive_attempt`) has none, because the sender there is the caller.
   Here **both** legs go through `proxy.esl.cisco.com`, which is where the 25-minutes-
   at-87% freeze was seen. B's wrapper runs croc in the background and watches its
   progress:
   - **No progress below 100%.** Kill croc after `CROC_RECEIVE_MIDSTALL_CHECKS`. This
     is deliberately **longer** than the sender's ~120 s (proposed ~180 s), so the
     sender always moves first. Then retry **once**, after a delay longer than
     `CROC_SEND_RETRY_DELAY_SECONDS` (proposed 8 + 12 = 20 s). By that point the
     sender's single retry has already registered its new room. Ordering by time is
     what keeps "sender first" true without a back-channel into B.
   - **All manifest files complete with matching MD5.** Kill croc and count it as
     success, even if croc then hangs after 100%.
   - The existing rate-limit backoff loop stays inside each attempt.

   *As built* (`croc_manager`):

   | Constant | Value | Meaning |
   |---|---|---|
   | `CROC_RECEIVE_MIDSTALL_CHECKS` | 36 (~180 s) | no progress below 100% → kill and retry |
   | `CROC_RECEIVE_STALL_CHECKS` | 9 (~45 s) | unchanged at 100% → verify once; complete → stop croc |
   | `CROC_RECEIVE_RETRY_DELAY_SECONDS` | 8 + 12 = 20 | delay before the single general retry |
   | `RELAY_RECEIVER_LAUNCH_BUDGET_SECONDS` | 600 | added to the sender's 300 s croc-send floor |
   | `relay_receive_timeout()` | max(900, bytes / 1 MB/s + 600) | the receiver's croc timeout |

   Success is decided by the files (size + MD5 against the manifest), never by croc's
   exit code. The MD5 of a multi-GB file is only computed once its size matches. At a
   100% stall it is checked once, not every 5 s. A failure prints
   `ERROR: croc file receive failed ...` (the upload wording, so
   `extract_transfer_errors` finds it) and `__CROC_RX_FAILED__ exit_code=N reason=...`.
   A failed croc install on the receiver emits the same FAILED sentinel.
6. **Cross-cancellation.** Before B exists, a failure on A ends the tool call with A's
   error. After that, `get_transfer_status` ends env B when it sees A's FAILED sentinel
   (and the reverse), so neither side waits out its timeout. If nobody polls, each
   side still stops on its own size-scaled croc timeout. `cancel_transfer` ends both.
7. **The caller is only in the control path.** Once the call has returned, the transfer
   doesn't depend on the caller at all: no background task, no in-memory state. If the
   caller hibernates or the MCP server restarts **during** the call (before B is
   launched), B never starts, and A's croc send times out on its own.

## Async

Two dedicated tools (decided by DannyK 2026-11-03):

```jsonc
get_transfer_status({ "sender_environment_id": "...", "receiver_environment_id": "...",
                      "sender_profile": "...", "receiver_profile": "...",   // optional
                      "receiver_torque_space": "...",   // optional, only when the result names it
                      "wait": 10 })
cancel_transfer({ "sender_environment_id": "...", "receiver_environment_id": "...",
                  "sender_profile": "...", "receiver_profile": "..." })
// Both also take {sender,receiver}_torque_{space,url,token}; see "Location overrides per side".
```

**When the call returns.** Sender-first ordering means B can only be launched after
A's READY, so B's id doesn't exist at the moment A is launched. The transfer tool
therefore returns once B has been **created**, not right after A. That first phase is
fairly short even at 15.4 GB:
- install croc;
- SCP from target A to agent A's container (LAN speed);
- one MD5 pass;
- READY;
- create env B.

It is expected to take a few minutes. The long part, the croc leg itself, runs after
the call returns. A failure in the first phase (install, SCP, a missing source path)
is reported synchronously, as the call's result. DannyK accepted this blocking first
phase for v1 (2026-11-03). It may be iterated on later.

**Stateless polling.** Each status call has everything it needs: two ids, plus two
profiles for the two Torque connections. Nothing is kept in memory between calls,
there is no background orchestration task, and an MCP server restart loses nothing.
Each `get_transfer_status`:
1. Reads both environments' states and both grain logs, each with its own profile's
   client.
2. Parses A's sentinels (`__CROC_DL_DONE__` / `__CROC_DL_FAILED__`) and B's
   (`__CROC_RX_*`, progress lines), from the full log each time. *As built:* with
   stateless parsers (`remote_transfer.parse_sender_log` / `parse_receiver_log`), not
   `DownloadPlan.observe_output`. The latter is incremental and drives signal files;
   a full-log parse needs neither. "Ready" means the latest READY was not followed by
   a RETRY. A sentinel that follows `echo` on its line is a command being shown, and is
   ignored.
3. Reports RUNNING / COMPLETED / FAILED for the **pair**. The transfer is finished when
   B is, not A. The result shows the files placed, the latest progress line, and both
   environment URLs. *As built:*
   - COMPLETED needs B's DONE **and** B's environment to have finished. Until then it is
     RUNNING ("finishing"), so the pair is ended only once it is really done.
   - A log that could not be read this time never turns into FAILED.
   - The transfer time is only in the CLI, which knows when it started. A stateless
     status call does not.
4. Does the cross-cancellation: on one side's FAILED, it ends the other side's
   environment.
5. Ends both environments once the pair is terminal, as `get_execution_status` does for
   one.

**Profiles.** `sender_profile` / `receiver_profile` are optional and default to the
default profile. The transfer tool's result spells out the exact follow-up call, with
both ids and both profiles filled in, so the LLM never has to reconstruct it.

**Same-agent shortcut.** There is only one environment, so the result gives the same id
for both. `get_transfer_status` recognizes equal ids and reads one environment.

**Background log streaming to stderr** is not started for transfer environments
(*as built*). It would be cosmetic, since nothing depends on it.

*As built:* the tool call remembers both connections (`_async_env_connections`), so a
status call without profiles also works while the MCP server keeps running. After a
restart, the profiles named in the follow-up text are needed.

**Location overrides per side** (2026-11-11). An endpoint can name its own
`torque_space` / `torque_url` / `torque_token`, and its environment then lives there,
not where its profile points. On 2026-11-09 the receiver was started with
`torque_space: torque-tunnel` while its profile's space was `ipam-rollout-test`, and
`get_transfer_status`, called exactly as the result said (ids and profiles), answered
`environment not found`. Now:
- the remembered connection wins when the call names the same profile (or none), so
  the override holds in the server that started the transfer;
- the result names every value a side's profile would not give back:
  `receiver_torque_space="torque-tunnel"`, `receiver_torque_url="…"`, and for a token
  only `receiver_torque_token=<the torque_token you started it with>`, never its value;
- `get_transfer_status` and `cancel_transfer` take `sender_torque_space`,
  `sender_torque_url`, `sender_torque_token` and the same three for the receiver,
  which win over everything else;
- "not found" names the side, and the space and URL it looked in.

Those three are all that locate an environment. The agent, the SSH target and the
files only matter when an environment is launched. The `torque_agent` the endpoint
named is in its environment already.

**Which failure is the reason** (2026-11-11). When both sides failed, the sender's
failure is the cause: the receiver only joins the sender's room, so its error
(`room (secure channel) not ready, maybe peer disconnected`) is how the sender's
failure looks from the receiver. The reason reads
`sender: <the sender's error>; the receiver then failed too: <the receiver's>`, and the
log tail shown is the sender's (`Sender log (tail)`). Before, the receiver's error was
the reason and the sender's real one (`dial tcp …:9009: i/o timeout`) was only in its
raw log. A receiver that failed on its own is still reported as before.

**Both sides check the relay first** (see croc-file-transfer.md, *Relay reachability
check*). The sender checks before its croc install and before staging anything. A
relay it cannot reach ends the call at once:
`Transfer failed before any data was sent: the sender failed: the sending side (agent mgmt-168-7) cannot reach the croc relay croc.schollz.com:9009: connecting to … timed out after 6 s …`.
*Since the Piping Server transport* (piping-transport.md), a side that cannot reach
croc's relay uses the Piping Server instead. That failure now happens only when it can
reach neither: `… can reach no file transport: croc relay …: …; the Piping Server …: …`.
The receiver checks at the start of its job, so a receiving agent that cannot reach the
relay fails in seconds, with `the receiving side (agent …)` in the reason. It can still
only do that once it is launched, i.e. after the sender has staged and hashed. Checking
the receiver's agent earlier would need a separate environment started in parallel
with the sender. That is not built.

**READY now means a live relay connection** (croc-file-transfer.md, *READY means a live
relay connection*), so "the sender … is waiting for the receiver" is true when the call
says it.

### Prerequisite fix: `profile` on `get_execution_status` / `cancel_execution`

This is needed regardless of the new tool (DannyK 2026-11-03).

The background streamer and `get_execution_status` use `get_torque_client()` with **no
arguments**, which means the default profile's Torque URL/space/token. The async
handlers start their environment with the **call's** profile
(`get_torque_client(torque_url, ..., config=cfg)`). So an `_async` call whose profile
points at another Torque instance or space is polled on the wrong one today. For a
download that also means the gated receiver never sees READY.

Neither tool has a `profile` argument. `call_tool` strips `profile` from every call's
arguments and builds an `effective_config` from it, but these two handlers never
receive that config, so a `profile` sent anyway is silently ignored.

Fix:
- **Add `profile`** to both tool schemas, and pass `effective_config` to both handlers.
  They use it for the Torque client, the environment URL, and `auto_delete_environments`.
- **The background streamer** gets the starting call's config, because it is created
  by the async handler that has it.
- **Every message that tells the caller to poll or cancel includes `profile`** when the
  call used one. Today those messages only name `environment_id`:
  - the three async handlers' return texts ("Use `get_execution_status` with
    environment_id=...", "Use `cancel_execution` with the same environment_id");
  - the "Call `get_execution_status` again ..." line in the status result.
  The `_async` tool descriptions ("Use get_execution_status to poll ...") and the
  `environment_id` descriptions in both schemas say the same, and also name
  `profile`.
- **Tests:** a non-default-profile environment is polled and cancelled on its own
  Torque instance, and the follow-up text contains the profile.

*As built:*
- An explicit `profile` wins. Otherwise the remembered connection is used, then the
  default profile (an environment started before a restart).
- A remembered connection survives a hot reload of the default profile.
- It picks up the profile's current token when the URL and space are unchanged, since a
  re-login may have replaced the old token.

### What 15.4 GB means

| Item | Estimate / handling |
|---|---|
| croc leg | 3-12 MB/s observed relay rate → ~20-85 min. The send/receive timeouts scale at 1 MB/s → ~4.3 h ceiling. |
| SCP legs | target ↔ agent container on each side, LAN speed |
| MD5 | sender (once), receiver container (once), target B after SCP (once): ~1 min each |
| Disk | **15.4 GB free on both agent containers** for staging. Today's download and upload need the same. |
| Env lifetime | Environments are created with an 8 h lifetime. When the payload's receive timeout + 1 h exceeds 7 h, the call sets both environments' end (`set_scheduled_end_time`) to fit it. At 15.4 GB that's ~5.6 h, so it fits as is. |

## Same-agent shortcut

If both endpoints resolve to the **same Torque URL, space and agent**, one environment
copies directly, with no croc and no relay, and nothing staged on the container's disk:

```
set -o pipefail
ssh A 'cat /src' | ssh B 'cat > /dst.tt-partial'
md5 on A == md5 on B  ||  remove the partial and fail
ssh B 'mv -f /dst.tt-partial /dst'
```

Directories use `tar czf -` / `tar xzf -` (gzip's CRC protects them). The partial is
verified before the `mv`, so a broken stream never leaves a file at the destination
path. *As built:* both ends are hashed separately instead of `tee`-ing the stream into
`md5sum`, because waiting on a process substitution is unreliable. That costs one more
read of the source file.

- It runs in container pre-commands, a blueprint slot that isn't printed in the
  "decoded for visibility" dump. (The commands no longer carry either SSH key: since
  2026-11-06 the destination's arrives as the environment's own `ssh_private_key` /
  `ssh_password` input and the source's as `aux_ssh_private_key` / `aux_ssh_password`,
  all sensitive inputs read through `env-vars` - see
  [secrets-in-torque.md](secrets-in-torque.md). The same holds for the croc transfer's
  keys, codes and relay password.)
- *As built:* it runs in an environment targeting the **destination**, so it uses the
  destination profile's `init_commands`. Both sides are behind the same agent anyway.
- It reports with the receiver's sentinels, and a 30 s heartbeat keeps its log moving.
- It returns the same result format, with the same id for both environments. The
  start message says it is a direct copy, and the CLI's `--json` has
  `path: direct`.

## Relay resolution

The relay is resolved today **purely from configuration**, on the caller:
- The profile's `croc_relay` is used, or `DEFAULT_CROC_RELAY` (`croc.schollz.com:9009`)
  if it isn't set. The value is pinned into the generated commands (`DownloadPlan` /
  `FileDeploymentPlan` `croc_relay`).
- Resolving it involves no connection and no transfer. The only network step is the
  DNS warm-up, and that runs where croc runs, i.e. on the agent container.

So the new tool resolves it **the same way, without the caller sending or receiving
anything**:
- It reads each endpoint's profile.
- **Both profiles give the same relay** (the normal case, including both unset → the
  public relay): that relay is used on both sides.
- **The profiles disagree:** the **source** profile's relay is used. The sender
  registers the room there, and the receiver joins it. If agent B can't reach that
  relay, B's error says so through the existing `describe_croc_error` text.
- `croc_relay_password` comes with the chosen relay. `croc_transfers` stays per side.

Existing bug, fixed on the way: `_croc_relay_settings()` reads the global `_config`
(the default profile), not the per-call `effective_config`. So a per-call `profile`
with its own `croc_relay` is ignored by today's uploads and downloads. The new tool
needs per-profile resolution anyway, so `_croc_relay_settings(cfg)` takes the effective
config and the existing handlers pass theirs.

## Reuse map

| Need | Existing code | Change |
|---|---|---|
*As built:*

| Need | Existing code reused | New |
|---|---|---|
| Sender stage + send | `_generate_croc_send_core` (unchanged) | `generate_croc_relay_send_commands`: ssh-pipe staging, `__CROC_DL_DIR__`, larger floor |
| Parsing the logs | – | `remote_transfer.parse_sender_log` / `parse_receiver_log` (stateless) |
| Croc install | `generate_remote_croc_install_script(failure_sentinel=...)` | – |
| Receiver | `generate_dns_warmup`, `_relay_env_export`, `_LAST_CROC_ERROR_SH` | `generate_croc_relay_receive_commands` (monitor, verify, place); upload code untouched |
| Relay | `effective_relay`, `_croc_relay_settings(cfg)` (now per call) | `remote_transfer.choose_relay` |
| Error text | `describe_croc_error`, `extract_transfer_errors` (same wording) | `remote_transfer.describe_failure` |
| Status / cancel | `_connection` / `_async_connection` (the profile fix) | `get_transfer_status`, `cancel_transfer`, `remote_transfer.evaluate_pair` |
| Env launch / end | `start_environment`, `end_environment`, `release_environment`, `set_scheduled_end_time` | `_terminate_environment` |
| Persistent container endpoint | `get_persistent_container_info` | `_attach_persistent_container` (never creates one) |

No local croc binary is involved (`ensure_local_croc` is not called).

## CLI

```
torque-tunnel transfer \
  --from-profile cisco-jarvis --from-host 10.91.36.240 --from-user root --from-key KEY \
  --to-profile laptop-local  --to-persistent-container ENV_ID \
  --file /data/image.vmdk:/vmfs/tmp/image.vmdk[:MODE] --file ...
```

The CLI runs the same orchestration in the foreground until both environments finish.
The exit code is non-zero unless every file was placed and verified. `--json` carries
per-file results, `path` (`croc` / `direct`) and `transfer_seconds`.

## Tests

*As built:*

| File | What it covers |
|---|---|
| `tests/test_async_status_profile.py` | the profile fix for status/cancel/streaming, and the follow-up messages |
| `tests/test_croc_relay_per_profile.py` | the relay from a per-call profile, all six run tools, both directions |
| `tests/test_remote_transfer_commands.py` | sender, receiver and direct copy run under WSL bash, with an ssh shim and a fake croc |
| `tests/test_remote_transfer_tool.py` | orchestration, status, cancel, CLI and parsing, against a fake Torque with scripted logs |
| `tests/test_argument_resolution.py` | every value at every level, for the six run_* tools and both transfer endpoints (see *Endpoint resolution*) |

The plan was:

- **Bash harness with fake croc** (as in `test_download_race_fix.py`):
  - Receiver monitor: stall kill and the single delayed retry.
  - Success-by-manifest even when croc hangs.
  - MD5 mismatch is rejected and never placed.
  - Directory tar round-trip.
  - Post-SCP MD5 check.
  - Same-agent pipe: an MD5 mismatch leaves no file at the destination.
- **Orchestrator with a fake TorqueClient:**
  - B is not launched before READY.
  - B's commands carry the full manifest.
  - A's FAILED ends B, and B's FAILED ends A.
  - RETRY followed by READY before B launched.
  - Timeout when B never starts.
  - Per-endpoint profile and relay resolution.
  - The same-agent path is chosen only when url+space+agent all match.
  - Same-host refusal.
- **Status / cancel:**
  - The tool returns only after B is created, with both ids. A first-phase failure is
    returned synchronously.
  - `get_transfer_status` stays RUNNING while B runs, after A finished.
  - It works with no in-memory state (simulating a restart).
  - It ends B on A's FAILED, and the reverse.
  - Equal ids (the shortcut) read one environment.
  - Each side is read with its own profile.
  - `cancel_transfer` ends both, and tolerates one already being gone.
  - The returned follow-up text carries both ids and both profiles.
- **Prerequisite fixes:**
  - `get_execution_status` / `cancel_execution` with `profile` hit that profile's Torque
    instance.
  - The follow-up messages include the profile.
  - `_croc_relay_settings` honors a per-call profile.
- **Live:** .240 ↔ .180 (two Torque instances), and a 15.4 GB file. *As built:* with a
  100 MB file for now (DannyK), run once rather than repeatedly because of the public
  relay's rate limit. Results below.

## Live results (2026-11-03)

**croc path:** .240 (profile `cisco-jarvis`, jarvis Torque) → .180 (profile
`localhost-torque-tunnel-dannyk-torque-dev-mgmt-server-in-cisco`, local Torque), through
the public relay. The payload was a 100 MB random file (mode 600) plus a directory
holding a file whose name has a space.

- **Result:** COMPLETED in 437 s. Identical MD5 on .180, mode 600, the directory intact,
  no `.tt-partial` left.
- **The stall recovery was exercised for real.** The transfer froze mid-flight at
  17:04:58 (sender 38%, receiver 16%):

  | Time | Side | What happened |
  |---|---|---|
  | 17:06:58 | sender | The stall detector killed croc (~120 s) and emitted RETRY. |
  | 17:06:59 | receiver | croc exited when its peer went away. The size-correct partial file was rejected as corrupt by MD5 ("...is corrupt (md5 a7252a31..., expected c3ebfe8a...)"). It waited the 20 s retry delay. |
  | 17:07:08 | sender | Re-registered: READY. |
  | ~17:07:20 | receiver | Joined the new room. croc resumed from 17% rather than 0%. |
  | 17:08:23 | receiver | Both files verified and placed: DONE. |

  The ordering held: the sender moved first, and the receiver never joined before
  the room existed.
- **Throughput** through the public relay was poor: 69 kB/s to 3.6 MB/s.

**Across two unconnected networks:** .240 in Chicago (profile `cisco-jarvis`) →
`cisco@host.docker.internal` (profile
`jarvis-ai-studio-to-mgmt2-jumper-dannyk-docker-agent`, a separate lab network; the
host is a WSL machine at 172.22.83.6, behind NAT). Before the transfer, both directions
were checked and are unreachable: TCP/22 and ping, .240 → 172.22.83.6 and
jumper → 10.91.36.240.

- **Result:** COMPLETED in 131 s, the croc leg ~50 s at up to 4.5 MB/s. The 100 MB file
  arrived with an identical MD5 and mode 600, and the directory (with a space in a file
  name) arrived intact.
- The destination used password auth (`sshpass -e`), the source key auth.
- **First attempt:** the jarvis runner was in an error state ("operation
  shell-grain-deploy failed since runner is in error state"). The sender's grain never
  ran and its log was empty. The tool reported only that it "ended before its croc
  sender was ready". **Fixed:** `_environment_errors()` now adds Torque's own
  `state.errors` to that message, and to `get_transfer_status`'s FAILED reason. Tests
  were written first. The retry succeeded.

**Direct path:** .240 → .180, both through `cisco-jarvis` (agent
`intersight-provisioning-agent`), with the same payload. One environment, no croc.
COMPLETED in 37 s (environment start included), identical MD5, directory intact.
