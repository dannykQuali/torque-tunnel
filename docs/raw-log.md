# Raw Torque logs (`--raw-log`)

## Why this exists

Torque's shell runner echoes the whole rendered grain script into the grain log before
running it (`Executing command: ...`). The blueprints template their inputs into that
script, so the echo contains every input in plain text — `remote-shell-executor` writes
`{{ .inputs.ssh_private_key }}` into it twice. Torque has no log masking.

torque-tunnel used to return that echo to the caller whenever the
`=== Beginning of execution ===` marker was not yet in the log, as a troubleshooting
fallback. The marker is printed only after the container pre-commands (croc uploads,
SCP to the target) finish, so polling `get_execution_status` while a job was still
uploading returned the script — and the key. On 2026-11-06 a worktogether orchestrator
that polled its test jobs that way collected two SSH keys across eight jobs.

## The three parts of a grain log

| Part | What it is | Starts at |
|------|------------|-----------|
| 1. Script echo (the raw log) | Torque's echo of the rendered script, every input included | the top of the log |
| 2. Setup output | `remote-shell-executor`'s container pre-commands: croc uploads, the transfer tool's whole work (it runs with `command="true"`), their errors | `=== Running container pre-commands ===`, up to the decoded-commands dump |
| 3. Command output | The command's own output | after `=== Beginning of (local )execution ===` |

The decoded-commands dump (`=== Commands (decoded for visibility) ===`) between parts 2
and 3 shows the decoded command text, which can hold secrets of its own (the transfer
tool writes keys into its commands), so it is treated as part of the raw log.

What the setup output can contain (checked 2026-11-06 against the generators in
`croc_manager.py` and 29 real upload logs, none of which contained its own croc code,
relay password or a key):

- upload receive (`generate_croc_receive_attempt`): croc receive's own output, passed
  through unfiltered — `connecting...`, `securing channel...`, `Receiving ...`, progress
  bars, croc's error lines. croc receive takes the code from `CROC_SECRET` and does not
  print it; that is the one thing this part relies on croc for. Our `ERROR:` line quotes
  croc's last line through a filter that drops code-bearing lines;
- croc install: our `ERROR:` line with curl's last error and the proxy, credentials masked;
- transfer receiver (`generate_croc_relay_receive_commands`): only croc's progress lines
  (`[croc receive] ...%...`), our status lines and sentinels (file names, sizes, MD5s);
- direct copy: our `[direct copy] ...` lines and ssh's errors;
- ssh/scp errors (`-o LogLevel=ERROR`): connection and auth failures, never key content;
- anything the profile's `init_commands` print themselves (they are sourced first).

The transfer sender is not here: it runs in the download slot, after the marker, and
strips croc's code lines itself (`_generate_croc_send_core`).

The part markers are matched as whole lines. In the echoed source the same texts sit
inside `echo "..."`, so the echo can never be mistaken for output.

## Modes

| Mode | Marker present | Marker missing (still in setup, or cancelled / failed / timed out there) | Streaming (MCP log notifications, stderr, CLI) |
|------|----------------|------------------------------------|-----------|
| `off` (default) | part 3 | part 2 only; if there is none yet, a note saying so and how to see the raw log | part 3 |
| `fallback` | part 3 | the whole log — the behavior before this flag existed | part 3 |
| `always` | the whole log | the whole log | the whole log |

In `off` mode, the setup output keeps transfer and upload failures diagnosable (for
example `ssh: connect to host ... No route to host` from a transfer sender), and the
Environment link in every result opens Torque's full log in its UI.

## Setting it

Only as a command-line flag, for the MCP server (in its `args` in the client's MCP
config) or for a CLI command:

```bash
python -m torque_tunnel.mcp_tool --raw-log fallback
```

```bash
torque-tunnel --raw-log always ssh "uname -a"
```

Deliberately not from the config file, a profile, an environment variable or a tool
argument: nothing a caller of the tools or a shared config file controls can turn raw
logs on. The flag replaces `verbose` (config key and `--verbose`/`-v`), which no longer
exist; a config file still holding `verbose` gets a warning and the key is ignored.

## Code

`src/torque_tunnel/raw_log.py` holds the mode and the one function that decides what of a
log may be returned (`command_output`). Everything that turns a grain log into output goes
through it: `filter_grain_log` and `format_log_section` in `mcp_tool.py` (every tool
result that shows a log), the three log streamers (`stream_preamble`), and the timeout
path of `TorqueClient.wait_for_environment`. Tests: `tests/test_raw_log_modes.py`.

## Not covered here

The key still sits in the Torque log itself (visible in Torque's UI to anyone in the
space) and in `container_pre_commands_b64`, an input not marked sensitive. Keeping
secrets out of the rendered script is a separate change.
