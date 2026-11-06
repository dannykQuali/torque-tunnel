# Keeping secrets out of Torque

## The problem

Two things Torque does make anything written into a grain readable to everyone who can
read the space, and keep it there:

- **The runner echoes the whole rendered script into the grain log** before running it
  (`Executing command: ...`). Blueprint inputs are templated into that script as text.
- **Inputs not marked `sensitive: true` are shown as-is** in the environment's inputs
  (UI and API). Base64 or gzip changes nothing there: anyone can decode them.

Before this change, the SSH key was templated into `remote-shell-executor`'s script
twice (and a password once), and the generated upload/download/transfer commands -
carried by ordinary inputs such as `container_pre_commands_b64` - held the target's key,
a second machine's key or password, the croc codes and the croc relay password.
Torque has no log masking, so all of it stayed in the environment's log and inputs.

## The rule

Every secret torque-tunnel hands to an environment travels **only** as a
`sensitive: true` input that the grain's `env-vars` turns into an environment variable.
Nothing secret is ever written into a script or into an ordinary input; scripts and
generated commands only name the variable.

Verified against jarvis (2026-11-06, Docker agent):

- A sensitive input passed through `env-vars` reaches the script **byte for byte** -
  multi-line, LF or CRLF line endings, trailing newline included - with the value
  quoted as `'{{ .inputs.x }}'`.
- The value appears nowhere in the grain log (the echo shows `"$TT_..."`) and the API
  returns the input as `null`.
- It works together with a credential's `authentication:` block.

Not verified: the K8s agent (its test cluster was down). `env-vars` is a generic grain
feature, so it is expected to behave the same.

## The variables

| Variable | Blueprint input | Used by |
|----------|-----------------|---------|
| `TT_SSH_PRIVATE_KEY` / `TT_SSH_PASSWORD` | `ssh_private_key` / `ssh_password` | the SSH step; uploads and downloads to the target; a transfer's sender (source) and receiver (destination); a direct copy's destination |
| `TT_AUX_SSH_PRIVATE_KEY` / `TT_AUX_SSH_PASSWORD` | `aux_ssh_private_key` / `aux_ssh_password` | a direct copy's source (the environment targets the destination) |
| `TT_CROC_RECEIVE_CODE` | `croc_receive_code` | croc receive on the agent: uploads, a transfer's receiver |
| `TT_CROC_SEND_CODE` | `croc_send_code` | croc send on the agent: downloads, a transfer's sender |
| `TT_CROC_RELAY_PASSWORD` | `croc_relay_password` | every croc on the agent (exported as `CROC_PASS` only when set) |

`remote-shell-executor` has all seven, `local-shell-executor` (disposable containers) the
three croc ones. Every input is always sent, empty when unused (`_secret_inputs` in
`torque_client.py`). The names are part of the blueprints' contract with the
generators: `croc_manager.*_ENV`.

How the scripts use them:

- **Key:** written to a temp file with `printf '%s'`, plus a final newline if the key
  has none (ssh rejects some formats without it; the old heredoc always added one),
  `chmod 600`, removed afterwards.
- **Password:** `SSHPASS="$TT_..." sshpass -e ...` - from the environment, so it is not
  in the process list either (it used to be `sshpass -p '<password>'`).
- **Which method:** decided when the script runs - the key if the variable is set, else
  the password, else an error (`croc_manager._ssh_auth`). The generators no longer take
  any secret, so they cannot embed one.
- **croc:** `CROC_SECRET="$TT_CROC_..._CODE"`, `CROC_PASS` from `TT_CROC_RELAY_PASSWORD`.

The target never sees these variables: the remote script forwards only an attached
credential's variables and `MGMT_SERVER_*`.

## Masking, as a backstop

Nothing torque-tunnel generates prints these values, but a command could (`env`,
`cat` of the key file). The blueprints' redactor - originally only for an attached
credential's secrets - now also masks torque-tunnel's own (`__TT_OWN_SECRETS`), and
covers the setup (container pre-commands) and download output as well as the command
output. A multi-line value is masked line by line, as output shows it; a key's
`-----BEGIN/END-----` armour is not secret and stays readable. Values shorter than 8
characters are left alone, as for credentials.

Because it now runs on every command, the redactor streams chunk by chunk instead of
line by line: everything up to the last `\n` or `\r` goes out at once, the rest after
0.2 s - minus a tail that could be the start of a secret still arriving. croc's progress
bars (redrawn with `\r`) and prompts without a newline therefore still stream live.
It needs `python3` on the runner (present on the jarvis Docker runner); without it the
output passes through unmasked.

## What did not change

- **The persistent container's own key** is still printed into *its* environment's log
  (`TORQUE_TUNNEL::KEY_START`), by design: later clients read it from there to connect.
  Commands run on the container no longer add copies of it to their own logs.
- **Environments created before this change** keep their logs and inputs; only deleting
  them removes those copies.
- **Secrets a user writes into their own command text** cannot be recognized. Torque
  credentials (`credential` argument) are the way to pass those.

## Code and tests

- Blueprints: `blueprints/remote-shell-executor.yaml`, `blueprints/local-shell-executor.yaml`.
- Generators: `croc_manager.py` (`*_ENV`, `_ssh_auth`, `_ssh_function`, `_relay_env_export`).
- Inputs: `torque_client._secret_inputs`; `mcp_tool._croc_secrets` collects a run's croc
  secrets from its upload/download plans.
- `tests/test_secrets_stay_out_of_torque.py`: the blueprint contract; the create payload
  of every tool path (all run tools, transfer, direct copy) rendered the way Torque
  renders it, checked for every secret in the echoed script, the blueprint and every
  ordinary input; the rendered script run under WSL with the variables set; the
  redactor's masking and streaming.

Live check (2026-11-06, jarvis): an SSH run with croc upload and download, a disposable
container with an upload, a persistent-container command, a direct copy (.240 → .180)
and a croc transfer across two isolated networks (.240 → the jumper host, password
auth) all worked, and none of their environments held a key line, a password or a croc
code in the log, the inputs or the API response.
