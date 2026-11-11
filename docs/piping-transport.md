# Piping Server transport: file transfers where croc's relay is blocked

Decided 2026-11-11 (DannyK): no relay of our own (docs/croc-relays.md). Where croc's
relay ports (TCP 9009-9013) are blocked, as on agent `mgmt-168-7`, uploads, downloads
and remote-to-remote transfers go through a public **Piping Server** over plain HTTPS
on 443. The default is `https://ppng.io`
([nwtgck/piping-server](https://github.com/nwtgck/piping-server)).

It applies to every tool that moves files:
- the six run tools (`upload_files` / `download_files`, blocking and async);
- the CLI's `--upload` / `--download`;
- `transfer_files_between_tunneled_hosts_async`;
- `get_execution_status` / `get_transfer_status`, which finish async ones;
- the cancel tools, which stop them.

## What a Piping Server does

- **Sender:** `PUT` (or `curl -T`) a stream to any path, e.g. `https://ppng.io/<path>`.
- **Receiver:** `GET` the same path. Whichever arrives first waits for the other; the
  server streams the bytes across and stores nothing.
- **Progress lines** go to the sender: `[INFO] Waiting for 1 receiver(s)...` at once,
  then `[INFO] All receiver(s) was/were received successfully.` at the end.
- **Waiting:** a sender waited 150 s for its receiver without trouble (measured
  2026-11-11).

**Speed is per connection.** Measured 2026-11-11:
- from the laptop: one stream 1.2 MB/s; four parallel streams 3.1 MB/s together;
- from agents `mgmt-168-7` and `cpoc-rtp-dev`: one stream 0.29 / 0.38 MB/s.

So data moves as **numbered chunks over parallel streams** (like croc's several data
ports).

## Choosing the transport: the sender offers, the receiver chooses

Each side checks what it can reach, before anything expensive:
- **croc:** the relay check (croc-file-transfer.md);
- **piping:** `GET <server>/version`, bounded by the same 6 s.

1. The **sender** offers every transport it can reach and says so in its log before
   READY: `__TT_OFFER__ croc piping` (or one of them). It serves each offer at once.
   croc registers its room. For piping, the sender builds the encrypted archive and
   gives its size and sha256 through Torque, then `PUT`s a constant *hello* that waits
   for a receiver. The archive is built even if the receiver then takes croc: the
   reference has to exist before the receiver starts.
2. The **receiver** takes croc if it was offered and the receiver reaches the relay,
   else piping if it was offered and reachable. Otherwise it fails at once, naming
   both causes.
3. When a piping receiver collects the hello, the sender knows piping was chosen. It
   stops croc (not a failure) and sends the data over piping. When croc completes
   instead, the waiting hello is abandoned.

Who is the sender:

| Tool | Sender | Receiver | Who decides |
|---|---|---|---|
| upload | this machine (Python) | agent container (bash) | the agent |
| download | agent container (bash) | this machine (Python) | this machine |
| transfer | agent A (bash) | agent B (bash), started after A's READY | agent B |

A sender that reaches neither transport fails at once, with both causes.

## The data stream

The unit is the **staging directory**, the same one croc sends. Its entries are files,
directories, or a transfer's `tar.gz` of a source directory.

### The key and the paths

Both come from the transfer's code (`croc_manager.generate_croc_code`):
`secrets.token_urlsafe(256)`, i.e. 2048 random bits in 342 characters, delivered to each
agent only as a sensitive input (an environment variable Torque keeps out of its log and
API). `piping.split_code` splits it by position into two disjoint random parts:
- **the key**: the first 309 characters, about 1854 bits. It encrypts.
- **the path token**: the 32 characters before the last one, 192 bits. It names the
  paths, `tt-<token>-hello` and `tt-<token>-<i>`.

The token is independent random data, not derived from the key, so the paths the server
sees reveal nothing about it. croc uses the whole code, unchanged. A code too short to
hold both is refused rather than replaced with anything derived from the key.

### What crosses the Piping Server, and what does not (DannyK, 2026-11-11)

| Crosses the Piping Server | Never crosses it |
|---|---|
| `tt-<token>-hello`: the constant line `hello` | the key, or anything derived from it |
| `tt-<token>-<i>`: ciphertext chunks (OpenSSL's `Salted__` header and an 8-byte random salt, then AES output) | any hash: the archive's sha256 goes **through Torque** |
| | the archive's size (also through Torque) |

How each receiver gets the sender's size and sha256, through Torque:

| Tool | How |
|---|---|
| download | the agent's log line `__TT_PP_ARCHIVE__ <bytes> <sha256>`, streamed to this machine |
| transfer | the same line in the sender's log, which the tool writes into the receiver's commands |
| upload | written into the agent's commands, from the archive this machine built while preparing |

Sending:
1. **Build the archive before offering it.** That is what lets the size and sha256 go
   through Torque before the receiver starts:
   - `archive = tar -C <staging> -cf - . | gzip -1`. This keeps directories, empty files
     and symlinks. `gzip -1` is fast (~100 MB/s), far above these links' speeds; the
     agents have no `zstd` or `pigz`.
   - `sha256` of `archive` (the plaintext), computed while it is written.
   - `cipher = openssl enc -aes-256-ctr -pbkdf2 -iter 100000 -pass env:<key>` of
     `archive`, written to a file. This is OpenSSL's salted format with
     PBKDF2-HMAC-SHA256 and a random 8-byte salt; Python reproduces it with
     `cryptography`. The key already has 1854 random bits, so the 100000 rounds are
     defence in depth.
2. Print `__TT_PP_ARCHIVE__ <cipher bytes> <sha256>` (agents) or pass both into the
   agent's commands (this machine).
3. `PUT` the hello, which waits for a receiver.
4. Once it is collected, send the 16 MiB chunks, 8 at a time.

Receiving:
1. Collect the hello. The number of chunks follows from the size given through Torque
   (a fixed 16 MiB each).
2. Fetch the chunks with the same parallelism, into one file at their offsets, and
   check each chunk's length.
3. Decrypt, compute the sha256 of the plaintext, `gunzip`, `tar -x` into the receive
   directory.
4. Compare that sha256 with the sender's from Torque. A mismatch, or a `gzip` or `tar`
   error, fails the transfer before anything is placed.

After that, everything is as with croc: the size and MD5 manifest of each file, then
placing the files.

Integrity and secrecy:
- **The server sees only the constant hello and ciphertext.** Tests assert this on
  every relayed body: `tests/test_piping.py` and `tests/test_piping_transport.py`, via
  the fake server's log.
- **Tampering is caught.** The reference sha256 is of the *plaintext* and comes by a
  different channel (Torque). Someone who controls the Piping Server has no key, so
  cannot produce ciphertext that decrypts to plaintext with that hash. Changed bytes
  also fail gzip's CRC.
- **Retries:** each chunk is retried (`PIPING_CHUNK_RETRIES`, 3) by both sides on the
  same path.

## Settings

- `piping_server` (profile/config): default `https://ppng.io`. A transfer's two sides
  use the source side's value.
- `file_transport` (profile/config): `auto` (default), `croc` or `piping`. Each side may
  only offer, or choose, what its own setting allows.
- No `piping_relay_password`: the code is the secret.

## Where it is built

| Piece | Code |
|---|---|
| This machine's side (encryption in OpenSSL's format, archive, chunks, the server check) | `torque_tunnel/piping.py` |
| The agent side (`__tt_pp_check`, `__tt_pp_send`, `__tt_pp_recv`) | `croc_manager.generate_piping_functions` |
| What a side offers or chooses, before the croc install and any staging | `croc_manager.generate_transport_step` |
| The sender serving both offers; croc is stopped when piping is taken | `croc_manager._generate_croc_send_core` |
| The three agent receivers branching on the choice | `croc_manager._receive_with_transport`, `generate_croc_relay_receive_commands` |
| Uploads: this machine's offers (decided before staging), the background offer | `mcp_tool.prepare_files_with_croc`, `execute_with_croc` |
| Downloads: this machine's choice from the agent's offer, the receive | `mcp_tool.DownloadPlan._choose_transport`, `complete_download` |
| Transfers: the receiver made from the sender's offers | `mcp_tool._start_croc_transfer`, `remote_transfer.parse_sender_log` |
| Withdrawing an offer or a receive (cleanup, cancel, async status) | `mcp_tool._withdraw_piping`, `cleanup_croc_resources`, `cleanup_download_resources` |

Tests: `tests/test_piping.py` (this machine's side, the OpenSSL format against the real
tools both ways) and `tests/test_piping_transport.py` (the agent scripts end to end).
Both run against `tests/_fake_piping_server.py`. Every other test sees the Piping Server
as unreachable (`tests/conftest.py`), so they keep testing croc.

## Verified live (2026-11-11, through https://ppng.io)

Agent `mgmt-168-7` drops croc's ports, so each case below went through the Piping
Server.

| Case | What moved | Result |
|---|---|---|
| upload to `mgmt-168-7` | 2 MB file + a folder (400 KB file, text file) | the agent chose piping (`__TT_TRANSPORT__ piping`); MD5s on the agent match this machine's; 38 s for the whole call |
| download from `mgmt-168-7` | 2 MB file + a folder with an inner symlink | the agent offered only piping; the downloaded file has the agent's MD5; the link arrived as a link; 44 s |
| transfer `mgmt-168-7` → `cpoc-rtp-dev` (persistent containers; the 2026-11-09 failure's path) | 3 MB file + a folder with an inner symlink | sender offered only piping; archive sha256 verified; both placed; MD5s and the link identical at the destination; 1 m 7 s |

Repeated for all three after the change that keeps the key, its hashes, and the
archive's size and sha256 off the Piping Server:
- **upload:** the agent got its reference in its commands; MD5s match.
- **download:** the reference arrived in the agent's log line
  `__TT_PP_ARCHIVE__ 2000810 9eea6d56…`; the MD5 matches; the link was kept.
- **transfer** from `mgmt-168-7` to `cpoc-rtp-dev`: 3 MB, an empty file, an inner
  link; byte-identical; 1 m 1 s.

Each receiver printed `archive verified (its sha256 matches the one the sender gave
through Torque)`.

## Limits and caveats

- **`ppng.io` is one free server run by its author.** It has no terms and no service
  level. Automation is its intended use (its README lists it as a public server; its
  help page shows only `curl` pipelines). It is the fallback, used only when croc's
  relay is unreachable.
- **Slow:** at the agents' measured 0.3-0.4 MB/s per stream, 8 streams give a few MB/s
  at best. A multi-GB file takes tens of minutes.
- **Disk:** the sender writes the encrypted archive next to the staging directory, and
  the receiver writes it before extracting, so each side needs about twice the payload.
