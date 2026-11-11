# croc relays: what exists, and what works through a corporate firewall

Research of 2026-11-11, after the 2026-11-09 transfer failure (see croc-file-transfer.md,
*Relay reachability check*): agent `mgmt-168-7` cannot reach any croc relay because its
network drops TCP 9009-9013. This page answers two questions: are there relays besides
the default, and is there one on a port such networks let out (80, 443, 8080)?
**Nothing here is implemented.** It is the input for that decision.

## Public relays

There is no maintained index of third-party relays (web searches turned up none; croc's
README only covers the official ones and self-hosting). The official ones are croc v11's
public **pool**, hard-coded in croc `src/publicrelay/publicrelay.go`:

| Relay | IPv4 (2026-11-11) | croc ping on 9009-9013 | 443 | 80 |
|---|---|---|---|---|
| `1.getcroc.com:9009` (= `croc.schollz.com`, `getcroc.com`) | 142.132.189.179 | pong on all five | a web server, not croc | open, no croc answer |
| `2.getcroc.com:9009` | 5.78.134.116 | pong on all five | web server | no croc answer |
| `3.getcroc.com:9009` | 165.227.90.189 | pong on all five | web server | no croc answer |
| `4.getcroc.com:9009` | 46.225.4.16 | pong on all five | web server | no croc answer |

Measured from the laptop with `croc_manager._relay_ping_once` (a croc ping costs nothing
against the relays' rate limit; see croc-file-transfer.md). `croc6.schollz.com` has no
DNS record.

How croc v11 uses the pool (README *Custom Code Phrase*): for the default public relay,
SHA-256 of the code modulo the pool size picks the relay, so both peers land on the same
one without talking. A sender with a generated code races a ping to every relay and
picks a code that maps to the first relay that answers, and caches that choice in a
`best-relay` file. `--relay` / `CROC_RELAY` bypass all of this. torque-tunnel always
passes `--relay` and pins croc **v10.4.2**, which has no pool, so it always uses
`croc.schollz.com:9009` only.

**What the pool would buy.** Four independent hosts (four IPs, at least three
providers). That means:
- **a quarter of the rate-limit pressure:** the ~30 joins/IP/minute limit is per relay;
- **no single point of failure:** an outage of `croc.schollz.com` stops every torque-tunnel transfer today.

**What it would not buy:** a way past a port block. All four relays listen on 9009-9013
only.

### Community and third-party relays (searched 2026-11-11)

Searched: croc's GitHub issues (#270, #441 "Public Relay List", #585 "Contributing public
relays", #931, #1040, #1269 "croc needs your help", #1425), a third-party app's tracker
(bakirgdev/CrocApp #166), GitHub code search for `CROC_RELAY=`, `croc --relay`,
`croc relay --ports` and croc together with `:443`/`:80`, and web search. Reddit could not be searched from here:
both its API and the search tool refuse automated clients. Findings:

- **No community relay list exists.** It has been requested since 2021 (#441, #585) and
  was never built as a list. Instead croc v11 (2026-08) hard-coded the four relays above.
  In #1269 the maintainer says he runs **all four**, they carry over 40 TB/month for
  about 400,000 users, and he asks volunteers to add relays by PR to
  `src/publicrelay/publicrelay.go`. None has been added yet. CrocApp's author is
  considering one (CrocApp #166).
- **Every relay address found, pinged** with croc's ping (free) on 9009-9017, 443, 80,
  8080, 8443 and 8153:

  | Address | Source | Result |
  |---|---|---|
  | `1-4.getcroc.com` | croc's pool | croc on **9009-9017** (all nine); 443 a web server, 80 silent, 8080/8443 closed |
  | `data-relay.qim.dk:9009` | qim-center/qim-data-croc (DTU QIM, Denmark) | no croc answer from outside on any port (9009+ time out); 443/80 are a web front end |
  | `croc.service.0xfab1.net:9009` | a personal site's notes | no longer resolves |
  | `142.93.177.120:9009` | croc's old default (issue #270, 2020) | dead |
  | `croc3.schollz.com`, `198.199.67.130:8153` | croc v1-v3 era defaults | no DNS / dead |
  | `100.104.42.96:9009` | a personal dotfile | a Tailscale-private address, unreachable by design |

  The rest were placeholders (`1.2.3.4`, `myrelay.example.com`) or localhost.
- **Nobody runs a public croc relay on a standard port.** The closest thing is QIM's
  design (`qim-data-croc/docs/server-mux-strategy.md`). They call 443 "the single
  outbound port that is universally allowed", so they carry croc's two ports over
  **one WebSocket to `https://data-relay.qim.dk/relay` on 443**:
  - nginx passes `/relay` to their small `qim-mux`, which opens the two TCP
    connections to the local `croc relay --ports 9009,9010`;
  - their client runs croc against `--relay localhost:9009`, with no changes to croc
    or the relay.

  It serves only their own users, through their `qim-data` client. It is a proven
  pattern for a torque-tunnel relay of our own, and better than raw croc on 443 where a
  firewall inspects TLS: the traffic is real HTTPS/WebSocket.

## Relays on standard ports

None of the public relays works on 80, 443 or 8080. The options for a network like the
Quali lab's:

1. **Self-host a relay on allowed ports.** `croc relay --ports 443,8080` (or `80,443`).
   The first port is the control port and the rest are data ports, and croc requires
   at least two. With one data port croc transfers over a single stream, which is
   slower over high-latency paths but works. Run it with a password (`CROC_PASS`) on a
   host both sides can reach, and point the profiles at it (`croc_relay:
   relay.example.com:443`, `croc_relay_password`). From `mgmt-168-7`, 80, 443 and 8080
   connect directly (probe of 2026-11-11). **Untested caveat:** some firewalls inspect
   443 and drop anything that is not TLS (a Splunk lab firewall did that in October).
   The relay check now tells that case apart: `… answered, but not as a croc relay` or
   `no croc answer came within 6 s`, instead of a timeout.
2. **Through the corporate HTTP proxy.** croc honours `HTTP_PROXY` (CONNECT), and the
   check does too. Many proxies allow CONNECT to 443 only (Squid's default
   `SSL_ports`). A relay's data ports have to differ from its control port, so "443
   only" is not enough for croc. You need a proxy that allows a second port as well.
3. **croc v11's DERP data transport** (`--transport auto|derp`). After the PAKE
   handshake, file data can go over Tailscale's DERP servers (HTTPS, 443) instead of
   the relay's data ports. The handshake itself still goes through the relay's
   control port (9009), so this does not help where 9009 is blocked. It would also
   mean moving both sides to croc v11.
4. **getcroc.com's WebSocket bridge** (`croc-web`, `wss://getcroc.com/ws` on 443). It
   bridges browsers to the public pool. The CLI does not use it, so it is not an
   option for torque-tunnel without a WebSocket-to-TCP shim on every agent.
5. **Another transport when croc cannot connect.** The failure report used an S3
   bucket with presigned URLs (443 both ways; 8.8 MiB/s up, 62.7 MiB/s down). It needs
   no live rendezvous, but it does need cloud credentials and a bucket.

## Decision (DannyK, 2026-11-11)

**We do not run a relay of our own, for now:** neither a croc relay on standard ports
nor a WebSocket bridge. So a network that blocks outgoing TCP 9009-9013 (like
`mgmt-168-7`'s) cannot use croc. Instead, uploads, downloads and transfers there fall
back to a public **Piping Server** over HTTPS on 443 (DannyK, 2026-11-11: "Let's go").
It is encrypted, compressed and checked with sha256. See piping-transport.md, which also
has the live results. The options below are kept for when this is revisited.

## Without a relay of our own: public HTTPS services (researched 2026-11-11)

DannyK suggested send-anywhere (a website on standard ports), but its terms do not
allow automation. Services that do, or at least do not forbid it, checked from both
sides of the 2026-11-09 failure:

| Service | What it is | Limits | Automation | `mgmt-168-7` (blocks 9009-9013) | `cpoc-rtp-dev` |
|---|---|---|---|---|---|
| **Piping Server**, `https://ppng.io` ([nwtgck/piping-server](https://github.com/nwtgck/piping-server)) | streaming relay over plain HTTPS: the sender `PUT`s to a path, the receiver `GET`s the same path at the same time, nothing is stored | none stated (it streams) | it is the intended use: its README lists ppng.io under "Public servers" and its `/help` shows only `curl` pipelines, including `openssl` encryption; no terms page | reachable; **20 MB round trip, MD5 matches** | same |
| Public **Send** servers ([list](https://gitlab.com/timvisee/send-instances), ~22, e.g. send.vis.ee, de.skysend.ch) | Firefox Send forks: end-to-end encrypted, stored for days | 2.5-50 GiB, 3-30 days, by server | the `ffsend` CLI exists; no terms on the list, which "does not give any promises" | reachable | reachable |
| temp.sh | anonymous `curl` upload, stored | 4 GB, 3 days | `curl -F` documented | **blocked** (no HTTP response: the lab's URL filter) | reachable |
| litterbox.catbox.moe | anonymous upload, stored | 1 GB, up to 72 h | API documented; its terms forbid scraping and bulk accounts | **blocked** | reachable |

**Piping Server fits torque-tunnel best.** It is croc's relay model (a live rendezvous,
the sender first, then the receiver) carried over HTTPS on 443. torque-tunnel's
transfer is built the same way, so:
- **Path:** a random 256-bit path is the rendezvous, kept secret like croc's code (a
  sensitive input, never in the log).
- **Sending:** `tar`/`cat | openssl enc | curl -T - https://ppng.io/<path>`.
- **Receiving:** `curl … | openssl enc -d`.
- **Integrity:** the existing size and MD5 manifest checks every file.

It needs only `curl` and `openssl` on the agent, both already present, and `curl` honours
`HTTPS_PROXY`. From this machine, Python streams the same way.

Caveats:
- `ppng.io` is one free server run by one person (its author), with no terms and no
  service level. Heavy, multi-GB automated use is not forbidden, but not explicitly
  invited either.
- Encryption has to be ours: the server sees whatever it relays.
- Throughput was not measured.
- A different public Piping Server, or a Send server as a store-and-forward fallback,
  could be added for redundancy.

## Recommendation

- **Port blocks:** no public relay helps (see the search above). A self-hosted relay
  on `443,8080` (or whatever the lab allows) is the only croc-native fix. Where 443 is
  inspected, or only one port is allowed, QIM's WebSocket-on-443 multiplexer is the
  model: a small shim on each agent, nginx and a mux next to the relay. It needs a host reachable from both labs, e.g. a small
  cloud VM. The relay check already says when a side cannot reach the configured
  relay, and why.
- **Resilience:** let torque-tunnel use the public pool instead of one relay. Both
  sides must agree on the relay, and the croc ping makes it cheap to try several:
  - Uploads: this machine checks the pool and picks the first relay that answers
    (before generating the agent's commands, so they name the same relay). The agent
    checks that relay first and fails with the cause as now. A smarter version would
    pass the agent an ordered list.
  - Downloads and transfers: the sender checks the pool in order and names the relay it
    registered on in its READY sentinel (`__CROC_SEND_READY__ relay=2.getcroc.com:9009`).
    The receiver is started (or, for downloads, ungated) only after READY, so it can
    read the relay from there. A receiver that cannot reach the sender's choice still
    fails at once, with the cause.
  - The relay password differs per private relay, so a pool is a list of
    `{address, password}`. The public pool uses croc's default password.

  This is a contained change (the relay becomes a per-call choice instead of a config
  constant). It does not need croc v11.

Sources: croc README and source on `main` (v11.6.5, released 2026-11-07):
`src/publicrelay/publicrelay.go`, `src/tcp/tcp.go`, `src/comm/comm.go`,
`src/utils/utils.go`, `src/cli/cli.go`; croc v10.4.2 for the pinned client.
