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

## Recommendation

- **Port blocks:** a self-hosted relay on `443,8080` (or whatever the lab allows) is
  the only croc-native fix. It needs a host reachable from both labs, e.g. a small
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
