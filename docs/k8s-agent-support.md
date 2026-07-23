# Kubernetes Agent Support — Findings & Plan

Status as of 2026-07-16. Live-tested against a real Torque **k8s agent** (`dannyk-kind-tunnel-test`
on jarvis/stackautomation) running in a **kind** cluster on `10.91.36.250`. Everything below was
verified empirically, not inferred.

## TL;DR

**torque-tunnel works against a Torque k8s agent almost out of the box.** Passed: disposable
containers, SSH (key + password), persistent containers with cross-call state, inline uploads,
async execution/status/cancel. Two real issues remain, both now root-caused:

1. ~~`replicas: 2` races on runner lifecycle~~ — **RETRACTED after controlled experiments;
   `replicas: 2` (Torque's production default) is exonerated** (see Finding 1). The one persistent
   container that died is now attributed to the **agent's proxied-HTTP misroute**: .NET ignores the
   CIDR entries in the agent pod's `NO_PROXY`, so a BE→agent HTTP-tunnel call targeting an
   in-cluster IP went to the Cisco proxy, timed out (100s), and the runner was declared errored →
   pod killed. Cisco-lab-specific, not a Torque bug, not kind-specific.
2. **croc transfers (both directions) fail on k8s** while docker works — TWO stacked bugs. **(2a,
   our DNS misconfig, FIXED):** a junk `localdomain` search suffix leaks host→node→pod, and lab DNS
   *times out* on it instead of returning NXDOMAIN; Go's resolver aborts → croc resolves its relay to
   nothing (`found no addresses`). Fixed by a CoreDNS `template … localdomain { rcode NXDOMAIN }`
   patch (verified: real transfer now succeeds via default DNS). **(2b, still open):** the MCP's
   receive retry-loop churns croc's relay room during the ~15-20s pod startup → `could not secure
   channel`. Fix: inline small transfers via the Torque API, and/or a gentler receive loop.

**Correction to an earlier draft:** the proxy env-var and image-pull-timeout items are **Cisco-lab
specific, not k8s-specific** — the docker agents on this network need the exact same proxy handling
and hit the same slow pulls. They are onboarding steps for *any* agent behind the Cisco proxy, not
k8s gaps. Kept below under "Cisco-lab onboarding" for completeness.

## Test environment

| Piece | Value |
|---|---|
| Cluster | kind v0.29.0 (`torque-k8s-test`), K8s v1.33.1, single node, on 10.91.36.250 (AlmaLinux 9.7, Docker) |
| Agent | `dannyk-kind-tunnel-test`, image `quali/kubernetes-agent:2.0.28322869019`, ns `torque-agent-dannyk-kind-tunnel-test-njsng5mvs` |
| Torque | https://jarvis.qtorque.io (a.k.a. stackautomation.cisco.com), associated to all 7 spaces, used in `AI-Studio` |
| Network | Cisco lab behind HTTP proxy `proxy.esl.cisco.com:80`; no direct internet |

## Test matrix (all with `torque_agent: dannyk-kind-tunnel-test`)

| Tool / feature | Result | Notes |
|---|---|---|
| `run_on_tunneled_disposable_container` | ✅ | Runner pod = same `quali/shell` Ubuntu 22.04 image as docker agents; runs as root |
| `run_on_tunneled_ssh` (key) | ✅ | Pod → lab host; target sees source IP = cluster host (10.91.36.250) |
| `run_on_tunneled_ssh` (password) | ✅ | `sshpass` auto-installed via apt through proxy |
| `upload_files` (inline, <300KB) | ✅ | |
| `download_files` (croc) | ❌ | k8s-specific — see Finding 2 |
| `run_on_tunneled_persistent_container` | ✅ | Dropbear pod gets pod IP, command runners SSH to it pod-to-pod; state persists for hours, survives agent restarts. One early "Active With Error" — see Finding 1 (agent proxy misroute, not replicas) |
| `run_on_tunneled_*_async` + `get_execution_status` | ✅ | Streaming partial output works |
| `cancel_execution` | ✅ | |

## Finding 1 — the "Active With Error" persistent container: `replicas: 2` EXONERATED

**Facts that stand:** `replicas: 2` is **Torque's own default** in the server-generated manifest
(re-fetched fresh, byte-identical modulo secrets; we never touched it), with no leader election —
two identical agent pods sharing one `ClusterId`/`ClusterToken`. There is **no replica/scale knob in
the Torque API** (`runner_settings` govern runner pods, not the agent Deployment), so a
Torque-only user cannot change it post-install anyway. A healthy live persistent container always
shows `computed_status: Launching` / grain `Deploying` (its `exec dropbear -F` deploy never
completes) — that is normal, not an error.

**Retraction:** an earlier draft blamed a runner-lifecycle race between the two uncoordinated
replicas and recommended scaling to 1. **Controlled experiments falsified that:**

- **E-soak (2 replicas):** a fresh persistent container born under 2 replicas ran 13+ min (past the
  ~9-min mark where the original died) with zero agent errors; a second persistent container — also
  born under 2 replicas — lived **4+ hours** through the whole investigation. Hours-long idle
  survival also rules out idle/proxy-idle timeouts.
- **E2 (agent restart, 1 replica):** deleted the sole agent pod; the deployment recreated it with
  empty in-memory state — existing persistent containers kept running, kept their state, and
  accepted new commands. So agent restarts / state loss don't kill runners either.
- Production default restored: the test agent runs `replicas: 2` now, healthy.

**What actually killed the one container (best-supported explanation):** the only anomaly in its
death window is the agent-side proxied-HTTP failure chain: 13:35:56 one agent replica's SignalR
websocket through the Cisco proxy dropped; ~13:41:30 a BE→agent `ReceiveHttpRequest` HTTP-tunnel
call started and hit .NET's 100s timeout (logged 13:43:13); pod killed ~13:46 with "runner is in
error state". Transport defect verified: the agent pod's `NO_PROXY` uses CIDR ranges
(`10.0.0.0/8`, …) which **.NET does not parse** — any BE-initiated HTTP call the agent must make to
an in-cluster **IP** (pod/service) is misrouted to the Cisco proxy, which cannot reach pod IPs →
guaranteed timeout → runner declared errored. Production agents have no proxy env at all, which is
why this never manifests outside proxied labs. The exact BE call wasn't identified (BE-side), so
this is high-confidence-attributed, not replayed.

**Answer to "kind or Torque?": neither.** Nothing kind-specific was ever implicated (standard
upstream k8s behavior throughout), and Torque's production default held up under soak. The defect is
**our proxied-agent configuration** — a real sharp edge for *any* customer running the k8s agent
behind an HTTP proxy.

**Fix for proxied environments (generic, works for all users):** don't hand the agent raw proxy env
vars. Deploy a tiny in-cluster forward proxy (privoxy/tinyproxy) that routes RFC1918/cluster CIDRs
**direct** and everything else to the corporate proxy, and point the agent's `HTTP(S)_PROXY` at it —
all CIDR intelligence lives where it's supported. Longer-term product ask for Quali: native proxy
support in the kubernetes-agent with a CIDR-aware bypass list.

## Finding 2 — croc transfers fail on k8s: TWO stacked bugs (one was our DNS misconfig)

croc fails on the k8s agent for **uploads *and* downloads**; docker succeeds both ways. (Inline
uploads <300KB always work — they bypass croc via the Torque API.) There are **two independent
causes** stacked on top of each other; the first is a **DNS misconfiguration on our side**, now
fixed.

### Bug 2a — DNS: a bogus `localdomain` search suffix + an upstream that drops it (OUR misconfig)

The error `could not connect to : found no addresses to connect` (note the *empty* host before the
colon) means croc resolved its relay hostname `croc.schollz.com` to **zero addresses**. Why, traced
live in the pod:

1. croc is a static Go binary → **pure-Go resolver** (`GODEBUG=netdns=2` confirms).
2. The pod's `resolv.conf` has `ndots:5` + a search list, so a 2-dot name like `croc.schollz.com` is
   tried **through the search list first**: `croc.schollz.com.<suffix>` for each suffix.
3. One suffix is **`localdomain`** — junk, there is no such domain. It is **leaked from the .250
   host's DHCP-derived `/etc/resolv.conf` (`search localdomain`)** down into the kind node
   (`ndots:0` + `search localdomain`) and then into pods.
4. A sane DNS answers `croc.schollz.com.localdomain` with **NXDOMAIN in ~1ms** and the resolver moves
   on. Ours didn't: the query is forwarded upstream (`10.91.36.250`→`64.102.6.247`) and **silently
   dropped** — measured **4s TIMEOUT** at *both* `named` on .250 and the Cisco upstream. (The
   `*.cluster.local` candidates return clean NXDOMAIN; only `.localdomain` hangs.)
5. **Go's resolver aborts the whole lookup on a search-candidate timeout** → zero addresses. glibc
   would keep going, which is why `getent`/curl/apt/ssh in the *same pod* all work — only the Go
   binary trips.

So it's two of our own misconfigs compounding: **(a)** a meaningless `localdomain` search suffix
propagating host→node→pod, and **(b)** DNS servers that *time out* instead of returning NXDOMAIN for
a name that plainly doesn't exist.

**Fix applied + verified:** patched the cluster CoreDNS ConfigMap to answer the junk zone instantly:
```
template IN ANY localdomain { rcode NXDOMAIN }
```
(inserted before `forward . /etc/resolv.conf`, then `rollout restart deployment/coredns`). After the
patch, `croc.schollz.com.localdomain` returns NXDOMAIN in **1ms** from a pod, and a k8s runner
**resolves the relay via default DNS and completes a real transfer** (350KB pod→workstation, md5
match, no `--relay` needed). The proxy, croc's 8-port data channel, and the double NAT are all fine.

Better long-term fixes (either/both): stop the host leaking `search localdomain` (fix .250's DHCP/
`resolv.conf`), or configure the lab DNS to NXDOMAIN unknown names instead of black-holing them.
Defense-in-depth in torque-tunnel: pass the relay as a **pre-resolved IP** (`--relay <ip>:9009`,
resolved on the local machine) or a **rooted FQDN** (`croc.schollz.com.` — trailing dot skips the
search walk) so a broken search list can never strand croc again.

### Bug 2b — receiver-first is unsupported by croc; the retry-loop workaround races (still open)

Even after 2a, real MCP downloads on k8s are **flaky**: measured **5/6 success in a burst, ~6/9
overall** post-DNS-fix (docker also failed once this way — it is not k8s-exclusive, just k8s-worse).

**Root cause:** croc's protocol expects the **sender to exist first**; a receiver joining a
nonexistent room simply exits (`room not ready`). torque-tunnel's download flow inverts this — the
local `croc receive` starts *before* the environment exists and is wrapped in a retry loop
(`start_croc_receive`, retry every 2s for up to 30 min). Each retry re-enters the relay room. When a
retry lands **during the sender's room establishment window**, the handshake interleaves and
corrupts — sender sees PAKE then `EOF` → `could not secure channel`; the colliding receiver attempt
logs `room not ready` or even `problem with decoding: invalid character …` (it parsed PAKE bytes
where it expected the relay's JSON). Whether a given transfer survives is a race between the
receiver's 2s retry cadence and the sender's establishment interval:

- docker: sender establishes its room in <1s (warm runner, croc preinstalled, fast proxy path) →
  tiny collision window → rarely fails;
- k8s: window stretches — fresh runner pod (~3–4s), croc install when cold, and the proxy CONNECT
  from a pod was measured anywhere from <1s to **~11s** → much larger window → frequent failures.

(Timing facts, measured: runner pod schedule→script-running ≈ 3–4s — pods start *fast*; the MCP's
own chunked croc install ≈ 2s; an earlier "15–20s pod start" claim conflated a naive single-stream
croc download (~17.6s) with pod startup and was wrong. Uploads never hit this bug at all: their
ordering is already sender-first — the local sender starts before the env and *waits*, the remote
receiver joins once — which is exactly why uploads have always been solid on docker.)

**Root-cause fix (keeps croc, works for all users — no inline expansion):** make downloads
sender-first too, i.e. use croc as designed:
1. The generated download commands echo a marker (e.g. `TORQUE_TUNNEL::CROC_SEND_READY`) immediately
   before `croc send`.
2. The MCP polls the environment's activity log for the marker — the same mechanism the
   persistent-container flow already uses for `TORQUE_TUNNEL::READY` — and only then starts the
   local `croc receive` **once** (no retry loop).
3. Keep a short bounded retry purely as a fallback for log-polling hiccups.

Supporting changes: **2a defense** — emit `--relay <ip resolved on the local machine>` (or rooted
FQDN `croc.schollz.com.`) in all generated croc commands so broken remote DNS can never strand croc;
**runner warmth** — raise the k8s agent `runner_settings.idle_timeout_seconds` (default 120) so
runners are reused like docker's long-lived containers and croc stays installed.

**Correction of earlier drafts:** this was first reported as a "proxy multi-port / egress-IP
shuffle" problem — wrong. It is two bugs: our DNS misconfig (2a, fixed) + the receiver-first retry
race (2b); the proxy and relay data ports were never at fault.

## Cisco-lab onboarding (applies to ANY agent here, not k8s-specific)

- **Proxy env for runners**: set proxy in the agent's runner settings so Torque injects it into
  every runner pod (`PUT /api/settings/computeservices/{name}/new`, `details.type` lowercase `"k8s"`,
  `runner_settings.environment_variables` = the proxy vars). Also `kubectl set env deployment/...`
  on the agent pod itself. ⚠️ Do **not** put `.cisco.com` in the runner `NO_PROXY` — the SaaS
  endpoint `stackautomation.cisco.com` must go *through* the proxy. (Docker agents need the
  equivalent host-level proxy config — same requirement, different mechanism.)
- **Image pull timeout**: `quali/shell` is 567MB; through the proxy the first pull took ~4m26s and
  exceeded the default `startup_timeout_seconds: 400`. Raise to 900, and/or pre-pull / mirror
  `quali/*` in the lab Harbor. (Docker agents hit the same slow first pull.)

## Onboarding runbook (repeatable, ~15 min)

1. **Create the agent record**:
   ```
   POST /api/settings/computeservices
   { "service_name": "<name>", "service_type": "k8s",
     "details": { "type": "K8S_UNMANAGED", "ingress_controller_type": "alb", "ingress_class": "alb",
                  "configure_dns": false, "generate_certificate": false } }
   ```
2. **Get + apply the manifest**: `POST /api/settings/executionhosts/deployment/url`
   `{"host_name":"<name>","host_type":"k8s"}` → `{token,fileName}` →
   `kubectl apply -f https://<torque>/api/settings/executionhosts/deployment/<token>/<fileName>`
3. Keep the manifest's `replicas: 2` as-is (production default — verified fine; see Finding 1).
4. **Proxy-patch** the agent deployment (`kubectl set env`) — proxied labs only. ⚠️ Until the
   smart-proxy fix from Finding 1 is in place, a raw proxy env on the agent leaves the
   BE→agent→in-cluster-IP HTTP path broken (CIDR NO_PROXY unsupported by .NET) — rare but can kill a
   runner (Finding 1).
5. **Runner settings**: proxy env + `startup_timeout_seconds: 900` (Cisco-lab only).
6. **Associate spaces**: `POST /api/executionhosts/k8s/<name>/spaces/<space>` with
   `{"default_namespace":"<ns>","default_service_account":"torque-agent-sa-<suffix>","type":"K8S"}`
   (the `type` field is required; without it the endpoint 500s).
7. Verify `GET /api/settings/agents?service_name=<name>` → `status: active`, then run a disposable
   container command.

## torque-tunnel MCP changes to implement

- **Agent-type awareness**: query `GET /api/settings/agents?service_name=...` → `type`. Make the
  "DANGEROUS COMMANDS" warning list conditional: on k8s the foot-guns are
  `kubectl delete deployment/ns torque-agent-*`, killing kubelet, etc. — not `docker restart`.
- **k8s onboarding**: automate runbook steps 1–6 in `setup`/onboarding, including the
  runner-settings proxy fix when the profile carries a proxy.
- **Inline small downloads** (Finding 2, option 1) — biggest robustness win, fixes downloads on both
  agent types behind the proxy.
- **Persistent-container resilience**: tolerate/retry a reaped dropbear pod; guard against
  `torque_agent` override splitting a persistent container's command runners from its dropbear pod.

## Open questions / next steps

- [ ] Deploy the in-cluster smart forward proxy (privoxy: RFC1918→direct, rest→corporate proxy) and
      point the agent's proxy env at it (Finding 1 fix); file the product ask with Quali for native
      CIDR-aware proxy support in the kubernetes-agent.
- [ ] (Optional) Identify the exact BE→agent `ReceiveHttpRequest` call that killed Kw3f — needs
      BE-side knowledge/logs; would upgrade Finding 1 from attributed to replayed.
- [ ] Implement inline small-file downloads in the MCP.
- [ ] Decide the cluster's long-term home (kind on .250 is a test rig; .110 vanished 2026-07-07).
- [ ] Test a real multi-node cluster (OpenShift/EKS) — kind is single node; pod-to-pod across nodes
      should still satisfy the persistent-container flow, but untested. Note: on a real >1-node
      cluster, 2 replicas may land on different nodes and the persistent dropbear pod could be
      unreachable from a command-runner on another node unless the CNI allows pod-to-pod across
      nodes (usually yes) — retest.
- [ ] Mirror `quali/shell` + `quali/kubernetes-agent` in the lab Harbor for fast, proxy-free pulls.
