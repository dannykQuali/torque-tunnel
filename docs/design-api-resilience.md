# Design: API Resilience (Retries & Idempotent Creates)

> **Status: implemented.** Core logic in `src/torque_tunnel/torque_client.py`
> (retry helpers, idempotent create + reconcile, two-budget `wait_for_environment`,
> naming helpers), config keys in `src/torque_tunnel/config.py` + `mcp_tool.py`,
> `command_description`/`container_description` exposed on all MCP tools and CLI
> subcommands. Tests in `tests/test_resilience.py`.

## Problem

Every time a new version of Torque is deployed, its gateway/auth backends flap for a
few minutes (rollouts can take **up to ~10 minutes**) and return a burst of transient
errors on API calls. `torque-tunnel` currently fails fast on these, aborting
long-running operations (installs, deployments) that were otherwise fine.

A representative failure (mid-install, during a Torque redeploy):

```
[WARNING] HTTP 500 error polling environment suDqckgho0gw (1/10): Server error '500 ...'
Error: HTTP 401 error: Client error '401 Unauthorized' for url '.../environments/suDqckgho0gw'
remote-server-installer.sh failed (exit code: 1)
```

The 500s were retried; the **401 killed the run**.

## Root cause (verified in code)

| # | Gap | Location |
|---|-----|----------|
| 1 | `wait_for_environment` treats **all 4xx as permanent** and returns immediately — including transient `401` from a flapping auth backend during deploy. This is what aborted the example. | `torque_client.py:496-510` |
| 2 | Monitoring retry budget is a fixed count: `max_consecutive_errors=10 × poll_interval=2s ≈ 20s`. A Torque rollout takes **minutes**. | `torque_client.py:464-465`, `469-533` |
| 3 | Environment **creates have zero retries** — first transient error → `RuntimeError` → whole op fails. Covers command launches and persistent-container start. | `torque_client.py:208-218`, `290-298`, `883-891` |

## Key enabler — labels at create + queryable (verified in cs2018 source)

After a failed create we must be able to ask Torque *"did my environment actually get
created?"* without a false negative (which would double-execute a user command). The
following are all **confirmed against the `C:\Work\cs2018` codebase**:

- **Labels are settable in the create payload.** `CreateSandboxRequest` (the
  standalone-blueprint endpoint torque-tunnel calls,
  `Devbox.Api/Model/Requests/CreateSandboxRequest.cs`) exposes:
  ```jsonc
  "labels": [ { "key": "torque-tunnel-id", "value": "<uuid>" } ]   // EnvironmentLabelRequest[]
  ```
  No separate `PUT .../labels` round-trip is required.
- **`labels` ≠ `tags`.** The same create request also has `tags`
  (`Dictionary<string,string>`) — but tags propagate to *deployed cloud/k8s resources*
  and are **not** queryable on the environments list, so tags are useless for
  reconciliation. Labels are the channel.
- **Query is an exact, CASE-SENSITIVE array-containment match** (`EnvironmentStore.cs`):
  `GET /environments?labels=torque-tunnel-id:<uuid>&match_all_labels=true`
  → SQL `e.labels @> ARRAY['torque-tunnel-id:<uuid>']`. `@>`/`&&` on a `text[]` column
  compare elements by byte equality — **no `lower()`/`ILIKE`** (deliberately unlike the
  `name` filter). Write paths preserve case (`EnvironmentRequestCreator`,
  `EnvironmentLabelsUpdater` — no case-folding), so store-case == query-case. Returns
  exactly our env (0 or 1), **independent of time**.
  - Quirk: Torque's *in-memory* `AreLabelsEqual` uses `OrdinalIgnoreCase`
    (case-*insensitive*), but that path is not the list-query filter — the DB search is
    case-sensitive. We sidestep the whole question via a case-insensitive key alphabet
    (§3).
  - By contrast the `name` filter is `doc->>'Name' ILIKE '%name%'` — case-insensitive
    **substring**, not exact. Fine as a human/fallback channel, not as the primary key.
- **Label format & limits** (`EnvironmentLabelExtensions`, `LabelValidationHelper`):
  stored/queried as the string `key:value`; parsing does `Split(':')` so the **value must
  not contain `:`** (our urlsafe-b64 uuid is `[A-Za-z0-9_-]` only → safe) and is
  `.Trim()`-ed (uuid has no spaces → safe); key and value each **≤128 chars**; reserved
  **system labels** are rejected (a custom `torque-tunnel-id` key won't collide).
- The create request also has a dedicated **`description`** field (separate from the
  name) that we may optionally populate with the human description (§6).

`GET /api/spaces/{space}/environments` additionally supports `name`, `blueprint_name`,
`status`, `from_start_time`/`to_start_time`, and paging — used only as optional
narrowing, never for correctness.

## Design decisions (agreed)

- **Retry `401` only (not `403`) for now.** More status codes can be added as we
  encounter them. `403` stays permanent until we have evidence it flaps during deploys.
- **Outages must not penalize the caller's wait budget.** The wait timeout counts only
  *healthy* time; outage time is "free" (bounded by a separate outage budget). See §2.
- **The reconciliation anchor is a create-time label `torque-tunnel-id:<uuid>`**, matched
  by exact array containment (verified settable at create). The human-readable name is
  best-effort; correctness rests on a time-independent unique id. See §3 and §5.
- **`from_start_time` is not needed for correctness** — an exact label match returns
  exactly our env regardless of time, so timezone/clock drift is a non-issue for the
  primary path. It stays available only as optional performance narrowing. See §5.
- **Idempotent create ⇒ at-most-once user-command execution.**

## Design

### 1. Centralized retry with time-based budget + backoff (idempotent ops)

A helper `_send_with_retry(coro_factory, *, budget_seconds)` wrapping the **safe**
(idempotent) calls: `get_environment_status`, `get_grain_log`, `end_environment`,
`release_environment`, `delete_environment`, `extend_environment`.

Error classification:

| Class | Statuses / errors | Action |
|-------|-------------------|--------|
| Transient | connection/read timeouts, connection errors, `5xx`, `429`, **`401`** | retry |
| Permanent | `403`, `400`, `404`, `422` | fail fast (propagate) |

- Retry until the applicable budget elapses (see §2 for how this composes with the
  caller timeout during monitoring).
- Exponential backoff `1 → 2 → 4 → …` capped at `retry_max_backoff_seconds` (default
  **15s**), plus small jitter.
- On budget exhaustion, raise the last error with context.

The set of transient statuses lives in one place (a module-level constant) so adding a
code later (e.g. `403`) is a one-line change.

### 2. Wait timeout vs. outage budget (`wait_for_environment`)

Today the retry loop `continue`s back to a `elapsed > timeout` check, so **outage time
is charged against the caller's command wait budget** — a 10-min outage can falsely time
out a command that was fine.

New model: **two independent budgets.**

- **Wait timeout** (caller's `timeout`) — counts **only healthy time**. Track
  `total_outage_seconds`; the deadline check becomes
  `(now - start) - total_outage_seconds > timeout`. The first successful poll after an
  outage closes the outage segment, so the timeout resumes exactly where it paused
  ("after a single successful read, apply the timeout").
- **Outage budget** (`retry_budget_seconds`, default **600s**, sized for a ~10-min
  rollout) — the max *consecutive* time spent in transient-error retries. Resets to 0 on
  any successful poll. This is the "Torque is genuinely down, give up" backstop.

The operation ends when: the environment reaches a terminal status (normal),
the **healthy** elapsed time exceeds the wait timeout, or a **single** outage exceeds the
outage budget.

**Suspend/hibernate exclusion.** Both budgets measure `time.monotonic()`, which advances
across an OS suspend (laptop sleep/hibernate). Without care, hibernating mid-poll makes
the first poll after wake see a huge elapsed time and falsely trip the outage budget
(observed: `outage 3s` → `unreachable for 3261s` after hibernating at the office and
resuming at home). Fix: if the gap between two consecutive polls exceeds
`_SUSPEND_GAP_SECONDS` (**120s** — far beyond any real inter-poll interval, since a poll
tops out at the 60s httpx timeout and backoff caps at a few seconds), the process was
frozen, not retrying. We shift `start_time`/`outage_start` forward by the frozen span so
it counts against **neither** budget: a suspend just pauses the watcher, and it resumes
polling on wake (the remote command kept running — and the Torque API is a public
endpoint, so polling works from any network the resumed machine lands on).

Why this is safe from runaway commands: the *actual* command-execution limit is enforced
**server-side** by the blueprint's `timeout_minutes` input (`torque_client.py:176`).
Torque kills a runaway command regardless of how long we wait. Our wait timeout only
governs how long we're willing to wait to *retrieve* a result, so pausing it during an
outage cannot extend command execution.

Keep `404 → status="deleted"` as terminal (correct — env was auto-cleaned).

### 3. Idempotent create (at-most-once user commands)

Applies to `start_environment`, `start_local_environment` (run user commands) and
`start_persistent_container` (see §4).

Note that `start_environment` is shared by two different operations (plain SSH **and**
per-command execution against a persistent container), so the environment "kind" used for
naming (§6) is passed in by the handler — it cannot be inferred from the client method.

1. Generate one client key per logical create, using a **case-insensitive alphabet** so
   matching is immune to any case handling in the stack (the DB label query is
   case-sensitive while Torque's in-memory label equality is case-insensitive — see the
   Key enabler section):
   `key = base64.b32encode(uuid4().bytes).decode().rstrip("=").lower()` (26 chars, only
   `[a-z2-7]` — colon-free and case-agnostic; 128 bits of collision resistance).
   Lowercase hex is an equally acceptable alternative.
2. Make the environment identifiable in two ways:
   - **Label (authoritative, verified settable at create)**: add
     `{ "key": "torque-tunnel-id", "value": "{key}" }` to the create payload's `labels`
     array. Queried by exact array containment (§5).
   - **Name (human-facing + fallback)**: see §6. The name *ends with* `-{key}`, so the
     key is also recoverable from the stored name via substring search.
3. Create flow:
   - `POST` create (with the label).
   - On **transient** failure → **reconcile** (§5):
     - **found** (the env carrying label `torque-tunnel-id:{key}`) → adopt its
       `environment_id`; do **not** re-send the command (at-most-once).
     - **not found** → safe to re-`POST` with the **same key** (keeps reconciliation
       valid), within `create_retry_budget_seconds` (default **600s**).
   - On **permanent** failure (`403`/`400`/`422`) → fail fast.

This guarantees a user command is executed **at most once** across all retries.

### 4. Persistent-container start

`start_persistent_container` uses the same key + reconcile mechanism. It runs no user
command (just dropbear), so a plain retry is inherently safe — but reconciliation
prevents **leaking orphan containers** when a create actually succeeded server-side but
the response was lost.

**Two distinct environments in the persistent-container flow** (do not conflate them):

1. The **persistent container itself** — the long-lived `persistent-container` blueprint
   environment created by `start_persistent_container` (name prefix
   `tunneled-persistent-container`).
2. A **per-command environment** — a separate short-lived `remote-shell-executor`
   environment created by `start_environment` for *each* command sent to the container
   (it SSHes from a throwaway grain into the container; name prefix
   `tunneled-persistent-command`).

Only #2 runs a user command and therefore needs the at-most-once guarantee; #1 only needs
retry + orphan-avoidance. #2 also carries a label
`torque-tunnel-parent: {persistent_env_id}` so users can trace a command back to its
container in the Torque UI.

**Each environment gets its own description** (see §6): the container (#1) is named from
`container_description`, and every command (#2) from `command_description`. Because the
container is created once and reused across many commands, `container_description` is
consumed **only when a new container is actually created** (first call, `new_container`,
or respawn of a dead one) and is ignored on reuse calls; `command_description` applies on
every call.

### 5. Reconciliation & timezone/clock-drift handling

Reconciliation answers "did my create land?" and must never produce a **false negative**
(which would trigger a duplicate command).

- **Primary query — exact label match:**
  `GET /environments?labels=torque-tunnel-id:{key}&match_all_labels=true`
  (SQL `e.labels @> ARRAY['torque-tunnel-id:{key}']`). Returns 0 or 1 env, **independent
  of time**. 0 → re-POST; 1 → adopt; >1 → impossible for a unique key (pick newest + log).
- **Timezone/clock drift is a non-issue** for this path: the match is by exact label, not
  by time, so there is no `from_start_time` in the correctness path and thus nothing to
  get wrong across timezones or clock skew.
- **`from_start_time` is optional performance narrowing only.** Label containment on the
  indexed `labels` array is already selective, so we default to **not** sending a time
  filter. If a busy space ever needs it, apply it with **generous backward slack, never
  forward**, anchored to **Torque's own clock** via the `Date` response header (fallback:
  `local_utc_now - larger_slack`), sent as UTC-`Z`. Even then it can only shrink the
  candidate set, never hide our env, because the label does the matching.
- **Fallback (defensive):** if a label query ever returns nothing but we're unsure, do a
  recent-page `name` substring search for the `-{key}` suffix before deciding to re-POST.
  Belt-and-suspenders; the label path is expected to be authoritative.

### 6. Environment naming redesign

Drop the timestamp (uuid provides identity) and the legacy `shell-cmd` prefix. New scheme:

```
tunneled-<description>-<kind>-<b32uuid>
```

The description leads (when present) so it isn't hidden behind a long kind prefix in the
Torque UI. Without a description the name is `tunneled-<kind>-<b32uuid>`.

Example:
```
tunneled-Monitoring vcenter until vm is up-ssh-mfrggzdfmztwq2lknnwg23tp
```

`<kind>` names the environment's role (NOT the client method — `start_environment` serves
two kinds, so the handler passes the kind in explicitly):

| Kind prefix | Created by | Blueprint | Description source |
|-------------|-----------|-----------|--------------------|
| `tunneled-ssh` | `run_on_tunneled_ssh[_async]` | remote-shell-executor | `command_description` |
| `tunneled-disposable-container` | `run_on_tunneled_disposable_container[_async]` | local-shell-executor | `command_description` |
| `tunneled-persistent-container` | persistent-container lifecycle (`start_persistent_container`) | persistent-container | `container_description` |
| `tunneled-persistent-command` | each command on a persistent container (`run_on_tunneled_persistent_container[_async]`) | remote-shell-executor | `command_description` |

There is **no `local` kind** — "local-shell-executor" is merely the internal blueprint
behind the disposable-container tool.

- `<description>` — an **optional** AI-supplied short human-oriented string so an end user
  can find the right environment in the Torque UI. Sanitized: strip newlines/control
  chars, collapse whitespace, cap ~60 chars. Omitted → the segment is dropped, yielding
  `tunneled-<kind>-<uuid>`.
- `<b32uuid>` — the idempotency key from §3 (stable suffix, lowercase base32).

**Two description parameters** (the persistent flow owns two environments, §4):

| Tool param | On which tools | Names which env | Consumed when |
|------------|----------------|-----------------|---------------|
| `command_description` | all (ssh, disposable, persistent, + async) | the per-call command env | every call |
| `container_description` | persistent tools only | the persistent container lifecycle env | only when a new container is actually created (first call / `new_container` / respawn); ignored on reuse |

Both optional. `command_description` supersedes the earlier working name
`environment_description` (now ambiguous, since on the persistent path the container is
also an environment).

The client gains a small `_build_environment_name(kind, description, key)` helper used by
all create paths, with `kind` supplied by the caller and `description` being whichever of
the two params applies to that environment.

#### Surface: MCP tools (required) vs CLI (optional)

The descriptions are exposed on **both** entry points, but with different obligation:

- **MCP tools — required.** An optional, passively-worded field gets skipped by models
  (they optimize for task completion, not cosmetic metadata), leaving description-less
  names. So the description fields are marked `required` in each tool's inputSchema to
  force a conscious choice. **Empty values are always accepted** (`""` is a valid string —
  standard JSON-Schema `required` only mandates presence, not a non-empty value); we never
  reject or fail on empty, since agents sometimes legitimately have nothing to add or want
  to save tokens. The wording says so explicitly.
- **CLI — optional.** Kept optional for human ergonomics and backwards-compatibility with
  existing scripts (a newly-required flag would break them).

| Surface | `command_description` | `container_description` |
|---------|-----------------------|-------------------------|
| MCP `run_on_tunneled_ssh[_async]` | **required** (empty ok) | — |
| MCP `run_on_tunneled_disposable_container[_async]` | **required** (empty ok) | — |
| MCP `run_on_tunneled_persistent_container[_async]` | **required** (empty ok) | **required** (empty ok; pass `""` when reusing) |
| CLI `ssh` | `--description` (optional) | — |
| CLI `disposable-container` | `--description` (optional) | — |
| CLI `persistent-container` | `--description` (optional) | `--container-description` (optional) |

- Empty/absent description → the name falls back to `tunneled-<kind>-<key>` (no failure).
- CLI flag naming: `--description` for the per-call command env; `--container-description`
  only on the `persistent-container` subcommand. No short aliases (avoid collision with
  the many existing `common_parser` flags). Both default to unset.
- The `read`/`list` CLI helpers don't take a flag; they auto-derive a description
  (e.g. `read <path>`, `list <path>`).
- Threading: CLI `args.description` / `args.container_description` map to the same handler
  params the MCP tools populate — a single code path builds the name for both surfaces.
- We deliberately did **not** auto-derive a description from the command; required-in-MCP
  is the chosen incentive instead.

### 7. Configuration knobs

Added to `config.py` `CONFIG_KEY_MAP` (so they flow through the `default` section and
profiles like every other setting) and to `_config` defaults in `mcp_tool.py`:

| YAML key | Default | Meaning |
|----------|---------|---------|
| `retry_enabled` | `true` | Master switch for all retry behavior |
| `retry_budget_seconds` | `600` | Max consecutive outage tolerated (monitoring & idempotent GETs), sized for a ~10-min rollout |
| `create_retry_budget_seconds` | `600` | Budget for idempotent create + reconcile |
| `retry_max_backoff_seconds` | `15` | Backoff cap |

When `retry_enabled=false`, behavior reverts to current fail-fast (for debugging).

## Testing (TDD)

Drive the **real** `TorqueClient` via `httpx.MockTransport` (built into httpx — no new
dep) with programmed response sequences, so the real retry/reconcile code executes.

Planned cases:

- **Monitoring**: `3×500 then 200` → completes; `401 then 200` → completes (regression
  for the example); `403` → fails fast (not retried); `404` → `deleted` terminal;
  consecutive transient errors past the outage budget → `error`.
- **Wait vs. outage budget**: inject an outage mid-wait, assert the wait timeout is
  effectively extended by the outage duration (healthy-time accounting), and that a
  single outage longer than the outage budget aborts.
- **Idempotent create**: `POST 500` but env **found** by the label query ⇒ assert exactly
  **one POST** and the adopted id is returned (no double-execution); `POST 500` + label
  query **empty** ⇒ a second POST is issued; assert the create payload carries
  `labels:[{key:"torque-tunnel-id",value:key}]` and the name carries the `-{key}` suffix;
  description sanitization (length/newlines/colon-free value).
- **Reconciliation**: env matched by exact label containment; the reconcile query sends
  `match_all_labels=true` and no `from_start_time` by default; name-suffix fallback path
  finds the env when exercised.
- **Descriptions**: `command_description` names each per-call env; `container_description`
  names the container only on creation and is ignored on a reuse call; a per-command env
  carries the `torque-tunnel-parent` label linking it to its container.
- **Backoff**: monkeypatch `asyncio.sleep` to **record** durations instead of sleeping
  (fast, non-flaky per project testing guidelines); assert exponential growth + cap.
- **Edge**: concurrent creates get distinct keys; `retry_enabled=false` restores
  fail-fast.

Per project guidelines: build first, then run the suite **100×** to confirm no flakiness.

## Out of scope

- Retrying inside the blueprint shell scripts themselves (this design is about the
  torque-tunnel ↔ Torque REST API boundary only).
- Persisting idempotency keys across process restarts (in-memory per operation is
  sufficient; a lost process means the caller re-invokes the tool anyway).
