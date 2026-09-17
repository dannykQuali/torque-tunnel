# Credentials support

Lets a `run_*` call use a credential stored in the connected Torque account without the
secret ever reaching the AI chat, the MCP client, or this machine.

Torque already knows how to inject a credential's secrets as environment variables into a
grain. torque-tunnel's job is to (a) let the caller pick a credential by name, (b) tell the
caller which environment variables it will get, (c) carry those variables to wherever the
command actually runs, and (d) keep their values out of the returned output.

---

## 1. The Torque mechanism

A shell grain takes a list of credential names:

```yaml
grains:
  local_executor:
    kind: shell
    spec:
      authentication:
        - vCenter-MX
```

At deploy time Torque resolves each name to a set of environment variables
(`Quali.Colony.Services.Environments.Grains/CredentialEnvsCreators/`) and writes them into
the grain script as `export K='V'` lines. The exports are **not** echoed to the user-visible
grain log — only the command body is — so attaching a credential does not by itself leak it.

### Verified behaviour

All of the following were confirmed live against `jarvis.qtorque.io` during design.

| behaviour | result |
|---|---|
| literal names in an inline (`base64_standalone_blueprint`) blueprint | works |
| `authentication: ['{{ .inputs.x }}']` with the value passed at launch | works — resolves end to end |
| an `authentication` entry resolving to empty | **HTTP 400** `VALUE_RESOLVED_TO_EMPTY_VALUE` |
| unknown credential name | **HTTP 400** `CREDENTIAL_NOT_FOUND_BY_PATH` at launch |
| credential not allowed in the launch space | **HTTP 400**, same code, message says "does not exist" |
| two credentials whose variables collide | both attach, **the last one silently wins** |
| a credential type with no env-var creator (e.g. `github`) | launch accepted, then deploy dies with `"unexpected error has occurred"` |
| grains of one environment | separate containers, **no shared filesystem** (`/storage` is shared but is the agent host's persistent disk) |

### Why only one credential per call

`GrainOperationRunnerRequestDataCreator.GetCredentialAsEnvs` merges each credential's
variables with `.Override(...)`, so on a name collision the **last credential wins, with no
error and no warning**. Proven live: attaching `vCenter-MX` and `vcsa-chicago` together
produced only `VSPHERE_SERVER=10.91.36.235` — the second one.

Fixing that properly needs a Torque-side change (per-credential namespaced injection), which
is out of scope. Until then torque-tunnel accepts **at most one credential per call**, and the
tool parameter is a single string rather than a list so the constraint is visible in the
schema rather than enforced after the fact.

A multi-credential *workflow* still works: with the persistent container, credential A on one
call and credential B on the next both act on the same live container. Only a single
*command* cannot hold two.

---

## 2. Blueprint shape

The `authentication` key cannot be left empty and a `type: credentials` input cannot be
optional (verified: with no value, with `pattern: '^$|^.+$'`, and with an explicit `""` — all
rejected). So both the input and the `authentication` block are emitted **conditionally**,
by substituting two anchor lines in the blueprint file at load time:

```yaml
inputs:
  # __TT_CREDENTIAL_INPUT__          ->  credential:
                                     ->    type: credentials
                                     ->    description: ...
grains:
  local_executor:
    spec:
      # __TT_CREDENTIAL_AUTH__       ->  authentication:
                                     ->    - '{{ .inputs.credential }}'
```

With no credential requested, both anchors are removed and the blueprint is byte-identical in
behaviour to before this feature.

`type: credentials` (rather than `type: string`) is used because it renders as a credential
picker in the Torque launch form and makes Torque itself validate the name at launch — a
second net under torque-tunnel's own pre-flight. Its two failure modes (blank value, and "no
credentials exist in this space") cannot bite, because the input is only emitted once a
credential has been resolved.

Substitution is plain text replacement of the anchor line, **not** a YAML round-trip: the
executor blueprints carry several hundred lines of shell in block scalars and reserialising
them risks changing whitespace that the script depends on.

---

## 3. Environment variables per credential type

There is **no Torque API that exposes this mapping** — it exists only in the C# source, and
the only credential metadata any endpoint returns is `cloud_type`. So torque-tunnel keeps a
cache of `credential_data_type -> variable names`, seeded with what the source says today and
extended by measurement for anything it hasn't seen.

### Seed (from `CredentialEnvsCreators/`, as of 2026-09)

| type | status | variables (**bold** = secret, returned as `null` by the API) |
|---|---|---|
| `aws__basic` | ok | `AWS_ACCESS_KEY_ID`, **`AWS_SECRET_ACCESS_KEY`** |
| `aws__role_arn` | ok | `AWS_ACCESS_KEY_ID`, **`AWS_SECRET_ACCESS_KEY`**, **`AWS_SESSION_TOKEN`** (STS AssumeRole happens at resolve time) |
| `azure__basic` | ok | `ARM_TENANT_ID`, `ARM_SUBSCRIPTION_ID`, `ARM_CLIENT_ID`, **`ARM_CLIENT_SECRET`** |
| `vsphere__basic` | ok | `VSPHERE_USER`, **`VSPHERE_PASSWORD`**, `VSPHERE_SERVER`, `VSPHERE_ALLOW_UNVERIFIED_SSL`, `VMWARE_USER`, **`VMWARE_PASSWORD`**, `VMWARE_HOST`, `VMWARE_VALIDATE_CERTS` |
| `intersight__basic` | ok | `INTERSIGHT_API_KEY`, **`INTERSIGHT_SECRET_KEY`**, `INTERSIGHT_REGION`, and the same three with a `TF_VAR_` prefix |
| `nexus_dashboard` | ok | **`NEXUS_DASHBOARD_API_KEY`**, `NEXUS_DASHBOARD_API_URL`, `NEXUS_DASHBOARD_API_USER`, `NEXUS_DASHBOARD_SKIP_VERIFICATION` |
| `nvaie` | ok | **`NVAIE_API_KEY`** |
| `redhat` | ok | **`REDHAT_PULL_SECRET`** |
| `kubernetes_service_account` | no_env_vars | none — `EmptyCredentialEnvsCreator`; namespace/service account are applied to the grain host instead |
| `github`, `github_enterprise`, `gitlab`, `gitlab_enterprise`, `gitlab_secrets_manager`, `bitbucket`, `bitbucket_server`, `azure`, `azure_enterprise`, `codecommit`, `cloudshell`, `artifactory` | unsupported | no creator is registered, so attaching one **kills the grain** |

The `unsupported` rows earn their place: without them a discovery probe would be sent at a
credential we already know will fail.

### Discovery, for a type not in the cache

One environment holding two baseline grains and one grain per unmeasured type:

```
grain_baseline_a   (no authentication)          -> names_0a
grain_baseline_b   (no authentication)          -> names_0b
grain_type_foo     (authentication: foo-cred)   -> names_1
grain_type_bar     (authentication: bar-cred)   -> names_2
```

Each grain prints `compgen -e` — **exported variable names only, never values**, so the
output is safe. A type's variables are `names_i - (names_0a ∩ names_0b)`, minus
`MGMT_SERVER_*` and `API_TOKEN`, which Torque injects per operation and which never belong to
a credential.

Two baselines rather than one because the environment also contains variables torque-tunnel
cannot enumerate — the compute service's own `RunnerSettings.EnvironmentVariables`, and the
members that `BaseShellStepper` expands out of `RUNNER_INPUTS`. Anything that varies between
two *identical* grains is excluded by construction, and anything constant cancels in the
subtraction. This is a controlled A/B on the same agent at the same moment, not a diff against
a baseline captured elsewhere.

Three details all come from watching this run against a live agent:

**Parallelism is capped at `DISCOVERY_MAX_PARALLEL_GRAINS` (4).** Grains with no
`depends-on` all deploy at once, and an agent's runner pool is finite — eight simultaneous
grains left two wedged in `Preparation: Executing` for over ten minutes. The type grains are
therefore chained into waves, with both baselines in the first wave where contention is
lowest, because a missing baseline invalidates the whole run.

**Results are read from each grain's own deploy log, not the environment's outputs.**
Environment-level outputs are published only once the *whole* environment settles, so a
single wedged runner would hide every finished grain's result. Each grain prints its answer
on a `TORQUE_TUNNEL::VARS=` line, assembled from two halves at runtime so the literal never
appears in the echoed script source and cannot match itself.

**Only successful measurements are ever cached.** A grain that produced nothing — failed or
still deploying — is omitted, so its type stays unmeasured and is retried later. Reading a
failed grain as "Torque has no env-var creator for this type" is tempting, because that is
exactly how such a type behaves, but a wedged runner fails identically and the result is
cached *permanently*. Observed live: `vsphere__basic`, used successfully throughout the same
session, was recorded `unsupported` after its grain wedged. Types Torque genuinely cannot
inject come from the seed instead, which is knowledge rather than inference.

The cost is that a genuinely new unsupported type is probed again on each attempt rather
than learned. It is refused either way — `prepare_credential` will not run a command whose
credential type it cannot redact — so the difference is a wasted probe, not a wrong answer.

A timeout is consequently not an error: whatever the finished grains measured is kept.

Waiting also stops early. Once no grain has changed state for `DISCOVERY_STALL_SECONDS`
(90) **and** both baselines are in, the rest is not coming, so the partial result is taken
rather than waiting out the 15-minute ceiling.

---

## 4. Caching

Two caches with genuinely different lifetimes, in `~/.torque-tunnel/credentials-cache.json`.

| cache | key | lifetime |
|---|---|---|
| credential list (name → type, cloud identifier, non-secret fields, allowed spaces) | `torque_url` + space | 24h; hard-refreshed by every `list_credentials` query; refreshed on demand when a `run_*` names a credential not in it |
| type → variable names | `torque_url` + `credential_data_type` | **permanent**; discovery runs only for a type absent from it |

The type cache can be permanent because a credential's type is immutable:
`UpdateCredentialRequestValidator` rejects a type change outright, `OverrideCredential`
persists the existing typed object, and names are unique per account
(`credential_store_item__account_id__name__uidx` on `(account_id, LOWER(name))`). The only way
a name's type changes is delete-and-recreate, which is rare and self-corrects on the next
query.

**Merge rule:** `effective = seed | user_cache`, the user side winning. A seed entry only ever
fills a gap; a measurement is never overwritten; types added to the seed in a later release
appear automatically for existing users.

`force_rediscover` on the query drops measured entries and re-measures, for the rare case
where a Torque upgrade changed a type's variables.

Writes are atomic (temp file + `os.replace`) and discovery is guarded by a lock file, because
the CLI flavour runs a fresh process per command and several can be in flight at once.

---

## 5. Spaces

Credential resolution is space-scoped in SQL:

```sql
WHERE account_id = @accountId AND lower(name) = lower(@credentialName)
  AND (space_id = @spaceId OR all_spaces_allowed = true OR @spaceId = ANY(allowed_spaces))
```

So an account credential restricted to certain spaces is invisible from anywhere else, and
Torque reports it as `does not exist` — which is misleading. torque-tunnel pre-flights this
and says which spaces the credential *is* allowed in.

`credentials_space_policy` decides what happens next:

- `preconfigured` (default) — fail with that message.
- `authorize` — add the profile's space to the credential's allowed list, then proceed.

Authorization happens **before** any type measurement. The probe environment launches in
this same space, so a credential not yet allowed here could not be attached to a probe grain
either. A type already known to be unusable is refused first, so nothing is widened for a
credential that could never work anyway.

The `authorize` write is safe to do without knowing the secret:
`UpdateCredentialRequestValidator` skips validation when `credential_data` is null and
`UpdateCredentialBase` uses `request.X ?? credential.X` throughout, so a minimal
`PUT {"allowed_space_names": [...existing..., "<space>"]}` preserves the secret, description,
cloud identifier and scopes. It requires `Account.ManageCredentials` and is audited. The list
is always read-modify-written — never sent partially — and the write is skipped entirely when
`all_spaces_allowed` is already true.

### Listing

`GET /api/spaces/{space}/settings/credentialstore/overridden_values` needs only
`Policy.SpaceAccess` and is already filtered to what is usable in that space. The
account-level `GET /api/settings/credentialstore` needs `Account.ManageCredentials` and is
**not** used for listing. Space-only credentials come from
`GET /api/spaces/{space}/settings/credentialstore`.

---

## 6. Carrying the variables to the command

Where the command actually runs differs per tool:

| tool | command runs | needs forwarding |
|---|---|---|
| disposable / local container | in the grain container | no — the variables are already there |
| persistent container | in a separate long-lived container, reached over SSH | yes |
| ssh | on the target host, reached over SSH | yes |

Forwarding is generated **inside the container** from its own environment, and prepended to
the remote script:

```bash
for __v in $__TT_FORWARD_VARS; do
  [ -n "${!__v+x}" ] && printf 'export %s=%q\n' "$__v" "${!__v}"
done >> "$REMOTE_SCRIPT"
```

`__TT_FORWARD_VARS` holds variable **names** only, so it is not a secret and passes through
the blueprint input as plain text.

Forwarded set:

- the credential's variables, from the cache;
- `MGMT_SERVER_*`, whenever present — this is the existing blueprint contract and is
  forwarded regardless of what the caller asked for;
- `credential_env_forward`, an explicit caller-supplied list, for overriding a cache entry;
- never `API_TOKEN` — it is runner-only and unusable downstream, and our blueprints declare no
  `api_access` so it is never present in the first place.

---

## 7. Keeping secrets out of the output

Torque has no log masking (`grep -r "Mask|Redact|Scrub"` over the server source returns
nothing), and `command_output` is returned to the caller *and* stored on the environment. So a
command that prints a secret leaks it in both places.

Before `command_output` is encoded, the grain replaces each secret value with `***`.

Which values are secret is known exactly, without a per-type table: **the credential API
returns non-secret fields populated and secret fields as `null`**. So the secret-bearing
variables are the credential's variables whose values torque-tunnel could not see.

Guards:

- values below a minimum length are skipped, so a field like `validate_certificate=false`
  cannot turn every `false` in the output into `***`; the grain reports which names it
  skipped;
- if none of the cached variables are actually set, the grain does **not** redact and says so
  — a stale cache becomes a visible error rather than a silent leak.

Running `env` is not forbidden. It is how a caller inspects an unmeasured type, and on a
development target it is harmless; redaction is what makes it safe where it matters.

---

## 8. Configuration

Both keys are ordinary config values in `CONFIG_KEY_MAP`, so they inherit through `extends`
and can be overridden per profile like any other setting. They are deliberately **not**
profile metadata (unlike `expose_values`), and the cache is deliberately **not**
configuration — a cache is a cache.

```yaml
credentials_enabled: false                  # default off; opt-in
credentials_space_policy: preconfigured     # preconfigured | authorize
```

Both are set from the setup UI, and both are surfaced by `list_profiles` regardless of
`expose_values`, since neither is a secret and the AI needs to know whether it may pass a
credential at all.

---

## 9. How this is tested

Beyond the unit and integration tests, two gates exist because of defects this feature
actually shipped:

**[`tests/test_credentials_handler_plumbing.py`](../tests/test_credentials_handler_plumbing.py)**
drives all six `run_*` handlers with a stubbed Torque, asserting for each that a call with
no credential still reaches Torque, that a credential on a disabled profile is refused, and
that a credential on an enabled profile yields a *credential* error rather than a plumbing
one. The credential call was threaded into six near-identical functions by hand; schema
tests cannot see a mistake in that, only invoking them can. A further test asserts the
covered set equals the live tool list, so a seventh execution tool cannot escape it.

**[`tests/test_static_analysis.py`](../tests/test_static_analysis.py)** runs pyflakes over
every Python file in the project and fails on anything except an explicit list of cosmetic
findings — so a check added by a future pyflakes release starts out enforced. pyflakes
rather than a hand-rolled AST walk specifically because it is scope-aware: the regression it
exists for was `handle_run_on_tunneled_ssh` passing `cfg`, a name five *other* handlers
define, so a flat walk collecting every assignment in the module would have called it
defined. The file includes a synthetic reproduction of that exact shape plus a test
asserting the flat-walk approach misses it, so the reasoning survives.

The same regression is also prevented structurally: all six handlers now resolve their
config into a local named `cfg`, and AST tests assert both that uniformity and that each
handler passes exactly that local to `_prepare_credential`. A copy-pasted plumbing line can
no longer be correct in five handlers and wrong in one.

## 10. What is deliberately not done

- **No `TORQUE_CRED_*` exported variables.** They would be a contract to break the day
  multi-credential support lands, and they would have needed the same mapping they were meant
  to replace.
- **No inference from `/proc/1/environ` or a shipped baseline.** The runner's own environment
  looks like a clean baseline and in one measurement it was — but the compute service's
  configured variables and the `RUNNER_INPUTS` expansion can both land in that difference, and
  neither is enumerable. Discovery uses a same-environment A/B instead.
- **No secret ever crosses this machine.** torque-tunnel passes credential *names*; Torque
  resolves the values inside the agent.
