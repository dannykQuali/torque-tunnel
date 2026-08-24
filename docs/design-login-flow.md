# Design: Interactive Login & Setup Flow

## Problem

Users configure `torque_url` but not `torque_token`, `torque_space`, or `torque_agent`.  
When they invoke a tool, instead of erroring, we want to guide them through login and selection.

## Verified API Surface

*All findings below confirmed via codebase inspection (C:\Work\cs2018) and live testing against review1/review2.*

### Login

| Endpoint | Body | Response | Notes |
|----------|------|----------|-------|
| `POST /api/accounts/login` | `{email, password}` | `Dict<account_alias, TokenResponse>` | Returns a token **per account** the user belongs to |
| `POST /api/accounts/{account}/login` | `{email, password}` | Single `TokenResponse` | Login to a specific account |

The generic endpoint calls `GetAllUserActiveAccounts(email)` internally, then logs in to each account.
This IS the account discovery mechanism — the dictionary keys are the account aliases.

**Verified live responses:**
```
review1: { "ZTP": { access_token: "...", ... } }          ← 1 account
review2: { "dannyk": { access_token: "...", ... } }       ← 1 account
```

### Spaces & Agents

| Endpoint | Response |
|----------|----------|
| `GET /api/accounts/user_spaces` | `[{name, color, icon}, ...]` — verified: 12 spaces on review1 |
| `GET /api/spaces/{space}/agents` | `[{name, type, status, create_date, agent_version, ...}, ...]` |

### Long Tokens

| Endpoint | Response | Notes |
|----------|----------|-------|
| `POST /api/long-token/{space}/longtoken?title=...` | `TokenResponse` with `expires_in: 2147483647` | **Space param is cosmetic — token is account-wide** |

**Critical finding from codebase:** The `{space_name}` route parameter is **completely ignored** in the controller. The long token is created at the account level with `GetLongAccessTokenAsync(user.Account, user.Email, user.Password)`. No space ID is stored — the `user_token` table only has `(id, user_id, token, created_at, title)`. A long token grants the same access as the user's session — all spaces the user has roles in.

**Verified live:** Generated long token via `shell-cmd` space, then used it to list all 12 spaces successfully.

## Permissions Assumption: Account Admin

torque-tunnel **assumes the Torque user account used during setup has account-admin-level
permissions.** Non-admin accounts have never been tested or used with torque-tunnel, and
various parts of the flow will fail for them. Supporting non-admin users is a valid scenario,
but it is explicitly **left for the future**.

**Required capabilities per endpoint** (verified in cs2018):

| Endpoint | Scope | Required capability |
|----------|-------|---------------------|
| `GET /api/settings/agents` | Account | `ManageCloudAccounts` |
| `POST /api/spaces` | Account | `ManageSpaces` |
| `POST /api/spaces/{space}/agents/{agent}` | Account | `ManageCloudAccounts` |
| `GET /api/accounts/user_spaces` | Space | space access only |
| `GET /api/spaces/{space}/agents` | Space | space access only |

The setup flow is **agent-first** (see [Login Flow v4](#login-flow-v4-agent-first-with-a-dedicated-space)),
listing agents account-wide (`GET /api/settings/agents`) and creating a `torque-tunnel` space
with the chosen agent associated to it. All three of those steps go through the admin-only
endpoints above, so the flow is admin-only by construction. The space-scoped endpoints are the
only parts a non-admin could use today.

A future enhancement could probe the account agent list and fall back to the space-first flow
when it returns `403`. That is deliberately **out of scope for now**.

## Architecture

```
┌──────────┐    stdio    ┌───────────────────┐    HTTP    ┌──────────────┐
│ VS Code  │ ◄─────────► │   MCP Server      │ ◄────────► │  Torque API  │
│ (AI)     │             │   (mcp_tool.py)   │           │ (torque_url) │
└──────────┘             │                   │           └──────────────┘
                         │  ┌──────────────┐ │
                         │  │ Local HTTP    │ │
                         │  │ Auth Server   │ │ ◄──────── Browser
                         │  │ (localhost:P) │ │
                         │  └──────────────┘ │
                         └───────────────────┘
```

The MCP server embeds a temporary local HTTP server that serves a login/selection UI in the browser. All API calls to Torque are proxied through this local server (bypasses CORS). The browser never talks to Torque directly.

## Flow

### Phase 1: Login

```
User invokes `login` tool/command
    │
    ├── torque_url configured? ──No──► Error: "Set torque_url first"
    │
    ├── torque_token configured? ──Yes──► Skip to Phase 3 (space selection)
    │
    ▼
Start local HTTP server on random port (127.0.0.1 only)
Open browser to http://localhost:{port}/
    │
    ▼
Browser shows login page with two sections:
    │
    ├── [Email + Password form]
    │     Form POSTs to localhost:{port}/api/login
    │     Local server proxies to {torque_url}/api/accounts/login
    │     Response: Dict<account_alias, TokenResponse>
    │     → If 1 account: auto-select, proceed
    │     → If N accounts: show account selector (Phase 2)
    │
    └── [I already have a token] (expandable section)
          Paste field → validated via GET /api/accounts/user_spaces
          If valid → skip to Phase 3
```

**SSO users:** Cannot proxy SSO redirects (IDP callback URLs are registered to `torque_url`, not localhost). SSO users should login on Torque's website, then either:
- Paste their short-lived token (from browser localStorage/DevTools)
- Generate a long token from Torque Settings → API Tokens and paste it

### Phase 2: Account Selection

```
Generic login returned Dict<alias, TokenResponse>
    │
    ├── 1 account  ──► Auto-select, use its token
    └── N accounts ──► Show account picker in browser
          User picks → use that account's token
```

No additional API call needed — the generic login already provides tokens for all accounts.

### Phase 3: Space Selection

```
Have access_token (short-lived or pasted)?
    │
    ├── torque_space already configured?
    │     Validate via GET /api/accounts/user_spaces
    │     ├── Exists ──► Skip to Phase 4
    │     └── Not found ──► Show selector
    │
    ▼
GET /api/accounts/user_spaces → [{name, color, icon}, ...]
    │
    ├── 0 spaces ──► Error: "No spaces available for this account"
    ├── 1 space  ──► Auto-select
    └── N spaces ──► Show space selector in browser
```

### Phase 4: Agent Selection

```
Have space selected?
    │
    ├── torque_agent already configured?
    │     Validate via GET /api/spaces/{space}/agents
    │     ├── Exists & active ──► Skip to Phase 5
    │     └── Not found ──► Show selector
    │
    ▼
GET /api/spaces/{space}/agents → [{name, type, status, ...}, ...]
Filter to status == "active" only
    │
    ├── 0 active agents ──► Warning: "No active agents in this space"
    │                       Allow proceeding without agent (some tools don't need it)
    ├── 1 active agent  ──► Auto-select
    └── N active agents ──► Show agent selector in browser
```

### Phase 5: Long Token Generation & Save

```
Have account token + space + agent?
    │
    ├── User pasted a long token (expires_in == 2147483647)? ──► Skip generation
    │
    ▼
POST /api/long-token/{space}/longtoken?title=torque-tunnel-{hostname}-{date}
    → TokenResponse with long-lived access_token (expires_in: 2147483647)
    │
    ▼
Save to config.yaml:
    ├── If --profile specified → update that profile's section
    ├── Else → update top-level defaults
    │
    Keys written:
    │   torque_token: <long_token>
    │   torque_space: <selected_space>
    │   torque_agent: <selected_agent>   (if selected)
    │
    ▼
Reload config in MCP server
Browser shows "Setup complete! You can close this tab."
Local HTTP server shuts down
Return success message to AI with summary
```

## Integration Points

### New MCP Tool: `login`

```python
Tool(
    name="login",
    description="Interactively login to Torque and configure space/agent. "
                "Opens a browser window for authentication.",
    inputSchema={
        "type": "object",
        "properties": {
            "torque_url": {
                "type": "string",
                "description": "Torque URL (if not already configured)",
            },
        },
    },
)
```

### New CLI Command: `torque-tunnel login`

```bash
torque-tunnel login                          # uses configured torque_url
torque-tunnel login --torque-url https://...  # explicit URL
torque-tunnel login --profile cisco-review1   # login for specific profile
```

### Automatic Trigger on Missing Token

In each tool handler (`handle_run_on_tunneled_ssh`, etc.), where we currently return:
```
"Error: Torque configuration missing. Need torque_url, torque_token, and torque_space"
```

Change to:
```
if torque_url and not torque_token:
    # Return guidance instead of hard error
    return "Torque token not configured. Use the 'login' tool to authenticate, 
            or set torque_token in your config/profile."
```

We do **not** auto-trigger the login flow from within a tool call because:
1. It would block the tool for an unpredictable time
2. The AI should decide whether to invoke `login` based on the error message
3. Keeps tool behavior predictable

## New Module: `auth.py`

```
src/torque_tunnel/auth.py
    class TorqueAuthServer:
        """Temporary local HTTP server for browser-based login flow."""
        
        - start(torque_url, port=0) → actual_port
        - wait_for_completion(timeout=300) → AuthResult
        - stop()
        
    @dataclass
    class AuthResult:
        token: str           # long-lived token
        space: str           # selected space
        agent: str           # selected agent
        account: str | None  # account name (if discovered)
```

### Local Server Endpoints

| Method | Path | Proxies to | Purpose |
|--------|------|-----------|---------|
| GET | `/` | — | Login/setup SPA (HTML/JS) |
| POST | `/api/login` | `POST {torque_url}/api/accounts/login` | Email/password → dict of account tokens |
| POST | `/api/validate-token` | `GET {torque_url}/api/accounts/user_spaces` | Validate pasted token |
| GET | `/api/spaces` | `GET {torque_url}/api/accounts/user_spaces` | List spaces for the selected account |
| GET | `/api/spaces/{space}/agents` | `GET {torque_url}/api/spaces/{space}/agents` | List agents in space |
| POST | `/api/generate-token` | `POST {torque_url}/api/long-token/{space}/longtoken?title=...` | Generate long-lived token |
| POST | `/api/complete` | — | Save selections to config.yaml + signal completion |
| GET | `/health` | — | Check server is alive (for MCP polling) |

### HTML/JS UI

Single-page app served from Python (embedded as string or template). Steps:

1. **Login card** — email, password, account (optional), OR token paste
2. **Space selector** — dropdown/list populated from API
3. **Agent selector** — dropdown/list filtered by selected space
4. **Confirmation** — summary of what will be saved, "Save & Finish" button
5. **Done** — "Setup complete" message

Minimal CSS (no framework dependency). All JavaScript is vanilla (no build step).

## Config File Updates

When saving, the module should:

1. **Read** the current `config.yaml` (preserve comments if using `ruamel.yaml`, otherwise `pyyaml` will strip them)
2. **Update** only the relevant keys:
   - If a profile is active → update that profile's section
   - Otherwise → update top-level keys
3. **Write** back with UTF-8 encoding

### Example: Before login

```yaml
torque_url: https://review1.qualilabs.net
default_profile: cisco-review1

profiles:
  cisco-review1:
    description: "Cisco Review1"
    host: 10.91.36.240
    ssh_key: "C:\\ZeroTouch\\torque dannyk private key.pem"
    ssh_user: root
```

### Example: After login

```yaml
torque_url: https://review1.qualilabs.net
torque_token: <generated-long-token>
torque_token_id: 77d38eb4-4b4f-4401-85b8-e517038ce23c  # allows safe revocation on re-login
torque_space: shell-cmd
torque_agent: my-agent
default_profile: cisco-review1

profiles:
  cisco-review1:
    description: "Cisco Review1"
    host: 10.91.36.240
    ssh_key: "C:\\ZeroTouch\\torque dannyk private key.pem"
    ssh_user: root
```

Or if the login was profile-specific:

```yaml
torque_url: https://review1.qualilabs.net
default_profile: cisco-review1

profiles:
  cisco-review1:
    description: "Cisco Review1"
    torque_token: <generated-long-token>
    torque_token_id: 77d38eb4-4b4f-4401-85b8-e517038ce23c
    torque_space: shell-cmd
    torque_agent: my-agent
    host: 10.91.36.240
    ssh_key: "C:\\ZeroTouch\\torque dannyk private key.pem"
    ssh_user: root
```

## Skip Logic

| Configured | Action |
|-----------|--------|
| Nothing (no `torque_url`) | Full flow: URL selection → login → space → agent → confirm → save |
| `torque_url` only | Login → space → agent → confirm → save (URL step skipped) |
| `torque_url` + `torque_token` | Skip login, go to space selection |
| `torque_url` + `torque_token` + `torque_space` | Skip to agent selection |
| `torque_url` + `torque_token` + `torque_space` + `torque_agent` | Already complete — "nothing to do" |

The flow should validate configured values against the API:
- If `torque_space` is set but doesn't exist in user_spaces → show space selector
- If `torque_agent` is set but doesn't exist in the space → show agent selector

## Resolved Questions

1. **Generic login response:** `Dict<account_alias, TokenResponse>` — each key is an account alias the user belongs to, each value is a short-lived token for that account. ✅ Confirmed via codebase + live test.

2. **Account selection:** The generic login IS the account discovery. Dict keys = accounts, values = tokens. If 1 account → auto-select. If N → show picker. No separate "list accounts" endpoint needed.

3. **Long token scope:** Account-wide. The `{space_name}` in the URL is cosmetic (controller ignores it). Token grants access to all spaces the user has roles in. ✅ Confirmed: generated token via `shell-cmd`, accessed all 12 spaces.

4. **Token title convention:** `torque-tunnel-{hostname}-{YYYYMMDD}` — stored in `user_token.title` for display only.

## Open Questions — Decided

1. **Comment preservation in YAML:** → **Use `ruamel.yaml`**. Easy win — preserves user comments in config.yaml during write-back. Heavier than pyyaml (~300KB) but worth it for round-trip safety.

2. **Token rotation:** → **Store `torque_token_id` alongside `torque_token`**. On re-login: if `torque_token_id` present → we generated it → revoke old token before generating new one. If only `torque_token` (no ID) → user-managed → overwrite token, leave old one alive. The title pattern `torque-tunnel-{hostname}-{date}` also helps identify our tokens.

3. **Profile-scoped login:** → Yes. `login --profile X` resolves `torque_url` from the profile chain and saves results into that profile section.

4. **Async HTTP server library:** → **Use `aiohttp`**. Clean async server with routing, JSON parsing, graceful shutdown out of the box. Built-in `http.server` is synchronous and would require ugly threading + asyncio mixing to achieve the same. Project already uses `httpx` so not dependency-shy.

## Dependencies

- **`aiohttp`** — async local HTTP server for the login UI
- **`ruamel.yaml`** — round-trip YAML parsing that preserves comments
- No new frontend dependencies — vanilla HTML/CSS/JS

## Security Considerations

- Local HTTP server binds to `127.0.0.1` only (not `0.0.0.0`)
- Server shuts down immediately after completion or timeout
- Credentials (email/password) travel: browser → localhost → Torque API (all local or HTTPS)
- The AI never sees the password (it flows through the browser directly to our local server)
- Long tokens are stored in `config.yaml` (same security posture as current manual config)
- CSRF protection: generate a random state token, verify on completion

## Implementation Plan

1. Add `aiohttp` + `ruamel.yaml` dependencies
2. `config.py` — add `update_config_file()` using ruamel.yaml for round-trip write-back; add `torque_token_id` to known keys
3. `auth.py` — `TorqueAuthServer` class with aiohttp; login page HTML/JS embedded; proxy endpoints; completion signaling
4. `mcp_tool.py` — `login` MCP tool + `torque-tunnel login` CLI command; update error messages in tool handlers
5. Tests — config write-back tests; auth server unit tests (mock HTTP); integration tests
6. `docs/configuration.md` — document login command and flow

---

## Login Flow v2 Changes

### URL Selection Step (new first step)

When `torque_url` is not provided (no CLI arg, no profile, no config), the UI now shows a URL selection step:
- Dropdown with presets: `portal.qtorque.io`, `jarvis.qtorque.io`, `review1/2/3.qualilabs.net`
- Custom URL free-text input option
- When `torque_url` IS provided, this step is skipped (as before)
- `TorqueAuthServer.__init__` accepts `torque_url=None` — the JS sends URL via `/api/login` and `/api/validate-token` body
- The server's `torque_url` is updated on first login/validate call for subsequent space/agent/token API calls

### Always Save to Profile

All configuration is now saved under a named profile (never root-level):
- UI shows a profile name input in the confirm step (pre-filled with derived name from URL hostname, e.g. `portal`, `jarvis`, `review1`)
- Profile name is required — `/api/complete` returns 400 if missing
- The `profile_name` is sent from JS in the complete request body

### `torque_url` Always Saved

`_handle_complete` now includes `torque_url` in the updates dict, so the profile is self-contained:
```yaml
profiles:
  review1:
    torque_url: https://review1.qualilabs.net
    torque_token: <token>
    torque_space: my-space
    torque_agent: my-agent
```

### Description Field

The confirm step includes an optional description textarea with placeholder guiding the user to describe:
- Network/proxy requirements
- Host machine or location
- Purpose (dev, staging, production)

Saved as `description` key in the profile.

### Proxy init_commands (auto-detected)

When an agent is selected, the JS extracts proxy environment variables from the agent's `additional_details.runner_settings.environment_variables`:
- Only proxy vars: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase equivalents)
- Formatted as `export KEY=VALUE; export KEY2=VALUE2; ...`
- Saved as `init_commands` in the profile
- Both account-level and space-level agent APIs return `additional_details`

### XSS Prevention

Template variables (`{{TORQUE_URL}}`, `{{CSRF_TOKEN}}`, `{{PROFILE_NAME}}`) are now escaped via `_js_string_escape()` before embedding in the HTML template, preventing injection if values contain quotes, backslashes, or HTML tags.

---

## Login Flow v3: Sign in with Cisco ID (SSO)

### How Cisco ID works in Torque (verified in cs2018 / cs2018-ui)

Torque's "Sign In with Cisco ID" button navigates the browser to
`GET {torque}/api/accounts/idp_login/Cisco` (`IdentityProviderController`). The backend
runs an OIDC Authorization Code + PKCE flow against `https://id.cisco.com/oauth2/default`
(`CiscoIdentityProvider.cs`) and receives the callback on a **hardcoded**
`{torque-host}/api/accounts/idp-callback` (pre-registered with Cisco's IdP client).
The resulting Torque token is **not** returned as JSON. Instead the backend sets a
one-shot, non-HttpOnly cookie on the Torque domain and 302s to the UI root:

- `loginResponse` — single account: JSON `{access_token, refresh_token, token_type, expires_in}`
- `loginMultiAccountResponse` — multiple accounts: JSON `Dict<account_alias, TokenResponse>`
  (same shape as `POST /api/accounts/login`)

The Torque SPA moves the cookie into `localStorage` (same key names) on boot and deletes it.

**Constraints that shaped the design:**
- `redirect_uri` is derived from the request Host and registered with Cisco — it can never
  point at `127.0.0.1`, so our local auth server cannot receive the OIDC callback.
- There is no device-code or polling flow in the Torque backend.
- The token therefore only ever materializes inside a browser on the Torque origin.

### torque-tunnel approach: temporary DevTools-controlled browser

`src/torque_tunnel/sso_browser.py` launches the user's Edge/Chrome with a **throwaway
profile** and `--remote-debugging-port=0`, pointed at `{torque}/api/accounts/idp_login/Cisco`.
The user completes the normal Cisco ID (+ Duo) sign-in in that window. Meanwhile the
local server polls the browser over the Chrome DevTools Protocol (plain aiohttp
websocket — no new dependencies):

1. Wait for `DevToolsActivePort` in the temp profile dir (real port of the ephemeral debug endpoint).
2. Every second, `GET http://127.0.0.1:{port}/json/list` and pick page targets on the Torque origin.
3. `Runtime.evaluate` on those pages: read `localStorage.loginResponse` /
   `localStorage.loginMultiAccountResponse` and `document.cookie` (covers the race
   window before the SPA consumes the cookie).
4. Detect failure: a Torque-origin page landing on `/ssoerror` or `/error`, the browser
   window being closed, or a timeout (default 10 min).
5. On success: close the browser, delete the temp profile, hand the token(s) to the
   setup page — which continues through the **existing** account → space → agent →
   long-token → save steps unchanged.

### Capability probe

The "Sign in with Cisco ID" button is only shown when the target instance supports it.
Probe: `GET {torque}/api/accounts/idp_login/Cisco` **without following redirects** —
supported means a 30x redirect whose `Location` carries a non-empty `client_id`.
(The production UI's visibility logic isn't reusable: it renders the Cisco button
unconditionally once `/api/about` loads.)

In addition, a small denylist (`_CISCO_SSO_DISABLED_HOSTS`) suppresses the button on
hosts where Cisco ID must not be offered regardless of what the probe says — currently
`portal.qtorque.io` (the public Quali SaaS portal). Denylisted hosts are rejected
without any network call.

### New local-server endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/sso-options?torque_url=...` | Capability probe → `{cisco_sso: bool}` |
| POST | `/api/sso-start` | Launch the SSO browser session (CSRF-protected) |
| GET | `/api/sso-status` | Poll: `pending` / `success` (+`token` or `accounts`) / `error` / `cancelled` / `none`; always includes the session's `torque_url` |
| POST | `/api/sso-cancel` | Abort: close browser, delete temp profile (CSRF-protected) |

Starting a new SSO attempt cancels any previous one; the setup server's `run()` also
cancels a dangling session on completion/cancel/timeout so no browser outlives setup.

**URL binding:** an SSO attempt is bound to the `torque_url` it was started for.
Navigating away from the login step (e.g. Back) while a sign-in is in flight aborts it
and closes the temporary browser — a login started for one URL must not complete after
the user switched to another. As defense in depth, `sso-status` reports the session's
`torque_url` and the page adopts it on success, so the harvested token, the
space/agent/long-token API calls, and the saved profile always refer to the same instance.

### Notes & trade-offs

- **Fresh profile every time**: the throwaway profile has no existing Cisco session, so the
  user does a full Cisco ID + Duo login each time. This is the price of being able to
  harvest the token; it also guarantees no interference with the user's real browser profile.
- **Browser discovery** (in order): the `TORQUE_TUNNEL_SSO_BROWSER` environment variable
  (path to an executable) → the **OS-default browser**, when it is Chromium-based
  (Edge/Chrome/Brave/Vivaldi/Opera/Chromium; detected via the Windows `https` UserChoice
  registry key, macOS LaunchServices plist, or `xdg-settings` on Linux) → well-known
  install locations → `PATH`. Firefox/Safari can't be used (different debugging protocol).
  If no Chromium-based browser is found, the UI shows an error; the email/password and
  paste-token paths remain available.
- **Security**: the DevTools port binds to 127.0.0.1 and lives only for the duration of the
  sign-in; the temp profile (which briefly holds the session) is deleted immediately after.
  The harvested short token flows through the same localhost channel as password login.

---

## Login Flow v4: Agent-first with a dedicated space

### Problem

torque-tunnel launches a Torque environment for every tunneled command. Pointed at whatever
space the user already had, those environments accumulate in a space that is also used for
real work — noisy at best, confusing at worst. The old flow made this the *default*: it asked
for a space first, then filtered agents down to that space.

### Decision

Steer every new profile into a **dedicated space** (default name `torque-tunnel`), created on
demand and associated with the chosen agent. Selection is **agent-first**: the agent is the
scarce, physically-meaningful resource (it determines network reachability); the space is
bookkeeping we can create for free.

### Flow

```
Authenticated (short token, or a reused profile token)
    │
    ▼
Step "space" (agent mode — the default)
    GET /api/accounts/user_spaces   → state.allSpaces
    GET /api/settings/agents        → state.allAgents  (admin-only; errors shown in the UI)
    │
    │  Filters: "Online only" ON, "With spaces only" OFF
    │  (space-less agents are valid now — the new space is what fixes them)
    │
    ├── [Choose by space instead] ──► legacy space-first path, unchanged
    │
    ▼  pick an agent
Step "agent-space"  — shown for EVERY agent, no auto-skip
    │
    ├── (default) Create a new space  [torque-tunnel]
    │      name not in allSpaces → "Agent <name> will be automatically allowed
    │                               in this space."
    │      name IS in allSpaces  → "Space '<name>' already exists — it will be
    │                               used, and the agent will be allowed in it."
    │      empty name → inline error on Continue
    │
    └── Use an existing space
           every space from user_spaces, badged "agent already allowed"
           where the space is in agent.spaces
    │
    ▼  Continue  →  state.createSpace / state.needsAssociation
Step "confirm"
    Space row: "<name> (will be created)"          when createSpace
    Agent row: "<name> (will be allowed in space)" when needsAssociation
    │
    ▼  Save & Finish
POST /api/ensure-space      ← only when createSpace || needsAssociation
POST /api/generate-token
POST /api/complete
```

On an `ensure-space` failure the error is shown in the confirm step and the button is
re-enabled, so the user can go **Back** and pick an existing space instead. The realistic
failures are `LICENSE_SPACES_LIMIT_REACHED` (403, account is out of space quota — verified
live on jarvis) and a non-admin token being refused.

### Endpoint: `POST /api/ensure-space`

CSRF-protected like every other POST. Makes the chosen space exist and the chosen agent usable
in it — **idempotently**, so a retry after a partial failure is harmless.

```
Request:  {"token": <short-or-long bearer>, "space": <name>,
           "agent": <name|null>, "agent_type": <"k8s"|"vcenter"|...|null>}
Response: {"space_created": <bool>, "agent_associated": <bool>}   200
Error:    {"error": "<Torque's message>", ...}                    Torque's status
```

Both flags are `false` when everything already existed. Steps:

1. `GET /api/accounts/user_spaces` — if `space` is listed, nothing to create.
2. Otherwise `POST /api/spaces` with `{"name": space, "icon": "flow", "color": "midnightBlue"}`.
   A `TAKEN_SPACE_NAME` **422** means someone else won the race → treated as success
   (`space_created: false`). Any other failure propagates Torque's message and status.
3. With an agent: `GET /api/executionhosts/{agent}/spaces`. If `space` is already among
   `space-associations[].space_name`, done.
4. Otherwise `POST /api/spaces/{space}/agents/{agent}` with a type-dependent body.
   A `SPACE_ASSOCIATION_ALREADY_EXIST` **422** is treated as success (race-safe).

Space and agent names are percent-encoded per path segment — Torque space names may contain
spaces. Every Torque call uses the same ~15s timeout as the other proxy handlers, and any
unexpected exception still returns a JSON `{"error": ...}` body rather than a bare 500.

#### Association body per agent type

| Agent type | Body | Why |
|-----------|------|-----|
| `vcenter`, `docker`, anything non-k8s | `{}` | Torque deserializes an empty body into default `InfraSettings` |
| `k8s` | `{"namespace", "service_account", "internet_facing"}` | k8s associations are namespace-scoped |

**Resolving the k8s spec** (in order):

1. **Copy from an existing association.** The first entry of
   `GET /api/executionhosts/{agent}/spaces` that carries both `namespace` and
   `service_account`. `internet_facing` is then read from that space's
   `GET /api/spaces/{that_space}/agents` → the agent's `spec.internet_facing`;
   any failure there defaults it to `false`.
2. **Discover, for a never-associated agent.**
   `GET /api/executionhosts/k8s/{agent}/agent/namespaces` → `{"namespaces": [...]}`.
   Prefer the agent's own `additional_details.agent_namespace` (looked up via
   `GET /api/settings/agents`) when it appears in that list, else the first namespace.
   Then `GET .../namespaces/{ns}/serviceaccounts` → `{"serviceAccounts": [...]}`, first entry.
   `internet_facing` defaults to `false`.
3. **Give up loudly.** If neither yields a namespace *and* a service account, return **422**
   with a message telling the user to associate the agent with a space once in the Torque UI —
   never guess, since a wrong namespace produces an agent that fails at runtime.

### What deliberately did not change

- The **space-first path** (mode toggle → space list → agents of that space → confirm) is
  untouched, including its auto-select-single-agent behaviour. It sets
  `createSpace = needsAssociation = false`, so it never calls `ensure-space`.
- Auto-selecting a lone space still happens, but only when the user actively toggles into
  space-first mode — it must not short-circuit the agent-first default.
- Long-token generation, config write-back, the heartbeat/cancel lifecycle, and the SSO flow
  are all unchanged.

## Error Responses Are Always JSON (error middleware)

**Problem observed:** connecting to `https://localhost` (self-signed cert) made
`_handle_login`'s outbound httpx call raise `httpx.ConnectError` — unhandled, so aiohttp
answered with its default `text/plain` body `500 Internal Server Error\n\nServer got itself
in trouble`. The browser JS did `await resp.json()` *before* checking `resp.ok`, so
`JSON.parse` consumed `500` as a number and choked on the `I` — surfacing the useless
*"Network error: Unexpected non-whitespace character after JSON at position 4"*.

**Fix (server):** `TorqueAuthServer._error_middleware` wraps every handler:

| Escaped exception | Response |
|---|---|
| `web.HTTPException` | re-raised unchanged (deliberate 403/404/...) |
| `json.JSONDecodeError` | **400** `{"error": "Invalid JSON in request body"}` |
| `httpx.HTTPError` | **502** `{"error": <friendly message>}` (logged to stderr) |
| anything else | **500** `{"error": "Internal error: ..."}` + traceback to stderr |

`_friendly_httpx_error()` translates transport failures: `CERTIFICATE_VERIFY_FAILED` →
"TLS certificate of <url> is not trusted (self-signed certificates are not supported)";
timeouts and plain connect failures get similarly readable messages with the target URL.
Self-signed Torque instances are deliberately **not** supported (no `verify=False` anywhere).

**Fix (client):** every `resp.json()` in `login_page.html` is now
`resp.json().catch(() => null)` and error branches render via `apiErrText(body, status)`,
so a non-JSON body can never throw past the `resp.ok` check. A repo test
(`tests/test_auth_error_middleware.py::TestLoginPageJsonParsing`) enforces this invariant —
any new bare `.json()` call fails CI.
