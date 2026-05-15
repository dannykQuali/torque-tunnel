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
