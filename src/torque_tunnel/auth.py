"""Browser-based login flow for Torque authentication.

Starts a temporary local HTTP server that serves a login/setup UI.
The browser handles user interaction (email/password, account/space/agent selection).
All Torque API calls are proxied through the local server to bypass CORS.
"""

import asyncio
import pathlib
import platform
import secrets
import sys
import time
import urllib.parse
import webbrowser
from typing import Optional

import httpx
from aiohttp import web

from . import config as config_module
from . import sso_browser

# Long token never-expire sentinel (Int32.MaxValue from Torque)
_LONG_TOKEN_EXPIRES = 2147483647

# Look of the space auto-created by the setup flow
_NEW_SPACE_ICON = "flow"
_NEW_SPACE_COLOR = "midnightBlue"

# Torque error codes that mean "the thing already exists" — i.e. success for us
_CODE_TAKEN_SPACE_NAME = "TAKEN_SPACE_NAME"
_CODE_ASSOCIATION_EXISTS = "SPACE_ASSOCIATION_ALREADY_EXIST"


_PROFILE_RESULT_META_KEYS = {"description", "extends", "expose_values"}


def _build_profile_result(profile_name: str, updates: dict, *, is_default: bool = False) -> dict:
    """Build a profile result dict in the same shape as config_module.list_profiles entries.

    Returns dict with keys: 'name', 'description', 'extends', 'overrides',
    'expose_values', 'values', 'is_default'.
    """
    override_keys = sorted(k for k in updates if k not in _PROFILE_RESULT_META_KEYS)
    return {
        "name": profile_name,
        "description": updates.get("description", ""),
        "extends": updates.get("extends"),
        "overrides": override_keys,
        "expose_values": updates.get("expose_values", False),
        "values": {k: updates[k] for k in override_keys},
        "is_default": is_default,
    }


def _q(value: str) -> str:
    """Percent-encode a single Torque path segment (space/agent names may have spaces)."""
    return urllib.parse.quote(str(value), safe="")


def _torque_errors(resp) -> list[dict]:
    """Extract Torque's `errors` array from a response, tolerating any body shape."""
    try:
        body = resp.json()
    except Exception:
        return []
    if not isinstance(body, dict):
        return []
    errors = body.get("errors")
    if not isinstance(errors, list):
        return []
    return [e for e in errors if isinstance(e, dict)]


def _torque_error_codes(resp) -> set[str]:
    """Return the set of Torque error codes present in a response body."""
    return {str(e.get("code")) for e in _torque_errors(resp) if e.get("code")}


def _torque_error_message(resp) -> str:
    """Best-effort human-readable message for a failed Torque response."""
    for e in _torque_errors(resp):
        msg = e.get("message") or e.get("name")
        if msg:
            return str(msg)
    text = (getattr(resp, "text", "") or "").strip()
    if text:
        return text[:500]
    return f"HTTP {resp.status_code}"


def _name_list(payload, key: str) -> list[str]:
    """Extract a list of names from a Torque list-response.

    Handles `{"<key>": ["a", "b"]}` (what the k8s namespace/service-account
    endpoints actually return), a bare list, and list entries that are objects
    with a `name` field.
    """
    items = None
    if isinstance(payload, dict):
        items = payload.get(key)
        if items is None:
            # Tolerate a different casing/spelling of the wrapper key
            for value in payload.values():
                if isinstance(value, list):
                    items = value
                    break
    elif isinstance(payload, list):
        items = payload

    names: list[str] = []
    for item in items or []:
        if isinstance(item, str):
            if item:
                names.append(item)
        elif isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return names


class _EnsureSpaceError(Exception):
    """A Torque call in the ensure-space flow failed; carries the HTTP status."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        # 5xx from Torque would be confusing as our own status; keep 4xx/5xx as-is
        self.status = status if 400 <= status <= 599 else 502


def _js_string_escape(s: str) -> str:
    """Escape a string for safe embedding in a JavaScript string literal."""
    return (s
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("<", "\\x3c")
            .replace(">", "\\x3e"))


def _login_page_html(torque_url: str, csrf_token: str, profile_name: str) -> str:
    """Return the login/setup single-page app HTML."""
    return (_LOGIN_HTML
            .replace("{{TORQUE_URL}}", _js_string_escape(torque_url))
            .replace("{{CSRF_TOKEN}}", _js_string_escape(csrf_token))
            .replace("{{PROFILE_NAME}}", _js_string_escape(profile_name)))


class TorqueAuthServer:
    """Temporary local HTTP server for browser-based Torque login.

    Usage:
        server = TorqueAuthServer(torque_url)
        result = await server.run()  # opens browser, waits for completion
    """

    def __init__(
        self,
        torque_url: Optional[str] = None,
        config_path: Optional[str] = None,
        profile_name: Optional[str] = None,
        timeout: int = 1800,
        sso_session_factory=None,
    ):
        self.torque_url = torque_url.rstrip("/") if torque_url else ""
        self.config_path = config_path
        self.profile_name = profile_name or ""
        self.timeout = timeout
        self._sso_session_factory = sso_session_factory or sso_browser.CiscoSsoSession
        self._sso_session = None
        self._csrf_token = secrets.token_urlsafe(32)
        self._url_secret = secrets.token_urlsafe(16)
        self._result: Optional[dict] = None
        self._completed = asyncio.Event()
        self._cancelled = False
        self._last_heartbeat: float = 0.0
        self._heartbeat_stale_seconds: float = 30.0
        self._heartbeat_check_interval: float = 5.0
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None

    async def run(self) -> Optional[dict]:
        """Start server, open browser, wait for user to complete, return result.

        Returns a profile dict (same shape as config_module.list_profiles entries)
        or None if the user cancelled.
        """
        self._app = self._create_app()
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        # Read back the actual port assigned by the OS (ephemeral range, always browser-safe)
        port = site._server.sockets[0].getsockname()[1]
        self._last_heartbeat = time.monotonic()

        url = f"http://127.0.0.1:{port}/{self._url_secret}"
        print(f"Opening browser for Torque setup: {url}", file=sys.stderr)
        webbrowser.open(url)

        try:
            await asyncio.wait_for(
                self._wait_for_completion(), timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Setup flow timed out after {self.timeout}s. "
                "Please try again with 'setup' tool."
            )
        finally:
            await self.cleanup_sso()
            await self._runner.cleanup()

        if self._cancelled:
            return None
        return self._result

    async def _wait_for_completion(self) -> None:
        """Wait for completion or cancellation, checking heartbeat periodically."""
        while True:
            try:
                await asyncio.wait_for(self._completed.wait(), timeout=self._heartbeat_check_interval)
                return  # completed or cancelled
            except asyncio.TimeoutError:
                pass  # check heartbeat
            # If browser tab was closed, heartbeat stops
            if self._last_heartbeat and (
                time.monotonic() - self._last_heartbeat > self._heartbeat_stale_seconds
            ):
                self._cancelled = True
                self._completed.set()
                print("Browser tab closed — setup cancelled.", file=sys.stderr)
                return

    def _create_app(self) -> web.Application:
        app = web.Application()
        s = self._url_secret
        app.router.add_get(f"/{s}", self._handle_page)
        app.router.add_get(f"/{s}/health", self._handle_health)
        app.router.add_post(f"/{s}/api/login", self._handle_login)
        app.router.add_post(f"/{s}/api/validate-token", self._handle_validate_token)
        app.router.add_get(f"/{s}/api/spaces", self._handle_list_spaces)
        app.router.add_get(f"/{s}/api/spaces/{{space}}/agents", self._handle_list_agents)
        app.router.add_get(f"/{s}/api/agents", self._handle_list_all_agents)
        app.router.add_post(f"/{s}/api/ensure-space", self._handle_ensure_space)
        app.router.add_post(f"/{s}/api/generate-token", self._handle_generate_token)
        app.router.add_post(f"/{s}/api/complete", self._handle_complete)
        app.router.add_post(f"/{s}/api/cancel", self._handle_cancel)
        app.router.add_get(f"/{s}/api/profiles", self._handle_list_profiles)
        app.router.add_post(f"/{s}/api/use-profile", self._handle_use_profile)
        app.router.add_get(f"/{s}/api/sso-options", self._handle_sso_options)
        app.router.add_post(f"/{s}/api/sso-start", self._handle_sso_start)
        app.router.add_get(f"/{s}/api/sso-status", self._handle_sso_status)
        app.router.add_post(f"/{s}/api/sso-cancel", self._handle_sso_cancel)
        return app

    def _check_csrf(self, request: web.Request) -> None:
        token = request.headers.get("X-CSRF-Token", "")
        if not secrets.compare_digest(token, self._csrf_token):
            raise web.HTTPForbidden(text="Invalid CSRF token")

    # -- Handlers --

    async def _handle_page(self, request: web.Request) -> web.Response:
        html = _login_page_html(self.torque_url, self._csrf_token, self.profile_name)
        return web.Response(text=html, content_type="text/html")

    async def _handle_health(self, request: web.Request) -> web.Response:
        self._last_heartbeat = time.monotonic()
        return web.json_response({"status": "ok"})

    async def _handle_cancel(self, request: web.Request) -> web.Response:
        """Handle explicit cancel from the UI."""
        self._check_csrf(request)
        self._cancelled = True
        self._completed.set()
        print("Setup cancelled by user.", file=sys.stderr)
        return web.json_response({"status": "cancelled"})

    async def _handle_list_profiles(self, request: web.Request) -> web.Response:
        """Return existing profiles and whether a default_profile is set."""
        try:
            config = config_module.load_config(self.config_path)
        except Exception:
            return web.json_response({"profiles": [], "has_default_profile": False})
        profiles = config.get("profiles", {})
        result = []
        for name, p in profiles.items():
            result.append({
                "name": name,
                "description": p.get("description", ""),
                "torque_url": p.get("torque_url", ""),
                "has_token": bool(p.get("torque_token")),
            })
        return web.json_response({
            "profiles": result,
            "has_default_profile": bool(config.get("default_profile")),
        })

    async def _handle_use_profile(self, request: web.Request) -> web.Response:
        """Reuse an existing profile's token. Validates it and returns spaces."""
        self._check_csrf(request)
        body = await request.json()
        profile_name = body.get("profile_name", "")
        if not profile_name:
            return web.json_response({"error": "profile_name is required"}, status=400)

        try:
            config = config_module.load_config(self.config_path)
        except Exception as e:
            return web.json_response({"error": f"Failed to load config: {e}"}, status=500)

        profiles = config.get("profiles", {})
        profile = profiles.get(profile_name)
        if profile is None:
            return web.json_response({"error": f"Profile '{profile_name}' not found"}, status=404)

        token = profile.get("torque_token", "")
        torque_url = profile.get("torque_url", "")
        if not token:
            return web.json_response({"error": f"Profile '{profile_name}' has no token"}, status=400)
        if not torque_url:
            return web.json_response({"error": f"Profile '{profile_name}' has no torque_url"}, status=400)

        # Update server state
        self.torque_url = torque_url.rstrip("/")

        # Validate the token
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/accounts/user_spaces",
                headers={"Authorization": f"Bearer {token}"},
            )
        if resp.status_code == 401:
            return web.json_response(
                {"error": f"Token from profile '{profile_name}' is invalid or expired"},
                status=401,
            )
        if resp.status_code != 200:
            return web.json_response(
                {"error": f"Token validation failed (HTTP {resp.status_code})"},
                status=resp.status_code,
            )

        return web.json_response({
            "token": token,
            "torque_url": self.torque_url,
            "token_id": profile.get("torque_token_id"),
            "spaces": resp.json(),
        })

    # -- Cisco ID SSO --

    async def cleanup_sso(self) -> None:
        """Cancel any in-flight SSO browser session (idempotent)."""
        if self._sso_session is not None:
            await self._sso_session.cancel()

    async def _handle_sso_options(self, request: web.Request) -> web.Response:
        """Report whether the target Torque instance supports Cisco ID login."""
        torque_url = (request.query.get("torque_url") or self.torque_url or "").rstrip("/")
        if not torque_url:
            return web.json_response({"cisco_sso": False})
        supported = await sso_browser.probe_cisco_sso(torque_url)
        return web.json_response({"cisco_sso": supported})

    async def _handle_sso_start(self, request: web.Request) -> web.Response:
        """Launch the Cisco ID sign-in flow in a temporary browser."""
        self._check_csrf(request)
        body = await request.json()
        torque_url = body.get("torque_url", "") or self.torque_url
        if not torque_url:
            return web.json_response({"error": "Torque URL is required"}, status=400)
        self.torque_url = torque_url.rstrip("/")

        # Only one SSO attempt at a time — abort any previous one
        if self._sso_session is not None:
            await self._sso_session.cancel()

        session = self._sso_session_factory(self.torque_url)
        try:
            await session.start()
        except sso_browser.SsoLoginError as e:
            return web.json_response({"error": str(e)}, status=500)
        self._sso_session = session
        print("Cisco ID sign-in: opened a temporary browser window.", file=sys.stderr)
        return web.json_response({"status": "started"})

    async def _handle_sso_status(self, request: web.Request) -> web.Response:
        """Poll the state of the running SSO attempt."""
        session = self._sso_session
        if session is None:
            return web.json_response({"status": "none"})
        return web.json_response({
            "status": session.status,
            "error": session.error,
            "token": session.token,
            "accounts": session.accounts,
            # The URL this sign-in belongs to — authoritative for the page,
            # which may have navigated to a different URL meanwhile.
            "torque_url": session.torque_url,
        })

    async def _handle_sso_cancel(self, request: web.Request) -> web.Response:
        """Abort the running SSO attempt (closes the temporary browser)."""
        self._check_csrf(request)
        await self.cleanup_sso()
        return web.json_response({"status": "cancelled"})

    async def _handle_login(self, request: web.Request) -> web.Response:
        """Proxy email/password login to Torque API."""
        self._check_csrf(request)
        body = await request.json()
        email = body.get("email", "")
        password = body.get("password", "")
        torque_url = body.get("torque_url", "") or self.torque_url
        if not email or not password:
            return web.json_response({"error": "Email and password are required"}, status=400)
        if not torque_url:
            return web.json_response({"error": "Torque URL is required"}, status=400)

        # Update server's torque_url for subsequent API calls
        self.torque_url = torque_url.rstrip("/")

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self.torque_url}/api/accounts/login",
                json={"email": email, "password": password},
            )
        if resp.status_code == 401:
            return web.json_response({"error": "Invalid email or password"}, status=401)
        if resp.status_code != 200:
            return web.json_response(
                {"error": f"Login failed (HTTP {resp.status_code}): {resp.text}"},
                status=resp.status_code,
            )
        # Response: Dict<account_alias, TokenResponse>
        return web.json_response(resp.json())

    async def _handle_validate_token(self, request: web.Request) -> web.Response:
        """Validate a pasted token by calling user_spaces."""
        self._check_csrf(request)
        body = await request.json()
        token = body.get("token", "")
        torque_url = body.get("torque_url", "") or self.torque_url
        if not token:
            return web.json_response({"error": "Token is required"}, status=400)
        if not torque_url:
            return web.json_response({"error": "Torque URL is required"}, status=400)

        # Update server's torque_url for subsequent API calls
        self.torque_url = torque_url.rstrip("/")

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/accounts/user_spaces",
                headers={"Authorization": f"Bearer {token}"},
            )
        if resp.status_code == 401:
            return web.json_response({"error": "Invalid or expired token"}, status=401)
        if resp.status_code != 200:
            return web.json_response(
                {"error": f"Token validation failed (HTTP {resp.status_code})"},
                status=resp.status_code,
            )
        # Return spaces as validation proof
        return web.json_response({"spaces": resp.json()})

    async def _handle_list_spaces(self, request: web.Request) -> web.Response:
        """Proxy list spaces request."""
        token = request.headers.get("Authorization", "")
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/accounts/user_spaces",
                headers={"Authorization": token},
            )
        return web.json_response(resp.json(), status=resp.status_code)

    async def _handle_list_agents(self, request: web.Request) -> web.Response:
        """Proxy list agents in space request."""
        space = request.match_info["space"]
        token = request.headers.get("Authorization", "")
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/spaces/{space}/agents",
                headers={"Authorization": token},
            )
        return web.json_response(resp.json(), status=resp.status_code)

    async def _handle_list_all_agents(self, request: web.Request) -> web.Response:
        """Proxy account-level agents list (all agents with spaces)."""
        token = request.headers.get("Authorization", "")
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/settings/agents",
                headers={"Authorization": token},
            )
        return web.json_response(resp.json(), status=resp.status_code)

    # -- Ensure space exists and the chosen agent is allowed in it --

    async def _handle_ensure_space(self, request: web.Request) -> web.Response:
        """Make `space` exist and (optionally) allow `agent` in it.

        Idempotent and race-safe: an existing space or an existing association is
        a success, not an error. Responds with what actually changed:
        `{"space_created": bool, "agent_associated": bool}`.
        """
        self._check_csrf(request)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        token = str(body.get("token") or "").strip()
        space = str(body.get("space") or "").strip()
        agent = str(body.get("agent") or "").strip() or None
        agent_type = str(body.get("agent_type") or "").strip().lower() or None

        if not token:
            return web.json_response({"error": "token is required"}, status=400)
        if not space:
            return web.json_response({"error": "space is required"}, status=400)
        if not self.torque_url:
            return web.json_response({"error": "Torque URL is required"}, status=400)

        auth = {"Authorization": f"Bearer {token}"}
        space_created = False
        agent_associated = False
        try:
            space_created = await self._ensure_space_exists(space, auth)
            if agent:
                agent_associated = await self._ensure_agent_allowed(
                    space, agent, agent_type, auth,
                )
        except _EnsureSpaceError as e:
            return web.json_response(
                {"error": str(e), "space_created": space_created, "agent_associated": False},
                status=e.status,
            )
        except Exception as e:
            # Never let an exception escape as a bare 500 without a JSON body
            return web.json_response(
                {"error": f"Failed to prepare space '{space}': {e}"},
                status=500,
            )

        return web.json_response({
            "space_created": space_created,
            "agent_associated": agent_associated,
        })

    async def _ensure_space_exists(self, space: str, auth: dict) -> bool:
        """Create `space` unless it already exists. Returns True if we created it."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/accounts/user_spaces", headers=auth,
            )
        if resp.status_code == 401:
            raise _EnsureSpaceError("Torque token is invalid or expired", status=401)
        if resp.status_code == 200:
            try:
                spaces = resp.json()
            except Exception:
                spaces = None
            if isinstance(spaces, list) and any(
                isinstance(s, dict) and s.get("name") == space for s in spaces
            ):
                return False
        # Either the space is missing or we couldn't tell — try to create it.
        # A TAKEN_SPACE_NAME response below covers the "couldn't tell" case.
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self.torque_url}/api/spaces",
                json={"name": space, "icon": _NEW_SPACE_ICON, "color": _NEW_SPACE_COLOR},
                headers=auth,
            )
        if 200 <= resp.status_code < 300:
            print(f"Created Torque space '{space}'", file=sys.stderr)
            return True
        if _CODE_TAKEN_SPACE_NAME in _torque_error_codes(resp):
            return False  # someone else created it — fine, it exists
        raise _EnsureSpaceError(
            f"Failed to create space '{space}': {_torque_error_message(resp)}",
            status=resp.status_code,
        )

    async def _ensure_agent_allowed(
        self, space: str, agent: str, agent_type: Optional[str], auth: dict,
    ) -> bool:
        """Associate `agent` with `space` unless already associated.

        Returns True if we created the association.
        """
        associations = await self._agent_space_associations(agent, auth)
        if any(a.get("space_name") == space for a in associations):
            return False

        if agent_type == "k8s":
            spec = await self._build_k8s_agent_spec(agent, associations, auth)
        else:
            # Every non-k8s host type deserializes an empty body into default
            # infra settings — no type-specific fields are needed.
            spec = {}

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self.torque_url}/api/spaces/{_q(space)}/agents/{_q(agent)}",
                json=spec,
                headers=auth,
            )
        if 200 <= resp.status_code < 300:
            print(f"Allowed agent '{agent}' in space '{space}'", file=sys.stderr)
            return True
        if _CODE_ASSOCIATION_EXISTS in _torque_error_codes(resp):
            return False  # already associated — fine
        raise _EnsureSpaceError(
            f"Failed to allow agent '{agent}' in space '{space}': "
            f"{_torque_error_message(resp)}",
            status=resp.status_code,
        )

    async def _agent_space_associations(self, agent: str, auth: dict) -> list[dict]:
        """List the agent's existing space associations (empty list on failure)."""
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/executionhosts/{_q(agent)}/spaces", headers=auth,
            )
        if resp.status_code != 200:
            return []
        try:
            body = resp.json()
        except Exception:
            return []
        items = body.get("space-associations") if isinstance(body, dict) else body
        if not isinstance(items, list):
            return []
        return [a for a in items if isinstance(a, dict)]

    async def _build_k8s_agent_spec(
        self, agent: str, associations: list[dict], auth: dict,
    ) -> dict:
        """Build the k8s association body: namespace, service account, internet_facing.

        Prefers copying from an existing association of the same agent; falls back
        to the k8s namespace/service-account discovery endpoints.
        """
        namespace = service_account = None
        source_space = None
        for a in associations:
            ns, sa = a.get("namespace"), a.get("service_account")
            if ns and sa:
                namespace, service_account, source_space = ns, sa, a.get("space_name")
                break

        if not (namespace and service_account):
            namespace, service_account = await self._discover_k8s_namespace(agent, auth)

        if not (namespace and service_account):
            raise _EnsureSpaceError(
                f"Could not determine the Kubernetes namespace and service account "
                f"for agent '{agent}'. Associate this agent with a space once in the "
                f"Torque UI, then run setup again.",
                status=422,
            )

        internet_facing = False
        if source_space:
            internet_facing = await self._agent_internet_facing(source_space, agent, auth)

        return {
            "namespace": namespace,
            "service_account": service_account,
            "internet_facing": internet_facing,
        }

    async def _discover_k8s_namespace(
        self, agent: str, auth: dict,
    ) -> tuple[Optional[str], Optional[str]]:
        """Discover a (namespace, service_account) pair for a never-associated agent."""
        preferred = await self._agent_namespace_hint(agent, auth)

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/executionhosts/k8s/{_q(agent)}/agent/namespaces",
                headers=auth,
            )
        if resp.status_code != 200:
            return None, None
        try:
            namespaces = _name_list(resp.json(), "namespaces")
        except Exception:
            return None, None
        if not namespaces:
            return None, None
        namespace = preferred if preferred in namespaces else namespaces[0]

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self.torque_url}/api/executionhosts/k8s/{_q(agent)}"
                f"/agent/namespaces/{_q(namespace)}/serviceaccounts",
                headers=auth,
            )
        if resp.status_code != 200:
            return namespace, None
        try:
            accounts = _name_list(resp.json(), "serviceAccounts")
        except Exception:
            return namespace, None
        return namespace, (accounts[0] if accounts else None)

    async def _agent_namespace_hint(self, agent: str, auth: dict) -> Optional[str]:
        """The agent's own `additional_details.agent_namespace`, if discoverable."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.torque_url}/api/settings/agents", headers=auth,
                )
            if resp.status_code != 200:
                return None
            for a in resp.json() or []:
                if isinstance(a, dict) and a.get("name") == agent:
                    details = a.get("additional_details") or {}
                    hint = details.get("agent_namespace")
                    return hint if isinstance(hint, str) and hint else None
        except Exception:
            pass
        return None

    async def _agent_internet_facing(self, space: str, agent: str, auth: dict) -> bool:
        """Read `spec.internet_facing` from an existing association (default False)."""
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self.torque_url}/api/spaces/{_q(space)}/agents", headers=auth,
                )
            if resp.status_code != 200:
                return False
            for a in resp.json() or []:
                if isinstance(a, dict) and a.get("name") == agent:
                    return bool((a.get("spec") or {}).get("internet_facing", False))
        except Exception:
            pass
        return False

    async def _handle_generate_token(self, request: web.Request) -> web.Response:
        """Generate a long-lived token via Torque API."""
        self._check_csrf(request)
        body = await request.json()
        token = body.get("token", "")
        space = body.get("space", "")
        if not token or not space:
            return web.json_response({"error": "token and space are required"}, status=400)

        hostname = platform.node() or "unknown"
        title = f"torque-tunnel-{hostname}"

        # List existing tokens BEFORE creating, so we can diff later
        existing_ids: set[str] = set()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                list_resp = await client.get(
                    f"{self.torque_url}/api/long-token/{space}/longtokens",
                    headers={"Authorization": f"Bearer {token}"},
                )
            if list_resp.status_code == 200:
                for t in list_resp.json():
                    if t.get("id"):
                        existing_ids.add(t["id"])
        except Exception:
            pass

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self.torque_url}/api/long-token/{space}/longtoken",
                params={"title": title},
                headers={"Authorization": f"Bearer {token}"},
            )
        if resp.status_code != 200:
            return web.json_response(
                {"error": f"Token generation failed (HTTP {resp.status_code}): {resp.text}"},
                status=resp.status_code,
            )

        token_data = resp.json()

        # Find the NEW token ID by diffing before/after
        token_id = None
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                list_resp = await client.get(
                    f"{self.torque_url}/api/long-token/{space}/longtokens",
                    headers={"Authorization": f"Bearer {token}"},
                )
            if list_resp.status_code == 200:
                for t in list_resp.json():
                    if t.get("id") and t["id"] not in existing_ids:
                        token_id = t["id"]
                        break
        except Exception:
            pass  # Token ID is nice-to-have, not critical

        return web.json_response({
            "access_token": token_data.get("access_token"),
            "token_id": token_id,
        })

    async def _handle_complete(self, request: web.Request) -> web.Response:
        """Save selections to config and signal completion."""
        self._check_csrf(request)
        body = await request.json()

        long_token = body.get("token", "")
        token_id = body.get("token_id")
        space = body.get("space", "")
        agent = body.get("agent")
        account = body.get("account")
        torque_url = body.get("torque_url", "") or self.torque_url
        profile_name = body.get("profile_name", "") or self.profile_name
        description = body.get("description", "")
        init_commands = body.get("init_commands", "")
        set_as_default = body.get("set_as_default", False)
        expose_values = body.get("expose_values", False)

        if not long_token or not space:
            return web.json_response({"error": "token and space are required"}, status=400)
        if not profile_name:
            return web.json_response({"error": "profile name is required"}, status=400)

        # Build updates dict
        updates: dict[str, object] = {
            "torque_url": torque_url,
            "torque_token": long_token,
            "torque_space": space,
        }
        if token_id:
            updates["torque_token_id"] = token_id
        if agent:
            updates["torque_agent"] = agent
        if description:
            updates["description"] = description
        if init_commands:
            updates["init_commands"] = init_commands
        updates["expose_values"] = expose_values

        # Update self for revocation context
        self.torque_url = torque_url.rstrip("/")
        self.profile_name = profile_name

        # Try to revoke old token if we placed it
        await self._revoke_old_token(long_token, space)

        # Save to config file
        try:
            path = config_module.update_config_file(
                updates,
                profile_name=self.profile_name,
                explicit_path=self.config_path,
            )
            if set_as_default and self.profile_name:
                config_module.update_config_file(
                    {"default_profile": self.profile_name},
                    profile_name=None,
                    explicit_path=self.config_path,
                )
        except Exception as e:
            return web.json_response({"error": f"Failed to save config: {e}"}, status=500)

        self._result = _build_profile_result(
            self.profile_name,
            updates,
            is_default=set_as_default,
        )
        self._completed.set()

        return web.json_response({
            "status": "ok",
            "config_path": str(path),
            "message": f"Saved to {path}",
        })

    async def _revoke_old_token(self, new_token: str, space: str) -> None:
        """Revoke old torque-tunnel-generated token if torque_token_id exists in config."""
        try:
            config = config_module.load_config(self.config_path)
            if self.profile_name:
                profiles = config.get("profiles", {})
                section = profiles.get(self.profile_name, {})
            else:
                section = config

            old_token_id = section.get("torque_token_id")
            old_token = section.get("torque_token")
            if not old_token_id or not old_token:
                return

            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.delete(
                    f"{self.torque_url}/api/long-token/{space}/{old_token_id}",
                    headers={"Authorization": f"Bearer {old_token}"},
                )
                print(f"Revoked old token {old_token_id}", file=sys.stderr)
        except Exception:
            pass  # Best-effort — don't block login if revocation fails


# ---------------------------------------------------------------------------
# Login page HTML / JS / CSS
# ---------------------------------------------------------------------------

_LOGIN_HTML = (pathlib.Path(__file__).with_name("login_page.html").read_text(encoding="utf-8"))
