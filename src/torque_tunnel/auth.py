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
import webbrowser
from dataclasses import dataclass
from typing import Optional

import httpx
from aiohttp import web

from . import config as config_module

# Long token never-expire sentinel (Int32.MaxValue from Torque)
_LONG_TOKEN_EXPIRES = 2147483647


@dataclass
class AuthResult:
    """Result of the interactive login flow."""
    token: str
    token_id: Optional[str]
    space: str
    agent: Optional[str]
    account: Optional[str]
    torque_url: Optional[str] = None



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
        timeout: int = 300,
    ):
        self.torque_url = torque_url.rstrip("/") if torque_url else ""
        self.config_path = config_path
        self.profile_name = profile_name or ""
        self.timeout = timeout
        self._csrf_token = secrets.token_urlsafe(32)
        self._result: Optional[AuthResult] = None
        self._completed = asyncio.Event()
        self._cancelled = False
        self._last_heartbeat: float = 0.0
        self._heartbeat_stale_seconds: float = 30.0
        self._heartbeat_check_interval: float = 5.0
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None

    async def run(self) -> Optional[AuthResult]:
        """Start server, open browser, wait for user to complete, return result.

        Returns None if the user cancelled (closed browser tab or clicked Cancel).
        """
        self._app = self._create_app()
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        # Read back the actual port assigned by the OS (ephemeral range, always browser-safe)
        port = site._server.sockets[0].getsockname()[1]
        self._last_heartbeat = time.monotonic()

        url = f"http://127.0.0.1:{port}/"
        print(f"Opening browser for Torque login: {url}", file=sys.stderr)
        webbrowser.open(url)

        try:
            await asyncio.wait_for(
                self._wait_for_completion(), timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(
                f"Login flow timed out after {self.timeout}s. "
                "Please try again with 'login' tool."
            )
        finally:
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
                print("Browser tab closed — login cancelled.", file=sys.stderr)
                return

    def _create_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/", self._handle_page)
        app.router.add_get("/health", self._handle_health)
        app.router.add_post("/api/login", self._handle_login)
        app.router.add_post("/api/validate-token", self._handle_validate_token)
        app.router.add_get("/api/spaces", self._handle_list_spaces)
        app.router.add_get("/api/spaces/{space}/agents", self._handle_list_agents)
        app.router.add_get("/api/agents", self._handle_list_all_agents)
        app.router.add_post("/api/generate-token", self._handle_generate_token)
        app.router.add_post("/api/complete", self._handle_complete)
        app.router.add_post("/api/cancel", self._handle_cancel)
        app.router.add_get("/api/profiles", self._handle_list_profiles)
        app.router.add_post("/api/use-profile", self._handle_use_profile)
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
        print("Login cancelled by user.", file=sys.stderr)
        return web.json_response({"status": "cancelled"})

    async def _handle_list_profiles(self, request: web.Request) -> web.Response:
        """Return existing profiles (name, description, torque_url, has_token) for reuse."""
        try:
            config = config_module.load_config(self.config_path)
        except Exception:
            return web.json_response([])
        profiles = config.get("profiles", {})
        result = []
        for name, p in profiles.items():
            result.append({
                "name": name,
                "description": p.get("description", ""),
                "torque_url": p.get("torque_url", ""),
                "has_token": bool(p.get("torque_token")),
            })
        return web.json_response(result)

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
        except Exception as e:
            return web.json_response({"error": f"Failed to save config: {e}"}, status=500)

        self._result = AuthResult(
            token=long_token,
            token_id=token_id,
            space=space,
            agent=agent,
            account=account,
            torque_url=torque_url,
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
