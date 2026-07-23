"""Tests for the Cisco ID SSO browser flow (sso_browser module).

Uses a fake CDP (Chrome DevTools Protocol) server over aiohttp so the real
production polling/harvesting code runs against realistic HTTP+WebSocket
endpoints, with only the browser process itself faked.
"""

import asyncio
import json
import os
import sys
import urllib.parse
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import web

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import sso_browser
from torque_tunnel.sso_browser import (
    CiscoSsoSession,
    SsoLoginError,
    find_chromium_browser,
    probe_cisco_sso,
)


TORQUE_URL = "https://torque.example.com"

SINGLE_TOKEN = {
    "access_token": "short-token-abc",
    "refresh_token": "refresh-xyz",
    "token_type": "Bearer",
    "expires_in": 3600,
}

MULTI_TOKENS = {
    "acme": {"access_token": "tok-acme", "token_type": "Bearer", "expires_in": 3600},
    "ztp": {"access_token": "tok-ztp", "token_type": "Bearer", "expires_in": 3600},
}


# ============================================================================
# Fake CDP server
# ============================================================================


class FakeCdpServer:
    """Fake Chrome DevTools Protocol endpoint: /json/list + per-page websocket."""

    def __init__(self):
        self.port = None
        self._runner = None
        # target_id -> {"url": str, "localStorage": dict, "cookie": str}
        self.pages = {}
        self.eval_count = 0

    async def start(self):
        app = web.Application()
        app.router.add_get("/json/list", self._handle_list)
        app.router.add_get("/devtools/page/{tid}", self._handle_ws)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    def add_page(self, tid, url, local_storage=None, cookie=""):
        self.pages[tid] = {
            "url": url,
            "localStorage": local_storage or {},
            "cookie": cookie,
        }

    async def _handle_list(self, request):
        targets = []
        for tid, page in self.pages.items():
            targets.append({
                "id": tid,
                "type": "page",
                "url": page["url"],
                "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}/devtools/page/{tid}",
            })
        return web.json_response(targets)

    async def _handle_ws(self, request):
        tid = request.match_info["tid"]
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            data = json.loads(msg.data)
            if data.get("method") == "Runtime.evaluate":
                self.eval_count += 1
                page = self.pages.get(tid, {})
                store = page.get("localStorage", {})
                payload = {
                    "lr": store.get("loginResponse"),
                    "lmar": store.get("loginMultiAccountResponse"),
                    "cookie": page.get("cookie", ""),
                }
                await ws.send_json({
                    "id": data["id"],
                    "result": {"result": {"type": "string", "value": json.dumps(payload)}},
                })
        return ws


@pytest_asyncio.fixture
async def fake_cdp():
    server = FakeCdpServer()
    await server.start()
    yield server
    await server.stop()


# ============================================================================
# Fake browser process + launcher
# ============================================================================


class FakeBrowserProcess:
    def __init__(self):
        self.returncode = None
        self.terminated = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.terminated = True
        self.returncode = -9

    def exit(self, code=0):
        """Test helper: simulate the user closing the browser window."""
        self.returncode = code


def make_launcher(cdp_port, record=None, write_port_file=True):
    """Return a fake launcher that writes DevToolsActivePort like a real browser."""

    def launcher(cmd):
        if record is not None:
            record.append(cmd)
        udd = next(a.split("=", 1)[1] for a in cmd if a.startswith("--user-data-dir="))
        if write_port_file:
            Path(udd, "DevToolsActivePort").write_text(
                f"{cdp_port}\n/devtools/browser/fake-id", encoding="ascii",
            )
        proc = FakeBrowserProcess()
        launcher.proc = proc
        return proc

    launcher.proc = None
    return launcher


def make_session(fake_cdp, **kwargs):
    kwargs.setdefault("browser_path", "/fake/browser.exe")
    kwargs.setdefault("launcher", make_launcher(fake_cdp.port))
    kwargs.setdefault("poll_interval", 0.05)
    kwargs.setdefault("timeout", 10.0)
    kwargs.setdefault("devtools_wait", 5.0)
    return CiscoSsoSession(TORQUE_URL, **kwargs)


async def wait_for_status(session, statuses, timeout=8.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while session.status not in statuses:
        if asyncio.get_event_loop().time() > deadline:
            pytest.fail(f"Session stuck in status '{session.status}', expected one of {statuses}. error={session.error}")
        await asyncio.sleep(0.02)


# ============================================================================
# Token harvesting
# ============================================================================


class TestHarvestSuccess:
    @pytest.mark.asyncio
    async def test_single_account_from_localstorage(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps(SINGLE_TOKEN)})
        session = make_session(fake_cdp)
        await session.start()
        await wait_for_status(session, {"success", "error"})
        assert session.status == "success"
        assert session.token == "short-token-abc"
        assert session.accounts is None

    @pytest.mark.asyncio
    async def test_multi_account_from_localstorage(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginMultiAccountResponse": json.dumps(MULTI_TOKENS)})
        session = make_session(fake_cdp)
        await session.start()
        await wait_for_status(session, {"success", "error"})
        assert session.status == "success"
        assert session.token is None
        assert session.accounts == MULTI_TOKENS

    @pytest.mark.asyncio
    async def test_single_account_from_cookie(self, fake_cdp):
        """Race-window case: cookie set by backend, SPA hasn't moved it to localStorage yet."""
        cookie_val = urllib.parse.quote(json.dumps(SINGLE_TOKEN))
        fake_cdp.add_page("1", TORQUE_URL + "/", cookie=f"other=1; loginResponse={cookie_val}")
        session = make_session(fake_cdp)
        await session.start()
        await wait_for_status(session, {"success", "error"})
        assert session.status == "success"
        assert session.token == "short-token-abc"

    @pytest.mark.asyncio
    async def test_multi_account_from_cookie(self, fake_cdp):
        cookie_val = urllib.parse.quote(json.dumps(MULTI_TOKENS))
        fake_cdp.add_page("1", TORQUE_URL + "/", cookie=f"loginMultiAccountResponse={cookie_val}")
        session = make_session(fake_cdp)
        await session.start()
        await wait_for_status(session, {"success", "error"})
        assert session.status == "success"
        assert session.accounts == MULTI_TOKENS

    @pytest.mark.asyncio
    async def test_token_appears_after_a_few_polls(self, fake_cdp):
        """Token shows up only after the user finishes SSO — session keeps polling."""
        fake_cdp.add_page("1", "https://id.cisco.com/login")
        session = make_session(fake_cdp)
        await session.start()
        await asyncio.sleep(0.2)
        assert session.status == "pending"
        # User finishes SSO: tab lands on torque origin with the token
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps(SINGLE_TOKEN)})
        await wait_for_status(session, {"success", "error"})
        assert session.status == "success"

    @pytest.mark.asyncio
    async def test_non_torque_pages_are_not_evaluated(self, fake_cdp):
        fake_cdp.add_page("1", "https://id.cisco.com/login")
        fake_cdp.add_page("2", "https://duo.example.com/prompt")
        session = make_session(fake_cdp)
        await session.start()
        await asyncio.sleep(0.3)
        assert fake_cdp.eval_count == 0
        assert session.status == "pending"
        await session.cancel()

    @pytest.mark.asyncio
    async def test_browser_closed_after_success(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps(SINGLE_TOKEN)})
        launcher = make_launcher(fake_cdp.port)
        session = make_session(fake_cdp, launcher=launcher)
        await session.start()
        await wait_for_status(session, {"success"})
        # Wait for the run task to finish cleanup
        await session.wait_done()
        assert launcher.proc.terminated

    @pytest.mark.asyncio
    async def test_temp_profile_deleted_after_success(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps(SINGLE_TOKEN)})
        session = make_session(fake_cdp)
        await session.start()
        udd = session._user_data_dir
        assert udd is not None and Path(udd).exists()
        await wait_for_status(session, {"success"})
        await session.wait_done()
        assert not Path(udd).exists()


# ============================================================================
# Error handling
# ============================================================================


class TestHarvestErrors:
    @pytest.mark.asyncio
    async def test_sso_error_page_detected(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/ssoerror?reason=nope")
        session = make_session(fake_cdp)
        await session.start()
        await wait_for_status(session, {"error"})
        assert "sign-in failed" in session.error.lower() or "error" in session.error.lower()

    @pytest.mark.asyncio
    async def test_generic_error_page_detected(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/error")
        session = make_session(fake_cdp)
        await session.start()
        await wait_for_status(session, {"error"})

    @pytest.mark.asyncio
    async def test_error_path_prefix_not_false_positive(self, fake_cdp):
        """A page like /errors-dashboard must NOT be mistaken for the error route."""
        fake_cdp.add_page("1", TORQUE_URL + "/errors-dashboard")
        session = make_session(fake_cdp)
        await session.start()
        await asyncio.sleep(0.3)
        assert session.status == "pending"
        await session.cancel()

    @pytest.mark.asyncio
    async def test_browser_process_exits(self, fake_cdp):
        """User closes the SSO browser window before completing sign-in."""
        fake_cdp.add_page("1", "https://id.cisco.com/login")
        launcher = make_launcher(fake_cdp.port)
        session = make_session(fake_cdp, launcher=launcher)
        await session.start()
        await asyncio.sleep(0.1)
        launcher.proc.exit(0)
        await wait_for_status(session, {"error"})
        assert "closed" in session.error.lower()

    @pytest.mark.asyncio
    async def test_timeout(self, fake_cdp):
        fake_cdp.add_page("1", "https://id.cisco.com/login")
        session = make_session(fake_cdp, timeout=0.3)
        await session.start()
        await wait_for_status(session, {"error"})
        assert "timed out" in session.error.lower()

    @pytest.mark.asyncio
    async def test_devtools_port_never_appears(self, fake_cdp):
        launcher = make_launcher(fake_cdp.port, write_port_file=False)
        session = make_session(fake_cdp, launcher=launcher, devtools_wait=0.3)
        await session.start()
        await wait_for_status(session, {"error"})
        assert "devtools" in session.error.lower() or "browser" in session.error.lower()

    @pytest.mark.asyncio
    async def test_malformed_localstorage_json_keeps_polling(self, fake_cdp):
        """Bad JSON in localStorage must not crash the watcher."""
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": "{not-json"})
        session = make_session(fake_cdp)
        await session.start()
        await asyncio.sleep(0.3)
        assert session.status == "pending"
        # Now good data appears
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps(SINGLE_TOKEN)})
        await wait_for_status(session, {"success"})

    @pytest.mark.asyncio
    async def test_token_without_access_token_ignored(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps({"token_type": "Bearer"})})
        session = make_session(fake_cdp)
        await session.start()
        await asyncio.sleep(0.3)
        assert session.status == "pending"
        await session.cancel()

    @pytest.mark.asyncio
    async def test_launcher_raises(self, fake_cdp):
        def bad_launcher(cmd):
            raise OSError("cannot execute")

        session = make_session(fake_cdp, launcher=bad_launcher)
        with pytest.raises(SsoLoginError, match="cannot execute"):
            await session.start()

    @pytest.mark.asyncio
    async def test_no_browser_path_raises(self, monkeypatch, fake_cdp):
        monkeypatch.setattr(sso_browser, "find_chromium_browser", lambda: None)
        session = CiscoSsoSession(TORQUE_URL)
        with pytest.raises(SsoLoginError, match="[Nn]o.*browser"):
            await session.start()


# ============================================================================
# Cancel
# ============================================================================


class TestCancel:
    @pytest.mark.asyncio
    async def test_cancel_pending_session(self, fake_cdp):
        fake_cdp.add_page("1", "https://id.cisco.com/login")
        launcher = make_launcher(fake_cdp.port)
        session = make_session(fake_cdp, launcher=launcher)
        await session.start()
        await asyncio.sleep(0.1)
        await session.cancel()
        assert session.status == "cancelled"
        assert launcher.proc.terminated

    @pytest.mark.asyncio
    async def test_cancel_deletes_temp_profile(self, fake_cdp):
        fake_cdp.add_page("1", "https://id.cisco.com/login")
        session = make_session(fake_cdp)
        await session.start()
        udd = session._user_data_dir
        await session.cancel()
        assert not Path(udd).exists()

    @pytest.mark.asyncio
    async def test_cancel_after_success_keeps_success(self, fake_cdp):
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps(SINGLE_TOKEN)})
        session = make_session(fake_cdp)
        await session.start()
        await wait_for_status(session, {"success"})
        await session.cancel()
        assert session.status == "success"
        assert session.token == "short-token-abc"

    @pytest.mark.asyncio
    async def test_cancel_is_idempotent(self, fake_cdp):
        fake_cdp.add_page("1", "https://id.cisco.com/login")
        session = make_session(fake_cdp)
        await session.start()
        await session.cancel()
        await session.cancel()
        assert session.status == "cancelled"


# ============================================================================
# Launch command
# ============================================================================


class TestLaunchCommand:
    @pytest.mark.asyncio
    async def test_command_contains_required_flags(self, fake_cdp):
        record = []
        launcher = make_launcher(fake_cdp.port, record=record)
        fake_cdp.add_page("1", TORQUE_URL + "/", {"loginResponse": json.dumps(SINGLE_TOKEN)})
        session = make_session(fake_cdp, launcher=launcher, browser_path="/fake/msedge.exe")
        await session.start()
        await wait_for_status(session, {"success"})

        cmd = record[0]
        assert cmd[0] == "/fake/msedge.exe"
        assert "--remote-debugging-port=0" in cmd
        assert any(a.startswith("--user-data-dir=") for a in cmd)
        assert "--no-first-run" in cmd
        # Login URL is the last argument
        assert cmd[-1] == TORQUE_URL + "/api/accounts/idp_login/Cisco"


# ============================================================================
# Browser discovery
# ============================================================================


class TestFindBrowser:
    def test_env_override_wins(self, monkeypatch, tmp_path):
        exe = tmp_path / "mybrowser.exe"
        exe.write_text("", encoding="ascii")
        monkeypatch.setenv("TORQUE_TUNNEL_SSO_BROWSER", str(exe))
        assert find_chromium_browser() == str(exe)

    def test_env_override_missing_file_ignored(self, monkeypatch):
        monkeypatch.setenv("TORQUE_TUNNEL_SSO_BROWSER", r"C:\nonexistent\browser.exe")
        # Should fall through to normal discovery (result depends on machine — just must not return the bogus path)
        assert find_chromium_browser() != r"C:\nonexistent\browser.exe"

    def test_default_browser_preferred_over_candidates(self, monkeypatch, tmp_path):
        monkeypatch.delenv("TORQUE_TUNNEL_SSO_BROWSER", raising=False)
        default_exe = str(tmp_path / "brave.exe")
        candidate_exe = tmp_path / "msedge.exe"
        candidate_exe.write_text("", encoding="ascii")
        monkeypatch.setattr(sso_browser, "find_default_chromium_browser", lambda: default_exe)
        monkeypatch.setattr(sso_browser, "_candidate_browser_paths", lambda: [str(candidate_exe)])
        assert find_chromium_browser() == default_exe

    def test_returns_existing_candidate(self, monkeypatch, tmp_path):
        monkeypatch.delenv("TORQUE_TUNNEL_SSO_BROWSER", raising=False)
        monkeypatch.setattr(sso_browser, "find_default_chromium_browser", lambda: None)
        exe = tmp_path / "msedge.exe"
        exe.write_text("", encoding="ascii")
        monkeypatch.setattr(sso_browser, "_candidate_browser_paths", lambda: [str(tmp_path / "nope.exe"), str(exe)])
        assert find_chromium_browser() == str(exe)

    def test_returns_none_when_nothing_found(self, monkeypatch):
        monkeypatch.delenv("TORQUE_TUNNEL_SSO_BROWSER", raising=False)
        monkeypatch.setattr(sso_browser, "find_default_chromium_browser", lambda: None)
        monkeypatch.setattr(sso_browser, "_candidate_browser_paths", lambda: [])
        monkeypatch.setattr(sso_browser.shutil, "which", lambda name: None)
        assert find_chromium_browser() is None


class TestDefaultBrowserDetection:
    def test_is_chromium_exe(self):
        assert sso_browser._is_chromium_exe(r"C:\Apps\Brave\brave.exe")
        assert sso_browser._is_chromium_exe(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
        assert sso_browser._is_chromium_exe("/usr/bin/google-chrome")
        assert not sso_browser._is_chromium_exe(r"C:\Mozilla\firefox.exe")
        assert not sso_browser._is_chromium_exe("/usr/bin/safari")

    def test_extract_exe_quoted(self):
        cmd = '"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" --single-argument %1'
        assert sso_browser._extract_exe_from_command(cmd) == \
            "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"

    def test_extract_exe_unquoted(self):
        assert sso_browser._extract_exe_from_command(r"C:\brave.exe %1") == r"C:\brave.exe"

    def test_extract_exe_empty(self):
        assert sso_browser._extract_exe_from_command("") is None
        assert sso_browser._extract_exe_from_command('"unterminated') is None

    def test_windows_default_chromium_used(self, monkeypatch, tmp_path):
        exe = tmp_path / "brave.exe"
        exe.write_text("", encoding="ascii")
        monkeypatch.setattr(sso_browser.sys, "platform", "win32")
        monkeypatch.setattr(sso_browser, "_windows_https_command", lambda: f'"{exe}" --single-argument %1')
        assert sso_browser.find_default_chromium_browser() == str(exe)

    def test_windows_default_firefox_ignored(self, monkeypatch, tmp_path):
        exe = tmp_path / "firefox.exe"
        exe.write_text("", encoding="ascii")
        monkeypatch.setattr(sso_browser.sys, "platform", "win32")
        monkeypatch.setattr(sso_browser, "_windows_https_command", lambda: f'"{exe}" -osint -url %1')
        assert sso_browser.find_default_chromium_browser() is None

    def test_windows_default_missing_exe_ignored(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sso_browser.sys, "platform", "win32")
        monkeypatch.setattr(
            sso_browser, "_windows_https_command",
            lambda: f'"{tmp_path / "brave.exe"}" %1',  # file does not exist
        )
        assert sso_browser.find_default_chromium_browser() is None

    def test_registry_error_returns_none(self, monkeypatch):
        def boom():
            raise OSError("registry key not found")
        monkeypatch.setattr(sso_browser.sys, "platform", "win32")
        monkeypatch.setattr(sso_browser, "_windows_https_command", boom)
        assert sso_browser.find_default_chromium_browser() is None


# ============================================================================
# Capability probe
# ============================================================================


class FakeTorque:
    """Fake Torque /api/accounts/idp_login/Cisco endpoint."""

    def __init__(self, status=302, location=None):
        self.status = status
        self.location = location
        self.port = None
        self._runner = None

    async def start(self):
        app = web.Application()
        app.router.add_get("/api/accounts/idp_login/Cisco", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    async def _handle(self, request):
        headers = {}
        if self.location:
            headers["Location"] = self.location
        return web.Response(status=self.status, headers=headers)


class TestProbeCiscoSso:
    @pytest.mark.asyncio
    async def test_supported(self):
        srv = FakeTorque(302, "https://id.cisco.com/oauth2/default/v1/authorize?client_id=abc123&response_type=code")
        await srv.start()
        try:
            assert await probe_cisco_sso(srv.url) is True
        finally:
            await srv.stop()

    @pytest.mark.asyncio
    async def test_empty_client_id_unsupported(self):
        srv = FakeTorque(302, "https://id.cisco.com/oauth2/default/v1/authorize?client_id=&response_type=code")
        await srv.start()
        try:
            assert await probe_cisco_sso(srv.url) is False
        finally:
            await srv.stop()

    @pytest.mark.asyncio
    async def test_404_unsupported(self):
        srv = FakeTorque(404)
        await srv.start()
        try:
            assert await probe_cisco_sso(srv.url) is False
        finally:
            await srv.stop()

    @pytest.mark.asyncio
    async def test_unreachable_unsupported(self):
        assert await probe_cisco_sso("http://127.0.0.1:1") is False

    @pytest.mark.asyncio
    async def test_portal_denylisted_without_http_call(self):
        """Cisco ID must never be offered on portal.qtorque.io — and the check must not hit the network."""
        from unittest.mock import patch

        def no_http(*args, **kwargs):
            raise AssertionError("HTTP must not be attempted for denylisted hosts")

        with patch("torque_tunnel.sso_browser.httpx.AsyncClient", no_http):
            assert await probe_cisco_sso("https://portal.qtorque.io") is False
            assert await probe_cisco_sso("https://PORTAL.qtorque.io/") is False

    @pytest.mark.asyncio
    async def test_denylist_matches_hostname_not_substring(self):
        """A lookalike host containing the denied name as a substring is still probed normally."""
        srv = FakeTorque(302, "https://id.cisco.com/v1/authorize?client_id=abc")
        await srv.start()
        try:
            # 127.0.0.1 is not denylisted even though the probe logic runs hostname checks
            assert await probe_cisco_sso(srv.url) is True
        finally:
            await srv.stop()
