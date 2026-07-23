"""Tests for the Cisco ID SSO endpoints on TorqueAuthServer.

The CDP browser session is faked via the injectable sso_session_factory;
the HTTP layer (routes, CSRF, status polling) is exercised for real through
an aiohttp test client.
"""

import asyncio
import os
import sys
from unittest.mock import patch

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel.auth import TorqueAuthServer
from torque_tunnel.sso_browser import SsoLoginError


TORQUE_URL = "https://torque.example.com"


class FakeSsoSession:
    """Stands in for sso_browser.CiscoSsoSession."""

    def __init__(self, torque_url, **kwargs):
        self.torque_url = torque_url
        self.status = "pending"
        self.error = None
        self.token = None
        self.accounts = None
        self.started = False
        self.cancelled_calls = 0
        self.start_error = None

    async def start(self):
        if self.start_error:
            raise self.start_error
        self.started = True

    async def cancel(self):
        self.cancelled_calls += 1
        if self.status == "pending":
            self.status = "cancelled"

    # Test helpers
    def succeed_single(self, token="short-tok"):
        self.status = "success"
        self.token = token

    def succeed_multi(self, accounts):
        self.status = "success"
        self.accounts = accounts

    def fail(self, error):
        self.status = "error"
        self.error = error


class RecordingFactory:
    def __init__(self):
        self.sessions = []
        self.next_start_error = None

    def __call__(self, torque_url, **kwargs):
        s = FakeSsoSession(torque_url, **kwargs)
        s.start_error = self.next_start_error
        self.sessions.append(s)
        return s


@pytest.fixture
def sso_factory():
    return RecordingFactory()


@pytest.fixture
def auth_server(tmp_path, sso_factory):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"torque_url: {TORQUE_URL}\n", encoding="utf-8")
    return TorqueAuthServer(
        torque_url=TORQUE_URL,
        config_path=str(config_path),
        sso_session_factory=sso_factory,
    )


@pytest.fixture
def csrf_headers(auth_server):
    return {
        "Content-Type": "application/json",
        "X-CSRF-Token": auth_server._csrf_token,
    }


@pytest_asyncio.fixture
async def client(auth_server):
    app = auth_server._create_app()
    async with TestClient(TestServer(app)) as c:
        c._base = f"/{auth_server._url_secret}"
        yield c


class TestSsoRoutes:
    def test_routes_registered(self, auth_server):
        app = auth_server._create_app()
        route_paths = {r.resource.canonical for r in app.router.routes() if hasattr(r, 'resource')}
        secret = auth_server._url_secret
        assert f"/{secret}/api/sso-options" in route_paths
        assert f"/{secret}/api/sso-start" in route_paths
        assert f"/{secret}/api/sso-status" in route_paths
        assert f"/{secret}/api/sso-cancel" in route_paths


class TestSsoOptions:
    @pytest.mark.asyncio
    async def test_supported(self, client):
        with patch("torque_tunnel.auth.sso_browser.probe_cisco_sso", return_value=True) as probe:
            resp = await client.get(f"{client._base}/api/sso-options?torque_url=https://other.example.com")
            assert resp.status == 200
            data = await resp.json()
            assert data["cisco_sso"] is True
            probe.assert_called_once_with("https://other.example.com")

    @pytest.mark.asyncio
    async def test_unsupported(self, client):
        with patch("torque_tunnel.auth.sso_browser.probe_cisco_sso", return_value=False):
            resp = await client.get(f"{client._base}/api/sso-options?torque_url=https://other.example.com")
            data = await resp.json()
            assert data["cisco_sso"] is False

    @pytest.mark.asyncio
    async def test_defaults_to_server_url(self, client):
        with patch("torque_tunnel.auth.sso_browser.probe_cisco_sso", return_value=True) as probe:
            resp = await client.get(f"{client._base}/api/sso-options")
            assert resp.status == 200
            probe.assert_called_once_with(TORQUE_URL)

    @pytest.mark.asyncio
    async def test_no_url_at_all(self, tmp_path, sso_factory):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("", encoding="utf-8")
        server = TorqueAuthServer(torque_url=None, config_path=str(config_path), sso_session_factory=sso_factory)
        app = server._create_app()
        async with TestClient(TestServer(app)) as c:
            resp = await c.get(f"/{server._url_secret}/api/sso-options")
            data = await resp.json()
            assert data["cisco_sso"] is False


class TestSsoStart:
    @pytest.mark.asyncio
    async def test_requires_csrf(self, client):
        resp = await client.post(f"{client._base}/api/sso-start", json={})
        assert resp.status == 403

    @pytest.mark.asyncio
    async def test_starts_session(self, client, csrf_headers, sso_factory):
        resp = await client.post(
            f"{client._base}/api/sso-start",
            json={"torque_url": "https://new.example.com"},
            headers=csrf_headers,
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "started"
        assert len(sso_factory.sessions) == 1
        assert sso_factory.sessions[0].started
        assert sso_factory.sessions[0].torque_url == "https://new.example.com"

    @pytest.mark.asyncio
    async def test_updates_server_torque_url(self, client, csrf_headers, auth_server):
        await client.post(
            f"{client._base}/api/sso-start",
            json={"torque_url": "https://new.example.com/"},
            headers=csrf_headers,
        )
        assert auth_server.torque_url == "https://new.example.com"

    @pytest.mark.asyncio
    async def test_uses_server_url_when_body_empty(self, client, csrf_headers, sso_factory):
        resp = await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        assert resp.status == 200
        assert sso_factory.sessions[0].torque_url == TORQUE_URL

    @pytest.mark.asyncio
    async def test_no_url_returns_400(self, tmp_path, sso_factory):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("", encoding="utf-8")
        server = TorqueAuthServer(torque_url=None, config_path=str(config_path), sso_session_factory=sso_factory)
        app = server._create_app()
        headers = {"Content-Type": "application/json", "X-CSRF-Token": server._csrf_token}
        async with TestClient(TestServer(app)) as c:
            resp = await c.post(f"/{server._url_secret}/api/sso-start", json={}, headers=headers)
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_second_start_cancels_first(self, client, csrf_headers, sso_factory):
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        assert len(sso_factory.sessions) == 2
        assert sso_factory.sessions[0].cancelled_calls == 1
        assert sso_factory.sessions[1].started

    @pytest.mark.asyncio
    async def test_browser_not_found_returns_error(self, client, csrf_headers, sso_factory):
        sso_factory.next_start_error = SsoLoginError("No Chromium-based browser found")
        resp = await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        assert resp.status == 500
        data = await resp.json()
        assert "browser" in data["error"].lower()


class TestSsoStatus:
    @pytest.mark.asyncio
    async def test_no_session(self, client):
        resp = await client.get(f"{client._base}/api/sso-status")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "none"

    @pytest.mark.asyncio
    async def test_pending(self, client, csrf_headers):
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        resp = await client.get(f"{client._base}/api/sso-status")
        data = await resp.json()
        assert data["status"] == "pending"

    @pytest.mark.asyncio
    async def test_status_includes_session_torque_url(self, client, csrf_headers, sso_factory):
        """The page must learn which URL the SSO session actually belongs to,
        even if the user navigated back and picked a different URL meanwhile."""
        await client.post(
            f"{client._base}/api/sso-start",
            json={"torque_url": "https://stack.example.com"},
            headers=csrf_headers,
        )
        sso_factory.sessions[0].succeed_single("tok")
        resp = await client.get(f"{client._base}/api/sso-status")
        data = await resp.json()
        assert data["torque_url"] == "https://stack.example.com"

    @pytest.mark.asyncio
    async def test_success_single(self, client, csrf_headers, sso_factory):
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        sso_factory.sessions[0].succeed_single("harvested-token")
        resp = await client.get(f"{client._base}/api/sso-status")
        data = await resp.json()
        assert data["status"] == "success"
        assert data["token"] == "harvested-token"
        assert data.get("accounts") is None

    @pytest.mark.asyncio
    async def test_success_multi(self, client, csrf_headers, sso_factory):
        accounts = {"a": {"access_token": "t1"}, "b": {"access_token": "t2"}}
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        sso_factory.sessions[0].succeed_multi(accounts)
        resp = await client.get(f"{client._base}/api/sso-status")
        data = await resp.json()
        assert data["status"] == "success"
        assert data["accounts"] == accounts

    @pytest.mark.asyncio
    async def test_error(self, client, csrf_headers, sso_factory):
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        sso_factory.sessions[0].fail("Browser window was closed")
        resp = await client.get(f"{client._base}/api/sso-status")
        data = await resp.json()
        assert data["status"] == "error"
        assert "closed" in data["error"]


class TestSsoCancel:
    @pytest.mark.asyncio
    async def test_requires_csrf(self, client):
        resp = await client.post(f"{client._base}/api/sso-cancel")
        assert resp.status == 403

    @pytest.mark.asyncio
    async def test_cancels_session(self, client, csrf_headers, sso_factory):
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        resp = await client.post(f"{client._base}/api/sso-cancel", headers=csrf_headers)
        assert resp.status == 200
        assert sso_factory.sessions[0].cancelled_calls == 1

    @pytest.mark.asyncio
    async def test_cancel_without_session_is_ok(self, client, csrf_headers):
        resp = await client.post(f"{client._base}/api/sso-cancel", headers=csrf_headers)
        assert resp.status == 200


class TestSsoCleanupOnServerEnd:
    @pytest.mark.asyncio
    async def test_pending_sso_cancelled_when_setup_completes(self, client, csrf_headers, auth_server, sso_factory):
        """A dangling SSO browser must not outlive the setup flow."""
        await client.post(f"{client._base}/api/sso-start", json={}, headers=csrf_headers)
        resp = await client.post(
            f"{client._base}/api/complete",
            json={"token": "tok", "space": "sp", "profile_name": "p", "torque_url": TORQUE_URL},
            headers=csrf_headers,
        )
        assert resp.status == 200
        await auth_server.cleanup_sso()
        assert sso_factory.sessions[0].cancelled_calls >= 1


class TestSsoPageHtml:
    @pytest.mark.asyncio
    async def test_page_contains_sso_ui(self, client):
        resp = await client.get(client._base)
        text = await resp.text()
        assert "Sign in with Cisco ID" in text
        assert "sso-start" in text
        assert "sso-status" in text
        assert "sso-options" in text
