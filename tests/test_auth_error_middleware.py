"""Tests for the auth server's JSON error middleware.

An unhandled exception in any handler (e.g. httpx.ConnectError on a
self-signed-cert Torque URL) must never leak aiohttp's default text/plain
"500 Internal Server Error" body — the browser-side fetch code JSON-parses
every response, and a plain-text body produces a confusing
"Unexpected non-whitespace character after JSON at position 4" message.

Every error response must be JSON with an "error" key.
"""

import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel.auth import TorqueAuthServer


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def auth_server(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("torque_url: https://torque.example.com\n", encoding="utf-8")
    return TorqueAuthServer(
        torque_url="https://torque.example.com",
        config_path=str(config_path),
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


class _RaisingClient:
    """Stand-in for httpx.AsyncClient whose every request raises `exc`."""

    def __init__(self, exc):
        self._exc = exc

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False

    async def get(self, url, **kwargs):
        raise self._exc

    async def post(self, url, **kwargs):
        raise self._exc

    async def delete(self, url, **kwargs):
        raise self._exc


def _patched(exc):
    return patch("torque_tunnel.auth.httpx.AsyncClient", _RaisingClient(exc))


_LOGIN_BODY = {
    "email": "a@b.c",
    "password": "pw",
    "torque_url": "https://localhost",
}


# ============================================================================
# httpx transport failures → JSON 502
# ============================================================================

class TestHttpxErrorsAreJson:

    @pytest.mark.asyncio
    async def test_self_signed_cert_gives_friendly_json_error(self, client, csrf_headers):
        exc = httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "self-signed certificate (_ssl.c:1028)"
        )
        with _patched(exc):
            resp = await client.post(
                f"{client._base}/api/login", json=_LOGIN_BODY, headers=csrf_headers,
            )
        assert resp.status == 502
        assert resp.content_type == "application/json"
        data = await resp.json()
        # Friendly message, not the raw SSL traceback gibberish
        assert "certificate" in data["error"].lower()
        assert "not trusted" in data["error"] or "self-signed" in data["error"]

    @pytest.mark.asyncio
    async def test_connect_error_gives_json_error(self, client, csrf_headers):
        with _patched(httpx.ConnectError("All connection attempts failed")):
            resp = await client.post(
                f"{client._base}/api/login", json=_LOGIN_BODY, headers=csrf_headers,
            )
        assert resp.status == 502
        assert resp.content_type == "application/json"
        data = await resp.json()
        assert "connect" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_timeout_gives_json_error(self, client, csrf_headers):
        with _patched(httpx.ConnectTimeout("timed out")):
            resp = await client.post(
                f"{client._base}/api/login", json=_LOGIN_BODY, headers=csrf_headers,
            )
        assert resp.status == 502
        assert resp.content_type == "application/json"
        data = await resp.json()
        assert "timed out" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_validate_token_transport_error_is_json(self, client, csrf_headers):
        """The middleware must cover every handler, not just login."""
        with _patched(httpx.ConnectError("boom")):
            resp = await client.post(
                f"{client._base}/api/validate-token",
                json={"token": "t", "torque_url": "https://localhost"},
                headers=csrf_headers,
            )
        assert resp.status == 502
        assert resp.content_type == "application/json"
        assert "error" in await resp.json()

    @pytest.mark.asyncio
    async def test_get_handler_transport_error_is_json(self, client):
        """GET handlers (no CSRF) are covered too."""
        with _patched(httpx.ConnectError("boom")):
            resp = await client.get(
                f"{client._base}/api/spaces",
                headers={"Authorization": "Bearer tok"},
            )
        assert resp.status == 502
        assert resp.content_type == "application/json"
        assert "error" in await resp.json()


# ============================================================================
# Unexpected exceptions → JSON 500
# ============================================================================

class TestUnexpectedErrorsAreJson:

    @pytest.mark.asyncio
    async def test_arbitrary_exception_gives_json_500(self, client, csrf_headers):
        with _patched(RuntimeError("totally unexpected")):
            resp = await client.post(
                f"{client._base}/api/login", json=_LOGIN_BODY, headers=csrf_headers,
            )
        assert resp.status == 500
        assert resp.content_type == "application/json"
        data = await resp.json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_malformed_json_body_gives_json_400(self, client, csrf_headers):
        resp = await client.post(
            f"{client._base}/api/login",
            data=b"{not json",
            headers=csrf_headers,
        )
        assert resp.status == 400
        assert resp.content_type == "application/json"
        data = await resp.json()
        assert "error" in data


# ============================================================================
# HTTPException passthrough — deliberate aiohttp errors keep working
# ============================================================================

class TestHttpExceptionPassthrough:

    @pytest.mark.asyncio
    async def test_csrf_rejection_still_403(self, client):
        resp = await client.post(
            f"{client._base}/api/login",
            json=_LOGIN_BODY,
            headers={"Content-Type": "application/json", "X-CSRF-Token": "bad"},
        )
        assert resp.status == 403

    @pytest.mark.asyncio
    async def test_unknown_route_still_404(self, client):
        resp = await client.get("/no-such-path")
        assert resp.status == 404


# ============================================================================
# Client-side invariant — every resp.json() in the login page tolerates
# a non-JSON body (must not throw before the resp.ok check runs)
# ============================================================================

class TestLoginPageJsonParsing:

    def test_every_json_parse_has_catch(self):
        html = (
            Path(__file__).parent.parent / "src" / "torque_tunnel" / "login_page.html"
        ).read_text(encoding="utf-8")
        raw = re.findall(r"^.*\.json\(\)(?!\.catch).*$", html, flags=re.MULTILINE)
        assert raw == [], (
            "These .json() calls have no .catch() and will throw a confusing "
            "'Unexpected non-whitespace character' error on a non-JSON body:\n"
            + "\n".join(raw)
        )
