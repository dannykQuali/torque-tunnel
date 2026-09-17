"""Setup-flow tests for the credentials controls.

Covers the pieces the browser drives: the availability probe the confirm step calls, the
fields /api/complete persists, and the markup/JS that has to exist for either to be reached.
"""

import os
import re
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import config as config_module
from torque_tunnel.auth import TorqueAuthServer


LOGIN_HTML = (
    Path(__file__).resolve().parent.parent / "src" / "torque_tunnel" / "login_page.html"
).read_text(encoding="utf-8")


# ============================================================================
# The page itself
# ============================================================================

def test_confirm_step_offers_the_credentials_toggle():
    assert 'id="credentialsEnabledToggle"' in LOGIN_HTML
    assert "Allow using Torque credentials" in LOGIN_HTML


def test_both_space_policies_are_offered_and_the_safe_one_is_preselected():
    assert 'name="credentialsSpacePolicy" value="preconfigured" checked' in LOGIN_HTML
    assert 'name="credentialsSpacePolicy" value="authorize"' in LOGIN_HTML


def test_the_policy_choice_is_hidden_until_credentials_are_enabled():
    assert 'id="credentialsPolicyBlock" style="display:none;' in LOGIN_HTML
    assert "function onCredentialsToggle()" in LOGIN_HTML


def test_save_sends_both_credential_fields():
    assert "credentials_enabled: document.getElementById('credentialsEnabledToggle').checked" in LOGIN_HTML
    assert "credentials_space_policy:" in LOGIN_HTML
    # Falls back to the non-mutating policy if nothing is selected.
    assert "|| 'preconfigured'" in LOGIN_HTML


def test_confirm_step_defaults_credentials_off():
    """Using a credential resolves a customer's real secrets into an agent container, so it
    is opted into rather than defaulted on."""
    assert "document.getElementById('credentialsEnabledToggle').checked = false;" in LOGIN_HTML


def test_the_page_asks_for_credential_availability_for_the_chosen_space():
    assert "loadCredentialAvailability()" in LOGIN_HTML
    assert "'/credentials'" in LOGIN_HTML or "/credentials'," in LOGIN_HTML


def test_page_warns_when_the_chosen_space_has_no_credentials():
    """The setup flow can create a brand-new space, which has none — 'preconfigured' would
    then be a dead end, and the user should hear that here rather than on their first call."""
    assert "no credentials available" in LOGIN_HTML


def test_page_disables_authorize_without_admin_rights():
    assert "authorizeRadio.disabled = true" in LOGIN_HTML
    assert "account-admin" in LOGIN_HTML


# ============================================================================
# Server side
# ============================================================================

@pytest.fixture
def auth_server(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("torque_url: https://torque.example.com\n", encoding="utf-8")
    return TorqueAuthServer(
        torque_url="https://torque.example.com", config_path=str(config_path)
    )


@pytest.fixture
def csrf_headers(auth_server):
    return {"Content-Type": "application/json", "X-CSRF-Token": auth_server._csrf_token}


try:
    from aiohttp.test_utils import TestClient, TestServer

    @pytest_asyncio.fixture
    async def client(auth_server):
        app = auth_server._create_app()
        async with TestClient(TestServer(app)) as c:
            c._base = f"/{auth_server._url_secret}"
            yield c

    def _mock_httpx(responses):
        """Build a mocked httpx.AsyncClient whose .get returns `responses` in order."""
        mock_client = AsyncMock()
        mock_client.get.side_effect = responses
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        return mock_client

    def _resp(status, payload=None):
        r = MagicMock()
        r.status_code = status
        r.json.return_value = payload
        return r

    class TestSpaceCredentialsEndpoint:
        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_reports_count_and_admin_rights(self, mock_cls, client):
            mock_cls.return_value = _mock_httpx([
                _resp(200, [{"name": "a"}, {"name": "b"}]),   # space listing
                _resp(200, [{"name": "a"}]),                  # account listing => admin
            ])
            resp = await client.get(
                f"{client._base}/api/spaces/VMaaS/credentials",
                headers={"Authorization": "Bearer tok"},
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["count"] == 2
            assert data["can_authorize"] is True

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_a_non_admin_token_cannot_authorize(self, mock_cls, client):
            """The account listing and the authorize write need the same capability, so a
            403 there is exactly the signal that 'authorize' would fail."""
            mock_cls.return_value = _mock_httpx([_resp(200, []), _resp(403, None)])
            resp = await client.get(
                f"{client._base}/api/spaces/VMaaS/credentials",
                headers={"Authorization": "Bearer tok"},
            )
            data = await resp.json()
            assert data["can_authorize"] is False
            assert data["count"] == 0

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_a_failure_is_reported_not_raised(self, mock_cls, client):
            """Availability is advisory; setup must remain completable without it."""
            mock_cls.return_value = _mock_httpx([RuntimeError("boom"), RuntimeError("boom")])
            resp = await client.get(
                f"{client._base}/api/spaces/VMaaS/credentials",
                headers={"Authorization": "Bearer tok"},
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["count"] is None
            assert data["error"]

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_space_name_is_url_encoded(self, mock_cls, client):
            mock = _mock_httpx([_resp(200, []), _resp(200, [])])
            mock_cls.return_value = mock
            await client.get(
                f"{client._base}/api/spaces/My%20Space/credentials",
                headers={"Authorization": "Bearer tok"},
            )
            called = mock.get.call_args_list[0][0][0]
            assert "My%20Space" in called

    class TestCompletePersistsCredentialSettings:
        @pytest.mark.asyncio
        async def test_saves_enabled_and_policy(self, client, csrf_headers, auth_server):
            resp = await client.post(
                f"{client._base}/api/complete",
                json={
                    "token": "tok", "space": "sp", "profile_name": "creds-on",
                    "torque_url": "https://example.com",
                    "credentials_enabled": True,
                    "credentials_space_policy": "authorize",
                },
                headers=csrf_headers,
            )
            assert resp.status == 200
            profile = config_module.load_config(auth_server.config_path)["profiles"]["creds-on"]
            assert profile["credentials_enabled"] is True
            assert profile["credentials_space_policy"] == "authorize"

        @pytest.mark.asyncio
        async def test_defaults_to_disabled_when_not_sent(self, client, csrf_headers, auth_server):
            resp = await client.post(
                f"{client._base}/api/complete",
                json={"token": "tok", "space": "sp", "profile_name": "creds-default",
                      "torque_url": "https://example.com"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            profile = config_module.load_config(auth_server.config_path)["profiles"]["creds-default"]
            assert profile["credentials_enabled"] is False

        @pytest.mark.asyncio
        async def test_no_policy_is_written_when_credentials_are_off(
            self, client, csrf_headers, auth_server
        ):
            """A policy on a disabled profile would be dead config that reads as if it did
            something."""
            resp = await client.post(
                f"{client._base}/api/complete",
                json={"token": "tok", "space": "sp", "profile_name": "creds-off",
                      "torque_url": "https://example.com",
                      "credentials_enabled": False,
                      "credentials_space_policy": "authorize"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            profile = config_module.load_config(auth_server.config_path)["profiles"]["creds-off"]
            assert "credentials_space_policy" not in profile

        @pytest.mark.asyncio
        async def test_saved_settings_survive_profile_resolution(
            self, client, csrf_headers, auth_server
        ):
            """They must behave as ordinary config values — inherited and overridable —
            rather than as profile metadata like expose_values."""
            resp = await client.post(
                f"{client._base}/api/complete",
                json={"token": "tok", "space": "sp", "profile_name": "resolvable",
                      "torque_url": "https://example.com",
                      "credentials_enabled": True,
                      "credentials_space_policy": "preconfigured"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            cfg = config_module.load_config(auth_server.config_path)
            resolved = config_module.resolve_profile(cfg, "resolvable")
            assert resolved["credentials_enabled"] is True

            effective = config_module.apply_profile_to_config({}, resolved)
            assert effective["credentials_enabled"] is True
            assert effective["credentials_space_policy"] == "preconfigured"

except ImportError:  # pragma: no cover - aiohttp test utils unavailable
    pass
