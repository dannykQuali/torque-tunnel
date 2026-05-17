"""Tests for update_config_file and TorqueAuthServer."""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import config as config_module
from torque_tunnel.auth import TorqueAuthServer, _build_profile_result


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def tmp_config_dir(tmp_path):
    """Create a temp dir for config files and return it."""
    return tmp_path


@pytest.fixture
def config_with_comments(tmp_config_dir):
    """Create a config file with comments that should be preserved."""
    path = tmp_config_dir / "config.yaml"
    path.write_text(
        "# Main Torque configuration\n"
        "torque_url: https://torque.example.com\n"
        "torque_space: old-space  # the production space\n"
        "\n"
        "# Profiles section\n"
        "profiles:\n"
        "  my-profile:\n"
        "    description: My profile  # profile desc\n"
        "    torque_agent: old-agent\n",
        encoding="utf-8",
    )
    return str(path)


# ============================================================================
# update_config_file — basic functionality
# ============================================================================


class TestUpdateConfigFileBasic:
    """Tests for basic update_config_file operations."""

    def test_update_top_level_key(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text("torque_url: https://example.com\n", encoding="utf-8")

        result = config_module.update_config_file(
            {"torque_token": "new-token"},
            explicit_path=str(path),
        )
        assert result == path
        content = path.read_text(encoding="utf-8")
        assert "torque_token: new-token" in content
        assert "torque_url: https://example.com" in content

    def test_update_overwrites_existing_key(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text("torque_space: old\n", encoding="utf-8")

        config_module.update_config_file(
            {"torque_space": "new-space"},
            explicit_path=str(path),
        )
        content = path.read_text(encoding="utf-8")
        assert "torque_space: new-space" in content
        assert "old" not in content

    def test_update_multiple_keys(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text("torque_url: https://example.com\n", encoding="utf-8")

        config_module.update_config_file(
            {
                "torque_token": "tok",
                "torque_space": "sp",
                "torque_agent": "ag",
                "torque_token_id": "id-123",
            },
            explicit_path=str(path),
        )
        content = path.read_text(encoding="utf-8")
        assert "torque_token: tok" in content
        assert "torque_space: sp" in content
        assert "torque_agent: ag" in content
        assert "torque_token_id: id-123" in content

    def test_creates_file_if_missing(self, tmp_config_dir, monkeypatch):
        """If no config file exists, update_config_file creates one at default path."""
        default_path = tmp_config_dir / ".torque-tunnel" / "config.yaml"
        monkeypatch.setattr(config_module, "_default_config_path", lambda: default_path)

        result = config_module.update_config_file(
            {"torque_token": "new-token"},
        )
        assert result == default_path
        assert default_path.exists()
        content = default_path.read_text(encoding="utf-8")
        assert "torque_token: new-token" in content

    def test_empty_file_works(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text("", encoding="utf-8")

        config_module.update_config_file(
            {"torque_space": "my-space"},
            explicit_path=str(path),
        )
        content = path.read_text(encoding="utf-8")
        assert "torque_space: my-space" in content


# ============================================================================
# update_config_file — comment preservation
# ============================================================================


class TestUpdateConfigFileComments:
    """Tests that comments and formatting are preserved via ruamel.yaml."""

    def test_preserves_inline_comments(self, config_with_comments):
        config_module.update_config_file(
            {"torque_token": "new-token"},
            explicit_path=config_with_comments,
        )
        content = Path(config_with_comments).read_text(encoding="utf-8")
        assert "# the production space" in content
        assert "torque_token: new-token" in content

    def test_preserves_section_comments(self, config_with_comments):
        config_module.update_config_file(
            {"torque_space": "updated-space"},
            explicit_path=config_with_comments,
        )
        content = Path(config_with_comments).read_text(encoding="utf-8")
        assert "# Main Torque configuration" in content
        assert "# Profiles section" in content

    def test_preserves_profile_comments(self, config_with_comments):
        config_module.update_config_file(
            {"torque_agent": "new-agent"},
            profile_name="my-profile",
            explicit_path=config_with_comments,
        )
        content = Path(config_with_comments).read_text(encoding="utf-8")
        assert "# profile desc" in content


# ============================================================================
# update_config_file — profile operations
# ============================================================================


class TestUpdateConfigFileProfiles:
    """Tests for updating profiles in config files."""

    def test_update_existing_profile(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text(
            "profiles:\n"
            "  lab:\n"
            "    torque_agent: old-agent\n",
            encoding="utf-8",
        )

        config_module.update_config_file(
            {"torque_token": "tok", "torque_space": "sp"},
            profile_name="lab",
            explicit_path=str(path),
        )
        data = config_module.load_config(str(path))
        assert data["profiles"]["lab"]["torque_token"] == "tok"
        assert data["profiles"]["lab"]["torque_space"] == "sp"
        # Original key preserved
        assert data["profiles"]["lab"]["torque_agent"] == "old-agent"

    def test_update_nonexistent_profile_creates_it(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text("torque_url: https://example.com\n", encoding="utf-8")

        config_module.update_config_file(
            {"torque_token": "tok"},
            profile_name="new-profile",
            explicit_path=str(path),
        )
        data = config_module.load_config(str(path))
        assert data["profiles"]["new-profile"]["torque_token"] == "tok"
        # Top-level key preserved
        assert data["torque_url"] == "https://example.com"

    def test_profile_update_does_not_affect_top_level(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text(
            "torque_token: top-level-token\n"
            "profiles:\n"
            "  lab:\n"
            "    host: 10.0.0.1\n",
            encoding="utf-8",
        )

        config_module.update_config_file(
            {"torque_token": "profile-token"},
            profile_name="lab",
            explicit_path=str(path),
        )
        data = config_module.load_config(str(path))
        assert data["torque_token"] == "top-level-token"
        assert data["profiles"]["lab"]["torque_token"] == "profile-token"

    def test_new_top_level_key_inserted_before_profiles(self, tmp_config_dir):
        path = tmp_config_dir / "config.yaml"
        path.write_text(
            "torque_url: https://example.com\n"
            "profiles:\n"
            "  lab:\n"
            "    torque_token: tok\n",
            encoding="utf-8",
        )

        config_module.update_config_file(
            {"default_profile": "lab"},
            explicit_path=str(path),
        )
        # Verify key ordering in the raw YAML text
        raw = path.read_text(encoding="utf-8")
        dp_pos = raw.index("default_profile:")
        prof_pos = raw.index("profiles:")
        assert dp_pos < prof_pos, f"default_profile at {dp_pos} should come before profiles at {prof_pos}"


# ============================================================================
# update_config_file — round-trip preservation
# ============================================================================


class TestUpdateConfigFileRoundTrip:
    """Tests that updating doesn't corrupt the rest of the YAML file."""

    def test_complex_config_survives_update(self, tmp_config_dir):
        original = (
            "torque_url: https://torque.example.com\n"
            "torque_token: old-token\n"
            "ssh_user: root\n"
            "auto_delete_environments: false\n"
            "container_idle_timeout: 7200\n"
            "profiles:\n"
            "  base:\n"
            "    description: Base profile\n"
            "    torque_agent: agent-1\n"
            "  derived:\n"
            "    extends: base\n"
            "    host: 10.0.0.1\n"
        )
        path = tmp_config_dir / "config.yaml"
        path.write_text(original, encoding="utf-8")

        config_module.update_config_file(
            {"torque_token": "new-token", "torque_space": "new-space"},
            explicit_path=str(path),
        )

        data = config_module.load_config(str(path))
        # Updated keys
        assert data["torque_token"] == "new-token"
        assert data["torque_space"] == "new-space"
        # Preserved keys
        assert data["torque_url"] == "https://torque.example.com"
        assert data["ssh_user"] == "root"
        assert data["auto_delete_environments"] is False
        assert data["container_idle_timeout"] == 7200
        # Profiles preserved
        assert data["profiles"]["base"]["description"] == "Base profile"
        assert data["profiles"]["derived"]["extends"] == "base"


# ============================================================================
# TorqueAuthServer — unit tests
# ============================================================================


class TestBuildProfileResult:
    """Tests for _build_profile_result helper."""

    def test_creates_with_all_fields(self):
        updates = {
            "torque_url": "https://x.com",
            "torque_token": "t",
            "torque_token_id": "id",
            "torque_space": "sp",
            "torque_agent": "agent1",
            "description": "my profile",
            "expose_values": True,
        }
        r = _build_profile_result("p", updates, is_default=True)
        assert r["name"] == "p"
        assert r["description"] == "my profile"
        assert r["expose_values"] is True
        assert r["is_default"] is True
        assert "torque_url" in r["overrides"]
        assert "torque_token" in r["overrides"]
        assert r["values"]["torque_url"] == "https://x.com"
        # Meta keys excluded from overrides
        assert "description" not in r["overrides"]
        assert "expose_values" not in r["overrides"]

    def test_minimal_fields(self):
        updates = {"torque_url": "https://x.com", "torque_token": "t", "torque_space": "sp"}
        r = _build_profile_result("p", updates)
        assert r["description"] == ""
        assert r["extends"] is None
        assert r["expose_values"] is False
        assert r["is_default"] is False
        assert set(r["overrides"]) == {"torque_url", "torque_token", "torque_space"}

    def test_overrides_are_sorted(self):
        updates = {"z_key": "z", "a_key": "a", "m_key": "m"}
        r = _build_profile_result("p", updates)
        assert r["overrides"] == ["a_key", "m_key", "z_key"]


class TestTorqueAuthServerInit:
    """Tests for TorqueAuthServer initialization."""

    def test_strips_trailing_slash(self):
        s = TorqueAuthServer("https://example.com/")
        assert s.torque_url == "https://example.com"

    def test_stores_config_path(self):
        s = TorqueAuthServer("https://example.com", config_path="/tmp/c.yaml", profile_name="p")
        assert s.config_path == "/tmp/c.yaml"
        assert s.profile_name == "p"

    def test_default_timeout(self):
        s = TorqueAuthServer("https://example.com")
        assert s.timeout == 1800

    def test_custom_timeout(self):
        s = TorqueAuthServer("https://example.com", timeout=60)
        assert s.timeout == 60

    def test_csrf_token_generated(self):
        s = TorqueAuthServer("https://example.com")
        assert s._csrf_token
        assert len(s._csrf_token) > 20

    def test_different_csrf_per_instance(self):
        s1 = TorqueAuthServer("https://example.com")
        s2 = TorqueAuthServer("https://example.com")
        assert s1._csrf_token != s2._csrf_token

    def test_none_torque_url(self):
        s = TorqueAuthServer(torque_url=None)
        assert s.torque_url == ""

    def test_empty_torque_url(self):
        s = TorqueAuthServer(torque_url="")
        assert s.torque_url == ""

    def test_profile_name_defaults_to_empty(self):
        s = TorqueAuthServer("https://example.com")
        assert s.profile_name == ""

    def test_none_profile_name_becomes_empty(self):
        s = TorqueAuthServer("https://example.com", profile_name=None)
        assert s.profile_name == ""


class TestTorqueAuthServerApp:
    """Tests for the aiohttp app created by TorqueAuthServer."""

    def test_creates_app_with_routes(self):
        s = TorqueAuthServer("https://example.com")
        app = s._create_app()
        route_paths = {r.resource.canonical for r in app.router.routes() if hasattr(r, 'resource')}
        secret = s._url_secret
        assert f"/{secret}" in route_paths
        assert f"/{secret}/health" in route_paths
        assert f"/{secret}/api/login" in route_paths
        assert f"/{secret}/api/validate-token" in route_paths
        assert f"/{secret}/api/spaces" in route_paths
        assert f"/{secret}/api/spaces/{{space}}/agents" in route_paths
        assert f"/{secret}/api/agents" in route_paths
        assert f"/{secret}/api/generate-token" in route_paths
        assert f"/{secret}/api/complete" in route_paths
        assert f"/{secret}/api/cancel" in route_paths
        assert f"/{secret}/api/profiles" in route_paths
        assert f"/{secret}/api/use-profile" in route_paths


# ============================================================================
# TorqueAuthServer — handler tests via aiohttp test client
# ============================================================================


@pytest.fixture
def auth_server(tmp_path):
    """Create a TorqueAuthServer with a temp config path."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("torque_url: https://torque.example.com\n", encoding="utf-8")
    return TorqueAuthServer(
        torque_url="https://torque.example.com",
        config_path=str(config_path),
    )


@pytest.fixture
def csrf_headers(auth_server):
    """Return headers with valid CSRF token."""
    return {
        "Content-Type": "application/json",
        "X-CSRF-Token": auth_server._csrf_token,
    }


@pytest.fixture
def bad_csrf_headers():
    """Return headers with invalid CSRF token."""
    return {
        "Content-Type": "application/json",
        "X-CSRF-Token": "bad-token",
    }


try:
    from aiohttp.test_utils import AioHTTPTestCase, TestClient, TestServer
    from aiohttp import web

    @pytest_asyncio.fixture
    async def client(auth_server):
        """Create an aiohttp test client for the auth server."""
        app = auth_server._create_app()
        async with TestClient(TestServer(app)) as c:
            c._base = f"/{auth_server._url_secret}"
            yield c

    class TestUrlSecretProtection:
        """Requests without the correct URL secret should be rejected."""

        @pytest.mark.asyncio
        async def test_root_without_secret_returns_404(self, client):
            resp = await client.get("/")
            assert resp.status == 404

        @pytest.mark.asyncio
        async def test_health_without_secret_returns_404(self, client):
            resp = await client.get("/health")
            assert resp.status == 404

        @pytest.mark.asyncio
        async def test_api_without_secret_returns_404(self, client, csrf_headers):
            resp = await client.post("/api/login", json={"email": "a", "password": "b"}, headers=csrf_headers)
            assert resp.status == 404

        @pytest.mark.asyncio
        async def test_wrong_secret_returns_404(self, client, csrf_headers):
            resp = await client.get("/wrong-secret")
            assert resp.status == 404

        @pytest.mark.asyncio
        async def test_wrong_secret_api_returns_404(self, client, csrf_headers):
            resp = await client.post("/wrong-secret/api/login", json={"email": "a", "password": "b"}, headers=csrf_headers)
            assert resp.status == 404

    class TestHealthEndpoint:
        @pytest.mark.asyncio
        async def test_health(self, client):
            resp = await client.get(f"{client._base}/health")
            assert resp.status == 200
            data = await resp.json()
            assert data["status"] == "ok"

    class TestLoginPage:
        @pytest.mark.asyncio
        async def test_returns_html(self, client):
            resp = await client.get(client._base)
            assert resp.status == 200
            text = await resp.text()
            assert "<!DOCTYPE html>" in text
            assert "Torque Tunnel" in text

        @pytest.mark.asyncio
        async def test_contains_torque_url(self, client):
            resp = await client.get(client._base)
            text = await resp.text()
            assert "https://torque.example.com" in text

        @pytest.mark.asyncio
        async def test_contains_csrf_token(self, client, auth_server):
            resp = await client.get(client._base)
            text = await resp.text()
            assert auth_server._csrf_token in text

        @pytest.mark.asyncio
        async def test_url_step_shown_when_no_url(self, tmp_path):
            """When torque_url is empty, the URL selection step should appear."""
            config_path = tmp_path / "config.yaml"
            config_path.write_text("", encoding="utf-8")
            server = TorqueAuthServer(torque_url=None, config_path=str(config_path))
            app = server._create_app()
            async with TestClient(TestServer(app)) as c:
                resp = await c.get(f"/{server._url_secret}")
                text = await resp.text()
                assert 'INITIAL_TORQUE_URL = ""' in text
                assert 'step-url' in text

        @pytest.mark.asyncio
        async def test_login_step_when_url_provided(self, client):
            """When torque_url is provided, URL step is skipped."""
            resp = await client.get(client._base)
            text = await resp.text()
            assert 'INITIAL_TORQUE_URL = "https://torque.example.com"' in text

    class TestCsrfProtection:
        @pytest.mark.asyncio
        async def test_login_rejects_bad_csrf(self, client, bad_csrf_headers):
            resp = await client.post(f"{client._base}/api/login", json={"email": "a", "password": "b"}, headers=bad_csrf_headers)
            assert resp.status == 403

        @pytest.mark.asyncio
        async def test_login_rejects_missing_csrf(self, client):
            resp = await client.post(f"{client._base}/api/login", json={"email": "a", "password": "b"})
            assert resp.status == 403

        @pytest.mark.asyncio
        async def test_validate_token_rejects_bad_csrf(self, client, bad_csrf_headers):
            resp = await client.post(f"{client._base}/api/validate-token", json={"token": "t"}, headers=bad_csrf_headers)
            assert resp.status == 403

        @pytest.mark.asyncio
        async def test_generate_token_rejects_bad_csrf(self, client, bad_csrf_headers):
            resp = await client.post(f"{client._base}/api/generate-token", json={"token": "t", "space": "s"}, headers=bad_csrf_headers)
            assert resp.status == 403

        @pytest.mark.asyncio
        async def test_complete_rejects_bad_csrf(self, client, bad_csrf_headers):
            resp = await client.post(f"{client._base}/api/complete", json={"token": "t", "space": "s"}, headers=bad_csrf_headers)
            assert resp.status == 403

    class TestLoginEndpoint:
        @pytest.mark.asyncio
        async def test_missing_email(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/login", json={"email": "", "password": "p"}, headers=csrf_headers)
            assert resp.status == 400

        @pytest.mark.asyncio
        async def test_missing_password(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/login", json={"email": "e", "password": ""}, headers=csrf_headers)
            assert resp.status == 400

        @pytest.mark.asyncio
        async def test_missing_torque_url_when_server_has_none(self, tmp_path):
            """Login fails if no torque_url from body or server."""
            config_path = tmp_path / "config.yaml"
            config_path.write_text("", encoding="utf-8")
            server = TorqueAuthServer(torque_url=None, config_path=str(config_path))
            app = server._create_app()
            async with TestClient(TestServer(app)) as c:
                resp = await c.post(
                    f"/{server._url_secret}/api/login",
                    json={"email": "e", "password": "p"},
                    headers={"Content-Type": "application/json", "X-CSRF-Token": server._csrf_token},
                )
                assert resp.status == 400
                data = await resp.json()
                assert "URL" in data["error"]

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_successful_login(self, mock_client_cls, client, csrf_headers):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"account1": {"access_token": "tok"}}

            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            resp = await client.post(
                f"{client._base}/api/login",
                json={"email": "user@test.com", "password": "pass", "torque_url": "https://torque.example.com"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            data = await resp.json()
            assert "account1" in data

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_login_updates_server_url(self, mock_client_cls, client, csrf_headers, auth_server):
            """Login request with torque_url updates the server's torque_url."""
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"acc": {"access_token": "t"}}

            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            resp = await client.post(
                f"{client._base}/api/login",
                json={"email": "u@t.com", "password": "p", "torque_url": "https://new-server.example.com"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            assert auth_server.torque_url == "https://new-server.example.com"

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_login_invalid_credentials(self, mock_client_cls, client, csrf_headers):
            mock_resp = MagicMock()
            mock_resp.status_code = 401

            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            resp = await client.post(
                f"{client._base}/api/login",
                json={"email": "user@test.com", "password": "wrong"},
                headers=csrf_headers,
            )
            assert resp.status == 401
            data = await resp.json()
            assert "error" in data

    class TestValidateTokenEndpoint:
        @pytest.mark.asyncio
        async def test_missing_token(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/validate-token", json={"token": ""}, headers=csrf_headers)
            assert resp.status == 400

        @pytest.mark.asyncio
        async def test_missing_torque_url_when_server_has_none(self, tmp_path):
            """Validate-token fails if no torque_url from body or server."""
            config_path = tmp_path / "config.yaml"
            config_path.write_text("", encoding="utf-8")
            server = TorqueAuthServer(torque_url=None, config_path=str(config_path))
            app = server._create_app()
            async with TestClient(TestServer(app)) as c:
                resp = await c.post(
                    f"/{server._url_secret}/api/validate-token",
                    json={"token": "some-token"},
                    headers={"Content-Type": "application/json", "X-CSRF-Token": server._csrf_token},
                )
                assert resp.status == 400
                data = await resp.json()
                assert "URL" in data["error"]

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_valid_token(self, mock_client_cls, client, csrf_headers):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [{"name": "space1"}]

            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            resp = await client.post(
                f"{client._base}/api/validate-token",
                json={"token": "valid-token"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            data = await resp.json()
            assert "spaces" in data

    class TestGenerateTokenEndpoint:
        @pytest.mark.asyncio
        async def test_missing_fields(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/generate-token", json={"token": "t"}, headers=csrf_headers)
            assert resp.status == 400

        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_successful_generation(self, mock_client_cls, client, csrf_headers):
            # Mock the long token generation response
            gen_resp = MagicMock()
            gen_resp.status_code = 200
            gen_resp.json.return_value = {"access_token": "long-tok", "token_type": "Bearer"}

            # Mock the list tokens response
            list_resp = MagicMock()
            list_resp.status_code = 200
            list_resp.json.return_value = [
                {"id": "uuid-123", "title": "torque-tunnel-HOSTNAME"},
            ]

            mock_client = AsyncMock()
            mock_client.post.return_value = gen_resp
            mock_client.get.return_value = list_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            resp = await client.post(
                f"{client._base}/api/generate-token",
                json={"token": "short-tok", "space": "my-space"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["access_token"] == "long-tok"

    class TestCompleteEndpoint:
        @pytest.mark.asyncio
        async def test_missing_token(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/complete", json={"space": "s", "profile_name": "p"}, headers=csrf_headers)
            assert resp.status == 400

        @pytest.mark.asyncio
        async def test_missing_space(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/complete", json={"token": "t", "profile_name": "p"}, headers=csrf_headers)
            assert resp.status == 400

        @pytest.mark.asyncio
        async def test_missing_profile_name(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/complete", json={"token": "t", "space": "s"}, headers=csrf_headers)
            assert resp.status == 400
            data = await resp.json()
            assert "profile name" in data["error"].lower()

        @pytest.mark.asyncio
        async def test_saves_config(self, client, csrf_headers, auth_server, tmp_path):
            resp = await client.post(
                f"{client._base}/api/complete",
                json={
                    "token": "long-token-val",
                    "token_id": "id-456",
                    "space": "my-space",
                    "agent": "my-agent",
                    "account": "my-account",
                    "torque_url": "https://torque.example.com",
                    "profile_name": "my-profile",
                },
                headers=csrf_headers,
            )
            assert resp.status == 200
            data = await resp.json()
            assert data["status"] == "ok"
            assert "config_path" in data

            # Verify config file was updated — saved to profile
            cfg = config_module.load_config(auth_server.config_path)
            profile = cfg["profiles"]["my-profile"]
            assert profile["torque_token"] == "long-token-val"
            assert profile["torque_space"] == "my-space"
            assert profile["torque_agent"] == "my-agent"
            assert profile["torque_token_id"] == "id-456"
            assert profile["torque_url"] == "https://torque.example.com"

        @pytest.mark.asyncio
        async def test_saves_description_and_init_commands(self, client, csrf_headers, auth_server):
            resp = await client.post(
                f"{client._base}/api/complete",
                json={
                    "token": "tok",
                    "space": "sp",
                    "profile_name": "desc-test",
                    "torque_url": "https://example.com",
                    "description": "My corp network behind proxy",
                    "init_commands": "export HTTPS_PROXY=http://proxy:8080",
                },
                headers=csrf_headers,
            )
            assert resp.status == 200
            cfg = config_module.load_config(auth_server.config_path)
            profile = cfg["profiles"]["desc-test"]
            assert profile["description"] == "My corp network behind proxy"
            assert profile["init_commands"] == "export HTTPS_PROXY=http://proxy:8080"

        @pytest.mark.asyncio
        async def test_sets_result_and_completed(self, client, csrf_headers, auth_server):
            resp = await client.post(
                f"{client._base}/api/complete",
                json={"token": "tok", "space": "sp", "profile_name": "p", "torque_url": "https://x.com"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            assert auth_server._completed.is_set()
            assert auth_server._result is not None
            assert auth_server._result["values"]["torque_token"] == "tok"
            assert auth_server._result["values"]["torque_space"] == "sp"
            assert auth_server._result["values"]["torque_url"] == "https://x.com"

        @pytest.mark.asyncio
        async def test_agent_is_optional(self, client, csrf_headers, auth_server):
            resp = await client.post(
                f"{client._base}/api/complete",
                json={"token": "tok", "space": "sp", "profile_name": "p"},
                headers=csrf_headers,
            )
            assert resp.status == 200
            assert "torque_agent" not in auth_server._result["values"]

        @pytest.mark.asyncio
        async def test_updates_server_torque_url(self, client, csrf_headers, auth_server):
            """Complete should update the server's torque_url for revocation."""
            resp = await client.post(
                f"{client._base}/api/complete",
                json={
                    "token": "tok",
                    "space": "sp",
                    "profile_name": "p",
                    "torque_url": "https://new-url.example.com",
                },
                headers=csrf_headers,
            )
            assert resp.status == 200
            assert auth_server.torque_url == "https://new-url.example.com"
            assert auth_server.profile_name == "p"

        @pytest.mark.asyncio
        async def test_set_as_default_true(self, client, csrf_headers, auth_server):
            """When set_as_default is true, default_profile is set in config."""
            resp = await client.post(
                f"{client._base}/api/complete",
                json={
                    "token": "tok",
                    "space": "sp",
                    "profile_name": "my-default",
                    "torque_url": "https://example.com",
                    "set_as_default": True,
                },
                headers=csrf_headers,
            )
            assert resp.status == 200
            cfg = config_module.load_config(auth_server.config_path)
            assert cfg["default_profile"] == "my-default"

        @pytest.mark.asyncio
        async def test_set_as_default_false(self, client, csrf_headers, auth_server):
            """When set_as_default is false, default_profile is not set."""
            resp = await client.post(
                f"{client._base}/api/complete",
                json={
                    "token": "tok",
                    "space": "sp",
                    "profile_name": "no-default",
                    "torque_url": "https://example.com",
                    "set_as_default": False,
                },
                headers=csrf_headers,
            )
            assert resp.status == 200
            cfg = config_module.load_config(auth_server.config_path)
            assert cfg.get("default_profile") is None

        @pytest.mark.asyncio
        async def test_set_as_default_preserves_existing(self, tmp_path):
            """When set_as_default is false, existing default_profile is preserved."""
            config_path = tmp_path / "config.yaml"
            config_path.write_text(
                "default_profile: old-prof\n"
                "profiles:\n"
                "  old-prof:\n"
                "    torque_url: https://example.com\n"
                "    torque_token: old-tok\n",
                encoding="utf-8",
            )
            s = TorqueAuthServer(torque_url="https://example.com", config_path=str(config_path))
            app = s._create_app()
            headers = {"Content-Type": "application/json", "X-CSRF-Token": s._csrf_token}
            async with TestClient(TestServer(app)) as c:
                resp = await c.post(
                    f"/{s._url_secret}/api/complete",
                    json={
                        "token": "tok",
                        "space": "sp",
                        "profile_name": "new-prof",
                        "torque_url": "https://example.com",
                        "set_as_default": False,
                    },
                    headers=headers,
                )
                assert resp.status == 200
                cfg = config_module.load_config(str(config_path))
                assert cfg["default_profile"] == "old-prof"

    class TestCancelEndpoint:
        @pytest.mark.asyncio
        async def test_cancel_sets_cancelled(self, client, csrf_headers, auth_server):
            resp = await client.post(f"{client._base}/api/cancel", headers=csrf_headers)
            assert resp.status == 200
            data = await resp.json()
            assert data["status"] == "cancelled"
            assert auth_server._cancelled is True
            assert auth_server._completed.is_set()

        @pytest.mark.asyncio
        async def test_cancel_rejects_bad_csrf(self, client, bad_csrf_headers):
            resp = await client.post(f"{client._base}/api/cancel", headers=bad_csrf_headers)
            assert resp.status == 403

    class TestHealthHeartbeat:
        @pytest.mark.asyncio
        async def test_health_updates_heartbeat(self, client, auth_server):
            import time
            old = auth_server._last_heartbeat
            await client.get(f"{client._base}/health")
            assert auth_server._last_heartbeat >= old

    class TestAllAgentsEndpoint:
        @pytest.mark.asyncio
        @patch("torque_tunnel.auth.httpx.AsyncClient")
        async def test_proxies_account_agents(self, mock_client_cls, client, csrf_headers):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = [
                {"name": "agent1", "status": "active", "spaces": ["sp1", "sp2"], "type": "k8s"},
                {"name": "agent2", "status": "error", "spaces": ["sp1"], "type": "vcenter"},
            ]

            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            resp = await client.get(
                f"{client._base}/api/agents",
                headers={"Authorization": "Bearer tok"},
            )
            assert resp.status == 200
            data = await resp.json()
            assert len(data) == 2
            assert data[0]["name"] == "agent1"
            assert data[0]["spaces"] == ["sp1", "sp2"]

    class TestListProfilesEndpoint:
        """Tests for GET /api/profiles."""

        @pytest.mark.asyncio
        async def test_returns_empty_when_no_profiles(self, client):
            resp = await client.get(f"{client._base}/api/profiles")
            assert resp.status == 200
            data = await resp.json()
            assert data["profiles"] == []
            assert data["has_default_profile"] is False

        @pytest.mark.asyncio
        async def test_returns_profiles(self, tmp_path):
            config_path = tmp_path / "config.yaml"
            config_path.write_text(
                "profiles:\n"
                "  my-prof:\n"
                "    description: test profile\n"
                "    torque_url: https://example.com\n"
                "    torque_token: secret-token\n"
                "  no-token:\n"
                "    torque_url: https://other.com\n",
                encoding="utf-8",
            )
            s = TorqueAuthServer(torque_url="https://example.com", config_path=str(config_path))
            app = s._create_app()
            async with TestClient(TestServer(app)) as c:
                resp = await c.get(f"/{s._url_secret}/api/profiles")
                assert resp.status == 200
                data = await resp.json()
                profiles = data["profiles"]
                assert len(profiles) == 2
                prof1 = next(p for p in profiles if p["name"] == "my-prof")
                assert prof1["description"] == "test profile"
                assert prof1["torque_url"] == "https://example.com"
                assert prof1["has_token"] is True
                prof2 = next(p for p in profiles if p["name"] == "no-token")
                assert prof2["has_token"] is False
                assert data["has_default_profile"] is False

        @pytest.mark.asyncio
        async def test_returns_empty_when_no_config_file(self):
            s = TorqueAuthServer(torque_url="https://example.com", config_path="/nonexistent/path.yaml")
            app = s._create_app()
            async with TestClient(TestServer(app)) as c:
                resp = await c.get(f"/{s._url_secret}/api/profiles")
                assert resp.status == 200
                data = await resp.json()
                assert data == {"profiles": [], "has_default_profile": False}

        @pytest.mark.asyncio
        async def test_has_default_profile_true_when_set(self, tmp_path):
            config_path = tmp_path / "config.yaml"
            config_path.write_text(
                "default_profile: my-prof\n"
                "profiles:\n"
                "  my-prof:\n"
                "    torque_url: https://example.com\n"
                "    torque_token: tok\n",
                encoding="utf-8",
            )
            s = TorqueAuthServer(torque_url="https://example.com", config_path=str(config_path))
            app = s._create_app()
            async with TestClient(TestServer(app)) as c:
                resp = await c.get(f"/{s._url_secret}/api/profiles")
                data = await resp.json()
                assert data["has_default_profile"] is True

    class TestUseProfileEndpoint:
        """Tests for POST /api/use-profile."""

        @pytest.mark.asyncio
        async def test_missing_profile_name(self, client, csrf_headers):
            resp = await client.post(f"{client._base}/api/use-profile", json={}, headers=csrf_headers)
            assert resp.status == 400

        @pytest.mark.asyncio
        async def test_profile_not_found(self, client, csrf_headers):
            resp = await client.post(
                f"{client._base}/api/use-profile",
                json={"profile_name": "nonexistent"},
                headers=csrf_headers,
            )
            assert resp.status == 404

        @pytest.mark.asyncio
        async def test_profile_no_token(self, tmp_path):
            config_path = tmp_path / "config.yaml"
            config_path.write_text(
                "profiles:\n"
                "  empty:\n"
                "    torque_url: https://example.com\n",
                encoding="utf-8",
            )
            s = TorqueAuthServer(torque_url="https://example.com", config_path=str(config_path))
            app = s._create_app()
            headers = {"Content-Type": "application/json", "X-CSRF-Token": s._csrf_token}
            async with TestClient(TestServer(app)) as c:
                resp = await c.post(f"/{s._url_secret}/api/use-profile", json={"profile_name": "empty"}, headers=headers)
                assert resp.status == 400
                data = await resp.json()
                assert "no token" in data["error"]

        @pytest.mark.asyncio
        async def test_profile_no_url(self, tmp_path):
            config_path = tmp_path / "config.yaml"
            config_path.write_text(
                "profiles:\n"
                "  no-url:\n"
                "    torque_token: some-token\n",
                encoding="utf-8",
            )
            s = TorqueAuthServer(config_path=str(config_path))
            app = s._create_app()
            headers = {"Content-Type": "application/json", "X-CSRF-Token": s._csrf_token}
            async with TestClient(TestServer(app)) as c:
                resp = await c.post(f"/{s._url_secret}/api/use-profile", json={"profile_name": "no-url"}, headers=headers)
                assert resp.status == 400
                data = await resp.json()
                assert "no torque_url" in data["error"]

        @pytest.mark.asyncio
        async def test_valid_profile_success(self, tmp_path):
            config_path = tmp_path / "config.yaml"
            config_path.write_text(
                "profiles:\n"
                "  good:\n"
                "    torque_url: https://torque.example.com\n"
                "    torque_token: valid-token\n"
                "    torque_token_id: tok-id-123\n",
                encoding="utf-8",
            )
            s = TorqueAuthServer(config_path=str(config_path))
            app = s._create_app()
            headers = {"Content-Type": "application/json", "X-CSRF-Token": s._csrf_token}
            spaces_response = [{"name": "space1"}, {"name": "space2"}]
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = spaces_response
                mock_get.return_value = mock_resp
                async with TestClient(TestServer(app)) as c:
                    resp = await c.post(f"/{s._url_secret}/api/use-profile", json={"profile_name": "good"}, headers=headers)
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["token"] == "valid-token"
                    assert data["torque_url"] == "https://torque.example.com"
                    assert data["token_id"] == "tok-id-123"
                    assert data["spaces"] == spaces_response
            # Server torque_url should be updated
            assert s.torque_url == "https://torque.example.com"

        @pytest.mark.asyncio
        async def test_expired_token(self, tmp_path):
            config_path = tmp_path / "config.yaml"
            config_path.write_text(
                "profiles:\n"
                "  expired:\n"
                "    torque_url: https://torque.example.com\n"
                "    torque_token: expired-token\n",
                encoding="utf-8",
            )
            s = TorqueAuthServer(config_path=str(config_path))
            app = s._create_app()
            headers = {"Content-Type": "application/json", "X-CSRF-Token": s._csrf_token}
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 401
                mock_get.return_value = mock_resp
                async with TestClient(TestServer(app)) as c:
                    resp = await c.post(f"/{s._url_secret}/api/use-profile", json={"profile_name": "expired"}, headers=headers)
                    assert resp.status == 401
                    data = await resp.json()
                    assert "invalid or expired" in data["error"]

        @pytest.mark.asyncio
        async def test_requires_csrf(self, client, bad_csrf_headers):
            resp = await client.post(
                f"{client._base}/api/use-profile",
                json={"profile_name": "test"},
                headers=bad_csrf_headers,
            )
            assert resp.status == 403

except ImportError:
    # aiohttp test utils not available — skip HTTP tests
    pass


# ============================================================================
# TorqueAuthServer.run — integration test
# ============================================================================


class TestAuthServerRun:
    """Tests for the full server run() lifecycle."""

    @pytest.mark.asyncio
    async def test_timeout(self):
        """Server times out if no completion happens."""
        server = TorqueAuthServer("https://example.com", timeout=1)
        with patch("torque_tunnel.auth.webbrowser.open"):
            with pytest.raises(TimeoutError, match="timed out"):
                await server.run()

    @pytest.mark.asyncio
    async def test_server_shuts_down_after_timeout(self):
        """Server runner is cleaned up even on timeout."""
        server = TorqueAuthServer("https://example.com", timeout=1)
        with patch("torque_tunnel.auth.webbrowser.open"):
            with pytest.raises(TimeoutError):
                await server.run()
        # Runner should be cleaned up (no lingering server)
        assert server._runner is not None  # runner was created

    @pytest.mark.asyncio
    async def test_opens_browser(self):
        """Server calls webbrowser.open with localhost URL."""
        server = TorqueAuthServer("https://example.com", timeout=1)
        mock_open = MagicMock()
        with patch("torque_tunnel.auth.webbrowser.open", mock_open):
            with pytest.raises(TimeoutError):
                await server.run()
        mock_open.assert_called_once()
        url = mock_open.call_args[0][0]
        assert url.startswith("http://127.0.0.1:")

    @pytest.mark.asyncio
    async def test_returns_result_on_completion(self, tmp_path):
        """Server returns profile dict when _completed is set."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text("torque_url: https://example.com\n", encoding="utf-8")

        server = TorqueAuthServer(
            "https://example.com",
            config_path=str(config_path),
            timeout=5,
        )

        async def complete_after_start():
            # Wait briefly for server to start
            await asyncio.sleep(0.1)
            # Simulate the /api/complete endpoint being called
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Find the port from the webbrowser.open call
                url = mock_open.call_args[0][0]
                async with session.post(
                    f"{url}/api/complete",
                    json={
                        "token": "test-tok",
                        "space": "test-space",
                        "profile_name": "test-profile",
                        "torque_url": "https://example.com",
                    },
                    headers={"X-CSRF-Token": server._csrf_token},
                ) as resp:
                    assert resp.status == 200

        mock_open = MagicMock()
        with patch("torque_tunnel.auth.webbrowser.open", mock_open):
            # Start server + completion task concurrently
            result = await asyncio.gather(
                server.run(),
                complete_after_start(),
            )

        auth_result = result[0]
        assert isinstance(auth_result, dict)
        assert auth_result["name"] == "test-profile"
        assert auth_result["values"]["torque_token"] == "test-tok"
        assert auth_result["values"]["torque_space"] == "test-space"
        assert auth_result["values"]["torque_url"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_returns_none_on_cancel(self):
        """Server returns None when cancelled via /api/cancel."""
        server = TorqueAuthServer("https://example.com", timeout=5)

        async def cancel_after_start():
            await asyncio.sleep(0.1)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = mock_open.call_args[0][0]
                async with session.post(
                    f"{url}/api/cancel",
                    headers={"X-CSRF-Token": server._csrf_token},
                ) as resp:
                    assert resp.status == 200

        mock_open = MagicMock()
        with patch("torque_tunnel.auth.webbrowser.open", mock_open):
            result = await asyncio.gather(
                server.run(),
                cancel_after_start(),
            )

        assert result[0] is None

    @pytest.mark.asyncio
    async def test_returns_none_on_heartbeat_stale(self):
        """Server returns None when heartbeat goes stale (browser tab closed)."""
        server = TorqueAuthServer("https://example.com", timeout=30)
        # Use very short intervals so the test is fast
        server._heartbeat_stale_seconds = 0.05
        server._heartbeat_check_interval = 0.1

        mock_open = MagicMock()
        with patch("torque_tunnel.auth.webbrowser.open", mock_open):
            result = await server.run()

        assert result is None


# ============================================================================
# Revoke old token
# ============================================================================


class TestRevokeOldToken:
    @pytest.mark.asyncio
    async def test_revokes_when_token_id_exists(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "torque_url: https://example.com\n"
            "torque_token: old-tok\n"
            "torque_token_id: old-id\n",
            encoding="utf-8",
        )
        server = TorqueAuthServer("https://example.com", config_path=str(config_path))

        with patch("torque_tunnel.auth.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            await server._revoke_old_token("new-tok", "sp")
            mock_client.delete.assert_called_once()
            call_url = mock_client.delete.call_args[0][0]
            assert "old-id" in call_url

    @pytest.mark.asyncio
    async def test_no_revoke_when_no_token_id(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "torque_url: https://example.com\n"
            "torque_token: old-tok\n",
            encoding="utf-8",
        )
        server = TorqueAuthServer("https://example.com", config_path=str(config_path))

        with patch("torque_tunnel.auth.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            await server._revoke_old_token("new-tok", "sp")
            mock_client.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_revoke_failure_is_silent(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "torque_url: https://example.com\n"
            "torque_token: old-tok\n"
            "torque_token_id: old-id\n",
            encoding="utf-8",
        )
        server = TorqueAuthServer("https://example.com", config_path=str(config_path))

        with patch("torque_tunnel.auth.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.delete.side_effect = Exception("network error")
            mock_cls.return_value = mock_client

            # Should not raise
            await server._revoke_old_token("new-tok", "sp")

    @pytest.mark.asyncio
    async def test_revokes_from_profile(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            "torque_url: https://example.com\n"
            "profiles:\n"
            "  lab:\n"
            "    torque_token: profile-old-tok\n"
            "    torque_token_id: profile-old-id\n",
            encoding="utf-8",
        )
        server = TorqueAuthServer(
            "https://example.com",
            config_path=str(config_path),
            profile_name="lab",
        )

        with patch("torque_tunnel.auth.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            await server._revoke_old_token("new-tok", "sp")
            mock_client.delete.assert_called_once()
            call_url = mock_client.delete.call_args[0][0]
            assert "profile-old-id" in call_url
