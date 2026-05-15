"""Tests for config file hot-reload in mcp_tool.py."""

import asyncio
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from mcp.types import TextContent

from torque_tunnel import config as config_module
from torque_tunnel import mcp_tool


@pytest.fixture
def config_dir(tmp_path):
    """Create a temporary config directory with a config file."""
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.dump({
        "torque_url": "https://original.example.com",
        "torque_token": "original-token",
        "torque_space": "original-space",
        "torque_agent": "original-agent",
    }), encoding="utf-8")
    return config_file


@pytest.fixture(autouse=True)
def save_and_restore_globals():
    """Save and restore mcp_tool globals around each test."""
    orig_config = dict(mcp_tool._config)
    orig_loaded = dict(mcp_tool._loaded_config)
    orig_path = mcp_tool._config_file_path
    orig_mtime = mcp_tool._config_file_mtime
    orig_cli_overrides = set(mcp_tool._cli_overrides)
    orig_cli_profile = mcp_tool._cli_profile
    orig_explicit_path = mcp_tool._config_explicit_path
    orig_config_error = mcp_tool._config_error
    orig_default_profile_warning = mcp_tool._default_profile_warning
    yield
    mcp_tool._config.update(orig_config)
    # Remove any keys that were added during test
    for k in list(mcp_tool._config):
        if k not in orig_config:
            del mcp_tool._config[k]
    mcp_tool._loaded_config.clear()
    mcp_tool._loaded_config.update(orig_loaded)
    mcp_tool._config_file_path = orig_path
    mcp_tool._config_file_mtime = orig_mtime
    mcp_tool._cli_overrides.clear()
    mcp_tool._cli_overrides.update(orig_cli_overrides)
    mcp_tool._cli_profile = orig_cli_profile
    mcp_tool._config_explicit_path = orig_explicit_path
    mcp_tool._config_error = orig_config_error
    mcp_tool._default_profile_warning = orig_default_profile_warning


class TestReloadConfig:
    """Tests for _reload_config()."""

    def test_reload_updates_config_from_file(self, config_dir):
        """Config values from file are applied to _config."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_url"] == "https://original.example.com"
        assert mcp_tool._config["torque_token"] == "original-token"
        assert mcp_tool._config["torque_space"] == "original-space"
        assert mcp_tool._config["default_agent"] == "original-agent"

    def test_reload_picks_up_changes(self, config_dir):
        """After file changes, reload picks up new values."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._reload_config()

        # Modify the file
        config_dir.write_text(yaml.dump({
            "torque_url": "https://updated.example.com",
            "torque_token": "updated-token",
            "torque_space": "updated-space",
        }), encoding="utf-8")

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_url"] == "https://updated.example.com"
        assert mcp_tool._config["torque_token"] == "updated-token"
        assert mcp_tool._config["torque_space"] == "updated-space"

    def test_reload_respects_cli_overrides(self, config_dir):
        """Keys set via CLI are not overwritten by file reload."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_overrides.add("torque_url")
        mcp_tool._config["torque_url"] = "https://cli-override.example.com"

        mcp_tool._reload_config()

        # torque_url should still be the CLI value
        assert mcp_tool._config["torque_url"] == "https://cli-override.example.com"
        # Other values should come from file
        assert mcp_tool._config["torque_token"] == "original-token"

    def test_reload_resets_removed_keys(self, config_dir):
        """Keys removed from file are reset to defaults."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._reload_config()

        assert mcp_tool._config["torque_token"] == "original-token"

        # Remove torque_token from file
        config_dir.write_text(yaml.dump({
            "torque_url": "https://original.example.com",
        }), encoding="utf-8")

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_token"] is None  # reset to default

    def test_reload_with_profile(self, config_dir):
        """Reload applies the active profile's values."""
        config_dir.write_text(yaml.dump({
            "torque_url": "https://base.example.com",
            "default_profile": "dev",
            "profiles": {
                "dev": {
                    "torque_url": "https://dev.example.com",
                    "torque_token": "dev-token",
                    "torque_space": "dev-space",
                },
            },
        }), encoding="utf-8")
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_profile = None  # No CLI profile — uses default_profile from file

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_url"] == "https://dev.example.com"
        assert mcp_tool._config["torque_token"] == "dev-token"
        assert mcp_tool._config["torque_space"] == "dev-space"

    def test_reload_cli_profile_overrides_default(self, config_dir):
        """CLI --profile takes precedence over default_profile in file."""
        config_dir.write_text(yaml.dump({
            "default_profile": "dev",
            "profiles": {
                "dev": {
                    "torque_url": "https://dev.example.com",
                    "torque_token": "dev-token",
                    "torque_space": "dev-space",
                },
                "prod": {
                    "torque_url": "https://prod.example.com",
                    "torque_token": "prod-token",
                    "torque_space": "prod-space",
                },
            },
        }), encoding="utf-8")
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_profile = "prod"  # CLI says use prod

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_url"] == "https://prod.example.com"
        assert mcp_tool._config["torque_token"] == "prod-token"

    def test_reload_updates_loaded_config(self, config_dir):
        """_loaded_config is updated with fresh file contents."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._reload_config()

        assert mcp_tool._loaded_config.get("torque_url") == "https://original.example.com"

        config_dir.write_text(yaml.dump({
            "torque_url": "https://new.example.com",
            "profiles": {"test-profile": {"torque_space": "test"}},
        }), encoding="utf-8")

        mcp_tool._reload_config()

        assert mcp_tool._loaded_config.get("torque_url") == "https://new.example.com"
        assert "test-profile" in mcp_tool._loaded_config.get("profiles", {})

    def test_reload_tracks_mtime(self, config_dir):
        """Reload updates _config_file_mtime."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._config_file_mtime = 0.0

        mcp_tool._reload_config()

        assert mcp_tool._config_file_mtime > 0.0
        assert mcp_tool._config_file_path == config_dir

    def test_reload_handles_missing_file(self, tmp_path):
        """Reload with nonexistent file doesn't crash, clears to defaults."""
        mcp_tool._config_explicit_path = str(tmp_path / "nonexistent.yaml")
        mcp_tool._cli_overrides.clear()
        mcp_tool._config["torque_url"] = "leftover-value"

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_url"] is None  # reset to default
        assert mcp_tool._loaded_config == {}

    def test_reload_handles_corrupt_yaml(self, config_dir):
        """Reload with corrupt YAML sets _config_error and raises."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._reload_config()
        assert mcp_tool._config_error is None

        old_url = mcp_tool._config["torque_url"]

        # Corrupt the file
        config_dir.write_text(": : : [invalid yaml", encoding="utf-8")

        with pytest.raises(Exception):
            mcp_tool._reload_config()

        # _config_error should be set
        assert mcp_tool._config_error is not None
        assert "Failed to load config file" in mcp_tool._config_error

    def test_reload_clears_error_on_success(self, config_dir):
        """After a failed reload, fixing the file clears _config_error."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()

        # Corrupt the file first
        config_dir.write_text(": : : [invalid yaml", encoding="utf-8")
        with pytest.raises(Exception):
            mcp_tool._reload_config()
        assert mcp_tool._config_error is not None

        # Fix the file
        config_dir.write_text(yaml.dump({
            "torque_url": "https://fixed.example.com",
        }), encoding="utf-8")
        mcp_tool._reload_config()

        assert mcp_tool._config_error is None
        assert mcp_tool._config["torque_url"] == "https://fixed.example.com"

    def test_reload_invalid_cli_profile_raises(self, config_dir):
        """If --profile CLI arg references a non-existent profile, it raises."""
        config_dir.write_text(yaml.dump({
            "torque_url": "https://base.example.com",
            "torque_token": "base-token",
        }), encoding="utf-8")
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_profile = "nonexistent-profile"

        with pytest.raises(ValueError, match="nonexistent-profile"):
            mcp_tool._reload_config()
        assert mcp_tool._config_error is not None
        assert "nonexistent-profile" in mcp_tool._config_error

    def test_reload_invalid_default_profile_sets_warning(self, config_dir):
        """If default_profile references non-existent profile, sets soft warning (not hard error)."""
        config_dir.write_text(yaml.dump({
            "torque_url": "https://base.example.com",
            "torque_token": "base-token",
            "default_profile": "nonexistent-profile",
        }), encoding="utf-8")
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_profile = None

        mcp_tool._reload_config()

        # Soft warning set, hard error not set
        assert mcp_tool._config_error is None
        assert mcp_tool._default_profile_warning is not None
        assert "nonexistent-profile" in mcp_tool._default_profile_warning
        # Falls back to base file defaults
        assert mcp_tool._config["torque_url"] == "https://base.example.com"
        assert mcp_tool._config["torque_token"] == "base-token"

    def test_reload_valid_default_profile_clears_warning(self, config_dir):
        """Fixing default_profile clears the soft warning."""
        # Start with broken default
        config_dir.write_text(yaml.dump({
            "default_profile": "nonexistent",
        }), encoding="utf-8")
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_profile = None
        mcp_tool._reload_config()
        assert mcp_tool._default_profile_warning is not None

        # Fix it
        config_dir.write_text(yaml.dump({
            "default_profile": "dev",
            "profiles": {"dev": {"torque_url": "https://dev.example.com"}},
        }), encoding="utf-8")
        mcp_tool._reload_config()
        assert mcp_tool._default_profile_warning is None
        assert mcp_tool._config["torque_url"] == "https://dev.example.com"

    def test_reload_multiple_cli_overrides(self, config_dir):
        """Multiple CLI overrides are all preserved."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_overrides.update({"torque_url", "torque_space", "default_agent"})
        mcp_tool._config["torque_url"] = "https://cli.example.com"
        mcp_tool._config["torque_space"] = "cli-space"
        mcp_tool._config["default_agent"] = "cli-agent"

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_url"] == "https://cli.example.com"
        assert mcp_tool._config["torque_space"] == "cli-space"
        assert mcp_tool._config["default_agent"] == "cli-agent"
        # token should come from file
        assert mcp_tool._config["torque_token"] == "original-token"


class TestWatchConfigFile:
    """Tests for _watch_config_file() async background task."""

    @pytest.mark.asyncio
    async def test_watcher_detects_change(self, config_dir):
        """Watcher calls _reload_config when file mtime changes."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._config_file_path = config_dir
        mcp_tool._config_file_mtime = config_dir.stat().st_mtime
        mcp_tool._cli_overrides.clear()

        # Initial load
        mcp_tool._reload_config()
        assert mcp_tool._config["torque_url"] == "https://original.example.com"

        # Modify file (ensure mtime changes)
        time.sleep(0.05)
        config_dir.write_text(yaml.dump({
            "torque_url": "https://changed.example.com",
            "torque_token": "changed-token",
            "torque_space": "changed-space",
        }), encoding="utf-8")

        # Run watcher for one iteration (patch sleep to not actually wait)
        iteration = 0

        async def fake_sleep(seconds):
            nonlocal iteration
            iteration += 1
            if iteration > 1:
                raise asyncio.CancelledError()

        with patch("torque_tunnel.mcp_tool.asyncio.sleep", side_effect=fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                await mcp_tool._watch_config_file()

        assert mcp_tool._config["torque_url"] == "https://changed.example.com"
        assert mcp_tool._config["torque_token"] == "changed-token"

    @pytest.mark.asyncio
    async def test_watcher_no_change_no_reload(self, config_dir):
        """Watcher does not reload if mtime hasn't changed."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._config_file_path = config_dir
        mcp_tool._config_file_mtime = config_dir.stat().st_mtime
        mcp_tool._cli_overrides.clear()
        mcp_tool._reload_config()

        # Manually set a different value to detect if reload happens
        mcp_tool._config["torque_url"] = "manually-set"

        iteration = 0

        async def fake_sleep(seconds):
            nonlocal iteration
            iteration += 1
            if iteration > 1:
                raise asyncio.CancelledError()

        with patch("torque_tunnel.mcp_tool.asyncio.sleep", side_effect=fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                await mcp_tool._watch_config_file()

        # Should NOT have reloaded — value stays manually-set
        assert mcp_tool._config["torque_url"] == "manually-set"

    @pytest.mark.asyncio
    async def test_watcher_discovers_new_file(self, tmp_path):
        """Watcher discovers a config file that didn't exist at startup."""
        config_file = tmp_path / "config.yaml"
        mcp_tool._config_explicit_path = str(config_file)
        mcp_tool._config_file_path = None
        mcp_tool._cli_overrides.clear()

        iteration = 0

        async def fake_sleep(seconds):
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                # Create file between first and second iteration
                config_file.write_text(yaml.dump({
                    "torque_url": "https://new.example.com",
                }), encoding="utf-8")
            elif iteration > 2:
                raise asyncio.CancelledError()

        with patch("torque_tunnel.mcp_tool.asyncio.sleep", side_effect=fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                await mcp_tool._watch_config_file()

        assert mcp_tool._config_file_path == config_file
        # File was discovered on iteration 2, mtime set to 0 to force reload on iteration 3
        assert mcp_tool._config["torque_url"] == "https://new.example.com"

    @pytest.mark.asyncio
    async def test_watcher_resets_config_when_file_removed(self, config_dir):
        """Watcher resets config to defaults when config file is removed/moved/renamed."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._config_file_path = config_dir
        mcp_tool._config_file_mtime = config_dir.stat().st_mtime
        mcp_tool._cli_overrides.clear()
        mcp_tool._reload_config()
        assert mcp_tool._config["torque_url"] is not None

        iteration = 0

        async def fake_sleep(seconds):
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                # Delete file before second check
                config_dir.unlink()
            elif iteration > 1:
                raise asyncio.CancelledError()

        with patch("torque_tunnel.mcp_tool.asyncio.sleep", side_effect=fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                await mcp_tool._watch_config_file()

        # Config should be reset to defaults
        assert mcp_tool._config["torque_url"] is None
        assert mcp_tool._config_file_path is None
        assert mcp_tool._config_file_mtime == 0.0
        assert mcp_tool._config_error is None

    @pytest.mark.asyncio
    async def test_watcher_preserves_cli_overrides_on_file_removal(self, config_dir):
        """CLI overrides survive config file removal."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._config_file_path = config_dir
        mcp_tool._config_file_mtime = config_dir.stat().st_mtime
        mcp_tool._cli_overrides = {"torque_url"}
        mcp_tool._config["torque_url"] = "https://cli-override.example.com"
        mcp_tool._reload_config()
        # CLI override should be preserved through reload
        assert mcp_tool._config["torque_url"] == "https://cli-override.example.com"

        iteration = 0

        async def fake_sleep(seconds):
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                config_dir.unlink()
            elif iteration > 1:
                raise asyncio.CancelledError()

        with patch("torque_tunnel.mcp_tool.asyncio.sleep", side_effect=fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                await mcp_tool._watch_config_file()

        # CLI override preserved, other keys reset
        assert mcp_tool._config["torque_url"] == "https://cli-override.example.com"
        assert mcp_tool._config["torque_token"] is None

    @pytest.mark.asyncio
    async def test_watcher_handles_corrupt_file(self, config_dir):
        """Watcher logs error and continues if reload fails due to corrupt YAML."""
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._config_file_path = config_dir
        mcp_tool._config_file_mtime = config_dir.stat().st_mtime
        mcp_tool._cli_overrides.clear()
        mcp_tool._reload_config()
        original_url = mcp_tool._config["torque_url"]

        iteration = 0

        async def fake_sleep(seconds):
            nonlocal iteration
            iteration += 1
            if iteration == 1:
                # Corrupt file
                time.sleep(0.05)
                config_dir.write_text(": : [\ninvalid", encoding="utf-8")
            elif iteration > 1:
                raise asyncio.CancelledError()

        with patch("torque_tunnel.mcp_tool.asyncio.sleep", side_effect=fake_sleep):
            with pytest.raises(asyncio.CancelledError):
                await mcp_tool._watch_config_file()

        # Watcher didn't crash, but _config_error should be set
        assert mcp_tool._config_error is not None
        assert "Failed to load config file" in mcp_tool._config_error


class TestConfigErrorGating:
    """Tests for _config_error blocking tool invocations."""

    @pytest.mark.asyncio
    async def test_tools_blocked_when_config_error(self):
        """Execution tools return error when _config_error is set."""
        mcp_tool._config_error = "Failed to load config file: invalid YAML"

        result = await mcp_tool.call_tool("run_on_tunneled_ssh", {"command": "whoami"})

        assert len(result) == 1
        assert "Config file is broken" in result[0].text
        assert "invalid YAML" in result[0].text
        assert "setup" in result[0].text

    @pytest.mark.asyncio
    async def test_setup_tool_not_blocked_by_config_error(self):
        """The setup tool can still run even when _config_error is set."""
        mcp_tool._config_error = "Failed to load config file: invalid YAML"

        # Mock handle_setup so it doesn't actually open a browser
        with patch("torque_tunnel.mcp_tool.handle_setup", return_value=[TextContent(type="text", text="Setup done")]) as mock_setup:
            result = await mcp_tool.call_tool("setup", {"torque_url": "https://example.com"})

        assert "Config file is broken" not in result[0].text
        mock_setup.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_profiles_not_blocked_by_config_error(self):
        """The list_profiles tool can still run even when _config_error is set."""
        mcp_tool._config_error = "Failed to load config file: invalid YAML"

        result = await mcp_tool.call_tool("list_profiles", {})

        # Should return profiles list (or empty), NOT the config error
        assert len(result) >= 1
        assert "Config file is broken" not in result[0].text

    @pytest.mark.asyncio
    async def test_tools_work_when_no_config_error(self):
        """When _config_error is None, tools are not blocked (may fail for other reasons)."""
        mcp_tool._config_error = None
        mcp_tool._default_profile_warning = None

        # Mock the actual handler to avoid needing real Torque infra
        with patch("torque_tunnel.mcp_tool.handle_run_on_tunneled_ssh", return_value=[TextContent(type="text", text="ok")]):
            result = await mcp_tool.call_tool("run_on_tunneled_ssh", {"command": "whoami"})

        assert "Config file is broken" not in result[0].text

    @pytest.mark.asyncio
    async def test_default_profile_warning_blocks_tools_without_explicit_profile(self):
        """Tools without explicit profile return error when default_profile is broken."""
        mcp_tool._config_error = None
        mcp_tool._default_profile_warning = "Profile 'jarvis' not found. Available profiles: cisco-jarvis"

        result = await mcp_tool.call_tool("run_on_tunneled_ssh", {"command": "whoami"})

        assert len(result) == 1
        assert "jarvis" in result[0].text
        assert "cisco-jarvis" in result[0].text
        assert "profile=" in result[0].text.lower() or "Specify a profile" in result[0].text

    @pytest.mark.asyncio
    async def test_default_profile_warning_allows_tools_with_explicit_profile(self):
        """Tools with explicit profile work even when default_profile is broken."""
        mcp_tool._config_error = None
        mcp_tool._default_profile_warning = "Profile 'jarvis' not found."
        mcp_tool._loaded_config = {
            "profiles": {
                "cisco-review1": {
                    "torque_url": "https://review1.example.com",
                    "torque_token": "tok",
                    "torque_space": "sp",
                    "torque_agent": "agent",
                }
            }
        }

        with patch("torque_tunnel.mcp_tool.handle_run_on_tunneled_ssh", return_value=[TextContent(type="text", text="ok")]) as mock_handler:
            result = await mcp_tool.call_tool("run_on_tunneled_ssh", {"command": "whoami", "profile": "cisco-review1"})

        assert "jarvis" not in result[0].text
        mock_handler.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_not_blocked_by_default_profile_warning(self):
        """Setup tool can run even when default_profile is broken."""
        mcp_tool._default_profile_warning = "Profile 'jarvis' not found."

        with patch("torque_tunnel.mcp_tool.handle_setup", return_value=[TextContent(type="text", text="Setup done")]):
            result = await mcp_tool.call_tool("setup", {})

        assert "jarvis" not in result[0].text

    @pytest.mark.asyncio
    async def test_list_profiles_not_blocked_by_default_profile_warning(self):
        """list_profiles can run even when default_profile is broken, and shows warning."""
        mcp_tool._default_profile_warning = "Profile 'jarvis' not found."
        mcp_tool._loaded_config = {
            "default_profile": "jarvis",
            "profiles": {
                "cisco-review1": {"torque_url": "https://review1.example.com"},
            }
        }

        result = await mcp_tool.call_tool("list_profiles", {})

        assert len(result) >= 1
        # Should show the warning at the top AND the profiles
        assert "jarvis" in result[0].text
        assert "cisco-review1" in result[0].text


class TestCliOverrides:
    """Tests for CLI override tracking."""

    def test_ssh_auth_mutual_exclusion(self, config_dir):
        """When CLI sets ssh_key, both ssh keys are locked from file reload."""
        config_dir.write_text(yaml.dump({
            "torque_url": "https://example.com",
            "ssh_key": "file-key",
            "ssh_password": "file-password",
        }), encoding="utf-8")
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()
        mcp_tool._cli_overrides.add("default_ssh_key")
        mcp_tool._cli_overrides.add("default_ssh_password")
        mcp_tool._config["default_ssh_key"] = "cli-key"
        mcp_tool._config["default_ssh_password"] = None

        mcp_tool._reload_config()

        assert mcp_tool._config["default_ssh_key"] == "cli-key"
        assert mcp_tool._config["default_ssh_password"] is None  # CLI chose key-only

    def test_no_cli_overrides_all_from_file(self, config_dir):
        """Without CLI overrides, all values come from file."""
        config_dir.write_text(yaml.dump({
            "torque_url": "https://file.example.com",
            "torque_token": "file-token",
            "torque_space": "file-space",
            "torque_agent": "file-agent",
            "ssh_key": "file-key",
            "ssh_user": "file-user",
            "host": "file-host",
            "init_commands": "echo hello",
            "verbose": True,
            "container_idle_timeout": 3600,
        }), encoding="utf-8")
        mcp_tool._config_explicit_path = str(config_dir)
        mcp_tool._cli_overrides.clear()

        mcp_tool._reload_config()

        assert mcp_tool._config["torque_url"] == "https://file.example.com"
        assert mcp_tool._config["torque_token"] == "file-token"
        assert mcp_tool._config["torque_space"] == "file-space"
        assert mcp_tool._config["default_agent"] == "file-agent"
        assert mcp_tool._config["default_ssh_key"] == "file-key"
        assert mcp_tool._config["default_ssh_user"] == "file-user"
        assert mcp_tool._config["default_target_ip"] == "file-host"
        assert mcp_tool._config["init_commands"] == "echo hello"
        assert mcp_tool._config["verbose"] is True
        assert mcp_tool._config["container_idle_timeout"] == 3600
