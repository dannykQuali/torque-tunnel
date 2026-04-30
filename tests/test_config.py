"""Tests for config module — profile loading, inheritance, and config resolution."""

import os
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import config as config_module


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def sample_config():
    """A full sample config dict (as if loaded from YAML)."""
    return {
        "default": {
            "torque_url": "https://default.example.com",
            "torque_token": "default-token",
            "torque_space": "default-space",
            "torque_agent": "default-agent",
            "ssh_user": "root",
            "ssh_key": "/default/key.pem",
            "host": "10.0.0.1",
            "init_commands": "export FOO=bar",
            "auto_delete_environments": False,
            "container_idle_timeout": 7200,
        },
        "profiles": {
            "lab-base": {
                "description": "Base profile for lab machines",
                "torque_agent": "lab-agent",
                "init_commands": "export PROXY=http://proxy:80",
            },
            "lab-server-1": {
                "description": "Lab server 10.0.0.10",
                "extends": "lab-base",
                "host": "10.0.0.10",
            },
            "lab-server-2": {
                "extends": "lab-base",
                "host": "10.0.0.20",
                "ssh_user": "admin",
            },
            "review2": {
                "description": "Review2 environment",
                "torque_url": "https://review2.example.com",
                "torque_token": "review2-token",
                "torque_space": "review2-space",
                "torque_agent": "review2-agent",
            },
            "deep-child": {
                "extends": "lab-server-1",
                "ssh_key": "/deep/key.pem",
            },
        },
    }


@pytest.fixture
def circular_config():
    """Config with circular profile inheritance."""
    return {
        "profiles": {
            "a": {"extends": "b", "host": "1.1.1.1"},
            "b": {"extends": "c", "host": "2.2.2.2"},
            "c": {"extends": "a", "host": "3.3.3.3"},
        }
    }


@pytest.fixture
def config_file(sample_config, tmp_path):
    """Write sample config to a temp file and return the path."""
    path = tmp_path / "config.yaml"
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(sample_config, f)
    return path


# ============================================================================
# load_config / find_config_file
# ============================================================================

class TestLoadConfig:
    def test_load_from_explicit_path(self, config_file, sample_config):
        result = config_module.load_config(str(config_file))
        assert result["default"]["torque_url"] == sample_config["default"]["torque_url"]
        assert "profiles" in result

    def test_load_missing_explicit_path_returns_empty(self, tmp_path):
        result = config_module.load_config(str(tmp_path / "nonexistent.yaml"))
        assert result == {}

    def test_load_no_config_file_returns_empty(self, monkeypatch, tmp_path):
        monkeypatch.delenv("TORQUE_TUNNEL_CONFIG", raising=False)
        # Point the default config path to a temp dir that doesn't have config.yaml
        monkeypatch.setattr(config_module, "_default_config_path", lambda: tmp_path / "config.yaml")
        result = config_module.load_config()
        assert result == {}

    def test_load_from_env_var(self, config_file, monkeypatch, sample_config):
        monkeypatch.setenv("TORQUE_TUNNEL_CONFIG", str(config_file))
        result = config_module.load_config()
        assert result["default"]["torque_url"] == sample_config["default"]["torque_url"]

    def test_load_from_default_path(self, sample_config, monkeypatch, tmp_path):
        monkeypatch.delenv("TORQUE_TUNNEL_CONFIG", raising=False)
        config_path = tmp_path / "config.yaml"
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(sample_config, f)
        monkeypatch.setattr(config_module, "_default_config_path", lambda: config_path)
        result = config_module.load_config()
        assert result["default"]["torque_url"] == sample_config["default"]["torque_url"]

    def test_load_empty_yaml_returns_empty(self, tmp_path):
        path = tmp_path / "empty.yaml"
        path.write_text("")
        result = config_module.load_config(str(path))
        assert result == {}

    def test_load_non_dict_yaml_returns_empty(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("- item1\n- item2\n")
        result = config_module.load_config(str(path))
        assert result == {}


# ============================================================================
# resolve_profile
# ============================================================================

class TestResolveProfile:
    def test_simple_profile(self, sample_config):
        result = config_module.resolve_profile(sample_config, "review2")
        assert result["torque_url"] == "https://review2.example.com"
        assert result["torque_token"] == "review2-token"
        assert result["torque_space"] == "review2-space"
        assert result["torque_agent"] == "review2-agent"

    def test_profile_with_extends(self, sample_config):
        result = config_module.resolve_profile(sample_config, "lab-server-1")
        # From lab-server-1 directly
        assert result["host"] == "10.0.0.10"
        # Inherited from lab-base
        assert result["torque_agent"] == "lab-agent"
        assert result["init_commands"] == "export PROXY=http://proxy:80"

    def test_child_overrides_parent(self, sample_config):
        result = config_module.resolve_profile(sample_config, "lab-server-2")
        # From lab-server-2 (overrides default ssh_user)
        assert result["ssh_user"] == "admin"
        # Inherited from lab-base
        assert result["torque_agent"] == "lab-agent"
        assert result["host"] == "10.0.0.20"

    def test_deep_inheritance(self, sample_config):
        """Test 3-level chain: deep-child → lab-server-1 → lab-base."""
        result = config_module.resolve_profile(sample_config, "deep-child")
        # From deep-child
        assert result["ssh_key"] == "/deep/key.pem"
        # From lab-server-1
        assert result["host"] == "10.0.0.10"
        # From lab-base (grandparent)
        assert result["torque_agent"] == "lab-agent"
        assert result["init_commands"] == "export PROXY=http://proxy:80"

    def test_circular_inheritance_raises(self, circular_config):
        with pytest.raises(ValueError, match="Circular profile inheritance"):
            config_module.resolve_profile(circular_config, "a")

    def test_missing_profile_raises(self, sample_config):
        with pytest.raises(ValueError, match="Profile 'nonexistent' not found"):
            config_module.resolve_profile(sample_config, "nonexistent")

    def test_missing_profile_lists_available(self, sample_config):
        with pytest.raises(ValueError, match="lab-base"):
            config_module.resolve_profile(sample_config, "nonexistent")

    def test_extends_to_missing_parent_raises(self):
        config = {
            "profiles": {
                "child": {"extends": "nonexistent", "host": "1.1.1.1"},
            }
        }
        with pytest.raises(ValueError, match="Profile 'nonexistent' not found"):
            config_module.resolve_profile(config, "child")

    def test_description_and_extends_not_in_values(self, sample_config):
        result = config_module.resolve_profile(sample_config, "lab-server-1")
        assert "description" not in result
        assert "extends" not in result

    def test_empty_profiles_section(self):
        config = {"profiles": {}}
        with pytest.raises(ValueError, match="not found"):
            config_module.resolve_profile(config, "anything")

    def test_no_profiles_section(self):
        config = {"default": {"torque_url": "https://example.com"}}
        with pytest.raises(ValueError, match="not found"):
            config_module.resolve_profile(config, "anything")


# ============================================================================
# get_defaults
# ============================================================================

class TestGetDefaults:
    def test_maps_yaml_keys_to_config_keys(self, sample_config):
        result = config_module.get_defaults(sample_config)
        assert result["torque_url"] == "https://default.example.com"
        assert result["torque_token"] == "default-token"
        assert result["torque_space"] == "default-space"
        assert result["default_agent"] == "default-agent"
        assert result["default_ssh_user"] == "root"
        assert result["default_ssh_key"] == "/default/key.pem"
        assert result["default_target_ip"] == "10.0.0.1"
        assert result["init_commands"] == "export FOO=bar"

    def test_missing_keys_not_included(self):
        config = {"default": {"torque_url": "https://example.com"}}
        result = config_module.get_defaults(config)
        assert "torque_url" in result
        assert "torque_token" not in result

    def test_no_default_section(self):
        result = config_module.get_defaults({})
        assert result == {}


# ============================================================================
# apply_profile_to_config
# ============================================================================

class TestApplyProfileToConfig:
    def test_overlays_profile_values(self):
        base_config = {
            "torque_url": "https://base.example.com",
            "torque_token": "base-token",
            "torque_space": "base-space",
            "default_agent": "base-agent",
            "default_ssh_key": None,
            "default_ssh_password": None,
            "default_target_ip": "10.0.0.1",
            "default_ssh_user": "root",
            "init_commands": None,
            "finally_commands": None,
            "auto_delete_environments": False,
            "verbose": False,
            "container_idle_timeout": 7200,
        }
        profile_values = {
            "torque_agent": "profile-agent",
            "host": "10.0.0.99",
            "init_commands": "export X=1",
        }
        result = config_module.apply_profile_to_config(base_config, profile_values)
        # Profile values applied
        assert result["default_agent"] == "profile-agent"
        assert result["default_target_ip"] == "10.0.0.99"
        assert result["init_commands"] == "export X=1"
        # Base values preserved
        assert result["torque_url"] == "https://base.example.com"
        assert result["torque_token"] == "base-token"
        assert result["default_ssh_user"] == "root"

    def test_does_not_mutate_base(self):
        base = {"torque_url": "original", "default_agent": "original-agent"}
        profile = {"torque_agent": "new-agent"}
        result = config_module.apply_profile_to_config(base, profile)
        assert base["default_agent"] == "original-agent"
        assert result["default_agent"] == "new-agent"


# ============================================================================
# inject_profile_into_arguments
# ============================================================================

class TestInjectProfileIntoArguments:
    def test_injects_missing_values(self):
        args = {"command": "uname -a"}
        profile = {"host": "10.0.0.10", "ssh_user": "admin", "torque_agent": "lab-agent"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert result["host"] == "10.0.0.10"
        assert result["user"] == "admin"
        assert result["torque_agent"] == "lab-agent"
        assert result["command"] == "uname -a"

    def test_does_not_override_explicit_values(self):
        args = {"host": "explicit-host", "command": "ls"}
        profile = {"host": "10.0.0.10", "ssh_user": "admin"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert result["host"] == "explicit-host"  # Not overridden
        assert result["user"] == "admin"  # Injected

    def test_maps_ssh_key_to_private_key(self):
        args = {}
        profile = {"ssh_key": "/path/to/key.pem"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert result["private_key"] == "/path/to/key.pem"

    def test_maps_ssh_password_to_password(self):
        args = {}
        profile = {"ssh_password": "secret123"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert result["password"] == "secret123"

    def test_does_not_mutate_original_args(self):
        args = {"command": "ls"}
        profile = {"host": "10.0.0.10"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert "host" not in args
        assert result["host"] == "10.0.0.10"

    def test_empty_profile_returns_copy(self):
        args = {"command": "ls", "host": "10.0.0.1"}
        result = config_module.inject_profile_into_arguments(args, {})
        assert result == args
        assert result is not args


# ============================================================================
# list_profiles
# ============================================================================

class TestListProfiles:
    def test_lists_all_profiles(self, sample_config):
        result = config_module.list_profiles(sample_config)
        names = [p["name"] for p in result]
        assert "lab-base" in names
        assert "lab-server-1" in names
        assert "review2" in names

    def test_includes_description(self, sample_config):
        result = config_module.list_profiles(sample_config)
        review2 = next(p for p in result if p["name"] == "review2")
        assert review2["description"] == "Review2 environment"

    def test_includes_extends(self, sample_config):
        result = config_module.list_profiles(sample_config)
        server1 = next(p for p in result if p["name"] == "lab-server-1")
        assert server1["extends"] == "lab-base"

    def test_no_extends_is_none(self, sample_config):
        result = config_module.list_profiles(sample_config)
        review2 = next(p for p in result if p["name"] == "review2")
        assert review2["extends"] is None

    def test_overrides_list(self, sample_config):
        result = config_module.list_profiles(sample_config)
        lab_base = next(p for p in result if p["name"] == "lab-base")
        assert "torque_agent" in lab_base["overrides"]
        assert "init_commands" in lab_base["overrides"]
        # Metadata keys excluded
        assert "description" not in lab_base["overrides"]
        assert "extends" not in lab_base["overrides"]

    def test_empty_config(self):
        result = config_module.list_profiles({})
        assert result == []

    def test_no_profiles_section(self):
        result = config_module.list_profiles({"default": {}})
        assert result == []


# ============================================================================
# Integration: full resolution chain
# ============================================================================

class TestIntegration:
    def test_full_flow_default_plus_profile(self, sample_config):
        """Simulate: config file defaults → profile → apply to config."""
        # Step 1: Get defaults from config file
        defaults = config_module.get_defaults(sample_config)
        assert defaults["torque_url"] == "https://default.example.com"

        # Step 2: Resolve a profile
        profile_values = config_module.resolve_profile(sample_config, "lab-server-1")
        assert profile_values["host"] == "10.0.0.10"
        assert profile_values["torque_agent"] == "lab-agent"

        # Step 3: Apply profile onto defaults
        effective = config_module.apply_profile_to_config(defaults, profile_values)
        # Profile values win
        assert effective["default_target_ip"] == "10.0.0.10"
        assert effective["default_agent"] == "lab-agent"
        assert effective["init_commands"] == "export PROXY=http://proxy:80"
        # Defaults preserved where profile doesn't override
        assert effective["torque_url"] == "https://default.example.com"
        assert effective["torque_token"] == "default-token"
        assert effective["default_ssh_user"] == "root"

    def test_full_flow_with_tool_arguments(self, sample_config):
        """Simulate: profile values injected into tool arguments."""
        profile_values = config_module.resolve_profile(sample_config, "lab-server-1")

        # Tool call with explicit command but no host
        tool_args = {"command": "uname -a", "torque_agent": "explicit-agent"}
        enriched = config_module.inject_profile_into_arguments(tool_args, profile_values)

        # Host injected from profile
        assert enriched["host"] == "10.0.0.10"
        # Explicit agent preserved
        assert enriched["torque_agent"] == "explicit-agent"
        # Profile doesn't override what's already set
        assert enriched["command"] == "uname -a"

    def test_load_and_resolve_from_file(self, config_file, sample_config):
        """Full round-trip: load from file → resolve profile → check values."""
        loaded = config_module.load_config(str(config_file))
        profile_values = config_module.resolve_profile(loaded, "review2")
        assert profile_values["torque_url"] == "https://review2.example.com"
        assert profile_values["torque_token"] == "review2-token"


# ============================================================================
# SSH auth mutual exclusion across config hierarchy
# ============================================================================

class TestSshAuthMutualExclusion:
    """When a more concrete config level sets one SSH auth method, the other must be cleared.

    Auth methods: ssh_key (private_key) and ssh_password (password) are mutually exclusive.
    The hierarchy (least → most concrete): default → profile → runtime arguments.
    """

    # --- apply_profile_to_config: profile overrides default ---

    def test_profile_password_clears_default_key(self):
        """Profile sets ssh_password → default_ssh_key from base config must be cleared."""
        base = {
            "default_ssh_key": "/default/key.pem",
            "default_ssh_password": None,
            "default_target_ip": "10.0.0.1",
        }
        profile_values = {"ssh_password": "secret123"}
        result = config_module.apply_profile_to_config(base, profile_values)
        assert result["default_ssh_password"] == "secret123"
        assert not result.get("default_ssh_key"), "key should be cleared when profile sets password"

    def test_profile_key_clears_default_password(self):
        """Profile sets ssh_key → default_ssh_password from base config must be cleared."""
        base = {
            "default_ssh_key": None,
            "default_ssh_password": "old-pass",
            "default_target_ip": "10.0.0.1",
        }
        profile_values = {"ssh_key": "/profile/key.pem"}
        result = config_module.apply_profile_to_config(base, profile_values)
        assert result["default_ssh_key"] == "/profile/key.pem"
        assert not result.get("default_ssh_password"), "password should be cleared when profile sets key"

    def test_profile_both_auth_methods_kept(self):
        """If profile explicitly sets both, both survive (user's explicit choice)."""
        base = {"default_ssh_key": None, "default_ssh_password": None}
        profile_values = {"ssh_key": "/key.pem", "ssh_password": "pass"}
        result = config_module.apply_profile_to_config(base, profile_values)
        assert result["default_ssh_key"] == "/key.pem"
        assert result["default_ssh_password"] == "pass"

    def test_profile_no_auth_preserves_defaults(self):
        """Profile with no auth keys doesn't touch the defaults."""
        base = {"default_ssh_key": "/default/key.pem", "default_ssh_password": None, "default_target_ip": "10.0.0.1"}
        profile_values = {"host": "10.0.0.99"}
        result = config_module.apply_profile_to_config(base, profile_values)
        assert result["default_ssh_key"] == "/default/key.pem"
        assert result.get("default_ssh_password") is None

    # --- inject_profile_into_arguments: args override profile ---

    def test_arg_password_blocks_profile_key_injection(self):
        """Runtime args have password → profile's ssh_key must NOT be injected."""
        args = {"password": "runtime-pass"}
        profile = {"ssh_key": "/profile/key.pem", "host": "10.0.0.10"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert result["password"] == "runtime-pass"
        assert not result.get("private_key"), "profile key should not be injected when args have password"
        assert result["host"] == "10.0.0.10"  # non-auth values still injected

    def test_arg_key_blocks_profile_password_injection(self):
        """Runtime args have private_key → profile's ssh_password must NOT be injected."""
        args = {"private_key": "/runtime/key.pem"}
        profile = {"ssh_password": "profile-pass", "host": "10.0.0.10"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert result["private_key"] == "/runtime/key.pem"
        assert not result.get("password"), "profile password should not be injected when args have key"

    def test_profile_password_not_combined_with_profile_key_into_args(self):
        """Profile has both key and password (from inheritance) — both injected since same level."""
        args = {"command": "ls"}
        profile = {"ssh_key": "/key.pem", "ssh_password": "pass"}
        result = config_module.inject_profile_into_arguments(args, profile)
        # Same-level: both survive (profile resolved them already)
        assert result["private_key"] == "/key.pem"
        assert result["password"] == "pass"

    def test_arg_password_not_overridden_by_profile_password(self):
        """Explicit arg password wins over profile password (existing behavior)."""
        args = {"password": "explicit"}
        profile = {"ssh_password": "from-profile"}
        result = config_module.inject_profile_into_arguments(args, profile)
        assert result["password"] == "explicit"

    # --- resolve_profile inheritance: child auth overrides parent ---

    def test_child_password_clears_parent_key_in_resolution(self):
        """Child profile sets ssh_password → parent's ssh_key must be cleared."""
        cfg = {
            "profiles": {
                "parent": {"ssh_key": "/parent/key.pem", "host": "10.0.0.1"},
                "child": {"extends": "parent", "ssh_password": "child-pass"},
            }
        }
        result = config_module.resolve_profile(cfg, "child")
        assert result["ssh_password"] == "child-pass"
        assert "ssh_key" not in result, "parent's key should be cleared when child sets password"
        assert result["host"] == "10.0.0.1"  # non-auth values still inherited

    def test_child_key_clears_parent_password_in_resolution(self):
        """Child profile sets ssh_key → parent's ssh_password must be cleared."""
        cfg = {
            "profiles": {
                "parent": {"ssh_password": "parent-pass", "host": "10.0.0.1"},
                "child": {"extends": "parent", "ssh_key": "/child/key.pem"},
            }
        }
        result = config_module.resolve_profile(cfg, "child")
        assert result["ssh_key"] == "/child/key.pem"
        assert "ssh_password" not in result, "parent's password should be cleared when child sets key"

    def test_child_both_auth_preserves_both(self):
        """Child explicitly sets both — user's choice, both survive."""
        cfg = {
            "profiles": {
                "parent": {"ssh_key": "/parent/key.pem"},
                "child": {"extends": "parent", "ssh_key": "/child/key.pem", "ssh_password": "child-pass"},
            }
        }
        result = config_module.resolve_profile(cfg, "child")
        assert result["ssh_key"] == "/child/key.pem"
        assert result["ssh_password"] == "child-pass"

    def test_grandchild_password_clears_grandparent_key(self):
        """3-level: grandparent has key, grandchild sets password → key cleared."""
        cfg = {
            "profiles": {
                "grandparent": {"ssh_key": "/gp/key.pem", "host": "10.0.0.1"},
                "parent": {"extends": "grandparent", "ssh_user": "admin"},
                "child": {"extends": "parent", "ssh_password": "child-pass"},
            }
        }
        result = config_module.resolve_profile(cfg, "child")
        assert result["ssh_password"] == "child-pass"
        assert "ssh_key" not in result
        # Non-auth inheritance still works
        assert result["host"] == "10.0.0.1"
        assert result["ssh_user"] == "admin"

    def test_no_auth_in_child_inherits_parent_key(self):
        """Child doesn't set any auth → parent's key survives."""
        cfg = {
            "profiles": {
                "parent": {"ssh_key": "/parent/key.pem", "host": "10.0.0.1"},
                "child": {"extends": "parent", "host": "10.0.0.2"},
            }
        }
        result = config_module.resolve_profile(cfg, "child")
        assert result["ssh_key"] == "/parent/key.pem"
        assert result["host"] == "10.0.0.2"
