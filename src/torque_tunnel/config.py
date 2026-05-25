"""Configuration file loading and profile resolution for torque-tunnel.

Supports a YAML config file at ~/.torque-tunnel/config.yaml (or custom path)
with a 'default' section and named 'profiles' that can override any setting.

Resolution order (highest precedence first):
  1. Runtime arguments (CLI flags or MCP tool parameters)
  2. Active profile values (from --profile or tool 'profile' param)
  3. Config file 'default' section
  4. Environment variables (handled by argparse defaults)
"""

import os
from pathlib import Path
from typing import Optional

import yaml
from ruamel.yaml import YAML as RuamelYAML


# Config file YAML keys → internal _config keys
CONFIG_KEY_MAP = {
    "torque_url": "torque_url",
    "torque_token": "torque_token",
    "torque_space": "torque_space",
    "torque_agent": "default_agent",
    "ssh_key": "default_ssh_key",
    "ssh_password": "default_ssh_password",
    "host": "default_target_ip",
    "ssh_user": "default_ssh_user",
    "init_commands": "init_commands",
    "finally_commands": "finally_commands",
    "auto_delete_environments": "auto_delete_environments",
    "verbose": "verbose",
    "container_idle_timeout": "container_idle_timeout",
}

# Profile YAML keys → MCP tool argument names (for injection into tool arguments)
PROFILE_TO_TOOL_ARG = {
    "host": "host",
    "ssh_user": "user",
    "ssh_key": "private_key",
    "ssh_password": "password",
    "torque_url": "torque_url",
    "torque_token": "torque_token",
    "torque_space": "torque_space",
    "torque_agent": "torque_agent",
}

# All valid configuration keys (the YAML key names)
VALID_CONFIG_KEYS = set(CONFIG_KEY_MAP.keys())

# Metadata-only keys in profiles (not config values)
_PROFILE_META_KEYS = {"description", "extends", "expose_values"}

# Keys managed by the login flow (not regular config values, but stored in YAML)
_LOGIN_META_KEYS = {"torque_token_id"}

# SSH auth mutual exclusion: (yaml_key_a, yaml_key_b) — when one is set at a
# more concrete level, the other inherited from a less concrete level is cleared.
_AUTH_YAML_PAIR = ("ssh_key", "ssh_password")
_AUTH_CONFIG_PAIR = ("default_ssh_key", "default_ssh_password")
_AUTH_ARG_PAIR = ("private_key", "password")


def _default_config_path() -> Path:
    """Default config file location."""
    return Path.home() / ".torque-tunnel" / "config.yaml"


def find_config_file(explicit_path: Optional[str] = None) -> Optional[Path]:
    """Find the config file by checking explicit path, env var, then default location.

    Returns the Path if found, None otherwise.
    """
    if explicit_path:
        p = Path(explicit_path).expanduser()
        if p.exists():
            return p
        return None

    env_path = os.environ.get("TORQUE_TUNNEL_CONFIG")
    if env_path:
        p = Path(env_path).expanduser()
        if p.exists():
            return p
        return None

    p = _default_config_path()
    if p.exists():
        return p
    return None


def load_config(explicit_path: Optional[str] = None) -> dict:
    """Load configuration from YAML file.

    Returns the parsed dict, or empty dict if no config file found.
    """
    path = find_config_file(explicit_path)
    if not path:
        return {}

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data if isinstance(data, dict) else {}


def _resolve_profile_chain(config: dict, profile_name: str, seen: Optional[list] = None) -> dict:
    """Resolve a profile's full values by following the 'extends' chain.

    Returns a flat dict of config values (YAML keys, excludes metadata keys).
    Raises ValueError on circular extends or missing profiles.
    """
    if seen is None:
        seen = []

    if profile_name in seen:
        chain = " -> ".join(seen + [profile_name])
        raise ValueError(f"Circular profile inheritance detected: {chain}")
    seen.append(profile_name)

    profiles = config.get("profiles", {})
    if profile_name not in profiles:
        raise ValueError(f"Profile '{profile_name}' not found.")

    profile = profiles[profile_name]

    # Resolve parent first (if extends)
    parent_values = {}
    if "extends" in profile:
        parent_values = _resolve_profile_chain(config, profile["extends"], seen)

    # Current profile values override parent
    current_values = {k: v for k, v in profile.items() if k not in _PROFILE_META_KEYS}

    merged = {**parent_values, **current_values}

    # SSH auth mutual exclusion: if child sets exactly one auth method,
    # clear the other one inherited from parents
    a_key, b_key = _AUTH_YAML_PAIR
    child_has_a = a_key in current_values
    child_has_b = b_key in current_values
    if child_has_a and not child_has_b:
        merged.pop(b_key, None)
    elif child_has_b and not child_has_a:
        merged.pop(a_key, None)

    return merged


def resolve_profile(config: dict, profile_name: str) -> dict:
    """Resolve a profile name to its effective config values (YAML keys).

    Follows 'extends' chain and merges parent → child values.
    """
    return _resolve_profile_chain(config, profile_name)


def get_default_profile_name(config: dict) -> str | None:
    """Get the default_profile name from config, if set."""
    return config.get("default_profile")


def get_defaults(config: dict) -> dict:
    """Get top-level config values mapped to internal _config keys.

    Reads recognized keys directly from the top level of the config dict,
    skipping non-config keys like 'profiles' and 'default_profile'.
    """
    result = {}
    for yaml_key, config_key in CONFIG_KEY_MAP.items():
        if yaml_key in config:
            result[config_key] = config[yaml_key]
    return result


def apply_profile_to_config(base_config: dict, profile_values: dict) -> dict:
    """Create an effective config dict by overlaying resolved profile values onto base config.

    Args:
        base_config: The current _config dict (internal keys).
        profile_values: Resolved profile values (YAML keys).

    Returns:
        New dict with internal _config keys, profile values overlaid.
    """
    result = dict(base_config)
    for yaml_key, config_key in CONFIG_KEY_MAP.items():
        if yaml_key in profile_values:
            result[config_key] = profile_values[yaml_key]

    # SSH auth mutual exclusion: if profile sets exactly one auth method,
    # clear the other one from base config
    a_yaml, b_yaml = _AUTH_YAML_PAIR
    a_cfg, b_cfg = _AUTH_CONFIG_PAIR
    profile_has_a = a_yaml in profile_values
    profile_has_b = b_yaml in profile_values
    if profile_has_a and not profile_has_b:
        result[b_cfg] = None
    elif profile_has_b and not profile_has_a:
        result[a_cfg] = None

    return result


def inject_profile_into_arguments(arguments: dict, profile_values: dict) -> dict:
    """Inject profile values into MCP tool arguments for keys that map to tool params.

    Only injects if the argument is not already explicitly set (explicit args take precedence).

    Returns:
        New arguments dict with profile values injected where gaps exist.
    """
    result = dict(arguments)

    # Determine if runtime args already specify an auth method
    a_arg, b_arg = _AUTH_ARG_PAIR
    args_have_a = bool(result.get(a_arg))
    args_have_b = bool(result.get(b_arg))

    for yaml_key, arg_key in PROFILE_TO_TOOL_ARG.items():
        if yaml_key in profile_values and not result.get(arg_key):
            # SSH auth mutual exclusion: don't inject a profile auth method
            # if the args already specify the OTHER auth method
            a_yaml, b_yaml = _AUTH_YAML_PAIR
            if yaml_key == a_yaml and args_have_b:
                continue
            if yaml_key == b_yaml and args_have_a:
                continue
            result[arg_key] = profile_values[yaml_key]
    return result


def list_profiles(config: dict) -> list[dict]:
    """List all available profiles with descriptions and overridden keys.

    Returns list of dicts with keys: 'name', 'description', 'extends', 'overrides', 'expose_values', 'values'.
    """
    profiles = config.get("profiles", {})
    result = []
    for name, profile in profiles.items():
        override_keys = sorted(k for k in profile if k not in _PROFILE_META_KEYS)
        entry = {
            "name": name,
            "description": profile.get("description", ""),
            "extends": profile.get("extends"),
            "overrides": override_keys,
            "expose_values": profile.get("expose_values", False),
            "values": {k: profile[k] for k in override_keys},
        }
        result.append(entry)
    return result


def get_top_level_defaults(config: dict) -> dict:
    """Get the top-level config values (YAML key names) that serve as base defaults.

    Returns a dict of {yaml_key: value} for recognized config keys found at the top level.
    """
    return {k: config[k] for k in VALID_CONFIG_KEYS if k in config}


def get_top_level_expose_values(config: dict) -> bool:
    """Get the top-level expose_values setting (default False)."""
    return config.get("expose_values", False)


def update_config_file(
    updates: dict[str, object],
    profile_name: Optional[str] = None,
    explicit_path: Optional[str] = None,
) -> Path:
    """Update config file in-place, preserving comments and formatting.

    Uses ruamel.yaml for round-trip YAML editing.

    Args:
        updates: Dict of YAML key → value to set (e.g. {"torque_token": "abc", "torque_space": "my-space"}).
        profile_name: If set, update inside profiles.<profile_name>; otherwise update top-level keys.
        explicit_path: Explicit config file path. If None, uses standard discovery
                       (env var / default location). Creates default path if no config file exists.

    Returns:
        The Path of the updated config file.

    Raises:
        ValueError: If profile_name is specified but doesn't exist in the config.
    """
    path = find_config_file(explicit_path)

    ryaml = RuamelYAML()
    ryaml.preserve_quotes = True
    ryaml.width = 4096  # prevent re-wrapping long strings

    if path:
        with open(path, "r", encoding="utf-8") as f:
            data = ryaml.load(f)
        if data is None:
            data = {}
    else:
        # No config file yet — create at default location
        path = _default_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {}

    if profile_name:
        profiles = data.get("profiles")
        if profiles is None:
            profiles = {}
            data["profiles"] = profiles
        if profile_name not in profiles:
            profiles[profile_name] = {}
        target = profiles[profile_name]
    else:
        target = data

    for key, value in updates.items():
        if target is data and key not in data and "profiles" in data:
            # Insert new top-level keys before the "profiles" block
            keys = list(data.keys())
            idx = keys.index("profiles")
            data.insert(idx, key, value)
        else:
            target[key] = value

    with open(path, "w", encoding="utf-8") as f:
        ryaml.dump(data, f)

    return path
