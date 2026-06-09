"""Tests for CLI argument parsing — focused on flag order-independence.

The --allow-dangerous-commands safety flag must be honored regardless of whether
it appears before or after the `ssh` subcommand. It is meaningful ONLY for the
`ssh` subcommand (containers/read/list either run inside a disposable container or
don't run commands at all), so it must be rejected on those subcommands.
"""

import os
import sys

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import mcp_tool


@pytest.fixture
def parser():
    return mcp_tool.build_parser()


# ============================================================================
# --allow-dangerous-commands order-independence for `ssh`
# ============================================================================

def test_dangerous_flag_after_subcommand(parser):
    """Flag placed AFTER the subcommand is honored (the always-worked case)."""
    args = parser.parse_args(["ssh", "reboot", "--allow-dangerous-commands"])
    assert args.command == "ssh"
    assert args.cmd == "reboot"
    assert args.allow_dangerous_commands is True


def test_dangerous_flag_before_subcommand(parser):
    """Flag placed BEFORE the subcommand is honored (the previously-broken case)."""
    args = parser.parse_args(["--allow-dangerous-commands", "ssh", "reboot"])
    assert args.command == "ssh"
    assert args.cmd == "reboot"
    assert args.allow_dangerous_commands is True


def test_dangerous_flag_interleaved_with_other_args(parser):
    """Flag works before the subcommand even with other args present.

    (--host is placed after the subcommand here; common args placed *before* the
    subcommand suffer a separate, pre-existing argparse subparser-clobber bug that
    is out of scope for this flag.)
    """
    args = parser.parse_args([
        "--allow-dangerous-commands",
        "ssh", "reboot", "--host", "1.2.3.4", "--user", "root",
    ])
    assert args.command == "ssh"
    assert args.cmd == "reboot"
    assert args.host == "1.2.3.4"
    assert args.user == "root"
    assert args.allow_dangerous_commands is True


def test_dangerous_flag_defaults_false(parser):
    """When the flag is not passed at all, it defaults to False (guard active)."""
    args = parser.parse_args(["ssh", "reboot"])
    assert args.command == "ssh"
    assert args.allow_dangerous_commands is False


def test_dangerous_flag_both_positions_still_true(parser):
    """Passing it in both positions must not clobber back to False (subparser gotcha)."""
    args = parser.parse_args([
        "--allow-dangerous-commands", "ssh", "reboot", "--allow-dangerous-commands",
    ])
    assert args.allow_dangerous_commands is True


# ============================================================================
# Flag is meaningful ONLY for ssh — rejected on other subcommands
# ============================================================================

@pytest.mark.parametrize("argv", [
    ["disposable-container", "echo hi", "--allow-dangerous-commands"],
    ["persistent-container", "echo hi", "--allow-dangerous-commands"],
    ["read", "/etc/hostname", "--allow-dangerous-commands"],
    ["list", "/var/log", "--allow-dangerous-commands"],
])
def test_dangerous_flag_rejected_on_non_ssh_subcommands(parser, argv):
    """The flag is meaningless for containers/read/list and must be rejected there."""
    with pytest.raises(SystemExit):
        parser.parse_args(argv)


# ============================================================================
# Common (global) arguments must be order-independent too — they were silently
# clobbered to None when placed BEFORE the subcommand (argparse subparser bug).
# ============================================================================

# Per-subcommand positional needed so the rest of the line parses.
_SUB_POSITIONAL = {
    "ssh": ["echo hi"],
    "persistent-container": ["echo hi"],
    "disposable-container": ["echo hi"],
    "read": ["/etc/hostname"],
    "list": ["/var/log"],
}


@pytest.mark.parametrize("sub", list(_SUB_POSITIONAL.keys()))
def test_common_arg_before_subcommand_retained(parser, sub):
    """--host placed BEFORE the subcommand must be retained (was clobbered to None)."""
    args = parser.parse_args(["--host", "1.2.3.4", sub, *_SUB_POSITIONAL[sub]])
    assert args.command == sub
    assert args.host == "1.2.3.4"


def test_common_arg_after_subcommand_retained(parser):
    """--host placed AFTER the subcommand still works (the always-worked case)."""
    args = parser.parse_args(["ssh", "echo hi", "--host", "1.2.3.4"])
    assert args.host == "1.2.3.4"


def test_common_arg_both_positions_after_wins(parser):
    """When given both before and after, the after-subcommand value wins (last wins)."""
    args = parser.parse_args(["--host", "before", "ssh", "echo hi", "--host", "after"])
    assert args.host == "after"


def test_multiple_common_args_before_subcommand(parser):
    """Several common args before the subcommand are all retained."""
    args = parser.parse_args([
        "--torque-url", "http://x", "--torque-token", "tok",
        "--host", "1.2.3.4", "--ssh-user", "root",
        "ssh", "echo hi",
    ])
    assert args.torque_url == "http://x"
    assert args.torque_token == "tok"
    assert args.host == "1.2.3.4"
    assert args.ssh_user == "root"


def test_boolean_common_arg_before_subcommand(parser):
    """store_true common flag (--auto-delete-environments) works before subcommand."""
    args = parser.parse_args(["--auto-delete-environments", "ssh", "echo hi"])
    assert args.auto_delete_environments is True


def _clear_common_env(monkeypatch):
    for var in [
        "TORQUE_TUNNEL_CONFIG", "TORQUE_TUNNEL_PROFILE", "TORQUE_URL", "TORQUE_TOKEN",
        "TORQUE_SPACE", "TORQUE_AGENT", "SSH_KEY", "SSH_PASSWORD", "TARGET_HOST",
        "SSH_USER", "INIT_COMMANDS", "FINALLY_COMMANDS", "AUTO_DELETE_ENVIRONMENTS",
        "CONTAINER_IDLE_TIMEOUT",
    ]:
        monkeypatch.delenv(var, raising=False)


def test_common_defaults_present_when_absent(monkeypatch):
    """With no env/CLI values, common attributes still exist with their defaults."""
    _clear_common_env(monkeypatch)
    p = mcp_tool.build_parser()
    args = p.parse_args(["ssh", "echo hi"])
    assert args.host is None
    assert args.torque_url is None
    assert args.verbose is False
    assert args.auto_delete_environments is False
    assert args.container_idle_timeout == 7200


def test_no_subcommand_has_common_defaults(monkeypatch):
    """Running with no subcommand (serve) still populates common defaults."""
    _clear_common_env(monkeypatch)
    p = mcp_tool.build_parser()
    args = p.parse_args([])
    assert args.command is None
    assert args.host is None
    assert hasattr(args, "torque_url")
    assert args.container_idle_timeout == 7200


def test_common_env_default_applied(monkeypatch):
    """Env-var default is applied when the flag is not passed."""
    _clear_common_env(monkeypatch)
    monkeypatch.setenv("TARGET_HOST", "10.9.9.9")
    p = mcp_tool.build_parser()
    args = p.parse_args(["ssh", "echo hi"])
    assert args.host == "10.9.9.9"


def test_common_env_default_overridden_before_subcommand(monkeypatch):
    """A flag BEFORE the subcommand overrides the env default (the core regression)."""
    _clear_common_env(monkeypatch)
    monkeypatch.setenv("TARGET_HOST", "10.9.9.9")
    p = mcp_tool.build_parser()
    args = p.parse_args(["--host", "1.2.3.4", "ssh", "echo hi"])
    assert args.host == "1.2.3.4"
