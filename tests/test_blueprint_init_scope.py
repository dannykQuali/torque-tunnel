"""The profile's init_commands must apply to the SSH runner's upload step too.

remote-shell-executor runs croc uploads for SSH targets in its
``container_pre_commands`` slot, on the runner container, before connecting to
the target. That slot did not load the profile's init_commands, where proxy
settings live, while the download slot did. A 2026-09-23 test with a profile
pointing at a non-existent proxy showed the split: the download failed on the
bad proxy, the upload silently used whatever proxy the agent container
happened to carry. On an agent without one, uploads would fail outright.

These tests run the real blueprint script under bash, with its Torque template
inputs filled in and ``ssh`` faked, so they check behaviour rather than text.
"""

import base64
import gzip
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel.torque_client import TorqueClient

import _bash_harness as bh
from _bash_harness import needs_bash


def _gz_b64(text: str) -> str:
    return base64.b64encode(gzip.compress(text.encode("utf-8"))).decode("ascii") if text else ""


def _run_ssh_command() -> str:
    encoded = TorqueClient._load_standalone_blueprint("remote-shell-executor", False)
    blueprint = yaml.safe_load(base64.b64decode(encoded).decode("utf-8"))
    spec = blueprint["grains"]["remote_executor"]["spec"]
    return spec["activities"]["deploy"]["commands"][0]["command"]


# The target: consume the remote script without running it (these tests are
# about what happens on the RUNNER), and leave a trace that SSH happened.
FAKE_SSH = r"""#!/bin/bash
echo "ssh $*" >> "$FAKE_DIR/ssh_calls"
cat > /dev/null
exit 0
"""

# `timeout` is a shell function, like the other harnesses' coreutils fakes.
FAKE_TIMEOUT_FUNC = r"""timeout() {
  shift 1
  "$@"
}
"""


@needs_bash
class TestPreCommandsSeeTheProfileInit:
    @pytest.fixture
    def run_blueprint(self, tmp_path):
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        bh.make_executable(fake_bin / "ssh", FAKE_SSH)
        template = _run_ssh_command()
        # Put first from inside the script, after the launcher's own PATH setup.
        fake_bin_posix = bh.shell_path(fake_bin)

        def run(init="", pre="", command="true"):
            inputs = {
                "command_b64": _gz_b64(command),
                "init_commands_b64": _gz_b64(init),
                "container_pre_commands_b64": _gz_b64(pre),
                "finally_commands_b64": "",
                "download_commands_b64": "",
                "credential_context_b64": "",
                "ssh_user": "root",
                "target_ip": "10.9.9.9",
                "ssh_private_key": "-----BEGIN KEY-----\nnot-a-key\n-----END KEY-----",
                "ssh_password": "",
                "timeout_minutes": "1",
            }
            rendered = re.sub(r"\{\{ \.inputs\.(\w+) \}\}",
                              lambda m: inputs.get(m.group(1), ""), template)
            script = tmp_path / "run_ssh.sh"
            # The proxy variables are cleared: the tests assert which proxy the
            # profile's init_commands set, and an inherited one would mask that.
            bh.write_text(script, f'export PATH="{fake_bin_posix}:$PATH"\n'
                                  "unset http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY\n"
                                  + FAKE_TIMEOUT_FUNC + rendered + "\n")
            proc = bh.run_script(script, env={"FAKE_DIR": control})
            calls = control / "ssh_calls"
            return proc, calls.exists()

        return run

    def test_pre_commands_see_the_profile_proxy(self, run_blueprint):
        proc, _ = run_blueprint(
            init="export HTTPS_PROXY=http://profile-proxy.test:80",
            pre='echo "PRE_PROXY=${HTTPS_PROXY:-unset}"')
        assert "PRE_PROXY=http://profile-proxy.test:80" in proc.stdout, proc.stdout + proc.stderr

    def test_init_cannot_disturb_the_blueprint_itself(self, run_blueprint):
        """init_commands are the user's; they must not be able to rewrite the
        blueprint's own state (here: the flag that decides whether to SSH)."""
        proc, ssh_ran = run_blueprint(
            init="export HTTPS_PROXY=http://p:80; __SKIP_SSH=1; cd /",
            pre="true")
        assert ssh_ran, "an init_commands variable leaked into the blueprint and skipped SSH"
        assert "Command completed with exit code: 0" in proc.stdout, proc.stdout + proc.stderr

    def test_a_failing_init_does_not_block_the_upload(self, run_blueprint):
        proc, _ = run_blueprint(init="false", pre='echo "PRE-$((40+2))"')
        assert "PRE-42" in proc.stdout, proc.stdout + proc.stderr

    def test_a_failing_pre_command_still_stops_before_ssh(self, run_blueprint):
        proc, ssh_ran = run_blueprint(init="export HTTPS_PROXY=http://p:80", pre="exit 3")
        assert not ssh_ran
        assert "Container pre-commands failed" in proc.stdout + proc.stderr
        assert "Command completed with exit code: 3" in proc.stdout

    def test_without_pre_commands_init_is_not_run_on_the_runner(self, run_blueprint):
        """init_commands are written for the target; only run them on the runner
        when there is runner work that needs them. (The visibility dump prints
        their SOURCE, hence the computed marker.)"""
        proc, ssh_ran = run_blueprint(init='echo "RUNNER-$((40+2))"', pre="")
        assert ssh_ran
        assert "RUNNER-42" not in proc.stdout
