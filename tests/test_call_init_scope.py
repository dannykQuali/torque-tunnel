"""A call's own init commands (its file uploads) run once, where the command runs.

The blueprints re-load init commands on the agent's runner container before the setup
step (container pre-commands) and the download step, because the profile's
init_commands carry the proxy settings croc needs there. A call's own init commands -
the upload commands mcp_tool generates - used to travel in the same input, so they were
re-run on the runner too. Confirmed live on 2026-11-06:

- disposable container, a croc upload and a download in one call: the download step ran
  the upload's croc receive a second time; it found no sender, failed, and its `exit 1`
  ended the whole script, so the call failed (environments g0qXIFP6xDnj, QBoVJVtvJl3v,
  and jL3M9jEyQqAs on the code before).
- SSH target (and persistent container): the small inline uploads were written on the
  runner as well (pzLxdbIsTXBq). Harmless, but work on the wrong machine.

These tests build the environment with the real TorqueClient, render its script the way
Torque does, and run it under bash with ssh faked.
"""

import base64
import os
import re
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel.torque_client import TorqueClient

import _bash_harness as bh
from _bash_harness import needs_bash


KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n"
# Computed, so the visibility dump of the command's SOURCE never contains the result
COMMAND = 'echo "CMD-$((40+2))"'
RAN = "CMD-42"
PROFILE_INIT = "export HTTPS_PROXY=http://profile-proxy.test:80"
UPLOAD = 'echo "UPLOAD-RAN on $(cat "$FAKE_DIR/where" 2>/dev/null || echo runner)" >> "$FAKE_DIR/upload_runs"'

_INPUT_REF = re.compile(r"\{\{\s*\.inputs\.(\w+)\s*\}\}")


class _Capturing(TorqueClient):
    payloads: list = []

    async def _create_environment_idempotent(self, payload, key):
        _Capturing.payloads.append(payload)
        return "env-1"


def _render(payload):
    """The script Torque runs and the environment variables its env-vars set."""
    blueprint = yaml.safe_load(base64.b64decode(payload["base64_standalone_blueprint"]))
    inputs = payload["inputs"]

    def render(text):
        return _INPUT_REF.sub(lambda m: str(inputs.get(m.group(1), "")), text)

    spec = next(iter(blueprint["grains"].values()))["spec"]
    script = render(spec["activities"]["deploy"]["commands"][0]["command"])
    env = {k: render(v) for entry in spec.get("env-vars") or [] for k, v in entry.items()}
    return script, env


# The target: save the script it was sent and run it, marked as running "on target".
FAKE_SSH = r"""#!/bin/bash
cat > "$FAKE_DIR/remote_script"
echo target > "$FAKE_DIR/where"
bash "$FAKE_DIR/remote_script"
rc=$?
rm -f "$FAKE_DIR/where"
exit $rc
"""

FAKE_TIMEOUT_FUNC = r"""timeout() {
  shift 1
  "$@"
}
"""


@needs_bash
class TestCallInitRunsOnceWhereTheCommandRuns:
    @pytest.fixture
    def run(self, tmp_path):
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        bh.make_executable(fake_bin / "ssh", FAKE_SSH)

        async def run(kind, **kw):
            _Capturing.payloads = []
            client = _Capturing(base_url="https://torque.example", token="t", space="S",
                                default_agent="agent", init_commands=PROFILE_INIT)
            if kind == "ssh":
                await client.start_environment(target_ip="10.9.9.9", ssh_user="root",
                                               ssh_private_key=KEY, **kw)
            else:
                await client.start_local_environment(**kw)
            script, env = _render(_Capturing.payloads[0])
            path = tmp_path / "grain.sh"
            bh.write_text(path, f'export PATH="{bh.shell_path(fake_bin)}:$PATH"\n'
                                "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY\n"
                                + FAKE_TIMEOUT_FUNC + script + "\n")
            proc = bh.run_script(path, env={"FAKE_DIR": control, **env})
            runs = control / "upload_runs"
            return proc, (runs.read_text().splitlines() if runs.exists() else []), control

        return run

    @pytest.mark.asyncio
    async def test_container_upload_runs_once_even_with_a_download(self, run):
        """The failure seen live: the download step re-ran the upload's croc receive."""
        proc, runs, _ = await run("local", command=COMMAND, init_commands=UPLOAD,
                                  download_commands='echo "DL-PROXY=${HTTPS_PROXY:-unset}"')
        assert RAN in proc.stdout, proc.stdout + proc.stderr
        assert len(runs) == 1, runs
        # The profile's init_commands are still loaded for the download (proxy)
        assert "DL-PROXY=http://profile-proxy.test:80" in proc.stdout

    @pytest.mark.asyncio
    async def test_container_upload_failure_still_stops_the_command(self, run):
        """A failed upload must not let the command run on missing files (as before)."""
        proc, _, _ = await run("local", command=COMMAND, init_commands="false")
        assert RAN not in proc.stdout
        assert "Command completed with exit code: 1" in proc.stdout, proc.stdout

    @pytest.mark.asyncio
    async def test_ssh_upload_runs_only_on_the_target(self, run):
        proc, runs, control = await run(
            "ssh", command=COMMAND, init_commands=UPLOAD,
            container_pre_commands='echo "PRE-PROXY=${HTTPS_PROXY:-unset}"',
            download_commands='echo "DL-PROXY=${HTTPS_PROXY:-unset}"')
        assert "Command completed with exit code: 0" in proc.stdout, proc.stdout + proc.stderr
        assert runs == ["UPLOAD-RAN on target"], runs
        # The runner still gets the profile's init_commands for its own steps
        assert "PRE-PROXY=http://profile-proxy.test:80" in proc.stdout
        assert "DL-PROXY=http://profile-proxy.test:80" in proc.stdout
        # On the target: profile init, then the upload, then the command
        remote = (control / "remote_script").read_text()
        assert remote.index(PROFILE_INIT) < remote.index(UPLOAD) < remote.index(COMMAND)
        assert RAN in proc.stdout

    @pytest.mark.asyncio
    async def test_ssh_upload_failure_still_stops_the_command(self, run):
        proc, _, _ = await run("ssh", command=COMMAND, init_commands="false")
        assert RAN not in proc.stdout
        assert "Command completed with exit code: 1" in proc.stdout, proc.stdout
