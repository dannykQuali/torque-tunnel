"""A transfer that fails because croc could not be INSTALLED must say so, and why.

Found 2026-09-23 by testing a profile whose proxy host does not exist:

- The install piped `curl -s` into `tar`, so the only output was
  "gzip: stdin: unexpected end of file" + "ERROR: Failed to install croc" -
  curl's own "Could not resolve proxy" was silenced.
- A download then reported "croc sender never registered with the relay",
  because the sender never got far enough to emit any sentinel.
- The upload-error extractor matched the croc receive SCRIPT, which the
  container blueprint echoes into its log, and reported
  `croc file receive failed (exit code: $__CROC_RC)...` - unexpanded source.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager
from torque_tunnel import mcp_tool
from torque_tunnel.mcp_tool import DownloadPlan

import _bash_harness as bh
from _bash_harness import needs_bash


# ============================================================================
# The install reports curl's reason (shell-level)
# ============================================================================

# Fails the way curl does when its proxy host does not resolve. Logs its argv.
FAKE_CURL_BAD_PROXY = r"""#!/bin/bash
echo "curl $*" >> "$FAKE_DIR/curl_calls"
echo "curl: (5) Could not resolve proxy: no-such-proxy.invalid" >&2
exit 5
"""


@needs_bash
class TestInstallFailureNamesTheCause:
    @pytest.fixture
    def run_install(self, tmp_path):
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        bh.make_executable(fake_bin / "curl", FAKE_CURL_BAD_PROXY)
        fake_bin_posix = subprocess.run(
            [bh.BASH, "-c", f"cygpath -u '{fake_bin}'"], capture_output=True, text=True
        ).stdout.strip() or str(fake_bin).replace("\\", "/")

        def run(proxy="http://no-such-proxy.invalid:80", failure_sentinel=None):
            script = croc_manager.generate_remote_croc_install_script(
                failure_sentinel=failure_sentinel)
            path = tmp_path / "install.sh"
            # A minimal PATH: a real croc elsewhere on PATH would skip the install.
            bh.write_text(path, f'export PATH="{fake_bin_posix}:/usr/bin:/bin"\n'
                                f"export https_proxy='{proxy}' HTTPS_PROXY='{proxy}'\n"
                                + script + '\necho "INSTALL-OK"\n')
            env = os.environ.copy()
            env["FAKE_DIR"] = str(control)
            proc = subprocess.run([bh.BASH, str(path)], capture_output=True, text=True,
                                  timeout=120, env=env)
            calls_file = control / "curl_calls"
            calls = calls_file.read_text().splitlines() if calls_file.exists() else []
            return proc, calls

        return run

    def test_curls_own_error_is_reported(self, run_install):
        proc, _ = run_install()
        assert proc.returncode != 0
        assert "INSTALL-OK" not in proc.stdout
        errors = [l for l in proc.stderr.splitlines() if "Failed to install croc" in l]
        assert errors, proc.stderr
        assert "Could not resolve proxy: no-such-proxy.invalid" in errors[-1]

    def test_the_proxy_in_use_is_named(self, run_install):
        proc, _ = run_install()
        errors = [l for l in proc.stderr.splitlines() if "Failed to install croc" in l]
        assert "no-such-proxy.invalid:80" in errors[-1]

    def test_proxy_credentials_are_never_printed(self, run_install):
        proc, _ = run_install(proxy="http://alice:s3cr3t@no-such-proxy.invalid:80")
        assert "s3cr3t" not in proc.stderr and "s3cr3t" not in proc.stdout
        assert "alice" not in proc.stderr

    def test_no_misleading_tar_noise(self, run_install):
        """The old pipe into tar turned every download failure into a gzip error."""
        proc, _ = run_install()
        assert "unexpected end of file" not in proc.stderr
        assert "tar:" not in proc.stderr

    def test_every_curl_has_a_connect_timeout(self, run_install):
        """A proxy that drops packets must not stall the install for minutes."""
        _, calls = run_install()
        assert calls, "curl was never called"
        assert all("--connect-timeout" in c for c in calls), calls

    def test_download_path_gets_a_failed_sentinel(self, run_install):
        """The local receiver waits for sentinels; without one it only learns that
        the sender 'never registered'."""
        proc, _ = run_install(failure_sentinel=croc_manager.CROC_SENTINEL_FAILED)
        failed = [l for l in proc.stdout.splitlines() if croc_manager.CROC_SENTINEL_FAILED in l]
        assert failed, proc.stdout
        assert "exit_code=install" in failed[-1]
        assert "reason=Failed to install croc: curl: (5) Could not resolve proxy" in failed[-1]

    def test_upload_path_emits_no_sentinel(self, run_install):
        proc, _ = run_install()
        assert croc_manager.CROC_SENTINEL_FAILED not in proc.stdout


# ============================================================================
# The download plan uses the sentinel-emitting install, and the tool reads it
# ============================================================================

class TestDownloadInstallFailureIsReported:
    def test_download_commands_install_with_a_failure_sentinel(self):
        plan = mcp_tool.prepare_download_with_croc(
            [{"remote_source_path": "/tmp/f", "local_destination_path": os.path.join(os.getcwd(), "f")}])
        try:
            install = plan.download_commands.split("# === End croc install ===")[0]
            assert f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=install" in install
        finally:
            import shutil
            shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_the_result_names_the_install_failure(self, tmp_path):
        plan = DownloadPlan(needs_download=True, croc_code="c", croc_receive_dir=str(tmp_path))
        plan.file_mappings = [{"croc_filename": "_croc_dl_0_f",
                               "local_destination_path": str(tmp_path / "out" / "f")}]
        plan.observe_output(
            f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=install reason=Failed to install "
            "croc: curl: (5) Could not resolve proxy: no-such-proxy.invalid (proxy: "
            "http://no-such-proxy.invalid:80)\n")
        _, errors = await mcp_tool.complete_download(plan, None)
        joined = "\n".join(errors)
        assert "Could not resolve proxy: no-such-proxy.invalid" in joined
        assert "never registered" not in joined

    def test_a_stage_name_is_not_presented_as_an_exit_code(self):
        text = mcp_tool.describe_remote_failure(
            f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=install reason=Failed to install croc: x")
        assert text == "Failed to install croc: x"

    def test_a_numeric_exit_code_is_still_shown(self):
        text = mcp_tool.describe_remote_failure(
            f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=1 reason=boom")
        assert text.startswith("exit code 1: boom")


# ============================================================================
# The upload-error extractor reads runtime output, not the echoed script
# ============================================================================

# Verbatim from the 2026-09-23 container run (env Q36kTXf5b5Js): the blueprint
# echoes the init commands, so the croc receive script's own source is in the log.
ECHOED_SOURCE = ('[16:55:24.600]   echo "ERROR: croc file receive failed (exit code: '
                 '$__CROC_RC)${__CROC_ERR:+: $__CROC_ERR}" >&2')


class TestUploadErrorExtraction:
    def test_the_echoed_script_source_is_not_an_error(self):
        assert mcp_tool.extract_transfer_errors(ECHOED_SOURCE + "\n") == []

    def test_a_runtime_receive_failure_is_found(self):
        log = "[16:55:25.000] ERROR: croc file receive failed (exit code: 1): could not secure channel\n"
        assert mcp_tool.extract_transfer_errors(log) == [
            "croc file receive failed (exit code: 1): could not secure channel"]

    def test_an_install_failure_is_found(self):
        log = ECHOED_SOURCE + "\n" + (
            "[16:55:24.691] ERROR: Failed to install croc: curl: (5) Could not resolve "
            "proxy: no-such-proxy.invalid (proxy: http://no-such-proxy.invalid:80)\n")
        assert mcp_tool.extract_transfer_errors(log) == [
            "Failed to install croc: curl: (5) Could not resolve proxy: no-such-proxy.invalid "
            "(proxy: http://no-such-proxy.invalid:80)"]

    def test_the_download_section_is_not_an_upload(self):
        """The same install failure in the download section is the DOWNLOAD's,
        and is already reported through the FAILED sentinel."""
        log = ("[16:55:24.696] === Running download commands ===\n"
               "[16:55:24.712] ERROR: Failed to install croc: curl: (5) nope\n")
        assert mcp_tool.extract_transfer_errors(log) == []

    def test_lines_without_timestamps_are_read_too(self):
        assert mcp_tool.extract_transfer_errors("ERROR: Failed to install croc: x\n") == [
            "Failed to install croc: x"]


# ============================================================================
# The CLI reports failed uploads too
# ============================================================================

class _Result:
    def __init__(self, status="completed", exit_code=0):
        self.status, self.exit_code, self.environment_id = status, exit_code, "env123"


class _FakeClient:
    def __init__(self, log):
        self.log, self.fetched = log, 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_grain_log(self, env_id):
        self.fetched += 1
        return self.log


class TestCliUploadErrors:
    LOG = ("[17:29:13.000] ERROR: Failed to install croc: curl: (5) Could not resolve proxy: "
           "no-such-proxy.invalid (proxy: http://no-such-proxy.invalid:80)\n")

    def _plan(self, needs_croc=True):
        return mcp_tool.FileDeploymentPlan(needs_croc=needs_croc)

    @pytest.mark.asyncio
    async def test_a_failed_croc_upload_reports_the_reason(self):
        client = _FakeClient(self.LOG)
        from unittest import mock
        with mock.patch.object(mcp_tool, "get_torque_client", return_value=client):
            errors = await mcp_tool._cli_upload_errors(self._plan(), _Result(exit_code=1))
        assert errors and "Could not resolve proxy: no-such-proxy.invalid" in errors[0]

    @pytest.mark.asyncio
    async def test_a_successful_run_does_not_fetch_the_log(self):
        client = _FakeClient(self.LOG)
        from unittest import mock
        with mock.patch.object(mcp_tool, "get_torque_client", return_value=client):
            assert await mcp_tool._cli_upload_errors(self._plan(), _Result()) == []
        assert client.fetched == 0

    @pytest.mark.asyncio
    async def test_no_croc_upload_means_nothing_to_report(self):
        client = _FakeClient(self.LOG)
        from unittest import mock
        with mock.patch.object(mcp_tool, "get_torque_client", return_value=client):
            assert await mcp_tool._cli_upload_errors(self._plan(needs_croc=False), _Result(exit_code=1)) == []
            assert await mcp_tool._cli_upload_errors(None, _Result(exit_code=1)) == []
        assert client.fetched == 0

    @pytest.mark.asyncio
    async def test_a_log_fetch_failure_is_not_fatal(self):
        from unittest import mock
        with mock.patch.object(mcp_tool, "get_torque_client", side_effect=RuntimeError("down")):
            assert await mcp_tool._cli_upload_errors(self._plan(), _Result(exit_code=1)) == []
