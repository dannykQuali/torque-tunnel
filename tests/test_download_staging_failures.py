"""A download source the agent cannot stage completely fails, with the reason.

Found live 2026-11-11 on .240 (SSH target): `scp -r` of a directory holding a dangling
symlink printed "scp: .../dangling: No such file or directory" and a WARNING, sent the
rest of the directory, and the download reported "Downloaded" with exit 0 - the entry
silently missing. The same applies on containers when `cp -rH` fails part-way (an
unreadable file). Now the partial copy is dropped and that source is reported failed
(STAGE_FAILED sentinel), while the other sources still download.
"""

import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, mcp_tool

import _bash_harness as bh
from _bash_harness import needs_bash

# Records the staged entries (Linux-side types), then succeeds.
FAKE_CROC = r"""#!/bin/bash
find . -mindepth 1 ! -name .croc_send.log -printf '%y %P\n' > "$FAKE_DIR/types"
echo "Code is: $CROC_SECRET"
exit 0
"""

# Fake scp for the SSH path: "copies" the directory with one entry missing and fails
# the way OpenSSH scp does on a dangling link; any other source copies fine.
FAKE_SCP = r"""#!/bin/bash
for a in "$@"; do last=$a; done
src=${@: -2:1}; src=${src#*:}
case "$src" in
  */broken)
    mkdir -p "$last" && echo partial > "$last/f"
    echo "scp: $src/dangling: No such file or directory" >&2
    exit 1 ;;
  *) echo whole > "$last"; exit 0 ;;
esac
"""


@needs_bash
class TestStagingFailures:
    @pytest.fixture
    def run(self, tmp_path, monkeypatch):
        monkeypatch.setattr(croc_manager, "CROC_SEND_RETRY_DELAY_SECONDS", 0)
        monkeypatch.setattr(croc_manager, "CROC_SEND_MONITOR_TICK_SECONDS", 0.05)
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        bh.make_executable(fake_bin / "croc", FAKE_CROC)
        bh.make_executable(fake_bin / "scp", FAKE_SCP)
        control = tmp_path / "control"
        control.mkdir()

        def run(commands, setup=""):
            script = tmp_path / "dl.sh"
            bh.write_text(script, setup + "\n" + commands + "\n")
            proc = bh.run_script(script, prepend_path=[fake_bin], env={
                "FAKE_DIR": control, croc_manager.CROC_SEND_CODE_ENV: "test-code",
                croc_manager.SSH_PASSWORD_ENV: "pw"})
            types = control / "types"
            proc.types = dict(reversed(line.split(" ", 1)) for line in
                              (types.read_text().splitlines() if types.exists() else []))
            return proc

        return run, tmp_path

    def test_container_an_unreadable_file_fails_its_source_and_the_rest_still_goes(self, run):
        run, _ = run
        # On Linux's own filesystem: on /mnt/c (WSL's view of a Windows drive)
        # chmod 000 does not make a file unreadable.
        import uuid
        src = f"/tmp/tt-stage-test-{uuid.uuid4().hex}"
        setup = "\n".join([f'S="{src}"', 'mkdir -p "$S/dir" && echo ok > "$S/good"',
                           'echo a > "$S/dir/readable" && echo b > "$S/dir/secret" && chmod 000 "$S/dir/secret"',
                           'trap \'chmod -R u+rwX "$S"; rm -rf "${S:?}"\' EXIT'])
        cmds = croc_manager.generate_croc_send_commands([
            {"remote_source_path": f"{src}/good", "croc_filename": "_croc_dl_0_good"},
            {"remote_source_path": f"{src}/dir", "croc_filename": "_croc_dl_1_dir"},
        ])
        proc = run(cmds, setup)
        if os.environ.get("USER") == "root" or "root" in proc.stdout:  # root can read 000
            pytest.skip("running as root")
        assert f"{croc_manager.CROC_SENTINEL_STAGE_FAILED} 1 reason=could not copy {src}/dir completely" in proc.stdout, proc.stdout + proc.stderr
        assert "Permission denied" in proc.stdout
        assert "_croc_dl_1_dir" not in proc.types, proc.types      # the partial copy was dropped
        assert proc.types.get("_croc_dl_0_good") == "f"           # the other source still goes
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout

    def test_ssh_a_failing_scp_fails_its_source_and_the_rest_still_goes(self, run):
        run, _ = run
        cmds = croc_manager.generate_croc_scp_download_commands([
            {"remote_source_path": "/data/fine.txt", "croc_filename": "_croc_dl_0_fine.txt"},
            {"remote_source_path": "/tmp/broken", "croc_filename": "_croc_dl_1_broken"},
        ], target_ip="10.0.0.1", ssh_user="root")
        proc = run(cmds)
        assert (f"{croc_manager.CROC_SENTINEL_STAGE_FAILED} 1 reason=could not copy /tmp/broken completely: "
                "scp: /tmp/broken/dangling: No such file or directory") in proc.stdout, proc.stdout + proc.stderr
        assert "WARNING: Failed to stage /tmp/broken" in proc.stderr
        assert "_croc_dl_1_broken" not in proc.types, proc.types
        assert proc.types.get("_croc_dl_0_fine.txt") == "f"

    def test_nothing_staged_is_still_the_senders_failure(self, run):
        run, _ = run
        cmds = croc_manager.generate_croc_scp_download_commands(
            [{"remote_source_path": "/tmp/broken", "croc_filename": "_croc_dl_0_broken"}],
            target_ip="10.0.0.1", ssh_user="root")
        proc = run(cmds)
        assert f"{croc_manager.CROC_SENTINEL_STAGE_FAILED} 0 " in proc.stdout
        assert f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=stage" in proc.stdout


def test_the_local_side_reports_the_reason_and_places_only_the_complete_sources():
    receive = tempfile.mkdtemp(prefix="tt_dl_")
    dest = tempfile.mkdtemp(prefix="tt_dest_")
    try:
        with open(os.path.join(receive, "_croc_dl_0_fine.txt"), "w") as f:
            f.write("whole\n")
        os.makedirs(os.path.join(receive, "_croc_dl_1_broken"))   # even if something arrived
        plan = mcp_tool.DownloadPlan(needs_download=True, croc_receive_dir=receive, file_mappings=[
            {"croc_filename": "_croc_dl_0_fine.txt", "local_destination_path": os.path.join(dest, "fine.txt")},
            {"croc_filename": "_croc_dl_1_broken", "local_destination_path": os.path.join(dest, "broken")},
        ])
        plan.observe_output(
            f"[12:00:00.000] {croc_manager.CROC_SENTINEL_STAGE_FAILED} 1 reason=could not copy /tmp/broken "
            "completely: scp: /tmp/broken/dangling: No such file or directory\n")

        successes, errors = mcp_tool.finalize_download(plan)

        assert successes == [f"Downloaded: {os.path.join(dest, 'fine.txt')}"]
        assert errors == [f"Download failed for {os.path.join(dest, 'broken')}: the agent could not copy "
                          "/tmp/broken completely: scp: /tmp/broken/dangling: No such file or directory"]
        assert not os.path.exists(os.path.join(dest, "broken"))
    finally:
        import shutil
        shutil.rmtree(receive, ignore_errors=True)
        shutil.rmtree(dest, ignore_errors=True)
