"""download_files of a symlink sends what it points to.

Found 2026-11-11 (live, agent cpoc-rtp-dev, and confirmed with GNU coreutils 8.32 on
the agent): container-mode downloads staged each source with `ln SRC STAGED || cp -r`.
GNU ln hard-links a symlink ITSELF, and succeeds, so the cp fallback never ran:
- a symlink with a relative target (/etc/os-release -> ../usr/lib/os-release) was left
  dangling in the staging directory, and the download failed with "no files were staged
  for download";
- a symlink to a directory, the same;
- a symlink with an absolute target was staged as a symlink, so the size sentinel
  (stat without -L) reported the length of the link, not of the file.

The generated send commands run here under bash with a fake croc that records what it
was given (symlinks preserved), exactly as croc would find it in its directory.
"""

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager

import _bash_harness as bh
from _bash_harness import needs_bash

# Records the staged entries as croc sees them, then exits 0: their types as Linux sees
# them (f file, d directory, l symlink) and a copy of their contents. The types are
# taken here, not from Windows: WSL stores a symlink on /mnt/c in one of two forms
# (depending on whether its target existed when it was made), and Windows Python
# recognizes only one of them.
FAKE_CROC = r"""#!/bin/bash
find . -mindepth 1 ! -name .croc_send.log -printf '%y %P\n' > "$FAKE_DIR/types"
mkdir -p "$FAKE_DIR/sent"
cp -rL ./. "$FAKE_DIR/sent/" 2>/dev/null
echo "Code is: $CROC_SECRET"
exit 0
"""

CONTENT = "the file's own contents\n"


@needs_bash
class TestSymlinkDownloads:
    @pytest.fixture
    def world(self, tmp_path, monkeypatch):
        monkeypatch.setattr(croc_manager, "CROC_SEND_RETRY_DELAY_SECONDS", 0)
        monkeypatch.setattr(croc_manager, "CROC_SEND_MONITOR_TICK_SECONDS", 0.05)
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        bh.make_executable(fake_bin / "croc", FAKE_CROC)
        control = tmp_path / "control"
        control.mkdir()
        src = tmp_path / "src"
        (src / "usr" / "lib").mkdir(parents=True)
        (src / "etc").mkdir()
        (src / "data").mkdir()
        (src / "usr" / "lib" / "os-release").write_text(CONTENT, newline="\n")
        (src / "data" / "inner.txt").write_text("inner\n", newline="\n")

        # The links are made by the script itself, inside WSL, so they are real Linux
        # symlinks (Windows-side symlinks need privileges and are not POSIX ones).
        setup = "\n".join([
            f'S="{bh.shell_path(src)}"',
            'ln -s ../usr/lib/os-release "$S/etc/os-release"',     # relative target
            'ln -s "$S/usr/lib/os-release" "$S/etc/absolute"',      # absolute target
            'ln -s ../data "$S/etc/datalink"',                      # symlink to a directory
            'ln -s inner.txt "$S/data/inner-link"',                 # a symlink INSIDE a directory
            'ln -s os-release "$S/etc/chain"',                      # symlink -> symlink -> file
            'ln -s nowhere "$S/etc/dangling"',
        ])

        def download(*names):
            infos = [{"remote_source_path": f"{bh.shell_path(src)}/{n}", "croc_filename": f"_croc_dl_{i}_x"}
                     for i, n in enumerate(names)]
            script = tmp_path / "dl.sh"
            bh.write_text(script, setup + "\n" + croc_manager.generate_croc_send_commands(infos) + "\n")
            proc = bh.run_script(script, prepend_path=[fake_bin], env={
                "FAKE_DIR": control, croc_manager.CROC_SEND_CODE_ENV: "test-code"})
            proc.sent = control / "sent"
            types = control / "types"
            proc.types = dict(reversed(line.split(" ", 1)) for line in
                              (types.read_text().splitlines() if types.exists() else []))
            return proc

        return download

    def _sentinel(self, proc, sentinel, name):
        for line in proc.stdout.splitlines():
            if line.startswith(sentinel) and line.endswith(name):
                return line.split()[1]
        return None

    @pytest.mark.parametrize("link", ["etc/os-release", "etc/absolute", "etc/chain"])
    def test_a_symlink_to_a_file_sends_the_file(self, world, link):
        proc = world(link)
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout, proc.stdout + proc.stderr
        assert proc.types.get("_croc_dl_0_x") == "f", proc.types   # the file, not the link
        assert (proc.sent / "_croc_dl_0_x").read_text() == CONTENT
        assert self._sentinel(proc, croc_manager.CROC_SENTINEL_SIZE, "_croc_dl_0_x") == str(len(CONTENT))
        assert self._sentinel(proc, croc_manager.CROC_SENTINEL_MD5, "_croc_dl_0_x") == \
            hashlib.md5(CONTENT.encode()).hexdigest()

    def test_a_symlink_to_a_directory_sends_the_directory(self, world):
        proc = world("etc/datalink")
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout, proc.stdout + proc.stderr
        assert proc.types.get("_croc_dl_0_x") == "d", proc.types
        assert (proc.sent / "_croc_dl_0_x" / "inner.txt").read_text() == "inner\n"

    def test_links_inside_a_directory_stay_links(self, world):
        """Only the path that was asked for is followed; a directory's contents are
        sent as they are."""
        proc = world("data")
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout, proc.stdout + proc.stderr
        assert proc.types.get("_croc_dl_0_x/inner-link") == "l", proc.types

    def test_a_regular_file_is_still_sent(self, world):
        proc = world("usr/lib/os-release")
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout, proc.stdout + proc.stderr
        assert (proc.sent / "_croc_dl_0_x").read_text() == CONTENT

    def test_a_dangling_symlink_is_reported_not_sent(self, world):
        proc = world("etc/dangling")
        assert "Failed to stage" in proc.stderr, proc.stderr
        assert f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=stage" in proc.stdout, proc.stdout
