"""Tests for the croc download race fix and failure propagation.

Covers the redesign born from the 2026-07-28 "could not secure channel" failure report:
- Remote send wrapper: registration sentinel (sender-first handshake), per-file size
  sentinels, one retry on failure, failure sentinel + non-zero exit, size-scaled timeout.
- Local receive wrapper: gated start (waits for the sender's room), abort signal,
  size-verified completion (rejects partial files), attempt logging.
- DownloadPlan.observe_output: sentinel parsing from the streamed remote output.
- finalize_download: size verification (partial files are errors, not successes).
- complete_download: bounded wind-down instead of the old unbounded wait.
- Versioned croc binary cache (stale cache after a CROC_VERSION bump).

The shell-level tests execute the actual generated commands under bash (Git Bash on
Windows) with a fake `croc` (and a recording `timeout` shim) on PATH, so they test
behavior rather than the generated text.
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager
from torque_tunnel import mcp_tool
from torque_tunnel.mcp_tool import (
    DownloadPlan,
    complete_download,
    finalize_download,
    make_download_watch_callback,
    cleanup_download_resources,
)

def _find_bash():
    """Locate a bash that accepts Windows paths (Git Bash) — NOT WSL bash.

    On Windows, shutil.which("bash") often returns C:\\Windows\\system32\\bash.EXE
    (WSL), which mangles Windows-style script paths. Prefer Git Bash.
    """
    if sys.platform != "win32":
        return shutil.which("bash")
    candidates = []
    git = shutil.which("git")
    if git:
        git_root = Path(git).parent.parent
        candidates += [git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe"]
    candidates += [
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


BASH = _find_bash()

needs_bash = pytest.mark.skipif(BASH is None, reason="Git Bash not available")


def _write_text(path, content):
    """Write a shell/text file with LF endings and no BOM."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def wait_until(condition, timeout=15.0, interval=0.05):
    """Poll until condition() is truthy or timeout; returns the last value."""
    deadline = time.monotonic() + timeout
    result = condition()
    while not result and time.monotonic() < deadline:
        time.sleep(interval)
        result = condition()
    return result


# ============================================================================
# Shell-level tests of the generated send commands (run under bash)
# ============================================================================

FAKE_CROC_SEND = r"""#!/bin/bash
# Fake croc for send-wrapper tests. Scenario per invocation from scenario.txt:
#   ok              - print registration lines, brief transfer, exit 0
#   fail_no_channel - register, then die like the PAKE race ("could not secure channel")
#   fail_early      - die before registering (relay unreachable)
d="$FAKE_CROC_DIR"
n=$(cat "$d/count" 2>/dev/null || echo 0)
n=$((n+1)); echo "$n" > "$d/count"
ls -A > "$d/cwd_listing_$n.txt"
mkdir -p "$d/staged_$n" && cp -r ./* "$d/staged_$n/" 2>/dev/null
scenario=$(sed -n "${n}p" "$d/scenario.txt")
[ -z "$scenario" ] && scenario=$(tail -n 1 "$d/scenario.txt")
case "$scenario" in
  ok)
    echo "Sending 'x' (5 B)"
    echo "Code is: $CROC_SECRET"
    echo "On the other computer run:"
    echo "(For Windows)"
    echo "    croc $CROC_SECRET"
    echo "(For Linux/macOS)"
    echo "    CROC_SECRET=\"$CROC_SECRET\" croc"
    sleep 1
    exit 0
    ;;
  fail_no_channel)
    echo "Sending 'x' (5 B)"
    echo "Code is: fake-code-123"
    sleep 0.2
    echo "could not secure channel"
    exit 1
    ;;
  fail_early)
    echo "could not connect to relay"
    exit 1
    ;;
  hang_at_100)
    echo "Sending 'x' (5 B)"
    echo "Code is: $CROC_SECRET"
    echo "_croc_dl_x 100% (5/5 B, 1 MB/s)"
    sleep 120
    exit 0
    ;;
  stall_mid)
    echo "Sending 'x' (5 B)"
    echo "Code is: $CROC_SECRET"
    echo "_croc_dl_x  87% (2.1/2.4 GB, 680 kB/s)"
    sleep 300
    exit 0
    ;;
  wait_then_ok)
    echo "Sending 'x' (5 B)"
    echo "Code is: $CROC_SECRET"
    sleep 22
    echo "_croc_dl_x 100% (5/5 B, 1 MB/s)"
    exit 0
    ;;
esac
exit 3
"""

# Records the requested timeout duration, then runs the command WITHOUT enforcing
# it. Defined as a shell FUNCTION prepended to the script under test because Git
# Bash prepends /usr/bin to PATH, so a fake-bin `timeout` would lose to the real
# one — functions outrank PATH lookup. Invoked as: timeout -k 5 <seconds> cmd...
FAKE_TIMEOUT_FUNC = r"""timeout() {
  echo "$3" >> "$FAKE_CROC_DIR/timeouts.txt"
  shift 3
  exec "$@"
}
"""


@needs_bash
class TestSendCommandsBehavior:
    @pytest.fixture
    def harness(self, tmp_path, monkeypatch):
        """Fake bin dir with croc + timeout shims, a control dir, and a source file."""
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        _write_text(fake_bin / "croc", FAKE_CROC_SEND)
        os.chmod(fake_bin / "croc", 0o755)

        src = tmp_path / "data.bin"
        src.write_bytes(b"hello")

        # No delay between send attempts in tests
        monkeypatch.setattr(croc_manager, "CROC_SEND_RETRY_DELAY_SECONDS", 0)

        def run(commands, scenarios):
            _write_text(control / "scenario.txt", "\n".join(scenarios) + "\n")
            script = tmp_path / "under_test.sh"
            _write_text(script, FAKE_TIMEOUT_FUNC + commands + "\n")
            env = os.environ.copy()
            env["FAKE_CROC_DIR"] = str(control)
            env["PATH"] = str(fake_bin) + os.pathsep + env["PATH"]
            proc = subprocess.run(
                [BASH, str(script)],
                capture_output=True, text=True, timeout=120, env=env,
            )
            return proc

        def attempts():
            count_file = control / "count"
            return int(count_file.read_text()) if count_file.exists() else 0

        return {"run": run, "control": control, "src": src, "attempts": attempts}

    def _commands(self, src, timeout=300):
        # POSIX-style path for use inside bash
        posix_src = str(src).replace("\\", "/")
        return croc_manager.generate_croc_send_commands(
            code="test-code",
            file_infos=[{
                "remote_source_path": posix_src,
                "croc_filename": "_croc_dl_0_data.bin",
            }],
            timeout=timeout,
        )

    def test_ready_sentinel_after_registration(self, harness):
        proc = harness["run"](self._commands(harness["src"]), ["ok"])
        assert proc.returncode == 0, proc.stderr
        assert croc_manager.CROC_SENTINEL_READY in proc.stdout
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout
        assert croc_manager.CROC_SENTINEL_FAILED not in proc.stdout

    def test_secret_never_echoed_to_output(self, harness):
        """Croc prints the transfer code; the wrapper must filter it out of the
        streamed output so it never lands in the persisted grain log."""
        proc = harness["run"](self._commands(harness["src"]), ["ok"])
        assert proc.returncode == 0, proc.stderr
        assert "test-code" not in proc.stdout
        assert "test-code" not in proc.stderr

    def test_no_ready_sentinel_when_sender_never_registers(self, harness):
        """If croc dies before registering its room, READY must NOT be emitted."""
        proc = harness["run"](self._commands(harness["src"]), ["fail_early"])
        assert croc_manager.CROC_SENTINEL_READY not in proc.stdout

    def test_size_sentinel_emitted(self, harness):
        proc = harness["run"](self._commands(harness["src"]), ["ok"])
        assert f"{croc_manager.CROC_SENTINEL_SIZE} 5 _croc_dl_0_data.bin" in proc.stdout

    def test_md5_sentinel_emitted(self, harness):
        """The sender must report a content hash — size alone is not integrity."""
        import hashlib
        expected_md5 = hashlib.md5(b"hello").hexdigest()
        proc = harness["run"](self._commands(harness["src"]), ["ok"])
        assert f"{croc_manager.CROC_SENTINEL_MD5} {expected_md5} _croc_dl_0_data.bin" in proc.stdout

    def test_retry_once_then_success(self, harness):
        """A single 'could not secure channel' failure is retried and recovers."""
        proc = harness["run"](
            self._commands(harness["src"]), ["fail_no_channel", "ok"]
        )
        assert proc.returncode == 0, proc.stderr
        assert harness["attempts"]() == 2
        assert croc_manager.CROC_SENTINEL_RETRY in proc.stdout
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout
        assert croc_manager.CROC_SENTINEL_FAILED not in proc.stdout

    def test_persistent_failure_propagates(self, harness):
        """Failure on both attempts → FAILED sentinel + non-zero exit (not a warning)."""
        proc = harness["run"](
            self._commands(harness["src"]), ["fail_no_channel"]
        )
        assert proc.returncode != 0
        assert harness["attempts"]() == 2  # exactly one retry
        assert f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=1" in proc.stdout
        assert croc_manager.CROC_SENTINEL_DONE not in proc.stdout

    def test_staging_places_file_content(self, harness):
        """The staged file (hardlink or copy) must reach croc's cwd with full content."""
        proc = harness["run"](self._commands(harness["src"]), ["ok"])
        assert proc.returncode == 0, proc.stderr
        staged = harness["control"] / "staged_1" / "_croc_dl_0_data.bin"
        assert staged.exists()
        assert staged.read_bytes() == b"hello"

    def test_timeout_scales_with_payload_size(self, harness, tmp_path):
        """A large payload must raise the croc send timeout above the floor."""
        big = tmp_path / "big.bin"
        with open(big, "wb") as f:
            f.seek(5_000_000 - 1)
            f.write(b"\0")
        posix_big = str(big).replace("\\", "/")
        commands = croc_manager.generate_croc_send_commands(
            code="c",
            file_infos=[{"remote_source_path": posix_big, "croc_filename": "_croc_dl_0_big.bin"}],
            timeout=1,  # floor of 1s so the size-scaled value must win
        )
        proc = harness["run"](commands, ["ok"])
        assert proc.returncode == 0, proc.stderr
        recorded = (harness["control"] / "timeouts.txt").read_text().split()
        # 5,000,000 bytes / 1MB-per-sec + 120s base = 125s
        assert int(recorded[0]) == 125

    def test_timeout_floor_respected_for_small_payload(self, harness):
        proc = harness["run"](self._commands(harness["src"], timeout=300), ["ok"])
        assert proc.returncode == 0, proc.stderr
        recorded = (harness["control"] / "timeouts.txt").read_text().split()
        assert int(recorded[0]) == 300

    def test_hang_after_100_percent_is_killed(self, harness, monkeypatch, tmp_path):
        """Croc stuck at 100% must be terminated after the stall grace instead of
        burning the remaining (size-scaled) timeout budget."""
        monkeypatch.setattr(croc_manager, "CROC_SEND_STALL_CHECKS", 1)
        commands = self._commands(harness["src"])
        start = time.monotonic()
        proc = harness["run"](commands, ["hang_at_100"])
        elapsed = time.monotonic() - start
        assert proc.returncode == 0, proc.stderr
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout
        assert "hang-after-transfer" in proc.stdout
        assert elapsed < 60  # far below the fake croc's 120s sleep

    def test_mid_transfer_stall_is_killed_and_retried(self, harness, monkeypatch):
        """A transfer frozen mid-flight (progress line unchanged, not at 100%)
        must be killed and RETRIED — observed live: croc froze at 87% for 25
        minutes until the whole command timed out (2026-08-03 incident)."""
        monkeypatch.setattr(croc_manager, "CROC_SEND_MIDSTALL_CHECKS", 2)
        proc = harness["run"](self._commands(harness["src"]), ["stall_mid", "ok"])
        assert proc.returncode == 0, proc.stderr
        assert harness["attempts"]() == 2
        assert croc_manager.CROC_SENTINEL_RETRY in proc.stdout
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout
        assert "stalled" in proc.stdout

    def test_mid_transfer_stall_on_both_attempts_fails(self, harness, monkeypatch):
        """Stalling on the retry too must surface as a FAILURE, not a
        whitelisted 'hang after success'."""
        monkeypatch.setattr(croc_manager, "CROC_SEND_MIDSTALL_CHECKS", 2)
        proc = harness["run"](self._commands(harness["src"]), ["stall_mid"])
        assert proc.returncode != 0
        assert harness["attempts"]() == 2
        assert croc_manager.CROC_SENTINEL_FAILED in proc.stdout
        assert croc_manager.CROC_SENTINEL_DONE not in proc.stdout

    def test_waiting_for_receiver_not_killed_as_stall(self, harness, monkeypatch):
        """Before the receiver connects the last line is 'Sending ...' (no %).
        That phase can legitimately last minutes (sentinel delivery through
        the log stream) and must NOT trip the mid-transfer stall detector."""
        monkeypatch.setattr(croc_manager, "CROC_SEND_MIDSTALL_CHECKS", 2)
        proc = harness["run"](self._commands(harness["src"]), ["wait_then_ok"])
        assert proc.returncode == 0, proc.stderr
        assert harness["attempts"]() == 1
        assert croc_manager.CROC_SENTINEL_RETRY not in proc.stdout
        assert croc_manager.CROC_SENTINEL_DONE in proc.stdout

    def test_no_files_staged_fails_fast(self, harness, tmp_path):
        """If nothing could be staged, fail immediately without invoking croc."""
        commands = croc_manager.generate_croc_send_commands(
            code="c",
            file_infos=[{
                "remote_source_path": str(tmp_path / "missing-file").replace("\\", "/"),
                "croc_filename": "_croc_dl_0_missing",
            }],
        )
        proc = harness["run"](commands, ["ok"])
        assert proc.returncode != 0
        assert croc_manager.CROC_SENTINEL_FAILED in proc.stdout
        assert harness["attempts"]() == 0


# ============================================================================
# Local receive wrapper (start_croc_receive)
# ============================================================================

FAKE_RECV_CONTROLLER = r"""
import json, os, sys, time
d = os.environ['FAKE_RECV_DIR']
cnt_f = os.path.join(d, 'count')
n = (int(open(cnt_f).read()) if os.path.exists(cnt_f) else 0) + 1
# Atomic write: the test polls this file concurrently, and a plain open('w')
# truncates first - a reader in that gap sees '' and int('') explodes
tmp_f = cnt_f + '.tmp'
with open(tmp_f, 'w') as f:
    f.write(str(n))
os.replace(tmp_f, cnt_f)
with open(os.path.join(d, 'invocations.txt'), 'a') as f:
    f.write('%r\n' % time.time())
steps = json.load(open(os.path.join(d, 'plan.json')))
step = steps[min(n, len(steps)) - 1]
for w in step.get('write', []):
    data = w['content'].encode() if 'content' in w else b'x' * w['size']
    with open(w['name'], 'wb') as f:
        f.write(data)
time.sleep(step.get('sleep', 0))
sys.exit(step.get('rc', 0))
"""


class TestReceiveWrapper:
    @pytest.fixture
    def recv(self, tmp_path, monkeypatch):
        """Fake croc executable driven by a per-attempt JSON plan."""
        control = tmp_path / "control"
        control.mkdir()
        receive_dir = tmp_path / "receive"
        receive_dir.mkdir()
        controller = control / "fake_recv.py"
        _write_text(controller, FAKE_RECV_CONTROLLER)

        if sys.platform == "win32":
            croc_path = control / "fake_croc.bat"
            _write_text(croc_path, f'@echo off\r\n"{sys.executable}" "{controller}" %*\r\n')
        else:
            croc_path = control / "fake_croc"
            _write_text(croc_path, f'#!/bin/sh\nexec "{sys.executable}" "{controller}" "$@"\n')
            os.chmod(croc_path, 0o755)

        monkeypatch.setenv("FAKE_RECV_DIR", str(control))
        monkeypatch.setattr(croc_manager, "CROC_RECEIVE_RETRY_SECONDS", 0.2)

        def set_plan(steps):
            _write_text(control / "plan.json", json.dumps(steps))

        def invocation_count():
            count_file = control / "count"
            try:
                return int(count_file.read_text()) if count_file.exists() else 0
            except (ValueError, OSError):
                # Concurrent update in flight (os.replace on Windows can
                # transiently fail the open) - report the last known floor;
                # callers poll, so the settled value arrives next round
                return 0

        def set_expected(manifest):
            """manifest: {croc_filename: {"size": bytes|None, "md5": hex|None}}"""
            _write_text(
                receive_dir / croc_manager.CROC_EXPECTED_SIZES_FILE,
                json.dumps(manifest),
            )

        def set_expected_sizes(sizes):
            set_expected({name: {"size": s, "md5": None} for name, s in sizes.items()})

        return {
            "croc_path": croc_path,
            "receive_dir": receive_dir,
            "set_plan": set_plan,
            "count": invocation_count,
            "set_expected": set_expected,
            "set_expected_sizes": set_expected_sizes,
        }

    async def _start(self, recv, gated, timeout=60):
        return await croc_manager.start_croc_receive(
            croc_path=Path(recv["croc_path"]),
            code="test-code",
            receive_dir=str(recv["receive_dir"]),
            timeout=timeout,
            gated=gated,
        )

    @pytest.mark.asyncio
    async def test_gated_receiver_waits_for_ready_signal(self, recv):
        recv["set_plan"]([{"rc": 1}])
        process = await self._start(recv, gated=True)
        try:
            # No croc attempt may happen before the ready signal appears
            await asyncio.sleep(1.5)
            assert recv["count"]() == 0
            (recv["receive_dir"] / croc_manager.CROC_READY_SIGNAL).touch()
            assert wait_until(lambda: recv["count"]() >= 1), "croc not invoked after ready signal"
        finally:
            (recv["receive_dir"] / croc_manager.CROC_ABORT_SIGNAL).touch()
            await asyncio.wait_for(process.wait(), timeout=15)

    @pytest.mark.asyncio
    async def test_abort_signal_stops_receiver_quickly(self, recv):
        recv["set_plan"]([{"rc": 1}])
        process = await self._start(recv, gated=True, timeout=600)
        (recv["receive_dir"] / croc_manager.CROC_ABORT_SIGNAL).touch()
        rc = await asyncio.wait_for(process.wait(), timeout=15)
        assert rc == 2
        assert recv["count"]() == 0

    @pytest.mark.asyncio
    async def test_ungated_receiver_starts_immediately(self, recv):
        """Legacy behavior: without gating, attempts start without a ready signal."""
        recv["set_plan"]([{"write": [{"name": "f.bin", "size": 3}], "rc": 0}])
        process = await self._start(recv, gated=False)
        rc = await asyncio.wait_for(process.wait(), timeout=15)
        assert rc == 0
        assert recv["count"]() >= 1

    @pytest.mark.asyncio
    async def test_size_match_accepts_despite_croc_error(self, recv):
        """Sender-hang-after-100%: croc exits non-zero but sizes verify → success."""
        recv["set_expected_sizes"]({"f.bin": 5})
        recv["set_plan"]([{"write": [{"name": "f.bin", "size": 5}], "rc": 1}])
        process = await self._start(recv, gated=False)
        rc = await asyncio.wait_for(process.wait(), timeout=15)
        assert rc == 0

    @pytest.mark.asyncio
    async def test_partial_file_not_accepted(self, recv):
        """A truncated file must NOT count as success; retry until sizes match."""
        recv["set_expected_sizes"]({"f.bin": 5})
        recv["set_plan"]([
            {"write": [{"name": "f.bin", "size": 3}], "rc": 1},  # partial
            {"write": [{"name": "f.bin", "size": 5}], "rc": 0},  # complete
        ])
        process = await self._start(recv, gated=False)
        rc = await asyncio.wait_for(process.wait(), timeout=30)
        assert rc == 0
        assert recv["count"]() == 2  # first (partial) attempt was not accepted
        assert (recv["receive_dir"] / "f.bin").stat().st_size == 5

    @pytest.mark.asyncio
    async def test_partial_file_with_croc_rc0_not_accepted(self, recv):
        """Even croc rc=0 must not win over a size mismatch."""
        recv["set_expected_sizes"]({"f.bin": 5})
        recv["set_plan"]([
            {"write": [{"name": "f.bin", "size": 3}], "rc": 0},
            {"write": [{"name": "f.bin", "size": 5}], "rc": 0},
        ])
        process = await self._start(recv, gated=False)
        rc = await asyncio.wait_for(process.wait(), timeout=30)
        assert rc == 0
        assert recv["count"]() == 2

    @pytest.mark.asyncio
    async def test_size_correct_but_corrupt_content_not_accepted(self, recv):
        """Croc pre-sizes its destination file, so a dead transfer can leave a
        size-correct file full of holes — the hash must gate acceptance."""
        import hashlib
        good_md5 = hashlib.md5(b"12345").hexdigest()
        recv["set_expected"]({"f.bin": {"size": 5, "md5": good_md5}})
        recv["set_plan"]([
            {"write": [{"name": "f.bin", "content": "12000"}], "rc": 0},  # size ok, corrupt
            {"write": [{"name": "f.bin", "content": "12345"}], "rc": 0},  # intact
        ])
        process = await self._start(recv, gated=False)
        rc = await asyncio.wait_for(process.wait(), timeout=30)
        assert rc == 0
        assert recv["count"]() == 2  # corrupt attempt was not accepted
        assert (recv["receive_dir"] / "f.bin").read_bytes() == b"12345"

    @pytest.mark.asyncio
    async def test_legacy_files_appeared_heuristic_without_sizes(self, recv):
        """No size info at all: files appearing still ends the loop (compat)."""
        recv["set_plan"]([{"write": [{"name": "f.bin", "size": 3}], "rc": 1}])
        process = await self._start(recv, gated=False)
        rc = await asyncio.wait_for(process.wait(), timeout=15)
        assert rc == 0

    @pytest.mark.asyncio
    async def test_cleanup_kills_in_flight_croc_and_removes_dir(self, recv):
        """cleanup_download_resources must not orphan the wrapper's croc child:
        an orphan holds the partial file open, which blocks directory deletion
        (observed live: ~58 stale torque_dl_* dirs, one with a 2.4 GB partial
        still being written 11 minutes after the CLI exited)."""
        recv["set_plan"]([{"sleep": 120, "rc": 0}])  # croc hangs mid-attempt
        process = await self._start(recv, gated=False, timeout=600)
        assert wait_until(lambda: recv["count"]() >= 1), "croc attempt never started"
        start = time.monotonic()
        await cleanup_download_resources(process, str(recv["receive_dir"]))
        elapsed = time.monotonic() - start
        assert elapsed < 15
        assert process.returncode is not None
        # Directory fully removed — only possible if the croc child (which
        # holds an open handle on the log file inside it) was killed
        assert not recv["receive_dir"].exists()

    @pytest.mark.asyncio
    async def test_receive_log_records_attempts(self, recv):
        recv["set_plan"]([{"write": [{"name": "f.bin", "size": 3}], "rc": 0}])
        process = await self._start(recv, gated=False)
        await asyncio.wait_for(process.wait(), timeout=15)
        log_file = recv["receive_dir"] / croc_manager.CROC_RECEIVE_LOG_FILE
        assert log_file.exists()
        content = log_file.read_text()
        assert "attempt 1" in content


# ============================================================================
# DownloadPlan.observe_output (sentinel watcher)
# ============================================================================

class TestObserveOutput:
    @pytest.fixture
    def plan(self, tmp_path):
        receive_dir = tmp_path / "recv"
        receive_dir.mkdir()
        return DownloadPlan(needs_download=True, croc_receive_dir=str(receive_dir))

    def _sig(self, plan, name):
        return os.path.join(plan.croc_receive_dir, name)

    def test_size_and_ready_sentinels(self, plan):
        plan.observe_output(
            f"[17:58:09.123] {croc_manager.CROC_SENTINEL_SIZE} 2398819328 _croc_dl_0_x.vmdk\n"
            f"[17:58:19.000] {croc_manager.CROC_SENTINEL_READY}\n"
        )
        assert plan.expected_sizes == {"_croc_dl_0_x.vmdk": 2398819328}
        assert plan.send_ready_seen
        assert os.path.exists(self._sig(plan, croc_manager.CROC_READY_SIGNAL))
        with open(self._sig(plan, croc_manager.CROC_EXPECTED_SIZES_FILE)) as f:
            assert json.load(f) == {"_croc_dl_0_x.vmdk": {"size": 2398819328, "md5": None}}

    def test_md5_sentinel_updates_manifest(self, plan):
        md5 = "0123456789abcdef0123456789abcdef"
        plan.observe_output(
            f"{croc_manager.CROC_SENTINEL_SIZE} 42 _croc_dl_0_x.bin\n"
            f"{croc_manager.CROC_SENTINEL_MD5} {md5.upper()} _croc_dl_0_x.bin\n"
        )
        assert plan.expected_hashes == {"_croc_dl_0_x.bin": md5}  # normalized to lowercase
        with open(self._sig(plan, croc_manager.CROC_EXPECTED_SIZES_FILE)) as f:
            assert json.load(f) == {"_croc_dl_0_x.bin": {"size": 42, "md5": md5}}

    def test_invalid_md5_ignored(self, plan):
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_MD5} not-a-hash _croc_dl_0_x.bin\n")
        assert plan.expected_hashes == {}

    def test_sentinel_split_across_chunks(self, plan):
        mid = len(croc_manager.CROC_SENTINEL_READY) // 2
        plan.observe_output(croc_manager.CROC_SENTINEL_READY[:mid])
        assert not plan.send_ready_seen
        plan.observe_output(croc_manager.CROC_SENTINEL_READY[mid:] + "\n")
        assert plan.send_ready_seen

    def test_unterminated_line_not_processed_until_newline(self, plan):
        plan.observe_output(croc_manager.CROC_SENTINEL_DONE + " exit_code=0")
        assert not plan.send_done_seen
        plan.observe_output("\n")
        assert plan.send_done_seen

    def test_retry_sentinel_clears_ready_signal(self, plan):
        plan.observe_output(croc_manager.CROC_SENTINEL_READY + "\n")
        assert os.path.exists(self._sig(plan, croc_manager.CROC_READY_SIGNAL))
        plan.observe_output(croc_manager.CROC_SENTINEL_RETRY + " (retrying)\n")
        assert not os.path.exists(self._sig(plan, croc_manager.CROC_READY_SIGNAL))

    def test_failed_sentinel_sets_abort(self, plan):
        plan.observe_output(croc_manager.CROC_SENTINEL_FAILED + " exit_code=1\n")
        assert plan.remote_failed
        assert "exit_code=1" in plan.remote_failure
        assert os.path.exists(self._sig(plan, croc_manager.CROC_ABORT_SIGNAL))

    def test_filename_with_spaces_in_size_sentinel(self, plan):
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_SIZE} 42 _croc_dl_0_my file.txt\n")
        assert plan.expected_sizes == {"_croc_dl_0_my file.txt": 42}

    def test_noise_lines_ignored(self, plan):
        plan.observe_output("Hashing _croc_dl_0... 50%\nsome random output\n")
        assert not plan.send_ready_seen
        assert not plan.remote_failed
        assert plan.expected_sizes == {}

    def test_no_receive_dir_does_not_crash(self):
        plan = DownloadPlan(needs_download=True, croc_receive_dir="")
        plan.observe_output(croc_manager.CROC_SENTINEL_READY + "\n")
        assert plan.send_ready_seen

    @pytest.mark.asyncio
    async def test_watch_callback_wraps_inner(self, plan):
        seen = []

        async def inner(content, environment_id=""):
            seen.append(content)

        cb = make_download_watch_callback(plan, inner)
        await cb(croc_manager.CROC_SENTINEL_READY + "\n", "env-1")
        assert plan.send_ready_seen
        assert seen == [croc_manager.CROC_SENTINEL_READY + "\n"]

    @pytest.mark.asyncio
    async def test_watch_callback_without_inner(self, plan):
        cb = make_download_watch_callback(plan, None)
        await cb(croc_manager.CROC_SENTINEL_READY + "\n")
        assert plan.send_ready_seen


# ============================================================================
# finalize_download size verification
# ============================================================================

class TestFinalizeSizeVerification:
    @pytest.fixture
    def dirs(self, tmp_path):
        receive_dir = tmp_path / "recv"
        receive_dir.mkdir()
        dest = tmp_path / "dest" / "out.bin"
        return receive_dir, dest

    def _plan(self, receive_dir, dest, expected_sizes, expected_hashes=None):
        return DownloadPlan(
            needs_download=True,
            croc_receive_dir=str(receive_dir),
            file_mappings=[{
                "croc_filename": "_croc_dl_0_out.bin",
                "local_destination_path": str(dest),
            }],
            expected_sizes=expected_sizes,
            expected_hashes=expected_hashes or {},
        )

    def test_size_mismatch_is_error_and_not_moved(self, dirs):
        receive_dir, dest = dirs
        (receive_dir / "_croc_dl_0_out.bin").write_bytes(b"xxx")  # 3 of 5 bytes
        plan = self._plan(receive_dir, dest, {"_croc_dl_0_out.bin": 5})
        successes, errors = finalize_download(plan)
        assert successes == []
        assert len(errors) == 1
        assert "3" in errors[0] and "5" in errors[0]
        assert not dest.exists()

    def test_size_match_moves_file(self, dirs):
        receive_dir, dest = dirs
        (receive_dir / "_croc_dl_0_out.bin").write_bytes(b"12345")
        plan = self._plan(receive_dir, dest, {"_croc_dl_0_out.bin": 5})
        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert errors == []
        assert dest.read_bytes() == b"12345"

    def test_content_corruption_is_error_and_not_moved(self, dirs):
        """Size-correct but content-wrong (croc's pre-sized holes) must be rejected."""
        import hashlib
        receive_dir, dest = dirs
        (receive_dir / "_croc_dl_0_out.bin").write_bytes(b"12000")  # right size, wrong bytes
        plan = self._plan(
            receive_dir, dest,
            {"_croc_dl_0_out.bin": 5},
            {"_croc_dl_0_out.bin": hashlib.md5(b"12345").hexdigest()},
        )
        successes, errors = finalize_download(plan)
        assert successes == []
        assert len(errors) == 1
        assert "corruption" in errors[0]
        assert not dest.exists()

    def test_content_match_moves_file(self, dirs):
        import hashlib
        receive_dir, dest = dirs
        (receive_dir / "_croc_dl_0_out.bin").write_bytes(b"12345")
        plan = self._plan(
            receive_dir, dest,
            {"_croc_dl_0_out.bin": 5},
            {"_croc_dl_0_out.bin": hashlib.md5(b"12345").hexdigest()},
        )
        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert errors == []
        assert dest.read_bytes() == b"12345"

    def test_no_size_info_keeps_old_behavior(self, dirs):
        receive_dir, dest = dirs
        (receive_dir / "_croc_dl_0_out.bin").write_bytes(b"xxx")
        plan = self._plan(receive_dir, dest, {})
        successes, errors = finalize_download(plan)
        assert len(successes) == 1
        assert errors == []

    def test_missing_file_message_names_destination(self, dirs):
        receive_dir, dest = dirs
        plan = self._plan(receive_dir, dest, {})
        successes, errors = finalize_download(plan)
        assert successes == []
        assert "not received" in errors[0]
        assert str(dest) in errors[0]


# ============================================================================
# complete_download (bounded wind-down)
# ============================================================================

class TestCompleteDownload:
    @pytest.fixture
    def receive_dir(self, tmp_path):
        d = tmp_path / "recv"
        d.mkdir()
        return d

    async def _sleeper_process(self):
        """A subprocess that would run for a long time unless aborted/killed."""
        return await asyncio.create_subprocess_exec(
            sys.executable, "-c", "import time; time.sleep(120)",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

    @pytest.mark.asyncio
    async def test_remote_failure_returns_quickly(self, receive_dir, monkeypatch):
        """Remote sender failed → no 30-minute wait; error mentions the remote failure."""
        monkeypatch.setattr(mcp_tool, "CROC_DOWNLOAD_ABORT_WAIT_SECONDS", 0.3)
        plan = DownloadPlan(
            needs_download=True,
            croc_receive_dir=str(receive_dir),
            file_mappings=[{
                "croc_filename": "_croc_dl_0_f",
                "local_destination_path": str(receive_dir / "never" / "f"),
            }],
            remote_failed=True,
            remote_failure="__CROC_DL_FAILED__ exit_code=1",
            send_ready_seen=True,
        )
        process = await self._sleeper_process()
        try:
            start = time.monotonic()
            successes, errors = await complete_download(plan, process)
            elapsed = time.monotonic() - start
            assert elapsed < 10
            assert successes == []
            assert any("remote croc send failed" in e for e in errors)
            # Abort signal must have been raised for the receiver
            assert (receive_dir / croc_manager.CROC_ABORT_SIGNAL).exists()
        finally:
            await cleanup_download_resources(process, str(receive_dir))

    @pytest.mark.asyncio
    async def test_sender_never_registered_aborts(self, receive_dir, monkeypatch):
        monkeypatch.setattr(mcp_tool, "CROC_DOWNLOAD_ABORT_WAIT_SECONDS", 0.3)
        plan = DownloadPlan(
            needs_download=True,
            croc_receive_dir=str(receive_dir),
            file_mappings=[{
                "croc_filename": "_croc_dl_0_f",
                "local_destination_path": str(receive_dir / "never" / "f"),
            }],
        )
        process = await self._sleeper_process()
        try:
            successes, errors = await complete_download(plan, process)
            assert successes == []
            assert any("never registered" in e for e in errors)
            assert (receive_dir / croc_manager.CROC_ABORT_SIGNAL).exists()
        finally:
            await cleanup_download_resources(process, str(receive_dir))

    @pytest.mark.asyncio
    async def test_successful_download_finalizes(self, receive_dir, tmp_path):
        (receive_dir / "_croc_dl_0_f").write_bytes(b"data")
        dest = tmp_path / "out" / "f"
        plan = DownloadPlan(
            needs_download=True,
            croc_receive_dir=str(receive_dir),
            file_mappings=[{
                "croc_filename": "_croc_dl_0_f",
                "local_destination_path": str(dest),
            }],
            send_ready_seen=True,
            send_done_seen=True,
        )
        # Receiver already exited cleanly
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-c", "pass",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await process.wait()
        successes, errors = await complete_download(plan, process)
        assert errors == []
        assert len(successes) == 1
        assert dest.read_bytes() == b"data"

    @pytest.mark.asyncio
    async def test_no_download_needed(self):
        successes, errors = await complete_download(None, None)
        assert successes == [] and errors == []
        successes, errors = await complete_download(DownloadPlan(), None)
        assert successes == [] and errors == []


# ============================================================================
# Versioned croc binary cache
# ============================================================================

class TestVersionedCrocCache:
    @pytest.fixture
    def cache_dir(self, tmp_path, monkeypatch):
        cache = tmp_path / "cache"
        cache.mkdir()
        monkeypatch.setattr(croc_manager, "_get_cache_dir", lambda: cache)
        monkeypatch.setattr(shutil, "which", lambda name: None)
        return cache

    def test_binary_name_includes_version(self):
        name = croc_manager._get_croc_binary_name()
        assert croc_manager.CROC_VERSION in name

    def test_versioned_cache_hit(self, cache_dir):
        cached = cache_dir / croc_manager._get_croc_binary_name()
        cached.write_bytes(b"fake-binary")
        assert croc_manager.get_local_croc_path() == cached

    def test_stale_unversioned_cache_ignored(self, cache_dir):
        """The old unversioned cache name must not be trusted after a version bump."""
        legacy_name = "croc.exe" if sys.platform == "win32" else "croc"
        (cache_dir / legacy_name).write_bytes(b"old-version-binary")
        assert croc_manager.get_local_croc_path() is None

    def test_stale_other_version_ignored_and_cleaned(self, cache_dir):
        suffix = ".exe" if sys.platform == "win32" else ""
        stale = cache_dir / f"croc-v0.0.1{suffix}"
        stale.write_bytes(b"ancient")
        assert croc_manager.get_local_croc_path() is None
        assert not stale.exists()  # stale versions are cleaned up

    def test_missing_cache_dir_ok(self, tmp_path, monkeypatch):
        monkeypatch.setattr(croc_manager, "_get_cache_dir", lambda: tmp_path / "nonexistent")
        monkeypatch.setattr(shutil, "which", lambda name: None)
        assert croc_manager.get_local_croc_path() is None
