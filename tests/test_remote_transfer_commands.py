"""The generated sender and receiver commands of a remote-to-remote transfer, run under bash.

Both sides are executed for real (WSL on Windows). `ssh` is a shell function that
runs the remote command locally, so the source and destination "machines" are local
directories; `croc` is a fake on PATH that plays a scenario per invocation. That tests
behaviour - staging, verification, retries, placement - rather than generated text.
"""

import hashlib
import io
import os
import tarfile
import time

import pytest

from _bash_harness import make_executable, needs_bash, run_script, shell_path, write_text

from torque_tunnel import croc_manager


KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----"
CODE = "the-secret-code"

# Runs the remote command locally. FAKE_SSH_CORRUPT=1 damages data piped into
# `cat > ...` (a broken hop to the destination); FAKE_SSH_NO_MD5=1 makes `md5sum`
# unavailable on the "remote" side.
FAKE_SSH_FUNC = r"""ssh() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -o|-i) shift 2 ;;
      -*) shift ;;
      *) break ;;
    esac
  done
  echo "$1" >> "$FAKE_DIR/ssh_targets.txt"
  shift
  case "$*" in
    "cat > "*) if [ "$FAKE_SSH_CORRUPT" = "1" ]; then { cat; printf 'X'; } | bash -c "$*"; return $?; fi ;;
    md5sum*) if [ "$FAKE_SSH_NO_MD5" = "1" ]; then echo "md5sum: not found" >&2; return 127; fi ;;
  esac
  bash -c "$*"
}
timeout() {
  echo "$3" >> "$FAKE_DIR/timeouts.txt"
  shift 3
  exec "$@"
}
"""

FAKE_CROC = r"""#!/bin/bash
d="$FAKE_DIR"
n=$(cat "$d/count" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$d/count"
[ -n "$CROC_SECRET" ] && echo "$CROC_SECRET" > "$d/secret_$n"
echo "$@" > "$d/args_$n"
ls -A > "$d/cwd_listing_$n.txt"
scenario=$(sed -n "${n}p" "$d/scenario.txt")
[ -z "$scenario" ] && scenario=$(tail -n 1 "$d/scenario.txt")
case "$scenario" in
  send_ok)
    mkdir -p "$d/sent_$n" && cp -r ./* "$d/sent_$n/" 2>/dev/null
    echo "Sending 2 files"
    echo "Code is: $CROC_SECRET"
    exit 0 ;;
  ok)
    cp -r "$d/payload/." .
    echo "Receiving 'x'"
    echo "x 100% |####| (5/5 B, 1 MB/s)"
    exit 0 ;;
  holes)
    for f in "$d/payload/"*; do head -c "$(stat -c %s "$f")" /dev/zero > "$(basename "$f")"; done
    echo "x 100% |####|"
    exit 0 ;;
  stall_mid)
    for f in "$d/payload/"*; do head -c 1 /dev/zero > "$(basename "$f")"; done
    echo "x  50% |##  | (1/2 B)"
    exec sleep 300 ;;
  hang_at_100)
    cp -r "$d/payload/." .
    echo "x 100% |####|"
    exec sleep 300 ;;
  rate_limited)
    echo "could not connect to croc.schollz.com:9009: got bad response: rate limited"
    exit 1 ;;
  fail)
    echo "could not secure channel"
    exit 1 ;;
esac
exit 3
"""


def _posix(path) -> str:
    return shell_path(path)


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


@pytest.fixture
def harness(tmp_path, monkeypatch):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    control = tmp_path / "control"
    (control / "payload").mkdir(parents=True)
    make_executable(fake_bin / "croc", FAKE_CROC)

    # Both monitors' ticks (production 0.5 s): the same check counts, decided sooner
    monkeypatch.setattr(croc_manager, "RELAY_MONITOR_TICK_SECONDS", 0.025)
    monkeypatch.setattr(croc_manager, "CROC_SEND_MONITOR_TICK_SECONDS", 0.025)
    monkeypatch.setattr(croc_manager, "CROC_RECEIVE_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(croc_manager, "CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS", (0, 0, 0))
    monkeypatch.setattr(croc_manager, "CROC_SEND_RETRY_DELAY_SECONDS", 0)

    def run(commands, scenarios, **env_extra):
        write_text(control / "scenario.txt", "\n".join(scenarios) + "\n")
        script = tmp_path / "under_test.sh"
        write_text(script, FAKE_SSH_FUNC + commands + "\n")
        # The secrets arrive as the grain's env-vars deliver them
        secrets = {croc_manager.SSH_PRIVATE_KEY_ENV: KEY, croc_manager.AUX_SSH_PRIVATE_KEY_ENV: KEY,
                   croc_manager.CROC_RECEIVE_CODE_ENV: CODE, croc_manager.CROC_SEND_CODE_ENV: CODE}
        return run_script(script, env={"FAKE_DIR": control, **secrets, **env_extra},
                          prepend_path=[fake_bin])

    def attempts():
        f = control / "count"
        return int(f.read_text()) if f.exists() else 0

    def payload(name, data: bytes):
        (control / "payload" / name).write_bytes(data)

    return {"run": run, "attempts": attempts, "payload": payload, "control": control,
            "bin": fake_bin}


def _receive(manifest, **kw):
    return croc_manager.generate_croc_relay_receive_commands(
        manifest=manifest, target_ip="dst-host", ssh_user="root", **kw)


def _file_entry(name, data, dest, **extra):
    return {"croc_filename": name, "size": len(data), "md5": _md5(data),
            "is_dir": False, "destination_path": _posix(dest), **extra}


# ============================================================================
# Sender: stage from the source, then the monitored croc send
# ============================================================================

@needs_bash
class TestSender:
    def _send(self, file_infos, **kw):
        return croc_manager.generate_croc_relay_send_commands(
            file_infos=file_infos, target_ip="src-host", ssh_user="root", **kw)

    def test_stages_a_file_and_reports_its_size_and_hash(self, harness, tmp_path):
        src = tmp_path / "source" / "image.vmdk"
        src.parent.mkdir()
        src.write_bytes(b"vmdk-bytes")
        proc = harness["run"](self._send([
            {"source_path": _posix(src), "croc_filename": "_croc_rl_0_image.vmdk"}]), ["send_ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        sent = harness["control"] / "sent_1" / "_croc_rl_0_image.vmdk"
        assert sent.read_bytes() == b"vmdk-bytes"
        assert f"{croc_manager.CROC_SENTINEL_SIZE} 10 _croc_rl_0_image.vmdk" in proc.stdout
        assert f"{croc_manager.CROC_SENTINEL_MD5} {_md5(b'vmdk-bytes')} _croc_rl_0_image.vmdk" in proc.stdout
        assert croc_manager.CROC_SENTINEL_READY in proc.stdout
        assert croc_manager.CROC_SENTINEL_DIR not in proc.stdout
        assert "src-host" in (harness["control"] / "ssh_targets.txt").read_text()

    def test_a_directory_is_sent_as_a_hashed_tarball(self, harness, tmp_path):
        src = tmp_path / "source dir"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_bytes(b"A")
        (src / "sub" / "b.txt").write_bytes(b"B")
        proc = harness["run"](self._send([
            {"source_path": _posix(src), "croc_filename": "_croc_rl_0_dir"}]), ["send_ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert f"{croc_manager.CROC_SENTINEL_DIR} _croc_rl_0_dir" in proc.stdout
        assert f"{croc_manager.CROC_SENTINEL_MD5} " in proc.stdout
        staged = (harness["control"] / "sent_1" / "_croc_rl_0_dir").read_bytes()
        with tarfile.open(fileobj=io.BytesIO(staged), mode="r:gz") as tar:
            names = {os.path.normpath(n) for n in tar.getnames()}
        assert {"a.txt", os.path.join("sub", "b.txt")} <= names

    def test_a_missing_source_fails_at_once_without_croc(self, harness, tmp_path):
        proc = harness["run"](self._send([
            {"source_path": _posix(tmp_path / "nope.bin"), "croc_filename": "_croc_rl_0_nope.bin"}]),
            ["send_ok"])

        assert proc.returncode != 0
        assert f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=stage reason=could not read" in proc.stdout
        assert "nope.bin" in proc.stdout
        assert harness["attempts"]() == 0
        assert croc_manager.CROC_SENTINEL_READY not in proc.stdout

    def test_the_send_timeout_leaves_room_for_the_receiver_to_start(self, harness, tmp_path):
        src = tmp_path / "small.bin"
        src.write_bytes(b"x")
        proc = harness["run"](self._send([
            {"source_path": _posix(src), "croc_filename": "_croc_rl_0_small.bin"}]), ["send_ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        recorded = int((harness["control"] / "timeouts.txt").read_text().split()[0])
        assert recorded >= 300 + croc_manager.RELAY_RECEIVER_LAUNCH_BUDGET_SECONDS

    def test_the_code_never_reaches_the_output(self, harness, tmp_path):
        src = tmp_path / "f.bin"
        src.write_bytes(b"x")
        proc = harness["run"](self._send([
            {"source_path": _posix(src), "croc_filename": "_croc_rl_0_f.bin"}]), ["send_ok"])
        assert "the-secret-code" not in proc.stdout + proc.stderr


# ============================================================================
# Receiver: monitored croc receive, verify, place on the destination
# ============================================================================

@needs_bash
class TestReceiver:
    def test_received_file_is_verified_and_placed(self, harness, tmp_path):
        data = b"payload-bytes"
        harness["payload"]("_croc_rl_0_f.bin", data)
        dest = tmp_path / "dest" / "deep" / "f.bin"
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f.bin", data, dest)]), ["ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert dest.read_bytes() == data
        assert not (dest.parent / "f.bin.tt-partial").exists()
        assert f"{croc_manager.CROC_RX_SENTINEL_PLACED} {_posix(dest)}" in proc.stdout
        assert croc_manager.CROC_RX_SENTINEL_DONE in proc.stdout
        assert harness["attempts"]() == 1
        assert "dst-host" in (harness["control"] / "ssh_targets.txt").read_text()

    def test_a_directory_tarball_is_extracted_at_the_destination(self, harness, tmp_path):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for name, content in (("a.txt", b"A"), ("sub/b.txt", b"B")):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        data = buf.getvalue()
        harness["payload"]("_croc_rl_0_dir", data)
        dest = tmp_path / "out dir"
        entry = dict(_file_entry("_croc_rl_0_dir", data, dest), is_dir=True)
        proc = harness["run"](_receive([entry]), ["ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert (dest / "a.txt").read_bytes() == b"A"
        assert (dest / "sub" / "b.txt").read_bytes() == b"B"

    def test_paths_with_spaces_and_quotes_are_placed_exactly(self, harness, tmp_path):
        data = b"q"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "it's a dir" / "na me's.bin"
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert dest.read_bytes() == data

    def test_a_size_correct_file_full_of_holes_is_retried_then_rejected(self, harness, tmp_path):
        data = b"real-content"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "dest" / "f"
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["holes"])

        assert proc.returncode != 0
        assert harness["attempts"]() == 2  # exactly one retry
        assert f"{croc_manager.CROC_RX_SENTINEL_FAILED} " in proc.stdout
        assert "corrupt" in proc.stdout
        assert not dest.exists()
        assert croc_manager.CROC_RX_SENTINEL_DONE not in proc.stdout

    def test_one_bad_attempt_then_a_good_one_succeeds(self, harness, tmp_path):
        data = b"real-content"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "dest" / "f"
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["fail", "ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert harness["attempts"]() == 2
        assert dest.read_bytes() == data

    def test_a_transfer_frozen_mid_flight_is_killed_and_retried(self, harness, monkeypatch, tmp_path):
        monkeypatch.setattr(croc_manager, "CROC_RECEIVE_MIDSTALL_CHECKS", 2)
        data = b"real-content"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "dest" / "f"
        start = time.monotonic()
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["stall_mid", "ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert time.monotonic() - start < 60
        assert "stalled" in proc.stdout
        assert harness["attempts"]() == 2
        assert dest.read_bytes() == data

    def test_croc_hanging_at_100_percent_with_complete_files_is_a_success(self, harness, monkeypatch, tmp_path):
        monkeypatch.setattr(croc_manager, "CROC_RECEIVE_STALL_CHECKS", 1)
        data = b"real-content"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "dest" / "f"
        start = time.monotonic()
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["hang_at_100"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert time.monotonic() - start < 60
        assert harness["attempts"]() == 1
        assert dest.read_bytes() == data

    def test_rate_limit_rejections_are_retried_with_backoff(self, harness, tmp_path):
        data = b"real-content"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "dest" / "f"
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]),
                              ["rate_limited", "rate_limited", "ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert proc.stdout.count("rate-limited") == 2
        assert dest.read_bytes() == data

    def test_a_corrupted_copy_to_the_destination_never_reaches_the_path(self, harness, tmp_path):
        data = b"real-content"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "dest" / "f"
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["ok"],
                              FAKE_SSH_CORRUPT="1")

        assert proc.returncode != 0
        assert "content corruption copying to" in proc.stdout
        assert not dest.exists()
        assert not (dest.parent / "f.tt-partial").exists()

    def test_no_md5sum_on_the_destination_is_a_warning_not_a_failure(self, harness, tmp_path):
        data = b"real-content"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "dest" / "f"
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["ok"],
                              FAKE_SSH_NO_MD5="1")

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "WARNING: md5sum is not available on the destination" in proc.stdout
        assert dest.read_bytes() == data

    def test_an_existing_directory_at_the_destination_path_is_refused(self, harness, tmp_path):
        """mv would otherwise drop the copy INTO it under its temporary name."""
        data = b"x"
        harness["payload"]("_croc_rl_0_f", data)
        dest = tmp_path / "already a dir"
        dest.mkdir()
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, dest)]), ["ok"])

        assert proc.returncode != 0
        assert "existing directory" in proc.stdout + proc.stderr
        assert list(dest.iterdir()) == []
        assert not (tmp_path / "already a dir.tt-partial").exists()

    def test_several_files_all_have_to_arrive(self, harness, tmp_path):
        a, b = b"first", b"second"
        harness["payload"]("_croc_rl_0_a", a)
        harness["payload"]("_croc_rl_1_b", b)
        da, db = tmp_path / "d" / "a", tmp_path / "d" / "b"
        proc = harness["run"](_receive([
            _file_entry("_croc_rl_0_a", a, da), _file_entry("_croc_rl_1_b", b, db)]), ["ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert da.read_bytes() == a and db.read_bytes() == b
        assert proc.stdout.count(croc_manager.CROC_RX_SENTINEL_PLACED) == 2

    def test_the_relay_is_named_and_the_code_comes_through_the_environment(self, harness, tmp_path):
        data = b"x"
        harness["payload"]("_croc_rl_0_f", data)
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, tmp_path / "f")],
                                       relay="relay.example:9009"), ["ok"])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        args = (harness["control"] / "args_1").read_text()
        assert "--relay relay.example:9009" in args
        assert "the-secret-code" not in args
        assert (harness["control"] / "secret_1").read_text().strip() == "the-secret-code"
        assert "the-secret-code" not in proc.stdout + proc.stderr

    def test_failure_reason_is_extracted_like_an_upload_error(self, harness, tmp_path):
        """The receive failure line uses the upload wording, so the existing extractor
        reports it with croc's reason."""
        from torque_tunnel import mcp_tool
        data = b"x"
        harness["payload"]("_croc_rl_0_f", data)
        proc = harness["run"](_receive([_file_entry("_croc_rl_0_f", data, tmp_path / "f")]), ["fail"])

        errors = mcp_tool.extract_transfer_errors(proc.stderr)
        assert errors and "could not secure channel" in errors[0], proc.stderr


# ============================================================================
# Direct copy: both endpoints behind one agent, ssh to ssh, no croc
# ============================================================================

@needs_bash
class TestDirectCopy:
    def _copy(self, files):
        return croc_manager.generate_direct_copy_commands(
            files,
            {"target_ip": "src-host", "ssh_user": "root"},
            {"target_ip": "dst-host", "ssh_user": "root"})

    def test_a_file_is_copied_verified_and_placed(self, harness, tmp_path):
        src = tmp_path / "src" / "image.vmdk"
        src.parent.mkdir()
        src.write_bytes(b"vmdk-bytes")
        dest = tmp_path / "dst" / "deep" / "image.vmdk"
        proc = harness["run"](self._copy([{"source_path": _posix(src), "destination_path": _posix(dest)}]), [])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert dest.read_bytes() == b"vmdk-bytes"
        assert not (dest.parent / "image.vmdk.tt-partial").exists()
        assert f"{croc_manager.CROC_RX_SENTINEL_PLACED} {_posix(dest)}" in proc.stdout
        assert croc_manager.CROC_RX_SENTINEL_DONE in proc.stdout
        assert harness["attempts"]() == 0  # croc never ran
        targets = (harness["control"] / "ssh_targets.txt").read_text()
        assert "src-host" in targets and "dst-host" in targets

    def test_passwords_of_both_machines_reach_sshpass_through_the_environment(self, harness, tmp_path):
        """The destination's password is the environment's own, the source's the
        second machine's; sshpass reads each from SSHPASS, never from its arguments."""
        control = harness["control"]
        write_text(control / "ssh_func.sh", FAKE_SSH_FUNC)
        make_executable(harness["bin"] / "sshpass", r"""#!/bin/bash
echo "argv: $*" >> "$FAKE_DIR/sshpass_calls"
echo "SSHPASS=$SSHPASS" >> "$FAKE_DIR/sshpass_calls"
. "$FAKE_DIR/ssh_func.sh"
shift  # -e
"$@"
""")
        src = tmp_path / "src" / "f"
        src.parent.mkdir()
        src.write_bytes(b"data")
        dest = tmp_path / "dst" / "f"
        no_keys = {croc_manager.SSH_PRIVATE_KEY_ENV: "", croc_manager.AUX_SSH_PRIVATE_KEY_ENV: ""}
        proc = harness["run"](
            self._copy([{"source_path": _posix(src), "destination_path": _posix(dest)}]), [],
            **no_keys, **{croc_manager.SSH_PASSWORD_ENV: "dst-password-1",
                          croc_manager.AUX_SSH_PASSWORD_ENV: "src-password-2"})

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert dest.read_bytes() == b"data"
        calls = (control / "sshpass_calls").read_text()
        assert "SSHPASS=dst-password-1" in calls and "SSHPASS=src-password-2" in calls
        argv = "\n".join(l for l in calls.splitlines() if l.startswith("argv:"))
        assert "PubkeyAuthentication=no" in argv
        assert "dst-password-1" not in argv and "src-password-2" not in argv

    def test_a_directory_is_copied(self, harness, tmp_path):
        src = tmp_path / "src dir"
        (src / "sub").mkdir(parents=True)
        (src / "a.txt").write_bytes(b"A")
        (src / "sub" / "b.txt").write_bytes(b"B")
        dest = tmp_path / "it's here"
        proc = harness["run"](self._copy([{"source_path": _posix(src), "destination_path": _posix(dest)}]), [])

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert (dest / "a.txt").read_bytes() == b"A"
        assert (dest / "sub" / "b.txt").read_bytes() == b"B"

    def test_a_missing_source_fails_and_leaves_nothing(self, harness, tmp_path):
        dest = tmp_path / "dst" / "f"
        proc = harness["run"](self._copy([{"source_path": _posix(tmp_path / "nope"),
                                           "destination_path": _posix(dest)}]), [])

        assert proc.returncode != 0
        assert f"{croc_manager.CROC_RX_SENTINEL_FAILED} " in proc.stdout
        assert croc_manager.CROC_RX_SENTINEL_DONE not in proc.stdout
        assert not dest.exists()
        assert not (dest.parent / "f.tt-partial").exists()

    def test_a_corrupted_copy_never_reaches_the_path(self, harness, tmp_path):
        src = tmp_path / "f"
        src.write_bytes(b"real")
        dest = tmp_path / "dst" / "f"
        proc = harness["run"](self._copy([{"source_path": _posix(src), "destination_path": _posix(dest)}]), [],
                              FAKE_SSH_CORRUPT="1")

        assert proc.returncode != 0
        assert "content corruption" in proc.stdout
        assert not dest.exists()
        assert not (dest.parent / "f.tt-partial").exists()

    def test_no_md5sum_is_a_warning(self, harness, tmp_path):
        src = tmp_path / "f"
        src.write_bytes(b"real")
        dest = tmp_path / "dst" / "f"
        proc = harness["run"](self._copy([{"source_path": _posix(src), "destination_path": _posix(dest)}]), [],
                              FAKE_SSH_NO_MD5="1")

        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "was not verified" in proc.stdout
        assert dest.read_bytes() == b"real"

    def test_finishes_promptly_despite_the_heartbeat(self, harness, tmp_path):
        """The heartbeat loop must not keep the script (and the grain) waiting."""
        src = tmp_path / "f"
        src.write_bytes(b"x")
        start = time.monotonic()
        proc = harness["run"](self._copy([{"source_path": _posix(src),
                                           "destination_path": _posix(tmp_path / "d" / "f")}]), [])
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert time.monotonic() - start < 20
