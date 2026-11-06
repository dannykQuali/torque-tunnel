"""Regression tests for the croc relay rate-limit failure.

Background (investigated 2026-09-17): ``upload_files`` with a file above the
inline threshold failed with

    Error starting croc file transfer: croc send exited immediately with code 1

and nothing else. The real reason was only visible once croc's own output was
captured instead of being sent to DEVNULL::

    could not connect to 142.132.189.179:9009: got bad response: rate limited

The public relay enforces an admission limiter keyed on the sender's exact
public IP (30 room joins per rolling minute). Each ``croc send`` costs roughly
four admissions, so one IP sustains only ~7-8 transfers per minute before the
relay rejects the next one and croc exits 1.

These tests lock in the three things that were missing: croc's output reaches
the caller, a rate-limited send is retried with backoff instead of failing, and
the relay is configurable so a private relay can sidestep the shared budget.
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager


RATE_LIMIT_OUTPUT = (
    b"could not connect to 142.132.189.179:9009: got bad response: rate limited\n"
)


def _fake_croc(returncode, output=b""):
    """Build a create_subprocess_exec side effect that behaves like one croc run.

    Writes ``output`` to whatever file object the caller passed as stdout — the
    same way the real croc writes to the log handle it inherits — then reports
    ``returncode``.
    """
    def run(*args, **kwargs):
        stream = kwargs.get("stdout")
        if output and hasattr(stream, "write"):
            stream.write(output)
            stream.flush()
        proc = mock.AsyncMock()
        proc.returncode = returncode
        return proc
    return run


def _sequence(*runs):
    """Chain several _fake_croc behaviours across consecutive spawns."""
    calls = list(runs)

    def run(*args, **kwargs):
        behaviour = calls.pop(0) if calls else calls_last[0]
        calls_last[0] = behaviour
        return behaviour(*args, **kwargs)

    calls_last = [runs[-1]]
    return run


async def _send(**overrides):
    kwargs = dict(
        croc_path=Path("/usr/bin/croc"),
        code="test-secret",
        files=["file1.txt"],
    )
    kwargs.update(overrides)
    # Keep these unit tests off the real resolver (covered in test_croc_relay_resolution)
    with mock.patch.object(croc_manager, "warm_dns_cache"):
        return await croc_manager.start_croc_send(**kwargs)


# ============================================================================
# croc's own output must reach the caller
# ============================================================================

class TestCrocSendOutputSurfacing:
    @pytest.mark.asyncio
    async def test_error_includes_croc_output(self):
        """The reason croc failed must be in the exception, not just the exit code."""
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(1, RATE_LIMIT_OUTPUT)), \
             mock.patch("asyncio.sleep"):
            with pytest.raises(RuntimeError) as exc:
                await _send()

        message = str(exc.value)
        assert "rate limited" in message
        assert "142.132.189.179:9009" in message
        # The exit code stays in the message; it just isn't the whole message.
        assert "1" in message

    @pytest.mark.asyncio
    async def test_error_never_leaks_the_transfer_code(self):
        """croc prints the PAKE secret on startup; it must not reach the caller.

        The remote-side send wrapper already strips these lines from the streamed
        grain log. The local error path has to do the same, or a failure would
        publish the transfer code into the conversation.
        """
        secret = "S3CR3T-cr0c-c0de-do-not-leak"
        noisy = (
            f"Code is: {secret}\n"
            "On the other computer run:\n"
            "(For Windows)\n"
            f"    croc {secret}\n"
            "(For Linux/macOS)\n"
            f'    CROC_SECRET="{secret}" croc \n'
            "Code copied to clipboard!\n"
        ).encode() + RATE_LIMIT_OUTPUT

        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(1, noisy)), \
             mock.patch("asyncio.sleep"):
            with pytest.raises(RuntimeError) as exc:
                await _send(code=secret)

        message = str(exc.value)
        assert secret not in message
        assert "CROC_SECRET" not in message
        # ...but the actual error still comes through
        assert "rate limited" in message

    @pytest.mark.asyncio
    async def test_progress_bars_are_stripped_from_the_error(self):
        """croc redraws progress with box-drawing glyphs; they add nothing to
        an error, and a legacy console codepage cannot even encode them.
        """
        cr, nl, bar = chr(13), chr(10), chr(0x2588) * 8
        noisy = (
            "Sending 'payload.bin' (1.0 MB)" + cr
            + f"payload... 65% |{bar}  | (655 kB/1.0 MB, 967 kB/s) [0s:0s]" + cr
            + f"payload... 100% |{bar}| (1.0/1.0 MB)" + nl
        ).encode() + RATE_LIMIT_OUTPUT

        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(1, noisy)), \
             mock.patch("asyncio.sleep"):
            with pytest.raises(RuntimeError) as exc:
                await _send()

        message = str(exc.value)
        assert "rate limited" in message
        assert message.isascii(), "error text must survive a legacy console codepage"
        assert "%" not in message, "a progress bar is not a diagnostic"

    @pytest.mark.asyncio
    async def test_silent_failure_still_reports_exit_code(self):
        """No output from croc must not produce an empty or broken message."""
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(2, b"")), \
             mock.patch("asyncio.sleep"):
            with pytest.raises(RuntimeError, match="croc send exited immediately with code 2"):
                await _send()


# ============================================================================
# Rate-limited sends must be retried, other failures must not
# ============================================================================

class TestCrocSendRateLimitRetry:
    @pytest.mark.asyncio
    async def test_retries_after_rate_limit_and_succeeds(self):
        runs = _sequence(
            _fake_croc(1, RATE_LIMIT_OUTPUT),   # relay rejected us
            _fake_croc(None),                   # window cleared; croc is running
        )
        with mock.patch("asyncio.create_subprocess_exec", side_effect=runs) as mock_exec, \
             mock.patch("asyncio.sleep") as mock_sleep:
            process = await _send()

        assert process is not None
        assert mock_exec.call_count == 2, "a rate-limited send must be retried"

        slept = [c.args[0] for c in mock_sleep.await_args_list if c.args]
        assert croc_manager.CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS[0] in slept, \
            "the retry must back off — hammering the relay burns more admissions"

    @pytest.mark.asyncio
    async def test_does_not_retry_other_failures(self):
        """A missing file or bad flag will fail identically every time."""
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(1, b"no such file or directory\n")) as mock_exec, \
             mock.patch("asyncio.sleep"):
            with pytest.raises(RuntimeError):
                await _send()

        assert mock_exec.call_count == 1

    @pytest.mark.asyncio
    async def test_gives_up_after_the_configured_attempts(self):
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(1, RATE_LIMIT_OUTPUT)) as mock_exec, \
             mock.patch("asyncio.sleep"):
            with pytest.raises(RuntimeError) as exc:
                await _send()

        expected = len(croc_manager.CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS) + 1
        assert mock_exec.call_count == expected
        # The caller should be told what to do about a persistent rate limit.
        assert "relay" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_backoff_grows(self):
        """Successive waits must not all be the same short delay."""
        backoff = croc_manager.CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS
        assert len(backoff) >= 2
        assert list(backoff) == sorted(backoff)
        assert backoff[-1] >= 60, (
            "the relay's window is a rolling minute; the last wait should outlast it"
        )


# ============================================================================
# The capture file must not be left behind
# ============================================================================

class TestCrocSendLogLifecycle:
    @pytest.mark.asyncio
    async def test_log_file_removed_when_send_fails(self):
        captured = {}

        def run(*args, **kwargs):
            captured["stdout"] = kwargs.get("stdout")
            proc = mock.AsyncMock()
            proc.returncode = 1
            return proc

        with mock.patch("asyncio.create_subprocess_exec", side_effect=run), \
             mock.patch("asyncio.sleep"):
            with pytest.raises(RuntimeError):
                await _send()

        log_path = captured["stdout"].name
        assert not os.path.exists(log_path), "failed send left its capture file behind"

    @pytest.mark.asyncio
    async def test_log_file_removed_by_cleanup_after_success(self):
        captured = {}

        def run(*args, **kwargs):
            captured["stdout"] = kwargs.get("stdout")
            proc = mock.AsyncMock()
            proc.returncode = None
            return proc

        with mock.patch("asyncio.create_subprocess_exec", side_effect=run), \
             mock.patch("asyncio.sleep"):
            process = await _send()

        log_path = captured["stdout"].name
        assert os.path.exists(log_path), "the log must survive while croc is running"

        process.returncode = 0  # croc finished on its own
        await croc_manager.cleanup_croc_send(process)
        assert not os.path.exists(log_path)

    @pytest.mark.asyncio
    async def test_cleanup_tolerates_a_process_it_did_not_start(self):
        """cleanup_croc_send is called on plain mocks elsewhere; it must not explode."""
        await croc_manager.cleanup_croc_send(None)
        proc = mock.AsyncMock()
        proc.returncode = 0
        await croc_manager.cleanup_croc_send(proc)


# ============================================================================
# Relay configuration (local send)
# ============================================================================

class TestLocalSendRelayOptions:
    @pytest.mark.asyncio
    async def test_relay_flag_precedes_the_send_subcommand(self):
        """--relay is a croc GLOBAL option; after 'send' croc rejects it."""
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(None)) as mock_exec, \
             mock.patch("asyncio.sleep"):
            await _send(relay="relay.internal:9009")

        argv = list(mock_exec.call_args[0])
        assert "--relay" in argv
        assert argv[argv.index("--relay") + 1] == "relay.internal:9009"
        assert argv.index("--relay") < argv.index("send")

    @pytest.mark.asyncio
    async def test_relay_password_goes_through_the_environment(self):
        """--pass on the command line would expose it in the process list."""
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(None)) as mock_exec, \
             mock.patch("asyncio.sleep"):
            await _send(relay="relay.internal:9009", relay_password="s3kr1t")

        argv = list(mock_exec.call_args[0])
        assert "--pass" not in argv
        assert "s3kr1t" not in argv
        assert mock_exec.call_args[1]["env"]["CROC_PASS"] == "s3kr1t"

    @pytest.mark.asyncio
    async def test_unconfigured_relay_means_the_public_hostname_and_no_password(self):
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(None)) as mock_exec, \
             mock.patch("asyncio.sleep"):
            await _send()

        argv = list(mock_exec.call_args[0])
        assert argv[argv.index("--relay") + 1] == croc_manager.DEFAULT_CROC_RELAY
        assert "CROC_PASS" not in mock_exec.call_args[1]["env"]

    @pytest.mark.asyncio
    async def test_transfers_flag_follows_the_send_subcommand(self):
        """--transfers is a 'croc send' option, and each stream costs an admission."""
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(None)) as mock_exec, \
             mock.patch("asyncio.sleep"):
            await _send(transfers=1)

        argv = list(mock_exec.call_args[0])
        assert argv[argv.index("--transfers") + 1] == "1"
        assert argv.index("send") < argv.index("--transfers")

    @pytest.mark.asyncio
    async def test_transfers_omitted_when_unset(self):
        with mock.patch("asyncio.create_subprocess_exec",
                        side_effect=_fake_croc(None)) as mock_exec, \
             mock.patch("asyncio.sleep"):
            await _send()

        assert "--transfers" not in list(mock_exec.call_args[0])


# ============================================================================
# Relay configuration (generated remote commands)
# ============================================================================

class TestRemoteRelayOptions:
    def test_receive_commands_carry_the_relay(self):
        script = croc_manager.generate_croc_receive_commands(
            file_transfers=[{"croc_filename": "f", "remote_destination_path": "/tmp/f"}],
            relay="relay.internal:9009",
        )
        assert "--relay relay.internal:9009" in script
        # The password from the environment (a sensitive input), when it has one
        assert f'export CROC_PASS="${croc_manager.CROC_RELAY_PASSWORD_ENV}"' in script
        # Global options must precede the (implicit) receive, i.e. right after `croc`
        assert "croc --relay" in script

    def test_receive_commands_use_the_public_relay_without_a_password(self):
        script = croc_manager.generate_croc_receive_commands(
            file_transfers=[{"croc_filename": "f", "remote_destination_path": "/tmp/f"}],
        )
        assert f"--relay {croc_manager.DEFAULT_CROC_RELAY}" in script
        # CROC_PASS is set only when the environment holds a password
        assert f'if [ -n "${{{croc_manager.CROC_RELAY_PASSWORD_ENV}:-}}" ]; then export CROC_PASS' in script

    def test_scp_commands_carry_the_relay(self):
        script = croc_manager.generate_croc_scp_commands(
            file_transfers=[{"croc_filename": "f", "remote_destination_path": "/tmp/f"}],
            target_ip="10.0.0.1",
            ssh_user="root",
            relay="relay.internal:9009",
        )
        assert "--relay relay.internal:9009" in script
        assert f'export CROC_PASS="${croc_manager.CROC_RELAY_PASSWORD_ENV}"' in script

    def test_remote_send_commands_carry_the_relay(self):
        script = croc_manager.generate_croc_send_commands(
            file_infos=[{"remote_source_path": "/tmp/f", "croc_filename": "f"}],
            relay="relay.internal:9009",
            transfers=2,
        )
        # croc send: global options first, subcommand options after
        assert "croc --relay relay.internal:9009 send" in script
        assert "--transfers 2" in script

    def test_remote_send_commands_use_the_public_relay_and_default_streams(self):
        script = croc_manager.generate_croc_send_commands(
            file_infos=[{"remote_source_path": "/tmp/f", "croc_filename": "f"}],
        )
        assert f"croc --relay {croc_manager.DEFAULT_CROC_RELAY} send --no-local" in script
        assert "--transfers" not in script

    @pytest.mark.asyncio
    async def test_local_receive_uses_the_relay(self):
        with mock.patch("asyncio.create_subprocess_exec") as mock_exec, \
             mock.patch("asyncio.sleep"):
            proc = mock.AsyncMock()
            proc.returncode = None
            mock_exec.return_value = proc

            await croc_manager.start_croc_receive(
                croc_path=Path("/usr/bin/croc"),
                code="abc",
                receive_dir=os.getcwd(),
                relay="relay.internal:9009",
                relay_password="s3kr1t",
            )

        script = mock_exec.call_args[0][2]
        assert "relay.internal:9009" in script
        assert "s3kr1t" in script


# ============================================================================
# Documented constants
# ============================================================================

class TestRateLimitConstants:
    def test_marker_matches_the_relay_wire_string(self):
        """croc's relay answers with this literal (src/tcp/tcp.go sendAdmission)."""
        assert croc_manager.CROC_RATE_LIMIT_MARKER == "rate limited"
        assert croc_manager.CROC_RATE_LIMIT_MARKER in RATE_LIMIT_OUTPUT.decode()

    def test_output_tail_is_bounded(self):
        """croc's progress output is unbounded; the captured tail must not be."""
        assert 0 < croc_manager.CROC_OUTPUT_TAIL_BYTES <= 64 * 1024


# ============================================================================
# The receiving side must survive a rate limit too (shell-level, under bash)
# ============================================================================

from _bash_harness import needs_bash, run_script

# `timeout` is a shell function, so the test does not depend on the real one (the
# generated script calls it in a pipeline). No `exec`: the caller is a { ...; } group
# that must keep going.
FAKE_TIMEOUT_FUNC = r"""timeout() {
  shift 1
  "$@"
}
"""

FAKE_CROC_RECEIVE = r"""#!/bin/bash
# Fake croc receive. One scenario line per invocation, from scenario.txt:
#   rate_limited - the relay's admission limiter rejected the join
#   other_fail   - any non-retryable failure
#   ok           - receives the file
d="$FAKE_CROC_DIR"
printf '%s' "$CROC_SECRET" > "$d/secret"
n=$(cat "$d/count" 2>/dev/null || echo 0)
n=$((n+1)); echo "$n" > "$d/count"
scenario=$(sed -n "${n}p" "$d/scenario.txt")
[ -z "$scenario" ] && scenario=$(tail -n 1 "$d/scenario.txt")
case "$scenario" in
  rate_limited)
    echo "could not connect to 142.132.189.179:9009: got bad response: rate limited"
    exit 1
    ;;
  other_fail)
    echo "could not secure channel"
    exit 1
    ;;
  ok)
    echo "Receiving 'payload.bin' (5 B)"
    echo "payload" > payload.bin
    exit 0
    ;;
esac
exit 9
"""


@needs_bash
class TestReceiveRetryBehaviour:
    @pytest.fixture
    def harness(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        workdir = tmp_path / "work"
        workdir.mkdir()

        croc = fake_bin / "croc"
        croc.write_text(FAKE_CROC_RECEIVE, encoding="utf-8", newline="\n")
        os.chmod(croc, 0o755)

        # Don't actually wait out the relay's window in a unit test.
        monkeypatch.setattr(
            croc_manager, "CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS", (0, 0, 0))

        def run(scenarios, relay=""):
            (control / "scenario.txt").write_text(
                "\n".join(scenarios) + "\n", encoding="utf-8", newline="\n")
            lines = croc_manager.generate_croc_receive_attempt(timeout=30, relay=relay)
            script = tmp_path / "under_test.sh"
            body = FAKE_TIMEOUT_FUNC + "\n".join(lines) + '\necho "RC=$__CROC_RC"\n'
            script.write_text(body, encoding="utf-8", newline="\n")
            # The code arrives as the grain's env-vars deliver it
            return run_script(script, env={"FAKE_CROC_DIR": control,
                                           croc_manager.CROC_RECEIVE_CODE_ENV: "test-code"},
                              prepend_path=[fake_bin], cwd=workdir)

        def attempts():
            f = control / "count"
            return int(f.read_text()) if f.exists() else 0

        return {"run": run, "attempts": attempts, "workdir": workdir}

    def test_succeeds_first_time_without_retrying(self, harness):
        proc = harness["run"](["ok"])
        assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
        assert harness["attempts"]() == 1

    def test_croc_gets_the_code_from_the_environment(self, harness, tmp_path):
        harness["run"](["ok"])
        assert (tmp_path / "control" / "secret").read_text() == "test-code"

    def test_retries_through_rate_limits_then_succeeds(self, harness):
        proc = harness["run"](["rate_limited", "rate_limited", "ok"])
        assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
        assert harness["attempts"]() == 3
        assert (harness["workdir"] / "payload.bin").exists()

    def test_does_not_retry_a_non_rate_limit_failure(self, harness):
        """A PAKE failure repeats identically and would burn relay admissions."""
        proc = harness["run"](["other_fail", "ok"])
        assert "RC=0" not in proc.stdout
        assert harness["attempts"]() == 1

    def test_gives_up_after_the_configured_attempts(self, harness):
        proc = harness["run"](["rate_limited"])
        assert "RC=0" not in proc.stdout
        expected = len(croc_manager.CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS) + 1
        assert harness["attempts"]() == expected

    def test_transfer_progress_stays_visible(self, harness):
        """Output is teed, not swallowed: a long transfer must still show progress."""
        proc = harness["run"](["ok"])
        assert "Receiving 'payload.bin'" in proc.stdout

    def test_scratch_files_are_cleaned_up(self, harness):
        harness["run"](["rate_limited", "ok"])
        leftovers = [p.name for p in harness["workdir"].iterdir()
                     if p.name.startswith(".croc_recv")]
        assert leftovers == [], f"left behind: {leftovers}"

    def test_relay_flag_reaches_the_receiver(self, harness):
        lines = croc_manager.generate_croc_receive_attempt(timeout=30, relay="relay.internal:9009")
        joined = "\n".join(lines)
        assert "croc --relay relay.internal:9009 --yes --overwrite" in joined
