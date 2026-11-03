"""Regression tests for croc's 500 ms relay lookup (investigated 2026-09-23).

``download_files`` failed on the cisco-jarvis-mx agent with

    could not connect to : could not connect

(note the EMPTY address). croc resolves its default relay hostname once at
process start with a hard 500 ms timeout (croc v10 src/models/constants.go);
when the agent's resolver is slower than that, croc silently blanks its default
relay and has nothing to dial. The tool reported only
``__CROC_DL_FAILED__ exit_code=1``; the real line was in Torque's grain log.

Two defences, both covered here:

1. Every croc invocation names the relay explicitly, by HOSTNAME
   (``--relay croc.schollz.com:9009``). croc then ignores its startup lookup,
   and with an HTTP proxy it sends ``CONNECT croc.schollz.com:9009`` so the
   proxy resolves the name - verified on 2026-09-23 with the container's DNS
   black-holed, 3 MB transferred intact.
2. The relay host is looked up just before croc starts (bounded, non-fatal),
   so the resolver's cache is warm for any lookup croc still does itself.

And croc's own error text now reaches the tool result.
"""

import asyncio
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager
from torque_tunnel import mcp_tool
from torque_tunnel.mcp_tool import DownloadPlan

import _bash_harness as bh
from _bash_harness import needs_bash


PUBLIC = "croc.schollz.com:9009"


def _fake_proc(returncode=None):
    proc = mock.AsyncMock()
    proc.returncode = returncode
    return proc


# ============================================================================
# 1. The relay is always named explicitly, by hostname
# ============================================================================

class TestExplicitRelayEverywhere:
    def test_default_relay_is_the_public_hostname_not_an_ip(self):
        """An IP would need a local lookup; the hostname lets the proxy resolve it."""
        assert croc_manager.DEFAULT_CROC_RELAY == PUBLIC

    def test_configured_relay_still_wins(self):
        script = croc_manager.generate_croc_receive_commands(
            code="c", file_transfers=[{"croc_filename": "f", "remote_destination_path": "/tmp/f"}],
            relay="relay.internal:9009")
        assert "--relay relay.internal:9009" in script
        assert PUBLIC not in script

    def test_remote_receive_names_the_relay_when_none_is_configured(self):
        script = croc_manager.generate_croc_receive_commands(
            code="c", file_transfers=[{"croc_filename": "f", "remote_destination_path": "/tmp/f"}])
        assert f"croc --relay {PUBLIC} --yes --overwrite" in script

    def test_remote_scp_receive_names_the_relay_when_none_is_configured(self):
        script = croc_manager.generate_croc_scp_commands(
            code="c", file_transfers=[{"croc_filename": "f", "remote_destination_path": "/tmp/f"}],
            target_ip="10.0.0.1", ssh_user="root", ssh_private_key="-----BEGIN KEY-----")
        assert f"croc --relay {PUBLIC} --yes --overwrite" in script

    def test_remote_send_names_the_relay_when_none_is_configured(self):
        script = croc_manager.generate_croc_send_commands(
            code="c", file_infos=[{"remote_source_path": "/tmp/f", "croc_filename": "f"}])
        assert f"croc --relay {PUBLIC} send --no-local" in script

    def test_remote_scp_send_names_the_relay_when_none_is_configured(self):
        script = croc_manager.generate_croc_scp_download_commands(
            code="c", file_infos=[{"remote_source_path": "/tmp/f", "croc_filename": "f"}],
            target_ip="10.0.0.1", ssh_user="root", ssh_private_key="-----BEGIN KEY-----")
        assert f"croc --relay {PUBLIC} send --no-local" in script

    @pytest.mark.asyncio
    async def test_local_send_names_the_relay_when_none_is_configured(self):
        with mock.patch("asyncio.create_subprocess_exec",
                        return_value=_fake_proc()) as mock_exec, \
             mock.patch("asyncio.sleep"), \
             mock.patch.object(croc_manager, "warm_dns_cache"):
            await croc_manager.start_croc_send(
                croc_path=Path("/usr/bin/croc"), code="test-secret", files=["f"])
        argv = list(mock_exec.call_args[0])
        assert argv[argv.index("--relay") + 1] == PUBLIC
        assert argv.index("--relay") < argv.index("send"), "--relay is a GLOBAL option"

    @pytest.mark.asyncio
    async def test_local_receive_names_the_relay_when_none_is_configured(self):
        with mock.patch("asyncio.create_subprocess_exec",
                        return_value=_fake_proc()) as mock_exec, \
             mock.patch("asyncio.sleep"):
            await croc_manager.start_croc_receive(
                croc_path=Path("/usr/bin/croc"), code="c", receive_dir=os.getcwd())
        wrapper_script = mock_exec.call_args[0][2]
        assert repr(["--relay", PUBLIC])[1:-1] in wrapper_script


# ============================================================================
# 2. The relay host is looked up just before croc starts (local side)
# ============================================================================

class TestLocalDnsWarmup:
    @pytest.mark.asyncio
    async def test_relay_host_is_resolved_before_croc_starts(self):
        events = []

        def fake_getaddrinfo(host, port, *a, **kw):
            events.append(("resolve", host))
            return []

        def fake_exec(*args, **kwargs):
            events.append(("croc", None))
            return _fake_proc()

        with mock.patch("socket.getaddrinfo", side_effect=fake_getaddrinfo), \
             mock.patch("asyncio.create_subprocess_exec", side_effect=fake_exec), \
             mock.patch("asyncio.sleep"):
            await croc_manager.start_croc_send(
                croc_path=Path("/usr/bin/croc"), code="test-secret", files=["f"])

        assert ("resolve", "croc.schollz.com") in events
        assert events.index(("resolve", "croc.schollz.com")) < events.index(("croc", None))

    def test_an_ip_relay_is_not_looked_up(self):
        with mock.patch("socket.getaddrinfo") as gai:
            croc_manager.warm_dns_cache("142.132.189.179:9009")
        gai.assert_not_called()

    def test_a_failing_lookup_is_not_fatal(self):
        import socket
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            croc_manager.warm_dns_cache(PUBLIC)  # must not raise

    def test_a_hanging_resolver_cannot_stall_the_transfer(self, monkeypatch):
        """The warm-up is an optimisation. A resolver that never answers must cost
        at most the bound, never the whole transfer."""
        import threading
        release = threading.Event()
        monkeypatch.setattr(croc_manager, "CROC_DNS_WARMUP_SECONDS", 0.2)

        def hang(*a, **kw):
            release.wait(10)
            return []

        try:
            with mock.patch("socket.getaddrinfo", side_effect=hang):
                started = time.monotonic()
                croc_manager.warm_dns_cache(PUBLIC)
                elapsed = time.monotonic() - started
        finally:
            release.set()
        assert elapsed < 2, f"warm-up blocked for {elapsed:.1f}s despite a 0.2s bound"

    @pytest.mark.asyncio
    async def test_local_receiver_warms_the_cache_before_every_attempt(self):
        """Each attempt is a fresh croc process doing its own startup lookup."""
        with mock.patch("asyncio.create_subprocess_exec",
                        return_value=_fake_proc()) as mock_exec, \
             mock.patch("asyncio.sleep"):
            await croc_manager.start_croc_receive(
                croc_path=Path("/usr/bin/croc"), code="c", receive_dir=os.getcwd())
        wrapper_script = mock_exec.call_args[0][2]
        compile(wrapper_script, "<receive wrapper>", "exec")  # still valid Python
        body = wrapper_script[wrapper_script.index("while time.monotonic() < deadline"):]
        assert body.index("warm_dns(") < body.index("subprocess.Popen("), \
            "the lookup must happen inside the attempt loop, before croc starts"


# ============================================================================
# 3. ...and on the remote side (shell-level, under bash)
# ============================================================================

FAKE_TIMEOUT_FUNC = r"""timeout() {
  shift 1
  "$@"
}
"""

# Logs every call to one file so the order of lookups and croc runs is visible.
FAKE_GETENT = r"""#!/bin/bash
echo "getent $*" >> "$FAKE_DIR/calls"
[ -f "$FAKE_DIR/getent_hangs" ] && sleep 30
[ -f "$FAKE_DIR/getent_fails" ] && exit 2
exit 0
"""

FAKE_CROC_RECEIVE = r"""#!/bin/bash
echo "croc $*" >> "$FAKE_DIR/calls"
n=$(grep -c '^croc ' "$FAKE_DIR/calls")
scenario=$(sed -n "${n}p" "$FAKE_DIR/scenario.txt")
[ -z "$scenario" ] && scenario=$(tail -n 1 "$FAKE_DIR/scenario.txt")
case "$scenario" in
  rate_limited) echo "could not connect to 142.132.189.179:9009: got bad response: rate limited"; exit 1 ;;
  blank_relay)  echo "could not connect to : could not connect"; exit 1 ;;
  ok)           echo "payload" > payload.bin; exit 0 ;;
esac
exit 9
"""


@needs_bash
class TestRemoteDnsWarmupAndErrors:
    @pytest.fixture
    def harness(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        work = tmp_path / "work"
        work.mkdir()
        bh.make_executable(fake_bin / "getent", FAKE_GETENT)
        bh.make_executable(fake_bin / "croc", FAKE_CROC_RECEIVE)
        monkeypatch.setattr(croc_manager, "CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS", (0, 0, 0))
        monkeypatch.setattr(croc_manager, "CROC_DNS_WARMUP_SECONDS", 1)

        def run(lines, scenarios, flags=()):
            bh.write_text(control / "scenario.txt", "\n".join(scenarios) + "\n")
            for f in flags:
                (control / f).write_text("1")
            script = tmp_path / "under_test.sh"
            bh.write_text(script, FAKE_TIMEOUT_FUNC + "\n".join(lines) + '\necho "RC=$__CROC_RC"\n')
            return bh.run_script(script, env={"FAKE_DIR": control},
                                 prepend_path=[fake_bin], cwd=work)

        def calls():
            f = control / "calls"
            return f.read_text().splitlines() if f.exists() else []

        return {"run": run, "calls": calls}

    def _receive(self, relay=""):
        return croc_manager.generate_croc_receive_attempt(code="c", timeout=30, relay=relay)

    def test_lookup_precedes_every_croc_attempt(self, harness):
        harness["run"](self._receive(), ["rate_limited", "ok"])
        calls = harness["calls"]()
        kinds = [c.split()[0] for c in calls]
        assert kinds == ["getent", "croc", "getent", "croc"], calls
        assert "croc.schollz.com" in calls[0]
        assert calls[0].startswith("getent ahosts"), "must ask for A and AAAA, as croc does"

    def test_ip_relay_skips_the_lookup(self, harness):
        harness["run"](self._receive(relay="10.1.2.3:9009"), ["ok"])
        assert not any(c.startswith("getent") for c in harness["calls"]())

    def test_a_failing_lookup_does_not_stop_the_transfer(self, harness):
        proc = harness["run"](self._receive(), ["ok"], flags=["getent_fails"])
        assert "RC=0" in proc.stdout, proc.stdout + proc.stderr

    def test_a_hanging_lookup_is_bounded(self, harness):
        started = time.monotonic()
        proc = harness["run"](self._receive(), ["ok"], flags=["getent_hangs"])
        elapsed = time.monotonic() - started
        assert "RC=0" in proc.stdout, proc.stdout + proc.stderr
        assert elapsed < 15, f"a hung resolver cost {elapsed:.0f}s against a 1s bound"

    def test_receive_failure_names_crocs_reason(self, harness):
        """The ERROR line is what the tool pulls from the log, so it must say why."""
        block = croc_manager.generate_croc_receive_commands(
            code="c", file_transfers=[{"croc_filename": "payload.bin",
                                       "remote_destination_path": "/tmp/p"}])
        proc = harness["run"]([block], ["blank_relay"])
        errors = [l for l in proc.stderr.splitlines() if "croc file receive failed" in l]
        assert errors, proc.stdout + proc.stderr
        assert "could not connect to : could not connect" in errors[-1]


# ============================================================================
# 4. The sender's reason reaches the tool result
# ============================================================================

class TestSenderReasonIsSurfaced:
    def _plan(self, tmp_path):
        plan = DownloadPlan(needs_download=True, croc_code="c",
                            croc_receive_dir=str(tmp_path))
        plan.file_mappings = [{"croc_filename": "_croc_dl_0_f",
                               "local_destination_path": str(tmp_path / "out" / "f")}]
        return plan

    @pytest.mark.asyncio
    async def test_failure_message_carries_crocs_own_words(self, tmp_path):
        plan = self._plan(tmp_path)
        plan.observe_output(
            f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=1 "
            "reason=could not connect to : could not connect\n")
        _, errors = await mcp_tool.complete_download(plan, None)
        joined = "\n".join(errors)
        assert "could not connect to : could not connect" in joined

    @pytest.mark.asyncio
    async def test_blank_relay_is_explained_in_plain_words(self, tmp_path):
        plan = self._plan(tmp_path)
        plan.observe_output(
            f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=1 "
            "reason=could not connect to : could not connect\n")
        _, errors = await mcp_tool.complete_download(plan, None)
        joined = "\n".join(errors).lower()
        assert "dns" in joined and "relay" in joined

    @pytest.mark.asyncio
    async def test_failure_without_a_reason_still_reads_sensibly(self, tmp_path):
        plan = self._plan(tmp_path)
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=stage\n")
        _, errors = await mcp_tool.complete_download(plan, None)
        assert any("remote croc send failed" in e for e in errors)

    def test_upload_receive_errors_are_pulled_from_the_log(self):
        log = (
            "[09:00:00.000] === Running container pre-commands ===\n"
            "[09:00:02.000] could not connect to : could not connect\n"
            "[09:00:02.001] ERROR: croc file receive failed (exit code: 1): "
            "could not connect to : could not connect\n"
            "[09:00:02.002] ERROR: Container pre-commands failed (exit code: 1)\n"
        )
        found = mcp_tool.extract_transfer_errors(log)
        assert found == ["croc file receive failed (exit code: 1): "
                         "could not connect to : could not connect"]

    def test_log_extraction_is_quiet_without_transfer_errors(self):
        assert mcp_tool.extract_transfer_errors("") == []
        assert mcp_tool.extract_transfer_errors("[09:00:00] all good\n") == []


@needs_bash
class TestSenderReasonShellLevel:
    """Run the real generated send commands against a fake croc that fails the
    way croc did on 2026-09-23, and check what the FAILED sentinel carries."""

    FAKE_CROC_SEND = r"""#!/bin/bash
echo "croc $*" >> "$FAKE_DIR/calls"
echo "Sending 'x' (5 B)"
echo "Code is: $CROC_SECRET"
echo "    CROC_SECRET=\"$CROC_SECRET\" croc"
echo "could not connect to : could not connect"
exit 1
"""

    TIMEOUT_FUNC = r"""timeout() {
  echo "$3" >> "$FAKE_DIR/timeouts.txt"
  shift 3
  exec "$@"
}
"""

    def test_failed_sentinel_carries_the_reason_but_never_the_code(self, tmp_path, monkeypatch):
        monkeypatch.setattr(croc_manager, "CROC_SEND_RETRY_DELAY_SECONDS", 0)
        monkeypatch.setattr(croc_manager, "CROC_DNS_WARMUP_SECONDS", 1)
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        control = tmp_path / "control"
        control.mkdir()
        bh.make_executable(fake_bin / "croc", self.FAKE_CROC_SEND)
        bh.make_executable(fake_bin / "getent", "#!/bin/bash\nexit 0\n")
        src = tmp_path / "data.bin"
        src.write_bytes(b"hello")

        secret = "SENTINEL-TEST-SECRET-do-not-leak-0123456789"
        cmds = croc_manager.generate_croc_send_commands(
            code=secret,
            file_infos=[{"remote_source_path": bh.shell_path(src),
                         "croc_filename": "_croc_dl_0_data.bin"}])
        script = tmp_path / "send.sh"
        bh.write_text(script, self.TIMEOUT_FUNC + cmds + "\n")
        proc = bh.run_script(script, env={"FAKE_DIR": control}, prepend_path=[fake_bin])

        failed = [l for l in proc.stdout.splitlines() if croc_manager.CROC_SENTINEL_FAILED in l]
        assert failed, proc.stdout + proc.stderr
        assert "reason=could not connect to : could not connect" in failed[-1]
        assert secret not in proc.stdout and secret not in proc.stderr
        # The warm-up must not go through `timeout`: other harnesses read the
        # first recorded value as croc send's own timeout. One entry per croc
        # attempt (first try + the retry), each the 300 s floor.
        recorded = (control / "timeouts.txt").read_text().split()
        assert recorded == ["300", "300"], recorded
