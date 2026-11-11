"""The croc relay reachability check, and READY meaning the relay room really exists.

Found on 2026-11-09 (docs/croc-file-transfer.md, "Relay reachability check"): an agent
whose network drops TCP 9009-9013 copied and hashed a 3.5 GB file, announced that it
was "waiting for the receiver", and only then failed - with the receiver's
"room not ready" as the reported reason. Two things were missing:

- a check, before anything expensive, that each side reaches the relay. It sends croc's
  own "ping" frame, which the relay answers before any room exists, so it costs nothing
  against the relay's per-IP join limit; and it goes through HTTP_PROXY the way croc
  does.
- READY was printed when croc printed its code, which croc does BEFORE dialing the
  relay. It now also needs croc to hold a live TCP connection.

Everything runs against tests/_fake_croc_relay.py: in WSL for the generated bash, in
this process for the Python check. Nothing here touches the real network.
"""

import json
import os
import socket
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, mcp_tool

import _bash_harness as bh
import _fake_croc_relay
from _bash_harness import needs_bash

PING_HEX = _fake_croc_relay.PING.hex()
FAST = 1  # the check's timeout in these tests (production: 6 s)


# ============================================================================
# The generated bash check, against a fake relay inside WSL
# ============================================================================

@pytest.fixture(scope="module")
def wsl_relay(tmp_path_factory):
    if bh.RUNNER is None:
        pytest.skip("needs WSL (on Windows) or bash")
    log = tmp_path_factory.mktemp("relay") / "relay.log"
    log.write_text("")
    server = os.path.join(os.path.dirname(__file__), "_fake_croc_relay.py")
    argv = (["wsl.exe", "-e", "python3", bh.shell_path(server), bh.shell_path(log)]
            if bh.RUNNER == "wsl" else [sys.executable, server, str(log)])
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    ports = json.loads(proc.stdout.readline())
    yield {"ports": ports, "log": log}
    proc.stdin.close()
    proc.wait(timeout=30)


@pytest.fixture
def check(tmp_path, monkeypatch, wsl_relay):
    monkeypatch.setattr(croc_manager, "RELAY_CHECK_TIMEOUT_SECONDS", FAST)

    def run(relay, env=None, extra=""):
        lines = croc_manager.generate_relay_check(
            relay, "the test side", ['echo "FAILED: $__TT_RELAY_ERR"', "exit 1"])
        script = tmp_path / "check.sh"
        bh.write_text(script, "unset HTTP_PROXY SOCKS5_PROXY\n"
                      + "".join(f"export {k}='{v}'\n" for k, v in (env or {}).items())
                      + "\n".join(lines) + "\n" + extra + 'echo "REACHED"\n')
        before = wsl_relay["log"].read_text()
        started = time.monotonic()
        proc = bh.run_script(script)
        proc.elapsed = time.monotonic() - started
        proc.relay_log = wsl_relay["log"].read_text()[len(before):]
        return proc

    return run


def _port(wsl_relay, kind):
    return wsl_relay["ports"][kind]


@needs_bash
class TestGeneratedCheck:
    def test_a_reachable_relay_passes_and_only_a_ping_was_sent(self, check, wsl_relay):
        port = _port(wsl_relay, "relay")
        proc = check(f"127.0.0.1:{port}")
        assert "REACHED" in proc.stdout, proc.stdout + proc.stderr
        # Nothing but croc's ping frame: no room, no handshake, nothing the relay's
        # join limiter counts.
        assert proc.relay_log.split() == ["relay", PING_HEX], proc.relay_log

    def test_refused(self, check, wsl_relay):
        port = _port(wsl_relay, "closed")
        proc = check(f"127.0.0.1:{port}")
        assert "REACHED" not in proc.stdout
        assert (f"FAILED: the test side cannot reach the croc relay 127.0.0.1:{port}: "
                f"connection refused by 127.0.0.1:{port}") in proc.stdout, proc.stdout

    def test_a_dropped_port_times_out_promptly(self, check, wsl_relay):
        port = _port(wsl_relay, "blackhole")
        proc = check(f"127.0.0.1:{port}")
        assert f"connecting to 127.0.0.1:{port} timed out after {FAST} s" in proc.stdout, proc.stdout
        assert "firewall" in proc.stdout
        assert proc.elapsed < FAST + 6, proc.elapsed

    def test_an_open_port_that_never_answers(self, check, wsl_relay):
        port = _port(wsl_relay, "silent")
        proc = check(f"127.0.0.1:{port}")
        assert f"connected to 127.0.0.1:{port}, but no croc answer came within {FAST} s" in proc.stdout, proc.stdout

    def test_something_that_is_not_a_croc_relay(self, check, wsl_relay):
        port = _port(wsl_relay, "other")
        proc = check(f"127.0.0.1:{port}")
        assert f"127.0.0.1:{port} answered, but not as a croc relay" in proc.stdout, proc.stdout

    def test_through_an_http_proxy_like_croc(self, check, wsl_relay):
        proxy = _port(wsl_relay, "proxy_ok")
        proc = check("croc.example.test:9009", env={"HTTP_PROXY": f"http://127.0.0.1:{proxy}"})
        assert "REACHED" in proc.stdout, proc.stdout + proc.stderr
        assert "proxy CONNECT croc.example.test:9009 HTTP/1.1" in proc.relay_log, proc.relay_log
        assert f"relay {PING_HEX}" in proc.relay_log

    def test_a_proxy_that_refuses_is_named_with_its_answer(self, check, wsl_relay):
        proxy = _port(wsl_relay, "proxy_403")
        proc = check("croc.example.test:9009", env={"HTTP_PROXY": f"http://127.0.0.1:{proxy}/"})
        assert (f"the HTTP proxy 127.0.0.1:{proxy} refused CONNECT croc.example.test:9009: "
                "HTTP/1.1 403 Forbidden") in proc.stdout, proc.stdout

    def test_a_private_relay_is_dialed_directly_as_croc_does(self, check, wsl_relay):
        proxy = _port(wsl_relay, "proxy_403")
        port = _port(wsl_relay, "relay")
        proc = check(f"127.0.0.1:{port}", env={"HTTP_PROXY": f"http://127.0.0.1:{proxy}"})
        assert "REACHED" in proc.stdout, proc.stdout
        assert "proxy" not in proc.relay_log

    def test_a_socks5_proxy_is_not_checked(self, check, wsl_relay):
        proc = check("croc.example.test:9009", env={"SOCKS5_PROXY": "127.0.0.1:1"})
        assert "REACHED" in proc.stdout and "skipped" in proc.stdout, proc.stdout

    def test_the_public_relays_data_ports_are_checked_too(self, check, wsl_relay, monkeypatch):
        relay, relay2, closed = (_port(wsl_relay, k) for k in ("relay", "relay2", "closed"))
        monkeypatch.setattr(croc_manager, "DEFAULT_CROC_RELAY", f"127.0.0.1:{relay}")
        monkeypatch.setattr(croc_manager, "DEFAULT_RELAY_DATA_PORTS", (relay2,))
        assert "REACHED" in check("").stdout

        monkeypatch.setattr(croc_manager, "DEFAULT_RELAY_DATA_PORTS", (relay2, closed))
        proc = check("")
        assert (f"the relay answers on port {relay} but not on its data port {closed}: "
                "connection refused") in proc.stdout, proc.stdout


def test_only_the_public_relay_has_known_data_ports():
    assert croc_manager.relay_check_ports("") == [9009, 9010, 9011, 9012, 9013]
    assert croc_manager.relay_check_ports("relay.example.com:443") == [443]
    assert croc_manager.relay_check_ports("[2001:db8::1]:9100") == [9100]


# ============================================================================
# The same check from this machine (Python), against an in-process fake relay
# ============================================================================

@pytest.fixture(scope="module")
def local_relay(tmp_path_factory):
    log = tmp_path_factory.mktemp("local-relay") / "relay.log"
    log.write_text("")
    return {"ports": _fake_croc_relay.start(str(log)), "log": log}


@pytest.fixture
def no_proxy(monkeypatch):
    for name in ("HTTP_PROXY", "http_proxy", "SOCKS5_PROXY"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.real_relay_check
@pytest.mark.usefixtures("no_proxy")
class TestLocalCheck:
    def test_a_reachable_relay(self, local_relay):
        before = local_relay["log"].read_text()
        assert croc_manager.check_relay(f"127.0.0.1:{local_relay['ports']['relay']}", timeout=FAST) == ""
        assert local_relay["log"].read_text()[len(before):].split() == ["relay", PING_HEX]

    def test_refused(self, local_relay):
        port = local_relay["ports"]["closed"]
        # Windows retries a refused SYN for ~2 s before reporting the refusal (the real
        # check's 6 s covers that), so this one needs a longer timeout than FAST.
        problem = croc_manager.check_relay(f"127.0.0.1:{port}", timeout=4)
        assert problem.startswith(f"connection refused by 127.0.0.1:{port}"), problem

    def test_no_answer(self, local_relay):
        port = local_relay["ports"]["silent"]
        problem = croc_manager.check_relay(f"127.0.0.1:{port}", timeout=0.5)
        assert problem == f"connected to 127.0.0.1:{port}, but no croc answer came within 0.5 s", problem

    def test_not_a_croc_relay(self, local_relay):
        port = local_relay["ports"]["other"]
        assert "not as a croc relay" in croc_manager.check_relay(f"127.0.0.1:{port}", timeout=FAST)

    def test_through_an_http_proxy(self, local_relay, monkeypatch):
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{local_relay['ports']['proxy_ok']}")
        before = local_relay["log"].read_text()
        assert croc_manager.check_relay("croc.example.test:9009", timeout=FAST) == ""
        assert "proxy CONNECT croc.example.test:9009" in local_relay["log"].read_text()[len(before):]

    def test_a_proxy_that_refuses(self, local_relay, monkeypatch):
        port = local_relay["ports"]["proxy_403"]
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{port}")
        problem = croc_manager.check_relay("croc.example.test:9009", timeout=FAST)
        assert problem == (f"the HTTP proxy 127.0.0.1:{port} refused CONNECT croc.example.test:9009: "
                           "HTTP/1.1 403 Forbidden"), problem

    def test_a_private_relay_ignores_the_proxy(self, local_relay, monkeypatch):
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{local_relay['ports']['proxy_403']}")
        assert croc_manager.check_relay(f"127.0.0.1:{local_relay['ports']['relay']}", timeout=FAST) == ""

    def test_a_socks5_proxy_is_not_checked(self, monkeypatch):
        monkeypatch.setenv("SOCKS5_PROXY", "127.0.0.1:1")
        assert croc_manager.check_relay("croc.example.test:9009", timeout=FAST) == ""

    def test_a_dropped_port(self, monkeypatch):
        def hang(*a, **kw):
            raise socket.timeout("timed out")
        monkeypatch.setattr(croc_manager.socket, "create_connection", hang)
        problem = croc_manager.check_relay("relay.example.com:9009", timeout=FAST)
        assert problem.startswith(f"connecting to relay.example.com:9009 timed out after {FAST} s"), problem

    def test_dns(self, monkeypatch):
        def no_such_host(*a, **kw):
            raise socket.gaierror(11001, "getaddrinfo failed")
        monkeypatch.setattr(croc_manager.socket, "create_connection", no_such_host)
        assert croc_manager.check_relay("nope.example:9009", timeout=FAST) == "DNS lookup of nope.example failed"

    def test_an_invalid_relay_is_reported_not_raised(self):
        assert "Invalid croc relay" in croc_manager.check_relay("bad relay;rm", timeout=FAST)


def test_an_upload_this_machine_cannot_send_stops_before_staging(monkeypatch, tmp_path):
    """Neither croc's relay nor the Piping Server answers from here: the call fails in
    preparation, naming both, before anything is staged or started."""
    monkeypatch.setattr(croc_manager, "check_relay", lambda relay="", timeout=None: "connection refused by x")
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(croc_manager.CROC_THRESHOLD_BYTES + 1024))
    plan = mcp_tool.prepare_files_with_croc([{"remote_destination_path": "/tmp/big.bin",
                                              "local_source_path": str(big)}])
    assert plan.errors == ["this machine can reach no file transport: croc relay croc.schollz.com:9009: "
                           "connection refused by x; the Piping Server is not used in tests"], plan.errors
    assert not plan.croc_staging_dir


def test_a_download_this_machine_cannot_receive_stops_before_anything(monkeypatch):
    monkeypatch.setattr(croc_manager, "check_relay", lambda relay="", timeout=None: "timed out")
    monkeypatch.setitem(mcp_tool._config, "croc_relay", "relay.example.com:443")
    plan = mcp_tool.prepare_download_with_croc([{"remote_source_path": "/var/log/x",
                                                 "local_destination_path": "C:\\x"}])
    assert plan.errors == ["this machine can reach no file transport: croc relay relay.example.com:443: "
                           "timed out; the Piping Server is not used in tests"], plan.errors
    assert not plan.needs_download and not plan.croc_receive_dir


# ============================================================================
# The check runs FIRST: before the croc install, staging, or anything else
# ============================================================================

def _before(text, *markers):
    positions = [text.index(m) for m in markers]
    return positions == sorted(positions)


def test_an_upload_checks_the_relay_before_installing_croc(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(croc_manager.CROC_THRESHOLD_BYTES + 1024))
    plan = mcp_tool.prepare_files_with_croc([{"remote_destination_path": "/tmp/big.bin",
                                              "local_source_path": str(big)}])
    try:
        assert _before(plan.croc_init_commands, "__tt_relay_check '", "Fast parallel croc install",
                       "Croc file receive"), plan.croc_init_commands
    finally:
        mcp_tool.shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)


def test_a_download_checks_the_relay_first_and_reports_it_as_the_senders_failure():
    plan = mcp_tool.prepare_download_with_croc([{"remote_source_path": "/var/log/x",
                                                 "local_destination_path": "C:\\x"}])
    try:
        cmds = plan.download_commands
        assert _before(cmds, "__tt_relay_check '", "Fast parallel croc install", "Croc file download"), cmds
        assert f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=relay reason=$__TT_TRANSPORT_ERR" in cmds
    finally:
        mcp_tool.shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)


@needs_bash
def test_a_download_from_a_blocked_agent_fails_at_once_with_the_cause(tmp_path, monkeypatch, wsl_relay):
    """The generated download step, run: the relay check fails, the sender's FAILED
    sentinel carries the cause, and nothing after it runs (no croc install)."""
    monkeypatch.setattr(croc_manager, "RELAY_CHECK_TIMEOUT_SECONDS", FAST)
    port = wsl_relay["ports"]["closed"]
    monkeypatch.setitem(mcp_tool._config, "croc_relay", f"127.0.0.1:{port}")
    plan = mcp_tool.prepare_download_with_croc([{"remote_source_path": "/var/log/x",
                                                 "local_destination_path": "C:\\x"}])
    mcp_tool.shutil.rmtree(plan.croc_receive_dir, ignore_errors=True)
    script = tmp_path / "dl.sh"
    bh.write_text(script, "unset HTTP_PROXY SOCKS5_PROXY\ncurl() { echo CURL-RAN; }\n"
                  + plan.download_commands + "\n")
    proc = bh.run_script(script)
    assert proc.returncode == 1
    # (this machine cannot use the Piping Server here - conftest - so croc is all the
    # agent may offer)
    assert (f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=relay reason=the agent container can "
            f"reach no file transport: croc relay 127.0.0.1:{port}: connection refused") in proc.stdout, proc.stdout
    assert "CURL-RAN" not in proc.stdout


# ============================================================================
# READY: only once croc holds a live connection
# ============================================================================

FAKE_CROC = r"""#!/bin/bash
# Fake croc send. $FAKE_MODE: "no-relay" prints its code (as croc does before dialing)
# and then fails to connect; "connected" also opens a TCP connection to the fake relay
# and holds it, then fails later (so only the monitor, not the after-exit path, can
# announce READY).
echo "Sending 'x' (5 B)"
echo "Code is: $CROC_SECRET"
if [ "$FAKE_MODE" = connected ]; then
  exec 9<>"/dev/tcp/127.0.0.1/$FAKE_RELAY_PORT"
  sleep 1.5
  echo "something went wrong later"
  exit 1
fi
sleep 0.6
echo "could not connect to croc.schollz.com:9009: comm.NewConnection failed: dial tcp 142.132.189.179:9009: i/o timeout"
exit 1
"""


@needs_bash
class TestReadyNeedsALiveConnection:
    @pytest.fixture
    def send(self, tmp_path, monkeypatch, wsl_relay):
        monkeypatch.setattr(croc_manager, "CROC_SEND_RETRY_DELAY_SECONDS", 0)
        monkeypatch.setattr(croc_manager, "CROC_SEND_MONITOR_TICK_SECONDS", 0.05)
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        bh.make_executable(fake_bin / "croc", FAKE_CROC)
        src = tmp_path / "data.bin"
        src.write_bytes(b"hello")

        def run(mode):
            commands = croc_manager.generate_croc_send_commands(
                [{"remote_source_path": bh.shell_path(src), "croc_filename": "_croc_dl_0_data.bin"}])
            script = tmp_path / "send.sh"
            bh.write_text(script, commands + "\n")
            return bh.run_script(script, prepend_path=[fake_bin], env={
                "FAKE_MODE": mode, "FAKE_RELAY_PORT": wsl_relay["ports"]["relay"],
                croc_manager.CROC_SEND_CODE_ENV: "test-code"})

        return run

    def test_a_code_without_a_relay_connection_is_not_ready(self, send):
        proc = send("no-relay")
        assert croc_manager.CROC_SENTINEL_READY not in proc.stdout, proc.stdout
        assert croc_manager.CROC_SENTINEL_RETRY in proc.stdout
        assert f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=1 reason=could not connect" in proc.stdout

    def test_a_code_with_a_live_connection_is_ready_while_croc_runs(self, send):
        proc = send("connected")
        out = proc.stdout
        assert croc_manager.CROC_SENTINEL_READY in out, out
        # Announced by the monitor while croc was up, i.e. before its first failure
        assert out.index(croc_manager.CROC_SENTINEL_READY) < out.index(croc_manager.CROC_SENTINEL_RETRY), out
