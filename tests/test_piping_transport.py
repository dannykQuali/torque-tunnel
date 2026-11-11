"""The Piping Server transport end to end: the generated agent scripts and this machine.

When croc's relay is blocked (2026-11-09: agent mgmt-168-7 drops TCP 9009-9013), every
file-moving tool falls back to a public Piping Server over HTTPS (docs/piping-transport.md):
- download_files: the agent's sender offers piping, this machine receives;
- upload_files: this machine offers croc and piping, the agent chooses piping;
- transfer: agent to agent; and a sender offering both, whose receiver takes piping,
  stops croc.

The agent scripts run under WSL against tests/_fake_piping_server.py (and the fake croc
relay for "croc reachable"); this machine's side reaches the same server through WSL's
localhost forwarding. Files, directories and links inside directories are moved, and
checked byte for byte at the other end.
"""

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, mcp_tool, piping, remote_transfer

import _bash_harness as bh

pytestmark = [pytest.mark.real_piping_check]

FAST = 1

# Runs the "remote" command locally (the target is this same WSL)
FAKE_SSH = r"""ssh() {
  while [ $# -gt 0 ]; do case "$1" in -o|-i) shift 2 ;; -*) shift ;; *) break ;; esac; done
  shift
  bash -c "$*"
}
"""


def _wsl_server(script_name, *args):
    script = os.path.join(os.path.dirname(__file__), script_name)
    proc = subprocess.Popen(["wsl.exe", "-e", "python3", bh.shell_path(script), *args],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    return proc, json.loads(proc.stdout.readline())


@pytest.fixture(scope="module")
def servers(tmp_path_factory):
    if bh.RUNNER != "wsl":
        pytest.skip("needs WSL")
    log = tmp_path_factory.mktemp("piping-e2e") / "server.log"
    log.write_text("")
    pp, info = _wsl_server("_fake_piping_server.py", bh.shell_path(log))
    relay, ports = _wsl_server("_fake_croc_relay.py")
    yield {"piping": f"http://127.0.0.1:{info['port']}", "log": log,
           "relay_ok": f"127.0.0.1:{ports['relay']}", "relay_blocked": f"127.0.0.1:{ports['closed']}"}
    for p in (pp, relay):
        p.stdin.close()
        p.wait(timeout=30)


@pytest.fixture
def config(monkeypatch, servers):
    monkeypatch.setattr(croc_manager, "RELAY_CHECK_TIMEOUT_SECONDS", FAST)
    monkeypatch.setattr(croc_manager, "CROC_SEND_MONITOR_TICK_SECONDS", 0.05)
    monkeypatch.setitem(mcp_tool._config, "piping_server", servers["piping"])
    # this machine reaches croc's relay (conftest); the agents do not
    monkeypatch.setitem(mcp_tool._config, "croc_relay", servers["relay_blocked"])
    monkeypatch.setitem(mcp_tool._config, "file_transport", None)
    return servers


def _tree(root):
    """A file, a directory with a nested file and an empty file - the payload."""
    os.makedirs(os.path.join(root, "dir", "sub"))
    with open(os.path.join(root, "big.bin"), "wb") as f:
        f.write(os.urandom(400_000))
    with open(os.path.join(root, "dir", "sub", "note.txt"), "w", newline="\n") as f:
        f.write("hello\n")
    # big enough that an upload of the directory is not inlined (CROC_THRESHOLD_BYTES)
    with open(os.path.join(root, "dir", "sub", "data.bin"), "wb") as f:
        f.write(os.urandom(350_000))
    open(os.path.join(root, "dir", "empty"), "w").close()


def _same(a, b):
    for base, _, files in os.walk(a):
        rel = os.path.relpath(base, a)
        for name in files:
            with open(os.path.join(base, name), "rb") as x, open(os.path.join(b, rel, name), "rb") as y:
                assert x.read() == y.read(), os.path.join(rel, name)


def _md5(path):
    return hashlib.md5(open(path, "rb").read()).hexdigest()


def _only_hello_and_ciphertext_crossed(log_text, code, sha):
    """What the Piping Server saw: the constant hello and ciphertext chunks, at paths
    named by the code's token; never the key, a hash of it, the archive's sha256 or a
    description of the archive (DannyK, 2026-11-11)."""
    key, token = piping.split_code(code)
    relayed = [line.split() for line in log_text.splitlines() if line.startswith("RELAY ")]
    assert relayed, log_text
    for _, path, _, head in relayed:
        assert re.fullmatch(rf"/tt-{re.escape(token)}-(hello|\d+)", path), path
        if path.endswith("-hello"):
            assert bytes.fromhex(head) == piping.HELLO
        elif path.endswith("-0"):
            assert bytes.fromhex(head).startswith(b"Salted__")
    for secret in (key, code, sha, hashlib.sha256(key.encode()).hexdigest()):
        assert secret not in log_text


# ---------------------------------------------------------------------------
# download_files: the agent sends, this machine receives
# ---------------------------------------------------------------------------

def test_a_download_goes_through_the_piping_server_when_the_agents_relay_is_blocked(tmp_path, config):
    src, dst = tmp_path / "src", tmp_path / "dst"
    _tree(src)
    files = [{"remote_source_path": bh.shell_path(src / "big.bin"), "local_destination_path": str(dst / "big.bin")},
             {"remote_source_path": bh.shell_path(src / "dir"), "local_destination_path": str(dst / "dir")}]
    plan = mcp_tool.prepare_download_with_croc(files)
    assert plan.local_transports == ["croc", "piping"], plan.errors
    script = tmp_path / "agent.sh"
    bh.write_text(script, "unset HTTP_PROXY HTTPS_PROXY SOCKS5_PROXY\n" + plan.download_commands + "\n")
    before = config["log"].read_text()

    async def run():
        loop = asyncio.get_running_loop()
        agent = bh.start_script(script, env={croc_manager.CROC_SEND_CODE_ENV: plan.croc_code})
        lines = []

        def stream():   # the agent's log reaching this machine line by line, as Torque streams it
            for line in agent.stdout:
                lines.append(line)
                loop.call_soon_threadsafe(plan.observe_output, line)

        reader = loop.run_in_executor(None, stream)
        await reader
        await loop.run_in_executor(None, agent.wait)
        try:
            return "".join(lines), await mcp_tool.complete_download(plan, None)
        finally:
            await mcp_tool.cleanup_download_resources(None, plan.croc_receive_dir)

    out, (successes, errors) = asyncio.run(run())
    assert f"{croc_manager.TRANSPORT_OFFER_SENTINEL} piping" in out, out
    assert f"{croc_manager.TRANSPORT_OFFER_SENTINEL} croc" not in out    # its relay is blocked
    assert croc_manager.CROC_SENTINEL_DONE in out and "[piping] every chunk sent" in out, out
    assert plan.transport == "piping"
    assert not errors, errors
    assert (dst / "big.bin").read_bytes() == (src / "big.bin").read_bytes()
    _same(src / "dir", dst / "dir")
    # The archive's reference went through the agent's log (Torque), not the server
    assert plan.piping_archive and f"{croc_manager.PIPING_ARCHIVE_SENTINEL} {plan.piping_archive[0]} " in out
    _only_hello_and_ciphertext_crossed(config["log"].read_text()[len(before):], plan.croc_code, plan.piping_archive[1])


# ---------------------------------------------------------------------------
# upload_files: this machine offers, the agent chooses
# ---------------------------------------------------------------------------

def test_an_upload_goes_through_the_piping_server_when_the_agents_relay_is_blocked(tmp_path, config, monkeypatch):
    src, dest = tmp_path / "src", tmp_path / "dest"
    _tree(src)
    plan = mcp_tool.prepare_files_with_croc([
        {"remote_destination_path": bh.shell_path(dest / "big.bin"), "local_source_path": str(src / "big.bin")},
        {"remote_destination_path": bh.shell_path(dest / "dir"), "local_source_path": str(src / "dir")},
    ])
    assert plan.offers == ["croc", "piping"], plan.errors
    started = []

    async def fake_croc_send(**kw):   # this machine's croc offer (the agent will not take it)
        started.append(kw)

    async def fake_croc_path():
        return "croc"

    monkeypatch.setattr(croc_manager, "start_croc_send", fake_croc_send)
    monkeypatch.setattr(croc_manager, "ensure_local_croc", fake_croc_path)
    script = tmp_path / "agent.sh"
    bh.write_text(script, "unset HTTP_PROXY HTTPS_PROXY SOCKS5_PROXY\n" + plan.croc_init_commands + "\n")
    before = config["log"].read_text()

    async def run():
        await mcp_tool.execute_with_croc(plan)
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, lambda: bh.run_script(
                script, env={croc_manager.CROC_RECEIVE_CODE_ENV: plan.croc_code}, timeout=180))
        finally:
            await mcp_tool.cleanup_croc_resources(None, plan.croc_staging_dir)

    proc = asyncio.run(run())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"{croc_manager.TRANSPORT_CHOSEN_SENTINEL} piping" in proc.stdout
    assert "[piping] archive verified" in proc.stdout
    assert started, "croc was offered too"
    assert (dest / "big.bin").read_bytes() == (src / "big.bin").read_bytes()
    _same(src / "dir", dest / "dir")
    # the agent got the archive's size and sha256 in its commands (Torque)
    assert f"__TT_PP_SIZE={plan.piping_archive[0]}; __TT_PP_SHA={plan.piping_archive[1]}" in plan.croc_init_commands
    _only_hello_and_ciphertext_crossed(config["log"].read_text()[len(before):], plan.croc_code, plan.piping_archive[1])


def test_the_agent_refuses_an_archive_whose_checksum_does_not_match(tmp_path, config, monkeypatch):
    """The agent checks the sha256 of what it decrypted against the sender's meta line:
    a mismatch (tampering, a wrong archive) fails the upload and places nothing."""
    src, dest = tmp_path / "src", tmp_path / "dest"
    _tree(src)
    real_build = piping.build_archive
    monkeypatch.setattr(piping, "build_archive", lambda *a: "0" * 64 if real_build(*a) else "")
    monkeypatch.setitem(mcp_tool._config, "file_transport", "piping")
    plan = mcp_tool.prepare_files_with_croc([
        {"remote_destination_path": bh.shell_path(dest / "big.bin"), "local_source_path": str(src / "big.bin")}])
    assert plan.offers == ["piping"], plan.errors
    script = tmp_path / "agent.sh"
    bh.write_text(script, "unset HTTP_PROXY HTTPS_PROXY SOCKS5_PROXY\n" + plan.croc_init_commands + "\n")

    async def run():
        await mcp_tool.execute_with_croc(plan)
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(None, lambda: bh.run_script(
                script, env={croc_manager.CROC_RECEIVE_CODE_ENV: plan.croc_code}, timeout=180))
        finally:
            await mcp_tool.cleanup_croc_resources(None, plan.croc_staging_dir)

    proc = asyncio.run(run())
    assert proc.returncode == 1
    assert "ERROR: file receive through the Piping Server failed (exit code: 1): archive checksum mismatch" \
        in proc.stderr, proc.stdout + proc.stderr
    assert not (dest / "big.bin").exists()


def test_an_agent_that_can_use_nothing_offered_says_so_at_once(tmp_path, config, monkeypatch):
    monkeypatch.setitem(mcp_tool._config, "file_transport", "croc")   # only croc offered
    src = tmp_path / "src"
    _tree(src)
    plan = mcp_tool.prepare_files_with_croc([
        {"remote_destination_path": "/tmp/x/big.bin", "local_source_path": str(src / "big.bin")}])
    try:
        assert plan.offers == ["croc"]
        script = tmp_path / "agent.sh"
        bh.write_text(script, "curl() { echo CURL-RAN; }\n" + plan.croc_init_commands + "\n")
        proc = bh.run_script(script, env={croc_manager.CROC_RECEIVE_CODE_ENV: plan.croc_code})
        assert proc.returncode == 1
        assert ("ERROR: the agent container can reach none of the file transports the sender offers "
                f"(croc): croc relay {config['relay_blocked']}: connection refused") in proc.stderr, proc.stderr
        assert "CURL-RAN" not in proc.stdout   # no croc install either
    finally:
        mcp_tool.shutil.rmtree(plan.croc_staging_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# transfer: agent to agent
# ---------------------------------------------------------------------------

TRANSFER_CODE = croc_manager.generate_croc_code()

FAKE_CROC_HOLDING = r"""#!/bin/bash
# croc send that registers (connects to the fake relay) and then waits for a receiver
echo "Sending 'x'"
echo "Code is: $CROC_SECRET"
exec 9<>"/dev/tcp/127.0.0.1/$FAKE_RELAY_PORT"
sleep "${FAKE_CROC_HOLD:-60}"
exit "${FAKE_CROC_RC:-1}"
"""


def _transfer(tmp_path, servers, files, sender_transports, receiver_offered_filter, relay, sender_env=None):
    """Run a real transfer pair: the sender until READY, then the receiver made from its
    report, as the transfer tool does. Returns (sender output, receiver process)."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    bh.make_executable(fake_bin / "croc", FAKE_CROC_HOLDING)
    send_cmds = (croc_manager.generate_transport_step(
        "send", relay, "the sending side (agent A)", failure_sentinel=croc_manager.CROC_SENTINEL_FAILED,
        piping_server=servers["piping"], transports=sender_transports)
        + "\n" + croc_manager.generate_croc_relay_send_commands(
            [{"source_path": f["source_path"], "croc_filename": f["croc_filename"]} for f in files],
            target_ip="10.0.0.1", ssh_user="root", relay=relay))
    sender_script = tmp_path / "sender.sh"
    bh.write_text(sender_script, "unset HTTP_PROXY HTTPS_PROXY SOCKS5_PROXY\n" + FAKE_SSH + send_cmds + "\n")
    env = {croc_manager.CROC_SEND_CODE_ENV: TRANSFER_CODE, croc_manager.SSH_PRIVATE_KEY_ENV: "k",
           "FAKE_RELAY_PORT": servers["relay_ok"].rsplit(":", 1)[1], **(sender_env or {})}
    sender = bh.start_script(sender_script, env=env, prepend_path=[fake_bin])
    out, deadline = [], time.monotonic() + 120
    reader = threading.Thread(target=lambda: out.extend(sender.stdout), daemon=True)
    reader.start()
    while time.monotonic() < deadline and not remote_transfer.parse_sender_log("".join(out)).ready:
        assert sender.poll() is None or out, "sender ended early"
        if sender.poll() is not None:
            break
        time.sleep(0.2)
    report = remote_transfer.parse_sender_log("".join(out))
    assert report.ready, "".join(out)
    manifest, errors = remote_transfer.build_manifest(files, report)
    assert not errors, errors
    offered = receiver_offered_filter(report.offers)
    recv_cmds = (croc_manager.generate_transport_step(
        "receive", relay, "the receiving side (agent B)", failure_sentinel=croc_manager.CROC_RX_SENTINEL_FAILED,
        piping_server=servers["piping"], offered=offered, piping_archive=report.piping_archive)
        + "\n" + croc_manager.generate_croc_relay_receive_commands(manifest, target_ip="10.0.0.2", ssh_user="root",
                                                                     relay=relay))
    receiver_script = tmp_path / "receiver.sh"
    bh.write_text(receiver_script, "unset HTTP_PROXY HTTPS_PROXY SOCKS5_PROXY\n" + FAKE_SSH + recv_cmds + "\n")
    receiver = bh.run_script(receiver_script, env={croc_manager.CROC_RECEIVE_CODE_ENV: TRANSFER_CODE,
                                                   croc_manager.SSH_PRIVATE_KEY_ENV: "k"}, timeout=180)
    sender.wait(timeout=180)
    reader.join(timeout=10)
    return "".join(out), receiver


def _files(src, dst):
    return [
        {"source_path": bh.shell_path(src / "big.bin"), "destination_path": bh.shell_path(dst / "big.bin"),
         "croc_filename": remote_transfer.croc_filename(0, "big.bin"), "mode": None},
        {"source_path": bh.shell_path(src / "dir"), "destination_path": bh.shell_path(dst / "dir"),
         "croc_filename": remote_transfer.croc_filename(1, "dir"), "mode": None},
    ]


def test_a_transfer_from_a_blocked_agent_goes_through_the_piping_server(tmp_path, config):
    src, dst = tmp_path / "src", tmp_path / "dst"
    _tree(src)
    before = config["log"].read_text()
    sender_out, receiver = _transfer(tmp_path, config, _files(src, dst), ["croc", "piping"],
                                     lambda offers: offers, config["relay_blocked"])
    archive = remote_transfer.parse_sender_log(sender_out).piping_archive
    assert archive, sender_out
    _only_hello_and_ciphertext_crossed(config["log"].read_text()[len(before):], TRANSFER_CODE, archive[1])
    assert f"{croc_manager.TRANSPORT_OFFER_SENTINEL} piping" in sender_out
    assert croc_manager.CROC_SENTINEL_DONE in sender_out, sender_out
    assert receiver.returncode == 0, receiver.stdout + receiver.stderr
    assert f"{croc_manager.TRANSPORT_CHOSEN_SENTINEL} piping" in receiver.stdout
    assert croc_manager.CROC_RX_SENTINEL_DONE in receiver.stdout
    assert (dst / "big.bin").read_bytes() == (src / "big.bin").read_bytes()
    _same(src / "dir", dst / "dir")


def test_a_sender_offering_both_stops_croc_when_the_receiver_takes_the_piping_server(tmp_path, config):
    """Croc's relay answers the sender, but the receiver takes the Piping Server (its
    profile allows only that, or it cannot reach the relay): the sender stops croc."""
    src, dst = tmp_path / "src", tmp_path / "dst"
    _tree(src)
    sender_out, receiver = _transfer(tmp_path, config, _files(src, dst), ["croc", "piping"],
                                     lambda offers: [t for t in offers if t == "piping"], config["relay_ok"])
    assert f"{croc_manager.TRANSPORT_OFFER_SENTINEL} croc piping" in sender_out, sender_out
    assert "the receiving side chose the Piping Server; stopping croc" in sender_out
    assert croc_manager.CROC_SENTINEL_DONE in sender_out and croc_manager.CROC_SENTINEL_FAILED not in sender_out
    assert receiver.returncode == 0, receiver.stdout + receiver.stderr
    _same(src / "dir", dst / "dir")
    assert (dst / "big.bin").read_bytes() == (src / "big.bin").read_bytes()


def test_when_croc_carries_it_the_piping_offer_is_withdrawn(tmp_path, config):
    """A croc that finishes (its receiver took croc) ends the sender at once, the
    Piping Server's hello still waiting is withdrawn, and nothing went through it."""
    src = tmp_path / "src"
    _tree(src)
    before = config["log"].read_text()
    started = time.monotonic()
    sender_out, _ = _transfer_sender_only(tmp_path, config, src, {"FAKE_CROC_HOLD": "1", "FAKE_CROC_RC": "0"})
    assert f"{croc_manager.TRANSPORT_OFFER_SENTINEL} croc piping" in sender_out
    assert croc_manager.CROC_SENTINEL_DONE in sender_out, sender_out
    assert time.monotonic() - started < 60
    assert config["log"].read_text()[len(before):] == ""      # no hello was relayed


def _transfer_sender_only(tmp_path, servers, src, env):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    bh.make_executable(fake_bin / "croc", FAKE_CROC_HOLDING)
    files = [{"source_path": bh.shell_path(src / "big.bin"), "croc_filename": "_croc_rl_0_big.bin"}]
    cmds = (croc_manager.generate_transport_step(
        "send", servers["relay_ok"], "the sending side", failure_sentinel=croc_manager.CROC_SENTINEL_FAILED,
        piping_server=servers["piping"])
        + "\n" + croc_manager.generate_croc_relay_send_commands(files, target_ip="10.0.0.1", ssh_user="root",
                                                                  relay=servers["relay_ok"]))
    script = tmp_path / "sender.sh"
    bh.write_text(script, "unset HTTP_PROXY HTTPS_PROXY SOCKS5_PROXY\n" + FAKE_SSH + cmds + "\n")
    proc = bh.run_script(script, prepend_path=[fake_bin], timeout=120, env={
        croc_manager.CROC_SEND_CODE_ENV: croc_manager.generate_croc_code(), croc_manager.SSH_PRIVATE_KEY_ENV: "k",
        "FAKE_RELAY_PORT": servers["relay_ok"].rsplit(":", 1)[1], **env})
    return proc.stdout + proc.stderr, proc


# ---------------------------------------------------------------------------
# This machine's choice from the agent's offer
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("local,offered,expected", [
    (["croc", "piping"], ["croc", "piping"], "croc"),
    (["croc", "piping"], ["piping"], "piping"),
    (["piping"], ["croc", "piping"], "piping"),
    (["croc"], ["piping"], "none"),
])
def test_this_machine_takes_croc_when_both_sides_can_else_the_piping_server(local, offered, expected, tmp_path):
    plan = mcp_tool.DownloadPlan(needs_download=True, croc_receive_dir=str(tmp_path), local_transports=local)

    async def offer():
        plan.observe_output(f"{croc_manager.TRANSPORT_OFFER_SENTINEL} {' '.join(offered)}\n"
                            f"{croc_manager.CROC_SENTINEL_READY}\n")
        task = mcp_tool._piping_tasks.pop(str(tmp_path), None)
        if task:
            task.cancel()
        return task

    task = asyncio.run(offer())
    assert plan.transport == expected
    assert (task is not None) == (expected == "piping")
    # the gated croc receiver is let go only when croc was chosen
    ready = (tmp_path / croc_manager.CROC_READY_SIGNAL).exists()
    assert ready == (expected == "croc")
