"""The Piping Server transport, this machine's side (torque_tunnel.piping).

Against tests/_fake_piping_server.py, run inside WSL (the same server the bash side's
tests use; Windows reaches it through WSL's localhost forwarding). The archive format
is checked against the real `openssl`, `gzip` and `tar` there, both ways, because the
agents produce and read it with those tools.

What may cross the server (DannyK, 2026-11-11): the constant hello and ciphertext. Never
the key, anything derived from it, a hash or a size; the receiver's reference (size,
sha256) comes through Torque.
"""

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, piping

import _bash_harness as bh

CODE = croc_manager.generate_croc_code()
KEY, TOKEN = piping.split_code(CODE)
OPENSSL = f"openssl enc -aes-256-ctr -pbkdf2 -iter {piping.PBKDF2_ITERATIONS}"


def _make_tree(root):
    os.makedirs(os.path.join(root, "dir", "sub"))
    with open(os.path.join(root, "big.bin"), "wb") as f:
        f.write(os.urandom(300_000))
    with open(os.path.join(root, "dir", "sub", "note.txt"), "w", newline="\n") as f:
        f.write("hello\n")
    with open(os.path.join(root, "empty"), "w"):
        pass
    return {"big.bin": open(os.path.join(root, "big.bin"), "rb").read()}


def _same_tree(a, b):
    for base, dirs, files in os.walk(a):
        rel = os.path.relpath(base, a)
        for name in files:
            with open(os.path.join(base, name), "rb") as x, open(os.path.join(b, rel, name), "rb") as y:
                assert x.read() == y.read(), os.path.join(rel, name)
        for name in dirs:
            assert os.path.isdir(os.path.join(b, rel, name)), os.path.join(rel, name)


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if bh.RUNNER != "wsl":
        pytest.skip("needs WSL")
    log = tmp_path_factory.mktemp("piping") / "server.log"
    log.write_text("")
    script = os.path.join(os.path.dirname(__file__), "_fake_piping_server.py")
    proc = subprocess.Popen(["wsl.exe", "-e", "python3", bh.shell_path(script), bh.shell_path(log), "-3"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    port = json.loads(proc.stdout.readline())["port"]
    yield {"url": f"http://127.0.0.1:{port}", "log": log}
    proc.stdin.close()
    proc.wait(timeout=30)


# --- the code: a strong key, and an independent path token -------------------------

def test_the_key_and_the_path_token_are_disjoint_parts_of_a_2048_bit_code():
    code = croc_manager.generate_croc_code()
    key, token = piping.split_code(code)
    assert len(code) == 342                                # secrets.token_urlsafe(256)
    assert len(key) * 6 >= 1800 and len(token) * 6 == 192  # bits
    assert key + token + code[-1] == code                  # disjoint: the token is not derived from the key
    assert token not in key


@pytest.mark.parametrize("code", ["", "short-code", "x" * 127, "has~a~separator" * 20 + "!"])
def test_a_code_that_cannot_hold_both_is_refused(code):
    with pytest.raises(ValueError):
        piping.split_code(code)


# --- the archive format, against the agents' tools --------------------------------

def test_the_archive_is_what_openssl_gzip_and_tar_read(tmp_path):
    src = tmp_path / "src"
    expected = _make_tree(src)
    sha = piping.build_archive(str(src), str(tmp_path / "a.enc"), CODE)
    script = tmp_path / "x.sh"
    out = tmp_path / "out"
    out.mkdir()
    bh.write_text(script, f"""set -e
export K='{KEY}'
{OPENSSL} -d -pass env:K < '{bh.shell_path(tmp_path / "a.enc")}' > /tmp/tt-piping-plain.$$
sha256sum < /tmp/tt-piping-plain.$$ | cut -c1-64
gzip -d < /tmp/tt-piping-plain.$$ | tar -C '{bh.shell_path(out)}' -xf -
rm -f /tmp/tt-piping-plain.$$
""")
    proc = bh.run_script(script)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == sha
    assert (out / "big.bin").read_bytes() == expected["big.bin"]
    _same_tree(src, out)


def test_an_archive_from_the_agents_tools_is_read_here(tmp_path):
    src = tmp_path / "src"
    _make_tree(src)
    script = tmp_path / "x.sh"
    bh.write_text(script, f"""set -e
export K='{KEY}'
tar -C '{bh.shell_path(src)}' -cf - . | gzip -1 > /tmp/tt-piping-plain.$$
sha256sum < /tmp/tt-piping-plain.$$ | cut -c1-64
{OPENSSL} -pass env:K < /tmp/tt-piping-plain.$$ > '{bh.shell_path(tmp_path / "a.enc")}'
rm -f /tmp/tt-piping-plain.$$
""")
    proc = bh.run_script(script)
    assert proc.returncode == 0, proc.stderr
    out = tmp_path / "out"
    out.mkdir()
    piping.extract_archive(str(tmp_path / "a.enc"), str(out), CODE, proc.stdout.strip())
    _same_tree(src, out)


def test_a_wrong_checksum_is_refused(tmp_path):
    src = tmp_path / "src"
    _make_tree(src)
    piping.build_archive(str(src), str(tmp_path / "a.enc"), CODE)
    with pytest.raises(ValueError, match="checksum mismatch"):
        piping.extract_archive(str(tmp_path / "a.enc"), str(tmp_path), CODE, "0" * 64)


def test_the_whole_code_is_not_the_key(tmp_path):
    """Encrypted with the key part only: the whole code (which includes the path token
    the server sees) does not decrypt it."""
    src = tmp_path / "src"
    _make_tree(src)
    piping.build_archive(str(src), str(tmp_path / "a.enc"), CODE)
    script = tmp_path / "x.sh"
    bh.write_text(script, f"export K='{CODE}'\n{OPENSSL} -d -pass env:K < '{bh.shell_path(tmp_path / 'a.enc')}' | gzip -t\n")
    assert bh.run_script(script).returncode != 0


# --- over the server ----------------------------------------------------------------

def test_send_and_receive_through_the_server_in_parallel_chunks(tmp_path, server):
    src, dst = tmp_path / "src", tmp_path / "dst"
    _make_tree(src)
    dst.mkdir()
    before = server["log"].read_text()
    archive = tmp_path / "a.enc"
    sha = piping.build_archive(str(src), str(archive), CODE)
    size = archive.stat().st_size
    chosen = []

    async def both():
        sender = asyncio.create_task(piping.send_archive(
            str(archive), CODE, server["url"], streams=4, chunk_bytes=64 * 1024,
            on_chosen=lambda: chosen.append(True)))
        # the receiver's reference comes from elsewhere (Torque), here: directly
        await piping.receive_dir(str(dst), CODE, server["url"], (size, sha), streams=4, chunk_bytes=64 * 1024)
        await sender

    asyncio.run(both())
    assert chosen == [True]
    _same_tree(src, dst)
    log = server["log"].read_text()[len(before):]
    relayed = [line.split() for line in log.splitlines() if line.startswith("RELAY ")]
    paths = [r[1] for r in relayed]
    # Only the hello and the chunks crossed the server, at paths named by the token
    assert all(re.fullmatch(rf"/tt-{re.escape(TOKEN)}-(hello|\d+)", p) for p in paths), paths
    hello = [r for r in relayed if r[1].endswith("-hello")]
    assert len(hello) == 1 and bytes.fromhex(hello[0][3]) == piping.HELLO
    # The chunks are ciphertext: OpenSSL's salted header first, never tar/gzip plaintext
    chunk0 = next(r for r in relayed if r[1].endswith("-0"))
    assert bytes.fromhex(chunk0[3]).startswith(b"Salted__")
    assert "1f8b08" not in log
    # No hash, no size, no key, nothing derived from the key went through
    assert sha not in log and str(size) not in " ".join(r[3] for r in relayed)
    for secret in (KEY, CODE, hashlib.sha256(KEY.encode()).hexdigest(), hashlib.sha256(CODE.encode()).hexdigest()):
        assert secret not in log
    # The chunk the server cut (path ending "-3") was retried
    assert f"CUT /tt-{TOKEN}-3" in log


def test_the_receiver_waits_for_its_reference_from_torque(tmp_path, server):
    """Before the size and sha256 arrive (through Torque, e.g. the sender's log line) the
    receiver fetches no chunk."""
    src, dst = tmp_path / "src", tmp_path / "dst"
    _make_tree(src)
    dst.mkdir()
    code = croc_manager.generate_croc_code()
    archive = tmp_path / "a.enc"
    sha = piping.build_archive(str(src), str(archive), code)
    reference = []

    async def both():
        sender = asyncio.create_task(piping.send_archive(str(archive), code, server["url"]))
        receiver = asyncio.create_task(piping.receive_dir(
            str(dst), code, server["url"], lambda: reference[0] if reference else None))
        await asyncio.sleep(2)
        assert not receiver.done() and not sender.done()     # waiting for the reference
        reference.append((archive.stat().st_size, sha))
        await receiver
        await sender

    asyncio.run(both())
    _same_tree(src, dst)


@pytest.mark.real_piping_check
def test_the_server_check(server):
    assert piping.check_server(server["url"]) == ""
    problem = piping.check_server("http://127.0.0.1:9", timeout=2)
    # Refused, or (Windows retries a refused SYN for ~2 s) out of time: either way named
    assert "Piping Server http://127.0.0.1:9" in problem, problem
    assert "Invalid piping_server" in piping.check_server("ftp://x")
