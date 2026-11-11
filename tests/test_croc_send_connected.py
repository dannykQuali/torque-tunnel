"""This machine's croc sender counts as registered only once it holds its relay connection.

croc prints its code before it dials the relay and gives the dial 5 s; the local
upload sender used to count as registered after being alive 3 s, so the environment
could be launched to receive from a room that never existed (the receiver then fails
with "room not ready", hiding the real cause). Same fix as the remote send monitor's
READY (tests/test_relay_check.py).
"""

import asyncio
import os
import socket
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager


# ---------------------------------------------------------------------------
# process_tcp_established, against this OS's real TCP table
# ---------------------------------------------------------------------------

def test_a_process_holding_an_established_connection_is_seen():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname())
    server, _ = listener.accept()
    try:
        assert croc_manager.process_tcp_established(os.getpid()) is True
    finally:
        for s in (client, server, listener):
            s.close()


def test_a_process_without_connections_is_not():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert croc_manager.process_tcp_established(child.pid) is False
    finally:
        child.kill()
        child.wait()


@pytest.mark.parametrize("pid", [None, "123", 0, -1, True, mock.Mock()])
def test_something_that_is_not_a_pid_cannot_be_told(pid):
    assert croc_manager.process_tcp_established(pid) is None


# ---------------------------------------------------------------------------
# start_croc_send waits for the connection
# ---------------------------------------------------------------------------

class FakeCroc:
    """A croc process: alive until terminated (or until `exit_after` checks)."""

    def __init__(self, output=b""):
        self.returncode = None
        self.pid = 4242
        self.terminated = False
        self.output = output

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.terminate()

    async def wait(self):
        return self.returncode


@pytest.fixture
def send(monkeypatch):
    monkeypatch.setattr(croc_manager, "CROC_SEND_STARTUP_SECONDS", 0)
    monkeypatch.setattr(croc_manager, "CROC_SEND_CONNECT_POLL_SECONDS", 0.01)
    monkeypatch.setattr(croc_manager, "CROC_SEND_CONNECT_MIN_SECONDS", 0.3)
    monkeypatch.setattr(croc_manager, "warm_dns_cache", lambda *a, **kw: None)

    def run(proc, states):
        answers = iter(states)

        def established(pid):
            assert pid == proc.pid
            try:
                answer = next(answers)
            except StopIteration:
                answer = states[-1]
            if answer == "exit":
                proc.returncode = 1
                return False
            return answer

        async def spawn(*args, **kwargs):
            if proc.output:
                kwargs["stdout"].write(proc.output)
                kwargs["stdout"].flush()
            return proc

        monkeypatch.setattr(croc_manager, "process_tcp_established", established)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
        return asyncio.run(croc_manager.start_croc_send(
            croc_path=Path("croc"), code="test-secret", files=["f"], relay="relay.example:9009"))

    return run


def test_ready_once_connected(send):
    proc = FakeCroc()
    assert send(proc, [False, False, True]) is proc
    assert not proc.terminated


def test_alive_but_never_connected_is_a_failure_and_croc_is_stopped(send):
    proc = FakeCroc(output=b"Sending 'f' (5 B)\n")
    with pytest.raises(RuntimeError, match=r"did not connect to the relay relay.example:9009 within 0 s"):
        send(proc, [False])
    assert proc.terminated


def test_croc_that_gives_up_on_the_relay_says_why(send):
    proc = FakeCroc(output=b"could not connect to relay.example:9009: dial tcp: i/o timeout\n")
    with pytest.raises(RuntimeError, match="i/o timeout"):
        send(proc, [False, "exit"])


def test_a_platform_that_cannot_tell_keeps_the_previous_behaviour(send):
    proc = FakeCroc()
    assert send(proc, [None]) is proc
