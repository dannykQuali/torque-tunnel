"""A local stand-in for a croc relay and the things in front of one, for the relay check tests.

Each behaviour listens on its own 127.0.0.1 port (port 0: the OS picks):

- relay      answers croc's "ping" frame with "pong" (as croc's relay does, before any
  relay2     room or handshake); any other first message is held open, like a relay
             waiting for the rest of a handshake (two of them: a control and a data port)
- silent     accepts and never answers
- other      answers like a web server (not a croc relay)
- proxy_ok   an HTTP CONNECT proxy: 200, then the tunnel behaves like `relay`
- proxy_403  an HTTP CONNECT proxy that refuses
- blackhole  never accepts and its backlog is full, so a new connection attempt hangs
             (Linux drops the SYN: how a firewall that drops a port looks)
- closed     bound but not listening (connection refused; nobody else can take the port)

Every first message (or CONNECT line) received is appended, hex-encoded, to the log
file named on the command line, so a test can check what the probe actually sent.

Run as a script (inside WSL for the bash tests): prints the ports as one JSON line,
then serves until stdin closes. Or call start() in-process. Python 3.8 compatible.
"""

import json
import socket
import sys
import threading

PING = b"croc\x04\x00\x00\x00ping"
PONG = b"croc\x04\x00\x00\x00pong"


def _log(path, entry):
    if path:
        with open(path, "a") as f:
            f.write(entry + "\n")


def _read_exactly(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _act_as_relay(conn, log_path):
    first = _read_exactly(conn, len(PING))
    _log(log_path, "relay " + first.hex())
    if first == PING:
        conn.sendall(PONG)
        return
    while conn.recv(4096):
        pass


def _read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
    return data.split(b"\r\n", 1)[0].decode("latin-1")


def _handle(kind, conn, log_path):
    try:
        if kind in ("relay", "relay2"):
            _act_as_relay(conn, log_path)
        elif kind == "silent":
            while conn.recv(4096):
                pass
        elif kind == "other":
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        elif kind == "proxy_ok":
            _log(log_path, "proxy " + _read_request(conn))
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            _act_as_relay(conn, log_path)
        elif kind == "proxy_403":
            _log(log_path, "proxy " + _read_request(conn))
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def _serve(kind, listener, log_path):
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=_handle, args=(kind, conn, log_path), daemon=True).start()


def start(log_path=""):
    """Start every behaviour in daemon threads; returns {kind: port}."""
    ports = {}
    for kind in ("relay", "relay2", "silent", "other", "proxy_ok", "proxy_403"):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        ports[kind] = listener.getsockname()[1]
        threading.Thread(target=_serve, args=(kind, listener, log_path), daemon=True).start()

    # Bound but never listening: a connection is refused, and the port stays ours
    # (bind-then-close would free it for any other listener on this host - another
    # test worker's fake relay took it once).
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    ports["closed"] = closed.getsockname()[1]
    start._closed = closed

    if sys.platform.startswith("linux"):
        hole = socket.socket()
        hole.bind(("127.0.0.1", 0))
        hole.listen(0)
        ports["blackhole"] = hole.getsockname()[1]
        start._keep = [hole]
        # Fill the accept queue; with it full, Linux drops further SYNs.
        for _ in range(4):
            filler = socket.socket()
            filler.setblocking(False)
            try:
                filler.connect(("127.0.0.1", ports["blackhole"]))
            except (BlockingIOError, OSError):
                pass
            start._keep.append(filler)
    return ports


if __name__ == "__main__":
    print(json.dumps(start(sys.argv[1] if len(sys.argv) > 1 else "")), flush=True)
    sys.stdin.read()
