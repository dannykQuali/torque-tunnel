"""A local Piping Server for the tests (the real one: https://ppng.io, nwtgck/piping-server).

Same rendezvous as the real server: a PUT/POST and a GET of the same path meet, in either
order; the server streams the sender's body to the receiver and stores nothing. The
sender gets the real server's progress lines ("[INFO] Waiting for 1 receiver(s)...",
"... received successfully."). GET /version answers.

Test hooks:
- every relayed stream is logged (path, byte count, first 64 bytes in hex - all of a
  small body) to the log file named on the command line, so a test can check exactly
  what went through;
- argv[2], optional: comma-separated path suffixes whose FIRST transfer is cut after
  1000 bytes (both connections dropped), to exercise chunk retries.

Run as a script (inside WSL for the bash tests; Windows reaches it through WSL's
localhost forwarding): prints {"port": N} as one JSON line, then serves until stdin
closes. Python 3.8 compatible, standard library only.
"""

import http.server
import json
import queue
import socketserver
import sys
import threading

LOG = sys.argv[1] if len(sys.argv) > 1 else ""
FAIL_ONCE = set(filter(None, (sys.argv[2] if len(sys.argv) > 2 else "").split(",")))
_failed = set()
_slots = {}
_cond = threading.Condition()


def _log(line):
    if LOG:
        with open(LOG, "a") as f:
            f.write(line + "\n")


class _Slot:
    def __init__(self):
        self.sender = False
        self.receiver = False
        self.q = queue.Queue(maxsize=64)
        self.done = threading.Event()
        self.cut = threading.Event()


def _slot(path):
    slot = _slots.get(path)
    if slot is None:
        slot = _slots[path] = _Slot()
    return slot


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body_pieces(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                line = self.rfile.readline().strip()
                size = int(line.split(b";")[0] or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    return
                data = self.rfile.read(size)
                self.rfile.readline()
                yield data
        else:
            left = int(self.headers.get("Content-Length") or 0)
            while left > 0:
                data = self.rfile.read(min(65536, left))
                if not data:
                    return
                left -= len(data)
                yield data

    def do_PUT(self):
        path = self.path
        with _cond:
            slot = _slot(path)
            if slot.sender:
                self.send_error(400, "a sender is already connected to this path")
                return
            slot.sender = True
            _cond.notify_all()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"[INFO] Waiting for 1 receiver(s)...\n")
        self.wfile.flush()
        with _cond:
            _cond.wait_for(lambda: slot.receiver)
        self.wfile.write(b"[INFO] A receiver was connected.\n[INFO] Start sending to 1 receiver(s)!\n")
        self.wfile.flush()
        cut_here = any(path.endswith(s) for s in FAIL_ONCE) and path not in _failed
        total, head = 0, b""
        try:
            for piece in self._body_pieces():
                if cut_here and total + len(piece) > 1000:
                    _failed.add(path)
                    slot.cut.set()
                    slot.q.put(None)
                    _log(f"CUT {path} after {total}")
                    self.close_connection = True
                    return
                if len(head) < 64:
                    head += piece[:64 - len(head)]
                total += len(piece)
                slot.q.put(piece)
        finally:
            if not slot.cut.is_set():
                slot.q.put(None)
        slot.done.wait(60)
        _log(f"RELAY {path} {total} {head.hex()}")
        self.wfile.write(b"[INFO] Sent successfully!\n[INFO] All receiver(s) was/were received successfully.\n")
        self.wfile.flush()
        self.close_connection = True

    do_POST = do_PUT

    def do_GET(self):
        if self.path == "/version":
            body = b"0.0.0-fake\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        path = self.path
        with _cond:
            slot = _slot(path)
            if slot.receiver:
                self.send_error(400, "a receiver is already connected to this path")
                return
            slot.receiver = True
            _cond.notify_all()
            _cond.wait_for(lambda: slot.sender)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            while True:
                piece = slot.q.get()
                if piece is None:
                    break
                self.wfile.write(piece)
            self.wfile.flush()
        finally:
            with _cond:
                if _slots.get(path) is slot:
                    del _slots[path]
            slot.done.set()
        self.close_connection = True


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(log="", fail_once=""):
    """In-process (tests on the bash host): returns the port."""
    global LOG, FAIL_ONCE
    LOG, FAIL_ONCE = log, set(filter(None, fail_once.split(",")))
    server = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


if __name__ == "__main__":
    server = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"port": server.server_address[1]}), flush=True)
    sys.stdin.read()
