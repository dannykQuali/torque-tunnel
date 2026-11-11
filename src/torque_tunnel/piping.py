"""Piping Server transport: this machine's side (see docs/piping-transport.md).

Where croc's relay ports are blocked, a staging directory moves through a public Piping
Server (https://ppng.io by default) over plain HTTPS:
- tar + gzip -1, then encrypted with the transfer's code (OpenSSL `enc -aes-256-ctr
  -pbkdf2` format, so the agents' `openssl` reads and writes the same thing);
- split into chunks sent over parallel streams, since the server limits each
  connection;
- checked end to end with sha256 of the plaintext archive.

The agent side is bash (croc_manager.generate_piping_*); both follow this protocol:
  <base>-hello  the constant line "hello"; sent first; waits for a receiver. Collecting
                it is the receiver's choice of this transport.
  <base>-<i>    chunk i (CHUNK_BYTES each) of the encrypted archive
where <base> = "tt-" + the code's path token. Only those cross the Piping Server: no
key, nothing derived from the key, no hash and no size. The archive's size and sha256
travel through Torque instead (the sender's log, or the receiver's commands), so the
receiver checks what it got against a reference the server never saw.

The code (croc_manager.generate_croc_code, 2048 random bits, secret: a sensitive input)
splits into a key (~1854 bits) and an independent path token (192 bits; split_code).
croc uses the whole code; the Piping Server sees only the token, which reveals nothing
of the key.
"""

import asyncio
import gzip
import hashlib
import os
import re
import tarfile
import tempfile
from typing import Callable, Optional

DEFAULT_PIPING_SERVER = "https://ppng.io"
CHUNK_BYTES = 16 * 1024 * 1024
STREAMS = 8
CHUNK_RETRIES = 3
CHECK_TIMEOUT_SECONDS = 6
# How long a side waits for its partner at one path before giving up. The receiver of a
# transfer is a Torque environment launched after the sender is ready: minutes.
RENDEZVOUS_TIMEOUT_SECONDS = 3600
# PBKDF2-HMAC-SHA256 rounds (openssl enc -pbkdf2 -iter). The key is 2048 random bits, so
# this is defence in depth, not what makes it strong.
PBKDF2_ITERATIONS = 100000
# The Piping Server's last line to a sender whose receiver got everything
SENT_OK = "received successfully"
HELLO = b"hello\n"
# How the transfer code (croc_manager.generate_croc_code: secrets.token_urlsafe(256), 342
# characters, each 6 independent random bits but the last) is split: the path token is
# the 32 characters before the last one (192 bits); the key is everything before them
# (309 characters, about 1854 bits). Disjoint random bits, so the token, which the Piping Server sees,
# reveals nothing of the key. croc keeps using the whole code, unchanged.
PATH_TOKEN_CHARS = 32
_MIN_CODE_CHARS = 128
_SERVER_RE = re.compile(r"^https?://[A-Za-z0-9._\-\[\]:]+(/[A-Za-z0-9._\-/]*)?$")
_IO_PIECE = 1024 * 1024


def split_code(code: str) -> tuple[str, str]:
    """(key, path token) of a transfer code. ValueError for a code too short to hold a
    strong key and an independent token: nothing else may stand in for them."""
    code = code or ""
    if len(code) < _MIN_CODE_CHARS or not re.fullmatch(r"[A-Za-z0-9_\-]+", code):
        raise ValueError("the transfer code is too short for the Piping Server transport")
    return code[:-(PATH_TOKEN_CHARS + 1)], code[-(PATH_TOKEN_CHARS + 1):-1]


def chunk_count(size: int, chunk_bytes: int = CHUNK_BYTES) -> int:
    return max(1, -(-size // chunk_bytes))


def validate_server(server: str) -> str:
    """The server URL without a trailing slash; ValueError for anything else."""
    server = (server or DEFAULT_PIPING_SERVER).strip().rstrip("/")
    if not _SERVER_RE.match(server):
        raise ValueError(f"Invalid piping_server {server!r}: expected http(s)://host[:port][/path]")
    return server


def base_path(code: str) -> str:
    return "tt-" + split_code(code)[1]


def check_server(server: str = "", timeout: float = CHECK_TIMEOUT_SECONDS) -> str:
    """"" when the Piping Server answers from this machine, else why not. Never raises."""
    import httpx
    try:
        url = validate_server(server) + "/version"
    except ValueError as e:
        return str(e)
    try:
        response = httpx.get(url, timeout=timeout)
    except httpx.TimeoutException:
        return f"the Piping Server {url[:-8]} did not answer within {timeout:g} s"
    except httpx.HTTPError as e:
        return f"could not reach the Piping Server {url[:-8]}: {e}"
    if response.status_code != 200:
        return f"the Piping Server {url[:-8]} answered HTTP {response.status_code}"
    return ""


# --- OpenSSL `enc -aes-256-ctr -pbkdf2` compatible encryption ---------------------------

def _key_iv(code: str, salt: bytes) -> tuple[bytes, bytes]:
    """AES key and IV from the code's KEY part, as `openssl enc -aes-256-ctr -pbkdf2
    -iter PBKDF2_ITERATIONS -pass env:...` derives them (the path token is not used)."""
    passphrase = split_code(code)[0]
    derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, PBKDF2_ITERATIONS, 48)
    return derived[:32], derived[32:]


def _ctr(code: str, salt: bytes):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key, iv = _key_iv(code, salt)
    return Cipher(algorithms.AES(key), modes.CTR(iv))


class _HashEncryptWriter:
    """File-like sink: hashes the plaintext written to it, encrypts it to ``out``."""

    def __init__(self, out, code: str):
        salt = os.urandom(8)
        self._out = out
        self._enc = _ctr(code, salt).encryptor()
        self.sha256 = hashlib.sha256()
        out.write(b"Salted__" + salt)

    def write(self, data):
        self.sha256.update(data)
        self._out.write(self._enc.update(bytes(data)))
        return len(data)

    def flush(self):
        self._out.flush()

    def finish(self):
        self._out.write(self._enc.finalize())


def build_archive(source_dir: str, cipher_path: str, code: str) -> str:
    """tar (the directory's entries; links kept as links) | gzip -1 | encrypt, into
    ``cipher_path``. Returns the sha256 hex of the plaintext archive (tar.gz)."""
    with open(cipher_path, "wb") as out:
        sink = _HashEncryptWriter(out, code)
        with gzip.GzipFile(fileobj=sink, mode="wb", compresslevel=1, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w|", format=tarfile.GNU_FORMAT) as tar:
                for name in sorted(os.listdir(source_dir)):
                    tar.add(os.path.join(source_dir, name), arcname=name)
        sink.finish()
    return sink.sha256.hexdigest()


class _DecryptHashReader:
    """File-like source: decrypts ``cipher`` and hashes the plaintext it returns."""

    def __init__(self, cipher, code: str):
        header = cipher.read(16)
        if len(header) != 16 or not header.startswith(b"Salted__"):
            raise ValueError("the received data is not an encrypted torque-tunnel archive")
        self._in = cipher
        self._dec = _ctr(code, header[8:]).decryptor()
        self.sha256 = hashlib.sha256()

    def read(self, size=-1):
        data = self._dec.update(self._in.read(size if size and size > 0 else _IO_PIECE))
        self.sha256.update(data)
        return data

    def drain(self):
        while self.read(_IO_PIECE):
            pass


def _safe_extract(tar: tarfile.TarFile, dest: str) -> None:
    if hasattr(tarfile, "tar_filter"):
        # "tar": refuses absolute and ../ member names, keeps any symlink target (a
        # downloaded directory may hold links to absolute paths on the agent)
        tar.extractall(dest, filter="tar")
        return
    for member in tar:   # Python without extraction filters (< 3.10.12 / 3.11.4)
        name = member.name
        if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/"):
            raise ValueError(f"refusing archive member {name!r}")
        tar.extract(member, dest)


def extract_archive(cipher_path: str, dest_dir: str, code: str, expected_sha256: str) -> None:
    """Decrypt, verify the plaintext's sha256, gunzip and untar into ``dest_dir``."""
    with open(cipher_path, "rb") as cipher:
        reader = _DecryptHashReader(cipher, code)
        with gzip.GzipFile(fileobj=reader, mode="rb") as gz:
            with tarfile.open(fileobj=gz, mode="r|") as tar:
                _safe_extract(tar, dest_dir)
        reader.drain()   # the gzip trailer may leave bytes unread; hash them too
    got = reader.sha256.hexdigest()
    if got != expected_sha256:
        raise ValueError(f"archive checksum mismatch (sha256 {got}, expected {expected_sha256})")


# --- Network ------------------------------------------------------------------------

def _client(timeout: Optional[float] = None):
    import httpx
    # No read timeout by default: a request waits for its partner at the server.
    return httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=30))


async def _put(client, url: str, content, deadline: float, retry: bool = True) -> None:
    """PUT; the server holds it until the partner shows up. With ``retry`` a connection
    that drops (while waiting) is retried until ``deadline``; without, one attempt."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            body = content() if callable(content) else content
            response = await client.put(url, content=body)
            # The server answers 200 at once and reports the outcome in the body; only
            # its last line says the receiver got everything.
            if response.status_code == 200 and SENT_OK in response.text:
                return
            problem = f"HTTP {response.status_code}: {response.text.strip()[-200:]}"
        except Exception as e:   # connection reset while waiting, etc.
            problem = str(e) or type(e).__name__
        if not retry or loop.time() > deadline:
            raise RuntimeError(f"sending {url.rsplit('/', 1)[-1]} failed: {problem}")
        await asyncio.sleep(2)


async def _get(client, url: str, deadline: float, sink=None) -> bytes:
    """GET; the server holds it until the sender shows up. A small body (``sink`` None)
    is retried until ``deadline``; a streamed one (``sink``) gets one attempt, because
    a retry has to restart where the caller's data started."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            async with client.stream("GET", url) as response:
                if response.status_code == 200:
                    if sink is None:
                        return await response.aread()
                    async for piece in response.aiter_bytes(_IO_PIECE):
                        sink(piece)
                    return b""
                problem = f"HTTP {response.status_code}"
        except Exception as e:
            problem = str(e) or type(e).__name__
        if sink is not None or loop.time() > deadline:
            raise RuntimeError(f"receiving {url.rsplit('/', 1)[-1]} failed: {problem}")
        await asyncio.sleep(2)


async def _parallel(count: int, streams: int, job) -> None:
    semaphore = asyncio.Semaphore(max(1, streams))

    async def one(i):
        async with semaphore:
            await job(i)

    await asyncio.gather(*(one(i) for i in range(count)))


async def send_archive(cipher_path: str, code: str, server: str = "", *,
                       streams: int = STREAMS, chunk_bytes: int = CHUNK_BYTES,
                       on_chosen: Optional[Callable[[], None]] = None,
                       rendezvous_timeout: float = RENDEZVOUS_TIMEOUT_SECONDS) -> None:
    """Offer an archive built by build_archive and send it when a receiver takes it.

    Its size and sha256 must reach the receiver some other way (Torque); only the
    constant hello and the ciphertext chunks cross the server. Waits (on the hello)
    until a receiver chooses this transport; ``on_chosen`` is called then. Cancel the
    task to withdraw the offer (the receiver chose croc).
    """
    server = validate_server(server)
    base = f"{server}/{base_path(code)}"
    loop = asyncio.get_running_loop()
    size = os.path.getsize(cipher_path)
    async with _client() as client:
        await _put(client, f"{base}-hello", HELLO, loop.time() + rendezvous_timeout)
        if on_chosen:
            on_chosen()

        async def chunk(i):
            offset, length = i * chunk_bytes, min(chunk_bytes, size - i * chunk_bytes)

            async def body():
                with open(cipher_path, "rb") as f:
                    f.seek(offset)
                    left = length
                    while left > 0:
                        piece = f.read(min(_IO_PIECE, left))
                        if not piece:
                            break
                        left -= len(piece)
                        yield piece

            await _put_with_retries(client, f"{base}-{i}", body, loop, rendezvous_timeout)

        await _parallel(chunk_count(size, chunk_bytes), streams, chunk)


async def _put_with_retries(client, url, body, loop, rendezvous_timeout):
    """A chunk: one attempt at a time, CHUNK_RETRIES in all; the receiver retries the
    same path in step."""
    for attempt in range(CHUNK_RETRIES):
        try:
            await _put(client, url, body, loop.time() + rendezvous_timeout, retry=False)
            return
        except RuntimeError:
            if attempt == CHUNK_RETRIES - 1:
                raise
            await asyncio.sleep(2)


async def receive_dir(dest_dir: str, code: str, server: str = "", archive=None, *,
                      streams: int = STREAMS, chunk_bytes: int = CHUNK_BYTES,
                      rendezvous_timeout: float = RENDEZVOUS_TIMEOUT_SECONDS) -> None:
    """Take the sender's piping offer and receive its directory into ``dest_dir``.

    ``archive`` is the sender's ``(cipher bytes, sha256 of the plaintext archive)``,
    known through Torque, never through the server: a tuple, or a callable returning
    one (or None while it has not arrived yet; it is polled after the hello). Raises
    RuntimeError / ValueError with the reason on any failure (a chunk that never
    arrives, a size or checksum mismatch, an archive that does not decrypt).
    """
    server = validate_server(server)
    base = f"{server}/{base_path(code)}"
    loop = asyncio.get_running_loop()
    async with _client() as client:
        await _get(client, f"{base}-hello", loop.time() + rendezvous_timeout)
        deadline = loop.time() + rendezvous_timeout
        info = archive() if callable(archive) else archive
        while info is None:
            if loop.time() > deadline:
                raise RuntimeError("the sender's archive size and checksum never arrived through Torque")
            await asyncio.sleep(0.5)
            info = archive() if callable(archive) else archive
        size, sha = int(info[0]), str(info[1])
        if size <= 0 or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError(f"unusable archive description from the sender: {info!r}")
        count = chunk_count(size, chunk_bytes)
        fd, cipher_path = tempfile.mkstemp(prefix="tt_piping_", suffix=".enc")
        os.close(fd)
        try:
            with open(cipher_path, "r+b") as f:
                f.truncate(size)

            async def chunk(i):
                offset, length = i * chunk_bytes, min(chunk_bytes, size - i * chunk_bytes)
                problem = ""
                for attempt in range(CHUNK_RETRIES):
                    written = 0
                    with open(cipher_path, "r+b") as f:
                        f.seek(offset)

                        def sink(piece):
                            nonlocal written
                            if written + len(piece) > length:
                                raise RuntimeError(f"chunk {i} is longer than {length} bytes")
                            f.write(piece)
                            written += len(piece)

                        try:
                            await _get(client, f"{base}-{i}", loop.time() + rendezvous_timeout, sink)
                            problem = "" if written == length else \
                                f"chunk {i} arrived incomplete ({written} of {length} bytes)"
                        except RuntimeError as e:
                            problem = str(e)
                    if not problem:
                        return
                    if attempt < CHUNK_RETRIES - 1:
                        await asyncio.sleep(2)
                raise RuntimeError(problem)

            await _parallel(count, streams, chunk)
            await asyncio.to_thread(extract_archive, cipher_path, dest_dir, code, sha)
        finally:
            os.remove(cipher_path)
