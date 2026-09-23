"""
Cross-platform croc binary management and file transfer orchestration.

Croc (https://github.com/schollz/croc) is used for transferring files that exceed
the Torque API inline payload limits (~300KB compressed). It provides:
- End-to-end encryption via PAKE (Password-Authenticated Key Exchange)
- Cross-platform support (Windows, macOS, Linux)
- Relay-based transfer (no direct connectivity needed between sender/receiver)

Architecture:
- Local machine runs `croc send --code <secret> --no-local <file>` in background
- Remote machine (agent container) runs `croc --yes` to receive
- For SSH targets: agent container receives via croc, then SCPs to the target
- The croc code is a 2048-bit cryptographically secure random token (secrets.token_urlsafe(256))

Benchmarks (from Cisco proxy network):
- Remote croc install via 7 parallel curl chunks: ~2.1 seconds
- Threshold for croc vs inline base64: ~300KB compressed
"""

import asyncio
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

# Pin to a known stable version
CROC_VERSION = "v10.4.2"

# Files with compressed size above this use croc instead of inline base64.
# Empirically tested: Torque API returns 413 at ~600KB, shell grain hangs at ~450KB.
# 300KB gives a safe margin.
CROC_THRESHOLD_BYTES = 300 * 1024  # 300KB compressed

# Number of parallel curl chunks for fast remote install.
# Benchmarked 1-40 chunks; 7 chunks is the sweet spot at ~2.1s average.
REMOTE_INSTALL_CHUNKS = 7

# How long to wait for croc to register with the relay before launching the remote receive
CROC_SEND_STARTUP_SECONDS = 3

# The public relay answers with this literal when its admission limiter rejects a
# join (croc master, src/tcp/tcp.go: sendAdmission("rate limited")); croc then
# prints "could not connect to <relay>: got bad response: rate limited" and exits 1.
CROC_RATE_LIMIT_MARKER = "rate limited"

# The limiter is keyed on the sender's EXACT public IP: 30 joins per rolling
# minute (src/tcp/defaults.go — DEFAULT_SOURCE_JOIN_LIMIT / DEFAULT_JOIN_LIMIT_WINDOW).
# One `croc send` costs roughly four joins (the control connection plus the
# --transfers parallel streams), so a single IP sustains only ~7-8 transfers per
# minute, shared by every session behind it. Measured 2026-09-17: 8 sends from a
# cold window succeeded, the 9th was rejected. A failed attempt still spends its
# joins, so retries back off past the rolling window instead of hammering.
# The pinned client has no limiter of its own, so it only ever sees the rejection.
CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS = (20, 45, 70)

# How much of croc's captured output is quoted back in an error message. croc
# redraws progress with \r and can produce megabytes; only the tail is useful.
CROC_OUTPUT_TAIL_BYTES = 4096

# The same limiter applies to the RECEIVING side, keyed on the agent container's
# egress IP — which behind a corporate NAT is shared by everything on it. Without
# a retry there, one rejection failed the whole upload with nothing but
# "croc file receive failed (exit code: 1)".
CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS = (20, 45, 70)

# How long the croc receive retry loop waits between attempts.
# Croc exits immediately when no sender room exists; this controls the retry interval.
CROC_RECEIVE_RETRY_SECONDS = 5

# --- Download (remote→local) coordination protocol ---
# The remote croc-send wrapper emits these sentinel lines on stdout. They reach the
# local machine through the streamed grain log, where DownloadPlan.observe_output
# (mcp_tool) parses them and coordinates the local receiver via signal files.
# This implements a sender-first handshake: the local receiver does not connect to
# the relay until the sender's room is registered, which eliminates the PAKE race
# ("could not secure channel") that receiver-first retry loops can trigger.
CROC_SENTINEL_READY = "__CROC_SEND_READY__"    # croc send registered its relay room
CROC_SENTINEL_RETRY = "__CROC_SEND_RETRY__"    # sender is about to restart croc send
CROC_SENTINEL_SIZE = "__CROC_DL_SIZE__"        # "<sentinel> <bytes> <croc_filename>"
CROC_SENTINEL_MD5 = "__CROC_DL_MD5__"          # "<sentinel> <md5hex> <croc_filename>"
CROC_SENTINEL_FAILED = "__CROC_DL_FAILED__"    # sender gave up (after one retry)
CROC_SENTINEL_DONE = "__CROC_DL_DONE__"        # sender finished (rc 0/124/137)

# Signal files inside the local receive dir (dot-prefixed so the received-files
# checks ignore them). Written by the local sentinel watcher, read by the
# receive retry wrapper. The manifest maps croc_filename ->
# {"size": bytes|None, "md5": hex|None}. MD5 verification is essential: croc
# pre-sizes the destination file and writes ranges in parallel, so a dead
# transfer leaves a file with the CORRECT length full of holes — size checks
# alone accepted a 2.3 GB VMDK that was 72.8% zeros (2026-07-29 incident).
CROC_READY_SIGNAL = ".croc_send_ready"
CROC_ABORT_SIGNAL = ".croc_abort"
CROC_EXPECTED_SIZES_FILE = ".croc_expected_manifest.json"
CROC_RECEIVE_LOG_FILE = ".croc_receive.log"

# Delay before the remote sender retries croc send after a failure. Gives the local
# watcher time to observe CROC_SENTINEL_RETRY (log stream polls every few seconds)
# and pull the ready signal so the receiver doesn't race the re-registration.
CROC_SEND_RETRY_DELAY_SECONDS = 8

# Minimum assumed relay transfer rate used to scale the remote croc-send timeout
# with the staged payload size. Observed relay rates in the Cisco lab are
# 3-12 MB/s; 1 MB/s keeps a generous margin without letting croc hang forever.
CROC_SEND_MIN_RATE_BYTES_PER_SEC = 1_000_000

# Croc reliably hangs after 100% when sending through a proxy relay. The send
# monitor kills it once its progress line has sat unchanged at 100% for this
# many consecutive 5-second checks (9 => ~45s) — without this, a size-scaled
# timeout would let a multi-GB download hang for its full remaining budget
# after the transfer already completed.
CROC_SEND_STALL_CHECKS = 9

# A transfer can also freeze MID-flight (observed live: 25 minutes at 87% —
# the proxy silently killed the long-lived relay tunnel). If the progress line
# (containing a percentage below 100%) is unchanged for this many consecutive
# 5-second checks (24 => ~120s), croc is killed and the send is RETRIED —
# croc can usually resume from the receiver's partial file. Only lines with a
# percentage count: the pre-transfer "Sending ..." wait (receiver gated on
# sentinel delivery) can legitimately last minutes and must not trip this.
CROC_SEND_MIDSTALL_CHECKS = 24


def _get_cache_dir() -> Path:
    """Get platform-appropriate cache directory for the croc binary."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "torque-tunnel" / "bin"


def _get_croc_binary_name(version: str = CROC_VERSION) -> str:
    """Return the platform- and version-specific cached croc binary name.

    The version is embedded in the filename so that bumping CROC_VERSION
    invalidates the cache: both sides must run the same croc version for the
    PAKE handshake to succeed, and a stale cached binary would fail it with
    the same "could not secure channel" symptom as the receiver race.
    """
    suffix = ".exe" if sys.platform == "win32" else ""
    return f"croc-{version}{suffix}"


def _get_croc_asset_name(version: str = CROC_VERSION) -> tuple[str, str]:
    """Get the croc release asset filename and download URL for the current platform.

    Returns:
        Tuple of (asset_filename, download_url)

    Raises:
        RuntimeError: If the current platform is not supported.
    """
    system = platform.system()
    machine = platform.machine().lower()

    arch_map = {
        ("Windows", "amd64"): "Windows-64bit",
        ("Windows", "x86_64"): "Windows-64bit",
        ("Windows", "arm64"): "Windows-ARM64",
        ("Darwin", "x86_64"): "macOS-64bit",
        ("Darwin", "arm64"): "macOS-ARM64",
        ("Linux", "x86_64"): "Linux-64bit",
        ("Linux", "aarch64"): "Linux-ARM64",
        ("Linux", "arm64"): "Linux-ARM64",
    }

    platform_str = arch_map.get((system, machine))
    if not platform_str:
        raise RuntimeError(
            f"Unsupported platform for croc: {system}/{machine}. "
            f"Supported: {', '.join(f'{s}/{m}' for s, m in arch_map.keys())}"
        )

    ext = "zip" if system == "Windows" else "tar.gz"
    asset = f"croc_{version}_{platform_str}.{ext}"
    url = f"https://github.com/schollz/croc/releases/download/{version}/{asset}"
    return asset, url


def get_local_croc_path() -> Optional[Path]:
    """Get path to local croc binary if it already exists.

    Checks (in order):
    1. Cached download in platform-specific cache directory (version embedded
       in the filename, so the cache can never serve a stale version)
    2. System PATH (only if version matches CROC_VERSION)

    We prefer the cache because the remote side installs CROC_VERSION, and
    both sides must run the same version for the PAKE handshake to succeed.
    """
    # Check cache directory first (versioned filename => guaranteed correct version)
    cache_dir = _get_cache_dir()
    cache_path = cache_dir / _get_croc_binary_name()
    if cache_path.exists():
        return cache_path

    # Clean up binaries from other versions and the old unversioned name
    # (best effort - a stale binary must never be picked up again)
    if cache_dir.exists():
        for stale in cache_dir.glob("croc*"):
            try:
                stale.unlink()
            except OSError:
                pass

    # Check PATH, but only if it's the right version
    croc_in_path = shutil.which("croc")
    if croc_in_path:
        try:
            result = subprocess.run(
                [croc_in_path, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            # Output is like "croc version v10.4.2"
            if CROC_VERSION in result.stdout:
                return Path(croc_in_path)
        except Exception:
            pass  # Can't verify version, skip PATH croc

    return None


async def ensure_local_croc() -> Path:
    """Ensure croc is available locally. Downloads from GitHub releases if needed.

    Returns:
        Path to the croc binary.

    Raises:
        RuntimeError: If download or extraction fails.
    """
    existing = get_local_croc_path()
    if existing:
        return existing

    asset_name, url = _get_croc_asset_name()
    binary_name = _get_croc_binary_name()
    cache_dir = _get_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    target_path = cache_dir / binary_name

    print(
        f"[croc] Downloading croc {CROC_VERSION} for {platform.system()}/{platform.machine()}...",
        file=sys.stderr,
    )

    # Download in thread pool to avoid blocking the event loop
    import urllib.request

    tmp_fd, tmp_path = tempfile.mkstemp(
        suffix=(".zip" if asset_name.endswith(".zip") else ".tar.gz")
    )
    os.close(tmp_fd)

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, urllib.request.urlretrieve, url, tmp_path)

        # Extract croc binary from archive
        if asset_name.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(tmp_path) as zf:
                for name in zf.namelist():
                    if os.path.basename(name).lower() in ("croc", "croc.exe"):
                        with zf.open(name) as src, open(target_path, "wb") as dst:
                            dst.write(src.read())
                        break
                else:
                    raise RuntimeError(f"croc binary not found in archive {asset_name}")
        else:
            import tarfile
            with tarfile.open(tmp_path, "r:gz") as tf:
                for member in tf.getmembers():
                    if os.path.basename(member.name) == "croc":
                        f = tf.extractfile(member)
                        if f:
                            with open(target_path, "wb") as dst:
                                dst.write(f.read())
                            break
                else:
                    raise RuntimeError(f"croc binary not found in archive {asset_name}")

        # Make executable on Unix
        if sys.platform != "win32":
            target_path.chmod(
                target_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )

        print(f"[croc] Installed to {target_path}", file=sys.stderr)
        return target_path
    except Exception as e:
        # Clean up partial download
        if target_path.exists():
            target_path.unlink()
        raise RuntimeError(f"Failed to download/install croc: {e}") from e
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def generate_croc_code() -> str:
    """Generate a 2048-bit cryptographically secure croc transfer code.

    Uses secrets.token_urlsafe(256) which produces ~344 URL-safe characters.
    This is used as the --code parameter for croc send/receive.
    The code serves as the PAKE password for end-to-end encryption.
    """
    return secrets.token_urlsafe(256)


def generate_remote_croc_install_script(version: str = CROC_VERSION) -> str:
    """Generate shell commands to install croc on a remote Linux container.

    Uses 7 parallel curl chunk downloads for speed (~2.1 seconds on tested network).
    Falls back to single-stream download if parallel approach fails.
    Skips installation if croc is already available.

    Returns:
        Multi-line shell script string.
    """
    url = (
        f"https://github.com/schollz/croc/releases/download/{version}"
        f"/croc_{version}_Linux-64bit.tar.gz"
    )
    return f"""# === Fast parallel croc install (~2s with {REMOTE_INSTALL_CHUNKS} chunks) ===
if ! command -v croc &>/dev/null; then
  __CROC_URL="{url}"
  __CROC_FSIZE=$(curl -sI -L "$__CROC_URL" 2>/dev/null | grep -i content-length | tail -1 | tr -dc '0-9')
  if [ -n "$__CROC_FSIZE" ] && [ "$__CROC_FSIZE" -gt 0 ] 2>/dev/null; then
    __CROC_NCHUNKS={REMOTE_INSTALL_CHUNKS}
    __CROC_CHUNK=$(( (__CROC_FSIZE + __CROC_NCHUNKS - 1) / __CROC_NCHUNKS ))
    mkdir -p /tmp/_croc_dl
    for __i in $(seq 0 $((__CROC_NCHUNKS - 1))); do
      __S=$((__i * __CROC_CHUNK))
      __E=$(((__i + 1) * __CROC_CHUNK - 1))
      [ $__E -ge $__CROC_FSIZE ] && __E=$((__CROC_FSIZE - 1))
      curl -sL -r "$__S-$__E" -o "/tmp/_croc_dl/$(printf %04d $__i)" "$__CROC_URL" &
    done
    wait
    cat /tmp/_croc_dl/* | tar xz -C /usr/local/bin croc 2>/dev/null
    rm -rf /tmp/_croc_dl
  else
    # Fallback: single-stream download if size detection fails
    curl -sL "$__CROC_URL" | tar xz -C /usr/local/bin croc
  fi
  export PATH="/usr/local/bin:$PATH"
  if ! command -v croc &>/dev/null; then
    echo "ERROR: Failed to install croc" >&2
    exit 1
  fi
fi
# === End croc install ==="""


def _shell_escape_single(s: str) -> str:
    """Escape a string for use inside single quotes in shell."""
    return s.replace("'", "'\\''")


# A relay address is interpolated unquoted into generated shell, so it is
# restricted to what a host:port can legitimately contain (including the
# bracketed IPv6 form) rather than escaped.
_RELAY_ADDRESS_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]+$")


def _validate_relay(relay: str) -> str:
    """Return the relay address, rejecting anything that isn't a plain host:port."""
    if not relay:
        return ""
    if not _RELAY_ADDRESS_RE.match(relay):
        raise ValueError(
            f"Invalid croc relay address {relay!r}: expected host:port "
            f"(letters, digits, '.', '-', '_', ':' and IPv6 brackets only)"
        )
    return relay


def _relay_env_export(relay_password: str) -> list[str]:
    """Shell lines exporting the relay password, or nothing when unset.

    The password goes through the environment rather than croc's ``--pass`` flag
    so it never shows up in the container's process list.
    """
    if not relay_password:
        return []
    return [f"export CROC_PASS='{_shell_escape_single(relay_password)}'"]


def _croc_global_flags(relay: str) -> str:
    """croc's GLOBAL options for a relay override — these must precede any subcommand."""
    return f"--relay {_validate_relay(relay)} " if relay else ""


# Scratch files the receive retry loop uses inside the croc receive directory.
# Dot-prefixed so they can never collide with a received file.
_RECEIVE_RC_FILE = ".croc_recv.rc"
_RECEIVE_LOG_FILE = ".croc_recv.log"


def generate_croc_receive_attempt(code: str, timeout: int, relay: str = "") -> list[str]:
    """Shell lines that receive via croc, retrying while the relay rate-limits us.

    Sets ``__CROC_RC`` to croc's exit code. croc's output still reaches stdout
    (through ``tee``) so transfer progress stays visible in the streamed grain
    log; the copy on disk is only there so the loop can tell a rate-limit
    rejection apart from a real failure.

    Must run with the croc receive directory as the working directory.
    """
    waits = list(CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS) + ["final"]
    return [
        '__CROC_RC=1',
        f'for __CROC_WAIT in {" ".join(str(w) for w in waits)}; do',
        f'  rm -f {_RECEIVE_RC_FILE} {_RECEIVE_LOG_FILE}',
        # The exit code goes through a file because the pipe into tee would
        # otherwise hide it, and PIPESTATUS is not portable to a plain sh grain.
        f'  {{ timeout {timeout} bash -c \'CROC_SECRET="{code}" '
        f'croc {_croc_global_flags(relay)}--yes --overwrite\'; '
        f'echo $? > {_RECEIVE_RC_FILE}; }} 2>&1 | tee {_RECEIVE_LOG_FILE}',
        f'  __CROC_RC=$(cat {_RECEIVE_RC_FILE} 2>/dev/null || echo 1)',
        '  [ "$__CROC_RC" = "0" ] && break',
        f'  grep -q "{CROC_RATE_LIMIT_MARKER}" {_RECEIVE_LOG_FILE} 2>/dev/null || break',
        '  [ "$__CROC_WAIT" = "final" ] && break',
        '  echo "[croc receive] relay rate-limited this host; retrying in ${__CROC_WAIT}s"',
        '  sleep "$__CROC_WAIT"',
        'done',
        f'rm -f {_RECEIVE_RC_FILE} {_RECEIVE_LOG_FILE}',
    ]


# croc prints the transfer code on startup ("Code is: ...", plus ready-made
# receive commands containing it). That code IS the PAKE password, so it must
# never reach an error message or a log. The remote send wrapper strips the same
# lines from the streamed grain log; this is the local equivalent.
_CROC_SECRET_LINE_MARKERS = (
    "CROC_SECRET=",
    "Code is:",
    "On the other computer",
    "(For ",
    "Code copied to clipboard",
)


def _is_progress_line(line: str) -> bool:
    """True for croc's redrawn progress bars, e.g. `x... 65% |####  | (655 kB/1.0 MB)`.

    They carry no diagnostic value and are full of box-drawing characters, which
    a legacy console codepage cannot even encode.
    """
    return "|" in line and "%" in line


def _scrub_croc_output(text: str) -> list[str]:
    """Split croc output into meaningful lines, dropping any that carry the code."""
    lines = []
    for raw in text.replace("\r", "\n").splitlines():
        line = raw.strip()
        if not line or line.startswith("croc ") or _is_progress_line(line):
            continue
        if any(marker in line for marker in _CROC_SECRET_LINE_MARKERS):
            continue
        lines.append(line)
    return lines


def read_croc_output_tail(
    log_path: str,
    limit: int = CROC_OUTPUT_TAIL_BYTES,
    secret: str = "",
    max_lines: int = 6,
) -> str:
    """Read the tail of a croc output capture, scrubbed of the transfer code.

    Returns "" when the file is missing or unreadable — a diagnostic must never
    be the reason a transfer fails.
    """
    try:
        size = os.path.getsize(log_path)
        with open(log_path, "rb") as f:
            if size > limit:
                f.seek(size - limit)
            data = f.read()
    except OSError:
        return ""

    text = data.decode("utf-8", "replace")
    if secret:
        # Belt and braces: the line filters above cover croc's known banner, this
        # covers any line they don't.
        text = text.replace(secret, "<transfer code>")
    return " | ".join(_scrub_croc_output(text)[-max_lines:])


def _remove_quietly(path: str) -> None:
    """Delete a file, ignoring the case where it is already gone or still locked."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _validate_mode(mode: str) -> bool:
    """Validate a Unix file permission mode string (e.g., '755', '0644')."""
    import re
    return bool(re.match(r'^[0-7]{3,4}$', mode))


def generate_croc_receive_commands(
    code: str,
    file_transfers: list[dict],
    timeout: int = 600,
    relay: str = "",
    relay_password: str = "",
) -> str:
    """Generate shell commands to receive files via croc and place them at destinations.

    Args:
        code: The croc secret code (2048-bit).
        file_transfers: List of dicts, each with:
            - croc_filename: The uniquely-prefixed filename as croc will deliver it.
            - remote_destination_path: Where the file should end up on the target.
            - mode: Optional file permissions (e.g. "755"). Must match ^[0-7]{3,4}$.
            - is_dir_tar: If True, the file is a gzipped tar of a directory; extract instead of move.
        timeout: Timeout in seconds for croc receive (default 600s).
        relay: Optional "host:port" of a private relay; must match the sender's.
        relay_password: Optional password for that relay.

    Returns:
        Shell commands string.
    """
    commands = []
    commands.append("# === Croc file receive ===")
    commands.append('__CROC_DIR=$(mktemp -d)')
    commands.append('cd "$__CROC_DIR"')
    commands.extend(_relay_env_export(relay_password))
    # Use CROC_SECRET env var (not command-line arg) to avoid leaking code in process list
    commands.extend(generate_croc_receive_attempt(code, timeout, relay))
    commands.append('if [ $__CROC_RC -ne 0 ]; then')
    commands.append('  echo "ERROR: croc file receive failed (exit code: $__CROC_RC)" >&2')
    commands.append('  rm -rf "$__CROC_DIR"')
    commands.append('  exit 1')
    commands.append('fi')

    for ft in file_transfers:
        croc_name = ft["croc_filename"]
        dest = ft["remote_destination_path"]
        mode = ft.get("mode")
        is_dir_tar = ft.get("is_dir_tar", False)

        escaped_dest = _shell_escape_single(dest)
        escaped_croc_name = _shell_escape_single(croc_name)
        dest_dir = os.path.dirname(dest)

        if is_dir_tar:
            # Directory was tarred on send; extract into destination
            commands.append(f"mkdir -p '{escaped_dest}'")
            commands.append(f'tar xzf "$__CROC_DIR/"\'{escaped_croc_name}\' -C \'{escaped_dest}\'')
        else:
            if dest_dir:
                escaped_dir = _shell_escape_single(dest_dir)
                commands.append(f"mkdir -p '{escaped_dir}'")
            commands.append(f'mv "$__CROC_DIR/"\'{escaped_croc_name}\' \'{escaped_dest}\'')

        if mode and _validate_mode(mode):
            commands.append(f"chmod {mode} '{escaped_dest}'")

    commands.append('rm -rf "$__CROC_DIR"')
    if relay_password:
        # These lines are prepended to the user's own commands; don't leave the
        # relay password in their environment.
        commands.append("unset CROC_PASS")
    commands.append("# === End croc file receive ===")
    return "\n".join(commands)


def generate_croc_scp_commands(
    code: str,
    file_transfers: list[dict],
    target_ip: str,
    ssh_user: str,
    ssh_private_key: str = "",
    ssh_password: str = "",
    timeout: int = 600,
    relay: str = "",
    relay_password: str = "",
) -> str:
    """Generate shell commands to receive files via croc on the CONTAINER, then SCP to SSH target.

    This is used for SSH tool uploads where files exceed the inline threshold:
    1. Install croc on the agent container
    2. Receive files from local machine via croc relay
    3. SCP each file from the container to the SSH target (directories are tar-piped)
    4. Clean up

    Args:
        code: The croc secret code.
        file_transfers: List of dicts with croc_filename, remote_destination_path, mode, is_dir_tar.
        target_ip: SSH target IP/hostname.
        ssh_user: SSH username.
        ssh_private_key: SSH private key content (PEM format).
        ssh_password: SSH password (alternative to key).
        timeout: Timeout in seconds for croc receive (default 600s).
        relay: Optional "host:port" of a private relay; must match the sender's.
        relay_password: Optional password for that relay.

    Returns:
        Shell commands string to run on the agent container (not on the target).
    """
    commands = []
    commands.append("# === Croc receive + SCP to target ===")

    escaped_target = _shell_escape_single(target_ip)
    escaped_user = _shell_escape_single(ssh_user)
    ssh_target = f"'{escaped_user}'@'{escaped_target}'"

    # Set up SSH auth for SCP
    scp_prefix = ""
    scp_auth = ""
    if ssh_private_key:
        commands.append('__SCP_KEY=$(mktemp)')
        commands.append("cat << '__SCP_KEYEOF' > \"$__SCP_KEY\"")
        commands.append(ssh_private_key)
        commands.append("__SCP_KEYEOF")
        commands.append('chmod 600 "$__SCP_KEY"')
        scp_auth = '-i "$__SCP_KEY"'
    elif ssh_password:
        # Install sshpass if needed
        escaped_pw = _shell_escape_single(ssh_password)
        commands.append("if ! command -v sshpass &>/dev/null; then")
        commands.append("  apt-get install -y -qq sshpass >/dev/null 2>&1 \\")
        commands.append("    || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq sshpass >/dev/null 2>&1; }")
        commands.append("fi")
        scp_prefix = f"sshpass -p '{escaped_pw}'"
    else:
        raise ValueError("Either ssh_private_key or ssh_password is required for SCP")

    pubkey_opt = "" if ssh_private_key else "-o PubkeyAuthentication=no"

    # Receive files via croc
    commands.append('__CROC_DIR=$(mktemp -d)')
    commands.append('cd "$__CROC_DIR"')
    commands.extend(_relay_env_export(relay_password))
    commands.extend(generate_croc_receive_attempt(code, timeout, relay))
    commands.append('if [ $__CROC_RC -ne 0 ]; then')
    commands.append('  echo "ERROR: croc file receive failed (exit code: $__CROC_RC)" >&2')
    if ssh_private_key:
        commands.append('  rm -f "$__SCP_KEY"')
    commands.append('  rm -rf "$__CROC_DIR"')
    commands.append('  exit 1')
    commands.append('fi')

    # Transfer each file to the target
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
    for ft in file_transfers:
        croc_name = ft["croc_filename"]
        dest = ft["remote_destination_path"]
        mode = ft.get("mode")
        is_dir_tar = ft.get("is_dir_tar", False)
        escaped_dest = _shell_escape_single(dest)
        escaped_croc_name = _shell_escape_single(croc_name)
        dest_dir = os.path.dirname(dest)

        if is_dir_tar:
            # Directory was tarred on send; extract on target via ssh pipe
            commands.append(
                f"{scp_prefix} ssh {ssh_opts} {scp_auth} {pubkey_opt} {ssh_target} "
                f"'mkdir -p '\"'\"'{escaped_dest}'\"'\"' && tar xzf - -C '\"'\"'{escaped_dest}'\"'\"'' "
                f'< "$__CROC_DIR/"\'{escaped_croc_name}\''
                f' || {{ echo "ERROR: Failed to transfer directory to {dest} on target" >&2; exit 1; }}'
            )
        else:
            # Create remote directory if needed
            if dest_dir:
                escaped_dir = _shell_escape_single(dest_dir)
                commands.append(
                    f"{scp_prefix} ssh {ssh_opts} {scp_auth} {pubkey_opt} {ssh_target} "
                    f"\"mkdir -p '{escaped_dir}'\""
                    f' || {{ echo "ERROR: Failed to create directory {dest_dir} on target" >&2; exit 1; }}'
                )

            # SCP the file
            commands.append(
                f'{scp_prefix} scp {ssh_opts} {scp_auth} {pubkey_opt} '
                f'"$__CROC_DIR/"\'{escaped_croc_name}\' {ssh_target}:\'{escaped_dest}\''
                f' || {{ echo "ERROR: SCP failed for {dest}" >&2; exit 1; }}'
            )

        # Set permissions
        if mode and _validate_mode(mode):
            commands.append(
                f"{scp_prefix} ssh {ssh_opts} {scp_auth} {pubkey_opt} {ssh_target} "
                f"\"chmod {mode} '{escaped_dest}'\""
            )

    # Cleanup
    if ssh_private_key:
        commands.append('rm -f "$__SCP_KEY"')
    commands.append('rm -rf "$__CROC_DIR"')
    if relay_password:
        commands.append("unset CROC_PASS")
    commands.append("# === End croc receive + SCP ===")
    return "\n".join(commands)


async def start_croc_send(
    croc_path: Path,
    code: str,
    files: list[str],
    timeout: float = 600,
    relay: str = "",
    relay_password: str = "",
    transfers: Optional[int] = None,
) -> asyncio.subprocess.Process:
    """Start croc send as a background process.

    The process connects to the relay and waits for a receiver. Caller must
    manage the process lifecycle (await completion or cleanup_croc_send).

    croc's output is captured to a temp file rather than discarded, so a startup
    failure can say *why*. It goes to a file and not a pipe because nothing
    drains the pipe while croc runs, and croc's progress output would eventually
    fill the buffer and deadlock it — that deadlock is why this used to be
    DEVNULL, which in turn is why a rate-limited send reported nothing but
    "exited immediately with code 1". The path is stashed on the returned
    process as ``croc_log_path`` and removed by cleanup_croc_send.

    A send rejected by the relay's admission limiter is retried after a backoff
    (see CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS); any other failure raises at once,
    because it will fail identically on a retry.

    Args:
        croc_path: Path to local croc binary.
        code: The croc secret code.
        files: List of local file paths to send.
        timeout: Not used directly; croc will wait for receiver.
        relay: Optional "host:port" of a private relay (default: croc's public one).
        relay_password: Optional password for that relay. Passed via CROC_PASS so
            it never appears in the process list.
        transfers: Optional number of parallel transfer streams. Each stream costs
            a relay admission, so lowering it buys more transfers per minute at
            the price of throughput. None leaves croc's default (4).

    Returns:
        The asyncio subprocess Process handle.

    Raises:
        RuntimeError: If croc exits during startup, with croc's own output.
    """
    cmd = [
        str(croc_path),
        "--yes",       # No interactive prompts (global option, must precede subcommand)
    ]
    if relay:
        cmd += ["--relay", _validate_relay(relay)]  # global option: must precede `send`
    cmd += [
        "send",
        "--no-local",  # Skip local network discovery (we always use the relay)
    ]
    if transfers:
        cmd += ["--transfers", str(transfers)]
    cmd += [str(f) for f in files]

    # Pass secrets via environment variables to avoid exposing them in process list
    env = os.environ.copy()
    env["CROC_SECRET"] = code
    if relay_password:
        env["CROC_PASS"] = relay_password

    log_fd, log_path = tempfile.mkstemp(prefix="torque_croc_send_", suffix=".log")
    os.close(log_fd)

    max_attempts = len(CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS) + 1
    attempt = 0
    while True:
        attempt += 1
        # The handle is closed as soon as croc has inherited it; croc keeps
        # writing through its own copy.
        with open(log_path, "wb") as log:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,  # Prevent parent stdin (e.g. MCP protocol) leaking in
                stdout=log,
                stderr=log,
                env=env,
            )

        # Give croc a few seconds to connect to the relay and register the code
        await asyncio.sleep(CROC_SEND_STARTUP_SECONDS)

        if process.returncode is None:
            # Registered and waiting for the receiver.
            process.croc_log_path = log_path
            return process

        output = read_croc_output_tail(log_path, secret=code)
        rate_limited = CROC_RATE_LIMIT_MARKER in output

        if rate_limited and attempt < max_attempts:
            wait = CROC_SEND_RATE_LIMIT_BACKOFF_SECONDS[attempt - 1]
            print(
                f"[croc] relay rate-limited this IP; retrying in {wait}s "
                f"(attempt {attempt + 1} of {max_attempts})",
                file=sys.stderr,
            )
            await asyncio.sleep(wait)
            continue

        _remove_quietly(log_path)
        message = f"croc send exited immediately with code {process.returncode}"
        if output:
            message += f": {output}"
        if rate_limited:
            message += (
                " - the relay admits about 30 room joins per minute per public IP"
                " and each send costs roughly four, shared with every other session"
                " behind that IP. Wait a minute and retry, or set 'croc_relay' in the"
                " config to a private relay to leave the shared budget behind."
            )
        raise RuntimeError(message)


async def cleanup_croc_send(process: Optional[asyncio.subprocess.Process]) -> None:
    """Clean up a croc send background process and its captured output.

    Safe to call even if process is None or already terminated.
    """
    if process is None:
        return

    # Only a process we started carries this; getattr on anything else (including
    # the mocks other call sites pass) must not be mistaken for a path.
    log_path = getattr(process, "croc_log_path", None)

    try:
        if process.returncode is None:
            try:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            except ProcessLookupError:
                pass  # Process already gone
    finally:
        # Deleting has to wait until croc is gone: Windows refuses to unlink a
        # file the process still holds open.
        if isinstance(log_path, str) and log_path:
            _remove_quietly(log_path)


# --- Download (remote→local) support ---


def _generate_croc_send_core(
    code: str,
    timeout: int,
    cleanup_commands: list[str],
    relay: str = "",
    relay_password: str = "",
    transfers: Optional[int] = None,
) -> list[str]:
    """Shared croc-send block used by both download command generators.

    Expects staged files to already exist in $__DL_DIR. Implements the
    coordination protocol (see CROC_SENTINEL_* constants):

    1. Emits a size sentinel per staged regular file so the local side can
       verify transfer completeness (rejecting partial files).
    2. Runs croc send in the background while tailing its output; emits the
       READY sentinel the moment croc prints "Code is:" (relay room registered).
       The local receiver connects only after that - sender-first by
       construction, so the PAKE handshake can't race a half-open receiver.
    3. Scales the croc-send timeout with the staged payload size (the fixed
       default killed healthy multi-GB transfers mid-flight).
    4. Retries the whole send once on failure (relay flakes), announcing it
       with the RETRY sentinel so the local receiver stands down first.
    5. Ends with an explicit DONE/FAILED sentinel and a non-zero exit on
       failure - a failed download must never look like success.

    Args:
        code: The croc secret code.
        timeout: Minimum (floor) croc send timeout in seconds.
        cleanup_commands: Extra cleanup lines to run after the send (e.g.
            removing a temporary SSH key), before the final status is emitted.
        relay: Optional "host:port" of a private relay; must match the receiver's.
        relay_password: Optional password for that relay (via CROC_PASS).
        transfers: Optional number of parallel transfer streams.

    Returns:
        List of shell command lines (bash).
    """
    c = []
    c.append('cd "$__DL_DIR"')
    # Fail fast if nothing was staged - croc send with no files would just error
    c.append('set -- *')
    c.append('if [ ! -e "$1" ]; then')
    c.append('  echo "ERROR: no files were staged for download" >&2')
    c.append(f'  echo "{CROC_SENTINEL_FAILED} exit_code=stage"')
    c.append('  cd /')
    c.append('  rm -rf "$__DL_DIR"')
    c.extend(f'  {line}' for line in cleanup_commands)
    c.append('  exit 1')
    c.append('fi')
    # Report per-file sizes AND content hashes so the local receiver can verify
    # completeness. Size alone is NOT integrity: croc pre-sizes the destination
    # and writes ranges in parallel, so a dead transfer leaves a size-correct
    # file full of holes.
    c.append('for __DL_F in *; do')
    c.append('  if [ -f "$__DL_F" ]; then')
    c.append(f'    echo "{CROC_SENTINEL_SIZE} $(stat -c %s "$__DL_F") $__DL_F"')
    c.append("    __DL_MD5=$(md5sum \"$__DL_F\" 2>/dev/null | cut -d' ' -f1)")
    c.append(f'    [ -n "$__DL_MD5" ] && echo "{CROC_SENTINEL_MD5} $__DL_MD5 $__DL_F"')
    c.append('  fi')
    c.append('done')
    c.append(f'export CROC_SECRET="{code}"')
    c.extend(_relay_env_export(relay_password))
    croc_send = f"croc {_croc_global_flags(relay)}send --no-local"
    if transfers:
        croc_send += f" --transfers {int(transfers)}"
    # Scale the send timeout with the payload size; `timeout` is the floor
    c.append('__DL_BYTES=$(du -sb . 2>/dev/null | cut -f1)')
    c.append(f'__DL_TIMEOUT=$(( ${{__DL_BYTES:-0}} / {CROC_SEND_MIN_RATE_BYTES_PER_SEC} + 120 ))')
    c.append(f'[ "$__DL_TIMEOUT" -lt {timeout} ] && __DL_TIMEOUT={timeout}')
    c.append('__croc_send_once() {')
    c.append('  set -- *')
    c.append('  : > .croc_send.log')
    # Croc prints the transfer code ("Code is:" / "On the other computer run:"
    # blocks). Keep those OUT of the echoed progress lines so the secret never
    # lands in the persisted grain log (an improvement over the old behavior,
    # which streamed croc's raw output including the code).
    c.append("  __croc_tail() { tr '\\r' '\\n' < .croc_send.log 2>/dev/null"
             " | grep -v -e '^[[:space:]]*$' -e 'CROC_SECRET=' -e 'Code is:'"
             " -e 'On the other computer' -e '(For ' -e '^[[:space:]]*croc '; }")
    # -k 5: SIGKILL 5s after SIGTERM if croc ignores it. Croc sometimes hangs
    # after 100% when going through a proxy relay.
    c.append(f'  timeout -k 5 "$__DL_TIMEOUT" {croc_send} "$@" > .croc_send.log 2>&1 &')
    c.append('  __CROC_PID=$!')
    c.append('  __CROC_READY=0')
    c.append('  __CROC_TICK=0')
    c.append('  __CROC_PREV=""')
    c.append('  __CROC_STALL=0')
    c.append('  __CROC_MIDSTALL=0')
    c.append('  __CROC_STALL_KILL=0')
    c.append('  __CROC_QUIET=0')
    c.append('  while kill -0 "$__CROC_PID" 2>/dev/null; do')
    c.append("    if [ \"$__CROC_READY\" -eq 0 ] && grep -q 'Code is:' .croc_send.log 2>/dev/null; then")
    c.append(f'      echo "{CROC_SENTINEL_READY}"')
    c.append('      __CROC_READY=1')
    c.append('    fi')
    # Surface croc's latest progress line every ~5s (its raw \r-updates would
    # otherwise flood the streamed log or be lost entirely)
    c.append('    if [ "$__CROC_TICK" -gt 0 ] && [ $((__CROC_TICK % 10)) -eq 0 ]; then')
    c.append('      __CROC_LAST=$(__croc_tail | tail -n 1)')
    # Echo only when the progress line changed (a post-100% hang would
    # otherwise repeat the same line every 5s for minutes)
    c.append('      if [ -n "$__CROC_LAST" ] && [ "$__CROC_LAST" != "$__CROC_PREV" ]; then')
    c.append('        echo "[croc send] $__CROC_LAST"')
    c.append('        __CROC_PREV=$__CROC_LAST')
    c.append('        __CROC_STALL=0')
    c.append('        __CROC_MIDSTALL=0')
    c.append('        __CROC_QUIET=0')
    # Progress stuck at 100%: croc's known hang-after-complete-transfer through
    # proxy relays. Kill it instead of burning the remaining (size-scaled)
    # timeout budget; the local side verifies the received sizes regardless.
    c.append('      elif case "$__CROC_LAST" in *100%*) true;; *) false;; esac; then')
    c.append('        __CROC_STALL=$((__CROC_STALL + 1))')
    c.append(f'        if [ "$__CROC_STALL" -ge {CROC_SEND_STALL_CHECKS} ]; then')
    c.append('          echo "[croc send] no progress after 100% - assuming croc hang-after-transfer, terminating"')
    c.append('          kill "$__CROC_PID" 2>/dev/null')
    c.append('        fi')
    # Progress frozen MID-transfer (percentage below 100% unchanged): a wedged
    # relay tunnel. Kill and RETRY - croc can usually resume from the
    # receiver's partial file. Observed live: 25 minutes frozen at 87%.
    c.append('      elif case "$__CROC_LAST" in *%*) true;; *) false;; esac; then')
    c.append('        __CROC_MIDSTALL=$((__CROC_MIDSTALL + 1))')
    c.append('        __CROC_QUIET=$((__CROC_QUIET + 1))')
    c.append(f'        if [ "$__CROC_MIDSTALL" -ge {CROC_SEND_MIDSTALL_CHECKS} ]; then')
    c.append('          echo "[croc send] transfer stalled with no progress - terminating for retry"')
    c.append('          __CROC_STALL_KILL=1')
    c.append('          kill "$__CROC_PID" 2>/dev/null')
    c.append('        elif [ "$__CROC_QUIET" -ge 6 ]; then')
    c.append('          echo "[croc send] still running ($((__CROC_TICK / 2))s): $__CROC_LAST"')
    c.append('          __CROC_QUIET=0')
    c.append('        fi')
    # Heartbeat every ~30s while output is otherwise unchanged: liveness signal
    # for humans, and it keeps the runner shipping log chunks - the local
    # receiver is gated on sentinels arriving through that stream, and a
    # fully quiet log can sit in the runner's buffer for minutes.
    c.append('      else')
    c.append('        __CROC_QUIET=$((__CROC_QUIET + 1))')
    c.append('        if [ "$__CROC_QUIET" -ge 6 ]; then')
    c.append('          echo "[croc send] still running ($((__CROC_TICK / 2))s): $__CROC_LAST"')
    c.append('          __CROC_QUIET=0')
    c.append('        fi')
    c.append('      fi')
    c.append('    fi')
    c.append('    __CROC_TICK=$((__CROC_TICK + 1))')
    c.append('    sleep 0.5')
    c.append('  done')
    c.append('  wait "$__CROC_PID"')
    c.append('  __DL_RC=$?')
    # A mid-transfer stall kill is NOT a post-completion hang: the whitelisted
    # kill codes (124/137/143) must not apply - force failure so the
    # retry/FAILED path runs instead of reporting DONE on a frozen transfer.
    c.append('  if [ "$__CROC_STALL_KILL" -eq 1 ]; then')
    c.append('    __DL_RC=1')
    c.append('  fi')
    # Croc may have registered and exited between monitor polls - emit READY
    # regardless so the local side knows the room existed
    c.append("  if [ \"$__CROC_READY\" -eq 0 ] && grep -q 'Code is:' .croc_send.log 2>/dev/null; then")
    c.append(f'    echo "{CROC_SENTINEL_READY}"')
    c.append('  fi')
    c.append('  __croc_tail | tail -n 3')
    c.append('}')
    c.append('__croc_send_once')
    # Exit codes 124 (timeout SIGTERM), 137 (SIGKILL) and 143 (stall-detection
    # TERM) can mean croc hung after a complete transfer; the local side
    # verifies received sizes either way.
    c.append('if [ $__DL_RC -ne 0 ] && [ $__DL_RC -ne 124 ] && [ $__DL_RC -ne 137 ] && [ $__DL_RC -ne 143 ]; then')
    c.append(f'  echo "{CROC_SENTINEL_RETRY} (first attempt failed with exit code $__DL_RC; retrying once)"')
    c.append(f'  sleep {CROC_SEND_RETRY_DELAY_SECONDS}')
    c.append('  __croc_send_once')
    c.append('fi')
    c.append('unset CROC_SECRET')
    if relay_password:
        c.append('unset CROC_PASS')
    c.append('cd /')
    c.append('rm -rf "$__DL_DIR"')
    c.extend(cleanup_commands)
    c.append('if [ $__DL_RC -ne 0 ] && [ $__DL_RC -ne 124 ] && [ $__DL_RC -ne 137 ] && [ $__DL_RC -ne 143 ]; then')
    c.append('  echo "ERROR: croc file download failed (exit code: $__DL_RC)" >&2')
    c.append(f'  echo "{CROC_SENTINEL_FAILED} exit_code=$__DL_RC"')
    c.append('  exit 1')
    c.append('fi')
    c.append(f'echo "{CROC_SENTINEL_DONE} exit_code=$__DL_RC"')
    return c


def generate_croc_send_commands(
    code: str,
    file_infos: list[dict],
    timeout: int = 300,
    relay: str = "",
    relay_password: str = "",
    transfers: Optional[int] = None,
) -> str:
    """Generate shell commands to send files from the container/target to local via croc.

    Used for container-target and local-executor downloads. Files are staged into
    a temp dir with unique names, then sent via croc to the local machine which
    runs ``croc receive`` in the background.

    Args:
        code: The croc secret code (2048-bit).
        file_infos: List of dicts, each with:
            - remote_source_path: Path on the container to download.
            - croc_filename: Uniquely-prefixed filename for staging.
        timeout: Minimum (floor) timeout in seconds for croc send (default 300s).
            The effective timeout scales with the staged payload size so
            multi-GB transfers are not killed mid-flight; croc may also hang
            after 100% through proxy relays, which this bounds.
        relay: Optional "host:port" of a private relay; must match the receiver's.
        relay_password: Optional password for that relay.
        transfers: Optional number of parallel transfer streams.

    Returns:
        Shell commands string.
    """
    commands = []
    commands.append("# === Croc file download (send to local) ===")
    commands.append('__DL_DIR=$(mktemp -d)')

    for fi in file_infos:
        src = fi["remote_source_path"]
        croc_name = fi["croc_filename"]
        escaped_src = _shell_escape_single(src)
        escaped_name = _shell_escape_single(croc_name)
        # Hardlink when possible (same filesystem): no disk-usage doubling and no
        # copy latency at GB scale. cp -r fallback covers directories and
        # cross-device sources.
        commands.append(
            f"ln '{escaped_src}' \"$__DL_DIR/\"'{escaped_name}' 2>/dev/null"
            f" || cp -r '{escaped_src}' \"$__DL_DIR/\"'{escaped_name}'"
            f" || {{ echo 'WARNING: Failed to stage {escaped_src} for download' >&2; }}"
        )

    commands.extend(_generate_croc_send_core(
        code, timeout, cleanup_commands=[],
        relay=relay, relay_password=relay_password, transfers=transfers,
    ))
    commands.append("# === End croc file download ===")
    return "\n".join(commands)


def generate_croc_scp_download_commands(
    code: str,
    file_infos: list[dict],
    target_ip: str,
    ssh_user: str,
    ssh_private_key: str = "",
    ssh_password: str = "",
    timeout: int = 300,
    relay: str = "",
    relay_password: str = "",
    transfers: Optional[int] = None,
) -> str:
    """Generate shell commands to SCP files from SSH target to container, then croc send to local.

    Used for SSH-target downloads:
    1. SCP files from the SSH target to a temp dir on the container
    2. croc send the files from the container to the local machine

    Args:
        code: The croc secret code.
        file_infos: List of dicts with remote_source_path and croc_filename.
        target_ip: SSH target IP/hostname.
        ssh_user: SSH username.
        ssh_private_key: SSH private key content (PEM format).
        ssh_password: SSH password (alternative to key).
        timeout: Minimum (floor) timeout in seconds for croc send (default 300s).
            The effective timeout scales with the staged payload size so
            multi-GB transfers are not killed mid-flight; croc may also hang
            after 100% through proxy relays, which this bounds.

    Returns:
        Shell commands string to run on the agent container.
    """
    commands = []
    commands.append("# === SCP download from target + croc send to local ===")

    escaped_target = _shell_escape_single(target_ip)
    escaped_user = _shell_escape_single(ssh_user)
    ssh_target = f"'{escaped_user}'@'{escaped_target}'"

    # Set up SSH auth for SCP
    scp_prefix = ""
    scp_auth = ""
    if ssh_private_key:
        commands.append('__DL_KEY=$(mktemp)')
        commands.append("cat << '__DL_KEYEOF' > \"$__DL_KEY\"")
        commands.append(ssh_private_key)
        commands.append("__DL_KEYEOF")
        commands.append('chmod 600 "$__DL_KEY"')
        scp_auth = '-i "$__DL_KEY"'
    elif ssh_password:
        escaped_pw = _shell_escape_single(ssh_password)
        commands.append("if ! command -v sshpass &>/dev/null; then")
        commands.append("  apt-get install -y -qq sshpass >/dev/null 2>&1 \\")
        commands.append("    || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq sshpass >/dev/null 2>&1; }")
        commands.append("fi")
        scp_prefix = f"sshpass -p '{escaped_pw}'"
    else:
        raise ValueError("Either ssh_private_key or ssh_password is required for SCP download")

    pubkey_opt = "" if ssh_private_key else "-o PubkeyAuthentication=no"
    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

    # Create staging directory and SCP each file/dir from target
    commands.append('__DL_DIR=$(mktemp -d)')

    for fi in file_infos:
        src = fi["remote_source_path"]
        croc_name = fi["croc_filename"]
        escaped_src = _shell_escape_single(src)
        escaped_name = _shell_escape_single(croc_name)
        # scp -r works for both files and directories
        commands.append(
            f'{scp_prefix} scp -r {ssh_opts} {scp_auth} {pubkey_opt} '
            f'{ssh_target}:\'{escaped_src}\' "$__DL_DIR/"\'{escaped_name}\''
            f" || {{ echo 'WARNING: SCP download failed for {escaped_src}' >&2; }}"
        )

    # croc send all staged files to local
    cleanup_commands = ['rm -f "$__DL_KEY"'] if ssh_private_key else []
    commands.extend(_generate_croc_send_core(
        code, timeout, cleanup_commands=cleanup_commands,
        relay=relay, relay_password=relay_password, transfers=transfers,
    ))
    commands.append("# === End SCP download + croc send ===")
    return "\n".join(commands)


async def start_croc_receive(
    croc_path: Path,
    code: str,
    receive_dir: str,
    timeout: int = 1800,
    gated: bool = False,
    relay: str = "",
    relay_password: str = "",
) -> asyncio.subprocess.Process:
    """Start croc receive as a background process with automatic retry.

    Croc receive exits immediately when no sender room exists on the relay,
    so croc runs inside a retry wrapper. With gated=True (the download flow),
    the wrapper holds off entirely until the CROC_READY_SIGNAL file appears in
    receive_dir — written by the sentinel watcher when the remote sender has
    registered its relay room. Sender-first ordering makes the PAKE handshake
    race-free; an ungated receiver hammering the room can cross the sender's
    registration and kill it with "could not secure channel".

    Files are saved to receive_dir (croc writes to cwd).

    Coordination files inside receive_dir (all dot-prefixed):
    - CROC_READY_SIGNAL: created externally; allows croc attempts (gated mode).
      Removed externally while the sender restarts, re-created on re-registration.
    - CROC_ABORT_SIGNAL: created externally; makes the wrapper stop immediately
      (exit 2), killing any in-flight croc attempt.
    - CROC_EXPECTED_SIZES_FILE: JSON {croc_filename: {"size": bytes, "md5": hex}}
      written externally from the sender's size/hash sentinels. When present,
      the wrapper only declares success once every expected file exists with
      the expected size AND content hash — a partial transfer keeps retrying
      instead of passing as done. The hash matters: croc pre-sizes the
      destination file, so a dead transfer can leave a size-correct file full
      of holes.
    - CROC_RECEIVE_LOG_FILE: attempt log + croc output, written by the wrapper
      for diagnosability (previously everything was discarded).

    Args:
        croc_path: Path to local croc binary.
        code: The croc secret code.
        receive_dir: Directory where received files will be saved.
        timeout: Maximum seconds to keep retrying (default 1800 = 30 min).
        gated: If True, wait for CROC_READY_SIGNAL before each croc attempt.
        relay: Optional "host:port" of a private relay; must match the sender's.
        relay_password: Optional password for that relay (via CROC_PASS).

    Returns:
        The asyncio subprocess Process handle (a Python wrapper process that
        internally retries croc). Kill this process to abort all retries.
    """
    # Build a small Python script that retries croc until it succeeds.
    # Using sys.executable ensures cross-platform compatibility.
    # repr() handles Windows backslashes in paths safely.
    # --relay is a croc GLOBAL option: it must precede the (implicit) receive
    # subcommand, so the argv is assembled here rather than inside the script.
    croc_argv = [str(croc_path), "--yes", "--overwrite"]
    if relay:
        croc_argv[1:1] = ["--relay", _validate_relay(relay)]

    retry_script = (
        "import hashlib, json, os, subprocess, sys, time\n"
        f"croc_argv = {croc_argv!r}\n"
        f"receive_dir = {receive_dir!r}\n"
        f"code = {code!r}\n"
        f"timeout = {timeout}\n"
        f"retry_interval = {CROC_RECEIVE_RETRY_SECONDS}\n"
        f"gated = {gated!r}\n"
        f"ready_f = os.path.join(receive_dir, {CROC_READY_SIGNAL!r})\n"
        f"abort_f = os.path.join(receive_dir, {CROC_ABORT_SIGNAL!r})\n"
        f"sizes_f = os.path.join(receive_dir, {CROC_EXPECTED_SIZES_FILE!r})\n"
        f"log_f = os.path.join(receive_dir, {CROC_RECEIVE_LOG_FILE!r})\n"
        "env = os.environ.copy()\n"
        "env['CROC_SECRET'] = code\n"
        + (f"env['CROC_PASS'] = {relay_password!r}\n" if relay_password else "")
        + "def log(msg):\n"
        "    try:\n"
        "        with open(log_f, 'a') as f:\n"
        "            f.write(time.strftime('[%H:%M:%S] ') + msg + '\\n')\n"
        "    except OSError:\n"
        "        pass\n"
        "def received_files():\n"
        "    return [f for f in os.listdir(receive_dir) if not f.startswith('.')]\n"
        "def kill_proc(p):\n"
        "    # Kill the whole tree: an orphaned child would keep the partial\n"
        "    # file open and block the receive dir's cleanup\n"
        "    try:\n"
        "        if os.name == 'nt':\n"
        "            subprocess.run(['taskkill', '/PID', str(p.pid), '/T', '/F'],\n"
        "                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        "        else:\n"
        "            p.kill()\n"
        "        p.wait()\n"
        "    except OSError:\n"
        "        pass\n"
        "def md5_of(path):\n"
        "    h = hashlib.md5()\n"
        "    with open(path, 'rb') as f:\n"
        "        for chunk in iter(lambda: f.read(1024 * 1024), b''):\n"
        "            h.update(chunk)\n"
        "    return h.hexdigest()\n"
        "def expected_status():\n"
        "    # True: every expected file present, size AND content hash matching\n"
        "    # False: some expected file missing, size-mismatched, or corrupt\n"
        "    # None: no expectation information available\n"
        "    # Size alone is NOT integrity: croc pre-sizes the destination file,\n"
        "    # so a dead transfer leaves a size-correct file full of holes.\n"
        "    try:\n"
        "        with open(sizes_f) as f:\n"
        "            expected = json.load(f)\n"
        "    except (OSError, ValueError):\n"
        "        return None\n"
        "    if not expected:\n"
        "        return None\n"
        "    for name, want in expected.items():\n"
        "        path = os.path.join(receive_dir, name)\n"
        "        if not os.path.exists(path):\n"
        "            return False\n"
        "        size = want.get('size')\n"
        "        if isinstance(size, int) and os.path.isfile(path) and os.path.getsize(path) != size:\n"
        "            return False\n"
        "        md5 = want.get('md5')\n"
        "        if md5 and os.path.isfile(path):\n"
        "            try:\n"
        "                if md5_of(path) != md5:\n"
        "                    log('content hash mismatch for %s' % name)\n"
        "                    return False\n"
        "            except OSError:\n"
        "                return False\n"
        "    return True\n"
        "deadline = time.monotonic() + timeout\n"
        "attempt = 0\n"
        "log('receiver started (gated=%s, timeout=%ss)' % (gated, timeout))\n"
        "while time.monotonic() < deadline:\n"
        "    if os.path.exists(abort_f):\n"
        "        log('abort signal received; giving up')\n"
        "        sys.exit(2)\n"
        "    if gated and not os.path.exists(ready_f):\n"
        "        time.sleep(0.25)\n"
        "        continue\n"
        "    attempt += 1\n"
        "    log('croc attempt %d starting' % attempt)\n"
        "    rc = None\n"
        "    try:\n"
        "        with open(log_f, 'a') as lf:\n"
        "            proc = subprocess.Popen(\n"
        "                croc_argv,\n"
        "                cwd=receive_dir, env=env,\n"
        "                stdin=subprocess.DEVNULL, stdout=lf, stderr=lf,\n"
        "            )\n"
        "            while True:\n"
        "                rc = proc.poll()\n"
        "                if rc is not None:\n"
        "                    break\n"
        "                if os.path.exists(abort_f) or time.monotonic() > deadline:\n"
        "                    kill_proc(proc)\n"
        "                    rc = -9\n"
        "                    break\n"
        "                time.sleep(0.5)\n"
        "    except OSError as e:\n"
        "        log('failed to run croc: %s' % e)\n"
        "        rc = -1\n"
        "    log('croc attempt %d finished (rc=%s)' % (attempt, rc))\n"
        "    status = expected_status()\n"
        "    if status is True:\n"
        "        log('all expected files received with matching sizes')\n"
        "        sys.exit(0)\n"
        "    if rc == 0:\n"
        "        if status is False:\n"
        "            log('croc exited 0 but expected files are incomplete; retrying')\n"
        "        else:\n"
        "            sys.exit(0)\n"
        "    elif status is None and received_files():\n"
        "        # Legacy heuristic (no size info): files appeared - the sender may\n"
        "        # hang after a complete transfer, so treat this as success.\n"
        "        log('files present and no size info; assuming complete')\n"
        "        sys.exit(0)\n"
        "    if os.path.exists(abort_f):\n"
        "        log('abort signal received; giving up')\n"
        "        sys.exit(2)\n"
        "    time.sleep(retry_interval)\n"
        "log('deadline reached; giving up after %d attempts' % attempt)\n"
        "sys.exit(1)\n"
    )

    process = await asyncio.create_subprocess_exec(
        sys.executable, "-c", retry_script,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    # Brief pause to ensure the wrapper process started
    await asyncio.sleep(1)

    # Check if it crashed during startup (e.g. syntax error in script).
    # A clean exit (0) is legitimate: files may already be present / the
    # transfer can finish faster than this startup pause.
    if process.returncode is not None and process.returncode != 0:
        raise RuntimeError(
            f"croc receive wrapper exited immediately with code {process.returncode}"
        )

    return process
