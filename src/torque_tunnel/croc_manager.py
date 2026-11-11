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
import socket
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

# Remote croc install (generate_remote_croc_install_script). Without a connect
# timeout, curl through a proxy that drops packets waits minutes per request.
CROC_INSTALL_CONNECT_TIMEOUT_SECONDS = 20
CROC_INSTALL_MAX_SECONDS = 300

# How long to wait for croc to register with the relay before launching the remote receive
CROC_SEND_STARTUP_SECONDS = 3

# The relay every croc invocation names explicitly unless the profile configures
# its own (croc_relay). croc resolves its BUILT-IN default relay once at process
# start with a hard 500 ms timeout (croc v10 src/models/constants.go) and, if the
# resolver is slower, silently blanks it — the send then fails with
# "could not connect to : could not connect" (empty address). That broke every
# download on the cisco-jarvis-mx agent on 2026-09-23 (resolver uncached lookups
# 1.3-2.5 s, still 0.1-0.7 s after a DNS fix). Naming the relay makes croc ignore
# that startup lookup. It is a HOSTNAME, not an IP, on purpose: with an HTTP
# proxy croc sends `CONNECT croc.schollz.com:9009` and the proxy resolves it, so
# no local DNS is needed at all (verified with the container's DNS black-holed:
# 3 MB transferred intact). Without a proxy the lookup happens at connect time
# with croc's normal ~30 s budget instead of 500 ms.
DEFAULT_CROC_RELAY = "croc.schollz.com:9009"

# Upper bound for the pre-croc lookup of the relay host (generate_dns_warmup /
# warm_dns_cache). The lookup only warms the resolver's cache for whatever
# lookup croc still does itself, so it must never cost more than this.
CROC_DNS_WARMUP_SECONDS = 3

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

# The local receive wrapper's other waits: how often a gated wrapper checks for the
# ready signal, how often it checks on a running croc (and for an abort), and how long
# start_croc_receive waits before checking that the wrapper did not crash on startup.
CROC_RECEIVE_GATE_POLL_SECONDS = 0.25
CROC_RECEIVE_CROC_POLL_SECONDS = 0.5
CROC_RECEIVE_STARTUP_CHECK_SECONDS = 1

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

# The send monitor polls every tick and checks progress every 10 ticks (5s). The
# CHECKS limits above count those checks, so they stay meaningful at any tick.
CROC_SEND_MONITOR_TICK_SECONDS = 0.5


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


def generate_remote_croc_install_script(
    version: str = CROC_VERSION,
    failure_sentinel: Optional[str] = None,
) -> str:
    """Generate shell commands to install croc on a remote Linux container.

    Uses 7 parallel curl chunk downloads for speed (~2.1 seconds on tested network).
    Falls back to single-stream download if parallel approach fails.
    Skips installation if croc is already available.

    A failed install says WHY: curl's own last error line and the proxy in use
    (credentials masked), e.g. ``ERROR: Failed to install croc: curl: (5) Could
    not resolve proxy: no-such-proxy.invalid (proxy: http://no-such-proxy.invalid:80)``.
    It used to pipe ``curl -s`` into ``tar``, which reduced every download
    failure to "gzip: stdin: unexpected end of file". Every curl has a connect
    timeout, so a proxy that drops packets fails in seconds, not minutes.

    Args:
        version: croc release to install.
        failure_sentinel: When set (the download path), also emit
            ``<sentinel> exit_code=install reason=<message>`` on failure. The
            local receiver waits on the sender's sentinels, and without one it
            could only report that the sender "never registered".

    Returns:
        Multi-line shell script string.
    """
    url = (
        f"https://github.com/schollz/croc/releases/download/{version}"
        f"/croc_{version}_Linux-64bit.tar.gz"
    )
    ct = CROC_INSTALL_CONNECT_TIMEOUT_SECONDS
    sentinel_line = (
        f'    echo "{failure_sentinel} exit_code=install reason=$__CROC_INSTALL_MSG"\n'
        if failure_sentinel else ""
    )
    return f"""# === Fast parallel croc install (~2s with {REMOTE_INSTALL_CHUNKS} chunks) ===
if ! command -v croc &>/dev/null; then
  __CROC_URL="{url}"
  __CROC_CURL="curl -fsSL --connect-timeout {ct} --max-time {CROC_INSTALL_MAX_SECONDS}"
  __CROC_TMP=$(mktemp -d)
  __CROC_FSIZE=$(curl -fsSIL --connect-timeout {ct} --max-time 60 "$__CROC_URL" 2>"$__CROC_TMP/head.err" | grep -i content-length | tail -1 | tr -dc '0-9')
  if [ -n "$__CROC_FSIZE" ] && [ "$__CROC_FSIZE" -gt 0 ] 2>/dev/null; then
    __CROC_NCHUNKS={REMOTE_INSTALL_CHUNKS}
    __CROC_CHUNK=$(( (__CROC_FSIZE + __CROC_NCHUNKS - 1) / __CROC_NCHUNKS ))
    for __i in $(seq 0 $((__CROC_NCHUNKS - 1))); do
      __S=$((__i * __CROC_CHUNK))
      __E=$(((__i + 1) * __CROC_CHUNK - 1))
      [ $__E -ge $__CROC_FSIZE ] && __E=$((__CROC_FSIZE - 1))
      $__CROC_CURL -r "$__S-$__E" -o "$__CROC_TMP/part$(printf %04d $__i)" "$__CROC_URL" 2>>"$__CROC_TMP/chunks.err" &
    done
    wait
    # A failed chunk can leave a TRUNCATED croc behind that would pass the
    # executable check below; remove it so the fallback runs instead.
    cat "$__CROC_TMP"/part* 2>/dev/null | tar xz -C /usr/local/bin croc 2>/dev/null || rm -f /usr/local/bin/croc
  fi
  if [ ! -x /usr/local/bin/croc ]; then
    # Fallback: single-stream download (size detection or a chunk failed).
    # Into a file, not a pipe, so curl's error is kept and tar never sees junk.
    if $__CROC_CURL -o "$__CROC_TMP/croc.tgz" "$__CROC_URL" 2>"$__CROC_TMP/curl.err"; then
      tar xzf "$__CROC_TMP/croc.tgz" -C /usr/local/bin croc 2>"$__CROC_TMP/tar.err" || rm -f /usr/local/bin/croc
    fi
  fi
  export PATH="/usr/local/bin:$PATH"
  if ! command -v croc &>/dev/null; then
    __CROC_INSTALL_MSG=$(tail -n 1 "$__CROC_TMP/curl.err" 2>/dev/null)
    [ -z "$__CROC_INSTALL_MSG" ] && __CROC_INSTALL_MSG=$(tail -n 1 "$__CROC_TMP/tar.err" 2>/dev/null)
    [ -z "$__CROC_INSTALL_MSG" ] && __CROC_INSTALL_MSG="the download produced no croc binary"
    __CROC_PROXY=$(printf '%s' "${{HTTPS_PROXY:-${{https_proxy:-}}}}" | sed -E 's#//[^/@]*@#//***@#')
    __CROC_INSTALL_MSG="Failed to install croc: $__CROC_INSTALL_MSG (proxy: ${{__CROC_PROXY:-none}})"
    echo "ERROR: $__CROC_INSTALL_MSG" >&2
{sentinel_line}    rm -rf "$__CROC_TMP"
    exit 1
  fi
  rm -rf "$__CROC_TMP"
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


# --- Secrets in generated scripts ---
# The scripts generated here travel in ordinary blueprint inputs, which Torque shows to
# anyone in the space, and run inside a grain whose source Torque echoes into its log.
# So they never contain a secret: they name environment variables that the executor
# blueprints fill from sensitive inputs through the grain's `env-vars`, which Torque keeps
# out of both its log and its API. These names are part of the blueprints' contract.
SSH_PRIVATE_KEY_ENV = "TT_SSH_PRIVATE_KEY"          # the environment's own target
SSH_PASSWORD_ENV = "TT_SSH_PASSWORD"
AUX_SSH_PRIVATE_KEY_ENV = "TT_AUX_SSH_PRIVATE_KEY"  # a second machine (a direct copy's source)
AUX_SSH_PASSWORD_ENV = "TT_AUX_SSH_PASSWORD"
CROC_RECEIVE_CODE_ENV = "TT_CROC_RECEIVE_CODE"      # croc receive on the agent: uploads, a transfer's receiver
CROC_SEND_CODE_ENV = "TT_CROC_SEND_CODE"            # croc send on the agent: downloads, a transfer's sender
CROC_RELAY_PASSWORD_ENV = "TT_CROC_RELAY_PASSWORD"


def _relay_env_export() -> list[str]:
    """Shell lines exporting the relay password, when the environment has one.

    The password goes through the environment rather than croc's ``--pass`` flag
    so it never shows up in the container's process list.
    """
    return [f'if [ -n "${{{CROC_RELAY_PASSWORD_ENV}:-}}" ]; then '
            f'export CROC_PASS="${CROC_RELAY_PASSWORD_ENV}"; fi']


def _relay_env_unset() -> list[str]:
    """Shell lines removing the relay password exported by _relay_env_export."""
    return [f'if [ -n "${{{CROC_RELAY_PASSWORD_ENV}:-}}" ]; then unset CROC_PASS; fi']


def _ssh_auth(tag: str, aux: bool = False) -> tuple[list[str], list[str]]:
    """Shell lines defining ``__ssh_<tag>`` and ``__scp_<tag>`` (ssh and scp signed in as
    one machine), and the lines that clean up.

    The key or password comes from the environment (the AUX_ variables with ``aux``), so
    the method is chosen when the script runs: the key if there is one, else the
    password, which sshpass reads from SSHPASS so it never shows in the process list.
    """
    key_env, password_env = ((AUX_SSH_PRIVATE_KEY_ENV, AUX_SSH_PASSWORD_ENV) if aux
                             else (SSH_PRIVATE_KEY_ENV, SSH_PASSWORD_ENV))
    key_file = f"__{tag.upper()}_KEY"
    lines = [
        f'{key_file}=""',
        f'if [ -n "${{{key_env}:-}}" ]; then',
        f'  {key_file}=$(mktemp)',
        f'  printf "%s" "${key_env}" > "${key_file}"',
        # ssh rejects some key formats without their final newline
        f'  if [ -n "$(tail -c 1 "${key_file}")" ]; then echo >> "${key_file}"; fi',
        f'  chmod 600 "${key_file}"',
        f'elif [ -n "${{{password_env}:-}}" ]; then',
        "  if ! command -v sshpass &>/dev/null; then",
        "    apt-get install -y -qq sshpass >/dev/null 2>&1 \\",
        "      || { apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq sshpass >/dev/null 2>&1; }",
        "  fi",
        "else",
        '  echo "ERROR: neither an SSH key nor a password was given for this machine" >&2',
        "  exit 1",
        "fi",
    ]
    for tool in ("ssh", "scp"):
        lines.append(
            f'__{tool}_{tag}() {{ if [ -n "${key_file}" ]; then {tool} -i "${key_file}" "$@"; '
            f'else SSHPASS="${password_env}" sshpass -e {tool} -o PubkeyAuthentication=no "$@"; fi; }}')
    return lines, [f'rm -f "${key_file}"']


def effective_relay(relay: str = "") -> str:
    """The relay every croc invocation names explicitly: the configured one, or
    croc's public relay by HOSTNAME (see DEFAULT_CROC_RELAY for why)."""
    return _validate_relay(relay) if relay else DEFAULT_CROC_RELAY


def _relay_host(relay: str) -> str:
    """Host part of a relay address ("host:port", "[v6]:port" or a bare host)."""
    host = relay.rsplit(":", 1)[0] if relay.count(":") == 1 or relay.startswith("[") else relay
    return host.strip("[]")


def _needs_lookup(host: str) -> bool:
    """False for an IP literal: there is nothing to resolve, or to warm."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return bool(host)


def _croc_global_flags(relay: str) -> str:
    """croc's GLOBAL options naming the relay — these must precede any subcommand."""
    return f"--relay {effective_relay(relay)} "


# --- Relay reachability check ---
# Before anything expensive (staging and hashing gigabytes, launching the other side),
# each side checks that it can reach the croc relay, so a blocked port fails in seconds
# with its real cause instead of minutes later as the OTHER side's "room not ready"
# (2026-11-09: the Quali lab drops every TCP port 9009-9013, the public relay's).
#
# The check speaks croc's own protocol: a "ping" frame, answered "pong" by the relay
# before any room or handshake exists (croc src/tcp/tcp.go: clientHandshake returns at
# once for "ping"). The relay's admission limiter (~30 joins/IP/minute) counts room
# joins only - it runs in clientCommunication, which a ping never reaches - so a check
# costs nothing against that budget. The same pong also proves the port is a croc relay
# and not just any open port.
#
# It goes the way croc goes: through SOCKS5_PROXY or HTTP_PROXY (croc's --socks5 and
# --connect flags read exactly those variables), except to a private or loopback relay
# address, which croc dials directly (utils.IsLocalIP). Through an HTTP proxy it sends
# CONNECT first, as croc does. A SOCKS5 proxy is not checked: the check is skipped.
RELAY_CHECK_TIMEOUT_SECONDS = 6

# croc frames every message as "croc" + uint32 little-endian length + payload.
RELAY_PING_FRAME = b"croc\x04\x00\x00\x00ping"

# The public relay's data ports: after the handshake it tells each side to open its
# transfer connections there (its banner). A network can pass the control port and
# still drop these, so they are checked too - only for the default relay, whose ports
# are known; a private relay announces its own only after the handshake.
DEFAULT_RELAY_DATA_PORTS = (9010, 9011, 9012, 9013)

# Where croc dials without a proxy (croc src/utils/utils.go privateIPBlocks + IsLocalIP).
_CROC_LOCAL_NETWORKS = ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                        "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7")


def _relay_port(relay: str) -> int:
    """Port part of a relay address (croc's default 9009 when none is given)."""
    if relay.startswith("["):
        _, _, rest = relay.partition("]")
        return int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 9009
    if relay.count(":") == 1:
        port = relay.rsplit(":", 1)[1]
        return int(port) if port.isdigit() else 9009
    return 9009


def _croc_dials_directly(host: str) -> bool:
    """True when croc ignores its proxy settings for this relay host."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(net) for net in _CROC_LOCAL_NETWORKS
               if ipaddress.ip_network(net).version == ip.version)


def relay_check_ports(relay: str = "") -> list[int]:
    """The ports a side must reach: the relay's control port, plus the public relay's
    data ports."""
    address = effective_relay(relay)
    ports = [_relay_port(address)]
    if address == DEFAULT_CROC_RELAY:
        ports += list(DEFAULT_RELAY_DATA_PORTS)
    return ports


def generate_relay_check(relay: str, where: str, on_failure: list[str]) -> list[str]:
    """Shell lines that check this machine reaches the croc relay, before anything else.

    On failure ``__TT_RELAY_ERR`` holds a one-line explanation that starts with
    ``where`` and names the relay, the port and the cause (timed out, refused, DNS,
    the proxy's answer, or "not a croc relay"), and ``on_failure`` runs. Uses only bash
    builtins for the connection (``/dev/tcp``), so a hung connect is simply killed.
    """
    address = effective_relay(relay)
    host = _relay_host(address)
    ports = relay_check_ports(relay)
    ticks = RELAY_CHECK_TIMEOUT_SECONDS * 10
    q = _shell_escape_single
    lines = [
        "# --- croc relay reachability check (a croc ping: no room join, no rate-limit cost) ---",
        # One ping to $1:$2, through the HTTP proxy $3:$4 (Basic auth $5) when $3 is set.
        # Prints the stage it reached: CONNECTED, TUNNEL (proxy said 200), then PONG or
        # NOPONG; or "PROXY <status line>" when the proxy refused.
        "__tt_relay_ping() {",
        "  local line",
        '  if [ -n "$3" ]; then',
        '    exec 3<>"/dev/tcp/$3/$4" || exit 3',
        "    echo CONNECTED",
        '    if [ -n "$5" ]; then',
        "      printf 'CONNECT %s:%s HTTP/1.1\\r\\nHost: %s:%s\\r\\nProxy-Authorization: Basic %s\\r\\n\\r\\n'"
        ' "$1" "$2" "$1" "$2" "$5" >&3',
        "    else",
        "      printf 'CONNECT %s:%s HTTP/1.1\\r\\nHost: %s:%s\\r\\n\\r\\n' \"$1\" \"$2\" \"$1\" \"$2\" >&3",
        "    fi",
        '    IFS= read -r line <&3 || { echo "PROXY (no answer)"; exit 4; }',
        "    line=${line%$'\\r'}",
        '    case "$line" in HTTP/*" 200"*) ;; *) echo "PROXY $line"; exit 4 ;; esac',
        "    while IFS= read -r line <&3; do [ -z \"${line%$'\\r'}\" ] && break; done",
        "    echo TUNNEL",
        "  else",
        '    exec 3<>"/dev/tcp/$1/$2" || exit 3',
        "    echo CONNECTED",
        "  fi",
        "  printf 'croc\\004\\000\\000\\000ping' >&3",
        # The answer is "croc" + length + "pong"; read up to the "g" (NUL bytes vanish).
        "  IFS= read -r -d g line <&3",
        '  case "$line" in *pon) echo PONG ;; *) echo NOPONG ;; esac',
        "}",
        # __tt_relay_check HOST PORT...: every port at once, each bounded by the timeout.
        "__tt_relay_check() {",
        '  local h=$1 ph="" pp="" pa="" via="" px p t=0 res err i=0 pids="" busy dir',
        "  shift",
        '  __TT_RELAY_ERR=""',
    ]
    if not _croc_dials_directly(host):
        lines += [
            '  if [ -n "${SOCKS5_PROXY:-}" ]; then',
            '    echo "[torque-tunnel] croc relay check skipped: croc goes through SOCKS5_PROXY"',
            "    return 0",
            "  fi",
            '  if [ -n "${HTTP_PROXY:-}" ]; then',
            '    px=${HTTP_PROXY#*://}; px=${px%%/*}',
            '    case "$px" in *@*) pa=$(printf "%s" "${px%@*}" | base64 | tr -d "\\n"); px=${px##*@} ;; esac',
            '    ph=${px%:*}; pp=${px##*:}',
            '    [ "$ph" = "$px" ] && pp=80',
            '    via=" through the HTTP proxy $ph:$pp"',
            "  fi",
        ]
    lines += [
        '  dir=$(mktemp -d)',
        '  for p in "$@"; do',
        '    ( __tt_relay_ping "$h" "$p" "$ph" "$pp" "$pa" ) >"$dir/$p.out" 2>"$dir/$p.err" &',
        '    pids="$pids $!"',
        "  done",
        f'  while [ "$t" -lt {ticks} ]; do',
        "    busy=0",
        '    for i in $pids; do kill -0 "$i" 2>/dev/null && busy=1; done',
        '    [ "$busy" -eq 0 ] && break',
        "    sleep 0.1; t=$((t + 1))",
        "  done",
        '  for i in $pids; do kill -9 "$i" 2>/dev/null; wait "$i" 2>/dev/null; done',
        '  for p in "$@"; do',
        '    res=$(tail -n 1 "$dir/$p.out" 2>/dev/null)',
        "    err=$(head -n 2 \"$dir/$p.err\" 2>/dev/null | sed -e 's/^bash: //' -e 's/^line [0-9]*: //' | tr '\\n' ' ')",
        '    case "$res" in',
        "      PONG) continue ;;",
        '      NOPONG) __TT_RELAY_ERR="$h:$p answered$via, but not as a croc relay" ;;',
        '      "PROXY "*) __TT_RELAY_ERR="the HTTP proxy $ph:$pp refused CONNECT $h:$p: ${res#PROXY }" ;;',
        f'      TUNNEL) __TT_RELAY_ERR="the HTTP proxy $ph:$pp opened a tunnel to $h:$p, but no croc answer came within {RELAY_CHECK_TIMEOUT_SECONDS} s" ;;',
        '      CONNECTED)',
        '        if [ -n "$ph" ]; then __TT_RELAY_ERR="connected to the HTTP proxy $ph:$pp, but it did not answer CONNECT $h:$p'
        f' within {RELAY_CHECK_TIMEOUT_SECONDS} s"',
        f'        else __TT_RELAY_ERR="connected to $h:$p, but no croc answer came within {RELAY_CHECK_TIMEOUT_SECONDS} s"; fi ;;',
        '      *)',
        '        case "$err" in',
        '          *"Connection refused"*) __TT_RELAY_ERR="connection refused by ${ph:-$h}:${pp:-$p}$via (nothing listens there, or a firewall rejects it)" ;;',
        '          *"not known"*|*"name resolution"*|*"No address associated"*|*"nodename nor servname"*)'
        ' __TT_RELAY_ERR="DNS lookup of ${ph:-$h} failed" ;;',
        '          *"unreachable"*|*"No route to host"*) __TT_RELAY_ERR="no route to ${ph:-$h}:${pp:-$p}: $err" ;;',
        f'          "") __TT_RELAY_ERR="connecting to ${{ph:-$h}}:${{pp:-$p}}$via timed out after {RELAY_CHECK_TIMEOUT_SECONDS} s'
        ' (no answer at all: a firewall is probably dropping the port)" ;;',
        '          *) __TT_RELAY_ERR="could not connect to ${ph:-$h}:${pp:-$p}$via: $err" ;;',
        "        esac ;;",
        "    esac",
        '    if [ "$p" != "$1" ]; then __TT_RELAY_ERR="the relay answers on port $1 but not on its data port $p: $__TT_RELAY_ERR"; fi',
        "    break",
        "  done",
        '  rm -rf "$dir"',
        '  [ -z "$__TT_RELAY_ERR" ]',
        "}",
        f"if ! __tt_relay_check '{q(host)}' {' '.join(str(p) for p in ports)}; then",
        f"  __TT_RELAY_ERR='{q(where)} cannot reach the croc relay {q(address)}: '\"$__TT_RELAY_ERR\"",
        *(f"  {line}" for line in on_failure),
        "fi",
    ]
    return lines


def generate_relay_check_step(relay: str, where: str,
                              failure_sentinel: Optional[str] = None) -> str:
    """The relay check as the FIRST step of a croc job: before the croc install and any
    staging. On failure it prints ``ERROR: <where> cannot reach the croc relay ...``,
    the ``failure_sentinel`` line (``exit_code=relay reason=...``) when given, and
    exits 1 - the same contract as the croc install's failure."""
    on_failure = ['echo "ERROR: $__TT_RELAY_ERR" >&2']
    if failure_sentinel:
        on_failure.append(f'echo "{failure_sentinel} exit_code=relay reason=$__TT_RELAY_ERR"')
    on_failure.append("exit 1")
    return "\n".join(generate_relay_check(relay, where, on_failure))


def _relay_ping_once(host: str, port: int, timeout: float) -> str:
    """One croc ping from THIS machine, the way croc would dial. "" when the relay
    answered, else why not."""
    proxy = ""
    if not _croc_dials_directly(host):
        if os.environ.get("SOCKS5_PROXY"):
            return ""  # croc goes through the SOCKS5 proxy; not checked
        proxy = os.environ.get("HTTP_PROXY", "")
    ph, pp, auth = "", 0, ""
    if proxy:
        from urllib.parse import urlsplit
        parsed = urlsplit(proxy if "://" in proxy else "http://" + proxy)
        ph, pp = parsed.hostname or "", parsed.port or 80
        if parsed.username is not None:
            import base64 as _b64
            from urllib.parse import unquote
            creds = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}"
            auth = _b64.b64encode(creds.encode()).decode()
    via = f" through the HTTP proxy {ph}:{pp}" if ph else ""
    dial_host, dial_port = (ph, pp) if ph else (host, port)
    try:
        sock = socket.create_connection((dial_host, dial_port), timeout=timeout)
    except socket.gaierror:
        return f"DNS lookup of {dial_host} failed"
    except ConnectionRefusedError:
        return (f"connection refused by {dial_host}:{dial_port}{via} "
                "(nothing listens there, or a firewall rejects it)")
    except (socket.timeout, TimeoutError):
        return (f"connecting to {dial_host}:{dial_port}{via} timed out after {timeout:g} s "
                "(no answer at all: a firewall is probably dropping the port)")
    except OSError as e:
        return f"could not connect to {dial_host}:{dial_port}{via}: {e.strerror or e}"
    try:
        with sock:
            if ph:
                request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                if auth:
                    request += f"Proxy-Authorization: Basic {auth}\r\n"
                sock.sendall((request + "\r\n").encode())
                head = b""
                while b"\r\n\r\n" not in head and len(head) < 8192:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    head += chunk
                status = head.split(b"\r\n", 1)[0].decode("latin-1").strip()
                if not status.startswith("HTTP/") or " 200" not in status:
                    return f"the HTTP proxy {ph}:{pp} refused CONNECT {host}:{port}: {status or '(no answer)'}"
            sock.sendall(RELAY_PING_FRAME)
            answer = b""
            while len(answer) < 12:
                chunk = sock.recv(12 - len(answer))
                if not chunk:
                    break
                answer += chunk
    except (socket.timeout, TimeoutError):
        return f"connected to {host}:{port}{via}, but no croc answer came within {timeout:g} s"
    except OSError as e:
        return f"{host}:{port}{via} closed the connection: {e.strerror or e}"
    if b"pong" not in answer:
        return f"{host}:{port}{via} answered, but not as a croc relay"
    return ""


def check_relay(relay: str = "", timeout: float = RELAY_CHECK_TIMEOUT_SECONDS) -> str:
    """Check THIS machine reaches the croc relay (see generate_relay_check). Blocking;
    returns "" when every port answered, else why not (without a "who" prefix).
    Never raises."""
    from concurrent.futures import ThreadPoolExecutor
    try:
        address = effective_relay(relay)
    except ValueError as e:
        return str(e)
    host = _relay_host(address)
    ports = relay_check_ports(relay)
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        results = list(pool.map(lambda p: _relay_ping_once(host, p, timeout), ports))
    for port, problem in zip(ports, results):
        if problem:
            if port != ports[0]:
                return f"the relay answers on port {ports[0]} but not on its data port {port}: {problem}"
            return problem
    return ""


def generate_dns_warmup(relay: str = "") -> list[str]:
    """Shell lines that look up the relay host, so croc's own lookup hits a warm cache.

    Bounded and non-fatal: returns as soon as the lookup does (milliseconds on a
    warm resolver) and gives up after CROC_DNS_WARMUP_SECONDS. With DNS
    black-holed, an unbounded `getent` took 20 s in testing.

    Deliberately avoids the `timeout` binary: the send wrapper's own
    `timeout ... croc send` must stay the only `timeout` call, and a foreground
    `timeout` would also break under test shims that `exec` it. `getent ahosts`
    asks for A and AAAA together, as croc's resolver does. Nothing is emitted
    for an IP relay.
    """
    host = _relay_host(effective_relay(relay))
    if not _needs_lookup(host):
        return []
    ticks = max(1, int(CROC_DNS_WARMUP_SECONDS * 10))
    return [
        f"getent ahosts '{_shell_escape_single(host)}' >/dev/null 2>&1 &",
        '__TT_DNS_PID=$!',
        '__TT_DNS_TICK=0',
        f'while kill -0 "$__TT_DNS_PID" 2>/dev/null && [ "$__TT_DNS_TICK" -lt {ticks} ]; do',
        '  sleep 0.1; __TT_DNS_TICK=$((__TT_DNS_TICK + 1))',
        'done',
        'kill "$__TT_DNS_PID" 2>/dev/null; wait "$__TT_DNS_PID" 2>/dev/null',
    ]


def warm_dns_cache(relay: str = "", timeout: Optional[float] = None) -> None:
    """Look up the relay host locally, so croc's own lookup is served from cache.

    Bounded by CROC_DNS_WARMUP_SECONDS (or ``timeout``) and never raises: the
    lookup runs in a daemon thread that is simply abandoned if the resolver
    doesn't answer in time.
    """
    import threading
    try:
        host = _relay_host(effective_relay(relay))
    except ValueError:
        return
    if not _needs_lookup(host):
        return
    limit = CROC_DNS_WARMUP_SECONDS if timeout is None else timeout

    def lookup():
        try:
            socket.getaddrinfo(host, None)
        except Exception:
            pass

    worker = threading.Thread(target=lookup, name="croc-dns-warmup", daemon=True)
    worker.start()
    worker.join(limit)


# Scratch files the receive retry loop uses inside the croc receive directory.
# Dot-prefixed so they can never collide with a received file.
_RECEIVE_RC_FILE = ".croc_recv.rc"
_RECEIVE_LOG_FILE = ".croc_recv.log"

# Shell expression: the last line of a croc output capture worth quoting in an
# error. Progress redraws (with a percentage) and anything carrying the transfer
# code are dropped. `$1` is the capture file.
_LAST_CROC_ERROR_SH = (
    "tr '\\r' '\\n' < \"$1\" 2>/dev/null | grep -v -e '%' -e 'CROC_SECRET' "
    "-e 'Code is:' -e 'On the other computer' -e '(For ' -e '^[[:space:]]*croc ' "
    "-e '^[[:space:]]*$' | tail -n 1"
)


def generate_croc_receive_attempt(timeout: int, relay: str = "") -> list[str]:
    """Shell lines that receive via croc, retrying while the relay rate-limits us.

    The code comes from CROC_RECEIVE_CODE_ENV, through the environment (not an
    argument) so it is not in the process list either.

    Sets ``__CROC_RC`` to croc's exit code. croc's output still reaches stdout
    (through ``tee``) so transfer progress stays visible in the streamed grain
    log; the copy on disk is only there so the loop can tell a rate-limit
    rejection apart from a real failure.

    Also sets ``__CROC_ERR`` to croc's last diagnostic line, for the caller's
    ERROR message.

    Must run with the croc receive directory as the working directory.
    """
    waits = list(CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS) + ["final"]
    return [
        '__CROC_RC=1',
        '__CROC_ERR=""',
        f'__tt_last_croc_error() {{ {_LAST_CROC_ERROR_SH}; }}',
        f'for __CROC_WAIT in {" ".join(str(w) for w in waits)}; do',
        f'  rm -f {_RECEIVE_RC_FILE} {_RECEIVE_LOG_FILE}',
        # Every attempt is a fresh croc process with its own 500 ms startup lookup
        *(f'  {line}' for line in generate_dns_warmup(relay)),
        # The exit code goes through a file because the pipe into tee would
        # otherwise hide it, and PIPESTATUS is not portable to a plain sh grain.
        f'  {{ timeout {timeout} bash -c \'CROC_SECRET="${CROC_RECEIVE_CODE_ENV}" '
        f'croc {_croc_global_flags(relay)}--yes --overwrite\'; '
        f'echo $? > {_RECEIVE_RC_FILE}; }} 2>&1 | tee {_RECEIVE_LOG_FILE}',
        f'  __CROC_RC=$(cat {_RECEIVE_RC_FILE} 2>/dev/null || echo 1)',
        '  [ "$__CROC_RC" = "0" ] && break',
        f'  __CROC_ERR=$(__tt_last_croc_error {_RECEIVE_LOG_FILE})',
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


def describe_croc_error(text: str) -> str:
    """Plain-words explanation for croc errors whose cause is known, else "".

    Only causes that were actually diagnosed are listed; guessing would send the
    reader in the wrong direction.
    """
    if not text:
        return ""
    if "could not connect to : " in text:
        # Empty relay address: croc's startup lookup blanked its default relay.
        return ("croc had no relay address: its startup DNS lookup of the relay "
                "did not finish within croc's 500 ms limit")
    if CROC_RATE_LIMIT_MARKER in text:
        return ("the relay rejected the connection: its per-IP admission limit "
                "(~30 joins/minute) was reached")
    return ""


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
    file_transfers: list[dict],
    timeout: int = 600,
    relay: str = "",
) -> str:
    """Generate shell commands to receive files via croc and place them at destinations.

    The code and the relay password come from the environment (CROC_RECEIVE_CODE_ENV,
    CROC_RELAY_PASSWORD_ENV).

    Args:
        file_transfers: List of dicts, each with:
            - croc_filename: The uniquely-prefixed filename as croc will deliver it.
            - remote_destination_path: Where the file should end up on the target.
            - mode: Optional file permissions (e.g. "755"). Must match ^[0-7]{3,4}$.
            - is_dir_tar: If True, the file is a gzipped tar of a directory; extract instead of move.
        timeout: Timeout in seconds for croc receive (default 600s).
        relay: Optional "host:port" of a private relay; must match the sender's.

    Returns:
        Shell commands string.
    """
    commands = []
    commands.append("# === Croc file receive ===")
    commands.append('__CROC_DIR=$(mktemp -d)')
    commands.append('cd "$__CROC_DIR"')
    commands.extend(_relay_env_export())
    commands.extend(generate_croc_receive_attempt(timeout, relay))
    commands.append('if [ $__CROC_RC -ne 0 ]; then')
    commands.append('  echo "ERROR: croc file receive failed (exit code: $__CROC_RC)${__CROC_ERR:+: $__CROC_ERR}" >&2')
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
    # These lines are prepended to the user's own commands; don't leave the relay
    # password in their environment.
    commands.extend(_relay_env_unset())
    commands.append("# === End croc file receive ===")
    return "\n".join(commands)


def generate_croc_scp_commands(
    file_transfers: list[dict],
    target_ip: str,
    ssh_user: str,
    timeout: int = 600,
    relay: str = "",
) -> str:
    """Generate shell commands to receive files via croc on the CONTAINER, then SCP to SSH target.

    This is used for SSH tool uploads where files exceed the inline threshold:
    1. Install croc on the agent container
    2. Receive files from local machine via croc relay
    3. SCP each file from the container to the SSH target (directories are tar-piped)
    4. Clean up

    The target's key or password, the code and the relay password come from the
    environment (SSH_*_ENV, CROC_RECEIVE_CODE_ENV, CROC_RELAY_PASSWORD_ENV).

    Args:
        file_transfers: List of dicts with croc_filename, remote_destination_path, mode, is_dir_tar.
        target_ip: SSH target IP/hostname.
        ssh_user: SSH username.
        timeout: Timeout in seconds for croc receive (default 600s).
        relay: Optional "host:port" of a private relay; must match the sender's.

    Returns:
        Shell commands string to run on the agent container (not on the target).
    """
    commands = []
    commands.append("# === Croc receive + SCP to target ===")

    escaped_target = _shell_escape_single(target_ip)
    escaped_user = _shell_escape_single(ssh_user)
    ssh_target = f"'{escaped_user}'@'{escaped_target}'"

    auth_lines, cleanup = _ssh_auth("tgt")
    commands.extend(auth_lines)

    # Receive files via croc
    commands.append('__CROC_DIR=$(mktemp -d)')
    commands.append('cd "$__CROC_DIR"')
    commands.extend(_relay_env_export())
    commands.extend(generate_croc_receive_attempt(timeout, relay))
    commands.append('if [ $__CROC_RC -ne 0 ]; then')
    commands.append('  echo "ERROR: croc file receive failed (exit code: $__CROC_RC)${__CROC_ERR:+: $__CROC_ERR}" >&2')
    commands.extend(f'  {line}' for line in cleanup)
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
                f"__ssh_tgt {ssh_opts} {ssh_target} "
                f"'mkdir -p '\"'\"'{escaped_dest}'\"'\"' && tar xzf - -C '\"'\"'{escaped_dest}'\"'\"'' "
                f'< "$__CROC_DIR/"\'{escaped_croc_name}\''
                f' || {{ echo "ERROR: Failed to transfer directory to {dest} on target" >&2; exit 1; }}'
            )
        else:
            # Create remote directory if needed
            if dest_dir:
                escaped_dir = _shell_escape_single(dest_dir)
                commands.append(
                    f"__ssh_tgt {ssh_opts} {ssh_target} "
                    f"\"mkdir -p '{escaped_dir}'\""
                    f' || {{ echo "ERROR: Failed to create directory {dest_dir} on target" >&2; exit 1; }}'
                )

            # SCP the file
            commands.append(
                f'__scp_tgt {ssh_opts} '
                f'"$__CROC_DIR/"\'{escaped_croc_name}\' {ssh_target}:\'{escaped_dest}\''
                f' || {{ echo "ERROR: SCP failed for {dest}" >&2; exit 1; }}'
            )

        # Set permissions
        if mode and _validate_mode(mode):
            commands.append(
                f"__ssh_tgt {ssh_opts} {ssh_target} "
                f"\"chmod {mode} '{escaped_dest}'\""
            )

    # Cleanup
    commands.extend(cleanup)
    commands.append('rm -rf "$__CROC_DIR"')
    commands.extend(_relay_env_unset())
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
    # Always named, never croc's built-in default (see DEFAULT_CROC_RELAY).
    # A global option: it must precede `send`.
    cmd += ["--relay", effective_relay(relay)]
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
        # Warm the resolver for croc's own startup lookup. In a worker thread:
        # it can take up to CROC_DNS_WARMUP_SECONDS and must not stall the loop.
        await asyncio.to_thread(warm_dns_cache, relay)
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


# __tt_croc_connected PID: does croc (PID, or a child of it - PID is usually the
# `timeout` wrapper) hold an ESTABLISHED TCP connection? 0 yes, 1 no, 2 cannot tell.
# croc logs its relay connection only in debug mode, whose output is not safe to keep,
# so this reads the kernel's TCP table instead: the process's socket inodes
# (/proc/PID/fd) matched against /proc/net/tcp{,6} rows in state 01 (ESTABLISHED).
# croc send --no-local opens no other TCP connection, so a live one is the relay - or
# the HTTP proxy carrying it, which the relay check has just proved goes through.
# Pure bash plus readlink: no awk, ss or pgrep, which slim images lack.
_CROC_CONNECTED_SH = [
    "__tt_croc_connected() {",
    '  local kids="" p pp fd l inos=" " f sl la ra st q1 q2 q3 uid to ino rest',
    "  [ -r /proc/net/tcp ] || return 2",
    '  kids=$(cat /proc/"$1"/task/*/children 2>/dev/null)',
    '  if [ -z "$kids" ]; then',
    "    for p in /proc/[0-9]*; do",
    '      read -r _ _ _ pp _ < "$p/stat" 2>/dev/null && [ "$pp" = "$1" ] && kids="$kids ${p#/proc/}"',
    "    done",
    "  fi",
    '  for p in "$1" $kids; do',
    '    for fd in /proc/"$p"/fd/*; do',
    '      l=$(readlink "$fd" 2>/dev/null) || continue',
    '      case "$l" in "socket:["*"]") l=${l#socket:[}; inos="$inos${l%]} " ;; esac',
    "    done",
    "  done",
    '  [ "$inos" = " " ] && return 1',
    "  for f in /proc/net/tcp /proc/net/tcp6; do",
    '    [ -r "$f" ] || continue',
    "    while read -r sl la ra st q1 q2 q3 uid to ino rest; do",
    '      [ "$st" = "01" ] && case "$inos" in *" $ino "*) return 0 ;; esac',
    '    done < "$f"',
    "  done",
    "  return 1",
    "}",
]


def _generate_croc_send_core(
    timeout: int,
    cleanup_commands: list[str],
    relay: str = "",
    transfers: Optional[int] = None,
) -> list[str]:
    """Shared croc-send block used by both download command generators.

    Expects staged files to already exist in $__DL_DIR. Implements the
    coordination protocol (see CROC_SENTINEL_* constants):

    1. Emits a size sentinel per staged regular file so the local side can
       verify transfer completeness (rejecting partial files).
    2. Runs croc send in the background while tailing its output; emits the
       READY sentinel once croc has printed "Code is:" AND holds a live TCP
       connection (the relay room exists; see _CROC_CONNECTED_SH). The receiver
       connects only after that - sender-first by construction, so the PAKE
       handshake can't race a half-open receiver.
    3. Scales the croc-send timeout with the staged payload size (the fixed
       default killed healthy multi-GB transfers mid-flight).
    4. Retries the whole send once on failure (relay flakes), announcing it
       with the RETRY sentinel so the local receiver stands down first.
    5. Ends with an explicit DONE/FAILED sentinel and a non-zero exit on
       failure - a failed download must never look like success.

    The code and the relay password come from the environment (CROC_SEND_CODE_ENV,
    CROC_RELAY_PASSWORD_ENV, the latter through CROC_PASS).

    Args:
        timeout: Minimum (floor) croc send timeout in seconds.
        cleanup_commands: Extra cleanup lines to run after the send (e.g.
            removing a temporary SSH key), before the final status is emitted.
        relay: Optional "host:port" of a private relay; must match the receiver's.
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
    c.append(f'  echo "{CROC_SENTINEL_FAILED} exit_code=stage reason=no files were staged for download"')
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
    c.append(f'export CROC_SECRET="${CROC_SEND_CODE_ENV}"')
    c.extend(_relay_env_export())
    croc_send = f"croc {_croc_global_flags(relay)}send --no-local"
    if transfers:
        croc_send += f" --transfers {int(transfers)}"
    # Scale the send timeout with the payload size; `timeout` is the floor
    c.append('__DL_BYTES=$(du -sb . 2>/dev/null | cut -f1)')
    c.append(f'__DL_TIMEOUT=$(( ${{__DL_BYTES:-0}} / {CROC_SEND_MIN_RATE_BYTES_PER_SEC} + 120 ))')
    c.append(f'[ "$__DL_TIMEOUT" -lt {timeout} ] && __DL_TIMEOUT={timeout}')
    c.extend(_CROC_CONNECTED_SH)
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
    # Each attempt is a fresh croc process doing its own 500 ms startup lookup
    c.extend(f'  {line}' for line in generate_dns_warmup(relay))
    c.append(f'  timeout -k 5 "$__DL_TIMEOUT" {croc_send} "$@" > .croc_send.log 2>&1 &')
    c.append('  __CROC_PID=$!')
    c.append('  __CROC_T0=$SECONDS')
    c.append('  __CROC_READY=0')
    c.append('  __CROC_TICK=0')
    c.append('  __CROC_PREV=""')
    c.append('  __CROC_STALL=0')
    c.append('  __CROC_MIDSTALL=0')
    c.append('  __CROC_STALL_KILL=0')
    c.append('  __CROC_QUIET=0')
    c.append('  while kill -0 "$__CROC_PID" 2>/dev/null; do')
    # READY = the room exists: croc printed its code AND holds a live connection.
    # croc prints "Code is:" BEFORE it dials the relay (croc.go Send), so the code
    # alone proved nothing: on 2026-11-09 READY came 5 s before "dial tcp ...:9009:
    # i/o timeout". Where the TCP table cannot be read (status 2), the code alone
    # still counts, as before.
    c.append("    if [ \"$__CROC_READY\" -eq 0 ] && grep -q 'Code is:' .croc_send.log 2>/dev/null; then")
    c.append('      __tt_croc_connected "$__CROC_PID"')
    c.append('      if [ $? -ne 1 ]; then')
    c.append(f'        echo "{CROC_SENTINEL_READY}"')
    c.append('        __CROC_READY=1')
    c.append('      fi')
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
    c.append('          echo "[croc send] still running ($((SECONDS - __CROC_T0))s): $__CROC_LAST"')
    c.append('          __CROC_QUIET=0')
    c.append('        fi')
    # Heartbeat every ~30s while output is otherwise unchanged: liveness signal
    # for humans, and it keeps the runner shipping log chunks - the local
    # receiver is gated on sentinels arriving through that stream, and a
    # fully quiet log can sit in the runner's buffer for minutes.
    c.append('      else')
    c.append('        __CROC_QUIET=$((__CROC_QUIET + 1))')
    c.append('        if [ "$__CROC_QUIET" -ge 6 ]; then')
    c.append('          echo "[croc send] still running ($((SECONDS - __CROC_T0))s): $__CROC_LAST"')
    c.append('          __CROC_QUIET=0')
    c.append('        fi')
    c.append('      fi')
    c.append('    fi')
    c.append('    __CROC_TICK=$((__CROC_TICK + 1))')
    c.append(f'    sleep {CROC_SEND_MONITOR_TICK_SECONDS}')
    c.append('  done')
    c.append('  wait "$__CROC_PID"')
    c.append('  __DL_RC=$?')
    # A mid-transfer stall kill is NOT a post-completion hang: the whitelisted
    # kill codes (124/137/143) must not apply - force failure so the
    # retry/FAILED path runs instead of reporting DONE on a frozen transfer.
    c.append('  if [ "$__CROC_STALL_KILL" -eq 1 ]; then')
    c.append('    __DL_RC=1')
    c.append('  fi')
    # A croc that finished between two monitor polls had a room (the transfer
    # succeeded): say so, so the local side knows. A FAILED croc never had one that
    # counted - announcing it would launch a receiver into nothing.
    c.append('  case "$__DL_RC" in 0|124|137|143)')
    c.append("    if [ \"$__CROC_READY\" -eq 0 ] && grep -q 'Code is:' .croc_send.log 2>/dev/null; then")
    c.append(f'      echo "{CROC_SENTINEL_READY}"')
    c.append('    fi ;;')
    c.append('  esac')
    c.append('  __croc_tail | tail -n 3')
    # croc's last diagnostic line, kept for the FAILED sentinel: the send log is
    # deleted before that sentinel is emitted, and without it the caller only
    # ever saw "exit_code=1" (the real "could not connect to : could not connect"
    # was only in Torque's grain log). __croc_tail has already dropped the code.
    c.append("  __CROC_ERR=$(__croc_tail | grep -v '%' | tail -n 1)")
    c.append('}')
    c.append('__CROC_ERR=""')
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
    c.extend(_relay_env_unset())
    c.append('cd /')
    c.append('rm -rf "$__DL_DIR"')
    c.extend(cleanup_commands)
    c.append('if [ $__DL_RC -ne 0 ] && [ $__DL_RC -ne 124 ] && [ $__DL_RC -ne 137 ] && [ $__DL_RC -ne 143 ]; then')
    c.append('  echo "ERROR: croc file download failed (exit code: $__DL_RC)${__CROC_ERR:+: $__CROC_ERR}" >&2')
    c.append(f'  echo "{CROC_SENTINEL_FAILED} exit_code=$__DL_RC${{__CROC_ERR:+ reason=$__CROC_ERR}}"')
    c.append('  exit 1')
    c.append('fi')
    c.append(f'echo "{CROC_SENTINEL_DONE} exit_code=$__DL_RC"')
    return c


def generate_croc_send_commands(
    file_infos: list[dict],
    timeout: int = 300,
    relay: str = "",
    transfers: Optional[int] = None,
) -> str:
    """Generate shell commands to send files from the container/target to local via croc.

    Used for container-target and local-executor downloads. Files are staged into
    a temp dir with unique names, then sent via croc to the local machine which
    runs ``croc receive`` in the background. The code and the relay password come
    from the environment (CROC_SEND_CODE_ENV, CROC_RELAY_PASSWORD_ENV).

    Args:
        file_infos: List of dicts, each with:
            - remote_source_path: Path on the container to download.
            - croc_filename: Uniquely-prefixed filename for staging.
        timeout: Minimum (floor) timeout in seconds for croc send (default 300s).
            The effective timeout scales with the staged payload size so
            multi-GB transfers are not killed mid-flight; croc may also hang
            after 100% through proxy relays, which this bounds.
        relay: Optional "host:port" of a private relay; must match the receiver's.
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
        # copy latency at GB scale. cp fallback covers directories and
        # cross-device sources.
        # A symlink is FOLLOWED, so croc gets what it points to: `ln -L` links the
        # target, `cp -rH` copies it (and keeps links inside a directory as links).
        # Plain `ln` hard-linked the symlink itself and succeeded, so a relative link
        # (/etc/os-release -> ../usr/lib/os-release) was staged dangling and the
        # download failed with "no files were staged" (2026-11-11, GNU coreutils
        # 8.32). A dangling source fails both and is reported.
        commands.append(
            f"ln -L '{escaped_src}' \"$__DL_DIR/\"'{escaped_name}' 2>/dev/null"
            f" || cp -rH '{escaped_src}' \"$__DL_DIR/\"'{escaped_name}'"
            f" || {{ echo 'WARNING: Failed to stage {escaped_src} for download' >&2; }}"
        )

    commands.extend(_generate_croc_send_core(
        timeout, cleanup_commands=[], relay=relay, transfers=transfers,
    ))
    commands.append("# === End croc file download ===")
    return "\n".join(commands)


def generate_croc_scp_download_commands(
    file_infos: list[dict],
    target_ip: str,
    ssh_user: str,
    timeout: int = 300,
    relay: str = "",
    transfers: Optional[int] = None,
) -> str:
    """Generate shell commands to SCP files from SSH target to container, then croc send to local.

    Used for SSH-target downloads:
    1. SCP files from the SSH target to a temp dir on the container
    2. croc send the files from the container to the local machine

    The target's key or password, the code and the relay password come from the
    environment (SSH_*_ENV, CROC_SEND_CODE_ENV, CROC_RELAY_PASSWORD_ENV).

    Args:
        file_infos: List of dicts with remote_source_path and croc_filename.
        target_ip: SSH target IP/hostname.
        ssh_user: SSH username.
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

    auth_lines, cleanup = _ssh_auth("tgt")
    commands.extend(auth_lines)
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
            f'__scp_tgt -r {ssh_opts} '
            f'{ssh_target}:\'{escaped_src}\' "$__DL_DIR/"\'{escaped_name}\''
            f" || {{ echo 'WARNING: SCP download failed for {escaped_src}' >&2; }}"
        )

    # croc send all staged files to local
    commands.extend(_generate_croc_send_core(
        timeout, cleanup_commands=cleanup, relay=relay, transfers=transfers,
    ))
    commands.append("# === End SCP download + croc send ===")
    return "\n".join(commands)


# --- Remote-to-remote transfer support ---
# A file goes from a SOURCE machine to a DESTINATION machine that cannot reach each
# other, through two Torque environments: the sender's (stage from the source + the
# monitored croc send above, in its download slot) and the receiver's (monitored croc
# receive + verify + place on the destination, in its container pre-commands). The
# caller only orchestrates. See docs/design-remote-to-remote-transfer.md.

# "<sentinel> <croc_filename>": the staged file is a tar.gz of a source DIRECTORY, so the
# receiver extracts it instead of placing it. Directories are tarred on the sender so
# every croc payload is a regular file covered by the size/MD5 sentinels (a directory
# sent as-is would have neither).
CROC_SENTINEL_DIR = "__CROC_DL_DIR__"

# Receiver sentinels, read from the receiver environment's grain log.
CROC_RX_SENTINEL_PLACED = "__CROC_RX_PLACED__"  # "<sentinel> <destination path>"
CROC_RX_SENTINEL_DONE = "__CROC_RX_DONE__"      # every file verified and placed
CROC_RX_SENTINEL_FAILED = "__CROC_RX_FAILED__"  # "<sentinel> exit_code=<n|stage> reason=<text>"

# The sender's croc-send clock starts before the receiver environment exists: the
# receiver is only launched once the sender reports READY. Its timeout floor therefore
# includes the time to create and start that environment.
RELAY_RECEIVER_LAUNCH_BUDGET_SECONDS = 600

# Receiver stall handling. Both legs of a remote-to-remote transfer go through the
# lab proxy, where a transfer was seen frozen mid-flight for 25 minutes. The receiver
# must NOT move before the sender does: the sender kills a frozen transfer after
# ~CROC_SEND_MIDSTALL_CHECKS (~120s), waits CROC_SEND_RETRY_DELAY_SECONDS and registers
# a fresh room. So the receiver's own stall limit is longer (36 x 5s = ~180s), and its
# retry waits longer than the sender's delay, so it joins the NEW room, after the sender
# has registered it - sender-first without a back-channel into the receiver.
CROC_RECEIVE_MIDSTALL_CHECKS = 36
CROC_RECEIVE_RETRY_DELAY_SECONDS = CROC_SEND_RETRY_DELAY_SECONDS + 12
# Progress unchanged at 100% for this many 5s checks: verify the files, and if they are
# all complete, stop croc instead of waiting out its timeout (the sender's known
# hang-after-transfer, seen from the other side).
CROC_RECEIVE_STALL_CHECKS = 9
# The receive monitor polls every tick and checks progress every 10 ticks (5s).
RELAY_MONITOR_TICK_SECONDS = 0.5

_SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"


def _ssh_function(name: str, target_ip: str, ssh_user: str,
                  aux: bool = False) -> tuple[list[str], list[str]]:
    """Shell lines defining ``name`` as "ssh to the target", and the lines that clean up.

    ``name <remote command>`` runs one remote command, which must already be quoted
    as ONE shell word (see ``_q``). Its stdin is the function's stdin, so callers pass
    ``</dev/null`` when not streaming data in. Files are copied by piping through ssh
    (``cat >``) rather than scp, whose remote-path quoting differs between the legacy
    and the SFTP protocol. The machine's key or password comes from the environment:
    the environment's own target's, or with ``aux`` the second machine's (_ssh_auth).
    """
    tag = name.strip("_")
    lines, cleanup = _ssh_auth(tag, aux)
    lines.append(f'{name}() {{ __ssh_{tag} {_SSH_OPTS} {_q(f"{ssh_user}@{target_ip}")} "$@"; }}')
    return lines, cleanup


def _q(s: str) -> str:
    """Quote a string as one POSIX shell word."""
    import shlex
    return shlex.quote(s)


def _move_into_place(partial: str, dest: str) -> str:
    """Remote command: move a verified copy to its destination path.

    Refuses an existing DIRECTORY there: ``mv`` would put the copy inside it, under its
    temporary name. destination_path names the file itself.
    """
    return (f"if [ -d {_q(dest)} ]; then rm -f {_q(partial)}; "
            f"echo {_q(dest + ' is an existing directory; destination_path must name the file itself')} >&2; "
            f"exit 1; fi; mv -f {_q(partial)} {_q(dest)}")


def generate_croc_relay_send_commands(
    file_infos: list[dict],
    target_ip: str,
    ssh_user: str,
    relay: str = "",
    transfers: Optional[int] = None,
) -> str:
    """Shell commands for the SENDER side of a remote-to-remote transfer.

    Runs on the source agent's container (the download slot of an SSH environment that
    targets the source machine):
    1. Copies each source path from the target into $__DL_DIR. A directory is streamed
       as ``tar czf -`` and announced with CROC_SENTINEL_DIR.
    2. Runs the same monitored croc send as downloads (_generate_croc_send_core): SIZE
       and MD5 sentinels, READY once the relay room exists, stall handling, one retry,
       DONE/FAILED.

    A source path that cannot be read fails the whole transfer at once, with a FAILED
    sentinel (``exit_code=stage``) naming it: unlike a download, there is no local side
    that could report the missing file later.

    The source's key or password, the code and the relay password come from the
    environment (SSH_*_ENV, CROC_SEND_CODE_ENV, CROC_RELAY_PASSWORD_ENV).

    Args:
        file_infos: List of dicts with source_path and croc_filename.
        target_ip, ssh_user: The source machine.
        relay, transfers: As for downloads; the receiver must use the same relay.
    """
    ssh_lines, cleanup = _ssh_function("__rl_src", target_ip, ssh_user)
    c = ["# === Remote transfer: stage from the source + croc send ==="]
    c.extend(ssh_lines)
    c.append('__DL_DIR=$(mktemp -d)')
    c.append('__rl_stage_fail() {')
    c.append('  echo "ERROR: $1" >&2')
    c.append(f'  echo "{CROC_SENTINEL_FAILED} exit_code=stage reason=$1"')
    c.append('  cd /')
    c.append('  rm -rf "$__DL_DIR"')
    c.extend(f'  {line}' for line in cleanup)
    c.append('  exit 1')
    c.append('}')
    for fi in file_infos:
        src = fi["source_path"]
        name = fi["croc_filename"]
        staged = f'"$__DL_DIR/"{_q(name)}'
        # The reason text goes inside double quotes: keep it free of anything the
        # shell would expand there.
        shown = re.sub(r'["$`\\]', "?", src)
        c.append(f'if __rl_src {_q("test -d " + _q(src))} </dev/null; then')
        c.append(f'  echo "{CROC_SENTINEL_DIR} {name}"')
        c.append(f'  __rl_src {_q("tar czf - -C " + _q(src) + " .")} </dev/null > {staged}'
                 f' || __rl_stage_fail "could not archive directory {shown} on the source"')
        c.append('else')
        c.append(f'  __rl_src {_q("cat " + _q(src))} </dev/null > {staged}'
                 f' || __rl_stage_fail "could not read {shown} on the source"')
        c.append('fi')
    c.extend(_generate_croc_send_core(
        300 + RELAY_RECEIVER_LAUNCH_BUDGET_SECONDS, cleanup_commands=cleanup,
        relay=relay, transfers=transfers,
    ))
    c.append("# === End remote transfer send ===")
    return "\n".join(c)


def relay_receive_timeout(total_bytes: int) -> int:
    """croc receive timeout for a payload: the sender's rate assumption plus margin."""
    return max(900, total_bytes // CROC_SEND_MIN_RATE_BYTES_PER_SEC + 600)


def generate_croc_relay_receive_commands(
    manifest: list[dict],
    target_ip: str,
    ssh_user: str,
    relay: str = "",
) -> str:
    """Shell commands for the RECEIVER side of a remote-to-remote transfer.

    Runs on the destination agent's container (container pre-commands of an SSH
    environment that targets the destination machine). Launched only after the sender
    reported READY, so the first croc attempt joins an existing room.

    1. Receives with croc in the background under a monitor that reports progress,
       kills a transfer frozen below 100% (longer limit than the sender's, see
       CROC_RECEIVE_MIDSTALL_CHECKS) and stops croc once every file is verified.
    2. Verifies every file's size AND MD5 against the sender's manifest - a dead
       transfer can leave a size-correct file full of holes.
    3. Retries once on failure (after the sender's own retry has registered its new
       room), plus the rate-limit backoff loop.
    4. Places each file on the destination: piped through ssh into a temporary name,
       MD5-checked there, then moved into place, so a broken copy never reaches the
       destination path. Directories (tar.gz) are extracted.
    5. Emits CROC_RX_SENTINEL_PLACED per file and DONE, or FAILED with the reason.

    The destination's key or password, the code and the relay password come from the
    environment (SSH_*_ENV, CROC_RECEIVE_CODE_ENV, CROC_RELAY_PASSWORD_ENV).

    Args:
        manifest: One dict per file: croc_filename, size (int), md5 (hex or None),
            is_dir (bool), destination_path, mode (optional).
        target_ip, ssh_user: The destination machine.
        relay: Must match the sender's.
    """
    ssh_lines, cleanup = _ssh_function("__rx_dst", target_ip, ssh_user)
    total = sum(int(m.get("size") or 0) for m in manifest)
    c = ["# === Remote transfer: croc receive + place on the destination ==="]
    c.extend(ssh_lines)
    c.append('__CROC_DIR=$(mktemp -d)')
    c.append('cd "$__CROC_DIR"')
    c.append('__rx_fail() {')
    c.append('  echo "ERROR: $1" >&2')
    c.append(f'  echo "{CROC_RX_SENTINEL_FAILED} exit_code=${{2:-1}} reason=$1"')
    c.append('  cd /')
    c.append('  rm -rf "$__CROC_DIR"')
    c.extend(f'  {line}' for line in cleanup)
    c.append('  exit 1')
    c.append('}')
    # __rx_check <name> <size> <md5>: the received file is complete and intact. Sets
    # __RX_BAD to why not. The hash is only computed once the size matches.
    c.append('__rx_check() {')
    c.append('  if [ ! -f "$1" ]; then __RX_BAD="$1 was not received"; return 1; fi')
    c.append('  __RX_SIZE=$(stat -c %s "$1" 2>/dev/null)')
    c.append('  if [ "$__RX_SIZE" != "$2" ]; then __RX_BAD="$1 is incomplete ($__RX_SIZE of $2 bytes)"; return 1; fi')
    c.append('  if [ -n "$3" ]; then')
    c.append("    __RX_MD5=$(md5sum \"$1\" 2>/dev/null | cut -d' ' -f1)")
    c.append('    if [ "$__RX_MD5" != "$3" ]; then __RX_BAD="$1 is corrupt (md5 $__RX_MD5, expected $3)"; return 1; fi')
    c.append('  fi')
    c.append('  return 0')
    c.append('}')
    c.append('__rx_verify() {')
    for m in manifest:
        c.append(f'  __rx_check {_q(m["croc_filename"])} {int(m["size"])} {_q(m.get("md5") or "")} || return 1')
    c.append('  return 0')
    c.append('}')
    c.append(f'__tt_last_croc_error() {{ {_LAST_CROC_ERROR_SH}; }}')
    c.append(f'export CROC_SECRET="${CROC_RECEIVE_CODE_ENV}"')
    c.extend(_relay_env_export())
    c.append(f'__RX_TIMEOUT={relay_receive_timeout(total)}')
    c.append('__rx_attempt() {')
    c.append('  : > .croc_recv.log')
    c.extend(f'  {line}' for line in generate_dns_warmup(relay))
    c.append(f'  timeout -k 5 "$__RX_TIMEOUT" croc {_croc_global_flags(relay)}--yes --overwrite'
             ' > .croc_recv.log 2>&1 &')
    c.append('  __RX_PID=$!')
    c.append('  __RX_T0=$SECONDS')
    c.append('  __RX_TICK=0; __RX_PREV=""; __RX_STALL=0; __RX_MIDSTALL=0; __RX_QUIET=0')
    c.append('  while kill -0 "$__RX_PID" 2>/dev/null; do')
    c.append('    if [ "$__RX_TICK" -gt 0 ] && [ $((__RX_TICK % 10)) -eq 0 ]; then')
    c.append("      __RX_LAST=$(tr '\\r' '\\n' < .croc_recv.log 2>/dev/null | grep '%' | tail -n 1)")
    c.append('      if [ -n "$__RX_LAST" ] && [ "$__RX_LAST" != "$__RX_PREV" ]; then')
    c.append('        echo "[croc receive] $__RX_LAST"')
    c.append('        __RX_PREV=$__RX_LAST; __RX_STALL=0; __RX_MIDSTALL=0; __RX_QUIET=0')
    c.append('      elif case "$__RX_LAST" in *100%*) true;; *) false;; esac; then')
    # At 100%: once it has sat there a while, check the files - once, since hashing a
    # multi-GB file takes a minute. All complete -> croc's job is done whatever it is
    # waiting for. Not complete (another file still to come, or holes) -> keep
    # counting toward the stall limit.
    c.append('        __RX_STALL=$((__RX_STALL + 1)); __RX_MIDSTALL=$((__RX_MIDSTALL + 1))')
    c.append(f'        if [ "$__RX_STALL" -eq {CROC_RECEIVE_STALL_CHECKS} ] && __rx_verify; then')
    c.append('          echo "[croc receive] all files received and verified; croc did not exit - terminating it"')
    c.append('          kill "$__RX_PID" 2>/dev/null')
    c.append(f'        elif [ "$__RX_MIDSTALL" -ge {CROC_RECEIVE_MIDSTALL_CHECKS} ]; then')
    c.append('          echo "[croc receive] transfer stalled with no progress - terminating for retry"')
    c.append('          kill "$__RX_PID" 2>/dev/null')
    c.append('        fi')
    c.append('      elif [ -n "$__RX_LAST" ]; then')
    c.append('        __RX_MIDSTALL=$((__RX_MIDSTALL + 1)); __RX_QUIET=$((__RX_QUIET + 1))')
    c.append(f'        if [ "$__RX_MIDSTALL" -ge {CROC_RECEIVE_MIDSTALL_CHECKS} ]; then')
    c.append('          echo "[croc receive] transfer stalled with no progress - terminating for retry"')
    c.append('          kill "$__RX_PID" 2>/dev/null')
    c.append('        elif [ "$__RX_QUIET" -ge 6 ]; then')
    c.append('          echo "[croc receive] still running ($((SECONDS - __RX_T0))s): $__RX_LAST"; __RX_QUIET=0')
    c.append('        fi')
    # No progress line yet: connecting, or the sender is still hashing. A heartbeat
    # keeps this environment's log moving for the status calls.
    c.append('      else')
    c.append('        __RX_QUIET=$((__RX_QUIET + 1))')
    c.append('        if [ "$__RX_QUIET" -ge 6 ]; then')
    c.append('          echo "[croc receive] waiting for data ($((SECONDS - __RX_T0))s)"; __RX_QUIET=0')
    c.append('        fi')
    c.append('      fi')
    c.append('    fi')
    c.append('    __RX_TICK=$((__RX_TICK + 1))')
    c.append(f'    sleep {RELAY_MONITOR_TICK_SECONDS}')
    c.append('  done')
    c.append('  wait "$__RX_PID"')
    c.append('  __RX_RC=$?')
    c.append('  __RX_ERR=$(__tt_last_croc_error .croc_recv.log)')
    c.append('}')
    # Attempts: one general retry (aligned after the sender's), plus the rate-limit
    # backoff waits. Success is decided by the files, not by croc's exit code.
    waits = " ".join(str(w) for w in CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS)
    c.append('__RX_OK=0; __RX_RETRY=1; __RX_RC=1; __RX_ERR=""')
    c.append(f'__RX_RL_LEFT="{waits}"')
    c.append(f'for __RX_N in $(seq 1 {len(CROC_RECEIVE_RATE_LIMIT_BACKOFF_SECONDS) + 2}); do')
    c.append('  __rx_attempt')
    c.append('  if __rx_verify; then __RX_OK=1; break; fi')
    c.append(f'  if grep -q "{CROC_RATE_LIMIT_MARKER}" .croc_recv.log 2>/dev/null && [ -n "$__RX_RL_LEFT" ]; then')
    c.append('    __RX_W=${__RX_RL_LEFT%% *}')
    c.append('    if [ "$__RX_W" = "$__RX_RL_LEFT" ]; then __RX_RL_LEFT=""; else __RX_RL_LEFT=${__RX_RL_LEFT#* }; fi')
    c.append('    echo "[croc receive] relay rate-limited this host; retrying in ${__RX_W}s"')
    c.append('    sleep "$__RX_W"')
    c.append('    continue')
    c.append('  fi')
    c.append('  if [ "$__RX_RETRY" -eq 1 ]; then')
    c.append('    __RX_RETRY=0')
    c.append(f'    echo "[croc receive] attempt failed (exit code $__RX_RC${{__RX_ERR:+: $__RX_ERR}}; $__RX_BAD); retrying once in {CROC_RECEIVE_RETRY_DELAY_SECONDS}s"')
    c.append(f'    sleep {CROC_RECEIVE_RETRY_DELAY_SECONDS}')
    c.append('    continue')
    c.append('  fi')
    c.append('  break')
    c.append('done')
    c.append('unset CROC_SECRET')
    c.extend(_relay_env_unset())
    c.append('if [ "$__RX_OK" -ne 1 ]; then')
    # Same wording as the upload receive's error, so extract_transfer_errors finds it.
    c.append('  __rx_fail "croc file receive failed (exit code: $__RX_RC)${__RX_ERR:+: $__RX_ERR}; $__RX_BAD" "$__RX_RC"')
    c.append('fi')
    for m in manifest:
        name = m["croc_filename"]
        dest = m["destination_path"]
        mode = m.get("mode")
        received = f'"$__CROC_DIR/"{_q(name)}'
        shown = re.sub(r'["$`\\]', "?", dest)
        if m.get("is_dir"):
            remote = f"mkdir -p {_q(dest)} && tar xzf - -C {_q(dest)}"
            c.append(f'__rx_dst {_q(remote)} < {received}'
                     f' || __rx_fail "could not extract into {shown} on the destination"')
        else:
            partial = dest + ".tt-partial"
            parent = os.path.dirname(dest)
            if parent:
                c.append(f'__rx_dst {_q("mkdir -p " + _q(parent))} </dev/null'
                         f' || __rx_fail "could not create the directory of {shown} on the destination"')
            c.append(f'__rx_dst {_q("cat > " + _q(partial))} < {received}'
                     f' || {{ __rx_dst {_q("rm -f " + _q(partial))} </dev/null;'
                     f' __rx_fail "could not copy to {shown} on the destination"; }}')
            if m.get("md5"):
                # Verified again where it landed: the hop from this container to the
                # destination is a second transfer.
                c.append(f"__RX_GOT=$(__rx_dst {_q('md5sum ' + _q(partial))} </dev/null 2>/dev/null | cut -d' ' -f1)")
                c.append('if [ -z "$__RX_GOT" ]; then')
                c.append(f'  echo "WARNING: md5sum is not available on the destination; {shown} was not re-verified there"')
                c.append(f'elif [ "$__RX_GOT" != {_q(m["md5"])} ]; then')
                c.append(f'  __rx_dst {_q("rm -f " + _q(partial))} </dev/null')
                c.append(f'  __rx_fail "content corruption copying to {shown} on the destination (md5 $__RX_GOT, expected {m["md5"]})"')
                c.append('fi')
            c.append(f'__rx_dst {_q(_move_into_place(partial, dest))} </dev/null'
                     f' || __rx_fail "could not move the copy into place at {shown} on the destination'
                     f' (is it an existing directory?)"')
        if mode and _validate_mode(mode):
            c.append(f'__rx_dst {_q("chmod " + mode + " " + _q(dest))} </dev/null'
                     f' || __rx_fail "could not chmod {shown} on the destination"')
        c.append(f'echo "{CROC_RX_SENTINEL_PLACED} {shown}"')
    c.append('cd /')
    c.append('rm -rf "$__CROC_DIR"')
    c.extend(cleanup)
    c.append(f'echo "{CROC_RX_SENTINEL_DONE}"')
    c.append("# === End remote transfer receive ===")
    return "\n".join(c)


def generate_direct_copy_commands(files: list[dict], source: dict, destination: dict) -> str:
    """Shell commands for a transfer whose endpoints sit behind the SAME agent.

    That agent's container reaches both machines, so no croc and no relay are needed:
    each file is streamed ``ssh source cat | ssh destination 'cat > partial'``, hashed
    on both ends, then moved into place (directories: ``tar c | tar x``, which gzip's
    CRC protects). Nothing is staged on the container's disk. Reports with the
    receiver's sentinels (CROC_RX_SENTINEL_*), so the status tool reads it the same way.

    The environment targets the destination, so the destination's key or password
    comes from SSH_*_ENV and the source's from AUX_SSH_*_ENV.

    Args:
        files: One dict per file: source_path, destination_path, mode (optional).
        source, destination: Dicts with target_ip and ssh_user.
    """
    src_lines, src_cleanup = _ssh_function(
        "__dc_src", source["target_ip"], source["ssh_user"], aux=True)
    dst_lines, dst_cleanup = _ssh_function(
        "__dc_dst", destination["target_ip"], destination["ssh_user"])
    cleanup = src_cleanup + dst_cleanup + ['kill "$__DC_HB" 2>/dev/null']
    c = ["# === Remote transfer: direct copy (both endpoints behind one agent) ==="]
    # A failure on the SOURCE end of a pipe must fail the copy.
    c.append("set -o pipefail")
    c.extend(src_lines)
    c.extend(dst_lines)
    # A long copy prints nothing; a heartbeat keeps the log (and the status calls) alive.
    # sleep itself must not hold the log's stdout: killing the loop then releases it
    # at once instead of after up to 30s.
    c.append('( while sleep 30 </dev/null >/dev/null 2>&1; do echo "[direct copy] still copying (${SECONDS}s)"; done ) &')
    c.append('__DC_HB=$!')
    c.append('__dc_fail() {')
    c.append('  echo "ERROR: $1" >&2')
    c.append(f'  echo "{CROC_RX_SENTINEL_FAILED} exit_code=1 reason=$1"')
    c.extend(f'  {line}' for line in cleanup)
    c.append('  exit 1')
    c.append('}')
    for f in files:
        src, dest, mode = f["source_path"], f["destination_path"], f.get("mode")
        shown_src = re.sub(r'["$`\\]', "?", src)
        shown = re.sub(r'["$`\\]', "?", dest)
        c.append(f'echo "[direct copy] {shown_src} -> {shown}"')
        c.append(f'if __dc_src {_q("test -d " + _q(src))} </dev/null; then')
        c.append(f'  __dc_dst {_q("mkdir -p " + _q(dest))} </dev/null'
                 f' || __dc_fail "could not create {shown} on the destination"')
        c.append(f'  __dc_src {_q("tar czf - -C " + _q(src) + " .")} </dev/null'
                 f' | __dc_dst {_q("tar xzf - -C " + _q(dest))}'
                 f' || __dc_fail "could not copy directory {shown_src} to {shown}"')
        c.append('else')
        partial = dest + ".tt-partial"
        parent = os.path.dirname(dest)
        if parent:
            c.append(f'  __dc_dst {_q("mkdir -p " + _q(parent))} </dev/null'
                     f' || __dc_fail "could not create the directory of {shown} on the destination"')
        c.append(f'  __dc_src {_q("cat " + _q(src))} </dev/null'
                 f' | __dc_dst {_q("cat > " + _q(partial))}'
                 f' || {{ __dc_dst {_q("rm -f " + _q(partial))} </dev/null;'
                 f' __dc_fail "could not copy {shown_src} to {shown}"; }}')
        c.append(f"  __DC_A=$(__dc_src {_q('md5sum ' + _q(src))} </dev/null 2>/dev/null | cut -d' ' -f1)")
        c.append(f"  __DC_B=$(__dc_dst {_q('md5sum ' + _q(partial))} </dev/null 2>/dev/null | cut -d' ' -f1)")
        c.append('  if [ -z "$__DC_A" ] || [ -z "$__DC_B" ]; then')
        c.append(f'    echo "WARNING: md5sum is not available on both machines; {shown} was not verified"')
        c.append('  elif [ "$__DC_A" != "$__DC_B" ]; then')
        c.append(f'    __dc_dst {_q("rm -f " + _q(partial))} </dev/null')
        c.append(f'    __dc_fail "content corruption copying to {shown} (md5 $__DC_B, expected $__DC_A)"')
        c.append('  fi')
        c.append(f'  __dc_dst {_q(_move_into_place(partial, dest))} </dev/null'
                 f' || __dc_fail "could not move the copy into place at {shown} (is it an existing directory?)"')
        c.append('fi')
        if mode and _validate_mode(mode):
            c.append(f'__dc_dst {_q("chmod " + mode + " " + _q(dest))} </dev/null'
                     f' || __dc_fail "could not chmod {shown} on the destination"')
        c.append(f'echo "{CROC_RX_SENTINEL_PLACED} {shown}"')
    c.extend(cleanup)
    c.append(f'echo "{CROC_RX_SENTINEL_DONE}"')
    c.append("# === End direct copy ===")
    return "\n".join(c)


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
    # The relay is always named, never croc's built-in default (DEFAULT_CROC_RELAY).
    relay_address = effective_relay(relay)
    croc_argv = [str(croc_path), "--relay", relay_address, "--yes", "--overwrite"]
    warm_host = _relay_host(relay_address)
    if not _needs_lookup(warm_host):
        warm_host = ""

    retry_script = (
        "import hashlib, json, os, socket, subprocess, sys, threading, time\n"
        f"croc_argv = {croc_argv!r}\n"
        f"warm_host = {warm_host!r}\n"
        f"warm_limit = {CROC_DNS_WARMUP_SECONDS!r}\n"
        f"receive_dir = {receive_dir!r}\n"
        f"code = {code!r}\n"
        f"timeout = {timeout}\n"
        f"retry_interval = {CROC_RECEIVE_RETRY_SECONDS}\n"
        f"gate_poll = {CROC_RECEIVE_GATE_POLL_SECONDS!r}\n"
        f"croc_poll = {CROC_RECEIVE_CROC_POLL_SECONDS!r}\n"
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
        "def warm_dns():\n"
        "    # Look the relay host up so croc's own 500 ms startup lookup is served\n"
        "    # from cache. Bounded, never fatal: a hung resolver is abandoned.\n"
        "    if not warm_host:\n"
        "        return\n"
        "    def lookup():\n"
        "        try:\n"
        "            socket.getaddrinfo(warm_host, None)\n"
        "        except Exception:\n"
        "            pass\n"
        "    t = threading.Thread(target=lookup, daemon=True)\n"
        "    t.start()\n"
        "    t.join(warm_limit)\n"
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
        "        time.sleep(gate_poll)\n"
        "        continue\n"
        "    attempt += 1\n"
        "    log('croc attempt %d starting' % attempt)\n"
        "    warm_dns()\n"
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
        "                time.sleep(croc_poll)\n"
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
    await asyncio.sleep(CROC_RECEIVE_STARTUP_CHECK_SECONDS)

    # Check if it crashed during startup (e.g. syntax error in script).
    # A clean exit (0) is legitimate: files may already be present / the
    # transfer can finish faster than this startup pause.
    if process.returncode is not None and process.returncode != 0:
        raise RuntimeError(
            f"croc receive wrapper exited immediately with code {process.returncode}"
        )

    return process
