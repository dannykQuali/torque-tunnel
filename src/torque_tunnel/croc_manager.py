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


def _get_cache_dir() -> Path:
    """Get platform-appropriate cache directory for the croc binary."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "torque-tunnel" / "bin"


def _get_croc_binary_name() -> str:
    """Return the platform-specific croc binary name."""
    return "croc.exe" if sys.platform == "win32" else "croc"


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
    1. Cached download in platform-specific cache directory (known correct version)
    2. System PATH (only if version matches CROC_VERSION)

    We prefer the cache because the remote side installs CROC_VERSION, and
    both sides must run the same version for the PAKE handshake to succeed.
    """
    # Check cache directory first (guaranteed correct version)
    binary_name = _get_croc_binary_name()
    cache_path = _get_cache_dir() / binary_name
    if cache_path.exists():
        return cache_path

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


def _validate_mode(mode: str) -> bool:
    """Validate a Unix file permission mode string (e.g., '755', '0644')."""
    import re
    return bool(re.match(r'^[0-7]{3,4}$', mode))


def generate_croc_receive_commands(
    code: str,
    file_transfers: list[dict],
    timeout: int = 600,
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

    Returns:
        Shell commands string.
    """
    commands = []
    commands.append("# === Croc file receive ===")
    commands.append('__CROC_DIR=$(mktemp -d)')
    commands.append('cd "$__CROC_DIR"')
    # Use CROC_SECRET env var (not command-line arg) to avoid leaking code in process list
    commands.append(f'timeout {timeout} bash -c \'CROC_SECRET="{code}" croc --yes --overwrite\'')
    commands.append('__CROC_RC=$?')
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
    commands.append(f'timeout {timeout} bash -c \'CROC_SECRET="{code}" croc --yes --overwrite\'')
    commands.append('__CROC_RC=$?')
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
    commands.append("# === End croc receive + SCP ===")
    return "\n".join(commands)


async def start_croc_send(
    croc_path: Path,
    code: str,
    files: list[str],
    timeout: float = 600,
) -> asyncio.subprocess.Process:
    """Start croc send as a background process.

    The process connects to the public relay and waits for a receiver.
    Caller must manage the process lifecycle (await completion or cleanup).

    Args:
        croc_path: Path to local croc binary.
        code: The croc secret code.
        files: List of local file paths to send.
        timeout: Not used directly; croc will wait for receiver.

    Returns:
        The asyncio subprocess Process handle.
    """
    cmd = [
        str(croc_path),
        "--yes",       # No interactive prompts (global option, must precede subcommand)
        "send",
        "--no-local",  # Skip local network discovery (we always use the relay)
    ] + [str(f) for f in files]

    # Pass code via environment variable to avoid exposing it in process list
    env = os.environ.copy()
    env["CROC_SECRET"] = code

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.DEVNULL,   # Prevent parent stdin (e.g., MCP protocol) leaking in
        stdout=asyncio.subprocess.DEVNULL,  # Discard progress output to avoid pipe buffer deadlock
        stderr=asyncio.subprocess.DEVNULL,  # Discard stderr too — croc sends progress there
        env=env,
    )

    # Give croc a few seconds to connect to the relay and register the code
    await asyncio.sleep(CROC_SEND_STARTUP_SECONDS)

    # Check if it crashed during startup
    if process.returncode is not None:
        raise RuntimeError(
            f"croc send exited immediately with code {process.returncode}"
        )

    return process


async def cleanup_croc_send(process: Optional[asyncio.subprocess.Process]) -> None:
    """Clean up a croc send background process.

    Safe to call even if process is None or already terminated.
    """
    if process is None:
        return
    if process.returncode is not None:
        return  # Already finished

    try:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
    except ProcessLookupError:
        pass  # Process already gone
