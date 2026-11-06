"""
torque-tunnel MCP Tool - Execute remote commands via Torque tunneled infrastructure.

This MCP tool provides Copilot with the ability to run commands on remote servers
by tunneling through Torque's agent infrastructure into unreachable networks.
"""

import base64
import gzip
import io
import json
import os
import re
import shutil
import sys
import tarfile
import time
import asyncio
import argparse
import tempfile
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

import httpx

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    LoggingLevel,
)

from .torque_client import TorqueClient
from . import croc_manager
from . import config as config_module
from . import auth as auth_module
from . import onboarding as onboarding_module
from . import credentials as credentials_module
from . import remote_transfer
from . import raw_log


# Shared compiled patterns for filtering grain/execution logs.
# Used by create_log_streamer (MCP streaming), _background_stream_grain_log and
# cli_log_callback (CLI streaming). Complete logs go through filter_grain_log.
# What may be shown of a log is decided by the raw_log module (--raw-log).
_EXECUTION_MARKER = raw_log.EXECUTION_MARKER
# Pattern for first line: [HH:MM:SS.mmm] >> Running on container. Storage: . Task Id: XXX
_FIRST_LINE_PATTERN = re.compile(r'^(\[\d{2}:\d{2}:\d{2}\.\d{3}\] >> Running on .+)$', re.MULTILINE)


def filter_grain_log(log: str) -> str:
    """The part of a complete grain log that may be returned: the command output after
    the execution marker. What happens without the marker depends on --raw-log (see
    raw_log.command_output); by default only the job's setup output, never Torque's
    echo of the script.
    """
    return raw_log.command_output(log)


def format_log_section(heading: str, log: Optional[str], tail_chars: Optional[int] = None) -> str:
    """A "**heading:**" + code block section for a grain log, or "" when there is nothing.

    The one way a tool result shows a grain log: it is filtered by --raw-log, and a log
    withheld entirely says so (with how to see it) instead of disappearing silently.
    """
    if not log:
        return ""
    if raw_log.withheld(log):
        return f"\n\n**{heading}:** {raw_log.HIDDEN_NOTE}"
    shown = filter_grain_log(log)
    if tail_chars is not None:
        shown = shown[-tail_chars:]
    if not shown.strip():
        return ""
    return f"\n\n**{heading}:**\n{format_code_block(shown)}"


def create_log_streamer(session) -> Callable[[str, str], Awaitable[None]]:
    """Create a log callback that streams to stderr and MCP client.

    Filters output to skip the Torque preamble and show only:
    - First line with "Running on" info + environment URL
    - Command output after the execution marker

    With --raw-log always, the full output is streamed instead.
    """
    show_all = raw_log.stream_preamble()
    torque_url = _config.get('torque_url', '')
    torque_space = _config.get('torque_space', '')

    # State for tracking streaming progress
    state = {'found': show_all, 'first_line_shown': show_all, 'buffer': ''}
    
    async def stream_log(content: str, environment_id: str = "") -> None:
        try:
            if state['found']:
                # Already past marker - print everything
                print(content, file=sys.stderr, end='', flush=True)
                session.send_log_message(level="info", data=content, logger="torque_tunnel.grain_log")
                return
            
            # Buffer data to handle markers split across chunks
            state['buffer'] += content
            
            # Show first line with environment info if not yet shown
            if not state['first_line_shown']:
                match = _FIRST_LINE_PATTERN.search(state['buffer'])
                if match:
                    first_line = match.group(1)
                    # Build environment URL
                    env_url = f"{torque_url}/{torque_space}/environments/{environment_id}" if environment_id else ""
                    env_info = f". {env_url}" if environment_id else ""
                    output = f"{first_line}{env_info}\n"
                    print(output, file=sys.stderr, end='', flush=True)
                    session.send_log_message(level="info", data=output, logger="torque_tunnel.grain_log")
                    state['first_line_shown'] = True
            
            # Look for execution marker
            match = _EXECUTION_MARKER.search(state['buffer'])
            if match:
                state['found'] = True
                # Print from after the marker line
                after_marker = state['buffer'][match.end():]
                if after_marker:
                    print(after_marker, file=sys.stderr, end='', flush=True)
                    session.send_log_message(level="info", data=after_marker, logger="torque_tunnel.grain_log")
                state['buffer'] = ''
        except Exception:
            pass  # Ignore streaming errors
    return stream_log


def format_code_block(content: str, language: str = "") -> str:
    """Format content as a markdown code block, handling content that contains backticks.
    
    Uses the minimum number of backticks needed to avoid conflicts with the content.
    Ensures proper line endings to avoid syntax highlighting bleed.
    """
    if not content:
        return f"```{language}\n```\n"
    
    # Find the longest sequence of backticks in the content
    backtick_sequences = re.findall(r'`+', content)
    max_backticks = max((len(seq) for seq in backtick_sequences), default=0)
    
    # Use at least 3 backticks, or one more than the longest sequence in content
    fence_length = max(3, max_backticks + 1)
    fence = '`' * fence_length
    
    # Ensure content ends with newline, and add blank line after closing fence
    content = content.rstrip('\n')
    return f"{fence}{language}\n{content}\n{fence}\n"


# Dangerous commands that can kill the Torque agent
DANGEROUS_PATTERNS = [
    "docker restart",
    "docker stop",
    "docker kill",
    "docker rm",
    "systemctl restart docker",
    "systemctl stop docker",
    "service docker restart",
    "service docker stop",
    "reboot",
    "shutdown",
    "init 0",
    "init 6",
    "poweroff",
    "halt",
]


def check_dangerous_command(command: str) -> str | None:
    """Check if command matches dangerous patterns. Returns warning message if dangerous."""
    cmd_lower = command.lower()
    for pattern in DANGEROUS_PATTERNS:
        # Use word-boundary match so e.g. "docker rm" doesn't flag "docker rmi"
        if re.search(r'(?<!\w)' + re.escape(pattern) + r'(?!\w)', cmd_lower):
            return f"""⚠️ **DANGEROUS COMMAND DETECTED** ⚠️

The command `{command}` contains `{pattern}` which can KILL the Torque agent and cause this operation to fail.

**This command should be run MANUALLY via direct SSH or console access, NOT via this tool.**

If you still want to proceed (NOT RECOMMENDED), call this tool again with the parameter `allow_dangerous_commands=true`.

Reason: The Torque Docker Agent may execute commands on the remote server. Restarting Docker or the agent container will terminate the agent mid-execution, causing an unrecoverable error."""
    return None


def read_ssh_key_file(file_path: str) -> str:
    """Read SSH private key from a file path."""
    expanded_path = os.path.expanduser(file_path)
    
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"SSH private key file not found: {file_path}")
    
    with open(expanded_path, 'r') as f:
        return f.read()


def _normalize_pem_content(pem_content: str) -> str:
    """
    Normalize PEM content from single-line to proper multi-line format.
    
    PEM content is often passed as command-line arguments or environment variables
    where newlines are converted to spaces. This reconstructs the proper format.
    
    From: C:/ZeroTouch/Compute2/blueprints/ai-ready-cluster/common.py
    """
    pem_content = pem_content.strip()
    # Strip Windows CRLF line endings to prevent libcrypto errors
    pem_content = pem_content.replace('\r', '')
    
    # Find BEGIN and END markers and reconstruct proper format
    if '-----BEGIN' in pem_content and '-----END' in pem_content:
        begin_start = pem_content.find('-----BEGIN')
        begin_end = pem_content.find('-----', begin_start + 10) + 5
        header = pem_content[begin_start:begin_end].strip()
        
        end_start = pem_content.find('-----END')
        end_end = pem_content.find('-----', end_start + 8) + 5
        footer = pem_content[end_start:end_end].strip()
        
        # Extract key content between header and footer
        content_start = begin_end
        content_end = end_start
        content = pem_content[content_start:content_end].strip()
        
        # Reconstruct: header, content, footer, each on its own line
        return f"{header}\n{content}\n{footer}\n"
    else:
        # Key doesn't match expected format, use as-is (ensure trailing newline)
        if not pem_content.endswith('\n'):
            pem_content += '\n'
        return pem_content


def normalize_ssh_key(ssh_key_content: str) -> str:
    """Normalize SSH private key content from single-line to proper multi-line format."""
    return _normalize_pem_content(ssh_key_content)


def is_valid_ssh_private_key(content: str) -> bool:
    """Check if content looks like a valid SSH private key."""
    content = content.strip()
    # Check for common private key headers
    valid_headers = [
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        '-----BEGIN RSA PRIVATE KEY-----',
        '-----BEGIN DSA PRIVATE KEY-----',
        '-----BEGIN EC PRIVATE KEY-----',
        '-----BEGIN PRIVATE KEY-----',
    ]
    return any(content.startswith(header) for header in valid_headers)


def resolve_ssh_private_key(value: str) -> str:
    """
    Resolve SSH private key from a file path, key content, or base64-encoded key.
    
    Args:
        value: A file path, the key content directly, or base64-encoded key content
        
    Returns:
        Normalized SSH private key content
        
    Raises:
        ValueError: If the value is not a valid file path, key content, or base64-encoded key
    """
    if not value:
        raise ValueError("SSH private key is required")
    
    # First, try to read as a file path
    expanded_path = os.path.expanduser(value)
    if os.path.exists(expanded_path):
        with open(expanded_path, 'r') as f:
            key_content = f.read()
        return normalize_ssh_key(key_content)
    
    # Not a file - check if it's valid key content
    if is_valid_ssh_private_key(value):
        return normalize_ssh_key(value)
    
    # Try base64 decoding (key may have been passed as base64-encoded string)
    try:
        decoded = base64.b64decode(value, validate=True).decode('utf-8')
        if is_valid_ssh_private_key(decoded):
            return normalize_ssh_key(decoded)
    except Exception:
        pass
    
    # Neither a valid file, valid key content, nor valid base64-encoded key
    raise ValueError(
        f"Invalid private_key: '{value[:50]}{'...' if len(value) > 50 else ''}' "
        f"is not a valid file path, SSH private key content, or base64-encoded key. "
        f"Provide a path to a key file, the key content starting with '-----BEGIN', or a base64-encoded key."
    )


# DEFLATE cannot compress by more than 1032:1, so anything larger than
# cap * MAX_GZIP_RATIO provably cannot fit inline and needs croc — no need to
# read a byte of it. This is what keeps a 15.7 GB image from being gzipped (and
# held in memory) purely to discover it is bigger than 300 KB.
MAX_GZIP_RATIO = 1032

# Chunk size for streaming compression. Bounds memory regardless of file size.
_COMPRESS_CHUNK_BYTES = 1024 * 1024


class _SinkBuffer(io.BytesIO):
    """A BytesIO that stops storing (and flags) once more than ``cap`` bytes arrive.

    Compressed output only ever grows, so passing the cap settles the question:
    the payload needs croc. Later writes are dropped rather than refused, so the
    compressor above still closes cleanly — raising from ``write`` leaves gzip's
    write buffer half-flushed and its finalizer throwing during GC.
    """

    def __init__(self, cap: int):
        super().__init__()
        self._cap = cap
        self.overflowed = False

    def write(self, b):  # type: ignore[override]
        if self.overflowed:
            return len(b)
        written = super().write(b)
        if super().tell() > self._cap:
            self.overflowed = True
        return written


def compress_file_if_inline(path: str, cap: int) -> Optional[bytes]:
    """Gzip a file, stopping as soon as the result cannot fit inline.

    Returns the gzipped bytes when the file fits within ``cap``, or None when it
    has to go over croc. The decision is the same one the old code made by
    gzipping the whole file and measuring — but that held the entire file plus
    its compressed copy in memory (~2.5 GB for a 1.27 GB upload, a MemoryError
    for a multi-GB image) just to compare against 300 KB.
    """
    if os.path.getsize(path) > cap * MAX_GZIP_RATIO:
        return None

    buffer = _SinkBuffer(cap)
    with gzip.GzipFile(fileobj=buffer, mode="wb") as gz:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_COMPRESS_CHUNK_BYTES), b""):
                gz.write(chunk)
                if buffer.overflowed:
                    break
    if buffer.overflowed:
        return None
    data = buffer.getvalue()
    return data if len(data) <= cap else None


def _tree_size(path: str) -> int:
    """Bytes tar would have to write for the files under ``path``.

    Symlinks are not followed, and hardlinks are counted once — tar stores the
    second and later names as links. Counting them once keeps this an
    *under*-estimate of the tar payload, which is the safe direction: the caller
    only uses it to skip work it can prove is pointless.
    """
    total = 0
    seen: set = set()
    for _root, _dirs, filenames in os.walk(path):
        for filename in filenames:
            try:
                st = os.lstat(os.path.join(_root, filename))
            except OSError:
                continue
            if st.st_nlink > 1:
                key = (st.st_dev, st.st_ino)
                if key in seen:
                    continue
                seen.add(key)
            total += st.st_size
    return total


def compress_dir_if_inline(path: str, cap: int) -> Optional[bytes]:
    """Tar+gzip a directory, stopping as soon as the result cannot fit inline.

    Same contract (and same reason) as compress_file_if_inline.
    """
    if _tree_size(path) > cap * MAX_GZIP_RATIO:
        return None

    buffer = _SinkBuffer(cap)
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for root, dirs, filenames in os.walk(path):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                tar.add(full_path, arcname=os.path.relpath(full_path, path))
                if buffer.overflowed:
                    break
            for dirname in dirs:
                full_path = os.path.join(root, dirname)
                tar.add(full_path, arcname=os.path.relpath(full_path, path),
                        recursive=False)
            if buffer.overflowed:
                break
    if buffer.overflowed:
        return None
    data = buffer.getvalue()
    return data if len(data) <= cap else None


def prepare_files_deployment(files: list[dict]) -> tuple[str, list[str]]:
    """
    Prepare shell commands to deploy files before command execution.
    
    Reads local files/directories and generates shell commands to write them
    on the target system. Files are written BEFORE init_commands run.
    
    Args:
        files: List of file specs, each with:
            - local_source_path: Path to local file or directory to upload
            - content: Direct content string (alternative to local_source_path)
            - remote_destination_path: Destination path on target
            - mode: Optional file permissions (e.g., "755")
    
    Returns:
        Tuple of (shell_commands_string, error_messages)
        If errors exist, the shell_commands_string will be empty.
    """
    
    if not files:
        return "", []
    
    errors = []
    commands = []
    commands.append("# === File Deployment ===")
    
    for i, file_spec in enumerate(files):
        remote_path = file_spec.get("remote_destination_path")
        local_path = file_spec.get("local_source_path")
        content = file_spec.get("content")
        mode = file_spec.get("mode")
        
        if not remote_path:
            errors.append(f"File {i+1}: missing 'remote_destination_path'")
            continue
        
        # Escape remote path for shell
        escaped_remote = remote_path.replace("'", "'\\''")
        remote_dir = os.path.dirname(remote_path)
        escaped_dir = remote_dir.replace("'", "'\\''") if remote_dir else ""
        
        # Get content from local_source_path or direct content
        if local_path and content:
            errors.append(f"File {i+1}: provide either 'local_source_path' OR 'content', not both")
            continue
        elif not local_path and not content:
            errors.append(f"File {i+1}: must provide either 'local_source_path' or 'content'")
            continue
        
        if local_path:
            expanded = os.path.expanduser(local_path)
            if not os.path.exists(expanded):
                errors.append(f"File {i+1}: local path not found: {local_path}")
                continue
            
            if os.path.isdir(expanded):
                # Directory - create tar archive
                try:
                    tar_buffer = io.BytesIO()
                    with tarfile.open(fileobj=tar_buffer, mode='w:gz') as tar:
                        # Add directory contents with relative paths
                        for root, dirs, filenames in os.walk(expanded):
                            for filename in filenames:
                                full_path = os.path.join(root, filename)
                                arcname = os.path.relpath(full_path, expanded)
                                tar.add(full_path, arcname=arcname)
                            for dirname in dirs:
                                full_path = os.path.join(root, dirname)
                                arcname = os.path.relpath(full_path, expanded)
                                tar.add(full_path, arcname=arcname, recursive=False)
                    tar_b64 = base64.b64encode(tar_buffer.getvalue()).decode('ascii')
                    
                    # Generate commands to create dir and extract tar
                    commands.append(f"mkdir -p '{escaped_remote}'")
                    commands.append(f"echo '{tar_b64}' | base64 -d | tar xzf - -C '{escaped_remote}'")
                except Exception as e:
                    errors.append(f"File {i+1}: error creating tar: {e}")
                    continue
            else:
                # Regular file - use gzip compression like directories
                try:
                    with open(expanded, 'rb') as f:
                        file_bytes = f.read()
                    compressed = gzip.compress(file_bytes)
                    file_b64 = base64.b64encode(compressed).decode('ascii')
                    
                    if escaped_dir:
                        commands.append(f"mkdir -p '{escaped_dir}'")
                    commands.append(f"echo '{file_b64}' | base64 -d | gzip -d > '{escaped_remote}'")
                    if mode:
                        commands.append(f"chmod {mode} '{escaped_remote}'")
                except Exception as e:
                    errors.append(f"File {i+1}: error reading file: {e}")
                    continue
        else:
            # Direct content - use gzip compression
            try:
                if isinstance(content, bytes):
                    content_bytes = content
                else:
                    content_bytes = content.encode('utf-8')
                compressed = gzip.compress(content_bytes)
                content_b64 = base64.b64encode(compressed).decode('ascii')
                
                if escaped_dir:
                    commands.append(f"mkdir -p '{escaped_dir}'")
                commands.append(f"echo '{content_b64}' | base64 -d | gzip -d > '{escaped_remote}'")
                if mode:
                    commands.append(f"chmod {mode} '{escaped_remote}'")
            except Exception as e:
                errors.append(f"File {i+1}: error encoding content: {e}")
                continue
    
    commands.append("# === End File Deployment ===")
    
    if errors:
        return "", errors
    
    return "\n".join(commands), []


@dataclass
class FileDeploymentPlan:
    """Result of preparing files for deployment, potentially using croc for large files.
    
    For small files: only inline_commands is populated (existing base64 approach).
    For large files: croc fields are populated, and the caller must manage the croc lifecycle.
    """
    # Shell commands for inline (small) files — runs on the target/container
    inline_commands: str = ""
    # Shell commands for croc install + receive — runs where croc receive needs to happen
    croc_init_commands: str = ""
    # Shell commands for croc receive + SCP (SSH targets only) — runs on the CONTAINER
    croc_container_pre_commands: str = ""
    # The croc secret code (needed to start local croc send)
    croc_code: str = ""
    # Local file paths that need croc send
    croc_local_files: list[str] = field(default_factory=list)
    # Temp staging directory for uniquely-named files (cleaned up after transfer)
    croc_staging_dir: str = ""
    # Relay settings resolved once, when the receive commands were generated.
    # Both sides MUST agree on the relay, and config hot-reload could otherwise
    # change it between generating those commands and starting the local send.
    croc_relay: str = ""
    croc_relay_password: str = ""
    croc_transfers: Optional[int] = None
    # Whether croc transfer is needed
    needs_croc: bool = False
    # Errors during preparation
    errors: list[str] = field(default_factory=list)
    # File info strings for output reporting
    files_info: list[str] = field(default_factory=list)


def _croc_relay_settings(config: Optional[dict] = None) -> dict:
    """Relay options for every croc invocation, resolved from the call's config.

    That is the call's effective config (its `profile`), not the global one: reading
    the global config made a per-call profile's croc_relay be silently ignored while
    its init_commands were applied. Empty values mean croc's public relay, whose
    admission limiter is keyed on this machine's public IP and shared with every other
    session behind it.
    """
    cfg = config or _config
    transfers = cfg.get("croc_transfers")
    try:
        transfers = int(transfers) if transfers else None
    except (TypeError, ValueError):
        transfers = None
    return {
        "relay": str(cfg.get("croc_relay") or ""),
        "relay_password": str(cfg.get("croc_relay_password") or ""),
        "transfers": transfers,
    }


def prepare_files_with_croc(
    files: list[dict],
    transfer_mode: str = "container",
    target_ip: str = "",
    ssh_user: str = "",
    ssh_private_key: str = "",
    ssh_password: str = "",
    config: Optional[dict] = None,
) -> FileDeploymentPlan:
    """Prepare file deployment, using croc for files exceeding the inline threshold.
    
    Splits files into two groups:
    - Small files (compressed < 300KB): deployed via inline base64 (existing approach)
    - Large files: deployed via croc (peer-to-peer encrypted transfer)
    
    Args:
        files: List of file specs (same format as prepare_files_deployment).
        transfer_mode: "container" for disposable/persistent containers,
                       "ssh" for SSH targets (requires croc receive on container + SCP).
        target_ip: SSH target IP (only for transfer_mode="ssh").
        ssh_user: SSH user (only for transfer_mode="ssh").
        ssh_private_key: SSH private key (only for transfer_mode="ssh").
        ssh_password: SSH password (only for transfer_mode="ssh").
        config: The call's effective config, for the croc relay (default: global).

    Returns:
        FileDeploymentPlan with deployment commands and croc transfer info.
    """
    
    plan = FileDeploymentPlan()
    
    if not files:
        return plan
    
    inline_files = []  # Files that fit inline
    croc_files = []    # Files that need croc
    # Torque's payload limit applies to the whole CALL (grain hangs ~450 KB, API
    # 413 ~600 KB), so the inline budget is shared by every file in it: two 290 KB
    # files used to pass a per-file check one by one and then travel together as
    # a 774 KB payload. A single file gets exactly the old per-file allowance.
    inline_budget = croc_manager.CROC_THRESHOLD_BYTES

    for i, file_spec in enumerate(files):
        remote_path = file_spec.get("remote_destination_path")
        local_path = file_spec.get("local_source_path")
        content = file_spec.get("content")
        mode = file_spec.get("mode")
        
        if not remote_path:
            plan.errors.append(f"File {i+1}: missing 'remote_destination_path'")
            continue
        
        if local_path and content:
            plan.errors.append(f"File {i+1}: provide either 'local_source_path' OR 'content', not both")
            continue
        elif not local_path and not content:
            plan.errors.append(f"File {i+1}: must provide either 'local_source_path' or 'content'")
            continue
        
        # Track file info for reporting
        plan.files_info.append(
            f"{local_path or '<content>'} -> {remote_path}"
        )
        
        # Content goes inline while it fits the call's remaining budget, and
        # takes the croc path (staged as a real file) when it doesn't.
        if content:
            content_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
            content_gz = gzip.compress(content_bytes)
            if len(content_gz) <= inline_budget:
                file_spec["_content_gz_b64"] = base64.b64encode(content_gz).decode("ascii")
                inline_budget -= len(content_gz)
                inline_files.append(file_spec)
            else:
                file_spec["_content_bytes"] = content_bytes
                croc_files.append(file_spec)
            continue
        
        # Check local file/directory size
        expanded = os.path.expanduser(local_path)
        if not os.path.exists(expanded):
            plan.errors.append(f"File {i+1}: local path not found: {local_path}")
            continue
        
        # The inline-vs-croc decision is made on COMPRESSED size, against what is
        # LEFT of this call's budget, and the compression stops the moment it
        # passes that — a multi-GB upload must never be read into memory just to
        # be told it needs croc.
        if os.path.isdir(expanded):
            try:
                tar_gz = compress_dir_if_inline(expanded, inline_budget)
                if tar_gz is None:
                    croc_files.append(file_spec)
                else:
                    # Store pre-computed tar for inline use
                    file_spec["_tar_b64"] = base64.b64encode(tar_gz).decode("ascii")
                    inline_budget -= len(tar_gz)
                    inline_files.append(file_spec)
            except Exception as e:
                plan.errors.append(f"File {i+1}: error reading directory: {e}")
                continue
        else:
            try:
                compressed = compress_file_if_inline(expanded, inline_budget)
                if compressed is None:
                    croc_files.append(file_spec)
                else:
                    # Store pre-computed compressed data for inline use
                    file_spec["_compressed_b64"] = base64.b64encode(compressed).decode("ascii")
                    inline_budget -= len(compressed)
                    inline_files.append(file_spec)
            except Exception as e:
                plan.errors.append(f"File {i+1}: error reading file: {e}")
                continue
    
    if plan.errors:
        _drop_cached_payloads(files)
        return plan

    # --- Generate inline commands for small files ---
    if inline_files:
        commands = ["# === File Deployment (inline) ==="]
        for file_spec in inline_files:
            remote_path = file_spec["remote_destination_path"]
            local_path = file_spec.get("local_source_path")
            content = file_spec.get("content")
            mode = file_spec.get("mode")
            escaped_remote = remote_path.replace("'", "'\\''")
            remote_dir = os.path.dirname(remote_path)
            escaped_dir = remote_dir.replace("'", "'\\''") if remote_dir else ""
            
            if local_path:
                expanded = os.path.expanduser(local_path)
                if os.path.isdir(expanded):
                    tar_b64 = file_spec.get("_tar_b64")
                    if not tar_b64:
                        # Should not happen, but compute if needed
                        import tarfile as tf_mod
                        buf = io.BytesIO()
                        with tf_mod.open(fileobj=buf, mode='w:gz') as tar:
                            for root, dirs, filenames in os.walk(expanded):
                                for fn in filenames:
                                    fp = os.path.join(root, fn)
                                    tar.add(fp, arcname=os.path.relpath(fp, expanded))
                        tar_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
                    commands.append(f"mkdir -p '{escaped_remote}'")
                    commands.append(f"echo '{tar_b64}' | base64 -d | tar xzf - -C '{escaped_remote}'")
                else:
                    file_b64 = file_spec.get("_compressed_b64")
                    if not file_b64:
                        with open(expanded, 'rb') as f:
                            file_b64 = base64.b64encode(gzip.compress(f.read())).decode("ascii")
                    if escaped_dir:
                        commands.append(f"mkdir -p '{escaped_dir}'")
                    commands.append(f"echo '{file_b64}' | base64 -d | gzip -d > '{escaped_remote}'")
                    if mode:
                        commands.append(f"chmod {mode} '{escaped_remote}'")
            else:
                # Direct content (already compressed when its budget was checked)
                content_b64 = file_spec.get("_content_gz_b64")
                if not content_b64:
                    content_bytes = content if isinstance(content, bytes) else content.encode('utf-8')
                    content_b64 = base64.b64encode(gzip.compress(content_bytes)).decode("ascii")
                if escaped_dir:
                    commands.append(f"mkdir -p '{escaped_dir}'")
                commands.append(f"echo '{content_b64}' | base64 -d | gzip -d > '{escaped_remote}'")
                if mode:
                    commands.append(f"chmod {mode} '{escaped_remote}'")
        
        commands.append("# === End File Deployment (inline) ===")
        plan.inline_commands = "\n".join(commands)
    
    # --- Generate croc commands for large files ---
    if croc_files:
        plan.needs_croc = True
        plan.croc_code = croc_manager.generate_croc_code()
        # Pin the relay for this transfer; execute_with_croc reads it back so the
        # two sides cannot end up on different relays.
        relay_settings = _croc_relay_settings(config)
        plan.croc_relay = relay_settings["relay"]
        plan.croc_relay_password = relay_settings["relay_password"]
        plan.croc_transfers = relay_settings["transfers"]
        
        # Create a staging directory with uniquely-named files to avoid basename collisions.
        # Directories are tarred to match the inline extraction semantics.
        staging_dir = tempfile.mkdtemp(prefix="torque_croc_")
        plan.croc_staging_dir = staging_dir
        
        croc_transfer_info = []
        for i, file_spec in enumerate(croc_files):
            remote_path = file_spec["remote_destination_path"]
            mode = file_spec.get("mode")

            if "_content_bytes" in file_spec:
                # Content that did not fit the inline budget: stage it as a file
                unique_name = f"_croc_{i}_{os.path.basename(remote_path) or 'content'}"
                staged_path = os.path.join(staging_dir, unique_name)
                with open(staged_path, "wb") as f:
                    f.write(file_spec["_content_bytes"])
                plan.croc_local_files.append(staged_path)
                croc_transfer_info.append({
                    "croc_filename": unique_name,
                    "remote_destination_path": remote_path,
                    "mode": mode,
                    "is_dir_tar": False,
                })
                continue

            local_path = file_spec["local_source_path"]
            expanded = os.path.expanduser(local_path)

            basename = os.path.basename(expanded)

            if os.path.isdir(expanded):
                # Tar directory for consistent extraction semantics (matches inline behavior)
                unique_name = f"_croc_{i}_{basename}.tar.gz"
                tar_path = os.path.join(staging_dir, unique_name)
                with tarfile.open(tar_path, 'w:gz') as tar:
                    # arcname="." puts directory contents at archive root
                    tar.add(expanded, arcname=".")
                plan.croc_local_files.append(tar_path)
                croc_transfer_info.append({
                    "croc_filename": unique_name,
                    "remote_destination_path": remote_path,
                    "mode": mode,
                    "is_dir_tar": True,
                })
            else:
                # Copy file with unique name to staging dir
                unique_name = f"_croc_{i}_{basename}"
                staged_path = os.path.join(staging_dir, unique_name)
                shutil.copy2(expanded, staged_path)
                plan.croc_local_files.append(staged_path)
                croc_transfer_info.append({
                    "croc_filename": unique_name,
                    "remote_destination_path": remote_path,
                    "mode": mode,
                    "is_dir_tar": False,
                })
        
        # Generate croc install + receive commands
        croc_install = croc_manager.generate_remote_croc_install_script()
        
        # Calculate croc timeout based on total file size: 600s base + 1s per MB
        total_croc_bytes = sum(os.path.getsize(f) for f in plan.croc_local_files)
        croc_timeout = 600 + total_croc_bytes // (1024 * 1024)
        
        if transfer_mode == "ssh":
            # For SSH: croc receive happens on the CONTAINER, then SCP to target
            croc_scp = croc_manager.generate_croc_scp_commands(
                code=plan.croc_code,
                file_transfers=croc_transfer_info,
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                ssh_password=ssh_password,
                timeout=croc_timeout,
                relay=plan.croc_relay,
                relay_password=plan.croc_relay_password,
            )
            plan.croc_container_pre_commands = croc_install + "\n" + croc_scp
        else:
            # For containers: croc receive runs directly in init_commands
            croc_recv = croc_manager.generate_croc_receive_commands(
                code=plan.croc_code,
                file_transfers=croc_transfer_info,
                timeout=croc_timeout,
                relay=plan.croc_relay,
                relay_password=plan.croc_relay_password,
            )
            plan.croc_init_commands = croc_install + "\n" + croc_recv
    
    _drop_cached_payloads(files)
    return plan


def _drop_cached_payloads(files: list[dict]) -> None:
    """Remove the payloads prepare_files_with_croc cached on the caller's specs.

    The specs are the caller's own dicts (the tool's arguments), so nothing
    computed here - least of all whole file contents - may stay attached to them.
    """
    for file_spec in files:
        for key in ("_tar_b64", "_compressed_b64", "_content_gz_b64", "_content_bytes"):
            file_spec.pop(key, None)


async def execute_with_croc(plan: FileDeploymentPlan) -> asyncio.subprocess.Process:
    """Start the local croc send process for a deployment plan.
    
    Must be called BEFORE launching the Torque environment.
    The returned process stays alive until the remote side receives.
    Caller MUST call croc_manager.cleanup_croc_send() when done.
    
    Args:
        plan: A FileDeploymentPlan with needs_croc=True.
    
    Returns:
        The background croc send process.
    """
    croc_path = await croc_manager.ensure_local_croc()
    process = await croc_manager.start_croc_send(
        croc_path=croc_path,
        code=plan.croc_code,
        files=plan.croc_local_files,
        relay=plan.croc_relay,
        relay_password=plan.croc_relay_password,
        transfers=plan.croc_transfers,
    )
    return process


async def cleanup_croc_resources(
    croc_process: Optional[asyncio.subprocess.Process] = None,
    staging_dir: str = "",
) -> None:
    """Clean up croc send process and staging directory.
    
    Safe to call with None/empty values.
    """
    if croc_process is not None:
        await croc_manager.cleanup_croc_send(croc_process)
    if staging_dir and os.path.exists(staging_dir):
        shutil.rmtree(staging_dir, ignore_errors=True)


# --- Download (remote→local) support ---

# Every sentinel the remote croc-send wrapper can emit. The first one observed
# marks the start of the transfer (DownloadPlan.transfer_started_at); ordinary
# command output streams through the same observer and must not.
_DOWNLOAD_SENTINELS = (
    croc_manager.CROC_SENTINEL_SIZE,
    croc_manager.CROC_SENTINEL_MD5,
    croc_manager.CROC_SENTINEL_READY,
    croc_manager.CROC_SENTINEL_RETRY,
    croc_manager.CROC_SENTINEL_FAILED,
    croc_manager.CROC_SENTINEL_DONE,
)


@dataclass
class DownloadPlan:
    """Result of preparing download instructions for remote→local file transfer via croc.

    Besides the prepared commands, this carries the sentinel-watcher state: the
    remote croc-send wrapper emits coordination sentinels (croc_manager.CROC_SENTINEL_*)
    into the streamed output, observe_output() parses them, and signal files in
    croc_receive_dir relay them to the receive retry wrapper (sender-first
    handshake, abort, expected sizes). See docs/croc-file-transfer.md.
    """
    # Shell commands to run on the container/target AFTER the main command (croc send)
    download_commands: str = ""
    # The croc secret code (needed to start local croc receive)
    croc_code: str = ""
    # Local directory where croc receive will save files
    croc_receive_dir: str = ""
    # Relay settings pinned when the remote send commands were generated, for the
    # same reason as FileDeploymentPlan: both sides must agree on the relay.
    croc_relay: str = ""
    croc_relay_password: str = ""
    croc_transfers: Optional[int] = None
    # Mapping from croc_filename → local_destination_path for post-receive file placement
    file_mappings: list[dict] = field(default_factory=list)
    # Whether download is needed
    needs_download: bool = False
    # Errors during preparation
    errors: list[str] = field(default_factory=list)
    # File info strings for output reporting
    files_info: list[str] = field(default_factory=list)
    # Expected file sizes reported by the remote sender (croc_filename → bytes)
    expected_sizes: dict = field(default_factory=dict)
    # Expected content hashes reported by the remote sender (croc_filename → md5 hex).
    # Size alone is NOT integrity: croc pre-sizes the destination file, so a
    # dead transfer can leave a size-correct file full of holes.
    expected_hashes: dict = field(default_factory=dict)
    # Sentinel observations from the streamed remote output
    send_ready_seen: bool = False
    send_done_seen: bool = False
    remote_failed: bool = False
    remote_failure: str = ""
    # Transfer timing (time.monotonic). The clock starts at the sender's FIRST
    # sentinel and stops when complete_download() is done, because the command's
    # own Duration excludes the transfer entirely: a download that spent 46 s
    # failing was once reported next to "Duration: 0.2s".
    transfer_started_at: Optional[float] = None
    transfer_seconds: Optional[float] = None
    # Partial-line carry-over for observe_output chunk handling
    _watch_tail: str = field(default="", repr=False)

    def observe_output(self, content: str) -> None:
        """Feed a chunk of streamed remote output to the sentinel watcher.

        Chunks may split lines arbitrarily; only complete (newline-terminated)
        lines are examined. Safe to call with duplicated content (log rotation
        overlap) — all reactions are idempotent.
        """
        if not self.needs_download or not content:
            return
        data = self._watch_tail + content
        lines = data.split("\n")
        # Keep the (possibly incomplete) last line for the next chunk, bounded
        self._watch_tail = lines.pop()[-1024:]
        for raw in lines:
            line = raw.strip()
            if self.transfer_started_at is None and any(
                    s in line for s in _DOWNLOAD_SENTINELS):
                self.transfer_started_at = time.monotonic()
            if croc_manager.CROC_SENTINEL_SIZE in line:
                payload = line.split(croc_manager.CROC_SENTINEL_SIZE, 1)[1].strip()
                size_str, _, name = payload.partition(" ")
                name = name.strip()
                if name and size_str.isdigit():
                    self.expected_sizes[name] = int(size_str)
                    self._write_expected_manifest()
            elif croc_manager.CROC_SENTINEL_MD5 in line:
                payload = line.split(croc_manager.CROC_SENTINEL_MD5, 1)[1].strip()
                md5_hex, _, name = payload.partition(" ")
                name = name.strip()
                if name and re.fullmatch(r"[0-9a-fA-F]{32}", md5_hex):
                    self.expected_hashes[name] = md5_hex.lower()
                    self._write_expected_manifest()
            elif croc_manager.CROC_SENTINEL_READY in line:
                self.send_ready_seen = True
                self._signal(croc_manager.CROC_READY_SIGNAL)
            elif croc_manager.CROC_SENTINEL_RETRY in line:
                # Sender is restarting croc send — hold the receiver off until
                # the new room is registered (a fresh READY sentinel re-arms it)
                self._clear_signal(croc_manager.CROC_READY_SIGNAL)
            elif croc_manager.CROC_SENTINEL_FAILED in line:
                self.remote_failed = True
                self.remote_failure = line[line.index(croc_manager.CROC_SENTINEL_FAILED):]
                self.signal_abort()
            elif croc_manager.CROC_SENTINEL_DONE in line:
                self.send_done_seen = True

    def signal_abort(self) -> None:
        """Tell the local receive wrapper to stop retrying immediately."""
        self._signal(croc_manager.CROC_ABORT_SIGNAL)

    def _signal(self, filename: str) -> None:
        if not self.croc_receive_dir:
            return
        try:
            with open(os.path.join(self.croc_receive_dir, filename), "w") as f:
                f.write("1")
        except OSError:
            pass

    def _clear_signal(self, filename: str) -> None:
        if not self.croc_receive_dir:
            return
        try:
            os.remove(os.path.join(self.croc_receive_dir, filename))
        except OSError:
            pass

    def _write_expected_manifest(self) -> None:
        if not self.croc_receive_dir:
            return
        manifest = {
            name: {
                "size": self.expected_sizes.get(name),
                "md5": self.expected_hashes.get(name),
            }
            for name in set(self.expected_sizes) | set(self.expected_hashes)
        }
        path = os.path.join(self.croc_receive_dir, croc_manager.CROC_EXPECTED_SIZES_FILE)
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(manifest, f)
        except OSError:
            return
        # On Windows os.replace fails transiently while another process has
        # the destination open (the receive wrapper polls this file; AV and
        # indexers also take peeks). A silently-stale manifest would degrade
        # verification to size-only — retry briefly before giving up.
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                return
            except OSError:
                time.sleep(0.05)
        try:
            os.remove(tmp)
        except OSError:
            pass


def make_download_watch_callback(dl_plan: DownloadPlan, inner=None):
    """Wrap a log callback so streamed remote output also feeds the download watcher.

    Every execution path that passes download_commands MUST wire this in (the
    gated receiver won't start until the watcher sees the sender's READY
    sentinel in the stream). `inner` may be None — the returned callback then
    only watches.
    """
    async def _watch(content: str, environment_id: str = "") -> None:
        try:
            dl_plan.observe_output(content)
        except Exception:
            pass  # Watching must never break log streaming
        if inner is not None:
            await inner(content, environment_id)
    return _watch


def prepare_download_with_croc(
    files: list[dict],
    transfer_mode: str = "container",
    target_ip: str = "",
    ssh_user: str = "",
    ssh_private_key: str = "",
    ssh_password: str = "",
    config: Optional[dict] = None,
) -> DownloadPlan:
    """Prepare download plan for remote→local file transfer via croc.
    
    Generates shell commands to run on the remote side (croc send) and
    prepares the local side (croc receive directory and file mappings).
    
    Args:
        files: List of dicts with remote_source_path and local_destination_path.
        transfer_mode: "container" for disposable containers (files on container),
                       "ssh" for SSH targets (SCP from target to container, then croc send).
        target_ip: SSH target IP (only for transfer_mode="ssh").
        ssh_user: SSH user (only for transfer_mode="ssh").
        ssh_private_key: SSH private key (only for transfer_mode="ssh").
        ssh_password: SSH password (only for transfer_mode="ssh").
        config: The call's effective config, for the croc relay (default: global).

    Returns:
        DownloadPlan with download commands and croc receive info.
    """
    plan = DownloadPlan()
    
    if not files:
        return plan
    
    plan.needs_download = True
    plan.croc_code = croc_manager.generate_croc_code()
    _dl_relay = _croc_relay_settings(config)
    plan.croc_relay = _dl_relay["relay"]
    plan.croc_relay_password = _dl_relay["relay_password"]
    plan.croc_transfers = _dl_relay["transfers"]
    
    # Create local receive directory
    receive_dir = tempfile.mkdtemp(prefix="torque_dl_")
    plan.croc_receive_dir = receive_dir
    
    # Build file info list for croc
    file_infos = []
    for i, file_spec in enumerate(files):
        remote_path = file_spec["remote_source_path"]
        local_path = file_spec["local_destination_path"]
        basename = os.path.basename(remote_path.rstrip("/\\"))
        croc_filename = f"_croc_dl_{i}_{basename}"
        
        file_infos.append({
            "remote_source_path": remote_path,
            "croc_filename": croc_filename,
        })
        plan.file_mappings.append({
            "croc_filename": croc_filename,
            "local_destination_path": local_path,
        })
        plan.files_info.append(f"  {remote_path} → {local_path}")
    
    # Generate croc install + send commands for the remote side. The install
    # reports its own failure through the FAILED sentinel: the local receiver
    # only learns about the sender from sentinels.
    croc_install = croc_manager.generate_remote_croc_install_script(
        failure_sentinel=croc_manager.CROC_SENTINEL_FAILED)
    
    if transfer_mode == "ssh":
        # For SSH: SCP files from target to container, then croc send
        croc_send = croc_manager.generate_croc_scp_download_commands(
            code=plan.croc_code,
            file_infos=file_infos,
            target_ip=target_ip,
            ssh_user=ssh_user,
            ssh_private_key=ssh_private_key,
            ssh_password=ssh_password,
            relay=plan.croc_relay,
            relay_password=plan.croc_relay_password,
            transfers=plan.croc_transfers,
        )
    else:
        # For containers: croc send directly from the container
        croc_send = croc_manager.generate_croc_send_commands(
            code=plan.croc_code,
            file_infos=file_infos,
            relay=plan.croc_relay,
            relay_password=plan.croc_relay_password,
            transfers=plan.croc_transfers,
        )
    
    plan.download_commands = croc_install + "\n" + croc_send
    return plan


async def execute_download_receive(
    plan: DownloadPlan,
    command_timeout: Optional[int] = None,
) -> asyncio.subprocess.Process:
    """Start the local croc receive process for a download plan.

    Must be called BEFORE launching the Torque environment. The receiver is
    GATED: it stays idle until the sentinel watcher sees the remote sender
    register its relay room (sender-first handshake) — so the caller MUST also
    wire make_download_watch_callback() into the environment's log stream.
    Caller MUST call cleanup_download_resources() when done.

    Args:
        plan: A DownloadPlan with needs_download=True.
        command_timeout: The remote command timeout in seconds, if known. The
            receiver deadline extends beyond it so a long-running remote
            command can't outlive its receiver.

    Returns:
        The background croc receive process.
    """
    croc_path = await croc_manager.ensure_local_croc()
    receive_timeout = 1800
    if command_timeout:
        receive_timeout = max(receive_timeout, int(command_timeout) + 300)
    process = await croc_manager.start_croc_receive(
        croc_path=croc_path,
        code=plan.croc_code,
        receive_dir=plan.croc_receive_dir,
        timeout=receive_timeout,
        gated=True,
        relay=plan.croc_relay,
        relay_password=plan.croc_relay_password,
    )
    return process


def _md5_of_file(path: str) -> str:
    """Chunked MD5 of a file (multi-GB downloads must not be read whole)."""
    import hashlib
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def finalize_download(plan: DownloadPlan) -> tuple[list[str], list[str]]:
    """Move received croc files to their final local destinations.

    Called after the environment has completed and croc receive has finished.
    Verifies received file sizes against the sender-reported sizes (when known)
    so a partial/truncated transfer is reported as a failure instead of being
    placed at the destination as if it completed.
    Retries briefly on file lock errors (e.g. croc still releasing the handle).

    Args:
        plan: The DownloadPlan with file_mappings and croc_receive_dir.

    Returns:
        Tuple of (successes, errors) lists of strings.
    """
    successes = []
    errors = []

    for mapping in plan.file_mappings:
        croc_filename = mapping["croc_filename"]
        local_dest = mapping["local_destination_path"]
        received_path = os.path.join(plan.croc_receive_dir, croc_filename)

        if not os.path.exists(received_path):
            errors.append(f"Download failed for {local_dest}: file not received ({croc_filename})")
            continue

        expected_size = plan.expected_sizes.get(croc_filename)
        if expected_size is not None and os.path.isfile(received_path):
            actual_size = os.path.getsize(received_path)
            if actual_size != expected_size:
                errors.append(
                    f"Download failed for {local_dest}: incomplete transfer of "
                    f"{croc_filename} ({actual_size} of {expected_size} bytes)"
                )
                continue

        # Size match is not integrity: croc pre-sizes the destination file, so
        # a dead transfer can leave a size-correct file full of holes. Verify
        # content against the sender-reported hash before placing the file.
        expected_md5 = plan.expected_hashes.get(croc_filename)
        if expected_md5 and os.path.isfile(received_path):
            try:
                actual_md5 = _md5_of_file(received_path)
            except OSError as e:
                errors.append(f"Download failed for {local_dest}: could not hash {croc_filename}: {e}")
                continue
            if actual_md5 != expected_md5:
                errors.append(
                    f"Download failed for {local_dest}: content corruption in "
                    f"{croc_filename} (md5 {actual_md5}, expected {expected_md5})"
                )
                continue

        # Retry move a few times in case croc just released the file handle
        max_retries = 5
        last_error = None
        for attempt in range(max_retries):
            try:
                # Ensure parent directory exists
                dest_dir = os.path.dirname(os.path.abspath(local_dest))
                os.makedirs(dest_dir, exist_ok=True)
                
                # Remove existing destination if present
                if os.path.exists(local_dest):
                    if os.path.isdir(local_dest):
                        shutil.rmtree(local_dest)
                    else:
                        os.remove(local_dest)
                
                # Move received file/directory to final destination
                shutil.move(received_path, local_dest)
                successes.append(f"Downloaded: {local_dest}")
                last_error = None
                break
            except PermissionError as e:
                last_error = e
                if attempt < max_retries - 1:
                    time.sleep(1)  # Brief wait for file handle release
            except Exception as e:
                last_error = e
                break  # Non-permission errors don't retry
        
        if last_error is not None:
            errors.append(f"Failed to place {croc_filename} at {local_dest}: {last_error}")
    
    return successes, errors


async def complete_download(
    dl_plan: Optional[DownloadPlan],
    dl_process: Optional[asyncio.subprocess.Process],
) -> tuple[list[str], list[str]]:
    """Wind down the local receiver after the remote command finished, then
    move received files into place.

    Replaces the old unbounded ``await dl_process.wait()`` (which let a failed
    transfer silently burn the receiver's full 30-minute deadline):
    - If the remote sender reported failure, or never registered its relay
      room, the receiver is aborted immediately.
    - Otherwise the receiver gets a bounded grace period to flush.

    Does NOT clean up resources — callers keep cleanup_download_resources()
    in their finally blocks.

    Returns:
        Tuple of (successes, errors) lists of strings.
    """
    if dl_plan is None or not dl_plan.needs_download:
        return [], []

    context_errors = []
    if dl_plan.remote_failed:
        dl_plan.signal_abort()
        context_errors.append(
            f"remote croc send failed: {describe_remote_failure(dl_plan.remote_failure)}"
        )
    elif not dl_plan.send_ready_seen and not dl_plan.send_done_seen:
        # The sender never registered with the relay — nothing will ever arrive
        dl_plan.signal_abort()
        context_errors.append(
            "croc sender never registered with the relay "
            "(no ready sentinel observed in the remote output)"
        )

    if dl_process is not None and dl_process.returncode is None:
        wait_seconds = (
            CROC_DOWNLOAD_ABORT_WAIT_SECONDS if context_errors
            else CROC_DOWNLOAD_RECEIVE_WAIT_SECONDS
        )
        try:
            await asyncio.wait_for(dl_process.wait(), timeout=wait_seconds)
        except asyncio.TimeoutError:
            pass  # cleanup_download_resources will terminate it

    successes, errors = finalize_download(dl_plan)
    if errors:
        # The context explains WHY files are missing/incomplete; drop it when
        # everything arrived intact despite scary sentinels.
        errors = context_errors + errors
        log_tail = _read_receive_log_tail(dl_plan)
        if log_tail:
            errors.append(f"receiver log (tail): {log_tail}")
    if dl_plan.transfer_started_at is not None:
        dl_plan.transfer_seconds = time.monotonic() - dl_plan.transfer_started_at
    return successes, errors


def describe_remote_failure(failure: str) -> str:
    """Render a FAILED sentinel for humans, e.g.

    ``__CROC_DL_FAILED__ exit_code=1 reason=could not connect to : could not connect``
    becomes ``exit code 1: could not connect to : could not connect (croc had no
    relay address: ...)``.
    """
    if not failure:
        return "unknown error"
    match = re.search(r"exit_code=(\S+)(?:\s+reason=(.*))?", failure)
    if not match:
        return failure
    code, reason = match.group(1), (match.group(2) or "").strip()
    # A non-numeric "code" names the stage that failed (install, stage); the
    # reason already says what happened there.
    if code.lstrip("-").isdigit():
        text = f"exit code {code}" + (f": {reason}" if reason else "")
    else:
        text = reason or f"failed during {code}"
    hint = croc_manager.describe_croc_error(reason)
    if hint:
        text += f" ({hint})"
    return text


def _format_seconds(seconds: float) -> str:
    return f"{int(seconds // 60)}m {seconds % 60:.1f}s" if seconds >= 60 else f"{seconds:.1f}s"


def format_download_summary(
    successes: list[str],
    errors: list[str],
    transfer_seconds: Optional[float] = None,
) -> str:
    """The **Files Downloaded:** block every handler shows (empty when there is nothing).

    One formatter for all handlers: hand-built copies had drifted, and the async
    status path labelled failed downloads "WARNING:" while the blocking handlers
    and the CLI treat them as failures.
    """
    lines = [f"- {s}" for s in successes]
    lines += [f"- DOWNLOAD FAILED: {e}" for e in errors]
    if not lines:
        return ""
    if transfer_seconds is not None:
        lines.append(f"- Transfer time: {_format_seconds(transfer_seconds)}")
    return "\n**Files Downloaded:**\n" + "\n".join(lines) + "\n"


def format_upload_summary(files_info: list[str], grain_log: Optional[str] = None) -> str:
    """The **Files Deployed:** block, plus any upload that actually failed.

    Without this, a failed croc upload was still listed as deployed, and the only
    hint was "Container pre-commands failed with exit code 1" in the output.
    """
    if not files_info:
        return ""
    lines = [f"- {f}" for f in files_info]
    lines += [f"- UPLOAD FAILED: {describe_upload_error(e)}" for e in extract_transfer_errors(grain_log)]
    return "\n**Files Deployed:**\n" + "\n".join(lines) + "\n"


def describe_upload_error(error: str) -> str:
    """An extracted upload error, plus a plain-words explanation when the cause is known."""
    hint = croc_manager.describe_croc_error(error)
    return error + (f" ({hint})" if hint else "")


async def _cli_upload_errors(plan: Optional["FileDeploymentPlan"], result) -> list[str]:
    """The CLI's equivalent of the UPLOAD FAILED lines in format_upload_summary.

    The CLI streams only the output after the execution marker, and upload
    pre-commands run before it, so a failed croc upload showed nothing but
    "Container pre-commands failed with exit code 1". Fetches the grain log only
    when a croc upload was involved AND the run did not succeed.
    """
    if plan is None or not plan.needs_croc or result is None:
        return []
    if result.status == "completed" and result.exit_code == 0:
        return []
    try:
        async with get_torque_client() as client:
            grain_log = await client.get_grain_log(result.environment_id)
    except Exception:
        return []
    return [describe_upload_error(e) for e in extract_transfer_errors(grain_log)]


# A runtime error line: optional "[hh:mm:ss.mmm]" log timestamp, then the ERROR
# itself at the start. Anchored because the container blueprint echoes its
# commands into the log, so the receive script's SOURCE line
# (`echo "ERROR: croc file receive failed (exit code: $__CROC_RC)..."`) is in
# there too and must not be mistaken for a failure.
_UPLOAD_ERROR_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)?ERROR: ((?:croc file receive failed|Failed to install croc).*)$")

# Where a grain log's download section begins; errors after it are the
# download's, and reach the caller through the FAILED sentinel instead.
_DOWNLOAD_SECTION_MARKER = "=== Running download commands ==="


def extract_transfer_errors(grain_log: Optional[str]) -> list[str]:
    """Failed upload transfers a grain printed, with the reason.

    The blueprint reports a failed upload only as "Container pre-commands failed
    with exit code 1" (or a failed command); the line saying why is in the grain
    log. Covers the croc receive and the croc install before it.
    """
    if not grain_log:
        return []
    found = []
    for line in grain_log.splitlines():
        if _DOWNLOAD_SECTION_MARKER in line and "echo" not in line:
            break
        match = _UPLOAD_ERROR_RE.match(line)
        if match:
            message = match.group(1).strip()
            if message not in found:
                found.append(message)
    return found


def _read_receive_log_tail(plan: DownloadPlan, max_chars: int = 1500) -> str:
    """Best-effort tail of the receive wrapper's log for failure diagnostics."""
    if not plan.croc_receive_dir:
        return ""
    path = os.path.join(plan.croc_receive_dir, croc_manager.CROC_RECEIVE_LOG_FILE)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return ""
    return content[-max_chars:].strip()


async def cleanup_download_resources(
    dl_process: Optional[asyncio.subprocess.Process] = None,
    receive_dir: str = "",
) -> None:
    """Clean up croc receive process and receive directory.

    Signals abort FIRST and waits briefly: the wrapper then kills its
    in-flight croc child and exits cleanly. Terminating the wrapper directly
    would orphan croc, and the orphan's open handle on the partial file
    blocks the directory removal below (observed live: a 2.4 GB partial
    still being written 11 minutes after the CLI exited, plus dozens of
    stale torque_dl_* dirs).

    Safe to call with None/empty values.
    """
    if receive_dir and dl_process is not None and dl_process.returncode is None:
        try:
            with open(os.path.join(receive_dir, croc_manager.CROC_ABORT_SIGNAL), "w") as f:
                f.write("1")
        except OSError:
            pass
        try:
            await asyncio.wait_for(dl_process.wait(), timeout=CROC_DOWNLOAD_CLEANUP_WAIT_SECONDS)
        except asyncio.TimeoutError:
            pass  # fall through to terminate
    if dl_process is not None:
        await croc_manager.cleanup_croc_send(dl_process)  # same cleanup logic
    if receive_dir and os.path.exists(receive_dir):
        shutil.rmtree(receive_dir, ignore_errors=True)
        # Windows: deletion can transiently fail while handles close (child
        # teardown, AV scans of fresh multi-GB files) — one brief retry
        if os.path.exists(receive_dir):
            await asyncio.sleep(1)
            shutil.rmtree(receive_dir, ignore_errors=True)


# Global configuration - set via command line args or environment variables
_config = {
    "torque_url": None,
    "torque_token": None,
    "torque_space": None,
    "default_agent": None,
    "default_ssh_key": None,
    "default_ssh_password": None,
    "default_target_ip": None,
    "default_ssh_user": None,
    "init_commands": None,
    "finally_commands": None,
    "auto_delete_environments": False,
    "container_idle_timeout": 86400,  # 24h: container dies this long after its last use
    # Resilience to Torque redeploys (transient API errors). See docs/design-api-resilience.md.
    "retry_enabled": True,
    "retry_budget_seconds": 600,
    "create_retry_budget_seconds": 600,
    "retry_max_backoff_seconds": 15,
    # Credentials: off until opted into, because using one resolves a customer's real
    # secrets into an agent container. See docs/design-credentials.md.
    "credentials_enabled": False,
    "credentials_space_policy": "preconfigured",
    # croc large-file transfer. Empty relay = croc's public one, whose admission
    # limiter is shared by everything behind this machine's public IP.
    # See docs/croc-file-transfer.md.
    "croc_relay": None,
    "croc_relay_password": None,
    "croc_transfers": None,
}

# Default values for _config keys (used to reset removed keys on hot-reload)
_CONFIG_DEFAULTS = dict(_config)

# Loaded config file data (for runtime profile resolution)
_loaded_config: dict = {}

# Hot-reload state
_config_file_path = None          # Path object of the watched config file
_config_file_mtime: float = 0.0   # Last known mtime
_cli_overrides: set = set()       # Config keys set via CLI (won't be overwritten on reload)
_cli_profile: Optional[str] = None          # Profile from --profile CLI arg
_config_explicit_path: Optional[str] = None  # Config path from --config CLI arg
_config_error: Optional[str] = None  # Last config load/parse error (None = healthy)
_default_profile_warning: Optional[str] = None  # Warning when default_profile references a non-existent profile


def _warn_removed_config_keys(loaded: dict) -> None:
    """Say on stderr that a config-file key torque-tunnel no longer reads is ignored."""
    for where, key, instead in config_module.find_removed_keys(loaded):
        print(f"Warning: '{key}' in {where} of the config file is no longer supported and "
              f"is ignored; {instead}.", file=sys.stderr)


def _reload_config() -> None:
    """Reload config file and update _config for non-CLI-overridden keys.

    Called by the file watcher and after the setup tool saves.
    Respects CLI overrides: keys explicitly set via CLI args are never changed.
    Sets _config_error on failure (tools will refuse to run until fixed).
    """
    global _loaded_config, _config_file_path, _config_file_mtime, _config_error, _default_profile_warning

    try:
        loaded = config_module.load_config(_config_explicit_path)
    except Exception as e:
        _config_error = f"Failed to load config file: {e}"
        _default_profile_warning = None
        # Update mtime so we don't retry every 2s with the same broken file
        path = config_module.find_config_file(_config_explicit_path)
        if path:
            _config_file_path = path
            try:
                _config_file_mtime = path.stat().st_mtime
            except OSError:
                pass
        raise

    _loaded_config = loaded
    _warn_removed_config_keys(loaded)

    # Update file tracking
    path = config_module.find_config_file(_config_explicit_path)
    if path:
        _config_file_path = path
        try:
            _config_file_mtime = path.stat().st_mtime
        except OSError:
            pass

    # Compute effective file values (defaults + active profile)
    file_defaults = config_module.get_defaults(_loaded_config)

    profile = _cli_profile
    is_default_profile = False
    if profile is None and _loaded_config:
        profile = config_module.get_default_profile_name(_loaded_config)
        if profile:
            is_default_profile = True

    default_profile_warning = None
    if profile and _loaded_config:
        try:
            profile_values = config_module.resolve_profile(_loaded_config, profile)
            effective = config_module.apply_profile_to_config(file_defaults, profile_values)
        except ValueError as e:
            if is_default_profile:
                # Bad default_profile — soft warning, don't block tools with explicit profile
                default_profile_warning = f"default_profile in config.yaml: {e}"
            else:
                # Bad --profile CLI arg — hard error
                _config_error = f"Profile resolution failed: {e}"
                _default_profile_warning = None
                raise ValueError(_config_error)
            effective = file_defaults
    else:
        effective = file_defaults

    # Update _config: reset non-CLI keys to defaults, then apply file values
    for key, default_value in _CONFIG_DEFAULTS.items():
        if key not in _cli_overrides:
            _config[key] = effective.get(key, default_value)

    # Clear hard errors on successful load; update soft warning
    _config_error = None
    _default_profile_warning = default_profile_warning


async def _watch_config_file() -> None:
    """Background task: poll config file for changes and hot-reload."""
    global _config_file_path, _config_file_mtime, _config_error, _default_profile_warning, _loaded_config
    while True:
        await asyncio.sleep(2)

        # If no config file known yet, try to find one (might have been created)
        if not _config_file_path:
            path = config_module.find_config_file(_config_explicit_path)
            if path:
                _config_file_path = path
                _config_file_mtime = 0.0  # Force reload on next iteration
            continue

        try:
            current_mtime = _config_file_path.stat().st_mtime
        except OSError:
            # File was removed/moved/renamed — reset to defaults
            print(f"Config file {_config_file_path} no longer exists, resetting to defaults.", file=sys.stderr)
            _config_file_path = None
            _config_file_mtime = 0.0
            _loaded_config = {}
            for key, default_value in _CONFIG_DEFAULTS.items():
                if key not in _cli_overrides:
                    _config[key] = default_value
            _config_error = None
            _default_profile_warning = None
            continue

        if current_mtime != _config_file_mtime:
            try:
                _reload_config()
                print(f"Config reloaded from {_config_file_path}", file=sys.stderr)
            except Exception as e:
                # _config_error is already set by _reload_config
                print(f"Config reload failed (tools will fail until fixed): {e}", file=sys.stderr)


# Persistent container session state
# Tracks all active persistent containers so the AI can run commands on any of them.
# Keyed by environment_id. The "_default" key tracks the most recently used container's env_id.
_persistent_containers: dict[str, dict] = {}
_default_persistent_container_id: Optional[str] = None
_background_streamers: dict[str, asyncio.Task] = {}  # env_id -> background streaming task
_streamer_cache: dict[str, dict] = {}  # env_id -> {'env_data': ..., 'status': ..., 'raw_status': ...}
_croc_async_state: dict[str, dict] = {}  # env_id -> {"process": Process, "staging_dir": str, "dl_process": Process, "dl_plan": DownloadPlan}
_download_results: dict[str, tuple] = {}  # env_id -> (successes, errors, transfer_seconds)
# env_id -> the Torque connection an async command was started with. Polling, streaming
# and cancelling must use it: the call's profile can point at another Torque instance or
# space than the default profile, and the default profile can change (hot reload) while
# the command runs.
_async_env_connections: dict[str, dict] = {}

# How long to wait for croc receive to finish AFTER the Torque environment completes.
# The croc transfer through relay proxy can take a while to complete even after
# the environment's croc send finishes.
CROC_DOWNLOAD_RECEIVE_WAIT_SECONDS = 120

# How long to wait for the receiver after it was told to abort (remote send
# failed / never registered) — just enough for the wrapper to notice the
# abort signal and exit; cleanup terminates it afterwards regardless.
CROC_DOWNLOAD_ABORT_WAIT_SECONDS = 10

# How long cleanup_download_resources waits for the receive wrapper to exit by itself
# after the abort signal, before terminating it.
CROC_DOWNLOAD_CLEANUP_WAIT_SECONDS = 5

# Slack added on top of a command's timeout when arming the persistent
# container's end time at command start, so the container cannot die under a
# command that is still running.
CONTAINER_COMMAND_SLACK_SECONDS = 1800


def _format_iso_duration(seconds: int) -> str:
    """Format seconds as an ISO 8601 duration (PT2H, PT1H30M, PT30M, ...)."""
    total_minutes = max(1, int(seconds) // 60)
    hours, minutes = divmod(total_minutes, 60)
    if hours and minutes:
        return f"PT{hours}H{minutes}M"
    if hours:
        return f"PT{hours}H"
    return f"PT{minutes}M"


def _container_deadline(idle_seconds: int, command_timeout: Optional[int] = None) -> datetime:
    """Absolute scheduled end time for a persistent container.

    Idle-timeout semantics: the container dies idle_seconds after its last
    use. At command START pass the command's timeout so the deadline also
    covers the command's own runtime (+ slack) — the container must not die
    under a running command. At command COMPLETION pass no timeout, which
    re-arms the plain idle window (shortening any longer protection window).
    """
    protect = (int(command_timeout) + CONTAINER_COMMAND_SLACK_SECONDS) if command_timeout else 0
    return datetime.now(timezone.utc) + timedelta(seconds=max(int(idle_seconds), protect))

# Terminal statuses that indicate the environment has finished
_TERMINAL_STATUSES = {
    "active", "success",  # Completed successfully
    "ended", "inactive",  # Ended (may have outputs)
    "active_with_error", "ended_with_error", "error", "failed", "terminating_failed",  # Errors
    "released", "cancelled", "terminated", "force_terminated",  # Cancelled
}


async def _background_stream_grain_log(environment_id: str) -> None:
    """Background task that streams grain log output to stderr for an async environment.
    
    Polls the grain log every 3 seconds and prints new filtered content.
    Caches latest env_data/status in _streamer_cache for get_execution_status to read.
    Stops when a terminal status is detected.
    """
    last_log_len = 0
    filter_state = {'found': raw_log.stream_preamble(), 'buffer': ''}
    
    try:
        while True:
            await asyncio.sleep(2)
            
            try:
                async with _connection_client(_async_connection(environment_id)) as client:
                    # Check status and cache it
                    env_data = await client.get_environment_status(environment_id)
                    details = env_data.get("details", {})
                    raw_status = details.get("computed_status") or env_data.get("computed_status") or env_data.get("status", "unknown")
                    status = raw_status.lower().replace(" ", "_")
                    _streamer_cache[environment_id] = {
                        'env_data': env_data,
                        'status': status,
                        'raw_status': raw_status,
                    }
                    
                    # Stream new grain log content
                    grain_log = await client.get_grain_log(environment_id) or ""
                    if len(grain_log) > last_log_len:
                        new_content = grain_log[last_log_len:]
                        last_log_len = len(grain_log)
                        # Feed the download sentinel watcher (async executions
                        # register their DownloadPlan in _croc_async_state; the
                        # gated receiver depends on the watcher seeing the
                        # sender's READY sentinel)
                        croc_state = _croc_async_state.get(environment_id)
                        if croc_state is not None:
                            dl_plan = croc_state.get("dl_plan")
                            if dl_plan is not None:
                                try:
                                    dl_plan.observe_output(new_content)
                                except Exception:
                                    pass
                        if filter_state['found']:
                            print(new_content, file=sys.stderr, end='', flush=True)
                        else:
                            filter_state['buffer'] += new_content
                            match = _EXECUTION_MARKER.search(filter_state['buffer'])
                            if match:
                                filter_state['found'] = True
                                after_marker = filter_state['buffer'][match.end():]
                                if after_marker:
                                    print(after_marker, file=sys.stderr, end='', flush=True)
                                filter_state['buffer'] = ''
                    
                    if status in _TERMINAL_STATUSES:
                        break
            except asyncio.CancelledError:
                raise
            except Exception:
                pass  # Ignore transient errors, keep polling
    except asyncio.CancelledError:
        pass
    finally:
        _background_streamers.pop(environment_id, None)


def _start_background_streamer(environment_id: str) -> None:
    """Start a background task to stream grain log output to stderr."""
    # Don't start if one already exists for this environment
    if environment_id in _background_streamers:
        return
    task = asyncio.create_task(_background_stream_grain_log(environment_id))
    _background_streamers[environment_id] = task


def _stop_background_streamer(environment_id: str) -> None:
    """Stop the background streamer for an environment (if running)."""
    task = _background_streamers.pop(environment_id, None)
    if task and not task.done():
        task.cancel()


# --- Persistent container state file (CLI mode) ---

def _state_file_path() -> str:
    """Get the path to the persistent container state file."""
    from pathlib import Path
    state_dir = Path.home() / ".torque-tunnel"
    state_dir.mkdir(exist_ok=True)
    return str(state_dir / "containers.json")


def _read_state() -> dict:
    """Read persistent container state from disk."""
    import json
    path = _state_file_path()
    if os.path.exists(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"default": None, "containers": {}}
    return {"default": None, "containers": {}}


def _write_state(state: dict):
    """Write persistent container state to disk."""
    import json
    path = _state_file_path()
    with open(path, 'w') as f:
        json.dump(state, f, indent=2)


def _save_container_to_state(env_id: str, agent: str, set_default: bool = True):
    """Save a container entry to the state file."""
    from datetime import datetime, timezone
    state = _read_state()
    state["containers"][env_id] = {
        "created": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
    }
    if set_default:
        state["default"] = env_id
    _write_state(state)


def _remove_container_from_state(env_id: str):
    """Remove a container from the state file."""
    state = _read_state()
    state["containers"].pop(env_id, None)
    if state["default"] == env_id:
        # Set default to another container if available, else None
        remaining = list(state["containers"].keys())
        state["default"] = remaining[-1] if remaining else None
    _write_state(state)


def get_torque_client(torque_url=None, torque_token=None, torque_space=None, config=None) -> TorqueClient:
    """Create a Torque client with current configuration, with optional per-call overrides."""
    cfg = config or _config
    url = torque_url or cfg["torque_url"]
    token = torque_token or cfg["torque_token"]
    space = torque_space or cfg["torque_space"]
    if not url:
        raise ValueError("Torque URL not configured. Run the 'setup' tool first, or set TORQUE_URL / --torque-url.")
    if not token:
        raise ValueError("Torque token not configured. Run the 'setup' tool first, or set TORQUE_TOKEN / --torque-token.")
    if not space:
        raise ValueError("Torque space not configured. Run the 'setup' tool first, or set TORQUE_SPACE / --torque-space.")
    
    return TorqueClient(
        base_url=url,
        token=token,
        space=space,
        default_agent=cfg["default_agent"],
        init_commands=cfg["init_commands"],
        finally_commands=cfg["finally_commands"],
        retry_enabled=cfg.get("retry_enabled", True),
        retry_budget_seconds=cfg.get("retry_budget_seconds", 600),
        create_retry_budget_seconds=cfg.get("create_retry_budget_seconds", 600),
        retry_max_backoff_seconds=cfg.get("retry_max_backoff_seconds", 15),
    )


def _config_for_profile(profile_name: str) -> dict:
    """The effective config of a named profile. Raises ValueError for an unknown one."""
    profile_values = config_module.resolve_profile(_loaded_config, profile_name)
    return config_module.apply_profile_to_config(_config, profile_values)


def _connection(cfg: dict, profile_name: Optional[str] = None,
                torque_url=None, torque_token=None, torque_space=None) -> dict:
    """A Torque connection: where an environment lives, and the config to reach it with."""
    return {
        "torque_url": torque_url or cfg["torque_url"],
        "torque_token": torque_token or cfg["torque_token"],
        "torque_space": torque_space or cfg["torque_space"],
        "config": dict(cfg),
        "profile": profile_name,
    }


def _remember_async_connection(environment_id: str, connection: dict) -> None:
    _async_env_connections[environment_id] = connection


def _async_connection(environment_id: str, cfg: Optional[dict] = None,
                      profile_name: Optional[str] = None) -> dict:
    """The connection to poll or cancel an async environment with.

    An explicit profile wins; then the connection the command was started with; then
    the default profile (an environment this server did not start, or one started
    before a restart).
    """
    if profile_name:
        return _connection(cfg or _config, profile_name)
    known = _async_env_connections.get(environment_id)
    if known:
        return _with_current_token(known)
    return _connection(_config)


def _with_current_token(connection: dict) -> dict:
    """Prefer the profile's current token for the same Torque URL and space: a re-login
    since the command started may have replaced the one it was started with."""
    try:
        cfg = _config_for_profile(connection["profile"]) if connection["profile"] else _config
    except ValueError:
        return connection
    if (cfg.get("torque_token") and cfg.get("torque_url") == connection["torque_url"]
            and cfg.get("torque_space") == connection["torque_space"]):
        return dict(connection, torque_token=cfg["torque_token"])
    return connection


def _connection_client(connection: dict) -> TorqueClient:
    return get_torque_client(
        connection["torque_url"], connection["torque_token"], connection["torque_space"],
        config=connection["config"],
    )


def _environment_url(connection: dict, environment_id: str) -> str:
    return f"{connection['torque_url']}/{connection['torque_space']}/environments/{environment_id}"


def _follow_up_args(environment_id: str, profile_name: Optional[str]) -> str:
    """The arguments a follow-up status/cancel call needs, as the caller should pass them."""
    text = f'environment_id="{environment_id}"'
    if profile_name:
        text += f', profile="{profile_name}"'
    return text


_FOLLOW_UP_PROFILE_SCHEMA = {
    "type": "string",
    "description": "The profile the async command was started with. Pass it exactly when the _async tool's result names one; omit it otherwise. Do NOT pass 'default'.",
}


# Arguments that mean the same in every tool that takes them, defined once: the run_*
# tools and each endpoint of a transfer (which resolve them through the same code, see
# "Argument resolution, shared by every tool").
_ARG_SCHEMAS = {
    "host": {
        "type": "string",
        "description": "The IP address or hostname of the remote server to connect to",
    },
    "user": {
        "type": "string",
        "description": "The username for authentication",
    },
    "private_key": {
        "type": "string",
        "description": "SSH private key - a LOCAL file path (e.g., C:\\Users\\you\\.ssh\\id_rsa), the key content directly (starting with '-----BEGIN'), or a base64-encoded key. Use this OR password.",
    },
    "password": {
        "type": "string",
        "description": "SSH password for authentication. Use this OR private_key. Requires sshpass on the Torque agent.",
    },
    "torque_agent": {
        "type": "string",
        "description": "DO NOT set unless the user explicitly provides this value or asks you to change it. Overrides the pre-configured Torque agent.",
    },
    "torque_token": {
        "type": "string",
        "description": "DO NOT set unless the user explicitly provides this value or asks you to change it. Overrides the pre-configured Torque API token.",
    },
    "torque_url": {
        "type": "string",
        "description": "DO NOT set unless the user explicitly provides this value or asks you to change it. Overrides the pre-configured Torque platform URL.",
    },
    "torque_space": {
        "type": "string",
        "description": "DO NOT set unless the user explicitly provides this value or asks you to change it. Overrides the pre-configured Torque space name.",
    },
    "profile": {
        "type": "string",
        "description": "Configuration profile name to use. Omit this parameter (or don't pass it) to use the default profile. Do NOT pass 'default' as the value — that would look for a profile literally named 'default'. Use list_profiles to see available profiles and which one is the default.",
    },
}

# One side of a transfer: the same arguments as a run_* tool call, plus which kind of
# machine it is.
_TRANSFER_ENDPOINT_SCHEMA = {
    "type": "object",
    "description": "One side of the transfer. Its fields mean exactly what they mean in run_on_tunneled_ssh (and resolve the same way: argument, else this side's profile, else the default configuration).",
    "properties": {
        "type": {"type": "string", "enum": ["ssh", "persistent_container"],
                 "description": "ssh (default): a machine reached over SSH. persistent_container: a running persistent container, by environment_id."},
        "environment_id": {"type": "string",
                           "description": "persistent_container only: the container's environment id. It must exist and be running (a transfer never creates one)."},
        **{name: _ARG_SCHEMAS[name] for name in (
            "host", "user", "private_key", "password", "profile",
            "torque_agent", "torque_url", "torque_token", "torque_space")},
    },
}


# Create MCP server
server = Server("torque-tunnel")


@server.list_tools()
async def list_tools():
    """List available tools."""
    return [
        Tool(
            name="run_on_tunneled_ssh",
            description="""Execute a shell command on a remote server via SSH. BLOCKS until completion.
For partial output or cancel mid-execution, use run_on_tunneled_ssh_async instead.

**WHEN TO USE vs regular SSH:**
All tools on this MCP server reach machines on a SEPARATE INTERNAL NETWORK with no direct access
from your machine. The Torque agent tunnels into that network.
- Unreachable internal/lab network target → use this tool
- Local network, local VM (VMware/VirtualBox), or directly SSH-reachable → use regular `ssh` in terminal

Prefer this over running `ssh` from a container - simpler and more efficient.

**private_key** accepts a file path (e.g., C:\\Users\\you\\.ssh\\id_rsa), raw key content ('-----BEGIN...'), or a base64-encoded key.
Alternatively, use **password** for password-based SSH authentication (requires sshpass on the agent).

**FILE TRANSFER:** NEVER manually encode/embed file contents into the command (no base64 encoding, no heredocs, no echo commands to create files). ALWAYS use the `upload_files` parameter instead — it handles compression, large files, and directories automatically. Use `upload_files` with `local_source_path` for existing local files, or `content` for dynamically generated text. Order: upload_files → init_commands → command → finally_commands → download_files.

**DANGEROUS COMMANDS** (may kill our Torque agent if running there):
docker restart/stop/kill, systemctl restart docker, reboot, shutdown, init 0/6

**PERFORMANCE:** Each call has overhead. Chain commands (`cmd1 && cmd2`) and use `upload_files` for file transfers in a single call.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": _ARG_SCHEMAS["host"],
                    "user": _ARG_SCHEMAS["user"],
                    "private_key": _ARG_SCHEMAS["private_key"],
                    "password": _ARG_SCHEMAS["password"],
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the remote server. Optional if only uploading files via upload_files.",
                    },
                    "command_description": {
                        "type": "string",
                        "description": "REQUIRED. A concise (3-6 word) description of what this command does, embedded in the Torque environment name so a user can find this environment in the Torque UI (e.g. 'restart nginx').",
                    },
                    "upload_files": {
                        "type": "array",
                        "description": "ALWAYS use this to transfer files instead of encoding file contents into the command. Uploads files from your local machine to the remote server BEFORE the command runs. Each item specifies one file to upload.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine to a file or directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct text content to write as a file on the remote server. Use this for dynamically generated content (scripts, configs, etc.) instead of encoding it into the command. Use this OR local_source_path, not both.",
                                },
                                "remote_destination_path": {
                                    "type": "string",
                                    "description": "Absolute destination path on the remote server where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_destination_path"],
                        },
                    },
                    "download_files": {
                        "type": "array",
                        "description": "Download files/directories from the remote server to your local machine AFTER the command runs. Uses croc for peer-to-peer encrypted transfer.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "remote_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on the remote server to a file or directory to download.",
                                },
                                "local_destination_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine where the file/directory will be saved.",
                                },
                            },
                            "required": ["remote_source_path", "local_destination_path"],
                        },
                    },
                    "credential": {
                        "type": "string",
                        "description": "Optional: name of a credential stored in the connected Torque account. Torque injects its secrets as environment variables where the command runs, so the command can reference them (e.g. \"$VSPHERE_PASSWORD\") without them ever being shown to you or written into the command. Call list_credentials to see the available names and which variables each one provides. One credential per call — for two, make two calls.",
                    },
                    "credential_env_forward": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: extra environment variable NAMES to carry to the remote host, on top of the credential's own. Only needed for a credential type torque-tunnel has not measured yet, or to correct a stale cache entry.",
                    },
                    "torque_agent": _ARG_SCHEMAS["torque_agent"],
                    "allow_dangerous_commands": {
                        "type": "boolean",
                        "description": "Optional: Set to true to bypass dangerous command warnings. Use with extreme caution.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                    "auto_delete": {
                        "type": "boolean",
                        "description": "Optional: Whether to automatically delete the Torque environment after completion.",
                    },
                    "torque_token": _ARG_SCHEMAS["torque_token"],
                    "torque_url": _ARG_SCHEMAS["torque_url"],
                    "torque_space": _ARG_SCHEMAS["torque_space"],
                    "profile": _ARG_SCHEMAS["profile"],
                },
                "required": ["command_description"],
            },
        ),
        Tool(
            name="run_on_tunneled_disposable_container",
            description="""Execute a command directly on a fresh container spawned by Torque agent and then kills it. BLOCKS until completion.
**Choosing the right tool** (all tools here reach an unreachable internal network -
for local network/VMs use regular terminal commands):
- Partial output or cancel mid-execution → run_on_tunneled_disposable_container_async.
- Particular remote server on internal network → run_on_tunneled_ssh (handles SSH)
- One-off container command, no state needed → THIS tool (cheaper/faster)
- Multi-step workflow needing state across calls (install then use a tool, incremental builds, etc.) → run_on_tunneled_persistent_container

**FILE TRANSFER:** NEVER manually encode/embed file contents into the command (no base64 encoding, no heredocs, no echo commands to create files). ALWAYS use the `upload_files` parameter instead — it handles compression, large files, and directories automatically. Use `upload_files` with `local_source_path` for existing local files, or `content` for dynamically generated text. Order: upload_files → init_commands → command → finally_commands → download_files.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the agent container. Optional if only uploading files via upload_files.",
                    },
                    "command_description": {
                        "type": "string",
                        "description": "REQUIRED. A concise (3-6 word) description of what this command does, embedded in the Torque environment name so a user can find this environment in the Torque UI (e.g. 'restart nginx').",
                    },
                    "upload_files": {
                        "type": "array",
                        "description": "ALWAYS use this to transfer files instead of encoding file contents into the command. Uploads files from your local machine to the container BEFORE the command runs. Each item specifies one file to upload.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine to a file or directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct text content to write as a file on the container. Use this for dynamically generated content (scripts, configs, etc.) instead of encoding it into the command. Use this OR local_source_path, not both.",
                                },
                                "remote_destination_path": {
                                    "type": "string",
                                    "description": "Absolute destination path on the container where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_destination_path"],
                        },
                    },
                    "download_files": {
                        "type": "array",
                        "description": "Download files/directories from the container to your local machine AFTER the command runs. Uses croc for peer-to-peer encrypted transfer.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "remote_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on the container to a file or directory to download.",
                                },
                                "local_destination_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine where the file/directory will be saved.",
                                },
                            },
                            "required": ["remote_source_path", "local_destination_path"],
                        },
                    },
                    "credential": {
                        "type": "string",
                        "description": "Optional: name of a credential stored in the connected Torque account. Torque injects its secrets as environment variables where the command runs, so the command can reference them (e.g. \"$VSPHERE_PASSWORD\") without them ever being shown to you or written into the command. Call list_credentials to see the available names and which variables each one provides. One credential per call — for two, make two calls.",
                    },
                    "torque_agent": _ARG_SCHEMAS["torque_agent"],
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                    "torque_token": _ARG_SCHEMAS["torque_token"],
                    "torque_url": _ARG_SCHEMAS["torque_url"],
                    "torque_space": _ARG_SCHEMAS["torque_space"],
                    "profile": _ARG_SCHEMAS["profile"],
                },
                "required": ["command_description"],
            },
        ),
        Tool(
            name="run_on_tunneled_persistent_container",
            description="""Execute a command on a persistent Torque agent container. BLOCKS until completion.
State persists across calls (files, packages, env vars) without the need for a particular machine for SSH.
For partial output or cancel mid-execution, use run_on_tunneled_persistent_container_async instead.

**Only use when you NEED state across calls** (install then use a tool, incremental builds, etc.).
All tools here reach an unreachable internal network - for local network/VMs, use terminal commands instead.
For one-off commands: run_on_tunneled_disposable_container. For remote servers: run_on_tunneled_ssh.

First call provisions ~30-40s. Subsequent calls reuse with near-zero overhead. Idle timeout: 24h after last use (default).

**Multiple containers:** `new_container=true` creates additional ones. `environment_id` targets a
specific one. Output includes `Persistent Container: <env_id>` - save to target it later.

**After restart:** Pass previous `environment_id` to reconnect (works if not expired).
Without the ID, a new container is created.

**FILE TRANSFER:** NEVER manually encode/embed file contents into the command (no base64 encoding, no heredocs, no echo commands to create files). ALWAYS use the `upload_files` parameter instead — it handles compression, large files, and directories automatically. Use `upload_files` with `local_source_path` for existing local files, or `content` for dynamically generated text. Order: upload_files → init_commands → command → finally_commands → download_files.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the agent container. Optional if only uploading files via upload_files.",
                    },
                    "command_description": {
                        "type": "string",
                        "description": "REQUIRED. A concise (3-6 word) description of what this command does, embedded in the Torque environment name so a user can find this environment in the Torque UI (e.g. 'restart nginx').",
                    },
                    "upload_files": {
                        "type": "array",
                        "description": "ALWAYS use this to transfer files instead of encoding file contents into the command. Uploads files from your local machine to the container BEFORE the command runs. Each item specifies one file to upload.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine to a file or directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct text content to write as a file on the container. Use this for dynamically generated content (scripts, configs, etc.) instead of encoding it into the command. Use this OR local_source_path, not both.",
                                },
                                "remote_destination_path": {
                                    "type": "string",
                                    "description": "Absolute destination path on the container where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_destination_path"],
                        },
                    },
                    "download_files": {
                        "type": "array",
                        "description": "Download files/directories from the remote server to your local machine AFTER the command runs. Uses croc for peer-to-peer encrypted transfer.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "remote_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on the remote server to a file or directory to download.",
                                },
                                "local_destination_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine where the file/directory will be saved.",
                                },
                            },
                            "required": ["remote_source_path", "local_destination_path"],
                        },
                    },
                    "credential": {
                        "type": "string",
                        "description": "Optional: name of a credential stored in the connected Torque account. Torque injects its secrets as environment variables where the command runs, so the command can reference them (e.g. \"$VSPHERE_PASSWORD\") without them ever being shown to you or written into the command. Call list_credentials to see the available names and which variables each one provides. One credential per call — for two, make two calls.",
                    },
                    "credential_env_forward": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: extra environment variable NAMES to carry to the remote host, on top of the credential's own. Only needed for a credential type torque-tunnel has not measured yet, or to correct a stale cache entry.",
                    },
                    "torque_agent": _ARG_SCHEMAS["torque_agent"],
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                    "new_container": {
                        "type": "boolean",
                        "description": "Set to true to create a new persistent container instead of reusing the current one. Old containers remain active.",
                    },
                    "container_description": {
                        "type": "string",
                        "description": "REQUIRED (may be an empty string). A concise description of the persistent container itself (its purpose/session), embedded in the container's Torque environment name. Only applied when a NEW container is created (first call, new_container=true, or respawn); ignored when reusing an existing container — pass an empty string in that case. Distinct from command_description, which names each command environment.",
                    },
                    "environment_id": {
                        "type": "string",
                        "description": "Target a specific persistent container by its environment ID. If omitted, uses the most recently used container (or creates one).",
                    },
                    "torque_token": _ARG_SCHEMAS["torque_token"],
                    "torque_url": _ARG_SCHEMAS["torque_url"],
                    "torque_space": _ARG_SCHEMAS["torque_space"],
                    "profile": _ARG_SCHEMAS["profile"],
                },
                "required": ["command_description", "container_description"],
            },
        ),
        Tool(
            name="run_on_tunneled_ssh_async",
            description="""Like run_on_tunneled_ssh but returns IMMEDIATELY with an environment ID.
Use get_execution_status to poll output/progress. Use cancel_execution to abort. Pass them the same `profile` if this call used one.
If you don't need intermediate output or cancel early, use run_on_tunneled_ssh instead (simpler, one call).

Same network rules: only for unreachable internal network targets.
For local network/VMs, use regular `ssh` in terminal.

**private_key** accepts a file path, raw key content ('-----BEGIN...'), or a base64-encoded key.
Alternatively, use **password** for password-based SSH authentication (requires sshpass on the agent).

**FILE TRANSFER:** NEVER manually encode/embed file contents into the command. ALWAYS use the `upload_files` parameter instead.

**DANGEROUS COMMANDS** (may kill our Torque agent if running there): docker restart/stop/kill,
systemctl restart docker, reboot, shutdown, init 0/6""",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": _ARG_SCHEMAS["host"],
                    "user": _ARG_SCHEMAS["user"],
                    "private_key": _ARG_SCHEMAS["private_key"],
                    "password": _ARG_SCHEMAS["password"],
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the remote server.",
                    },
                    "command_description": {
                        "type": "string",
                        "description": "REQUIRED. A concise (3-6 word) description of what this command does, embedded in the Torque environment name so a user can find this environment in the Torque UI (e.g. 'restart nginx').",
                    },
                    "upload_files": {
                        "type": "array",
                        "description": "ALWAYS use this to transfer files instead of encoding file contents into the command. Uploads files from your local machine to the remote server BEFORE the command runs. Each item specifies one file to upload.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine to a file or directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct text content to write as a file on the remote server. Use this for dynamically generated content (scripts, configs, etc.) instead of encoding it into the command. Use this OR local_source_path, not both.",
                                },
                                "remote_destination_path": {
                                    "type": "string",
                                    "description": "Absolute destination path on the remote server where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_destination_path"],
                        },
                    },
                    "download_files": {
                        "type": "array",
                        "description": "Download files/directories from the remote server to your local machine AFTER the command runs. Uses croc for peer-to-peer encrypted transfer.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "remote_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on the remote server to a file or directory to download.",
                                },
                                "local_destination_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine where the file/directory will be saved.",
                                },
                            },
                            "required": ["remote_source_path", "local_destination_path"],
                        },
                    },
                    "credential": {
                        "type": "string",
                        "description": "Optional: name of a credential stored in the connected Torque account. Torque injects its secrets as environment variables where the command runs, so the command can reference them (e.g. \"$VSPHERE_PASSWORD\") without them ever being shown to you or written into the command. Call list_credentials to see the available names and which variables each one provides. One credential per call — for two, make two calls.",
                    },
                    "credential_env_forward": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: extra environment variable NAMES to carry to the remote host, on top of the credential's own. Only needed for a credential type torque-tunnel has not measured yet, or to correct a stale cache entry.",
                    },
                    "torque_agent": _ARG_SCHEMAS["torque_agent"],
                    "allow_dangerous_commands": {
                        "type": "boolean",
                        "description": "Optional: Set to true to bypass dangerous command warnings.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                    "torque_token": _ARG_SCHEMAS["torque_token"],
                    "torque_url": _ARG_SCHEMAS["torque_url"],
                    "torque_space": _ARG_SCHEMAS["torque_space"],
                    "profile": _ARG_SCHEMAS["profile"],
                },
                "required": ["command", "command_description"],
            },
        ),
        Tool(
            name="run_on_tunneled_persistent_container_async",
            description="""Like run_on_tunneled_persistent_container but returns IMMEDIATELY with an environment ID.
Use get_execution_status to poll output/progress. Use cancel_execution to abort. Pass them the same `profile` if this call used one.
If you don't need intermediate output or cancel early, use run_on_tunneled_persistent_container instead (simpler).

Only for unreachable internal network targets. For local network/VMs, use terminal commands.
Only use when you NEED state across calls. One-off: run_on_tunneled_disposable_container_async.
Remote server: run_on_tunneled_ssh_async.

First call provisions ~30-40s. Subsequent calls reuse. Idle timeout: 24h after last use (default).
`new_container=true` for additional containers. `environment_id` to target a specific one.
After restart: pass previous `environment_id` to reconnect.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the agent container.",
                    },
                    "command_description": {
                        "type": "string",
                        "description": "REQUIRED. A concise (3-6 word) description of what this command does, embedded in the Torque environment name so a user can find this environment in the Torque UI (e.g. 'restart nginx').",
                    },
                    "upload_files": {
                        "type": "array",
                        "description": "ALWAYS use this to transfer files instead of encoding file contents into the command. Uploads files from your local machine to the container BEFORE the command runs. Each item specifies one file to upload.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine to a file or directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct text content to write as a file on the container. Use this for dynamically generated content (scripts, configs, etc.) instead of encoding it into the command. Use this OR local_source_path, not both.",
                                },
                                "remote_destination_path": {
                                    "type": "string",
                                    "description": "Absolute destination path on the container where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_destination_path"],
                        },
                    },
                    "download_files": {
                        "type": "array",
                        "description": "Download files/directories from the remote server to your local machine AFTER the command runs. Uses croc for peer-to-peer encrypted transfer.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "remote_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on the remote server to a file or directory to download.",
                                },
                                "local_destination_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine where the file/directory will be saved.",
                                },
                            },
                            "required": ["remote_source_path", "local_destination_path"],
                        },
                    },
                    "credential": {
                        "type": "string",
                        "description": "Optional: name of a credential stored in the connected Torque account. Torque injects its secrets as environment variables where the command runs, so the command can reference them (e.g. \"$VSPHERE_PASSWORD\") without them ever being shown to you or written into the command. Call list_credentials to see the available names and which variables each one provides. One credential per call — for two, make two calls.",
                    },
                    "credential_env_forward": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: extra environment variable NAMES to carry to the remote host, on top of the credential's own. Only needed for a credential type torque-tunnel has not measured yet, or to correct a stale cache entry.",
                    },
                    "torque_agent": _ARG_SCHEMAS["torque_agent"],
                    "new_container": {
                        "type": "boolean",
                        "description": "Set to true to create a new persistent container instead of reusing the current one. Old containers remain active.",
                    },
                    "container_description": {
                        "type": "string",
                        "description": "REQUIRED (may be an empty string). A concise description of the persistent container itself (its purpose/session), embedded in the container's Torque environment name. Only applied when a NEW container is created (first call, new_container=true, or respawn); ignored when reusing an existing container — pass an empty string in that case. Distinct from command_description, which names each command environment.",
                    },
                    "environment_id": {
                        "type": "string",
                        "description": "Target a specific persistent container by its environment ID. If omitted, uses the most recently used container (or creates one).",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                    "torque_token": _ARG_SCHEMAS["torque_token"],
                    "torque_url": _ARG_SCHEMAS["torque_url"],
                    "torque_space": _ARG_SCHEMAS["torque_space"],
                    "profile": _ARG_SCHEMAS["profile"],
                },
                "required": ["command", "command_description", "container_description"],
            },
        ),
        Tool(
            name="run_on_tunneled_disposable_container_async",
            description="""Like run_on_tunneled_disposable_container but returns IMMEDIATELY with an environment ID.
Use get_execution_status to poll output/progress. Use cancel_execution to abort. Pass them the same `profile` if this call used one.
If you don't need intermediate output or cancel early, use run_on_tunneled_disposable_container instead (simpler).

Only for unreachable internal network targets. For local network/VMs, use terminal commands.
- Remote server on internal network → run_on_tunneled_ssh_async
- One-off container command → THIS tool
- Multi-step with state → run_on_tunneled_persistent_container_async""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the agent container.",
                    },
                    "command_description": {
                        "type": "string",
                        "description": "REQUIRED. A concise (3-6 word) description of what this command does, embedded in the Torque environment name so a user can find this environment in the Torque UI (e.g. 'restart nginx').",
                    },
                    "upload_files": {
                        "type": "array",
                        "description": "ALWAYS use this to transfer files instead of encoding file contents into the command. Uploads files from your local machine to the container BEFORE the command runs. Each item specifies one file to upload.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine to a file or directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct text content to write as a file on the container. Use this for dynamically generated content (scripts, configs, etc.) instead of encoding it into the command. Use this OR local_source_path, not both.",
                                },
                                "remote_destination_path": {
                                    "type": "string",
                                    "description": "Absolute destination path on the container where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_destination_path"],
                        },
                    },
                    "download_files": {
                        "type": "array",
                        "description": "Download files/directories from the container to your local machine AFTER the command runs. Uses croc for peer-to-peer encrypted transfer.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "remote_source_path": {
                                    "type": "string",
                                    "description": "Absolute path on the container to a file or directory to download.",
                                },
                                "local_destination_path": {
                                    "type": "string",
                                    "description": "Absolute path on your local machine where the file/directory will be saved.",
                                },
                            },
                            "required": ["remote_source_path", "local_destination_path"],
                        },
                    },
                    "credential": {
                        "type": "string",
                        "description": "Optional: name of a credential stored in the connected Torque account. Torque injects its secrets as environment variables where the command runs, so the command can reference them (e.g. \"$VSPHERE_PASSWORD\") without them ever being shown to you or written into the command. Call list_credentials to see the available names and which variables each one provides. One credential per call — for two, make two calls.",
                    },
                    "torque_agent": _ARG_SCHEMAS["torque_agent"],
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                    "torque_token": _ARG_SCHEMAS["torque_token"],
                    "torque_url": _ARG_SCHEMAS["torque_url"],
                    "torque_space": _ARG_SCHEMAS["torque_space"],
                    "profile": _ARG_SCHEMAS["profile"],
                },
                "required": ["command", "command_description"],
            },
        ),
        Tool(
            name="get_execution_status",
            description="""Check status/output of an async command. Returns running/completed/failed with partial or full output.
Use `wait` to avoid tight polling. Typical: wait=10, repeat until completed.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "environment_id": {
                        "type": "string",
                        "description": "The environment ID returned by an _async tool (run_on_tunneled_ssh_async, run_on_tunneled_persistent_container_async or run_on_tunneled_disposable_container_async).",
                    },
                    "profile": _FOLLOW_UP_PROFILE_SCHEMA,
                    "wait": {
                        "type": "integer",
                        "description": "Seconds to wait before checking status. Use this to avoid tight polling loops. Suggested: 5-10 for short commands, 15-30 for installs/builds. Default: 5.",
                    },
                },
                "required": ["environment_id"],
            },
        ),
        Tool(
            name="cancel_execution",
            description="""Cancel a running async command. Terminates the environment and stops execution.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "environment_id": {
                        "type": "string",
                        "description": "The environment ID returned by an _async tool (run_on_tunneled_ssh_async, run_on_tunneled_persistent_container_async or run_on_tunneled_disposable_container_async).",
                    },
                    "profile": _FOLLOW_UP_PROFILE_SCHEMA,
                },
                "required": ["environment_id"],
            },
        ),
        Tool(
            name="transfer_files_between_tunneled_hosts_async",
            description="""Copy files/directories from one machine to another when BOTH are reachable through torque-tunnel but NOT from each other (e.g. two lab networks behind different Torque agents, or even different Torque accounts). The data never passes through your machine.

Returns once the transfer is under way (the source side has been copied and hashed, which can take a few minutes for multi-GB files), with two environment ids. Then poll `get_transfer_status` with the arguments the result gives you, and use `cancel_transfer` to abort. Large files (tens of GB) are fine.

`sender` and `receiver` are each an SSH machine (`type`: "ssh", with host/user and private_key or password) or a running persistent container (`type`: "persistent_container", with its environment_id). Their fields are the same as run_on_tunneled_ssh's and resolve the same way; each side may name its own `profile`.

How it works: torque-tunnel runs croc on each side's agent container (encrypted, through the croc relay), and verifies every file's size and MD5 before placing it. When both endpoints are behind the same agent, one environment copies directly over SSH instead.

Do NOT use this to move files between your local machine and a remote one - use upload_files / download_files of the run_* tools for that.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command_description": {
                        "type": "string",
                        "description": "REQUIRED. A concise (3-6 word) description of the transfer, embedded in the Torque environment names (e.g. 'copy ova to esxi').",
                    },
                    "sender": _TRANSFER_ENDPOINT_SCHEMA,
                    "receiver": _TRANSFER_ENDPOINT_SCHEMA,
                    "files": {
                        "type": "array",
                        "description": "What to copy. Each item: one file or directory.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source_path": {"type": "string", "description": "Path of a file or directory on the source machine."},
                                "destination_path": {"type": "string", "description": "Full path to create on the destination machine: for a file, the file's own path (an existing file is replaced; an existing DIRECTORY there is an error); for a directory, the directory whose CONTENTS will be the source directory's."},
                                "mode": {"type": "string", "description": "Optional permissions to set on the destination (e.g. '644')."},
                            },
                            "required": ["source_path", "destination_path"],
                        },
                    },
                    "timeout": {
                        "type": "integer",
                        "description": f"Optional: overall limit in seconds. Default {TRANSFER_DEFAULT_TIMEOUT_SECONDS}.",
                    },
                },
                "required": ["command_description", "sender", "receiver", "files"],
            },
        ),
        Tool(
            name="get_transfer_status",
            description="""Check a transfer started by transfer_files_between_tunneled_hosts_async: RUNNING (with progress), COMPLETED (every file verified and placed) or FAILED (with the reason). Pass exactly the arguments that tool's result gave you. Use `wait` to avoid tight polling.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "sender_environment_id": {"type": "string", "description": "From the transfer tool's result."},
                    "receiver_environment_id": {"type": "string", "description": "From the transfer tool's result (the same id as the sender's for a direct copy)."},
                    "sender_profile": {"type": "string", "description": "Only if the transfer tool's result names one."},
                    "receiver_profile": {"type": "string", "description": "Only if the transfer tool's result names one."},
                    "wait": {"type": "integer", "description": "Seconds to wait (returning early when the transfer finishes). Suggested: 30. Default: 5."},
                },
                "required": ["sender_environment_id", "receiver_environment_id"],
            },
        ),
        Tool(
            name="cancel_transfer",
            description="""Abort a transfer started by transfer_files_between_tunneled_hosts_async: ends both of its environments. Pass the same arguments as get_transfer_status (without wait).""",
            inputSchema={
                "type": "object",
                "properties": {
                    "sender_environment_id": {"type": "string"},
                    "receiver_environment_id": {"type": "string"},
                    "sender_profile": {"type": "string"},
                    "receiver_profile": {"type": "string"},
                },
                "required": ["sender_environment_id", "receiver_environment_id"],
            },
        ),
        Tool(
            name="list_credentials",
            description="""List the credentials stored in the connected Torque account that are usable from this profile's space.

Use this before passing `credential` to any run_* tool: it gives you the exact credential names and, for each one, the environment variables Torque will inject where your command runs. The secrets themselves are never returned here or anywhere else — only names, types, and non-secret details such as which vCenter or AWS account a credential points at.

Typical flow: call this once, pick the credential that matches the target infrastructure, then pass its name as `credential` to a run_* tool and reference the variables in your command (e.g. `govc -u "$VSPHERE_USER:$VSPHERE_PASSWORD@$VSPHERE_SERVER"`).

The first call against a Torque account may take ~30s if it has to measure credential types it has not seen before; results are cached, so later calls are immediate.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "force_rediscover": {
                        "type": "boolean",
                        "description": "Optional: re-measure which environment variables each credential type injects, instead of using the cached result. Only needed if Torque was upgraded and the cached variable names look wrong.",
                    },
                    "profile": {
                        "type": "string",
                        "description": "Configuration profile name to use. Omit to use the default profile.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="list_profiles",
            description="""List all available configuration profiles and base configuration. Profiles pre-configure connection settings (Torque URL, agent, SSH target, etc.) so you don't have to specify them on every call. Use a profile by passing its name as the 'profile' parameter to any execution tool.""",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="setup",
            description="""Interactively set up or add a Torque connection profile. Opens a browser window where the user can authenticate with email/password, sign in with Cisco ID (SSO), or paste an existing token, select account/space/agent, and optionally reuse an existing profile. The selections are saved to the config file for future use.

WHEN TO USE THIS TOOL (always prefer this over searching config files manually):
- User says "add agent", "add connection", "connect to torque", "set up torque tunnel", "configure torque"
- torque_token is missing or needs to be refreshed
- User wants to configure a new profile or add another agent/profile
- Any request about adding, connecting, or configuring torque-tunnel access

DO NOT search for config files or try to edit them manually — this tool handles everything interactively.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "torque_url": {
                        "type": "string",
                        "description": "Torque URL to authenticate against. Uses the configured URL if not specified.",
                    },
                    "profile": {
                        "type": "string",
                        "description": "Save results to this profile instead of top-level config.",
                    },
                },
            },
        ),
    ]


# --- Argument resolution, shared by every tool ------------------------------------------
# Each value comes from the tool argument, else the call's profile, else the base config.
# The run_* tools and both endpoints of a remote-to-remote transfer resolve through these
# same functions (tests/test_argument_resolution.py pins the behaviour for all of them).

async def _resolve_call_profile(arguments: dict):
    """Apply the `profile` named in `arguments`, as every tool call does.

    Returns (arguments, effective_config, profile_name, error). The arguments come back
    without `profile`, with the profile's tool-mappable values (host, user, private_key,
    torque_* ...) filled in where the caller gave none; effective_config overlays the
    profile's other values (init_commands, croc_relay ...) onto the base config.
    `error` is the text to return instead of running anything. The caller's dict is not
    modified.
    """
    arguments = dict(arguments)
    effective_config = _config
    profile_name = arguments.pop("profile", None)

    # Block tools that would use the broken default profile (but allow explicit profile)
    if not profile_name and _default_profile_warning:
        return arguments, effective_config, profile_name, (
            f"Error: {_default_profile_warning}\nSpecify a profile explicitly "
            f"(e.g. profile='cisco-review1') or fix default_profile in config.yaml.")
    if profile_name and _loaded_config:
        try:
            profile_values = config_module.resolve_profile(_loaded_config, profile_name)
            # Inject tool-argument-mappable values (host, user, private_key, etc.)
            arguments = config_module.inject_profile_into_arguments(arguments, profile_values)
            # Create effective config with config-only values (init_commands, etc.)
            effective_config = config_module.apply_profile_to_config(_config, profile_values)
        except ValueError as e:
            error_parts = [f"Error: {str(e)}"]
            if profile_name == "default":
                error_parts.append("**Hint:** To use the default profile, simply omit the 'profile' parameter entirely.")
            # Append profile listing for context
            profile_listing = await handle_list_profiles()
            if profile_listing:
                error_parts.append("")
                error_parts.append(profile_listing[0].text)
            return arguments, effective_config, profile_name, "\n".join(error_parts)
    return arguments, effective_config, profile_name, None


def _resolve_agent(arguments: dict, cfg: dict) -> Optional[str]:
    """The Torque agent a call runs on: its `torque_agent`, else the config's."""
    return arguments.get("torque_agent") or cfg["default_agent"]


def _resolve_connection(arguments: dict, cfg: dict, profile_name: Optional[str] = None) -> dict:
    """The Torque a call runs against: its torque_url/token/space, else the config's."""
    return _connection(cfg, profile_name, arguments.get("torque_url"),
                       arguments.get("torque_token"), arguments.get("torque_space"))


def _missing_torque_config(connection: dict) -> Optional[str]:
    if not all([connection["torque_url"], connection["torque_token"], connection["torque_space"]]):
        return ("Error: Torque configuration missing. Need torque_url, torque_token, and torque_space "
                "(or configure defaults).")
    return None


def _resolve_ssh_target(arguments: dict, cfg: dict):
    """The SSH target of a call: host, user and exactly one auth pair.

    host/user: the argument, else the config's default. Auth: if the arguments give
    either private_key or password, only the arguments' pair is used; otherwise the
    config's pair. The key goes through resolve_ssh_private_key (a path, the key's
    content, or base64 of it).

    Returns ({"host", "user", "private_key", "password"}, None) or (None, error text).
    """
    target_ip = arguments.get("host") or cfg["default_target_ip"]
    ssh_user = arguments.get("user") or cfg["default_ssh_user"]
    # SSH auth mutual exclusion: if args specify either auth method, use only args;
    # only fall back to config defaults when neither is provided in args.
    private_key_value = arguments.get("private_key")
    ssh_password = arguments.get("password")
    if not private_key_value and not ssh_password:
        private_key_value = cfg.get("default_ssh_key")
        ssh_password = cfg.get("default_ssh_password")
    if not all([target_ip, ssh_user]):
        return None, "Error: Missing required parameters. Need host and user (or configure defaults)."
    if not private_key_value and not ssh_password:
        return None, "Error: Missing authentication. Need private_key or password (or configure defaults)."
    ssh_private_key = ""
    if private_key_value:
        try:
            ssh_private_key = resolve_ssh_private_key(private_key_value)
        except ValueError as e:
            return None, f"Error: {str(e)}"
    return {"host": target_ip, "user": ssh_user, "private_key": ssh_private_key,
            "password": ssh_password}, None


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Handle tool calls."""
    
    # Handle list_profiles (no profile resolution needed)
    if name == "list_profiles":
        return await handle_list_profiles()

    # Handle setup (no profile resolution needed)
    if name == "setup":
        return await handle_setup(arguments)

    # Block execution tools if config file has errors
    if _config_error:
        return [TextContent(type="text", text=f"Error: Config file is broken — {_config_error}\nFix the config file or run the 'setup' tool to reconfigure.")]

    # The transfer tools name a profile PER ENDPOINT (each side can be another Torque),
    # so the call-level profile handling below does not apply to them.
    if name == "transfer_files_between_tunneled_hosts_async":
        return await handle_transfer_files_between_tunneled_hosts_async(arguments)
    if name == "get_transfer_status":
        return await handle_get_transfer_status(arguments)
    if name == "cancel_transfer":
        return await handle_cancel_transfer(arguments)

    # Resolve profile for execution tools: inject profile values into arguments
    # and create an effective_config overlay for config-only keys
    arguments, effective_config, profile_name, error = await _resolve_call_profile(arguments)
    if error:
        return [TextContent(type="text", text=error)]

    if name == "list_credentials":
        return await handle_list_credentials(arguments, effective_config)

    # A credential resolves a customer's real secrets into an agent container, so it is
    # opted into per profile. Checked here rather than in six handlers.
    if arguments.get("credential"):
        disabled = _credentials_disabled_message(effective_config)
        if disabled:
            return [TextContent(type="text", text=disabled)]

    # Credential problems carry messages meant for the caller (which space a credential is
    # allowed in, why a type cannot be used), so they are surfaced as-is rather than
    # flattened into a generic execution error by the handlers' own except clauses.
    try:
        if name == "run_on_tunneled_ssh":
            return await handle_run_on_tunneled_ssh(arguments, effective_config)

        elif name == "run_on_tunneled_persistent_container":
            return await handle_run_on_tunneled_persistent_container(arguments, effective_config)

        elif name == "run_on_tunneled_disposable_container":
            return await handle_run_on_tunneled_disposable_container(arguments, effective_config)

        elif name == "run_on_tunneled_ssh_async":
            return await handle_run_on_tunneled_ssh_async(arguments, effective_config, profile_name=profile_name)

        elif name == "run_on_tunneled_persistent_container_async":
            return await handle_run_on_tunneled_persistent_container_async(arguments, effective_config, profile_name=profile_name)

        elif name == "run_on_tunneled_disposable_container_async":
            return await handle_run_on_tunneled_disposable_container_async(arguments, effective_config, profile_name=profile_name)
    except credentials_module.CredentialError as e:
        return [TextContent(type="text", text=f"Credential error: {e}")]

    if name == "get_execution_status":
        return await handle_get_execution_status(arguments, effective_config, profile_name=profile_name)

    elif name == "cancel_execution":
        return await handle_cancel_execution(arguments, effective_config, profile_name=profile_name)
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


# --- Credentials --------------------------------------------------------------------


def _credentials_space_policy(cfg: dict) -> str:
    """The configured space policy, falling back to the safe one on a bad value."""
    policy = (cfg or {}).get("credentials_space_policy") or credentials_module.SPACE_POLICY_PRECONFIGURED
    if policy not in credentials_module.SPACE_POLICIES:
        return credentials_module.SPACE_POLICY_PRECONFIGURED
    return policy


def _credentials_disabled_message(cfg: dict) -> Optional[str]:
    """Why credentials cannot be used at all, or None when they can.

    Off by default: using a credential resolves a customer's real secrets into an agent
    container, so it is opted into per profile rather than assumed.
    """
    if (cfg or {}).get("credentials_enabled"):
        return None
    return (
        "Torque credentials are not enabled for this profile. Set `credentials_enabled: true` "
        "in ~/.torque-tunnel/config.yaml (at the top level or inside the profile), or re-run "
        "the `setup` tool and tick \"Allow using Torque credentials\"."
    )


async def _prepare_credential(arguments: dict, cfg: dict, client, *, forward: bool):
    """Resolve the `credential` argument into (name, context) for a run_* call.

    Returns (None, None) when no credential was requested. Raises CredentialError with a
    caller-facing message when the credential cannot be used.
    """
    name = arguments.get("credential")
    if not name:
        return None, None
    if isinstance(name, (list, tuple)):
        raise credentials_module.CredentialError(
            "Only one credential can be used per call, because Torque merges credential "
            "environment variables and a second credential of the same type would silently "
            "overwrite the first. Make one call per credential."
        )
    prep = await credentials_module.prepare_credential(
        client,
        name=name,
        space=client.space,
        space_policy=_credentials_space_policy(cfg),
        agent=arguments.get("torque_agent") or cfg.get("default_agent"),
        forward=forward,
        extra_forward=arguments.get("credential_env_forward"),
        enabled=bool((cfg or {}).get("credentials_enabled")),
    )
    return prep["credential"]["name"], prep["context"]


def _format_credential_entry(credential: dict, type_entry: Optional[dict]) -> list[str]:
    """Render one credential for list_credentials output."""
    name = credential.get("name")
    ctype = credential.get("type") or "unknown"
    head = f"- **{name}** ({ctype}"
    if credential.get("cloud_identifier"):
        head += f", {credential['cloud_identifier']}"
    head += ")"
    if credential.get("description"):
        head += f" - {credential['description']}"
    lines = [head]

    fields = credentials_module.displayable_fields(credential)
    if fields:
        lines.append("  " + ", ".join(f"{k}={v}" for k, v in sorted(fields.items())))

    status = (type_entry or {}).get("status")
    if type_entry is None:
        lines.append("  env vars: not measured yet - will be measured on first use")
    elif status == credentials_module.STATUS_OK:
        lines.append("  env vars: " + " ".join(type_entry.get("vars") or []))
    elif status == credentials_module.STATUS_NO_ENV_VARS:
        lines.append("  env vars: none - this type cannot be used with run_* tools")
    else:
        lines.append("  UNUSABLE: Torque cannot inject this credential type as env vars")

    if not credential.get("all_spaces_allowed"):
        allowed = credential.get("allowed_space_names") or []
        if allowed:
            lines.append("  allowed spaces: " + ", ".join(allowed))
    return lines


async def handle_list_credentials(arguments: dict, config: dict = None):
    """List the Torque credentials usable from this profile's space."""
    cfg = config or _config
    disabled = _credentials_disabled_message(cfg)
    if disabled:
        return [TextContent(type="text", text=disabled)]

    force = bool(arguments.get("force_rediscover"))
    try:
        async with get_torque_client(config=cfg) as client:
            cache = credentials_module.load_cache()
            if force:
                credentials_module.drop_measured_types(cache, client.base_url)
                credentials_module.save_cache(cache)

            # An explicit query always re-fetches the list, so a credential added a moment
            # ago shows up. Measurements are separate and are not re-run unless forced.
            cache, creds_list = await credentials_module.get_credentials(
                client, client.space, force_refresh=True, cache=cache
            )

            probe_targets: dict[str, str] = {}
            for c in creds_list:
                ctype = c.get("type")
                if ctype and ctype not in probe_targets:
                    probe_targets[ctype] = c["name"]
            if force:
                # The seed is the cache's initial shape, so "don't trust what I have" has to
                # reach seeded types too - otherwise forcing a rediscover on an account whose
                # types are all seeded would do nothing at all.
                pending = list(probe_targets)
            else:
                pending = credentials_module.unmeasured_types(
                    cache, client.base_url, list(probe_targets)
                )

            notes: list[str] = []
            if pending:
                notes.append(
                    f"Measuring {len(pending)} credential type(s) "
                    f"({', '.join(pending)}). This launches one short Torque environment "
                    f"and takes ~30s; the result is cached permanently."
                )
                try:
                    cache = await credentials_module.ensure_types_measured(
                        client, cache,
                        {t: probe_targets[t] for t in pending},
                        agent=cfg.get("default_agent"),
                        force=force,
                    )
                except Exception as e:
                    notes.append(f"Measurement failed: {e}")

            lines = [f"## Torque credentials in space '{client.space}'", ""]
            if notes:
                lines.extend(notes + [""])
            if not creds_list:
                lines.append("(none - this space has no credentials available)")
            for c in sorted(creds_list, key=lambda x: (x.get("name") or "").lower()):
                entry = credentials_module.get_type_entry(cache, client.base_url, c.get("type"))
                lines.extend(_format_credential_entry(c, entry))

            lines += [
                "",
                "Pass a name as `credential` to any run_* tool. Torque injects the listed "
                "variables where the command runs; reference them in the command "
                "(e.g. \"$VSPHERE_PASSWORD\") rather than pasting values.",
            ]
            return [TextContent(type="text", text="\n".join(lines))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing credentials: {e}")]


def _format_profile_entry(p: dict, default_profile: str | None = None) -> list[str]:
    """Format a single profile entry for display.

    Args:
        p: Profile dict with keys from config_module.list_profiles() or auth._build_profile_result():
           'name', 'description', 'extends', 'overrides', 'expose_values', 'values', and optionally 'is_default'.
        default_profile: Name of the default profile (from config).
            If None, falls back to p.get('is_default', False) to determine the marker.
    Returns:
        List of formatted lines for this profile.
    """
    is_default = (p['name'] == default_profile) if default_profile is not None else p.get('is_default', False)
    default_marker = " (default)" if is_default else ""
    desc = f" — {p['description']}" if p['description'] else ""
    extends = f" (extends: {p['extends']})" if p['extends'] else ""
    lines = [f"- **{p['name']}**{default_marker}{desc}{extends}"]
    if p['expose_values']:
        for key in p['overrides']:
            lines.append(f"  {key}: {p['values'][key]}")
    else:
        overrides = ", ".join(p['overrides']) if p['overrides'] else "(none)"
        lines.append(f"  Overrides: {overrides}")
        # Whether credentials may be used is not a secret, and the caller needs it to know
        # whether passing `credential` is even an option - so it is shown regardless of
        # expose_values, unlike the connection details.
        if p.get('values', {}).get('credentials_enabled'):
            lines.append("  credentials_enabled: true (see list_credentials)")
    return lines


async def handle_list_profiles():
    """Return the list of available configuration profiles with base config."""
    if not _config_file_path and not _loaded_config:
        return [TextContent(type="text", text="No configuration file found. Create ~/.torque-tunnel/config.yaml to define profiles.")]
    
    lines = []

    # Warn about broken default_profile
    if _default_profile_warning:
        lines.append(f"**Warning:** {_default_profile_warning}")
        lines.append("")
    
    # Show base configuration
    top_defaults = config_module.get_top_level_defaults(_loaded_config)
    if top_defaults:
        show_base_values = config_module.get_top_level_expose_values(_loaded_config)
        lines.append("**Base configuration:**")
        if show_base_values:
            for key in sorted(top_defaults):
                lines.append(f"  {key}: {top_defaults[key]}")
        else:
            lines.append(f"  {', '.join(sorted(top_defaults))}")
        lines.append("")
    
    # Show profiles
    default_profile = config_module.get_default_profile_name(_loaded_config)
    profiles = config_module.list_profiles(_loaded_config)
    if not profiles:
        lines.append("No profiles defined. Add a 'profiles' section to your config.yaml.")
        return [TextContent(type="text", text="\n".join(lines))]
    
    lines.append("**Profiles:**")
    for p in profiles:
        lines.extend(_format_profile_entry(p, default_profile))
    
    return [TextContent(type="text", text="\n".join(lines))]


async def handle_setup(arguments: dict):
    """Handle the setup tool — open browser for interactive Torque setup."""
    global _loaded_config
    profile_name = arguments.get("profile")

    # Resolve torque_url: argument > profile > config (may be None — UI will prompt)
    torque_url = arguments.get("torque_url")
    if not torque_url and profile_name and _loaded_config:
        try:
            pv = config_module.resolve_profile(_loaded_config, profile_name)
            torque_url = pv.get("torque_url")
        except ValueError:
            pass
    if not torque_url:
        torque_url = _config.get("torque_url")

    config_path = config_module.find_config_file()

    try:
        auth_server = auth_module.TorqueAuthServer(
            torque_url=torque_url or None,
            config_path=str(config_path) if config_path else None,
            profile_name=profile_name,
        )
        result = await auth_server.run()
    except TimeoutError as e:
        return [TextContent(type="text", text=f"Error: {e}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error during setup: {e}")]

    if result is None:
        return [TextContent(type="text", text="Setup cancelled.")]

    # Reload config immediately (watcher would also pick it up within ~2s)
    _reload_config()

    # Build summary using shared formatter (result is a profile dict)
    lines = ["Setup complete! Configured profile:"]
    lines.extend(_format_profile_entry(result))

    return [TextContent(type="text", text="\n".join(lines))]


async def handle_run_on_tunneled_ssh(arguments: dict, config: dict = None):
    """Execute a remote command via SSH, optionally uploading files first."""
    cfg = config or _config
    command = arguments.get("command")
    command_description = arguments.get("command_description")
    files = arguments.get("upload_files", [])
    download_files = arguments.get("download_files", [])
    agent = _resolve_agent(arguments, cfg)
    allow_dangerous_commands = arguments.get("allow_dangerous_commands", False)
    timeout = arguments.get("timeout")  # Optional timeout override
    # Per-call auto_delete overrides global config if specified
    auto_delete = arguments.get("auto_delete")
    if auto_delete is None:
        auto_delete = cfg["auto_delete_environments"]

    # Per-call Torque config overrides
    connection = _resolve_connection(arguments, cfg)
    torque_url, torque_space = connection["torque_url"], connection["torque_space"]

    # Must have at least command OR upload_files OR download_files
    if not command and not files and not download_files:
        return [TextContent(
            type="text",
            text="Error: Must provide either 'command', 'upload_files', or 'download_files' (or any combination).",
        )]

    target, error = _resolve_ssh_target(arguments, cfg)
    if error:
        return [TextContent(type="text", text=error)]
    target_ip, ssh_user = target["host"], target["user"]
    ssh_private_key, ssh_password = target["private_key"], target["password"]

    error = _missing_torque_config(connection)
    if error:
        return [TextContent(type="text", text=error)]

    # Check for dangerous commands unless allow_dangerous_commands=true
    if command and not allow_dangerous_commands:
        warning = check_dangerous_command(command)
        if warning:
            return [TextContent(type="text", text=warning)]

    # Process files parameter - generate deployment commands (with croc for large files)
    files_info = []
    init_commands = None
    container_pre_commands = None
    plan = None
    croc_process = None
    if files:
        plan = prepare_files_with_croc(
            files, transfer_mode="ssh",
            target_ip=target_ip, ssh_user=ssh_user,
            ssh_private_key=ssh_private_key, ssh_password=ssh_password,
            config=cfg,
        )
        if plan.errors:
            return [TextContent(
                type="text",
                text="Error preparing files:\n" + "\n".join(f"- {e}" for e in plan.errors),
            )]
        if plan.inline_commands:
            init_commands = plan.inline_commands
        if plan.croc_container_pre_commands:
            container_pre_commands = plan.croc_container_pre_commands
        files_info = plan.files_info
    
    # Process download_files parameter
    dl_plan = None
    dl_process = None
    if download_files:
        dl_plan = prepare_download_with_croc(
            download_files, transfer_mode="ssh",
            target_ip=target_ip, ssh_user=ssh_user,
            ssh_private_key=ssh_private_key, ssh_password=ssh_password,
            config=cfg,
        )
        if dl_plan.errors:
            return [TextContent(
                type="text",
                text="Error preparing downloads:\n" + "\n".join(f"- {e}" for e in dl_plan.errors),
            )]
    
    # If no command, use a simple echo
    effective_command = command or "echo 'Files deployed successfully'"
    
    # Create log streamer for real-time output
    log_callback = None
    try:
        session = server.request_context.session
        log_callback = create_log_streamer(session)
    except Exception:
        pass  # Streaming not available

    # Downloads are gated on the sender's READY sentinel, so the watcher must
    # observe the streamed output even when MCP streaming is unavailable
    if dl_plan is not None and dl_plan.needs_download:
        log_callback = make_download_watch_callback(dl_plan, log_callback)

    try:
        # Start croc send locally if needed (must happen BEFORE Torque environment)
        if plan is not None and plan.needs_croc:
            try:
                croc_process = await execute_with_croc(plan)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file transfer: {str(e)}")]
        
        # Start croc receive locally if download is needed (gated: idle until
        # the watcher sees the sender's READY sentinel)
        if dl_plan is not None and dl_plan.needs_download:
            try:
                dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file download receiver: {str(e)}")]
        
        # Create client with per-call or global cfg
        client = _connection_client(connection)
        async with client:
            __cred_name, __cred_ctx = await _prepare_credential(arguments, cfg, client, forward=True)
            result = await client.execute_remote_command(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=effective_command,
                agent=agent,
                timeout=timeout,
                auto_cleanup=auto_delete,
                log_callback=log_callback,
                init_commands=init_commands,
                ssh_password=ssh_password,
                container_pre_commands=container_pre_commands,
                download_commands=dl_plan.download_commands if dl_plan else None,
                command_description=command_description,
                environment_kind="ssh",
                credential_name=__cred_name,
                credential_context=__cred_ctx,
            )
            
            # Try to get grain log for additional context (especially useful on failures)
            grain_log = None
            try:
                grain_log = await client.get_grain_log(result.environment_id)
            except Exception:
                pass
        
        # Finalize file downloads if any
        dl_summary = ""
        if dl_plan is not None and dl_plan.needs_download:
            dl_successes, dl_errors = await complete_download(dl_plan, dl_process)
            dl_summary = format_download_summary(
                dl_successes, dl_errors, dl_plan.transfer_seconds)
        
        # Format execution duration
        if result.execution_duration is not None:
            duration = result.execution_duration
            duration_str = f"{int(duration // 60)}m {duration % 60:.1f}s" if duration >= 60 else f"{duration:.1f}s"
        else:
            duration_str = "N/A"
        
        # Build environment URL for reference
        env_url = f"{torque_url}/{torque_space}/environments/{result.environment_id}"
        
        # Build files summary if any were uploaded
        files_summary = ""
        if files_info:
            files_summary = format_upload_summary(files_info, grain_log)
        
        if result.status == "completed":
            output_block = format_code_block(result.command_output)
            success_msg = "Command executed successfully" if result.exit_code == 0 else "Command failed"
            output_text = f"""{success_msg} on {target_ip}
{files_summary}{dl_summary}
**Exit Code:** {result.exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
        else:
            output_text = f"""Command execution failed on {target_ip}
{files_summary}{dl_summary}
**Status:** {result.status}
**Error:** {result.error}

**Duration:** {duration_str}

**Environment:** {env_url}"""
            
            # Include partial output if available (e.g., on timeout)
            if result.command_output:
                partial_block = format_code_block(result.command_output)
                output_text += f"""

**Partial Output:**
{partial_block}"""
            # Include grain log on failure for debugging
            elif grain_log:
                output_text += format_log_section("Grain Execution Log", grain_log)
        
        # Add tip if command took >60s
        if result.execution_duration is not None and result.execution_duration > 60:
            output_text += "\n\n**TIP:** This command took over 60 seconds. Consider using `run_on_tunneled_ssh_async` for similar long-running commands to get progress updates while waiting."
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        # A credential problem carries a message written for the caller (which space
        # allows it, why its type cannot be used) - pass it through verbatim.
        if isinstance(e, credentials_module.CredentialError):
            return [TextContent(type="text", text=f"Credential error: {e}")]
        return [TextContent(type="text", text=f"Error executing remote command: {str(e)}")]
    finally:
        await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")
        await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir if dl_plan else "")


async def _ensure_persistent_container(
    agent: Optional[str] = None,
    new_container: bool = False,
    environment_id: Optional[str] = None,
    torque_url: Optional[str] = None,
    torque_token: Optional[str] = None,
    torque_space: Optional[str] = None,
    config: Optional[dict] = None,
    container_description: Optional[str] = None,
) -> dict:
    """
    Ensure a persistent container is running and return its connection details.
    
    Supports multiple persistent containers simultaneously:
    - No args: returns the default (most recently used) container, creating one if needed
    - environment_id: returns that specific container (fetches details if unknown)
    - new_container=True: always creates a fresh container (keeps old ones alive)
    
    Returns:
        Dict with 'environment_id', 'container_ip', 'container_id', 'private_key', 'agent'
    """
    global _default_persistent_container_id
    cfg = config or _config
    agent_name = agent or cfg["default_agent"]
    
    # If a specific environment_id was requested
    if environment_id:
        # Check if we have it cached
        if environment_id in _persistent_containers:
            info = _persistent_containers[environment_id]
            # Verify it's still alive (deploying/launching = SSH daemon still running)
            try:
                async with get_torque_client(torque_url, torque_token, torque_space, config=cfg) as client:
                    env_data = await client.get_environment_status(environment_id)
                    current_state = env_data.get("details", {}).get("state", {}).get("current_state", "")
                    if current_state in ("deploying", "launching"):
                        _default_persistent_container_id = environment_id
                        return dict(info)
            except Exception:
                pass
            # Container is gone - remove from cache and fall through to create a new one
            del _persistent_containers[environment_id]
            if _default_persistent_container_id == environment_id:
                _default_persistent_container_id = None
            print(f"[torque-tunnel] Persistent container {environment_id} is no longer usable, creating a new one...", file=sys.stderr, flush=True)
        else:
            # Not cached - try to fetch details from Torque
            try:
                async with get_torque_client(torque_url, torque_token, torque_space, config=cfg) as client:
                    env_data = await client.get_environment_status(environment_id)
                    current_state = env_data.get("details", {}).get("state", {}).get("current_state", "")
                    if current_state not in ("deploying", "launching"):
                        print(f"[torque-tunnel] Environment {environment_id} is in state '{current_state}', creating a new container...", file=sys.stderr, flush=True)
                    else:
                        # Fetch connection details from the deploy log
                        info = await client.get_persistent_container_info(environment_id)
                        container_entry = {
                            "environment_id": environment_id,
                            "container_ip": info["container_ip"],
                            "container_id": info["container_id"],
                            "private_key": info["private_key"],
                            "agent": agent_name,
                        }
                        _persistent_containers[environment_id] = container_entry
                        _default_persistent_container_id = environment_id
                        print(f"[torque-tunnel] Attached to persistent container: {info['container_id']} @ {info['container_ip']} (env: {environment_id})", file=sys.stderr, flush=True)
                        return dict(container_entry)
            except Exception as e:
                print(f"[torque-tunnel] Could not connect to persistent container {environment_id}: {e}. Creating a new one...", file=sys.stderr, flush=True)
    
    # If new_container requested, always create a new one (don't release old ones)
    if not new_container:
        # Try to use the default container
        if _default_persistent_container_id and _default_persistent_container_id in _persistent_containers:
            info = _persistent_containers[_default_persistent_container_id]
            if (info.get("agent") or "") == (agent_name or ""):
                # Verify it's still alive
                try:
                    async with get_torque_client(torque_url, torque_token, torque_space, config=cfg) as client:
                        env_data = await client.get_environment_status(_default_persistent_container_id)
                        current_state = env_data.get("details", {}).get("state", {}).get("current_state", "")
                        if current_state in ("deploying", "launching"):
                            return dict(info)
                except Exception:
                    pass
                # Container is gone - remove from cache
                del _persistent_containers[_default_persistent_container_id]
                _default_persistent_container_id = None
    
    # Launch a new persistent container. Initial lifetime = the idle timeout
    # (was a hardcoded PT24H, which made the documented "2h idle timeout" a
    # fiction); every command re-arms the end via set_scheduled_end_time.
    # Floor of 30 min so container provisioning can't outrun a tiny timeout.
    initial_duration = _format_iso_duration(max(int(cfg["container_idle_timeout"]), 1800))
    async with get_torque_client(torque_url, torque_token, torque_space, config=cfg) as client:
        env_id = await client.start_persistent_container(
            agent=agent_name,
            container_description=container_description,
            duration=initial_duration,
        )
        print(f"[torque-tunnel] Launching persistent container (env: {env_id})...", file=sys.stderr, flush=True)
        
        info = await client.get_persistent_container_info(env_id)
        
        container_entry = {
            "environment_id": env_id,
            "container_ip": info["container_ip"],
            "container_id": info["container_id"],
            "private_key": info["private_key"],
            "agent": agent_name,
        }
        _persistent_containers[env_id] = container_entry
        _default_persistent_container_id = env_id
        
        print(f"[torque-tunnel] Persistent container ready: {info['container_id']} @ {info['container_ip']} (env: {env_id})", file=sys.stderr, flush=True)
        
        return dict(container_entry)


async def handle_run_on_tunneled_persistent_container(arguments: dict, config: dict = None):
    """Execute a command on a persistent Torque agent container via SSH.
    
    On first call, launches a persistent container with dropbear (SSH server). Subsequent calls
    reuse the same container. The command is executed by SSHing from a disposable
    grain container into the persistent container.
    
    Reuses the same SSH execution logic as handle_run_on_tunneled_ssh.
    """
    cfg = config or _config
    command = arguments.get("command")
    command_description = arguments.get("command_description")
    container_description = arguments.get("container_description")
    files = arguments.get("upload_files", [])
    download_files = arguments.get("download_files", [])
    agent = _resolve_agent(arguments, cfg)
    timeout = arguments.get("timeout")
    new_container = arguments.get("new_container", False)
    target_env_id = arguments.get("environment_id")
    connection = _resolve_connection(arguments, cfg)
    torque_url, torque_token, torque_space = (
        connection["torque_url"], connection["torque_token"], connection["torque_space"])

    # Must have at least command OR upload_files OR download_files
    if not command and not files and not download_files:
        return [TextContent(
            type="text",
            text="Error: Must provide either 'command', 'upload_files', or 'download_files' (or any combination).",
        )]

    try:
        # Ensure we have a persistent container running
        container_info = await _ensure_persistent_container(agent=agent, new_container=new_container, environment_id=target_env_id, torque_url=torque_url, torque_token=torque_token, torque_space=torque_space, config=cfg, container_description=container_description)
        container_ip = container_info["container_ip"]
        private_key = container_info["private_key"]
        env_id = container_info["environment_id"]
    except Exception as e:
        return [TextContent(type="text", text=f"Error setting up persistent container: {str(e)}")]
    
    # Process files parameter - generate deployment commands (with croc for large files)
    files_info = []
    init_commands = None
    container_pre_commands = None
    plan = None
    croc_process = None
    if files:
        plan = prepare_files_with_croc(
            files, transfer_mode="ssh",
            target_ip=container_ip, ssh_user="root",
            ssh_private_key=private_key,
            config=cfg,
        )
        if plan.errors:
            return [TextContent(
                type="text",
                text="Error preparing files:\n" + "\n".join(f"- {e}" for e in plan.errors),
            )]
        if plan.inline_commands:
            init_commands = plan.inline_commands
        if plan.croc_container_pre_commands:
            container_pre_commands = plan.croc_container_pre_commands
        files_info = plan.files_info
    
    # Process download_files parameter
    dl_plan = None
    dl_process = None
    if download_files:
        dl_plan = prepare_download_with_croc(
            download_files, transfer_mode="ssh",
            target_ip=container_ip, ssh_user="root",
            ssh_private_key=private_key,
            config=cfg,
        )
        if dl_plan.errors:
            return [TextContent(
                type="text",
                text="Error preparing downloads:\n" + "\n".join(f"- {e}" for e in dl_plan.errors),
            )]
    
    effective_command = command or "echo 'Files deployed successfully'"
    
    # Create log streamer for real-time output
    log_callback = None
    try:
        session = server.request_context.session
        log_callback = create_log_streamer(session)
    except Exception:
        pass

    # Downloads are gated on the sender's READY sentinel, so the watcher must
    # observe the streamed output even when MCP streaming is unavailable
    if dl_plan is not None and dl_plan.needs_download:
        log_callback = make_download_watch_callback(dl_plan, log_callback)

    try:
        # Start croc send locally if needed (must happen BEFORE Torque environment)
        if plan is not None and plan.needs_croc:
            try:
                croc_process = await execute_with_croc(plan)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file transfer: {str(e)}")]
        
        # Start croc receive locally if download is needed
        if dl_plan is not None and dl_plan.needs_download:
            try:
                dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file download receiver: {str(e)}")]
        
        # Reuse the SSH execution logic - SSH from a disposable grain into the persistent container
        async with _connection_client(connection) as client:
            # Arm the container's end time so it cannot die under this command
            try:
                await client.set_scheduled_end_time(
                    env_id, _container_deadline(cfg["container_idle_timeout"], timeout)
                )
            except Exception:
                pass  # Non-critical

            __cred_name, __cred_ctx = await _prepare_credential(arguments, cfg, client, forward=True)
            result = await client.execute_remote_command(
                target_ip=container_ip,
                ssh_user="root",
                ssh_private_key=private_key,
                command=effective_command,
                agent=agent,
                timeout=timeout,
                auto_cleanup=cfg["auto_delete_environments"],
                log_callback=log_callback,
                init_commands=init_commands,
                container_pre_commands=container_pre_commands,
                download_commands=dl_plan.download_commands if dl_plan else None,
                command_description=command_description,
                environment_kind="persistent-command",
                parent_env_id=env_id,
                credential_name=__cred_name,
                credential_context=__cred_ctx,
            )

            grain_log = None
            try:
                grain_log = await client.get_grain_log(result.environment_id)
            except Exception:
                pass

            # Re-arm the idle timeout: the container dies idle_timeout after
            # its LAST USE. Absolute end time — the previous additive /extend
            # accumulated +2h per command on top of a 24h initial duration,
            # so containers effectively never idled out.
            try:
                await client.set_scheduled_end_time(
                    env_id, _container_deadline(cfg["container_idle_timeout"])
                )
            except Exception:
                pass  # Non-critical
        
        # Format output (same formatting as handle_run_on_tunneled_ssh)
        # Finalize file downloads if any
        dl_summary = ""
        if dl_plan is not None and dl_plan.needs_download:
            dl_successes, dl_errors = await complete_download(dl_plan, dl_process)
            dl_summary = format_download_summary(
                dl_successes, dl_errors, dl_plan.transfer_seconds)
        
        if result.execution_duration is not None:
            duration = result.execution_duration
            duration_str = f"{int(duration // 60)}m {duration % 60:.1f}s" if duration >= 60 else f"{duration:.1f}s"
        else:
            duration_str = "N/A"
        
        env_url = _environment_url(connection, result.environment_id)
        agent_name = agent or cfg["default_agent"]
        
        files_summary = ""
        if files_info:
            files_summary = format_upload_summary(files_info, grain_log)
        
        if result.status == "completed":
            output_block = format_code_block(result.command_output)
            success_msg = "Command executed successfully" if result.exit_code == 0 else "Command failed"
            output_text = f"""{success_msg} on agent `{agent_name}`
{files_summary}{dl_summary}
**Persistent Container:** {env_id}
**Exit Code:** {result.exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
        else:
            output_text = f"""Command execution failed on agent `{agent_name}`
{files_summary}{dl_summary}
**Persistent Container:** {env_id}
**Status:** {result.status}
**Error:** {result.error}

**Duration:** {duration_str}

**Environment:** {env_url}"""
            
            if result.command_output:
                partial_block = format_code_block(result.command_output)
                output_text += f"""

**Partial Output:**
{partial_block}"""
            elif grain_log:
                output_text += format_log_section("Grain Execution Log", grain_log)
        
        if result.execution_duration is not None and result.execution_duration > 60:
            output_text += "\n\n**TIP:** This command took over 60 seconds. Consider using `run_on_tunneled_persistent_container_async` for similar long-running commands to get progress updates while waiting."
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        # A credential problem carries a message written for the caller (which space
        # allows it, why its type cannot be used) - pass it through verbatim.
        if isinstance(e, credentials_module.CredentialError):
            return [TextContent(type="text", text=f"Credential error: {e}")]
        return [TextContent(type="text", text=f"Error executing command on container: {str(e)}")]
    finally:
        await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")
        await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir if dl_plan else "")


async def handle_run_on_tunneled_disposable_container(arguments: dict, config: dict = None):
    """Execute a command on a fresh Torque agent container, optionally uploading files first."""
    cfg = config or _config
    command = arguments.get("command")
    command_description = arguments.get("command_description")
    files = arguments.get("upload_files", [])
    download_files = arguments.get("download_files", [])
    agent = _resolve_agent(arguments, cfg)
    timeout = arguments.get("timeout")  # Optional timeout override
    connection = _resolve_connection(arguments, cfg)
    torque_url, torque_token, torque_space = (
        connection["torque_url"], connection["torque_token"], connection["torque_space"])

    # Must have at least command OR upload_files OR download_files
    if not command and not files and not download_files:
        return [TextContent(
            type="text",
            text="Error: Must provide either 'command', 'upload_files', or 'download_files' (or any combination).",
        )]

    # Process files parameter - generate deployment commands (with croc for large files)
    files_info = []
    init_commands = None
    plan = None
    croc_process = None
    if files:
        plan = prepare_files_with_croc(files, transfer_mode="container", config=cfg)
        if plan.errors:
            return [TextContent(
                type="text",
                text="Error preparing files:\n" + "\n".join(f"- {e}" for e in plan.errors),
            )]
        # Combine croc init + inline commands for container target
        combined = []
        if plan.croc_init_commands:
            combined.append(plan.croc_init_commands)
        if plan.inline_commands:
            combined.append(plan.inline_commands)
        if combined:
            init_commands = "\n".join(combined)
        files_info = plan.files_info
    
    # Process download_files parameter
    dl_plan = None
    dl_process = None
    if download_files:
        dl_plan = prepare_download_with_croc(download_files, transfer_mode="container", config=cfg)
        if dl_plan.errors:
            return [TextContent(
                type="text",
                text="Error preparing downloads:\n" + "\n".join(f"- {e}" for e in dl_plan.errors),
            )]
    
    # If no command, use a simple echo
    effective_command = command or "echo 'Files deployed successfully'"
    
    # Create log streamer for real-time output
    log_callback = None
    try:
        session = server.request_context.session
        log_callback = create_log_streamer(session)
    except Exception:
        pass  # Streaming not available

    # Downloads are gated on the sender's READY sentinel, so the watcher must
    # observe the streamed output even when MCP streaming is unavailable
    if dl_plan is not None and dl_plan.needs_download:
        log_callback = make_download_watch_callback(dl_plan, log_callback)

    try:
        # Start croc send locally if needed (must happen BEFORE Torque environment)
        if plan is not None and plan.needs_croc:
            try:
                croc_process = await execute_with_croc(plan)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file transfer: {str(e)}")]
        
        # Start croc receive locally if download is needed
        if dl_plan is not None and dl_plan.needs_download:
            try:
                dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file download receiver: {str(e)}")]
        
        async with _connection_client(connection) as client:
            __cred_name, __cred_ctx = await _prepare_credential(arguments, cfg, client, forward=False)
            result = await client.execute_local_command(
                command=effective_command,
                agent=agent,
                timeout=timeout,
                auto_cleanup=cfg["auto_delete_environments"],
                log_callback=log_callback,
                init_commands=init_commands,
                download_commands=dl_plan.download_commands if dl_plan else None,
                command_description=command_description,
                credential_name=__cred_name,
                credential_context=__cred_ctx,
            )

            # Try to get grain log for additional context (especially useful on failures)
            grain_log = None
            try:
                grain_log = await client.get_grain_log(result.environment_id)
            except Exception:
                pass
        
        # Finalize file downloads if any
        dl_summary = ""
        if dl_plan is not None and dl_plan.needs_download:
            dl_successes, dl_errors = await complete_download(dl_plan, dl_process)
            dl_summary = format_download_summary(
                dl_successes, dl_errors, dl_plan.transfer_seconds)
        
        # Format execution duration
        if result.execution_duration is not None:
            duration = result.execution_duration
            duration_str = f"{int(duration // 60)}m {duration % 60:.1f}s" if duration >= 60 else f"{duration:.1f}s"
        else:
            duration_str = "N/A"
        
        # Build environment URL for reference
        env_url = _environment_url(connection, result.environment_id)
        agent_name = agent or cfg["default_agent"]
        
        # Build files summary if any were uploaded
        files_summary = ""
        if files_info:
            files_summary = format_upload_summary(files_info, grain_log)
        
        if result.status == "completed":
            output_block = format_code_block(result.command_output)
            success_msg = "Command executed successfully" if result.exit_code == 0 else "Command failed"
            output_text = f"""{success_msg} on agent `{agent_name}`
{files_summary}{dl_summary}
**Exit Code:** {result.exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
        else:
            output_text = f"""Command execution failed on agent `{agent_name}`
{files_summary}{dl_summary}
**Status:** {result.status}
**Error:** {result.error}

**Duration:** {duration_str}

**Environment:** {env_url}"""
            
            # Include partial output if available (e.g., on timeout)
            if result.command_output:
                partial_block = format_code_block(result.command_output)
                output_text += f"""

**Partial Output:**
{partial_block}"""
            # Include grain log on failure for debugging
            elif grain_log:
                output_text += format_log_section("Grain Execution Log", grain_log)
        
        # Add tip if command took >60s
        if result.execution_duration is not None and result.execution_duration > 60:
            output_text += "\n\n**TIP:** This command took over 60 seconds. Consider using `run_on_tunneled_disposable_container_async` for similar long-running commands to get progress updates while waiting."
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        # A credential problem carries a message written for the caller (which space
        # allows it, why its type cannot be used) - pass it through verbatim.
        if isinstance(e, credentials_module.CredentialError):
            return [TextContent(type="text", text=f"Credential error: {e}")]
        return [TextContent(type="text", text=f"Error executing command on agent: {str(e)}")]
    finally:
        await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")
        await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir if dl_plan else "")


async def handle_run_on_tunneled_ssh_async(arguments: dict, config: dict = None,
                                           profile_name: Optional[str] = None):
    """Start a remote SSH command without waiting for completion."""
    cfg = config or _config
    command = arguments.get("command")
    command_description = arguments.get("command_description")
    files = arguments.get("upload_files", [])
    download_files = arguments.get("download_files", [])
    agent = _resolve_agent(arguments, cfg)
    allow_dangerous_commands = arguments.get("allow_dangerous_commands", False)
    timeout = arguments.get("timeout")
    connection = _resolve_connection(arguments, cfg, profile_name)

    if not command and not files and not download_files:
        return [TextContent(type="text", text="Error: Must provide either 'command', 'upload_files', or 'download_files' (or any combination).")]

    target, error = _resolve_ssh_target(arguments, cfg)
    if error:
        return [TextContent(type="text", text=error)]
    target_ip, ssh_user = target["host"], target["user"]
    ssh_private_key, ssh_password = target["private_key"], target["password"]

    # Check for dangerous commands
    if command and not allow_dangerous_commands:
        warning = check_dangerous_command(command)
        if warning:
            return [TextContent(type="text", text=warning)]

    # Process files parameter - generate deployment commands (with croc for large files)
    files_info = []
    init_commands = None
    container_pre_commands = None
    plan = None
    croc_process = None
    if files:
        plan = prepare_files_with_croc(
            files, transfer_mode="ssh",
            target_ip=target_ip, ssh_user=ssh_user,
            ssh_private_key=ssh_private_key, ssh_password=ssh_password,
            config=cfg,
        )
        if plan.errors:
            return [TextContent(type="text", text="Error preparing files:\n" + "\n".join(f"- {e}" for e in plan.errors))]
        if plan.inline_commands:
            init_commands = plan.inline_commands
        if plan.croc_container_pre_commands:
            container_pre_commands = plan.croc_container_pre_commands
        files_info = plan.files_info
    
    # Process download_files parameter
    dl_plan = None
    dl_process = None
    if download_files:
        dl_plan = prepare_download_with_croc(
            download_files, transfer_mode="ssh",
            target_ip=target_ip, ssh_user=ssh_user,
            ssh_private_key=ssh_private_key, ssh_password=ssh_password,
            config=cfg,
        )
        if dl_plan.errors:
            return [TextContent(type="text", text="Error preparing downloads:\n" + "\n".join(f"- {e}" for e in dl_plan.errors))]
    
    effective_command = command or "echo 'Files deployed successfully'"
    
    try:
        # Start croc send locally if needed (must happen BEFORE Torque environment)
        if plan is not None and plan.needs_croc:
            try:
                croc_process = await execute_with_croc(plan)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file transfer: {str(e)}")]
        
        # Start croc receive locally if download is needed
        if dl_plan is not None and dl_plan.needs_download:
            try:
                dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file download receiver: {str(e)}")]
        
        async with _connection_client(connection) as client:
            __cred_name, __cred_ctx = await _prepare_credential(arguments, cfg, client, forward=True)
            environment_id = await client.start_environment(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=effective_command,
                agent=agent,
                init_commands=init_commands,
                timeout=timeout,
                ssh_password=ssh_password,
                container_pre_commands=container_pre_commands,
                download_commands=dl_plan.download_commands if dl_plan else None,
                command_description=command_description,
                environment_kind="ssh",
                credential_name=__cred_name,
                credential_context=__cred_ctx,
            )

        # Track croc state for cleanup when execution completes
        async_state = {}
        if croc_process is not None:
            async_state["process"] = croc_process
            async_state["staging_dir"] = plan.croc_staging_dir if plan else ""
            croc_process = None  # Don't clean up in except block
        if dl_process is not None:
            async_state["dl_process"] = dl_process
            async_state["dl_plan"] = dl_plan
            dl_process = None  # Don't clean up in except block
        if async_state:
            _croc_async_state[environment_id] = async_state
        
        # Start background streaming of grain log to stderr
        _remember_async_connection(environment_id, dict(connection, profile=profile_name))
        _start_background_streamer(environment_id)
        
        env_url = _environment_url(connection, environment_id)
        
        files_summary = ""
        if files_info:
            files_summary = "\n**Files Queued:**\n" + "\n".join(f"- {f}" for f in files_info) + "\n"
        
        dl_info = ""
        if dl_plan is not None and dl_plan.files_info:
            dl_info = "\n**Downloads Queued:**\n" + "\n".join(f"- {f}" for f in dl_plan.files_info) + "\n"
        
        # Suggest appropriate wait time based on command content
        suggested_wait = _suggest_wait_time(effective_command)
        
        output_text = f"""Command started on {target_ip} (async)
{files_summary}{dl_info}
**Environment ID:** {environment_id}
**Environment:** {env_url}

Use `get_execution_status` with {_follow_up_args(environment_id, profile_name)} to check progress (suggested initial wait={suggested_wait}, adjust as needed).
Use `cancel_execution` with {_follow_up_args(environment_id, profile_name)} to abort if needed."""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        # Clean up croc on error (not tracked for async cleanup)
        await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")
        await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir if dl_plan else "")
        # A credential problem carries a message written for the caller (which space
        # allows it, why its type cannot be used) - pass it through verbatim.
        if isinstance(e, credentials_module.CredentialError):
            return [TextContent(type="text", text=f"Credential error: {e}")]
        return [TextContent(type="text", text=f"Error starting async command: {str(e)}")]


async def handle_run_on_tunneled_persistent_container_async(arguments: dict, config: dict = None,
                                                            profile_name: Optional[str] = None):
    """Start a command on the persistent container without waiting for completion.
    
    Blocks until the persistent container is up, then launches the command
    asynchronously via SSH from a disposable grain into the persistent container.
    """
    cfg = config or _config
    command = arguments.get("command")
    command_description = arguments.get("command_description")
    container_description = arguments.get("container_description")
    files = arguments.get("upload_files", [])
    download_files = arguments.get("download_files", [])
    agent = _resolve_agent(arguments, cfg)
    new_container = arguments.get("new_container", False)
    target_env_id = arguments.get("environment_id")
    timeout = arguments.get("timeout")
    connection = _resolve_connection(arguments, cfg)
    torque_url, torque_token, torque_space = (
        connection["torque_url"], connection["torque_token"], connection["torque_space"])

    if not command and not files and not download_files:
        return [TextContent(type="text", text="Error: Must provide either 'command', 'upload_files', or 'download_files' (or any combination).")]

    try:
        # Ensure persistent container is up (this blocks until ready)
        container_info = await _ensure_persistent_container(agent=agent, new_container=new_container, environment_id=target_env_id, torque_url=torque_url, torque_token=torque_token, torque_space=torque_space, config=cfg, container_description=container_description)
        container_ip = container_info["container_ip"]
        private_key = container_info["private_key"]
        env_id = container_info["environment_id"]
    except Exception as e:
        return [TextContent(type="text", text=f"Error setting up persistent container: {str(e)}")]
    
    # Process files parameter - generate deployment commands (with croc for large files)
    files_info = []
    init_commands = None
    container_pre_commands = None
    plan = None
    croc_process = None
    if files:
        plan = prepare_files_with_croc(
            files, transfer_mode="ssh",
            target_ip=container_ip, ssh_user="root",
            ssh_private_key=private_key,
            config=cfg,
        )
        if plan.errors:
            return [TextContent(type="text", text="Error preparing files:\n" + "\n".join(f"- {e}" for e in plan.errors))]
        if plan.inline_commands:
            init_commands = plan.inline_commands
        if plan.croc_container_pre_commands:
            container_pre_commands = plan.croc_container_pre_commands
        files_info = plan.files_info
    
    # Process download_files parameter
    dl_plan = None
    dl_process = None
    if download_files:
        dl_plan = prepare_download_with_croc(
            download_files, transfer_mode="ssh",
            target_ip=container_ip, ssh_user="root",
            ssh_private_key=private_key,
            config=cfg,
        )
        if dl_plan.errors:
            return [TextContent(type="text", text="Error preparing downloads:\n" + "\n".join(f"- {e}" for e in dl_plan.errors))]
    
    effective_command = command or "echo 'Files deployed successfully'"
    
    try:
        # Start croc send locally if needed (must happen BEFORE Torque environment)
        if plan is not None and plan.needs_croc:
            try:
                croc_process = await execute_with_croc(plan)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file transfer: {str(e)}")]
        
        # Start croc receive locally if download is needed
        if dl_plan is not None and dl_plan.needs_download:
            try:
                dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file download receiver: {str(e)}")]
        
        # Start the SSH command asynchronously - SSH from disposable grain into persistent container
        async with _connection_client(connection) as client:
            __cred_name, __cred_ctx = await _prepare_credential(arguments, cfg, client, forward=True)
            environment_id = await client.start_environment(
                target_ip=container_ip,
                ssh_user="root",
                ssh_private_key=private_key,
                command=effective_command,
                agent=agent,
                init_commands=init_commands,
                timeout=timeout,
                container_pre_commands=container_pre_commands,
                download_commands=dl_plan.download_commands if dl_plan else None,
                command_description=command_description,
                environment_kind="persistent-command",
                parent_env_id=env_id,
                credential_name=__cred_name,
                credential_context=__cred_ctx,
            )
            
            # Track croc state for cleanup when execution completes
            async_state = {}
            if croc_process is not None:
                async_state["process"] = croc_process
                async_state["staging_dir"] = plan.croc_staging_dir if plan else ""
                croc_process = None  # Don't clean up in except block
            if dl_process is not None:
                async_state["dl_process"] = dl_process
                async_state["dl_plan"] = dl_plan
                dl_process = None  # Don't clean up in except block
            if async_state:
                _croc_async_state[environment_id] = async_state
            
            # Arm the container's end time: it must outlive this async command
            # (idle window or command timeout + slack, whichever is larger).
            # The command runs unattended, so the idle window is re-armed from
            # launch rather than from completion — the next command (or
            # get_execution_status of a sync one) tightens it again.
            try:
                await client.set_scheduled_end_time(
                    env_id, _container_deadline(cfg["container_idle_timeout"], timeout)
                )
            except Exception:
                pass

        # Start background streaming of grain log to stderr
        _remember_async_connection(environment_id, dict(connection, profile=profile_name))
        _start_background_streamer(environment_id)
        
        env_url = _environment_url(connection, environment_id)
        agent_name = agent or cfg["default_agent"]
        
        files_summary = ""
        if files_info:
            files_summary = "\n**Files Queued:**\n" + "\n".join(f"- {f}" for f in files_info) + "\n"
        
        dl_info = ""
        if dl_plan is not None and dl_plan.files_info:
            dl_info = "\n**Downloads Queued:**\n" + "\n".join(f"- {f}" for f in dl_plan.files_info) + "\n"
        
        suggested_wait = _suggest_wait_time(effective_command)
        
        output_text = f"""Command started on persistent container (async)
{files_summary}{dl_info}
**Persistent Container:** {env_id}
**Environment ID:** {environment_id}
**Environment:** {env_url}

Use `get_execution_status` with {_follow_up_args(environment_id, profile_name)} to check progress (suggested initial wait={suggested_wait}, adjust as needed).
Use `cancel_execution` with {_follow_up_args(environment_id, profile_name)} to abort if needed."""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        # Clean up croc on error (not tracked for async cleanup)
        await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")
        await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir if dl_plan else "")
        # A credential problem carries a message written for the caller (which space
        # allows it, why its type cannot be used) - pass it through verbatim.
        if isinstance(e, credentials_module.CredentialError):
            return [TextContent(type="text", text=f"Credential error: {e}")]
        return [TextContent(type="text", text=f"Error starting async command on container: {str(e)}")]


async def handle_run_on_tunneled_disposable_container_async(arguments: dict, config: dict = None,
                                                            profile_name: Optional[str] = None):
    """Start a disposable container command without waiting for completion."""
    cfg = config or _config
    command = arguments.get("command")
    command_description = arguments.get("command_description")
    files = arguments.get("upload_files", [])
    download_files = arguments.get("download_files", [])
    agent = _resolve_agent(arguments, cfg)
    timeout = arguments.get("timeout")
    connection = _resolve_connection(arguments, cfg)
    torque_url, torque_token, torque_space = (
        connection["torque_url"], connection["torque_token"], connection["torque_space"])

    if not command and not files and not download_files:
        return [TextContent(type="text", text="Error: Must provide either 'command', 'upload_files', or 'download_files' (or any combination).")]

    # Process files parameter - generate deployment commands (with croc for large files)
    files_info = []
    init_commands = None
    plan = None
    croc_process = None
    if files:
        plan = prepare_files_with_croc(files, transfer_mode="container", config=cfg)
        if plan.errors:
            return [TextContent(type="text", text="Error preparing files:\n" + "\n".join(f"- {e}" for e in plan.errors))]
        # Combine croc init + inline commands for container target
        combined = []
        if plan.croc_init_commands:
            combined.append(plan.croc_init_commands)
        if plan.inline_commands:
            combined.append(plan.inline_commands)
        if combined:
            init_commands = "\n".join(combined)
        files_info = plan.files_info
    
    # Process download_files parameter
    dl_plan = None
    dl_process = None
    if download_files:
        dl_plan = prepare_download_with_croc(download_files, transfer_mode="container", config=cfg)
        if dl_plan.errors:
            return [TextContent(type="text", text="Error preparing downloads:\n" + "\n".join(f"- {e}" for e in dl_plan.errors))]
    
    effective_command = command or "echo 'Files deployed successfully'"
    
    try:
        # Start croc send locally if needed (must happen BEFORE Torque environment)
        if plan is not None and plan.needs_croc:
            try:
                croc_process = await execute_with_croc(plan)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file transfer: {str(e)}")]
        
        # Start croc receive locally if download is needed
        if dl_plan is not None and dl_plan.needs_download:
            try:
                dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)
            except Exception as e:
                return [TextContent(type="text", text=f"Error starting croc file download receiver: {str(e)}")]
        
        async with _connection_client(connection) as client:
            __cred_name, __cred_ctx = await _prepare_credential(arguments, cfg, client, forward=False)
            environment_id = await client.start_local_environment(
                command=effective_command,
                agent=agent,
                init_commands=init_commands,
                timeout=timeout,
                download_commands=dl_plan.download_commands if dl_plan else None,
                command_description=command_description,
                credential_name=__cred_name,
                credential_context=__cred_ctx,
            )

        # Track croc state for cleanup when execution completes
        async_state = {}
        if croc_process is not None:
            async_state["process"] = croc_process
            async_state["staging_dir"] = plan.croc_staging_dir if plan else ""
            croc_process = None  # Don't clean up in except block
        if dl_process is not None:
            async_state["dl_process"] = dl_process
            async_state["dl_plan"] = dl_plan
            dl_process = None  # Don't clean up in except block
        if async_state:
            _croc_async_state[environment_id] = async_state
        
        # Start background streaming of grain log to stderr
        _remember_async_connection(environment_id, dict(connection, profile=profile_name))
        _start_background_streamer(environment_id)
        
        env_url = _environment_url(connection, environment_id)
        agent_name = agent or cfg["default_agent"]
        
        files_summary = ""
        if files_info:
            files_summary = "\n**Files Queued:**\n" + "\n".join(f"- {f}" for f in files_info) + "\n"
        
        dl_info = ""
        if dl_plan is not None and dl_plan.files_info:
            dl_info = "\n**Downloads Queued:**\n" + "\n".join(f"- {f}" for f in dl_plan.files_info) + "\n"
        
        suggested_wait = _suggest_wait_time(effective_command)
        
        output_text = f"""Command started on agent `{agent_name}` (async)
{files_summary}{dl_info}
**Environment ID:** {environment_id}
**Environment:** {env_url}

Use `get_execution_status` with {_follow_up_args(environment_id, profile_name)} to check progress (suggested initial wait={suggested_wait}, adjust as needed).
Use `cancel_execution` with {_follow_up_args(environment_id, profile_name)} to abort if needed."""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        # Clean up croc on error (not tracked for async cleanup)
        await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")
        await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir if dl_plan else "")
        # A credential problem carries a message written for the caller (which space
        # allows it, why its type cannot be used) - pass it through verbatim.
        if isinstance(e, credentials_module.CredentialError):
            return [TextContent(type="text", text=f"Credential error: {e}")]
        return [TextContent(type="text", text=f"Error starting async command: {str(e)}")]


async def handle_get_execution_status(arguments: dict, config: dict = None,
                                      profile_name: Optional[str] = None):
    """Check status of an async execution.

    Polls the Torque the environment lives on: the given profile's, else the one the
    command was started with, else the default profile's.
    """
    environment_id = arguments.get("environment_id")
    wait_seconds = arguments.get("wait", 5)

    if not environment_id:
        return [TextContent(type="text", text="Error: environment_id is required.")]

    connection = _async_connection(environment_id, config, profile_name)
    cfg = connection["config"]
    follow_up = _follow_up_args(environment_id, connection["profile"])

    # Wait with early exit — check the background streamer's cached status every second.
    # The background streamer (started by the async handler) already polls the API and
    # streams grain log to stderr, so we just piggyback on its cached results.
    elapsed = 0.0
    while elapsed < wait_seconds:
        cached = _streamer_cache.get(environment_id)
        if cached and cached['status'] in _TERMINAL_STATUSES:
            break
        sleep_time = min(1.0, wait_seconds - elapsed)
        await asyncio.sleep(sleep_time)
        elapsed += sleep_time
    
    # Use cached env_data if available, otherwise fall back to a direct API call
    # (handles cases like server restart where no background streamer exists)
    cached = _streamer_cache.get(environment_id)
    
    try:
        if cached:
            env_data = cached['env_data']
            status = cached['status']
            raw_status = cached['raw_status']
        else:
            async with _connection_client(connection) as client:
                env_data = await client.get_environment_status(environment_id)
            details = env_data.get("details", {})
            raw_status = details.get("computed_status") or env_data.get("computed_status") or env_data.get("status", "unknown")
            status = raw_status.lower().replace(" ", "_")

        details = env_data.get("details", {})
        env_url = _environment_url(connection, environment_id)

        # Stop background streamer if terminal (it may already have stopped itself)
        if status in _TERMINAL_STATUSES:
            _stop_background_streamer(environment_id)
            _streamer_cache.pop(environment_id, None)
            _async_env_connections.pop(environment_id, None)
            # Clean up any croc send process/staging dir associated with this async execution
            croc_state = _croc_async_state.pop(environment_id, None)
            if croc_state:
                await cleanup_croc_resources(
                    croc_state.get("process"),
                    croc_state.get("staging_dir", ""),
                )
                # Finalize file downloads if any
                dl_process = croc_state.get("dl_process")
                dl_plan = croc_state.get("dl_plan")
                if dl_plan is not None and dl_plan.needs_download:
                    # The background streamer stops on terminal status and may
                    # have missed the tail of the log; refeed the full log so
                    # the watcher sees the final sentinels (idempotent) before
                    # the download's fate is decided.
                    try:
                        async with _connection_client(connection) as log_client:
                            final_log = await log_client.get_grain_log(environment_id) or ""
                        dl_plan.observe_output("\n" + final_log + "\n")
                    except Exception:
                        pass
                    dl_successes, dl_errors = await complete_download(dl_plan, dl_process)
                    # Store results for output formatting
                    _download_results[environment_id] = (
                        dl_successes, dl_errors, dl_plan.transfer_seconds)
                    await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir)
        
        # We need a client for extracting outputs, cleanup, and grain log fetching
        async with _connection_client(connection) as client:
            # Completed successfully
            if status in ("active", "success"):
                outputs = client._extract_outputs(env_data)
                command_output_b64 = outputs.get("command_output", "")
                exit_code_str = outputs.get("exit_code", "0")
                execution_duration_ms_str = outputs.get("execution_duration_ms", "")
                
                try:
                    command_output = base64.b64decode(command_output_b64).decode('utf-8') if command_output_b64 else ""
                except Exception:
                    command_output = command_output_b64
                
                try:
                    exit_code = int(exit_code_str)
                except (ValueError, TypeError):
                    exit_code = 0
                
                # Duration
                try:
                    duration = int(execution_duration_ms_str) / 1000.0 if execution_duration_ms_str else None
                except (ValueError, TypeError):
                    duration = None
                duration_str = f"{int(duration // 60)}m {duration % 60:.1f}s" if duration and duration >= 60 else f"{duration:.1f}s" if duration else "N/A"
                
                output_block = format_code_block(command_output)
                status_msg = "Command completed." if exit_code == 0 else "Command failed."
                
                # Include download results if any
                dl_summary = ""
                dl_result = _download_results.pop(environment_id, None)
                if dl_result:
                    dl_summary = format_download_summary(*dl_result)
                
                output_text = f"""{status_msg}

**Status:** {"COMPLETED" if exit_code == 0 else "FAILED"}
**Exit Code:** {exit_code}
{dl_summary}
**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
                
                # Tip for fast commands
                if duration is not None and duration < 10:
                    output_text += "\n\n**TIP:** This command completed in under 10 seconds. For quick commands like this, `run_on_tunneled_ssh` or `run_on_tunneled_persistent_container` provides simpler one-shot execution without polling."
                
                # Auto-cleanup
                try:
                    await client.end_environment(environment_id)
                    if cfg["auto_delete_environments"]:
                        await client.delete_environment(environment_id)
                except Exception:
                    pass
                
                return [TextContent(type="text", text=output_text)]
            
            # Ended with outputs (may be success or failure)
            elif status in ("ended", "inactive"):
                outputs = client._extract_outputs(env_data)
                command_output_b64 = outputs.get("command_output", "")
                exit_code_str = outputs.get("exit_code", "")
                execution_duration_ms_str = outputs.get("execution_duration_ms", "")
                
                if command_output_b64 or exit_code_str:
                    try:
                        command_output = base64.b64decode(command_output_b64).decode('utf-8') if command_output_b64 else ""
                    except Exception:
                        command_output = command_output_b64
                    
                    try:
                        exit_code = int(exit_code_str) if exit_code_str else 0
                    except (ValueError, TypeError):
                        exit_code = 0
                    
                    try:
                        duration = int(execution_duration_ms_str) / 1000.0 if execution_duration_ms_str else None
                    except (ValueError, TypeError):
                        duration = None
                    duration_str = f"{int(duration // 60)}m {duration % 60:.1f}s" if duration and duration >= 60 else f"{duration:.1f}s" if duration else "N/A"
                    
                    output_block = format_code_block(command_output)
                    status_msg = "Command completed." if exit_code == 0 else "Command failed."
                    output_text = f"""{status_msg}

**Status:** {"COMPLETED" if exit_code == 0 else "FAILED"}
**Exit Code:** {exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
                    
                    # Auto-cleanup
                    if cfg["auto_delete_environments"]:
                        try:
                            await client.delete_environment(environment_id)
                        except Exception:
                            pass
                    
                    return [TextContent(type="text", text=output_text)]
                else:
                    output_text = f"""Command ended without output.

**Status:** ENDED
**Environment:** {env_url}

This may indicate a deployment failure. Check the environment URL for details."""
                    return [TextContent(type="text", text=output_text)]
            
            # Error states
            elif status in ("active_with_error", "ended_with_error", "error", "failed", "terminating_failed"):
                state_errors = details.get("state", {}).get("errors", [])
                error_messages = []
                for err in state_errors:
                    if isinstance(err, dict) and err.get("message"):
                        error_messages.append(err["message"])
                    elif isinstance(err, str):
                        error_messages.append(err)
                
                if not error_messages:
                    root_errors = env_data.get("errors", [])
                    error_messages = [str(e) for e in root_errors if e]
                
                error_msg = "; ".join(error_messages) if error_messages else f"Environment failed with status: {raw_status}"
                
                output_text = f"""Command failed.

**Status:** FAILED
**Error:** {error_msg}

**Environment:** {env_url}"""
                
                # Try to get partial output
                try:
                    grain_log = await client.get_grain_log(environment_id)
                    output_text += format_log_section("Grain Execution Log (tail)", grain_log, 2000)
                except Exception:
                    pass
                
                return [TextContent(type="text", text=output_text)]
            
            # Cancelled/released
            elif status in ("released", "cancelled", "terminating", "force_terminated"):
                grain_log = ""
                try:
                    grain_log = await client.get_grain_log(environment_id) or ""
                except Exception:
                    pass

                output_text = f"""Execution was cancelled.

**Status:** CANCELLED
**Environment:** {env_url}"""

                output_text += format_log_section("Output before cancellation", grain_log)

                # Auto-cleanup
                if cfg["auto_delete_environments"]:
                    try:
                        await client.delete_environment(environment_id)
                    except Exception:
                        pass
                
                return [TextContent(type="text", text=output_text)]
            
            # Still running - get partial output
            else:
                grain_log = ""
                try:
                    grain_log = await client.get_grain_log(environment_id) or ""
                except Exception:
                    pass

                output_text = f"""Command is still running.

**Status:** RUNNING
**Environment:** {env_url}"""

                output_text += format_log_section("Partial Output (so far)", grain_log)

                output_text += f"""

Call `get_execution_status` again with {follow_up} and wait=10 to check progress."""
                
                return [TextContent(type="text", text=output_text)]
    
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return [TextContent(type="text", text=f"Error: Environment {environment_id} not found. It may have been deleted or the ID is incorrect.")]
        return [TextContent(type="text", text=f"Error checking execution status: {str(e)}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error checking execution status: {str(e)}")]


async def handle_cancel_execution(arguments: dict, config: dict = None,
                                  profile_name: Optional[str] = None):
    """Cancel a running async execution, on the Torque it lives on (see
    handle_get_execution_status)."""
    environment_id = arguments.get("environment_id")

    if not environment_id:
        return [TextContent(type="text", text="Error: environment_id is required.")]

    connection = _async_connection(environment_id, config, profile_name)
    cfg = connection["config"]

    # Stop background streamer for this environment
    _stop_background_streamer(environment_id)
    _streamer_cache.pop(environment_id, None)
    _async_env_connections.pop(environment_id, None)

    # Clean up any croc send process/staging dir associated with this execution
    croc_state = _croc_async_state.pop(environment_id, None)
    if croc_state:
        await cleanup_croc_resources(
            croc_state.get("process"),
            croc_state.get("staging_dir", ""),
        )
        # Clean up download resources too
        dl_process = croc_state.get("dl_process")
        dl_plan = croc_state.get("dl_plan")
        await cleanup_download_resources(
            dl_process,
            dl_plan.croc_receive_dir if dl_plan else "",
        )
    _download_results.pop(environment_id, None)
    
    try:
        async with _connection_client(connection) as client:
            # First check current status
            try:
                env_data = await client.get_environment_status(environment_id)
                details = env_data.get("details", {})
                raw_status = details.get("computed_status") or env_data.get("computed_status") or env_data.get("status", "unknown")
                status = raw_status.lower().replace(" ", "_")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    return [TextContent(type="text", text=f"Environment {environment_id} not found. It may have already completed or been deleted.")]
                raise
            
            env_url = _environment_url(connection, environment_id)

            # Already fully terminated - nothing to cancel
            if status in ("ended", "inactive", "terminated", "released", "cancelled"):
                # Still respect auto-delete
                if cfg["auto_delete_environments"]:
                    try:
                        await client.delete_environment(environment_id)
                    except Exception:
                        pass
                return [TextContent(type="text", text=f"""Environment {environment_id} has already ended (status: {raw_status}). Nothing to cancel.

**Environment:** {env_url}""")]
            
            # Transitional states (Launching, Deploying, etc.) - use release endpoint
            # since end_environment returns 409 on these states
            transitional_states = ("launching", "deploying", "preparing", "provisioning")
            if status in transitional_states:
                await client.release_environment(environment_id, force=True)
                action_msg = "Execution cancelled (environment was still deploying)."
            else:
                # Active, running, error states, etc. - use regular end
                await client.end_environment(environment_id, force=True)
                action_msg = "Execution cancelled."
            
            # Auto-delete if configured
            if cfg["auto_delete_environments"]:
                try:
                    await client.delete_environment(environment_id)
                    action_msg += " Environment deleted."
                except Exception:
                    pass
            
            return [TextContent(type="text", text=f"""{action_msg}

**Environment ID:** {environment_id}
**Previous Status:** {raw_status}
**Environment:** {env_url}""")]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error cancelling execution: {str(e)}")]


# --- Remote-to-remote transfer ----------------------------------------------------------
# See docs/design-remote-to-remote-transfer.md. The tool call launches the sender, waits
# for its READY (the receiver may only connect once the sender's relay room exists),
# launches the receiver with the sender's manifest, and returns both environment ids.
# From then on get_transfer_status / cancel_transfer work from those ids alone.

TRANSFER_DEFAULT_TIMEOUT_SECONDS = 21600
# The blocking first phase (install croc, copy from the source, hash) never waits longer
# than this, whatever the transfer's own timeout.
TRANSFER_STAGE_TIMEOUT_SECONDS = 3600
TRANSFER_POLL_SECONDS = 3
# Consecutive Torque API failures tolerated while waiting for the sender.
TRANSFER_POLL_ERRORS_TOLERATED = 5
# Environments are created with an 8h lifetime (TorqueClient.start_environment). A
# payload whose transfer could take longer extends both, once its size is known.
TRANSFER_DEFAULT_LIFETIME_SECONDS = 8 * 3600


@dataclass
class _TransferEndpoint:
    """One side of a transfer, fully resolved: the machine and how to reach it."""
    role: str                      # "sender" | "receiver"
    profile: Optional[str]
    cfg: dict
    connection: dict
    host: str
    user: str
    private_key: str
    password: str
    agent: str
    container_env_id: Optional[str] = None   # persistent_container endpoints
    label: str = ""

    @property
    def environment_kind(self) -> str:
        return "persistent-command" if self.container_env_id else "ssh"

    def ssh(self) -> dict:
        return {"target_ip": self.host, "ssh_user": self.user,
                "ssh_private_key": self.private_key, "ssh_password": self.password}


async def _resolve_transfer_endpoint(spec: dict, role: str) -> _TransferEndpoint:
    """Resolve one endpoint exactly as a run_* tool call resolves its arguments.

    The endpoint object is treated as that call's arguments: its `profile` through
    _resolve_call_profile (each side can name another profile, even another Torque), then
    _resolve_agent, _resolve_connection and, for an SSH endpoint, _resolve_ssh_target -
    the same functions the run_* tools use. Only `type` and `environment_id` are the
    transfer's own (see the persistent-container branch).

    Raises ValueError with a message for the caller.
    """
    if not isinstance(spec, dict):
        raise ValueError(f"{role} must be an object")

    def failed(error: str) -> ValueError:
        return ValueError(f"{role}: {error.removeprefix('Error: ')}")

    args, cfg, profile, error = await _resolve_call_profile(spec)
    if error:
        raise failed(error)
    agent = _resolve_agent(args, cfg)
    connection = _resolve_connection(args, cfg, profile)
    error = _missing_torque_config(connection)
    if error:
        raise failed(error)

    kind = args.get("type") or "ssh"
    if kind == "ssh":
        target, error = _resolve_ssh_target(args, cfg)
        if error:
            raise failed(error)
        return _TransferEndpoint(role, profile, cfg, connection, target["host"], target["user"],
                                 target["private_key"], target["password"] or "", agent,
                                 label=f"{target['user']}@{target['host']}")

    if kind == "persistent_container":
        # Not the persistent-container tools' _ensure_persistent_container: that one uses
        # the default container when no environment_id is given, and creates a NEW one
        # when the given container is gone. A new, empty container is never what a
        # transfer means - as a source it has nothing to send, as a destination the files
        # would land where nobody looks. So the container must be named and running.
        env_id = args.get("environment_id")
        if not env_id:
            raise ValueError(f"{role}: environment_id of the persistent container is required")
        info = await _attach_persistent_container(env_id, connection)
        return _TransferEndpoint(role, profile, cfg, connection, info["container_ip"], "root",
                                 info["private_key"], "", agent,
                                 container_env_id=env_id, label=f"persistent container {env_id}")

    raise ValueError(f"{role}: unknown type {kind!r} (expected 'ssh' or 'persistent_container')")


async def _attach_persistent_container(environment_id: str, connection: dict) -> dict:
    """Connection details of an EXISTING, running persistent container.

    Unlike _ensure_persistent_container this never creates one: a transfer endpoint
    that is gone is an error, not a reason to start an empty container.
    """
    async with _connection_client(connection) as client:
        env_data = await client.get_environment_status(environment_id)
        state = env_data.get("details", {}).get("state", {}).get("current_state", "")
        if state not in ("deploying", "launching"):
            raise ValueError(f"persistent container {environment_id} is not running (state: {state or 'unknown'})")
        cached = _persistent_containers.get(environment_id)
        if cached:
            return dict(cached)
        info = await client.get_persistent_container_info(environment_id)
    return {"container_ip": info["container_ip"], "private_key": info["private_key"]}


def _same_place(a: _TransferEndpoint, b: _TransferEndpoint) -> bool:
    """Both endpoints run their environments on the same Torque agent."""
    return (a.connection["torque_url"].rstrip("/") == b.connection["torque_url"].rstrip("/")
            and a.connection["torque_space"] == b.connection["torque_space"]
            and (a.agent or "") == (b.agent or ""))


def _environment_status(env_data: dict) -> tuple[str, str]:
    """(normalized status, raw status) of an environment, as the status tools use them."""
    details = env_data.get("details", {})
    raw = details.get("computed_status") or env_data.get("computed_status") or env_data.get("status", "unknown")
    return raw.lower().replace(" ", "_"), raw


def _environment_errors(env_data: dict) -> str:
    """Torque's own error messages for an environment, joined ("" when none).

    When the grain never starts (e.g. "runner is in error state") the log is empty, and
    these are the only explanation there is.
    """
    errors = env_data.get("details", {}).get("state", {}).get("errors") or []
    messages = [e.get("message") if isinstance(e, dict) else e for e in errors]
    return "; ".join(str(m) for m in messages if m)


async def _terminate_environment(connection: dict, environment_id: str) -> str:
    """End an environment in whatever state it is in. Returns what was done, for humans."""
    async with _connection_client(connection) as client:
        try:
            status, raw = _environment_status(await client.get_environment_status(environment_id))
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return "not found"
            raise
        if status in ("ended", "inactive", "terminated", "released", "cancelled"):
            return f"already ended ({raw})"
        if status in ("launching", "deploying", "preparing", "provisioning"):
            # end_environment returns 409 in these states
            await client.release_environment(environment_id, force=True)
        else:
            await client.end_environment(environment_id, force=True)
        if connection["config"].get("auto_delete_environments"):
            try:
                await client.delete_environment(environment_id)
            except Exception:
                pass
        return f"ended (was {raw})"


async def _terminate_quietly(connection: dict, environment_id: str) -> None:
    try:
        await _terminate_environment(connection, environment_id)
    except Exception as e:
        print(f"[torque-tunnel] Could not end environment {environment_id}: {e}", file=sys.stderr, flush=True)
    _async_env_connections.pop(environment_id, None)


def _transfer_follow_up(sender_id: str, receiver_id: str,
                        sender_profile: Optional[str], receiver_profile: Optional[str]) -> str:
    text = f'sender_environment_id="{sender_id}", receiver_environment_id="{receiver_id}"'
    if sender_profile:
        text += f', sender_profile="{sender_profile}"'
    if receiver_profile:
        text += f', receiver_profile="{receiver_profile}"'
    return text


def _validate_transfer_files(files) -> tuple[list[dict], list[str]]:
    if not isinstance(files, list) or not files:
        return [], ["'files' must be a non-empty list"]
    out, errors = [], []
    for i, f in enumerate(files):
        if not isinstance(f, dict):
            errors.append(f"File {i + 1}: must be an object")
            continue
        src, dest, mode = f.get("source_path"), f.get("destination_path"), f.get("mode")
        if not src or not isinstance(src, str):
            errors.append(f"File {i + 1}: missing 'source_path'")
        if not dest or not isinstance(dest, str):
            errors.append(f"File {i + 1}: missing 'destination_path'")
        if mode and not croc_manager._validate_mode(str(mode)):
            errors.append(f"File {i + 1}: invalid mode {mode!r} (expected e.g. '644' or '0755')")
        if src and dest:
            out.append({"source_path": src, "destination_path": dest,
                        "mode": str(mode) if mode else None,
                        "croc_filename": remote_transfer.croc_filename(i, src)})
    return out, errors


async def _wait_for_sender_ready(connection: dict, environment_id: str, deadline: float):
    """Poll the sender until its relay room exists. Returns (report, problem)."""
    errors = 0
    report = remote_transfer.SenderReport()
    while True:
        try:
            async with _connection_client(connection) as client:
                env_data = await client.get_environment_status(environment_id)
                status, raw = _environment_status(env_data)
                log = await client.get_grain_log(environment_id) or ""
            errors = 0
        except Exception as e:
            errors += 1
            if errors > TRANSFER_POLL_ERRORS_TOLERATED:
                return report, f"could not read the sending environment's status: {e}"
            await asyncio.sleep(TRANSFER_POLL_SECONDS)
            continue
        report = remote_transfer.parse_sender_log(log)
        if report.failure:
            return report, "the sender failed: " + remote_transfer.describe_failure(report.failure)
        if report.ready:
            return report, ""
        if status in _TERMINAL_STATUSES:
            torque_errors = _environment_errors(env_data)
            return report, (f"the sending environment ended ({raw}) before its croc sender was ready"
                            + (f" - Torque: {torque_errors}" if torque_errors else "")
                            + format_log_section("Sender log (tail)", log, 1500))
        if time.monotonic() > deadline:
            return report, "timed out waiting for the sender to copy, hash and register its files"
        await asyncio.sleep(TRANSFER_POLL_SECONDS)


async def _extend_for_payload(endpoints: list, total_bytes: int) -> None:
    """Lengthen the environments' lifetime when the payload could outlast it."""
    needed = croc_manager.relay_receive_timeout(total_bytes) + 3600
    if needed <= TRANSFER_DEFAULT_LIFETIME_SECONDS - 3600:
        return
    end = datetime.now(timezone.utc) + timedelta(seconds=needed)
    for connection, environment_id in endpoints:
        try:
            async with _connection_client(connection) as client:
                await client.set_scheduled_end_time(environment_id, end)
        except Exception as e:
            print(f"[torque-tunnel] Could not extend environment {environment_id}: {e}",
                  file=sys.stderr, flush=True)


def _transfer_files_summary(files: list[dict], sizes: Optional[dict] = None) -> str:
    lines = []
    for f in files:
        size = (sizes or {}).get(f["croc_filename"])
        shown = f" ({size:,} bytes)" if isinstance(size, int) else ""
        lines.append(f"- {f['source_path']} → {f['destination_path']}{shown}")
    return "\n".join(lines)


@dataclass
class _TransferHandle:
    """The two environments of a started transfer (one, twice, for a direct copy)."""
    sender_id: str
    receiver_id: str
    sender_connection: dict
    receiver_connection: dict


async def handle_transfer_files_between_tunneled_hosts_async(arguments: dict):
    """Start a transfer between two machines torque-tunnel reaches but that cannot reach
    each other. Returns once both environments exist (see the section comment)."""
    _, text = await _start_transfer(arguments)
    return [TextContent(type="text", text=text)]


async def _start_transfer(arguments: dict) -> tuple[Optional[_TransferHandle], str]:
    """Returns (handle, text for the caller); the handle is None when nothing is running."""
    description = arguments.get("command_description")
    if not description:
        return None, "Error: command_description is required."
    files, errors = _validate_transfer_files(arguments.get("files"))
    if errors:
        return None, "Error in files:\n" + "\n".join(f"- {e}" for e in errors)
    try:
        source = await _resolve_transfer_endpoint(arguments.get("sender") or {}, "sender")
        destination = await _resolve_transfer_endpoint(arguments.get("receiver") or {}, "receiver")
    except Exception as e:
        return None, f"Error: {e}"
    if _same_place(source, destination) and source.host == destination.host:
        return None, (
            f"Error: sender and receiver are the same machine ({source.label} via agent "
            f"{source.agent}). Use a command (cp/mv) on it instead, or check that both 'host' "
            f"values were given.")

    timeout = int(arguments.get("timeout") or TRANSFER_DEFAULT_TIMEOUT_SECONDS)
    if _same_place(source, destination):
        return await _start_direct_copy(description, files, source, destination, timeout)
    return await _start_croc_transfer(description, files, source, destination, timeout)


async def _start_direct_copy(description, files, source, destination, timeout):
    """Both endpoints behind one agent: one environment copies ssh to ssh, no croc."""
    commands = croc_manager.generate_direct_copy_commands(files, source.ssh(), destination.ssh())
    try:
        async with _connection_client(destination.connection) as client:
            environment_id = await client.start_environment(
                target_ip=destination.host, ssh_user=destination.user,
                ssh_private_key=destination.private_key, ssh_password=destination.password or None,
                command="true", agent=destination.agent, timeout=timeout,
                container_pre_commands=commands,
                command_description=f"{description} (copy)",
                environment_kind=destination.environment_kind,
                parent_env_id=destination.container_env_id,
            )
    except Exception as e:
        return None, f"Error starting the copy: {e}"
    _remember_async_connection(environment_id, destination.connection)
    handle = _TransferHandle(environment_id, environment_id, destination.connection, destination.connection)
    follow_up = _transfer_follow_up(environment_id, environment_id, destination.profile, destination.profile)
    return handle, f"""Transfer started (async): {source.label} → {destination.label}
Both machines are behind agent `{destination.agent}`, so one environment copies directly (no croc, no relay).

**Files:**
{_transfer_files_summary(files)}

**Environment:** {_environment_url(destination.connection, environment_id)}

Use `get_transfer_status` with {follow_up} to check progress (suggested initial wait=30).
Use `cancel_transfer` with the same arguments to abort."""


async def _start_croc_transfer(description, files, source, destination, timeout):
    relay = remote_transfer.choose_relay(_croc_relay_settings(source.cfg),
                                         _croc_relay_settings(destination.cfg))
    code = croc_manager.generate_croc_code()
    sender_commands = (
        croc_manager.generate_remote_croc_install_script(failure_sentinel=croc_manager.CROC_SENTINEL_FAILED)
        + "\n" + croc_manager.generate_croc_relay_send_commands(
            code, [{"source_path": f["source_path"], "croc_filename": f["croc_filename"]} for f in files],
            relay=relay["relay"], relay_password=relay["relay_password"],
            transfers=relay["transfers"], **source.ssh())
    )
    try:
        async with _connection_client(source.connection) as client:
            sender_id = await client.start_environment(
                target_ip=source.host, ssh_user=source.user,
                ssh_private_key=source.private_key, ssh_password=source.password or None,
                command="true", agent=source.agent, timeout=timeout,
                download_commands=sender_commands,
                command_description=f"{description} (send)",
                environment_kind=source.environment_kind,
                parent_env_id=source.container_env_id,
            )
    except Exception as e:
        return None, f"Error starting the sending environment: {e}"
    _remember_async_connection(sender_id, source.connection)
    sender_url = _environment_url(source.connection, sender_id)
    print(f"[torque-tunnel] Transfer: sender {sender_id} started; waiting for it to stage and register...",
          file=sys.stderr, flush=True)

    deadline = time.monotonic() + min(timeout, TRANSFER_STAGE_TIMEOUT_SECONDS)
    try:
        report, problem = await _wait_for_sender_ready(source.connection, sender_id, deadline)
    except asyncio.CancelledError:
        # The call was abandoned (client gone, Ctrl+C): nobody will ever launch the
        # receiver, so the sender must not be left waiting out its croc timeout.
        await asyncio.shield(_terminate_quietly(source.connection, sender_id))
        raise
    manifest = []
    if not problem:
        manifest, manifest_errors = remote_transfer.build_manifest(files, report)
        problem = "; ".join(manifest_errors)
    if problem:
        await _terminate_quietly(source.connection, sender_id)
        return None, f"""Transfer failed before any data was sent: {problem}

**Sender environment:** {sender_url}"""

    receiver_commands = (
        croc_manager.generate_remote_croc_install_script(failure_sentinel=croc_manager.CROC_RX_SENTINEL_FAILED)
        + "\n" + croc_manager.generate_croc_relay_receive_commands(
            code, manifest, relay=relay["relay"], relay_password=relay["relay_password"],
            **destination.ssh())
    )
    try:
        async with _connection_client(destination.connection) as client:
            receiver_id = await client.start_environment(
                target_ip=destination.host, ssh_user=destination.user,
                ssh_private_key=destination.private_key, ssh_password=destination.password or None,
                command="true", agent=destination.agent, timeout=timeout,
                container_pre_commands=receiver_commands,
                command_description=f"{description} (receive)",
                environment_kind=destination.environment_kind,
                parent_env_id=destination.container_env_id,
            )
    except Exception as e:
        await _terminate_quietly(source.connection, sender_id)
        return None, f"Error starting the receiving environment: {e} (the sender was ended)\n\n**Sender environment:** {sender_url}"
    _remember_async_connection(receiver_id, destination.connection)
    total = sum(m["size"] for m in manifest)
    await _extend_for_payload([(source.connection, sender_id), (destination.connection, receiver_id)], total)

    relay_note = ""
    if relay["relays_differ"]:
        relay_note = (f"\nNote: the two profiles name different croc relays; both sides use the "
                      f"source's ({croc_manager.effective_relay(relay['relay'])}).\n")
    follow_up = _transfer_follow_up(sender_id, receiver_id, source.profile, destination.profile)
    handle = _TransferHandle(sender_id, receiver_id, source.connection, destination.connection)
    return handle, f"""Transfer started (async): {source.label} → {destination.label}
The source side copied and hashed the files and is waiting for the receiver.
{relay_note}
**Files:**
{_transfer_files_summary(files, report.sizes)}

**Sender environment:** {sender_url}
**Receiver environment:** {_environment_url(destination.connection, receiver_id)}

Use `get_transfer_status` with {follow_up} to check progress (suggested initial wait=30).
Use `cancel_transfer` with the same arguments to abort."""


def _transfer_connections(arguments: dict) -> tuple[dict, dict]:
    """The sender's and receiver's connections: given profile, else remembered, else default."""
    out = []
    for id_key, profile_key in (("sender_environment_id", "sender_profile"),
                                ("receiver_environment_id", "receiver_profile")):
        profile = arguments.get(profile_key) or None
        cfg = _config_for_profile(profile) if profile else None
        out.append(_async_connection(arguments[id_key], cfg, profile))
    return out[0], out[1]


async def _read_environment(connection: dict, environment_id: str):
    """(status, raw status, env_data, log) of one environment; log is None if unreadable."""
    async with _connection_client(connection) as client:
        env_data = await client.get_environment_status(environment_id)
        status, raw = _environment_status(env_data)
        log = await client.get_grain_log(environment_id)
    return status, raw, env_data, log


async def handle_get_transfer_status(arguments: dict):
    """Status of a transfer, from its two environment ids alone (no state kept here)."""
    sender_id = arguments.get("sender_environment_id")
    receiver_id = arguments.get("receiver_environment_id")
    if not sender_id or not receiver_id:
        return [TextContent(type="text", text="Error: sender_environment_id and receiver_environment_id are required.")]
    try:
        sender_conn, receiver_conn = _transfer_connections(arguments)
    except ValueError as e:
        return [TextContent(type="text", text=f"Error: {e}")]
    wait_seconds = max(0, min(int(arguments.get("wait", 5) or 0), 300))
    handle = _TransferHandle(sender_id, receiver_id, sender_conn, receiver_conn)
    _, text, _ = await _check_transfer(handle, wait_seconds)
    return [TextContent(type="text", text=text)]


async def _check_transfer(handle: _TransferHandle, wait_seconds: float):
    """Poll a transfer for up to ``wait_seconds`` (returning early once it is finished),
    end its environments if it is, and describe it.

    Returns (PairState, text, ReceiverReport), or (None, error text, None).
    """
    sender_id, receiver_id = handle.sender_id, handle.receiver_id
    sender_conn, receiver_conn = handle.sender_connection, handle.receiver_connection
    direct = sender_id == receiver_id
    deadline = time.monotonic() + wait_seconds

    while True:
        try:
            r_status, r_raw, r_data, r_log = await _read_environment(receiver_conn, receiver_id)
            if direct:
                s_status, s_raw, s_data, s_log = r_status, r_raw, r_data, r_log
            else:
                s_status, s_raw, s_data, s_log = await _read_environment(sender_conn, sender_id)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None, "Error: environment not found. Check both ids (and the profiles, if the transfer used any).", None
            return None, f"Error checking transfer status: {e}", None
        except Exception as e:
            return None, f"Error checking transfer status: {e}", None

        receiver = remote_transfer.parse_receiver_log(r_log or "")
        sender = None if direct else remote_transfer.parse_sender_log(s_log or "")
        state = remote_transfer.evaluate_pair(
            receiver, r_raw, r_status in _TERMINAL_STATUSES,
            sender, s_raw, s_status in _TERMINAL_STATUSES)
        # A log that could not be read is not evidence the transfer failed.
        unreadable = r_log is None or (not direct and s_log is None)
        if state.status == "FAILED" and unreadable and not (receiver.failure or (sender and sender.failure)):
            state = remote_transfer.PairState("RUNNING", "an environment's log could not be read this time")
        if state.status != "RUNNING" or time.monotonic() >= deadline:
            break
        await asyncio.sleep(min(TRANSFER_POLL_SECONDS, max(0.0, deadline - time.monotonic())))

    if state.status == "FAILED":
        # An environment that ended without reporting may never have run at all; then
        # Torque's own errors are the only explanation.
        extra = [f"{side} environment: {msg}" for side, msg in (
            ("receiving", _environment_errors(r_data)),
            ("sending", "" if direct else _environment_errors(s_data))) if msg]
        if extra:
            state.reason = "; ".join([state.reason] + extra) if state.reason else "; ".join(extra)

    actions = []
    if state.end_sender and not direct:
        actions.append(("sender", sender_conn, sender_id))
    if state.end_receiver:
        actions.append(("receiver", receiver_conn, receiver_id))
    for _, conn, env_id in actions:
        await _terminate_quietly(conn, env_id)

    lines = [f"**Status:** {state.status}"]
    if state.reason:
        lines.append(f"**Reason:** {state.reason}")
    if receiver.placed:
        lines.append("\n**Files placed on the destination:**")
        lines += [f"- {p}" for p in receiver.placed]
    if state.status == "RUNNING":
        if sender is not None and not sender.done:
            lines.append("\n**Sender:** sending" if sender.ready else "\n**Sender:** preparing")
        elif sender is not None:
            lines.append("\n**Sender:** finished sending")
        if receiver.progress:
            lines.append(f"**Progress:** {receiver.progress}")
    if state.status == "FAILED":
        tail_log = s_log if (sender is not None and sender.failure and not receiver.failure) else r_log
        tail_section = format_log_section("Log (tail)", tail_log, 1500)
        if tail_section:
            lines.append("\n" + tail_section.lstrip("\n"))
    if direct:
        lines.append(f"\n**Environment:** {_environment_url(receiver_conn, receiver_id)}")
    else:
        lines.append(f"\n**Sender environment:** {_environment_url(sender_conn, sender_id)} ({s_raw})")
        lines.append(f"**Receiver environment:** {_environment_url(receiver_conn, receiver_id)} ({r_raw})")
    if state.status == "RUNNING":
        follow_up = _transfer_follow_up(sender_id, receiver_id, sender_conn["profile"], receiver_conn["profile"])
        lines.append(f"\nCall `get_transfer_status` again with {follow_up} and wait=30 to check progress.")
    return state, "\n".join(lines), receiver


async def handle_cancel_transfer(arguments: dict):
    """End both environments of a transfer (one, for a direct copy)."""
    sender_id = arguments.get("sender_environment_id")
    receiver_id = arguments.get("receiver_environment_id")
    if not sender_id or not receiver_id:
        return [TextContent(type="text", text="Error: sender_environment_id and receiver_environment_id are required.")]
    try:
        sender_conn, receiver_conn = _transfer_connections(arguments)
    except ValueError as e:
        return [TextContent(type="text", text=f"Error: {e}")]
    targets = [("Receiver", receiver_conn, receiver_id)]
    if sender_id != receiver_id:
        targets.insert(0, ("Sender", sender_conn, sender_id))
    lines = ["Transfer cancelled."]
    for label, conn, env_id in targets:
        try:
            outcome = await _terminate_environment(conn, env_id)
        except Exception as e:
            outcome = f"could not be ended: {e}"
        _async_env_connections.pop(env_id, None)
        lines.append(f"**{label}:** {_environment_url(conn, env_id)} - {outcome}")
    return [TextContent(type="text", text="\n".join(lines))]


def _parse_transfer_files(specs) -> list[dict]:
    """``--file SOURCE:DESTINATION[:MODE]`` (both are remote POSIX paths)."""
    files = []
    for spec in specs or []:
        parts = spec.split(":")
        mode = None
        if len(parts) == 3 and croc_manager._validate_mode(parts[2]):
            mode = parts.pop()
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"Invalid --file {spec!r}: use SOURCE_PATH:DESTINATION_PATH[:MODE]")
        entry = {"source_path": parts[0], "destination_path": parts[1]}
        if mode:
            entry["mode"] = mode
        files.append(entry)
    return files


def _cli_transfer_endpoint(args, prefix: str) -> dict:
    """An endpoint spec from the --from-* / --to-* options."""
    container = getattr(args, f"{prefix}_persistent_container", None)
    spec = ({"type": "persistent_container", "environment_id": container} if container
            else {"type": "ssh"})
    for option, key in (("host", "host"), ("user", "user"), ("key", "private_key"),
                        ("password", "password"), ("profile", "profile"), ("agent", "torque_agent")):
        value = getattr(args, f"{prefix}_{option}", None)
        if value:
            spec[key] = value
    return spec


async def _cli_transfer(args) -> None:
    """``torque-tunnel transfer``: the same transfer as the MCP tool, followed in the
    foreground until it finishes. Exits non-zero unless every file was placed."""
    import json as json_module
    try:
        files = _parse_transfer_files(getattr(args, "file", None))
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    arguments = {
        "command_description": getattr(args, "description", None) or "file transfer",
        "sender": _cli_transfer_endpoint(args, "from"),
        "receiver": _cli_transfer_endpoint(args, "to"),
        "files": files,
        "timeout": getattr(args, "timeout", None),
    }
    started = time.monotonic()
    handle, text = await _start_transfer(arguments)
    if handle is None:
        print(text, file=sys.stderr)
        sys.exit(1)
    print(text.split("\n\nUse `get_transfer_status`")[0], file=sys.stderr, flush=True)

    shown = ""
    while True:
        state, text, receiver = await _check_transfer(handle, 30)
        if state is None:
            print(text, file=sys.stderr)
            sys.exit(1)
        if receiver.progress and receiver.progress != shown:
            print(receiver.progress, file=sys.stderr, flush=True)
            shown = receiver.progress
        if state.status != "RUNNING":
            break
    elapsed = time.monotonic() - started

    if getattr(args, "json", False):
        print(json_module.dumps({
            "status": state.status,
            "reason": state.reason,
            "placed": receiver.placed,
            "path": "direct" if handle.sender_id == handle.receiver_id else "croc",
            "sender_environment_id": handle.sender_id,
            "receiver_environment_id": handle.receiver_id,
            "transfer_seconds": round(elapsed, 1),
        }))
    else:
        for p in receiver.placed:
            print(f"Placed: {p}", file=sys.stderr)
        if state.status != "COMPLETED":
            print(f"TRANSFER FAILED: {state.reason}", file=sys.stderr)
        print(f"Transfer time: {_format_seconds(elapsed)}", file=sys.stderr)
    sys.exit(0 if state.status == "COMPLETED" else 1)


def _suggest_wait_time(command: str) -> int:
    """Suggest a wait time based on command content."""
    command_lower = command.lower()
    # Long-running patterns
    long_patterns = ['install', 'upgrade', 'update', 'build', 'make', 'compile', 'download',
                     'pip install', 'apt', 'yum', 'dnf', 'npm install', 'cargo build',
                     'docker pull', 'docker build', 'git clone', 'wget', 'curl.*-o',
                     'ansible', 'terraform', 'kubectl apply']
    for pattern in long_patterns:
        if pattern in command_lower:
            return 30
    # Medium patterns
    medium_patterns = ['sleep', 'test', 'pytest', 'mvn', 'gradle']
    for pattern in medium_patterns:
        if pattern in command_lower:
            return 15
    return 10


async def cli_dispatch(args):
    """Dispatch CLI commands to appropriate handlers."""
    import json as json_module
    
    show_all = raw_log.stream_preamble()
    torque_url = _config.get('torque_url', '')
    torque_space = _config.get('torque_space', '')

    def cli_log_callback(content: str):
        """Simple callback that prints to stderr for CLI streaming."""
        # State for tracking streaming progress
        # - found: whether we've passed the execution marker (--raw-log always skips filtering)
        # - first_line_shown: whether we've printed the "Running on" header line
        # - buffer: accumulated data for finding markers
        state = {'found': show_all, 'first_line_shown': show_all, 'buffer': ''}
        
        async def _stream(data: str, environment_id: str = ""):
            if state['found']:
                # Already past marker - print everything
                print(data, file=sys.stderr, end='', flush=True)
                return
            
            # Buffer data to handle markers split across chunks
            state['buffer'] += data
            
            # Show first line with environment info if not yet shown
            if not state['first_line_shown']:
                match = _FIRST_LINE_PATTERN.search(state['buffer'])
                if match:
                    first_line = match.group(1)
                    # Build environment URL
                    env_url = f"{torque_url}/{torque_space}/environments/{environment_id}" if environment_id else ""
                    env_info = f". {env_url}" if environment_id else ""
                    print(f"{first_line}{env_info}\n", file=sys.stderr, end='', flush=True)
                    state['first_line_shown'] = True
            
            # Look for execution marker
            match = _EXECUTION_MARKER.search(state['buffer'])
            if match:
                state['found'] = True
                # Print from after the marker line
                after_marker = state['buffer'][match.end():]
                if after_marker:
                    print(after_marker, file=sys.stderr, end='', flush=True)
                state['buffer'] = ''
        return _stream
    
    # Helper to parse --upload arguments into files list
    def parse_uploads(upload_args):
        """Parse --upload arguments into files list for deployment.
        
        Format: LOCAL:REMOTE[:MODE]
        Handles Windows paths with drive letters (e.g., C:\\path\\file.txt)
        """
        if not upload_args:
            return []
        files = []
        for spec in upload_args:
            parts = spec.split(':')
            # Handle Windows drive letters (e.g., C:\path -> ['C', '\path', ...])
            # If first part is single letter and second part starts with \ or /, rejoin them
            if len(parts) >= 2 and len(parts[0]) == 1 and parts[0].isalpha():
                if parts[1].startswith('\\') or parts[1].startswith('/'):
                    # Rejoin drive letter with path
                    parts = [parts[0] + ':' + parts[1]] + parts[2:]
            
            if len(parts) < 2:
                print(f"Error: Invalid upload spec '{spec}'. Use LOCAL:REMOTE[:MODE]", file=sys.stderr)
                sys.exit(1)
            file_spec = {
                'local_source_path': parts[0],
                'remote_destination_path': parts[1],
            }
            if len(parts) >= 3:
                file_spec['mode'] = parts[2]
            files.append(file_spec)
        return files
    
    # Helper to parse --download arguments into download files list
    def parse_downloads(download_args):
        """Parse --download arguments into download files list.
        
        Format: REMOTE:LOCAL
        Handles Windows paths with drive letters (e.g., C:\\path\\file.txt) for the LOCAL part.
        """
        if not download_args:
            return []
        files = []
        for spec in download_args:
            parts = spec.split(':')
            # The REMOTE path is first (Linux, no drive letters)
            # The LOCAL path may have Windows drive letters
            # After splitting: [remote, local_part1, local_part2, ...]
            # If local_part1 is a single letter and local_part2 starts with \ or /, rejoin
            if len(parts) >= 3 and len(parts[1]) == 1 and parts[1].isalpha():
                if parts[2].startswith('\\') or parts[2].startswith('/'):
                    parts = [parts[0], parts[1] + ':' + parts[2]] + parts[3:]
            
            if len(parts) < 2:
                print(f"Error: Invalid download spec '{spec}'. Use REMOTE:LOCAL", file=sys.stderr)
                sys.exit(1)
            file_spec = {
                'remote_source_path': parts[0],
                'local_destination_path': parts[1],
            }
            files.append(file_spec)
        return files
    
    try:
        if args.command == "credentials":
            # Same output as the MCP list_credentials tool, so the two flavours agree.
            result = await handle_list_credentials(
                {"force_rediscover": getattr(args, "force_rediscover", False)}, _config
            )
            text = result[0].text if result else ""
            if getattr(args, "json", False):
                disabled = _credentials_disabled_message(_config)
                if disabled:
                    print(json_module.dumps({"error": disabled}, indent=2))
                    sys.exit(1)
                async with get_torque_client() as client:
                    # handle_list_credentials just refreshed the list and ran any needed
                    # measurement, so read the cache rather than fetching twice.
                    cache, creds_list = await credentials_module.get_credentials(
                        client, client.space
                    )
                    payload = []
                    for c in sorted(creds_list, key=lambda x: (x.get("name") or "").lower()):
                        entry = credentials_module.get_type_entry(
                            cache, client.base_url, c.get("type"))
                        payload.append({
                            "name": c.get("name"),
                            "type": c.get("type"),
                            "cloud_type": c.get("cloud_type"),
                            "cloud_identifier": c.get("cloud_identifier"),
                            "description": c.get("description"),
                            "all_spaces_allowed": c.get("all_spaces_allowed"),
                            "allowed_space_names": c.get("allowed_space_names"),
                            "fields": credentials_module.displayable_fields(c),
                            "env_vars": (entry or {}).get("vars"),
                            "status": (entry or {}).get("status"),
                        })
                    print(json_module.dumps(payload, indent=2))
            else:
                print(text)
            return

        if args.command == "transfer":
            await _cli_transfer(args)
            return

        if args.command == "ssh":
            # SSH command execution (with optional file uploads)
            target_ip = _config["default_target_ip"]
            ssh_user = getattr(args, 'user', None) or _config["default_ssh_user"]
            ssh_key_path = getattr(args, 'key', None) or _config["default_ssh_key"]
            ssh_password = getattr(args, 'password', None) or _config["default_ssh_password"]
            agent = getattr(args, 'torque_agent', None)
            timeout = getattr(args, 'timeout', None)
            allow_dangerous_commands = getattr(args, 'allow_dangerous_commands', False)
            output_json = getattr(args, 'json', False)
            command_description = getattr(args, 'description', None)
            uploads = parse_uploads(getattr(args, 'upload', None))
            downloads = parse_downloads(getattr(args, 'download', None))
            cmd = getattr(args, 'cmd', None)
            
            # Must have command or uploads or downloads
            if not cmd and not uploads and not downloads:
                print("Error: Must provide a command, --upload files, --download files, or any combination.", file=sys.stderr)
                sys.exit(1)
            
            if not all([target_ip, ssh_user]):
                print("Error: Missing host or user. Use --host, --user or set defaults.", file=sys.stderr)
                sys.exit(1)
            
            if not ssh_key_path and not ssh_password:
                print("Error: Missing authentication. Use --key or --password (or set defaults).", file=sys.stderr)
                sys.exit(1)
            
            # Check dangerous commands
            if cmd and not allow_dangerous_commands:
                warning = check_dangerous_command(cmd)
                if warning:
                    print(warning, file=sys.stderr)
                    sys.exit(2)
            
            ssh_key = ""
            if ssh_key_path:
                try:
                    ssh_key = resolve_ssh_private_key(ssh_key_path)
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)
            
            # Process file uploads (with croc for large files)
            init_commands = None
            container_pre_commands = None
            plan = None
            croc_process = None
            if uploads:
                plan = prepare_files_with_croc(
                    uploads, transfer_mode="ssh",
                    target_ip=target_ip, ssh_user=ssh_user,
                    ssh_private_key=ssh_key, ssh_password=ssh_password,
                )
                if plan.errors:
                    print("Error preparing files:", file=sys.stderr)
                    for e in plan.errors:
                        print(f"  - {e}", file=sys.stderr)
                    sys.exit(1)
                if plan.inline_commands:
                    init_commands = plan.inline_commands
                if plan.croc_container_pre_commands:
                    container_pre_commands = plan.croc_container_pre_commands
            
            effective_command = cmd or "echo 'Files deployed successfully'"
            
            # Prepare download plan
            dl_plan = None
            dl_process = None
            if downloads:
                dl_plan = prepare_download_with_croc(
                    downloads, transfer_mode="ssh",
                    target_ip=target_ip, ssh_user=ssh_user,
                    ssh_private_key=ssh_key, ssh_password=ssh_password,
                )
                if dl_plan.errors:
                    print("Download preparation warnings:", file=sys.stderr)
                    for e in dl_plan.errors:
                        print(f"  - {e}", file=sys.stderr)
            
            log_cb = cli_log_callback("")
            if dl_plan is not None and dl_plan.needs_download:
                # The gated receiver depends on the watcher seeing the sender's
                # READY sentinel in the streamed output
                log_cb = make_download_watch_callback(dl_plan, log_cb)

            try:
                # Start croc send locally if needed (uploads)
                if plan is not None and plan.needs_croc:
                    croc_process = await execute_with_croc(plan)

                # Start croc receive locally if needed (downloads)
                if dl_plan is not None and dl_plan.needs_download:
                    dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)

                async with get_torque_client() as client:
                    __cred_args = {"credential": getattr(args, "credential", None),
                                    "credential_env_forward": getattr(args, "credential_env_forward", None)}
                    __cred_name, __cred_ctx = await _prepare_credential(
                        __cred_args, _config, client, forward=True)
                    result = await client.execute_remote_command(
                        target_ip=target_ip,
                        ssh_user=ssh_user,
                        ssh_private_key=ssh_key,
                        command=effective_command,
                        agent=agent,
                        timeout=timeout,
                        auto_cleanup=_config["auto_delete_environments"],
                        log_callback=log_cb,
                        init_commands=init_commands,
                        ssh_password=ssh_password,
                        container_pre_commands=container_pre_commands,
                        download_commands=dl_plan.download_commands if dl_plan and dl_plan.needs_download else None,
                        command_description=command_description,
                        environment_kind="ssh",
                        credential_name=__cred_name,
                        credential_context=__cred_ctx,
                    )
            finally:
                await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")

            # Finalize downloads (bounded: aborts the receiver instead of
            # letting a failed transfer burn its full deadline)
            dl_successes = []
            dl_errors = []
            if dl_plan and dl_plan.needs_download:
                try:
                    dl_successes, dl_errors = await complete_download(dl_plan, dl_process)
                except Exception as e:
                    dl_errors.append(f"Download finalization error: {e}")
                finally:
                    await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir)

            upload_errors = await _cli_upload_errors(plan, result)
            if output_json:
                result_dict = {
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "output": result.command_output,
                    "error": result.error,
                    "environment_id": result.environment_id,
                }
                if dl_successes or dl_errors:
                    result_dict["downloads"] = {"successes": dl_successes, "errors": dl_errors, "transfer_seconds": dl_plan.transfer_seconds if dl_plan else None}
                if upload_errors:
                    result_dict["upload_errors"] = upload_errors
                print(json_module.dumps(result_dict))
                if dl_errors or upload_errors:
                    sys.exit(1)
            else:
                for e in upload_errors:
                    print(f"UPLOAD FAILED: {e}", file=sys.stderr)
                if result.status == "completed":
                    print(result.command_output or "", end='')
                    for s in dl_successes:
                        print(s, file=sys.stderr)  # already reads "Downloaded: <path>"
                    for e in dl_errors:
                        print(f"DOWNLOAD FAILED: {e}", file=sys.stderr)
                    if dl_plan is not None and dl_plan.transfer_seconds is not None:
                        print(f"Transfer time: {_format_seconds(dl_plan.transfer_seconds)}", file=sys.stderr)
                    # A requested download that did not complete is a failure,
                    # even when the remote command itself exited 0
                    sys.exit(1 if (dl_errors or upload_errors) else (result.exit_code or 0))
                else:
                    print(f"Error: {result.error}", file=sys.stderr)
                    sys.exit(1)

        elif args.command == "persistent-container":
            # Persistent container command
            agent = getattr(args, 'torque_agent', None)
            timeout = getattr(args, 'timeout', None)
            output_json = getattr(args, 'json', False)
            uploads = parse_uploads(getattr(args, 'upload', None))
            downloads = parse_downloads(getattr(args, 'download', None))
            cmd = getattr(args, 'cmd', None)
            env_id = getattr(args, 'env_id', None)
            new_container = getattr(args, 'new', False)
            release_all = getattr(args, 'all', False)
            command_description = getattr(args, 'description', None)
            container_description = getattr(args, 'container_description', None)

            # Handle sub-actions: create, list, release
            if cmd == "create":
                # Create a new persistent container and output its env_id
                try:
                    container_info = await _ensure_persistent_container(agent=agent, new_container=True, container_description=container_description)
                    cid = container_info["environment_id"]
                    agent_name = container_info.get("agent", agent or _config["default_agent"])
                    _save_container_to_state(cid, agent_name)
                    if output_json:
                        print(json_module.dumps({
                            "environment_id": cid,
                            "container_id": container_info.get("container_id"),
                            "container_ip": container_info.get("container_ip"),
                            "agent": agent_name,
                        }))
                    else:
                        print(cid)  # stdout: just the env_id for easy capture
                        print(f"Created persistent container {cid} on {agent_name}", file=sys.stderr)
                except Exception as e:
                    print(f"Error creating persistent container: {e}", file=sys.stderr)
                    sys.exit(1)
                    
            elif cmd == "list":
                # List known persistent containers and check their status
                state = _read_state()
                containers = state.get("containers", {})
                default_id = state.get("default")
                
                if not containers:
                    print("No persistent containers in state file.", file=sys.stderr)
                    sys.exit(0)
                
                results = []
                async with get_torque_client() as client:
                    for cid, info in containers.items():
                        try:
                            env_data = await client.get_environment_status(cid)
                            current_state = env_data.get("details", {}).get("state", {}).get("current_state", "unknown")
                            status = "active" if current_state in ("deploying", "launching") else current_state
                        except Exception:
                            status = "expired"
                        marker = "*" if cid == default_id else " "
                        results.append({
                            "environment_id": cid,
                            "status": status,
                            "agent": info.get("agent", ""),
                            "created": info.get("created", ""),
                            "default": cid == default_id,
                        })
                
                if output_json:
                    print(json_module.dumps(results, indent=2))
                else:
                    for r in results:
                        marker = "*" if r["default"] else " "
                        print(f"  {marker} {r['environment_id']}  {r['status']:<10}  {r['agent']}  {r['created']}")
                
            elif cmd == "release":
                # Release persistent container(s)
                if release_all:
                    state = _read_state()
                    containers = list(state.get("containers", {}).keys())
                    if not containers:
                        print("No persistent containers to release.", file=sys.stderr)
                        sys.exit(0)
                    async with get_torque_client() as client:
                        for cid in containers:
                            try:
                                await client.end_environment(cid, force=True)
                                _remove_container_from_state(cid)
                                print(f"Released {cid}", file=sys.stderr)
                            except Exception as e:
                                print(f"Failed to release {cid}: {e}", file=sys.stderr)
                elif env_id:
                    async with get_torque_client() as client:
                        try:
                            await client.end_environment(env_id, force=True)
                            _remove_container_from_state(env_id)
                            print(f"Released {env_id}", file=sys.stderr)
                        except Exception as e:
                            print(f"Failed to release {env_id}: {e}", file=sys.stderr)
                            sys.exit(1)
                else:
                    # Release default
                    state = _read_state()
                    default_id = state.get("default")
                    if not default_id:
                        print("Error: No default persistent container. Use --env-id or --all.", file=sys.stderr)
                        sys.exit(1)
                    async with get_torque_client() as client:
                        try:
                            await client.end_environment(default_id, force=True)
                            _remove_container_from_state(default_id)
                            print(f"Released {default_id}", file=sys.stderr)
                        except Exception as e:
                            print(f"Failed to release {default_id}: {e}", file=sys.stderr)
                            sys.exit(1)
                
            else:
                # Execute a command on persistent container
                # Must have command or uploads or downloads
                if not cmd and not uploads and not downloads:
                    print("Error: Must provide a command, --upload files, --download files, or a sub-action (create, list, release).", file=sys.stderr)
                    sys.exit(1)
                
                # Determine which container to use
                target_env_id = env_id
                if not target_env_id and not new_container:
                    # Try state file default
                    state = _read_state()
                    target_env_id = state.get("default")
                
                try:
                    container_info = await _ensure_persistent_container(
                        agent=agent, new_container=new_container, environment_id=target_env_id,
                        container_description=container_description,
                    )
                    container_ip = container_info["container_ip"]
                    private_key = container_info["private_key"]
                    used_env_id = container_info["environment_id"]
                    agent_name = container_info.get("agent", agent or _config["default_agent"])
                    
                    # Save to state file
                    _save_container_to_state(used_env_id, agent_name)
                except Exception as e:
                    print(f"Error setting up persistent container: {e}", file=sys.stderr)
                    sys.exit(1)
                
                # Process file uploads (with croc for large files)
                init_commands = None
                container_pre_commands = None
                plan = None
                croc_process = None
                if uploads:
                    plan = prepare_files_with_croc(
                        uploads, transfer_mode="ssh",
                        target_ip=container_ip, ssh_user="root",
                        ssh_private_key=private_key,
                    )
                    if plan.errors:
                        print("Error preparing files:", file=sys.stderr)
                        for e in plan.errors:
                            print(f"  - {e}", file=sys.stderr)
                        sys.exit(1)
                    if plan.inline_commands:
                        global_init = _config.get("init_commands") or ""
                        init_commands = (plan.inline_commands + "\n" + global_init) if global_init else plan.inline_commands
                    if plan.croc_container_pre_commands:
                        container_pre_commands = plan.croc_container_pre_commands
                
                effective_command = cmd or "echo 'Files deployed successfully'"
                
                # Prepare download plan
                dl_plan = None
                dl_process = None
                if downloads:
                    dl_plan = prepare_download_with_croc(
                        downloads, transfer_mode="ssh",
                        target_ip=container_ip, ssh_user="root",
                        ssh_private_key=private_key,
                    )
                    if dl_plan.errors:
                        print("Download preparation warnings:", file=sys.stderr)
                        for e in dl_plan.errors:
                            print(f"  - {e}", file=sys.stderr)
                
                print(f"Persistent Container: {used_env_id}", file=sys.stderr)

                log_cb = cli_log_callback("")
                if dl_plan is not None and dl_plan.needs_download:
                    # The gated receiver depends on the watcher seeing the
                    # sender's READY sentinel in the streamed output
                    log_cb = make_download_watch_callback(dl_plan, log_cb)

                try:
                    # Start croc send locally if needed (uploads)
                    if plan is not None and plan.needs_croc:
                        croc_process = await execute_with_croc(plan)

                    # Start croc receive locally if needed (downloads)
                    if dl_plan is not None and dl_plan.needs_download:
                        dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)

                    async with get_torque_client() as client:
                        # Arm the container's end time so it cannot die under
                        # this command
                        try:
                            await client.set_scheduled_end_time(
                                used_env_id,
                                _container_deadline(_config["container_idle_timeout"], timeout),
                            )
                        except Exception:
                            pass

                        __cred_args = {"credential": getattr(args, "credential", None),
                                        "credential_env_forward": getattr(args, "credential_env_forward", None)}
                        __cred_name, __cred_ctx = await _prepare_credential(
                            __cred_args, _config, client, forward=True)
                        result = await client.execute_remote_command(
                            target_ip=container_ip,
                            ssh_user="root",
                            ssh_private_key=private_key,
                            command=effective_command,
                            agent=agent,
                            timeout=timeout,
                            auto_cleanup=_config["auto_delete_environments"],
                            log_callback=log_cb,
                            init_commands=init_commands,
                            container_pre_commands=container_pre_commands,
                            download_commands=dl_plan.download_commands if dl_plan and dl_plan.needs_download else None,
                            command_description=command_description,
                            environment_kind="persistent-command",
                            parent_env_id=used_env_id,
                            credential_name=__cred_name,
                            credential_context=__cred_ctx,
                        )

                        # Re-arm the idle timeout: the container dies
                        # idle_timeout after its LAST USE (absolute end; the
                        # old additive /extend accumulated lifetime instead)
                        try:
                            await client.set_scheduled_end_time(
                                used_env_id,
                                _container_deadline(_config["container_idle_timeout"]),
                            )
                        except Exception:
                            pass
                finally:
                    await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")
                
                # Finalize downloads (bounded: aborts the receiver instead of
                # letting a failed transfer burn its full deadline)
                dl_successes = []
                dl_errors = []
                if dl_plan and dl_plan.needs_download:
                    try:
                        dl_successes, dl_errors = await complete_download(dl_plan, dl_process)
                    except Exception as e:
                        dl_errors.append(f"Download finalization error: {e}")
                    finally:
                        await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir)

                upload_errors = await _cli_upload_errors(plan, result)
                if output_json:
                    result_dict = {
                        "status": result.status,
                        "exit_code": result.exit_code,
                        "output": result.command_output,
                        "error": result.error,
                        "environment_id": result.environment_id,
                        "persistent_container_id": used_env_id,
                    }
                    if dl_successes or dl_errors:
                        result_dict["downloads"] = {"successes": dl_successes, "errors": dl_errors, "transfer_seconds": dl_plan.transfer_seconds if dl_plan else None}
                    if upload_errors:
                        result_dict["upload_errors"] = upload_errors
                    print(json_module.dumps(result_dict))
                    if dl_errors or upload_errors:
                        sys.exit(1)
                else:
                    for e in upload_errors:
                        print(f"UPLOAD FAILED: {e}", file=sys.stderr)
                    if result.status == "completed":
                        print(result.command_output or "", end='')
                        for s in dl_successes:
                            print(s, file=sys.stderr)  # already reads "Downloaded: <path>"
                        for e in dl_errors:
                            print(f"DOWNLOAD FAILED: {e}", file=sys.stderr)
                        if dl_plan is not None and dl_plan.transfer_seconds is not None:
                            print(f"Transfer time: {_format_seconds(dl_plan.transfer_seconds)}", file=sys.stderr)
                        # A requested download that did not complete is a failure,
                        # even when the remote command itself exited 0
                        sys.exit(1 if (dl_errors or upload_errors) else (result.exit_code or 0))
                    else:
                        print(f"Error: {result.error}", file=sys.stderr)
                        sys.exit(1)
        
        elif args.command == "disposable-container":
            # Disposable container command (with optional file uploads)
            agent = getattr(args, 'torque_agent', None)
            timeout = getattr(args, 'timeout', None)
            output_json = getattr(args, 'json', False)
            uploads = parse_uploads(getattr(args, 'upload', None))
            downloads = parse_downloads(getattr(args, 'download', None))
            cmd = getattr(args, 'cmd', None)
            command_description = getattr(args, 'description', None)
            
            # Must have command or uploads or downloads
            if not cmd and not uploads and not downloads:
                print("Error: Must provide a command or --upload/--download files (or both).", file=sys.stderr)
                sys.exit(1)
            
            # Process file uploads (with croc for large files)
            init_commands = None
            plan = None
            croc_process = None
            if uploads:
                plan = prepare_files_with_croc(uploads, transfer_mode="container")
                if plan.errors:
                    print("Error preparing files:", file=sys.stderr)
                    for e in plan.errors:
                        print(f"  - {e}", file=sys.stderr)
                    sys.exit(1)
                # Combine croc init + inline commands for container target
                combined = []
                if plan.croc_init_commands:
                    combined.append(plan.croc_init_commands)
                if plan.inline_commands:
                    combined.append(plan.inline_commands)
                if combined:
                    init_commands = "\n".join(combined)
            
            effective_command = cmd or "echo 'Files deployed successfully'"
            
            # Prepare download plan
            dl_plan = None
            dl_process = None
            if downloads:
                dl_plan = prepare_download_with_croc(
                    downloads, transfer_mode="container",
                )
                if dl_plan.errors:
                    print("Download preparation warnings:", file=sys.stderr)
                    for e in dl_plan.errors:
                        print(f"  - {e}", file=sys.stderr)
            
            log_cb = cli_log_callback("")
            if dl_plan is not None and dl_plan.needs_download:
                # The gated receiver depends on the watcher seeing the sender's
                # READY sentinel in the streamed output
                log_cb = make_download_watch_callback(dl_plan, log_cb)

            try:
                # Start croc send locally if needed (uploads)
                if plan is not None and plan.needs_croc:
                    croc_process = await execute_with_croc(plan)

                # Start croc receive locally if needed (downloads)
                if dl_plan is not None and dl_plan.needs_download:
                    dl_process = await execute_download_receive(dl_plan, command_timeout=timeout)

                async with get_torque_client() as client:
                    __cred_args = {"credential": getattr(args, "credential", None),
                                    "credential_env_forward": getattr(args, "credential_env_forward", None)}
                    __cred_name, __cred_ctx = await _prepare_credential(
                        __cred_args, _config, client, forward=False)
                    result = await client.execute_local_command(
                        command=effective_command,
                        agent=agent,
                        timeout=timeout,
                        auto_cleanup=_config["auto_delete_environments"],
                        log_callback=log_cb,
                        init_commands=init_commands,
                        download_commands=dl_plan.download_commands if dl_plan and dl_plan.needs_download else None,
                        command_description=command_description,
                        credential_name=__cred_name,
                        credential_context=__cred_ctx,
                    )
            finally:
                await cleanup_croc_resources(croc_process, plan.croc_staging_dir if plan else "")

            # Finalize downloads (bounded: aborts the receiver instead of
            # letting a failed transfer burn its full deadline)
            dl_successes = []
            dl_errors = []
            if dl_plan and dl_plan.needs_download:
                try:
                    dl_successes, dl_errors = await complete_download(dl_plan, dl_process)
                except Exception as e:
                    dl_errors.append(f"Download finalization error: {e}")
                finally:
                    await cleanup_download_resources(dl_process, dl_plan.croc_receive_dir)

            upload_errors = await _cli_upload_errors(plan, result)
            if output_json:
                result_dict = {
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "output": result.command_output,
                    "error": result.error,
                    "environment_id": result.environment_id,
                }
                if dl_successes or dl_errors:
                    result_dict["downloads"] = {"successes": dl_successes, "errors": dl_errors, "transfer_seconds": dl_plan.transfer_seconds if dl_plan else None}
                if upload_errors:
                    result_dict["upload_errors"] = upload_errors
                print(json_module.dumps(result_dict))
                if dl_errors or upload_errors:
                    sys.exit(1)
            else:
                for e in upload_errors:
                    print(f"UPLOAD FAILED: {e}", file=sys.stderr)
                if result.status == "completed":
                    print(result.command_output or "", end='')
                    for s in dl_successes:
                        print(s, file=sys.stderr)  # already reads "Downloaded: <path>"
                    for e in dl_errors:
                        print(f"DOWNLOAD FAILED: {e}", file=sys.stderr)
                    if dl_plan is not None and dl_plan.transfer_seconds is not None:
                        print(f"Transfer time: {_format_seconds(dl_plan.transfer_seconds)}", file=sys.stderr)
                    # A requested download that did not complete is a failure,
                    # even when the remote command itself exited 0
                    sys.exit(1 if (dl_errors or upload_errors) else (result.exit_code or 0))
                else:
                    print(f"Error: {result.error}", file=sys.stderr)
                    sys.exit(1)

        elif args.command == "read":
            # Read remote file
            target_ip = _config["default_target_ip"]
            ssh_user = getattr(args, 'user', None) or _config["default_ssh_user"]
            ssh_key_path = getattr(args, 'key', None) or _config["default_ssh_key"]
            ssh_password = getattr(args, 'password', None) or _config["default_ssh_password"]
            agent = getattr(args, 'torque_agent', None)
            timeout = getattr(args, 'timeout', None)
            max_size = getattr(args, 'max_size', 102400)
            
            if not all([target_ip, ssh_user]):
                print("Error: Missing target or user.", file=sys.stderr)
                sys.exit(1)
            
            if not ssh_key_path and not ssh_password:
                print("Error: Missing authentication. Use --key or --password.", file=sys.stderr)
                sys.exit(1)
            
            ssh_key = ""
            if ssh_key_path:
                try:
                    ssh_key = resolve_ssh_private_key(ssh_key_path)
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)
            
            # Build safe read command
            escaped_path = args.path.replace("'", "'\\''") 
            cmd = f"head -c {max_size} '{escaped_path}' 2>/dev/null || cat '{escaped_path}' 2>&1"

            async with get_torque_client() as client:
                result = await client.execute_remote_command(
                    target_ip=target_ip,
                    ssh_user=ssh_user,
                    ssh_private_key=ssh_key,
                    command=cmd,
                    agent=agent,
                    timeout=timeout,
                    auto_cleanup=_config["auto_delete_environments"],
                    ssh_password=ssh_password,
                    command_description=f"read {args.path}",
                    environment_kind="ssh",
                )
            
            if result.status == "completed":
                print(result.command_output or "", end='')
                sys.exit(result.exit_code or 0)
            else:
                print(f"Error: {result.error}", file=sys.stderr)
                sys.exit(1)
        
        elif args.command == "list":
            # List remote directory
            target_ip = _config["default_target_ip"]
            ssh_user = getattr(args, 'user', None) or _config["default_ssh_user"]
            ssh_key_path = getattr(args, 'key', None) or _config["default_ssh_key"]
            ssh_password = getattr(args, 'password', None) or _config["default_ssh_password"]
            agent = getattr(args, 'torque_agent', None)
            timeout = getattr(args, 'timeout', None)
            show_all = getattr(args, 'all', False)
            long_format = getattr(args, 'long', False)
            
            if not all([target_ip, ssh_user]):
                print("Error: Missing target or user.", file=sys.stderr)
                sys.exit(1)
            
            if not ssh_key_path and not ssh_password:
                print("Error: Missing authentication. Use --key or --password.", file=sys.stderr)
                sys.exit(1)
            
            ssh_key = ""
            if ssh_key_path:
                try:
                    ssh_key = resolve_ssh_private_key(ssh_key_path)
                except ValueError as e:
                    print(f"Error: {e}", file=sys.stderr)
                    sys.exit(1)
            
            # Build ls command
            flags = "-"
            if show_all:
                flags += "a"
            if long_format:
                flags += "lh"
            flags = flags if len(flags) > 1 else ""
            
            escaped_path = args.path.replace("'", "'\\''") 
            cmd = f"ls {flags} '{escaped_path}'" if flags else f"ls '{escaped_path}'"

            async with get_torque_client() as client:
                result = await client.execute_remote_command(
                    target_ip=target_ip,
                    ssh_user=ssh_user,
                    ssh_private_key=ssh_key,
                    command=cmd,
                    agent=agent,
                    timeout=timeout,
                    auto_cleanup=_config["auto_delete_environments"],
                    ssh_password=ssh_password,
                    command_description=f"list {args.path}",
                    environment_kind="ssh",
                )
            
            if result.status == "completed":
                print(result.command_output or "", end='')
                sys.exit(result.exit_code or 0)
            else:
                print(f"Error: {result.error}", file=sys.stderr)
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


class _DefaultSeedingArgumentParser(argparse.ArgumentParser):
    """Top-level parser that seeds common-arg defaults into a fresh namespace.

    Why this exists — the argparse subparser clobber:
    `common_parser` is inherited (via parents=[...]) by BOTH this top-level parser
    AND every subparser, so they share the SAME action objects. argparse (3.13+)
    parses the tokens after the subcommand into a FRESH namespace and copies every
    key back onto the main namespace. If the common args carried real defaults, the
    subparser would copy its (default None) values back, wiping out any value set by
    a flag placed BEFORE the subcommand.

    The fix: every common arg uses default=argparse.SUPPRESS (so an omitted arg
    leaves NO key to copy back), and the real/env defaults are seeded here — ONLY on
    the top-level namespace, ONLY when the caller didn't pass one. We deliberately do
    NOT use parser.set_defaults(), because that mutates the shared action.default
    (defeating SUPPRESS), and the subparsers are created as plain ArgumentParsers so
    they never seed (and therefore never copy common defaults back).
    """

    common_defaults: dict = {}

    def parse_known_args(self, args=None, namespace=None):
        if namespace is None:
            namespace = argparse.Namespace()
            for key, value in self.common_defaults.items():
                setattr(namespace, key, value)
        return super().parse_known_args(args, namespace)


def build_parser():
    """Build the argparse parser for the CLI.

    Extracted from main() so argument parsing can be unit-tested in isolation
    (e.g. order-independence of flags) without executing the program.
    """
    # Common-arg defaults (env-backed). Seeded onto the top-level namespace by
    # _DefaultSeedingArgumentParser. See that class for the full rationale; in short,
    # every common arg below uses default=argparse.SUPPRESS to avoid the argparse
    # subparser clobber, and these values supply the actual defaults.
    common_defaults = {
        "config": os.environ.get("TORQUE_TUNNEL_CONFIG"),
        "profile": os.environ.get("TORQUE_TUNNEL_PROFILE"),
        "torque_url": os.environ.get("TORQUE_URL"),
        "torque_token": os.environ.get("TORQUE_TOKEN"),
        "torque_space": os.environ.get("TORQUE_SPACE"),
        "torque_agent": os.environ.get("TORQUE_AGENT"),
        "ssh_key": os.environ.get("SSH_KEY"),
        "ssh_password": os.environ.get("SSH_PASSWORD"),
        "host": os.environ.get("TARGET_HOST"),
        "ssh_user": os.environ.get("SSH_USER"),
        "init_commands": os.environ.get("INIT_COMMANDS"),
        "finally_commands": os.environ.get("FINALLY_COMMANDS"),
        "auto_delete_environments": os.environ.get("AUTO_DELETE_ENVIRONMENTS", "").lower() in ("true", "1", "yes"),
        # Deliberately NOT env-backed (nor in the config file): see raw_log.py.
        "raw_log": raw_log.OFF,
        "container_idle_timeout": int(os.environ.get("CONTAINER_IDLE_TIMEOUT", "86400")),
    }
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--config",
        default=argparse.SUPPRESS,
        help="Path to config YAML file (default: $TORQUE_TUNNEL_CONFIG or ~/.torque-tunnel/config.yaml)",
    )
    common_parser.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Configuration profile name to use (default: $TORQUE_TUNNEL_PROFILE)",
    )
    common_parser.add_argument(
        "--torque-url",
        default=argparse.SUPPRESS,
        help="Torque base URL (default: $TORQUE_URL)",
    )
    common_parser.add_argument(
        "--torque-token",
        default=argparse.SUPPRESS,
        help="Torque API token (default: $TORQUE_TOKEN)",
    )
    common_parser.add_argument(
        "--torque-space",
        default=argparse.SUPPRESS,
        help="Torque space name (default: $TORQUE_SPACE)",
    )
    common_parser.add_argument(
        "--torque-agent",
        default=argparse.SUPPRESS,
        help="Default Torque agent name (default: $TORQUE_AGENT)",
    )
    common_parser.add_argument(
        "--ssh-key",
        default=argparse.SUPPRESS,
        help="SSH private key - file path, key content, or base64-encoded key (env: $SSH_KEY)",
    )
    common_parser.add_argument(
        "--ssh-password",
        default=argparse.SUPPRESS,
        help="SSH password for authentication (env: $SSH_PASSWORD)",
    )
    common_parser.add_argument(
        "--host",
        default=argparse.SUPPRESS,
        help="Target server IP/hostname (env: $TARGET_HOST)",
    )
    common_parser.add_argument(
        "--ssh-user",
        default=argparse.SUPPRESS,
        help="SSH username (env: $SSH_USER)",
    )
    common_parser.add_argument(
        "--init-commands",
        default=argparse.SUPPRESS,
        help="Commands to run before every SSH command",
    )
    common_parser.add_argument(
        "--finally-commands",
        default=argparse.SUPPRESS,
        help="Commands to run after every SSH command",
    )
    common_parser.add_argument(
        "--auto-delete-environments",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Automatically delete environments after completion",
    )
    common_parser.add_argument(
        "--raw-log",
        choices=raw_log.MODES,
        default=argparse.SUPPRESS,
        help="How much of Torque's raw grain log to return. The raw log holds the rendered "
             "script with every input, SSH keys included. off (default): only the command's "
             "output; fallback: also the whole raw log when the command never started "
             "(still in setup, cancelled, failed or timed out before it); always: the whole "
             "raw log everywhere, streaming included. Settable only by this flag.",
    )
    common_parser.add_argument(
        "--container-idle-timeout",
        type=int,
        default=argparse.SUPPRESS,
        help="Idle timeout in seconds for persistent containers before auto-cleanup (default: 86400 = 24 hours, env: $CONTAINER_IDLE_TIMEOUT)",
    )
    
    # Main parser with subcommands - also inherits common args for when no subcommand is given
    parser = _DefaultSeedingArgumentParser(
        parents=[common_parser],
        description="torque-tunnel - Execute remote commands via Torque (MCP server or CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  serve (default)           Run as MCP server (for VS Code Copilot)
  ssh                      Execute a command on a remote target server via SSH
  persistent-container     Execute a command on a persistent Torque agent container (state preserved)
  disposable-container     Execute a command on a fresh disposable Torque agent container (nothing persists)
  read                     Read a file from a remote server
  list                     List a directory on a remote server

Examples:
  # Run as MCP server (for VS Code)
  torque-tunnel serve

  # CLI mode - run a command on a remote server
  torque-tunnel ssh "uname -a"
  torque-tunnel ssh --host 10.0.0.1 --user root "df -h"

  # CLI mode - upload files and run a command on remote server
  torque-tunnel ssh --upload ./script.sh:/tmp/script.sh:755 "bash /tmp/script.sh"
  torque-tunnel ssh --upload ./config.yaml:/etc/app/config.yaml --upload ./data:/var/data "cat /etc/app/config.yaml"

  # CLI mode - download files after running a command
  torque-tunnel ssh --download /var/log/app.log:./app.log "echo done"
  torque-tunnel ssh --download /opt/results:/tmp/results "run-test-suite"

  # CLI mode - run on a persistent Torque agent container
  torque-tunnel persistent-container "curl https://example.com"
  torque-tunnel persistent-container --upload ./test.py:/tmp/test.py "python /tmp/test.py"
  torque-tunnel persistent-container --download /tmp/output.csv:./output.csv "generate-report"

  # CLI mode - run on a fresh disposable container
  torque-tunnel disposable-container "curl https://example.com"

  # CLI mode - read/list files
  torque-tunnel read /etc/hostname
  torque-tunnel list /var/log

Environment Variables:
  TORQUE_URL, TORQUE_TOKEN, TORQUE_SPACE, TORQUE_AGENT
  SSH_KEY, SSH_PASSWORD, TARGET_HOST, SSH_USER

UPLOAD FORMAT:
  --upload LOCAL:REMOTE[:MODE]
  LOCAL  = path to local file or directory
  REMOTE = destination path on target
  MODE   = optional file permissions (e.g., 755) - default: 644 for files
  Directories are transferred via tar archive.

DOWNLOAD FORMAT:
  --download REMOTE:LOCAL
  REMOTE = path to file or directory on the remote target
  LOCAL  = destination path on local machine
  Files are always transferred via croc (peer-to-peer encrypted).
  Download occurs after the main command and finally commands complete.

DANGEROUS COMMANDS (may kill the Torque agent):
  docker restart, docker stop, docker kill, docker rm
  systemctl restart docker, systemctl stop docker
  service docker restart, service docker stop
  reboot, shutdown, init 0, init 6, poweroff, halt
  Use --allow-dangerous-commands to bypass (NOT RECOMMENDED), or run manually via SSH.

LONG-RUNNING COMMANDS:
  Default timeout is 30 minutes. Use --timeout to extend.
  For very long operations, run in background:
    torque-tunnel ssh "nohup command > /tmp/output.log 2>&1 &"
  Then check status:
    torque-tunnel ssh "cat /tmp/output.log"

PERFORMANCE TIP:
  Each command invocation has significant roundtrip overhead
  (environment provisioning, SSH connection, etc.).
  Consolidate multiple commands into a single invocation:
    torque-tunnel ssh "cmd1; cmd2; cmd3"           # sequential
    torque-tunnel ssh "cmd1 && cmd2 && cmd3"       # stop on failure
        """,
    )
    
    # Seed the env-backed common defaults onto the top-level namespace only (see
    # _DefaultSeedingArgumentParser). We attach the dict rather than calling
    # parser.set_defaults(), because set_defaults mutates the shared action.default
    # and would defeat the SUPPRESS that prevents the subparser clobber.
    parser.common_defaults = common_defaults
    
    # --allow-dangerous-commands is registered on BOTH the main parser (so it is
    # accepted BEFORE the subcommand) and on the ssh subparser (so it is accepted
    # AFTER it) — argparse splits the token stream at the subcommand boundary, so a
    # flag must exist on whichever parser owns its position. The main-parser copy
    # uses default=False (the baseline always present in the namespace); the ssh
    # subparser copy uses default=SUPPRESS so that, when omitted there, it does NOT
    # overwrite a True already set by the main parser. It is intentionally NOT added
    # to read/list/*-container, where bypassing the guard is meaningless.
    parser.add_argument(
        "--allow-dangerous-commands", action="store_true", default=False,
        help="Bypass dangerous command warnings for the 'ssh' subcommand (use with extreme caution)",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run",
                                       parser_class=argparse.ArgumentParser)
    
    # serve subcommand (MCP server mode)
    subparsers.add_parser("serve", parents=[common_parser], help="Run as MCP server")
    
    # profiles subcommand (list configuration profiles)
    subparsers.add_parser("profiles", parents=[common_parser], help="List available configuration profiles")

    creds_parser = subparsers.add_parser(
        "credentials", parents=[common_parser],
        help="List Torque credentials usable from this profile's space")
    creds_parser.add_argument("--force-rediscover", action="store_true",
                              help="Re-measure which env vars each credential type injects, ignoring the cache")
    creds_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    
    # setup subcommand (interactive Torque setup)
    subparsers.add_parser("setup", parents=[common_parser], help="Set up Torque connection interactively (opens browser)")

    # register-mcp-client subcommand (register this MCP server with AI clients)
    register_parser = subparsers.add_parser(
        "register-mcp-client",
        help="Register the torque-tunnel MCP server with AI clients (Claude Code, Copilot, Cursor, ...)",
    )
    register_parser.add_argument(
        "--client", action="append", choices=list(onboarding_module.CLIENTS),
        help="Client to register with (repeatable). Default: auto-detect installed clients.",
    )
    register_parser.add_argument(
        "--all", action="store_true", help="Register with every supported client, detected or not.",
    )
    register_parser.add_argument(
        "--list", action="store_true", help="List supported clients and which are detected, then exit.",
    )
    register_parser.add_argument(
        "--python", help="Interpreter path to write into client configs (default: the current venv interpreter).",
    )
    register_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing any files.",
    )
    register_parser.add_argument(
        "--run-setup", action="store_true", help="After registering, launch the interactive Torque setup (opens browser).",
    )

    # ssh subcommand (remote command via SSH)
    ssh_parser = subparsers.add_parser("ssh", parents=[common_parser], help="Execute a command on remote server via SSH")
    ssh_parser.add_argument("cmd", nargs='?', help="The shell command to execute (optional if --upload used)")
    ssh_parser.add_argument("--user", "-u", help="SSH username (overrides --ssh-user)")
    ssh_parser.add_argument("--key", "-k", help="SSH private key - file path, key content, or base64-encoded key (overrides --ssh-key)")
    ssh_parser.add_argument("--password", help="SSH password for authentication (overrides --ssh-password)")
    ssh_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    ssh_parser.add_argument("--allow-dangerous-commands", action="store_true", default=argparse.SUPPRESS, help="Bypass dangerous command warnings (use with extreme caution)")
    ssh_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    ssh_parser.add_argument("--upload", action="append", metavar="LOCAL:REMOTE[:MODE]",
                              help="Upload local file/dir to remote path (can be repeated)")
    ssh_parser.add_argument("--download", action="append", metavar="REMOTE:LOCAL",
                              help="Download remote file/dir to local path after command runs (can be repeated)")
    ssh_parser.add_argument("--description", help="Optional short description embedded in the Torque environment name (for finding it in the UI)")
    ssh_parser.add_argument("--credential", help="Name of a Torque credential to attach; its secrets are injected as environment variables where the command runs (see `torque-tunnel credentials`)")
    ssh_parser.add_argument("--credential-env-forward", action="append", metavar="VAR", help="Extra env var NAME to carry to the remote host (repeatable); only needed for an unmeasured credential type")

    # transfer subcommand (machine to machine, neither reachable from the other)
    transfer_parser = subparsers.add_parser(
        "transfer", parents=[common_parser],
        help="Copy files between two remote machines that cannot reach each other (data does not pass through this machine)")
    for prefix, role in (("from", "sender"), ("to", "receiver")):
        transfer_parser.add_argument(f"--{prefix}-host", help=f"The {role} machine's IP or hostname")
        transfer_parser.add_argument(f"--{prefix}-user", help=f"SSH user on the {role}")
        transfer_parser.add_argument(f"--{prefix}-key", help=f"SSH private key for the {role} - file path, key content, or base64")
        transfer_parser.add_argument(f"--{prefix}-password", help=f"SSH password for the {role}")
        transfer_parser.add_argument(f"--{prefix}-persistent-container", metavar="ENV_ID",
                                     help=f"Use a running persistent container as the {role}")
        transfer_parser.add_argument(f"--{prefix}-profile", help=f"Configuration profile for the {role} (default: --profile / the default profile)")
        transfer_parser.add_argument(f"--{prefix}-agent", help=f"Torque agent for the {role} (default: its profile's)")
    transfer_parser.add_argument("--file", action="append", required=True, metavar="SOURCE:DESTINATION[:MODE]",
                                 help="A file or directory to copy (can be repeated)")
    transfer_parser.add_argument("--description", help="Optional short description embedded in the Torque environment names")
    transfer_parser.add_argument("--timeout", type=int, help=f"Overall limit in seconds (default {TRANSFER_DEFAULT_TIMEOUT_SECONDS})")
    transfer_parser.add_argument("--json", "-j", action="store_true", help="Output the result as JSON")

    # persistent-container subcommand (run on persistent Torque agent container)
    pc_parser = subparsers.add_parser("persistent-container", parents=[common_parser],
                                       help="Execute a command on a persistent Torque agent container (state preserved across calls)")
    pc_parser.add_argument("cmd", nargs='?', help="The shell command to execute, or a sub-action: create, list, release")
    pc_parser.add_argument("--env-id", help="Target a specific persistent container by environment ID")
    pc_parser.add_argument("--new", action="store_true", help="Create a new container (keeps existing ones alive)")
    pc_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    pc_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    pc_parser.add_argument("--upload", action="append", metavar="LOCAL:REMOTE[:MODE]",
                             help="Upload local file/dir to container (can be repeated)")
    pc_parser.add_argument("--download", action="append", metavar="REMOTE:LOCAL",
                             help="Download file/dir from container to local path after command runs (can be repeated)")
    pc_parser.add_argument("--all", action="store_true", help="Release all containers (used with 'release' action)")
    pc_parser.add_argument("--description", help="Optional short description of the command, embedded in the command's Torque environment name")
    pc_parser.add_argument("--container-description", help="Optional short description of the persistent container itself; used only when a new container is created")
    pc_parser.add_argument("--credential", help="Name of a Torque credential to attach; its secrets are injected as environment variables where the command runs (see `torque-tunnel credentials`)")
    pc_parser.add_argument("--credential-env-forward", action="append", metavar="VAR", help="Extra env var NAME to carry to the remote host (repeatable); only needed for an unmeasured credential type")

    # disposable-container subcommand (run on fresh Torque agent container)
    dc_parser = subparsers.add_parser("disposable-container", parents=[common_parser],
                                       help="Execute a command on a fresh disposable Torque agent container (nothing persists)")
    dc_parser.add_argument("cmd", nargs='?', help="The shell command to execute (optional if --upload used)")
    dc_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    dc_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    dc_parser.add_argument("--upload", action="append", metavar="LOCAL:REMOTE[:MODE]",
                             help="Upload local file/dir to container (can be repeated)")
    dc_parser.add_argument("--download", action="append", metavar="REMOTE:LOCAL",
                             help="Download file/dir from container to local path after command runs (can be repeated)")
    dc_parser.add_argument("--description", help="Optional short description embedded in the Torque environment name (for finding it in the UI)")
    dc_parser.add_argument("--credential", help="Name of a Torque credential to attach; its secrets are injected as environment variables where the command runs (see `torque-tunnel credentials`)")

    # read subcommand
    read_parser = subparsers.add_parser("read", parents=[common_parser], help="Read a file from remote server")
    read_parser.add_argument("path", help="Remote file path to read")
    read_parser.add_argument("--user", "-u", help="SSH username")
    read_parser.add_argument("--key", "-k", help="SSH private key - file path, key content, or base64-encoded key")
    read_parser.add_argument("--password", help="SSH password for authentication")
    read_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    read_parser.add_argument("--max-size", type=int, default=102400, help="Max file size in bytes (default: 100KB)")
    
    # list subcommand
    list_parser = subparsers.add_parser("list", parents=[common_parser], help="List a directory on remote server")
    list_parser.add_argument("path", help="Remote directory path")
    list_parser.add_argument("--user", "-u", help="SSH username")
    list_parser.add_argument("--key", "-k", help="SSH private key - file path, key content, or base64-encoded key")
    list_parser.add_argument("--password", help="SSH password for authentication")
    list_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    list_parser.add_argument("--all", "-A", action="store_true", help="Show hidden files")
    list_parser.add_argument("--long", "-l", action="store_true", help="Long format with details")
    
    return parser


def _handle_register_mcp_client_cli(args):
    """Handle 'register-mcp-client': register the MCP server with AI clients."""
    clients = onboarding_module.CLIENTS

    # --list: show supported clients and detection status, then exit.
    if getattr(args, "list", False):
        detected = set(onboarding_module.detect_clients())
        print("Supported AI clients:\n")
        for name, spec in clients.items():
            mark = "detected" if name in detected else "not detected"
            tested = "" if spec.tested else " [untested]"
            print(f"  {name:<16} {spec.display}{tested}")
            print(f"  {'':<16} {spec.note}")
            print(f"  {'':<16} config: {onboarding_module.config_path(name)}  ({mark})\n")
        return

    selected = args.client or None
    if not selected and not args.all:
        detected = onboarding_module.detect_clients()
        if not detected:
            print("No AI clients auto-detected. Use --client <name> or --all, or run "
                  "'register-mcp-client --list' to see options.", file=sys.stderr)
            sys.exit(1)
        print(f"Auto-detected clients: {', '.join(detected)}")

    results = onboarding_module.register_clients(
        clients=selected,
        all_clients=args.all,
        python=getattr(args, "python", None),
        dry_run=args.dry_run,
    )

    if not results:
        print("Nothing to configure.", file=sys.stderr)
        sys.exit(1)

    had_error = False
    for r in results:
        if r.status == "aborted":
            had_error = True
            print(f"  [SKIP] {r.client}: {r.reason}\n         {r.path}")
        elif r.status == "dry-run":
            print(f"  [DRY-RUN] {r.client}: would {r.reason} {r.path}")
        elif r.status == "unchanged":
            print(f"  [OK] {r.client}: already configured ({r.path})")
        else:
            backup = f"  (backup: {r.backup})" if r.backup else ""
            print(f"  [{r.status.upper()}] {r.client}: {r.path}{backup}")

    if not args.dry_run:
        print("\nRestart the affected client(s) so they pick up the new MCP server.")

    if args.run_setup and not args.dry_run:
        print("\nLaunching interactive Torque setup...")
        loaded = config_module.load_config()
        torque_url = config_module.get_top_level_defaults(loaded).get("torque_url")
        config_path = config_module.find_config_file()

        async def run_setup():
            auth_server = auth_module.TorqueAuthServer(
                torque_url=torque_url or None,
                config_path=str(config_path) if config_path else None,
            )
            result = await auth_server.run()
            if result is None:
                print("Setup cancelled.", file=sys.stderr)
                return
            lines = ["\nSetup complete! Configured profile:"]
            lines.extend(_format_profile_entry(result))
            print("\n".join(lines))

        asyncio.run(run_setup())

    if had_error:
        sys.exit(1)


def main():
    """Main entry point - supports both MCP server mode and CLI commands."""
    parser = build_parser()
    args = parser.parse_args()
    # The only place the raw-log mode is ever set (see raw_log.py).
    raw_log.set_mode(args.raw_log)

    # The 'register-mcp-client' subcommand registers this MCP server with AI
    # clients. It does not need Torque config loaded, and handling it early
    # avoids the missing-config warnings below.
    if args.command == "register-mcp-client":
        _handle_register_mcp_client_cli(args)
        return

    # Load config file and store globally for runtime profile resolution
    global _loaded_config, _config_error, _default_profile_warning
    try:
        _loaded_config = config_module.load_config(getattr(args, 'config', None))
    except Exception as e:
        _config_error = f"Failed to load config file: {e}"
        print(f"Warning: {_config_error}. Tools will fail until the config is fixed.", file=sys.stderr)
        _loaded_config = {}
    _warn_removed_config_keys(_loaded_config)

    # Apply config file defaults as base values
    file_defaults = config_module.get_defaults(_loaded_config)

    # Apply startup profile (--profile or default_profile from config) on top of defaults
    startup_profile = getattr(args, 'profile', None)
    is_default_profile = False
    if not startup_profile and _loaded_config:
        startup_profile = config_module.get_default_profile_name(_loaded_config)
        if startup_profile:
            is_default_profile = True
    if startup_profile and _loaded_config:
        try:
            profile_values = config_module.resolve_profile(_loaded_config, startup_profile)
            file_defaults_with_profile = config_module.apply_profile_to_config(file_defaults, profile_values)
        except ValueError as e:
            if is_default_profile:
                _default_profile_warning = f"default_profile in config.yaml: {e}"
                print(f"Warning: {_default_profile_warning}. Tools without explicit profile will fail.", file=sys.stderr)
            else:
                _config_error = f"Profile resolution failed: {e}"
                print(f"Warning: {_config_error}. Tools will fail until the config is fixed.", file=sys.stderr)
            file_defaults_with_profile = file_defaults
    else:
        file_defaults_with_profile = file_defaults
    
    # Update global config: CLI/env args override profile, which overrides file defaults
    # For each config key: use argparse value if set (not None/False for booleans), else file default
    _config["torque_url"] = args.torque_url or file_defaults_with_profile.get("torque_url")
    _config["torque_token"] = args.torque_token or file_defaults_with_profile.get("torque_token")
    _config["torque_space"] = args.torque_space or file_defaults_with_profile.get("torque_space")
    _config["default_agent"] = args.torque_agent or file_defaults_with_profile.get("default_agent")
    # SSH auth mutual exclusion: if CLI specifies one method, don't fall back to the other from file
    cli_ssh_key = args.ssh_key
    cli_ssh_password = args.ssh_password
    if cli_ssh_key and not cli_ssh_password:
        _config["default_ssh_key"] = cli_ssh_key
        _config["default_ssh_password"] = None
    elif cli_ssh_password and not cli_ssh_key:
        _config["default_ssh_password"] = cli_ssh_password
        _config["default_ssh_key"] = None
    else:
        # Both or neither from CLI — use file defaults for any gaps
        _config["default_ssh_key"] = cli_ssh_key or file_defaults_with_profile.get("default_ssh_key")
        _config["default_ssh_password"] = cli_ssh_password or file_defaults_with_profile.get("default_ssh_password")
    _config["default_target_ip"] = args.host or file_defaults_with_profile.get("default_target_ip")
    _config["default_ssh_user"] = args.ssh_user or file_defaults_with_profile.get("default_ssh_user")
    _config["init_commands"] = args.init_commands or file_defaults_with_profile.get("init_commands")
    _config["finally_commands"] = args.finally_commands or file_defaults_with_profile.get("finally_commands")
    # Boolean/numeric: argparse defaults to False/86400, so only override from file if argparse didn't set explicitly
    _config["auto_delete_environments"] = args.auto_delete_environments or file_defaults_with_profile.get("auto_delete_environments", False)
    _config["container_idle_timeout"] = args.container_idle_timeout if args.container_idle_timeout != 86400 else file_defaults_with_profile.get("container_idle_timeout", 86400)
    # No CLI flags for these by design: they are set in the config file or by the setup UI,
    # because enabling credentials is a deliberate per-profile decision rather than a
    # per-invocation one.
    _config["credentials_enabled"] = file_defaults_with_profile.get("credentials_enabled", False)
    _config["credentials_space_policy"] = file_defaults_with_profile.get("credentials_space_policy", "preconfigured")
    # Same reasoning for the croc relay: a per-profile piece of infrastructure,
    # not something to pass on every invocation.
    _config["croc_relay"] = file_defaults_with_profile.get("croc_relay")
    _config["croc_relay_password"] = file_defaults_with_profile.get("croc_relay_password")
    _config["croc_transfers"] = file_defaults_with_profile.get("croc_transfers")

    # Record CLI overrides for hot-reload (these keys won't be changed when config file is reloaded)
    global _cli_overrides, _cli_profile, _config_explicit_path, _config_file_path, _config_file_mtime
    _config_explicit_path = getattr(args, 'config', None)
    _cli_profile = getattr(args, 'profile', None)
    _cli_overrides.clear()
    if args.torque_url: _cli_overrides.add("torque_url")
    if args.torque_token: _cli_overrides.add("torque_token")
    if args.torque_space: _cli_overrides.add("torque_space")
    if args.torque_agent: _cli_overrides.add("default_agent")
    if args.ssh_key or args.ssh_password:
        _cli_overrides.add("default_ssh_key")
        _cli_overrides.add("default_ssh_password")
    if args.host: _cli_overrides.add("default_target_ip")
    if args.ssh_user: _cli_overrides.add("default_ssh_user")
    if args.init_commands: _cli_overrides.add("init_commands")
    if args.finally_commands: _cli_overrides.add("finally_commands")
    if args.auto_delete_environments: _cli_overrides.add("auto_delete_environments")
    if args.container_idle_timeout != 86400: _cli_overrides.add("container_idle_timeout")
    # Track config file for hot-reload watcher
    cfg_path = config_module.find_config_file(_config_explicit_path)
    if cfg_path:
        _config_file_path = cfg_path
        try:
            _config_file_mtime = cfg_path.stat().st_mtime
        except OSError:
            pass
    
    # Warn about missing recommended config (but don't block startup — AI agent can supply at runtime)
    missing = []
    if not _config["torque_url"]:
        missing.append("--torque-url or TORQUE_URL")
    if not _config["torque_token"]:
        missing.append("--torque-token or TORQUE_TOKEN")
    if not _config["torque_space"]:
        missing.append("--torque-space or TORQUE_SPACE")
    if not _config.get("default_agent"):
        missing.append("--torque-agent or TORQUE_AGENT")
    
    if missing:
        print(f"Warning: Missing recommended configuration: {', '.join(missing)}. "
              f"The AI agent can supply these at runtime, but pre-configuring them is recommended.", file=sys.stderr)
    
    # Default to serve mode if no subcommand
    if args.command is None or args.command == "serve":
        # Run as MCP server
        async def run_server():
            watcher = asyncio.create_task(_watch_config_file())
            try:
                async with stdio_server() as (read_stream, write_stream):
                    await server.run(
                        read_stream,
                        write_stream,
                        server.create_initialization_options(),
                    )
            finally:
                watcher.cancel()
                try:
                    await watcher
                except asyncio.CancelledError:
                    pass
        asyncio.run(run_server())
    elif args.command == "profiles":
        # List profiles
        profiles = config_module.list_profiles(_loaded_config)
        if not profiles:
            config_path = config_module.find_config_file(getattr(args, 'config', None))
            if config_path:
                print("No profiles defined in configuration file.", file=sys.stderr)
            else:
                print("No configuration file found. Create ~/.torque-tunnel/config.yaml to define profiles.", file=sys.stderr)
            sys.exit(0)
        for p in profiles:
            desc = f"  {p['description']}" if p['description'] else ""
            extends = f"\n    Extends: {p['extends']}" if p['extends'] else ""
            overrides = ", ".join(p['overrides']) if p['overrides'] else "(none)"
            print(f"  {p['name']:<20}{desc}{extends}\n{'':20}    Overrides: {overrides}\n")
    elif args.command == "setup":
        # Interactive setup
        torque_url = _config.get("torque_url")
        profile_name = getattr(args, 'profile', None)
        if profile_name and _loaded_config:
            try:
                pv = config_module.resolve_profile(_loaded_config, profile_name)
                torque_url = pv.get("torque_url", torque_url)
            except ValueError:
                pass
        config_path = config_module.find_config_file(getattr(args, 'config', None))

        async def run_setup():
            auth_server = auth_module.TorqueAuthServer(
                torque_url=torque_url or None,
                config_path=str(config_path) if config_path else None,
                profile_name=profile_name,
            )
            result = await auth_server.run()
            if result is None:
                print("Setup cancelled.", file=sys.stderr)
                return

            # Build summary using shared formatter (result is a profile dict)
            lines = ["\nSetup complete! Configured profile:"]
            lines.extend(_format_profile_entry(result))
            print("\n".join(lines))

        asyncio.run(run_setup())
    else:
        # CLI mode - run the appropriate command
        asyncio.run(cli_dispatch(args))


if __name__ == "__main__":
    main()
