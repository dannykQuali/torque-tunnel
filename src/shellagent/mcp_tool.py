"""
ShellAgent MCP Tool - Execute remote commands via Torque Shell Grains.

This MCP tool provides Copilot with the ability to run commands on remote servers
by leveraging Torque's Shell Grain infrastructure.
"""

import base64
import gzip
import os
import re
import sys
import asyncio
import argparse
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


def create_log_streamer(session) -> Callable[[str, str], Awaitable[None]]:
    """Create a log callback that streams to stderr and MCP client.
    
    By default, filters output to skip Torque preamble and show only:
    - First line with "Running on" info + environment URL
    - Command output after the execution marker
    
    Use --verbose flag or VERBOSE=true to show full output.
    """
    verbose = _config.get('verbose', False)
    torque_url = _config.get('torque_url', '')
    torque_space = _config.get('torque_space', '')
    
    # State for tracking streaming progress
    state = {'found': verbose, 'first_line_shown': verbose, 'buffer': ''}
    # Marker pattern - matches both "=== Beginning of execution ===" and "=== Beginning of local execution ==="
    # Requires 50+ trailing = chars to avoid false positives from user output
    marker_pattern = re.compile(r'=== Beginning of (?:local )?execution ={50,}\n')
    # Pattern for first line: [HH:MM:SS.mmm] >> Running on container. Storage: . Task Id: XXX
    first_line_pattern = re.compile(r'^(\[\d{2}:\d{2}:\d{2}\.\d{3}\] >> Running on .+)$', re.MULTILINE)
    
    async def stream_log(content: str, environment_id: str = "") -> None:
        try:
            if state['found']:
                # Already past marker - print everything
                print(content, file=sys.stderr, end='', flush=True)
                session.send_log_message(level="info", data=content, logger="shellagent.grain_log")
                return
            
            # Buffer data to handle markers split across chunks
            state['buffer'] += content
            
            # Show first line with environment info if not yet shown
            if not state['first_line_shown']:
                match = first_line_pattern.search(state['buffer'])
                if match:
                    first_line = match.group(1)
                    # Build environment URL
                    env_url = f"{torque_url}/{torque_space}/environments/{environment_id}" if environment_id else ""
                    env_info = f". {env_url}" if environment_id else ""
                    output = f"{first_line}{env_info}\n"
                    print(output, file=sys.stderr, end='', flush=True)
                    session.send_log_message(level="info", data=output, logger="shellagent.grain_log")
                    state['first_line_shown'] = True
            
            # Look for execution marker
            match = marker_pattern.search(state['buffer'])
            if match:
                state['found'] = True
                # Print from after the marker line
                after_marker = state['buffer'][match.end():]
                if after_marker:
                    print(after_marker, file=sys.stderr, end='', flush=True)
                    session.send_log_message(level="info", data=after_marker, logger="shellagent.grain_log")
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
        if pattern in cmd_lower:
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
    Resolve SSH private key from either a file path or key content.
    
    Args:
        value: Either a file path or the key content directly
        
    Returns:
        Normalized SSH private key content
        
    Raises:
        ValueError: If the value is neither a valid file path nor valid key content
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
    
    # Neither a valid file nor valid key content
    raise ValueError(
        f"Invalid private_key: '{value[:50]}{'...' if len(value) > 50 else ''}' "
        f"is not a valid file path and doesn't look like SSH private key content. "
        f"Provide either a path to an existing key file or the key content starting with '-----BEGIN'"
    )


def prepare_files_deployment(files: list[dict]) -> tuple[str, list[str]]:
    """
    Prepare shell commands to deploy files before command execution.
    
    Reads local files/directories and generates shell commands to write them
    on the target system. Files are written BEFORE init_commands run.
    
    Args:
        files: List of file specs, each with:
            - local_path: Path to local file or directory to upload
            - content: Direct content string (alternative to local_path)
            - remote_path: Destination path on target
            - mode: Optional file permissions (e.g., "755")
    
    Returns:
        Tuple of (shell_commands_string, error_messages)
        If errors exist, the shell_commands_string will be empty.
    """
    import tarfile
    import io
    
    if not files:
        return "", []
    
    errors = []
    commands = []
    commands.append("# === File Deployment ===")
    
    for i, file_spec in enumerate(files):
        remote_path = file_spec.get("remote_path")
        local_path = file_spec.get("local_path")
        content = file_spec.get("content")
        mode = file_spec.get("mode")
        
        if not remote_path:
            errors.append(f"File {i+1}: missing 'remote_path'")
            continue
        
        # Escape remote path for shell
        escaped_remote = remote_path.replace("'", "'\\''")
        remote_dir = os.path.dirname(remote_path)
        escaped_dir = remote_dir.replace("'", "'\\''") if remote_dir else ""
        
        # Get content from local_path or direct content
        if local_path and content:
            errors.append(f"File {i+1}: provide either 'local_path' OR 'content', not both")
            continue
        elif not local_path and not content:
            errors.append(f"File {i+1}: must provide either 'local_path' or 'content'")
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


# Global configuration - set via command line args or environment variables
_config = {
    "torque_url": None,
    "torque_token": None,
    "torque_space": None,
    "default_agent": None,
    "default_ssh_key": None,
    "default_target_ip": None,
    "default_ssh_user": None,
    "init_commands": None,
    "finally_commands": None,
    "auto_delete_environments": False,
    "verbose": False,
}


def get_torque_client() -> TorqueClient:
    """Create a Torque client with current configuration."""
    if not _config["torque_url"]:
        raise ValueError("Torque URL not configured. Set TORQUE_URL or use --torque-url")
    if not _config["torque_token"]:
        raise ValueError("Torque token not configured. Set TORQUE_TOKEN or use --torque-token")
    if not _config["torque_space"]:
        raise ValueError("Torque space not configured. Set TORQUE_SPACE or use --torque-space")
    
    return TorqueClient(
        base_url=_config["torque_url"],
        token=_config["torque_token"],
        space=_config["torque_space"],
        default_agent=_config["default_agent"],
        init_commands=_config["init_commands"],
        finally_commands=_config["finally_commands"],
    )


# Create MCP server
server = Server("shellagent")


@server.list_tools()
async def list_tools():
    """List available tools."""
    return [
        Tool(
            name="run_on_ssh",
            description="""Execute a short shell command on a remote server via SSH. This tool BLOCKS until completion.
Use only for commands expected to finish within ~60 seconds (simple checks, echo, cat, ls, short scripts).

For installations, builds, downloads, service restarts, or ANY command that might take more than a minute,
use run_on_ssh_async instead - it returns immediately and lets you poll for progress with get_execution_status.

This tool connects to a remote server using SSH credentials and can:
1. Upload files/directories from your local machine to the remote server
2. Execute shell commands on the remote server
3. Both upload files AND run commands in a single operation (recommended for efficiency)

Execution order: files are deployed FIRST, then init_commands, then main command, then finally_commands.

**CRITICAL WARNING - DANGEROUS COMMANDS:**
The following commands may KILL the Torque agent and cause the operation to fail:
- `docker restart`, `docker stop`, `docker kill` (any container operations that affect the agent)
- `systemctl restart docker` or any Docker daemon restart
- `reboot`, `shutdown`, `init 6`, `init 0`

These commands require MANUAL execution via direct SSH or console access.

**PERFORMANCE TIP:**
Each invocation has significant roundtrip overhead. Consolidate operations:
- Upload files AND run commands in one call
- Chain commands: `cmd1 && cmd2 && cmd3`
- Use the `files` parameter instead of multiple write operations""",
            inputSchema={
                "type": "object",
                "properties": {
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
                        "description": "SSH private key - either a LOCAL file path (e.g., C:\\Users\\you\\.ssh\\id_rsa) OR the key content directly (starting with '-----BEGIN').",
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the remote server. Optional if only uploading files.",
                    },
                    "files": {
                        "type": "array",
                        "description": "Files to upload TO THE REMOTE SERVER before running the command. These are transferred from your local machine to the target server.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_path": {
                                    "type": "string",
                                    "description": "Path on YOUR LOCAL MACHINE to a file/directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct content to write TO THE REMOTE SERVER. Use this OR local_path, not both.",
                                },
                                "remote_path": {
                                    "type": "string",
                                    "description": "Destination path ON THE REMOTE SERVER where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_path"],
                        },
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use. If not specified, uses the default agent.",
                    },
                    "allow_dangerous_commands": {
                        "type": "boolean",
                        "description": "Optional: Set to true to bypass dangerous command warnings. Use with extreme caution.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                    "init_commands": {
                        "type": "string",
                        "description": "Optional: Commands to run after file deployment but before the main command.",
                    },
                    "finally_commands": {
                        "type": "string",
                        "description": "Optional: Cleanup commands that run even if main command fails.",
                    },
                    "auto_delete": {
                        "type": "boolean",
                        "description": "Optional: Whether to automatically delete the Torque environment after completion.",
                    },
                    "torque_token": {
                        "type": "string",
                        "description": "Optional: Torque API token. Overrides global config.",
                    },
                    "torque_url": {
                        "type": "string",
                        "description": "Optional: Torque platform URL. Overrides global config.",
                    },
                    "torque_space": {
                        "type": "string",
                        "description": "Optional: Torque space name. Overrides global config.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="run_on_container",
            description="""Execute a short command on the Torque agent container. This tool BLOCKS until completion.
Use only for commands expected to finish within ~60 seconds.

For long-running commands, use run_on_container_async instead - it returns immediately
and lets you poll for progress with get_execution_status.

This tool runs commands directly on the Torque agent container - NO SSH target needed.
Unlike run_on_ssh, this doesn't connect to a remote server.

**Key difference from run_on_ssh:**
- run_on_ssh: SSH to a remote server (needs host, user, private_key)
- run_on_container: Runs locally on the Torque agent container (no SSH needed)

**Use cases:**
- Run tools/scripts available in the agent environment
- Test network connectivity from the Torque infrastructure
- Upload scripts and run them on the agent
- Build/compile projects in a clean container environment
- Operations that don't require a specific target machine

**Files parameter:**
You can upload files/directories to the agent container and then run commands on them.
This is powerful because files persist for the entire command execution - unlike
separate invocations which would get different containers.

Execution order: files deployed FIRST, then init_commands, then main command.

**PERFORMANCE TIP:**
Each invocation spawns a fresh container. Consolidate operations:
- Upload files AND run commands in one call
- Chain commands: `cmd1 && cmd2 && cmd3`""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the agent container. Optional if only uploading files.",
                    },
                    "files": {
                        "type": "array",
                        "description": "Files to upload TO THE CONTAINER before running the command. These are transferred from your local machine to the target container.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_path": {
                                    "type": "string",
                                    "description": "Path on YOUR LOCAL MACHINE to a file/directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct content to write TO THE CONTAINER. Use this OR local_path, not both.",
                                },
                                "remote_path": {
                                    "type": "string",
                                    "description": "Destination path ON THE CONTAINER where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_path"],
                        },
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use. If not specified, uses the default agent.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time in seconds. Default is 1800 (30 minutes).",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="run_on_ssh_async",
            description="""Execute a command on a remote server via SSH WITHOUT waiting for completion.
Returns immediately with an environment ID. Use get_execution_status to poll for output and progress.

Use this for: package installs (apt/yum/pip), builds, downloads, database migrations,
config management runs, service deployments, or any command where duration is uncertain.
This gives you the ability to provide progress updates to the user while waiting.

Same parameters as run_on_ssh. The command starts executing immediately and you get
the environment ID back to track progress.

**CRITICAL WARNING - DANGEROUS COMMANDS:**
The following commands may KILL the Torque agent and cause the operation to fail:
- `docker restart`, `docker stop`, `docker kill` (any container operations that affect the agent)
- `systemctl restart docker` or any Docker daemon restart
- `reboot`, `shutdown`, `init 6`, `init 0`""",
            inputSchema={
                "type": "object",
                "properties": {
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
                        "description": "SSH private key - either a LOCAL file path OR the key content directly (starting with '-----BEGIN').",
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the remote server.",
                    },
                    "files": {
                        "type": "array",
                        "description": "Files to upload TO THE REMOTE SERVER before running the command.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_path": {
                                    "type": "string",
                                    "description": "Path on YOUR LOCAL MACHINE to a file/directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct content to write TO THE REMOTE SERVER. Use this OR local_path, not both.",
                                },
                                "remote_path": {
                                    "type": "string",
                                    "description": "Destination path ON THE REMOTE SERVER where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_path"],
                        },
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use.",
                    },
                    "allow_dangerous_commands": {
                        "type": "boolean",
                        "description": "Optional: Set to true to bypass dangerous command warnings.",
                    },
                    "init_commands": {
                        "type": "string",
                        "description": "Optional: Commands to run after file deployment but before the main command.",
                    },
                    "finally_commands": {
                        "type": "string",
                        "description": "Optional: Cleanup commands that run even if main command fails.",
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="run_on_container_async",
            description="""Execute a command on the Torque agent container WITHOUT waiting for completion.
Returns immediately with an environment ID. Use get_execution_status to poll for output and progress.

Use this for long-running operations on the agent container. Same as run_on_container
but non-blocking. Track progress with get_execution_status.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the agent container.",
                    },
                    "files": {
                        "type": "array",
                        "description": "Files to upload TO THE CONTAINER before running the command.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "local_path": {
                                    "type": "string",
                                    "description": "Path on YOUR LOCAL MACHINE to a file/directory to upload. Use this OR content, not both.",
                                },
                                "content": {
                                    "type": "string",
                                    "description": "Direct content to write TO THE CONTAINER. Use this OR local_path, not both.",
                                },
                                "remote_path": {
                                    "type": "string",
                                    "description": "Destination path ON THE CONTAINER where the file will be written.",
                                },
                                "mode": {
                                    "type": "string",
                                    "description": "Optional file permissions (e.g., '755' for executable).",
                                },
                            },
                            "required": ["remote_path"],
                        },
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use.",
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="get_execution_status",
            description="""Check the status and output of an async command started with run_on_ssh_async or run_on_container_async.

Returns the current status (running/completed/failed), partial output if still running,
or full output if completed. Use the `wait` parameter to avoid tight polling loops.

Typical usage pattern:
1. Call run_on_ssh_async or run_on_container_async to start a command
2. Call get_execution_status with wait=10 to check after 10 seconds
3. If still running, call again with wait=10-15
4. When completed, get the full output""",
            inputSchema={
                "type": "object",
                "properties": {
                    "environment_id": {
                        "type": "string",
                        "description": "The environment ID returned by run_on_ssh_async or run_on_container_async.",
                    },
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
            description="""Cancel a running async command started with run_on_ssh_async or run_on_container_async.

Terminates the Torque environment, stopping the command. Use this when:
- A command is taking too long and you want to abort
- You started the wrong command
- The partial output shows the command is failing and there's no point waiting

The environment will be terminated and cleaned up.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "environment_id": {
                        "type": "string",
                        "description": "The environment ID returned by run_on_ssh_async or run_on_container_async.",
                    },
                },
                "required": ["environment_id"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Handle tool calls."""
    
    if name == "run_on_ssh":
        return await handle_run_on_ssh(arguments)
    
    elif name == "run_on_container":
        return await handle_run_on_container(arguments)
    
    elif name == "run_on_ssh_async":
        return await handle_run_on_ssh_async(arguments)
    
    elif name == "run_on_container_async":
        return await handle_run_on_container_async(arguments)
    
    elif name == "get_execution_status":
        return await handle_get_execution_status(arguments)
    
    elif name == "cancel_execution":
        return await handle_cancel_execution(arguments)
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def handle_run_on_ssh(arguments: dict):
    """Execute a remote command via SSH, optionally uploading files first."""
    target_ip = arguments.get("host") or _config["default_target_ip"]
    ssh_user = arguments.get("user") or _config["default_ssh_user"]
    private_key_value = arguments.get("private_key") or _config["default_ssh_key"]
    command = arguments.get("command")
    files = arguments.get("files", [])
    agent = arguments.get("agent")
    allow_dangerous_commands = arguments.get("allow_dangerous_commands", False)
    timeout = arguments.get("timeout")  # Optional timeout override
    init_commands = arguments.get("init_commands")  # Per-call init commands
    finally_commands = arguments.get("finally_commands")  # Per-call finally commands
    # Per-call auto_delete overrides global config if specified
    auto_delete = arguments.get("auto_delete")
    if auto_delete is None:
        auto_delete = _config["auto_delete_environments"]
    
    # Per-call Torque config overrides
    torque_url = arguments.get("torque_url") or _config["torque_url"]
    torque_token = arguments.get("torque_token") or _config["torque_token"]
    torque_space = arguments.get("torque_space") or _config["torque_space"]
    
    # Must have at least command OR files
    if not command and not files:
        return [TextContent(
            type="text",
            text="Error: Must provide either 'command' or 'files' (or both).",
        )]
    
    if not all([target_ip, ssh_user, private_key_value]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need host, user, private_key (or configure defaults).",
        )]
    
    if not all([torque_url, torque_token, torque_space]):
        return [TextContent(
            type="text",
            text="Error: Torque configuration missing. Need torque_url, torque_token, and torque_space (or configure defaults).",
        )]
    
    # Check for dangerous commands unless allow_dangerous_commands=true
    if command and not allow_dangerous_commands:
        warning = check_dangerous_command(command)
        if warning:
            return [TextContent(type="text", text=warning)]
    
    try:
        ssh_private_key = resolve_ssh_private_key(private_key_value)
    except ValueError as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    # Process files parameter - generate deployment commands
    files_info = []
    if files:
        file_deploy_commands, file_errors = prepare_files_deployment(files)
        if file_errors:
            return [TextContent(
                type="text",
                text="Error preparing files:\n" + "\n".join(f"- {e}" for e in file_errors),
            )]
        # Prepend file deployment to init_commands (files run BEFORE init)
        if file_deploy_commands:
            if init_commands:
                init_commands = file_deploy_commands + "\n" + init_commands
            else:
                init_commands = file_deploy_commands
        # Track files for output reporting
        for f in files:
            local = f.get("local_path", "<content>")
            remote = f.get("remote_path", "")
            files_info.append(f"{local} -> {remote}")
    
    # If no command, use a simple echo
    effective_command = command or "echo 'Files deployed successfully'"
    
    # Create log streamer for real-time output
    log_callback = None
    try:
        session = server.request_context.session
        log_callback = create_log_streamer(session)
    except Exception:
        pass  # Streaming not available
    
    try:
        # Create client with per-call or global config
        client = TorqueClient(
            base_url=torque_url,
            token=torque_token,
            space=torque_space,
            default_agent=_config["default_agent"],
            init_commands=_config["init_commands"],
            finally_commands=_config["finally_commands"],
        )
        async with client:
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
                finally_commands=finally_commands,
            )
            
            # Try to get grain log for additional context (especially useful on failures)
            grain_log = None
            try:
                grain_log = await client.get_grain_log(result.environment_id)
            except Exception:
                pass
        
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
            files_summary = "\n**Files Deployed:**\n" + "\n".join(f"- {f}" for f in files_info) + "\n"
        
        if result.status == "completed":
            output_block = format_code_block(result.command_output)
            output_text = f"""Command executed successfully on {target_ip}
{files_summary}
**Exit Code:** {result.exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
        else:
            output_text = f"""Command execution failed on {target_ip}
{files_summary}
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
                log_block = format_code_block(grain_log)
                output_text += f"""

**Grain Execution Log:**
{log_block}"""
        
        # Add tip if command took >60s
        if result.execution_duration is not None and result.execution_duration > 60:
            output_text += "\n\n**TIP:** This command took over 60 seconds. Consider using `run_on_ssh_async` for similar long-running commands to get progress updates while waiting."
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error executing remote command: {str(e)}")]


async def handle_run_on_container(arguments: dict):
    """Execute a command on a Torque agent container, optionally uploading files first."""
    command = arguments.get("command")
    files = arguments.get("files", [])
    agent = arguments.get("agent")
    timeout = arguments.get("timeout")  # Optional timeout override
    
    # Must have at least command OR files
    if not command and not files:
        return [TextContent(
            type="text",
            text="Error: Must provide either 'command' or 'files' (or both).",
        )]
    
    # Process files parameter - generate deployment commands
    files_info = []
    init_commands = None
    if files:
        file_deploy_commands, file_errors = prepare_files_deployment(files)
        if file_errors:
            return [TextContent(
                type="text",
                text="Error preparing files:\n" + "\n".join(f"- {e}" for e in file_errors),
            )]
        if file_deploy_commands:
            init_commands = file_deploy_commands
        # Track files for output reporting
        for f in files:
            local = f.get("local_path", "<content>")
            remote = f.get("remote_path", "")
            files_info.append(f"{local} -> {remote}")
    
    # If no command, use a simple echo
    effective_command = command or "echo 'Files deployed successfully'"
    
    # Create log streamer for real-time output
    log_callback = None
    try:
        session = server.request_context.session
        log_callback = create_log_streamer(session)
    except Exception:
        pass  # Streaming not available
    
    try:
        async with get_torque_client() as client:
            result = await client.execute_local_command(
                command=effective_command,
                agent=agent,
                timeout=timeout,
                auto_cleanup=_config["auto_delete_environments"],
                log_callback=log_callback,
                init_commands=init_commands,
            )
            
            # Try to get grain log for additional context (especially useful on failures)
            grain_log = None
            try:
                grain_log = await client.get_grain_log(result.environment_id)
            except Exception:
                pass
        
        # Format execution duration
        if result.execution_duration is not None:
            duration = result.execution_duration
            duration_str = f"{int(duration // 60)}m {duration % 60:.1f}s" if duration >= 60 else f"{duration:.1f}s"
        else:
            duration_str = "N/A"
        
        # Build environment URL for reference
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{result.environment_id}"
        agent_name = agent or _config["default_agent"]
        
        # Build files summary if any were uploaded
        files_summary = ""
        if files_info:
            files_summary = "\n**Files Deployed:**\n" + "\n".join(f"- {f}" for f in files_info) + "\n"
        
        if result.status == "completed":
            output_block = format_code_block(result.command_output)
            output_text = f"""Command executed successfully on agent `{agent_name}`
{files_summary}
**Exit Code:** {result.exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
        else:
            output_text = f"""Command execution failed on agent `{agent_name}`
{files_summary}
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
                log_block = format_code_block(grain_log)
                output_text += f"""

**Grain Execution Log:**
{log_block}"""
        
        # Add tip if command took >60s
        if result.execution_duration is not None and result.execution_duration > 60:
            output_text += "\n\n**TIP:** This command took over 60 seconds. Consider using `run_on_container_async` for similar long-running commands to get progress updates while waiting."
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error executing command on agent: {str(e)}")]


async def handle_run_on_ssh_async(arguments: dict):
    """Start a remote SSH command without waiting for completion."""
    target_ip = arguments.get("host") or _config["default_target_ip"]
    ssh_user = arguments.get("user") or _config["default_ssh_user"]
    private_key_value = arguments.get("private_key") or _config["default_ssh_key"]
    command = arguments.get("command")
    files = arguments.get("files", [])
    agent = arguments.get("agent")
    allow_dangerous_commands = arguments.get("allow_dangerous_commands", False)
    init_commands = arguments.get("init_commands")
    finally_commands = arguments.get("finally_commands")
    
    if not command and not files:
        return [TextContent(type="text", text="Error: Must provide either 'command' or 'files' (or both).")]
    
    if not all([target_ip, ssh_user, private_key_value]):
        return [TextContent(type="text", text="Error: Missing required parameters. Need host, user, private_key (or configure defaults).")]
    
    # Check for dangerous commands
    if command and not allow_dangerous_commands:
        warning = check_dangerous_command(command)
        if warning:
            return [TextContent(type="text", text=warning)]
    
    try:
        ssh_private_key = resolve_ssh_private_key(private_key_value)
    except ValueError as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    # Process files
    files_info = []
    if files:
        file_deploy_commands, file_errors = prepare_files_deployment(files)
        if file_errors:
            return [TextContent(type="text", text="Error preparing files:\n" + "\n".join(f"- {e}" for e in file_errors))]
        if file_deploy_commands:
            init_commands = (file_deploy_commands + "\n" + init_commands) if init_commands else file_deploy_commands
        for f in files:
            files_info.append(f"{f.get('local_path', '<content>')} -> {f.get('remote_path', '')}")
    
    effective_command = command or "echo 'Files deployed successfully'"
    
    try:
        async with get_torque_client() as client:
            environment_id = await client.start_environment(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=effective_command,
                agent=agent,
                init_commands=init_commands,
                finally_commands=finally_commands,
            )
        
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{environment_id}"
        
        files_summary = ""
        if files_info:
            files_summary = "\n**Files Queued:**\n" + "\n".join(f"- {f}" for f in files_info) + "\n"
        
        # Suggest appropriate wait time based on command content
        suggested_wait = _suggest_wait_time(effective_command)
        
        output_text = f"""Command started on {target_ip} (async)
{files_summary}
**Environment ID:** {environment_id}
**Environment:** {env_url}

Use `get_execution_status` with environment_id="{environment_id}" to check progress (suggested initial wait={suggested_wait}, adjust as needed)."""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error starting async command: {str(e)}")]


async def handle_run_on_container_async(arguments: dict):
    """Start a container command without waiting for completion."""
    command = arguments.get("command")
    files = arguments.get("files", [])
    agent = arguments.get("agent")
    
    if not command and not files:
        return [TextContent(type="text", text="Error: Must provide either 'command' or 'files' (or both).")]
    
    # Process files
    files_info = []
    init_commands = None
    if files:
        file_deploy_commands, file_errors = prepare_files_deployment(files)
        if file_errors:
            return [TextContent(type="text", text="Error preparing files:\n" + "\n".join(f"- {e}" for e in file_errors))]
        if file_deploy_commands:
            init_commands = file_deploy_commands
        for f in files:
            files_info.append(f"{f.get('local_path', '<content>')} -> {f.get('remote_path', '')}")
    
    effective_command = command or "echo 'Files deployed successfully'"
    
    try:
        async with get_torque_client() as client:
            environment_id = await client.start_local_environment(
                command=effective_command,
                agent=agent,
                init_commands=init_commands,
            )
        
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{environment_id}"
        agent_name = agent or _config["default_agent"]
        
        files_summary = ""
        if files_info:
            files_summary = "\n**Files Queued:**\n" + "\n".join(f"- {f}" for f in files_info) + "\n"
        
        suggested_wait = _suggest_wait_time(effective_command)
        
        output_text = f"""Command started on agent `{agent_name}` (async)
{files_summary}
**Environment ID:** {environment_id}
**Environment:** {env_url}

Use `get_execution_status` with environment_id="{environment_id}" to check progress (suggested initial wait={suggested_wait}, adjust as needed)."""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error starting async command: {str(e)}")]


async def handle_get_execution_status(arguments: dict):
    """Check status of an async execution."""
    environment_id = arguments.get("environment_id")
    wait_seconds = arguments.get("wait", 5)
    
    if not environment_id:
        return [TextContent(type="text", text="Error: environment_id is required.")]
    
    # Wait before checking
    if wait_seconds > 0:
        await asyncio.sleep(wait_seconds)
    
    try:
        async with get_torque_client() as client:
            env_data = await client.get_environment_status(environment_id)
            
            details = env_data.get("details", {})
            raw_status = details.get("computed_status") or env_data.get("computed_status") or env_data.get("status", "unknown")
            status = raw_status.lower().replace(" ", "_")
            
            env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{environment_id}"
            
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
                output_text = f"""Command completed.

**Status:** COMPLETED
**Exit Code:** {exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
                
                # Tip for fast commands
                if duration is not None and duration < 10:
                    output_text += "\n\n**TIP:** This command completed in under 10 seconds. For quick commands like this, `run_on_ssh` or `run_on_container` provides simpler one-shot execution without polling."
                
                # Auto-cleanup
                try:
                    await client.end_environment(environment_id)
                    if _config["auto_delete_environments"]:
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
                    output_text = f"""Command completed.

**Status:** COMPLETED
**Exit Code:** {exit_code}

**Output:**
{output_block}

**Duration:** {duration_str}

**Environment:** {env_url}"""
                    
                    # Auto-cleanup
                    if _config["auto_delete_environments"]:
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
                    if grain_log:
                        log_block = format_code_block(grain_log[-2000:])  # Last 2000 chars
                        output_text += f"""

**Grain Execution Log (tail):**
{log_block}"""
                except Exception:
                    pass
                
                return [TextContent(type="text", text=output_text)]
            
            # Cancelled/released
            elif status in ("released", "cancelled", "terminating", "force_terminated"):
                partial_output = ""
                try:
                    grain_log = await client.get_grain_log(environment_id) or ""
                    output_marker_pattern = re.compile(r'=== Beginning of (?:local )?execution ={50,}\n')
                    timestamp_pattern = re.compile(r'^\[\d{2}:\d{2}:\d{2}\.\d{3}\] ', re.MULTILINE)
                    marker_match = output_marker_pattern.search(grain_log)
                    if marker_match:
                        partial_output = grain_log[marker_match.end():]
                    else:
                        partial_output = grain_log[-1000:] if len(grain_log) > 1000 else grain_log
                    partial_output = timestamp_pattern.sub('', partial_output)
                except Exception:
                    pass
                
                output_text = f"""Execution was cancelled.

**Status:** CANCELLED
**Environment:** {env_url}"""
                
                if partial_output.strip():
                    partial_block = format_code_block(partial_output)
                    output_text += f"""

**Output before cancellation:**
{partial_block}"""
                
                # Auto-cleanup
                if _config["auto_delete_environments"]:
                    try:
                        await client.delete_environment(environment_id)
                    except Exception:
                        pass
                
                return [TextContent(type="text", text=output_text)]
            
            # Still running - get partial output
            else:
                partial_output = ""
                try:
                    grain_log = await client.get_grain_log(environment_id) or ""
                    output_marker_pattern = re.compile(r'=== Beginning of (?:local )?execution ={50,}\n')
                    timestamp_pattern = re.compile(r'^\[\d{2}:\d{2}:\d{2}\.\d{3}\] ', re.MULTILINE)
                    marker_match = output_marker_pattern.search(grain_log)
                    if marker_match:
                        partial_output = grain_log[marker_match.end():]
                    else:
                        partial_output = grain_log[-1000:] if len(grain_log) > 1000 else grain_log
                    partial_output = timestamp_pattern.sub('', partial_output)
                except Exception:
                    pass
                
                output_text = f"""Command is still running.

**Status:** RUNNING
**Environment:** {env_url}"""
                
                if partial_output.strip():
                    partial_block = format_code_block(partial_output)
                    output_text += f"""

**Partial Output (so far):**
{partial_block}"""
                
                output_text += f"""

Call `get_execution_status` again with environment_id="{environment_id}" and wait=10 to check progress."""
                
                return [TextContent(type="text", text=output_text)]
    
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return [TextContent(type="text", text=f"Error: Environment {environment_id} not found. It may have been deleted or the ID is incorrect.")]
        return [TextContent(type="text", text=f"Error checking execution status: {str(e)}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error checking execution status: {str(e)}")]


async def handle_cancel_execution(arguments: dict):
    """Cancel a running async execution."""
    environment_id = arguments.get("environment_id")
    
    if not environment_id:
        return [TextContent(type="text", text="Error: environment_id is required.")]
    
    try:
        async with get_torque_client() as client:
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
            
            env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{environment_id}"
            
            # Already fully terminated - nothing to cancel
            if status in ("ended", "inactive", "terminated", "released", "cancelled"):
                # Still respect auto-delete
                if _config["auto_delete_environments"]:
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
            if _config["auto_delete_environments"]:
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
    
    verbose = getattr(args, 'verbose', False)
    torque_url = _config.get('torque_url', '')
    torque_space = _config.get('torque_space', '')
    
    def cli_log_callback(content: str):
        """Simple callback that prints to stderr for CLI streaming."""
        # State for tracking streaming progress
        # - found: whether we've passed the execution marker (verbose=True skips filtering)
        # - first_line_shown: whether we've printed the "Running on" header line
        # - buffer: accumulated data for finding markers
        state = {'found': verbose, 'first_line_shown': verbose, 'buffer': ''}
        # Marker pattern - matches both "=== Beginning of execution ===" and "=== Beginning of local execution ==="
        # Requires 50+ trailing = chars to avoid false positives from user output
        marker_pattern = re.compile(r'=== Beginning of (?:local )?execution ={50,}\n')
        # Pattern for first line: [HH:MM:SS.mmm] >> Running on container. Storage: . Task Id: XXX
        first_line_pattern = re.compile(r'^(\[\d{2}:\d{2}:\d{2}\.\d{3}\] >> Running on .+)$', re.MULTILINE)
        
        async def _stream(data: str, environment_id: str = ""):
            if state['found']:
                # Already past marker - print everything
                print(data, file=sys.stderr, end='', flush=True)
                return
            
            # Buffer data to handle markers split across chunks
            state['buffer'] += data
            
            # Show first line with environment info if not yet shown
            if not state['first_line_shown']:
                match = first_line_pattern.search(state['buffer'])
                if match:
                    first_line = match.group(1)
                    # Build environment URL
                    env_url = f"{torque_url}/{torque_space}/environments/{environment_id}" if environment_id else ""
                    env_info = f". {env_url}" if environment_id else ""
                    print(f"{first_line}{env_info}\n", file=sys.stderr, end='', flush=True)
                    state['first_line_shown'] = True
            
            # Look for execution marker
            match = marker_pattern.search(state['buffer'])
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
                'local_path': parts[0],
                'remote_path': parts[1],
            }
            if len(parts) >= 3:
                file_spec['mode'] = parts[2]
            files.append(file_spec)
        return files
    
    try:
        if args.command == "ssh":
            # SSH command execution (with optional file uploads)
            target_ip = _config["default_target_ip"]
            ssh_user = getattr(args, 'user', None) or _config["default_ssh_user"]
            ssh_key_path = getattr(args, 'key', None) or _config["default_ssh_key"]
            agent = getattr(args, 'agent', None)
            timeout = getattr(args, 'timeout', None)
            allow_dangerous_commands = getattr(args, 'allow_dangerous_commands', False)
            output_json = getattr(args, 'json', False)
            uploads = parse_uploads(getattr(args, 'upload', None))
            cmd = getattr(args, 'cmd', None)
            
            # Must have command or uploads
            if not cmd and not uploads:
                print("Error: Must provide a command or --upload files (or both).", file=sys.stderr)
                sys.exit(1)
            
            if not all([target_ip, ssh_user, ssh_key_path]):
                print("Error: Missing host, user, or SSH key. Use --host, --user, --key or set defaults.", file=sys.stderr)
                sys.exit(1)
            
            # Check dangerous commands
            if cmd and not allow_dangerous_commands:
                warning = check_dangerous_command(cmd)
                if warning:
                    print(warning, file=sys.stderr)
                    sys.exit(2)
            
            try:
                ssh_key = resolve_ssh_private_key(ssh_key_path)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            
            # Process file uploads
            init_commands = None
            if uploads:
                file_deploy_commands, file_errors = prepare_files_deployment(uploads)
                if file_errors:
                    print("Error preparing files:", file=sys.stderr)
                    for e in file_errors:
                        print(f"  - {e}", file=sys.stderr)
                    sys.exit(1)
                if file_deploy_commands:
                    init_commands = file_deploy_commands
            
            effective_command = cmd or "echo 'Files deployed successfully'"
            
            async with get_torque_client() as client:
                result = await client.execute_remote_command(
                    target_ip=target_ip,
                    ssh_user=ssh_user,
                    ssh_private_key=ssh_key,
                    command=effective_command,
                    agent=agent,
                    timeout=timeout,
                    auto_cleanup=_config["auto_delete_environments"],
                    log_callback=cli_log_callback(""),
                    init_commands=init_commands,
                )
            
            if output_json:
                print(json_module.dumps({
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "output": result.command_output,
                    "error": result.error,
                    "environment_id": result.environment_id,
                }))
            else:
                if result.status == "completed":
                    print(result.command_output or "", end='')
                    sys.exit(result.exit_code or 0)
                else:
                    print(f"Error: {result.error}", file=sys.stderr)
                    sys.exit(1)
        
        elif args.command == "container":
            # Container command (with optional file uploads)
            agent = getattr(args, 'agent', None)
            timeout = getattr(args, 'timeout', None)
            output_json = getattr(args, 'json', False)
            uploads = parse_uploads(getattr(args, 'upload', None))
            cmd = getattr(args, 'cmd', None)
            
            # Must have command or uploads
            if not cmd and not uploads:
                print("Error: Must provide a command or --upload files (or both).", file=sys.stderr)
                sys.exit(1)
            
            # Process file uploads
            init_commands = None
            if uploads:
                file_deploy_commands, file_errors = prepare_files_deployment(uploads)
                if file_errors:
                    print("Error preparing files:", file=sys.stderr)
                    for e in file_errors:
                        print(f"  - {e}", file=sys.stderr)
                    sys.exit(1)
                if file_deploy_commands:
                    init_commands = file_deploy_commands
            
            effective_command = cmd or "echo 'Files deployed successfully'"
            
            async with get_torque_client() as client:
                result = await client.execute_local_command(
                    command=effective_command,
                    agent=agent,
                    timeout=timeout,
                    auto_cleanup=_config["auto_delete_environments"],
                    log_callback=cli_log_callback(""),
                    init_commands=init_commands,
                )
            
            if output_json:
                print(json_module.dumps({
                    "status": result.status,
                    "exit_code": result.exit_code,
                    "output": result.command_output,
                    "error": result.error,
                    "environment_id": result.environment_id,
                }))
            else:
                if result.status == "completed":
                    print(result.command_output or "", end='')
                    sys.exit(result.exit_code or 0)
                else:
                    print(f"Error: {result.error}", file=sys.stderr)
                    sys.exit(1)
        
        elif args.command == "read":
            # Read remote file
            target_ip = _config["default_target_ip"]
            ssh_user = getattr(args, 'user', None) or _config["default_ssh_user"]
            ssh_key_path = getattr(args, 'key', None) or _config["default_ssh_key"]
            agent = getattr(args, 'agent', None)
            timeout = getattr(args, 'timeout', None)
            max_size = getattr(args, 'max_size', 102400)
            
            if not all([target_ip, ssh_user, ssh_key_path]):
                print("Error: Missing target, user, or SSH key.", file=sys.stderr)
                sys.exit(1)
            
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
            agent = getattr(args, 'agent', None)
            timeout = getattr(args, 'timeout', None)
            show_all = getattr(args, 'all', False)
            long_format = getattr(args, 'long', False)
            
            if not all([target_ip, ssh_user, ssh_key_path]):
                print("Error: Missing target, user, or SSH key.", file=sys.stderr)
                sys.exit(1)
            
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


def main():
    """Main entry point - supports both MCP server mode and CLI commands."""
    
    # Common arguments parser
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "--torque-url",
        default=os.environ.get("TORQUE_URL"),
        help="Torque base URL (default: $TORQUE_URL)",
    )
    common_parser.add_argument(
        "--torque-token",
        default=os.environ.get("TORQUE_TOKEN"),
        help="Torque API token (default: $TORQUE_TOKEN)",
    )
    common_parser.add_argument(
        "--torque-space",
        default=os.environ.get("TORQUE_SPACE"),
        help="Torque space name (default: $TORQUE_SPACE)",
    )
    common_parser.add_argument(
        "--torque-agent",
        default=os.environ.get("TORQUE_AGENT"),
        help="Default Torque agent name (default: $TORQUE_AGENT)",
    )
    common_parser.add_argument(
        "--ssh-key",
        default=os.environ.get("SSH_KEY"),
        help="SSH private key - file path or key content (env: $SSH_KEY)",
    )
    common_parser.add_argument(
        "--host",
        default=os.environ.get("TARGET_HOST"),
        help="Target server IP/hostname (env: $TARGET_HOST)",
    )
    common_parser.add_argument(
        "--ssh-user",
        default=os.environ.get("SSH_USER"),
        help="SSH username (env: $SSH_USER)",
    )
    common_parser.add_argument(
        "--init-commands",
        default=os.environ.get("INIT_COMMANDS"),
        help="Commands to run before every SSH command",
    )
    common_parser.add_argument(
        "--finally-commands",
        default=os.environ.get("FINALLY_COMMANDS"),
        help="Commands to run after every SSH command",
    )
    common_parser.add_argument(
        "--auto-delete-environments",
        action="store_true",
        default=os.environ.get("AUTO_DELETE_ENVIRONMENTS", "").lower() in ("true", "1", "yes"),
        help="Automatically delete environments after completion",
    )
    common_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full output including Torque preamble (default: skip to '=== Beginning of execution ===' marker)",
    )
    
    # Main parser with subcommands - also inherits common args for when no subcommand is given
    parser = argparse.ArgumentParser(
        parents=[common_parser],
        description="ShellAgent - Execute remote commands via Torque (MCP server or CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  serve (default)  Run as MCP server (for VS Code Copilot)
  ssh              Execute a command on a remote target server via SSH
  container        Execute a command on the Torque agent container itself
  read             Read a file from a remote server
  list             List a directory on a remote server

Examples:
  # Run as MCP server (for VS Code)
  shellagent serve

  # CLI mode - run a command on a remote server
  shellagent ssh "uname -a"
  shellagent ssh --host 10.0.0.1 --user root "df -h"

  # CLI mode - upload files and run a command on remote server
  shellagent ssh --upload ./script.sh:/tmp/script.sh:755 "bash /tmp/script.sh"
  shellagent ssh --upload ./config.yaml:/etc/app/config.yaml --upload ./data:/var/data "cat /etc/app/config.yaml"

  # CLI mode - run on the Torque agent container directly
  shellagent container "curl https://example.com"
  shellagent container --upload ./test.py:/tmp/test.py "python /tmp/test.py"

  # CLI mode - read/list files
  shellagent read /etc/hostname
  shellagent list /var/log

Environment Variables:
  TORQUE_URL, TORQUE_TOKEN, TORQUE_SPACE, TORQUE_AGENT
  SSH_KEY, TARGET_HOST, SSH_USER

UPLOAD FORMAT:
  --upload LOCAL:REMOTE[:MODE]
  LOCAL  = path to local file or directory
  REMOTE = destination path on target
  MODE   = optional file permissions (e.g., 755) - default: 644 for files
  Directories are transferred via tar archive.

DANGEROUS COMMANDS (may kill the Torque agent):
  docker restart, docker stop, docker kill, docker rm
  systemctl restart docker, systemctl stop docker
  service docker restart, service docker stop
  reboot, shutdown, init 0, init 6, poweroff, halt
  Use --allow-dangerous-commands to bypass (NOT RECOMMENDED), or run manually via SSH.

LONG-RUNNING COMMANDS:
  Default timeout is 30 minutes. Use --timeout to extend.
  For very long operations, run in background:
    shellagent ssh "nohup command > /tmp/output.log 2>&1 &"
  Then check status:
    shellagent ssh "cat /tmp/output.log"

PERFORMANCE TIP:
  Each command invocation has significant roundtrip overhead
  (environment provisioning, SSH connection, etc.).
  Consolidate multiple commands into a single invocation:
    shellagent ssh "cmd1; cmd2; cmd3"           # sequential
    shellagent ssh "cmd1 && cmd2 && cmd3"       # stop on failure
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # serve subcommand (MCP server mode)
    subparsers.add_parser("serve", parents=[common_parser], help="Run as MCP server")
    
    # ssh subcommand (remote command via SSH)
    ssh_parser = subparsers.add_parser("ssh", parents=[common_parser], help="Execute a command on remote server via SSH")
    ssh_parser.add_argument("cmd", nargs='?', help="The shell command to execute (optional if --upload used)")
    ssh_parser.add_argument("--user", "-u", help="SSH username (overrides --ssh-user)")
    ssh_parser.add_argument("--key", "-k", help="SSH private key - file path or key content (overrides --ssh-key)")
    ssh_parser.add_argument("--agent", "-a", help="Torque agent name (overrides default)")
    ssh_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    ssh_parser.add_argument("--allow-dangerous-commands", action="store_true", help="Bypass dangerous command warnings (use with extreme caution)")
    ssh_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    ssh_parser.add_argument("--upload", action="append", metavar="LOCAL:REMOTE[:MODE]",
                              help="Upload local file/dir to remote path (can be repeated)")
    
    # container subcommand (run on Torque agent container)
    container_parser = subparsers.add_parser("container", parents=[common_parser], help="Execute a command on Torque agent container")
    container_parser.add_argument("cmd", nargs='?', help="The shell command to execute (optional if --upload used)")
    container_parser.add_argument("--agent", "-a", help="Torque agent name (overrides default)")
    container_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    container_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    container_parser.add_argument("--upload", action="append", metavar="LOCAL:REMOTE[:MODE]",
                             help="Upload local file/dir to container (can be repeated)")
    
    # read subcommand
    read_parser = subparsers.add_parser("read", parents=[common_parser], help="Read a file from remote server")
    read_parser.add_argument("path", help="Remote file path to read")
    read_parser.add_argument("--user", "-u", help="SSH username")
    read_parser.add_argument("--key", "-k", help="SSH private key - file path or key content")
    read_parser.add_argument("--agent", "-a", help="Torque agent name")
    read_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    read_parser.add_argument("--max-size", type=int, default=102400, help="Max file size in bytes (default: 100KB)")
    
    # list subcommand
    list_parser = subparsers.add_parser("list", parents=[common_parser], help="List a directory on remote server")
    list_parser.add_argument("path", help="Remote directory path")
    list_parser.add_argument("--user", "-u", help="SSH username")
    list_parser.add_argument("--key", "-k", help="SSH private key - file path or key content")
    list_parser.add_argument("--agent", "-a", help="Torque agent name")
    list_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    list_parser.add_argument("--all", "-A", action="store_true", help="Show hidden files")
    list_parser.add_argument("--long", "-l", action="store_true", help="Long format with details")
    
    args = parser.parse_args()
    
    # Update global config from common args
    _config["torque_url"] = args.torque_url
    _config["torque_token"] = args.torque_token
    _config["torque_space"] = args.torque_space
    _config["default_agent"] = args.torque_agent
    _config["default_ssh_key"] = args.ssh_key
    _config["default_target_ip"] = args.host
    _config["default_ssh_user"] = args.ssh_user
    _config["init_commands"] = args.init_commands
    _config["finally_commands"] = args.finally_commands
    _config["auto_delete_environments"] = args.auto_delete_environments
    _config["verbose"] = args.verbose
    
    # Validate required config
    missing = []
    if not _config["torque_url"]:
        missing.append("--torque-url or TORQUE_URL")
    if not _config["torque_token"]:
        missing.append("--torque-token or TORQUE_TOKEN")
    if not _config["torque_space"]:
        missing.append("--torque-space or TORQUE_SPACE")
    
    if missing:
        print(f"Error: Missing required configuration: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)
    
    # Default to serve mode if no subcommand
    if args.command is None or args.command == "serve":
        # Run as MCP server
        async def run_server():
            async with stdio_server() as (read_stream, write_stream):
                await server.run(
                    read_stream,
                    write_stream,
                    server.create_initialization_options(),
                )
        asyncio.run(run_server())
    else:
        # CLI mode - run the appropriate command
        asyncio.run(cli_dispatch(args))


if __name__ == "__main__":
    main()
