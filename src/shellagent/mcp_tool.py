"""
ShellAgent MCP Tool - Execute remote commands via Torque Shell Grains.

This MCP tool provides Copilot with the ability to run commands on remote servers
by leveraging Torque's Shell Grain infrastructure.
"""

import base64
import os
import re
import sys
import asyncio
import argparse
from typing import Optional, Callable, Awaitable

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
    LoggingLevel,
)

from .torque_client import TorqueClient


def create_log_streamer(session) -> Callable[[str], Awaitable[None]]:
    """Create a log callback that streams to stderr and MCP client."""
    async def stream_log(content: str) -> None:
        try:
            # Print the actual log content to stderr for visibility in MCP output panel
            print(content, file=sys.stderr, end='', flush=True)
            # Also send via MCP logging notification (for future VS Code support)
            session.send_log_message(
                level="info",
                data=content,
                logger="shellagent.grain_log"
            )
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

If you still want to proceed (NOT RECOMMENDED), call this tool again with the parameter `force=true`.

Reason: The Torque Docker Agent executes commands on the remote server. Restarting Docker or the agent container will terminate the agent mid-execution, causing an unrecoverable error."""
    return None


def read_ssh_key_file(file_path: str) -> str:
    """Read SSH private key from a file path."""
    expanded_path = os.path.expanduser(file_path)
    
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"SSH private key file not found: {file_path}")
    
    with open(expanded_path, 'r') as f:
        return f.read()


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
            name="run_remote_command",
            description="""Execute a shell command on a remote server via SSH.

This tool connects to a remote server using SSH credentials and executes the specified command.
The command is executed through Torque's Shell Grain infrastructure (a Docker-based agent).

Use this tool when you need to:
- Troubleshoot a remote server
- Check system status (disk space, memory, processes, etc.)
- View log files
- Run diagnostic commands
- Execute administrative tasks

**CRITICAL WARNING - DANGEROUS COMMANDS:**
The following commands will KILL the Torque agent and cause the operation to fail:
- `docker restart`, `docker stop`, `docker kill` (any container operations that affect the agent)
- `systemctl restart docker` or any Docker daemon restart
- `reboot`, `shutdown`, `init 6`, `init 0`
- Any command that restarts/stops the Torque agent container

These commands require MANUAL execution via direct SSH or console access.
If you must run these commands, warn the user and DO NOT use this tool.

The tool will return the command output and exit code.

**LONG-RUNNING COMMANDS:**
Default timeout is 30 minutes. For longer commands, use the `timeout` parameter.
Note: Output is only available after command completes (no streaming).
For very long operations, consider running in background: `nohup command > /tmp/output.log 2>&1 &`
Then check status with: `cat /tmp/output.log`""",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "The IP address or hostname of the remote server to connect to",
                    },
                    "ssh_user": {
                        "type": "string",
                        "description": "The SSH username for authentication",
                    },
                    "ssh_private_key": {
                        "type": "string",
                        "description": "The path to the SSH private key file for authentication (e.g., C:\\path\\to\\key.pem)",
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the remote server",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use. If not specified, uses the default agent.",
                    },
                    "force": {
                        "type": "boolean",
                        "description": "Optional: Set to true to bypass dangerous command warnings. Use with extreme caution.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time to wait for command completion in seconds. Default is 1800 (30 minutes). For long operations, increase this or run command in background.",
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="read_remote_file",
            description="""Read the contents of a file on a remote server.

This is a convenience wrapper around run_remote_command that reads a file's content.
Useful for viewing configuration files, logs, or any text file on the remote server.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "The IP address or hostname of the remote server",
                    },
                    "ssh_user": {
                        "type": "string",
                        "description": "The SSH username for authentication",
                    },
                    "ssh_private_key": {
                        "type": "string",
                        "description": "The path to the SSH private key file for authentication (e.g., C:\\path\\to\\key.pem)",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "The absolute path to the file to read",
                    },
                    "tail_lines": {
                        "type": "integer",
                        "description": "Optional: Only read the last N lines of the file (useful for log files)",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use",
                    },
                },
                "required": ["file_path"],
            },
        ),
        Tool(
            name="list_remote_directory",
            description="""List contents of a directory on a remote server.

Returns a detailed listing of files and directories including permissions, size, and modification time.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "The IP address or hostname of the remote server",
                    },
                    "ssh_user": {
                        "type": "string",
                        "description": "The SSH username for authentication",
                    },
                    "ssh_private_key": {
                        "type": "string",
                        "description": "The path to the SSH private key file for authentication (e.g., C:\\path\\to\\key.pem)",
                    },
                    "directory_path": {
                        "type": "string",
                        "description": "The path to the directory to list (defaults to home directory)",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="run_on_runner",
            description="""Execute a shell command on a Torque runner container (no SSH target needed).

This tool runs commands on a runner container that gets spawned by the Torque agent.
No SSH credentials or target IP required - useful when you need to:
- Run scripts or tools available in the runner environment
- Execute commands that don't require a specific target machine
- Test connectivity or run network diagnostics from the Torque infrastructure
- Perform operations that only need the runner's capabilities

Note: Each command spawns a fresh runner container via the Torque agent.

**LONG-RUNNING COMMANDS:**
Default timeout is 30 minutes. For longer commands, use the `timeout` parameter.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the agent container",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use. If not specified, uses the default agent.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Optional: Maximum time to wait for command completion in seconds. Default is 1800 (30 minutes).",
                    },
                },
                "required": ["command"],
            },
        ),
        Tool(
            name="write_remote_file",
            description="""Write content to a file on a remote server.

This tool transfers file content to a remote server via SSH. It can:
- Write content directly provided as a string
- Copy a local file to the remote server

The content is base64-encoded for transfer, so it works with both text and binary files.

**Use cases:**
- Upload configuration files
- Transfer scripts to execute remotely
- Copy any file from local machine to remote server

**Note:** For very large files (>10MB), consider using other transfer methods like scp or rsync.""",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "The IP address or hostname of the remote server",
                    },
                    "ssh_user": {
                        "type": "string",
                        "description": "The SSH username for authentication",
                    },
                    "ssh_private_key": {
                        "type": "string",
                        "description": "The path to the SSH private key file for authentication (e.g., C:\\path\\to\\key.pem)",
                    },
                    "remote_path": {
                        "type": "string",
                        "description": "The destination path on the remote server where the file will be written",
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write to the file. Either provide this OR local_path, not both.",
                    },
                    "local_path": {
                        "type": "string",
                        "description": "Path to a local file to upload. Either provide this OR content, not both.",
                    },
                    "mode": {
                        "type": "string",
                        "description": "Optional: File permissions in octal (e.g., '755' for executable, '644' for regular file). Default is '644'.",
                    },
                    "create_dirs": {
                        "type": "boolean",
                        "description": "Optional: Create parent directories if they don't exist. Default is true.",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use",
                    },
                },
                "required": ["remote_path"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    """Handle tool calls."""
    
    if name == "run_remote_command":
        return await handle_run_remote_command(arguments)
    
    elif name == "read_remote_file":
        return await handle_read_remote_file(arguments)
    
    elif name == "list_remote_directory":
        return await handle_list_remote_directory(arguments)
    
    elif name == "run_on_runner":
        return await handle_run_on_runner(arguments)
    
    elif name == "write_remote_file":
        return await handle_write_remote_file(arguments)
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def handle_run_remote_command(arguments: dict):
    """Execute a remote command."""
    target_ip = arguments.get("target_ip") or _config["default_target_ip"]
    ssh_user = arguments.get("ssh_user") or _config["default_ssh_user"]
    ssh_private_key_path = arguments.get("ssh_private_key") or _config["default_ssh_key"]
    command = arguments.get("command")
    agent = arguments.get("agent")
    force = arguments.get("force", False)
    timeout = arguments.get("timeout")  # Optional timeout override
    
    if not all([target_ip, ssh_user, ssh_private_key_path, command]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need target_ip, ssh_user, ssh_private_key, and command (or configure defaults).",
        )]
    
    # Check for dangerous commands unless force=true
    if not force:
        warning = check_dangerous_command(command)
        if warning:
            return [TextContent(type="text", text=warning)]
    
    try:
        ssh_private_key = read_ssh_key_file(ssh_private_key_path)
    except FileNotFoundError as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    # Create log streamer for real-time output
    log_callback = None
    try:
        session = server.request_context.session
        log_callback = create_log_streamer(session)
    except Exception:
        pass  # Streaming not available
    
    try:
        async with get_torque_client() as client:
            result = await client.execute_remote_command(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=command,
                agent=agent,
                timeout=timeout,
                auto_cleanup=_config["auto_delete_environments"],
                log_callback=log_callback,
            )
            
            # Try to get grain log for additional context (especially useful on failures)
            grain_log = None
            try:
                grain_log = await client.get_grain_log(result.environment_id)
            except Exception:
                pass
        
        # Build environment URL for reference
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{result.environment_id}"
        
        if result.status == "completed":
            output_block = format_code_block(result.command_output)
            output_text = f"""Command executed successfully on {target_ip}

**Exit Code:** {result.exit_code}

**Output:**
{output_block}

**Environment:** `{result.environment_id}` - {env_url}"""
        else:
            output_text = f"""Command execution failed on {target_ip}

**Status:** {result.status}
**Error:** {result.error}

**Environment:** `{result.environment_id}` - {env_url}"""
            
            # Include grain log on failure for debugging
            if grain_log:
                log_block = format_code_block(grain_log)
                output_text += f"""

**Grain Execution Log:**
{log_block}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error executing remote command: {str(e)}")]


async def handle_read_remote_file(arguments: dict):
    """Read a remote file."""
    target_ip = arguments.get("target_ip") or _config["default_target_ip"]
    ssh_user = arguments.get("ssh_user") or _config["default_ssh_user"]
    ssh_private_key_path = arguments.get("ssh_private_key") or _config["default_ssh_key"]
    file_path = arguments.get("file_path")
    tail_lines = arguments.get("tail_lines")
    agent = arguments.get("agent")
    
    if not all([target_ip, ssh_user, ssh_private_key_path, file_path]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need target_ip, ssh_user, ssh_private_key, and file_path (or configure defaults).",
        )]
    
    try:
        ssh_private_key = read_ssh_key_file(ssh_private_key_path)
    except FileNotFoundError as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    # Build the command - use base64 encoding to handle special characters and binary files
    if tail_lines:
        command = f"tail -n {tail_lines} '{file_path}' | base64"
    else:
        command = f"base64 '{file_path}'"
    
    try:
        async with get_torque_client() as client:
            result = await client.execute_remote_command(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=command,
                agent=agent,
            )
        
        # Build environment URL for reference
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{result.environment_id}"
        
        if result.status == "completed" and result.exit_code == 0:
            # Decode the base64 content
            try:
                file_content = base64.b64decode(result.command_output).decode('utf-8')
            except UnicodeDecodeError:
                # Binary file - show as base64 or indicate it's binary
                file_content = f"[Binary file - {len(base64.b64decode(result.command_output))} bytes]\n\nBase64 content:\n{result.command_output}"
            except Exception as decode_err:
                file_content = f"[Decode error: {decode_err}]\n\nRaw output:\n{result.command_output}"
            
            output_text = f"""Contents of `{file_path}` on {target_ip}:

{format_code_block(file_content)}

**Environment:** `{result.environment_id}` - {env_url}"""
        elif result.status == "completed":
            output_text = f"""Failed to read file `{file_path}` on {target_ip}

**Exit Code:** {result.exit_code}
**Output:** {result.command_output}

**Environment:** `{result.environment_id}` - {env_url}"""
        else:
            output_text = f"""Failed to read file on {target_ip}

**Status:** {result.status}
**Error:** {result.error}

**Environment:** `{result.environment_id}` - {env_url}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error reading remote file: {str(e)}")]


async def handle_list_remote_directory(arguments: dict):
    """List a remote directory."""
    target_ip = arguments.get("target_ip") or _config["default_target_ip"]
    ssh_user = arguments.get("ssh_user") or _config["default_ssh_user"]
    ssh_private_key_path = arguments.get("ssh_private_key") or _config["default_ssh_key"]
    directory_path = arguments.get("directory_path", "~")
    agent = arguments.get("agent")
    
    if not all([target_ip, ssh_user, ssh_private_key_path]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need target_ip, ssh_user, and ssh_private_key (or configure defaults).",
        )]
    
    try:
        ssh_private_key = read_ssh_key_file(ssh_private_key_path)
    except FileNotFoundError as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    command = f"ls -la {directory_path}"
    
    try:
        async with get_torque_client() as client:
            result = await client.execute_remote_command(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=command,
                agent=agent,
            )
        
        # Build environment URL for reference
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{result.environment_id}"
        
        if result.status == "completed" and result.exit_code == 0:
            output_text = f"""Contents of `{directory_path}` on {target_ip}:

{format_code_block(result.command_output)}

**Environment:** `{result.environment_id}` - {env_url}"""
        elif result.status == "completed":
            output_text = f"""Failed to list directory `{directory_path}` on {target_ip}

**Exit Code:** {result.exit_code}
**Output:** {result.command_output}

**Environment:** `{result.environment_id}` - {env_url}"""
        else:
            output_text = f"""Failed to list directory on {target_ip}

**Status:** {result.status}
**Error:** {result.error}

**Environment:** `{result.environment_id}` - {env_url}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing remote directory: {str(e)}")]


async def handle_run_on_runner(arguments: dict):
    """Execute a command on a Torque runner container."""
    command = arguments.get("command")
    agent = arguments.get("agent")
    timeout = arguments.get("timeout")  # Optional timeout override
    
    if not command:
        return [TextContent(
            type="text",
            text="Error: Missing required parameter 'command'.",
        )]
    
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
                command=command,
                agent=agent,
                timeout=timeout,
                auto_cleanup=_config["auto_delete_environments"],
                log_callback=log_callback,
            )
            
            # Try to get grain log for additional context (especially useful on failures)
            grain_log = None
            try:
                grain_log = await client.get_grain_log(result.environment_id)
            except Exception:
                pass
        
        # Build environment URL for reference
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{result.environment_id}"
        agent_name = agent or _config["default_agent"]
        
        if result.status == "completed":
            output_block = format_code_block(result.command_output)
            output_text = f"""Command executed successfully on runner (via agent `{agent_name}`)

**Exit Code:** {result.exit_code}

**Output:**
{output_block}

**Environment:** `{result.environment_id}` - {env_url}"""
        else:
            output_text = f"""Command execution failed on runner (via agent `{agent_name}`)

**Status:** {result.status}
**Error:** {result.error}

**Environment:** `{result.environment_id}` - {env_url}"""
            
            # Include grain log on failure for debugging
            if grain_log:
                log_block = format_code_block(grain_log)
                output_text += f"""

**Grain Execution Log:**
{log_block}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error executing command on agent: {str(e)}")]


async def handle_write_remote_file(arguments: dict):
    """Write content to a file on a remote server."""
    target_ip = arguments.get("target_ip") or _config["default_target_ip"]
    ssh_user = arguments.get("ssh_user") or _config["default_ssh_user"]
    ssh_private_key_path = arguments.get("ssh_private_key") or _config["default_ssh_key"]
    remote_path = arguments.get("remote_path")
    content = arguments.get("content")
    local_path = arguments.get("local_path")
    mode = arguments.get("mode", "644")
    create_dirs = arguments.get("create_dirs", True)
    agent = arguments.get("agent")
    
    if not all([target_ip, ssh_user, ssh_private_key_path, remote_path]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need target_ip, ssh_user, ssh_private_key, and remote_path (or configure defaults).",
        )]
    
    # Must have either content or local_path
    if not content and not local_path:
        return [TextContent(
            type="text",
            text="Error: Must provide either 'content' or 'local_path' parameter.",
        )]
    
    if content and local_path:
        return [TextContent(
            type="text",
            text="Error: Provide either 'content' OR 'local_path', not both.",
        )]
    
    try:
        ssh_private_key = read_ssh_key_file(ssh_private_key_path)
    except FileNotFoundError as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]
    
    # Get content from local file if local_path is provided
    if local_path:
        expanded_path = os.path.expanduser(local_path)
        if not os.path.exists(expanded_path):
            return [TextContent(type="text", text=f"Error: Local file not found: {local_path}")]
        
        try:
            with open(expanded_path, 'rb') as f:
                file_bytes = f.read()
        except Exception as e:
            return [TextContent(type="text", text=f"Error reading local file: {str(e)}")]
    else:
        # Content provided directly - encode as UTF-8
        file_bytes = content.encode('utf-8')
    
    # Base64 encode the content
    content_b64 = base64.b64encode(file_bytes).decode('ascii')
    
    # Build the command to write the file on the remote server
    # Create parent directories if requested
    dir_cmd = ""
    if create_dirs:
        remote_dir = os.path.dirname(remote_path)
        if remote_dir:
            dir_cmd = f"mkdir -p '{remote_dir}' && "
    
    # Use echo with base64 -d to write the file, then set permissions
    command = f"{dir_cmd}echo '{content_b64}' | base64 -d > '{remote_path}' && chmod {mode} '{remote_path}' && echo 'File written successfully' && ls -la '{remote_path}'"
    
    try:
        async with get_torque_client() as client:
            result = await client.execute_remote_command(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=command,
                agent=agent,
                auto_cleanup=_config["auto_delete_environments"],
            )
        
        # Build environment URL for reference
        env_url = f"{_config['torque_url']}/{_config['torque_space']}/environments/{result.environment_id}"
        
        file_size = len(file_bytes)
        source_info = f"local file `{local_path}`" if local_path else "provided content"
        
        if result.status == "completed" and result.exit_code == 0:
            output_text = f"""File written successfully to {target_ip}

**Remote Path:** `{remote_path}`
**Source:** {source_info}
**Size:** {file_size} bytes
**Mode:** {mode}

**Output:**
{format_code_block(result.command_output)}

**Environment:** `{result.environment_id}` - {env_url}"""
        elif result.status == "completed":
            output_text = f"""Failed to write file to {target_ip}

**Remote Path:** `{remote_path}`
**Exit Code:** {result.exit_code}
**Output:** {result.command_output}

**Environment:** `{result.environment_id}` - {env_url}"""
        else:
            output_text = f"""Failed to write file to {target_ip}

**Status:** {result.status}
**Error:** {result.error}

**Environment:** `{result.environment_id}` - {env_url}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error writing remote file: {str(e)}")]


async def cli_dispatch(args):
    """Dispatch CLI commands to appropriate handlers."""
    import json as json_module
    
    def cli_log_callback(content: str):
        """Simple callback that prints to stderr for CLI streaming."""
        async def _stream(data: str):
            print(data, file=sys.stderr, end='', flush=True)
        return _stream
    
    try:
        if args.command == "run":
            # Remote command execution
            target_ip = _config["default_target_ip"]
            ssh_user = getattr(args, 'user', None) or _config["default_ssh_user"]
            ssh_key_path = getattr(args, 'key', None) or _config["default_ssh_key"]
            agent = getattr(args, 'agent', None)
            timeout = getattr(args, 'timeout', None)
            force = getattr(args, 'force', False)
            output_json = getattr(args, 'json', False)
            
            if not all([target_ip, ssh_user, ssh_key_path]):
                print("Error: Missing target, user, or SSH key. Use --target, --user, --key or set defaults.", file=sys.stderr)
                sys.exit(1)
            
            # Check dangerous commands
            if not force:
                warning = check_dangerous_command(args.cmd)
                if warning:
                    print(warning, file=sys.stderr)
                    sys.exit(2)
            
            try:
                ssh_key = read_ssh_key_file(ssh_key_path)
            except FileNotFoundError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            
            async with get_torque_client() as client:
                result = await client.execute_remote_command(
                    target_ip=target_ip,
                    ssh_user=ssh_user,
                    ssh_private_key=ssh_key,
                    command=args.cmd,
                    agent=agent,
                    timeout=timeout,
                    auto_cleanup=_config["auto_delete_environments"],
                    log_callback=cli_log_callback(""),
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
        
        elif args.command == "runner":
            # Runner command
            agent = getattr(args, 'agent', None)
            timeout = getattr(args, 'timeout', None)
            output_json = getattr(args, 'json', False)
            
            async with get_torque_client() as client:
                result = await client.execute_local_command(
                    command=args.cmd,
                    agent=agent,
                    timeout=timeout,
                    auto_cleanup=_config["auto_delete_environments"],
                    log_callback=cli_log_callback(""),
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
            max_size = getattr(args, 'max_size', 102400)
            
            if not all([target_ip, ssh_user, ssh_key_path]):
                print("Error: Missing target, user, or SSH key.", file=sys.stderr)
                sys.exit(1)
            
            ssh_key = read_ssh_key_file(ssh_key_path)
            
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
            show_all = getattr(args, 'all', False)
            long_format = getattr(args, 'long', False)
            
            if not all([target_ip, ssh_user, ssh_key_path]):
                print("Error: Missing target, user, or SSH key.", file=sys.stderr)
                sys.exit(1)
            
            ssh_key = read_ssh_key_file(ssh_key_path)
            
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
                    auto_cleanup=_config["auto_delete_environments"],
                )
            
            if result.status == "completed":
                print(result.command_output or "", end='')
                sys.exit(result.exit_code or 0)
            else:
                print(f"Error: {result.error}", file=sys.stderr)
                sys.exit(1)
        
        elif args.command == "write":
            # Write to remote file
            target_ip = _config["default_target_ip"]
            ssh_user = getattr(args, 'user', None) or _config["default_ssh_user"]
            ssh_key_path = getattr(args, 'key', None) or _config["default_ssh_key"]
            agent = getattr(args, 'agent', None)
            mode = getattr(args, 'mode', None)
            backup = getattr(args, 'backup', False)
            use_stdin = getattr(args, 'stdin', False)
            
            if not all([target_ip, ssh_user, ssh_key_path]):
                print("Error: Missing target, user, or SSH key.", file=sys.stderr)
                sys.exit(1)
            
            # Get content
            if use_stdin:
                content = sys.stdin.read()
            elif args.content:
                content = args.content
            else:
                print("Error: No content provided. Use positional argument or --stdin.", file=sys.stderr)
                sys.exit(1)
            
            ssh_key = read_ssh_key_file(ssh_key_path)
            
            # Build write command
            escaped_path = args.path.replace("'", "'\\''")
            content_b64 = base64.b64encode(content.encode()).decode()
            
            cmd_parts = []
            if backup:
                cmd_parts.append(f"[ -f '{escaped_path}' ] && cp '{escaped_path}' '{escaped_path}.bak'")
            cmd_parts.append(f"echo '{content_b64}' | base64 -d > '{escaped_path}'")
            if mode:
                cmd_parts.append(f"chmod {mode} '{escaped_path}'")
            cmd = "; ".join(cmd_parts)
            
            async with get_torque_client() as client:
                result = await client.execute_remote_command(
                    target_ip=target_ip,
                    ssh_user=ssh_user,
                    ssh_private_key=ssh_key,
                    command=cmd,
                    agent=agent,
                    auto_cleanup=_config["auto_delete_environments"],
                )
            
            if result.status == "completed" and result.exit_code == 0:
                print(f"Written to {args.path}")
                sys.exit(0)
            else:
                print(f"Error: {result.error or result.command_output}", file=sys.stderr)
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
        help="SSH private key file path (env: $SSH_KEY)",
    )
    common_parser.add_argument(
        "--target-host",
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
    
    # Main parser with subcommands - also inherits common args for when no subcommand is given
    parser = argparse.ArgumentParser(
        parents=[common_parser],
        description="ShellAgent - Execute remote commands via Torque (MCP server or CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  serve (default)  Run as MCP server (for VS Code Copilot)
  run              Execute a command on a remote server
  runner           Execute a command on the Torque runner
  read             Read a file from a remote server
  list             List a directory on a remote server
  write            Write content to a file on a remote server

Examples:
  # Run as MCP server (for VS Code)
  shellagent serve

  # CLI mode - run a remote command
  shellagent run "uname -a"
  shellagent run --target 10.0.0.1 --user root "df -h"

  # CLI mode - run on the Torque runner directly
  shellagent runner "curl https://example.com"

  # CLI mode - read/list/write files
  shellagent read /etc/hostname
  shellagent list /var/log
  shellagent write /tmp/test.txt "Hello World"

Environment Variables:
  TORQUE_URL, TORQUE_TOKEN, TORQUE_SPACE, TORQUE_AGENT
  SSH_KEY, TARGET_HOST, SSH_USER
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # serve subcommand (MCP server mode)
    subparsers.add_parser("serve", parents=[common_parser], help="Run as MCP server")
    
    # run subcommand (remote command)
    run_parser = subparsers.add_parser("run", parents=[common_parser], help="Execute a command on remote server")
    run_parser.add_argument("cmd", help="The shell command to execute")
    run_parser.add_argument("--user", "-u", help="SSH username (overrides --ssh-user)")
    run_parser.add_argument("--key", "-k", help="SSH private key file (overrides --ssh-key)")
    run_parser.add_argument("--agent", "-a", help="Torque agent name (overrides default)")
    run_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    run_parser.add_argument("--force", "-f", action="store_true", help="Force dangerous commands")
    run_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    
    # runner subcommand (run on Torque runner)
    runner_parser = subparsers.add_parser("runner", parents=[common_parser], help="Execute a command on Torque runner")
    runner_parser.add_argument("cmd", help="The shell command to execute")
    runner_parser.add_argument("--agent", "-a", help="Torque agent name (overrides default)")
    runner_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    runner_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    
    # read subcommand
    read_parser = subparsers.add_parser("read", parents=[common_parser], help="Read a file from remote server")
    read_parser.add_argument("path", help="Remote file path to read")
    read_parser.add_argument("--user", "-u", help="SSH username")
    read_parser.add_argument("--key", "-k", help="SSH private key file")
    read_parser.add_argument("--agent", "-a", help="Torque agent name")
    read_parser.add_argument("--max-size", type=int, default=102400, help="Max file size in bytes (default: 100KB)")
    
    # list subcommand
    list_parser = subparsers.add_parser("list", parents=[common_parser], help="List a directory on remote server")
    list_parser.add_argument("path", help="Remote directory path")
    list_parser.add_argument("--user", "-u", help="SSH username")
    list_parser.add_argument("--key", "-k", help="SSH private key file")
    list_parser.add_argument("--agent", "-a", help="Torque agent name")
    list_parser.add_argument("--all", "-A", action="store_true", help="Show hidden files")
    list_parser.add_argument("--long", "-l", action="store_true", help="Long format with details")
    
    # write subcommand
    write_parser = subparsers.add_parser("write", parents=[common_parser], help="Write content to a remote file")
    write_parser.add_argument("path", help="Remote file path to write")
    write_parser.add_argument("content", nargs="?", help="Content to write (or use --stdin)")
    write_parser.add_argument("--stdin", action="store_true", help="Read content from stdin")
    write_parser.add_argument("--user", "-u", help="SSH username")
    write_parser.add_argument("--key", "-k", help="SSH private key file")
    write_parser.add_argument("--agent", "-a", help="Torque agent name")
    write_parser.add_argument("--mode", help="File permissions (e.g., 0644)")
    write_parser.add_argument("--backup", action="store_true", help="Create backup before overwriting")
    
    args = parser.parse_args()
    
    # Update global config from common args
    _config["torque_url"] = args.torque_url
    _config["torque_token"] = args.torque_token
    _config["torque_space"] = args.torque_space
    _config["default_agent"] = args.torque_agent
    _config["default_ssh_key"] = args.ssh_key
    _config["default_target_ip"] = args.target_host
    _config["default_ssh_user"] = args.ssh_user
    _config["init_commands"] = args.init_commands
    _config["finally_commands"] = args.finally_commands
    _config["auto_delete_environments"] = args.auto_delete_environments
    
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
