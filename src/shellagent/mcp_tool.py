"""
ShellAgent MCP Tool - Execute remote commands via Torque Shell Grains.

This MCP tool provides Copilot with the ability to run commands on remote servers
by leveraging Torque's Shell Grain infrastructure.
"""

import os
import sys
import asyncio
import argparse
from typing import Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Tool,
    TextContent,
)

from .torque_client import TorqueClient


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
            name="run_on_agent",
            description="""Execute a shell command directly on the Torque agent container.

This tool runs commands locally on the Torque Docker agent without SSH to any remote host.
Useful when you need to:
- Run scripts or tools installed on the agent
- Execute commands that don't require a target machine
- Test connectivity or run network diagnostics from the agent's perspective
- Run commands that need agent-local resources

No SSH credentials or target IP required - the command runs directly on the agent container.

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
    
    elif name == "run_on_agent":
        return await handle_run_on_agent(arguments)
    
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
            output_text = f"""Command executed successfully on {target_ip}

**Exit Code:** {result.exit_code}

**Output:**
```
{result.command_output}
```

**Environment:** [{result.environment_id}]( {env_url} )"""
        else:
            output_text = f"""Command execution failed on {target_ip}

**Status:** {result.status}
**Error:** {result.error}

**Environment:** [{result.environment_id}]( {env_url} )"""
            
            # Include grain log on failure for debugging
            if grain_log:
                output_text += f"""

**Grain Execution Log:**
```
{grain_log}
```"""
        
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
    
    # Build the command
    if tail_lines:
        command = f"tail -n {tail_lines} {file_path}"
    else:
        command = f"cat {file_path}"
    
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
            output_text = f"""Contents of `{file_path}` on {target_ip}:

```
{result.command_output}
```

**Environment:** [{result.environment_id}]( {env_url} )"""
        elif result.status == "completed":
            output_text = f"""Failed to read file `{file_path}` on {target_ip}

**Exit Code:** {result.exit_code}
**Output:** {result.command_output}

**Environment:** [{result.environment_id}]( {env_url} )"""
        else:
            output_text = f"""Failed to read file on {target_ip}

**Status:** {result.status}
**Error:** {result.error}

**Environment:** [{result.environment_id}]( {env_url} )"""
        
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

```
{result.command_output}
```

**Environment:** [{result.environment_id}]( {env_url} )"""
        elif result.status == "completed":
            output_text = f"""Failed to list directory `{directory_path}` on {target_ip}

**Exit Code:** {result.exit_code}
**Output:** {result.command_output}

**Environment:** [{result.environment_id}]( {env_url} )"""
        else:
            output_text = f"""Failed to list directory on {target_ip}

**Status:** {result.status}
**Error:** {result.error}

**Environment:** [{result.environment_id}]( {env_url} )"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing remote directory: {str(e)}")]


async def handle_run_on_agent(arguments: dict):
    """Execute a command locally on the Torque agent container."""
    command = arguments.get("command")
    agent = arguments.get("agent")
    timeout = arguments.get("timeout")  # Optional timeout override
    
    if not command:
        return [TextContent(
            type="text",
            text="Error: Missing required parameter 'command'.",
        )]
    
    try:
        async with get_torque_client() as client:
            result = await client.execute_local_command(
                command=command,
                agent=agent,
                timeout=timeout,
                auto_cleanup=_config["auto_delete_environments"],
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
            output_text = f"""Command executed successfully on agent `{agent_name}`

**Exit Code:** {result.exit_code}

**Output:**
```
{result.command_output}
```

**Environment:** [{result.environment_id}]( {env_url} )"""
        else:
            output_text = f"""Command execution failed on agent `{agent_name}`

**Status:** {result.status}
**Error:** {result.error}

**Environment:** [{result.environment_id}]( {env_url} )"""
            
            # Include grain log on failure for debugging
            if grain_log:
                output_text += f"""

**Grain Execution Log:**
```
{grain_log}
```"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error executing command on agent: {str(e)}")]


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="ShellAgent MCP Tool - Execute remote commands via Torque",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  TORQUE_URL      Torque base URL (e.g., https://portal.qtorque.io)
  TORQUE_TOKEN    Torque API token
  TORQUE_SPACE    Torque space name
  TORQUE_AGENT    Default Torque agent name

Example:
  shellagent --torque-url https://review1.qualilabs.net --torque-space BMaaS --torque-agent my-agent
        """,
    )
    
    parser.add_argument(
        "--torque-url",
        default=os.environ.get("TORQUE_URL"),
        help="Torque base URL (default: $TORQUE_URL)",
    )
    parser.add_argument(
        "--torque-token",
        default=os.environ.get("TORQUE_TOKEN"),
        help="Torque API token (default: $TORQUE_TOKEN)",
    )
    parser.add_argument(
        "--torque-space",
        default=os.environ.get("TORQUE_SPACE"),
        help="Torque space name (default: $TORQUE_SPACE)",
    )
    parser.add_argument(
        "--torque-agent",
        default=os.environ.get("TORQUE_AGENT"),
        help="Default Torque agent name (default: $TORQUE_AGENT)",
    )
    parser.add_argument(
        "--default-ssh-key",
        default=os.environ.get("DEFAULT_SSH_KEY"),
        help="Default SSH private key file path (default: $DEFAULT_SSH_KEY)",
    )
    parser.add_argument(
        "--default-target-ip",
        default=os.environ.get("DEFAULT_TARGET_IP"),
        help="Default target server IP/hostname (default: $DEFAULT_TARGET_IP)",
    )
    parser.add_argument(
        "--default-ssh-user",
        default=os.environ.get("DEFAULT_SSH_USER"),
        help="Default SSH username (default: $DEFAULT_SSH_USER)",
    )
    parser.add_argument(
        "--init-commands",
        default=os.environ.get("INIT_COMMANDS"),
        help="Commands to run before every SSH command (e.g., proxy setup). Use semicolons to separate multiple commands.",
    )
    parser.add_argument(
        "--finally-commands",
        default=os.environ.get("FINALLY_COMMANDS"),
        help="Commands to run after every SSH command (cleanup). Always runs even on failure.",
    )
    parser.add_argument(
        "--auto-delete-environments",
        action="store_true",
        default=os.environ.get("AUTO_DELETE_ENVIRONMENTS", "").lower() in ("true", "1", "yes"),
        help="Automatically delete Torque environments after command completion (default: keep environments)",
    )
    
    args = parser.parse_args()
    
    # Update global config
    _config["torque_url"] = args.torque_url
    _config["torque_token"] = args.torque_token
    _config["torque_space"] = args.torque_space
    _config["default_agent"] = args.torque_agent
    _config["default_ssh_key"] = args.default_ssh_key
    _config["default_target_ip"] = args.default_target_ip
    _config["default_ssh_user"] = args.default_ssh_user
    _config["init_commands"] = args.init_commands
    _config["finally_commands"] = args.finally_commands
    _config["auto_delete_environments"] = args.auto_delete_environments
    
    # Debug: Print config at startup
    print(f"[DEBUG] auto_delete_environments = {_config['auto_delete_environments']}", file=sys.stderr, flush=True)
    
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
    
    # Run the MCP server
    async def run():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )
    
    asyncio.run(run())


if __name__ == "__main__":
    main()
