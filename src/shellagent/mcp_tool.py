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


# Global configuration - set via command line args or environment variables
_config = {
    "torque_url": None,
    "torque_token": None,
    "torque_space": None,
    "default_agent": None,
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
The command is executed through Torque's Shell Grain infrastructure.

Use this tool when you need to:
- Troubleshoot a remote server
- Check system status (disk space, memory, processes, etc.)
- View log files
- Run diagnostic commands
- Execute administrative tasks

The tool will return the command output and exit code.""",
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
                        "description": "The SSH private key content for authentication (the actual key content, not a file path)",
                    },
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute on the remote server",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional: The Torque agent name to use. If not specified, uses the default agent.",
                    },
                },
                "required": ["target_ip", "ssh_user", "ssh_private_key", "command"],
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
                        "description": "The SSH private key content for authentication",
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
                "required": ["target_ip", "ssh_user", "ssh_private_key", "file_path"],
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
                        "description": "The SSH private key content for authentication",
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
                "required": ["target_ip", "ssh_user", "ssh_private_key"],
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
    
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def handle_run_remote_command(arguments: dict):
    """Execute a remote command."""
    target_ip = arguments.get("target_ip")
    ssh_user = arguments.get("ssh_user")
    ssh_private_key = arguments.get("ssh_private_key")
    command = arguments.get("command")
    agent = arguments.get("agent")
    
    if not all([target_ip, ssh_user, ssh_private_key, command]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need target_ip, ssh_user, ssh_private_key, and command.",
        )]
    
    try:
        async with get_torque_client() as client:
            result = await client.execute_remote_command(
                target_ip=target_ip,
                ssh_user=ssh_user,
                ssh_private_key=ssh_private_key,
                command=command,
                agent=agent,
            )
        
        if result.status == "completed":
            output_text = f"""Command executed successfully on {target_ip}

**Exit Code:** {result.exit_code}

**Output:**
```
{result.command_output}
```"""
        else:
            output_text = f"""Command execution failed on {target_ip}

**Status:** {result.status}
**Error:** {result.error}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error executing remote command: {str(e)}")]


async def handle_read_remote_file(arguments: dict):
    """Read a remote file."""
    target_ip = arguments.get("target_ip")
    ssh_user = arguments.get("ssh_user")
    ssh_private_key = arguments.get("ssh_private_key")
    file_path = arguments.get("file_path")
    tail_lines = arguments.get("tail_lines")
    agent = arguments.get("agent")
    
    if not all([target_ip, ssh_user, ssh_private_key, file_path]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need target_ip, ssh_user, ssh_private_key, and file_path.",
        )]
    
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
        
        if result.status == "completed" and result.exit_code == 0:
            output_text = f"""Contents of `{file_path}` on {target_ip}:

```
{result.command_output}
```"""
        elif result.status == "completed":
            output_text = f"""Failed to read file `{file_path}` on {target_ip}

**Exit Code:** {result.exit_code}
**Output:** {result.command_output}"""
        else:
            output_text = f"""Failed to read file on {target_ip}

**Status:** {result.status}
**Error:** {result.error}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error reading remote file: {str(e)}")]


async def handle_list_remote_directory(arguments: dict):
    """List a remote directory."""
    target_ip = arguments.get("target_ip")
    ssh_user = arguments.get("ssh_user")
    ssh_private_key = arguments.get("ssh_private_key")
    directory_path = arguments.get("directory_path", "~")
    agent = arguments.get("agent")
    
    if not all([target_ip, ssh_user, ssh_private_key]):
        return [TextContent(
            type="text",
            text="Error: Missing required parameters. Need target_ip, ssh_user, and ssh_private_key.",
        )]
    
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
        
        if result.status == "completed" and result.exit_code == 0:
            output_text = f"""Contents of `{directory_path}` on {target_ip}:

```
{result.command_output}
```"""
        elif result.status == "completed":
            output_text = f"""Failed to list directory `{directory_path}` on {target_ip}

**Exit Code:** {result.exit_code}
**Output:** {result.command_output}"""
        else:
            output_text = f"""Failed to list directory on {target_ip}

**Status:** {result.status}
**Error:** {result.error}"""
        
        return [TextContent(type="text", text=output_text)]
    
    except Exception as e:
        return [TextContent(type="text", text=f"Error listing remote directory: {str(e)}")]


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
    
    args = parser.parse_args()
    
    # Update global config
    _config["torque_url"] = args.torque_url
    _config["torque_token"] = args.torque_token
    _config["torque_space"] = args.torque_space
    _config["default_agent"] = args.torque_agent
    
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
