"""
Torque API Client for interacting with Quali Torque REST API.
"""

import asyncio
import time
from typing import Optional
from dataclasses import dataclass

import httpx


@dataclass
class EnvironmentResult:
    """Result of an environment execution."""
    environment_id: str
    status: str
    command_output: Optional[str] = None
    exit_code: Optional[int] = None
    error: Optional[str] = None


class TorqueClient:
    """Client for interacting with Torque REST API."""
    
    BLUEPRINT_NAME = "remote-shell-executor"
    
    def __init__(
        self,
        base_url: str,
        token: str,
        space: str,
        default_agent: Optional[str] = None,
        timeout: int = 300,
        poll_interval: int = 5,
    ):
        """
        Initialize Torque client.
        
        Args:
            base_url: Torque base URL (e.g., https://portal.qtorque.io)
            token: Torque API token
            space: Torque space name
            default_agent: Default agent name to use
            timeout: Maximum time to wait for environment completion (seconds)
            poll_interval: How often to check environment status (seconds)
        """
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.space = space
        self.default_agent = default_agent
        self.timeout = timeout
        self.poll_interval = poll_interval
        
        self._client = httpx.AsyncClient(
            base_url=f"{self.base_url}/api",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=60.0,
        )
    
    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def start_environment(
        self,
        target_ip: str,
        ssh_user: str,
        ssh_private_key: str,
        command: str,
        agent: Optional[str] = None,
        environment_name: Optional[str] = None,
    ) -> str:
        """
        Start a new environment to execute remote command.
        
        Args:
            target_ip: Target host IP/hostname
            ssh_user: SSH username
            ssh_private_key: SSH private key (will be base64 encoded)
            command: Command to execute
            agent: Agent name (uses default if not specified)
            environment_name: Optional name for the environment
            
        Returns:
            Environment ID
        """
        agent_name = agent or self.default_agent
        if not agent_name:
            raise ValueError("Agent name must be provided either as argument or default")
        
        # Generate environment name if not provided
        if not environment_name:
            environment_name = f"shell-cmd-{int(time.time())}"
        
        payload = {
            "blueprint_name": self.BLUEPRINT_NAME,
            "environment_name": environment_name,
            "duration": "PT10M",  # 10 minutes - short lived
            "inputs": {
                "agent": agent_name,
                "target_ip": target_ip,
                "ssh_user": ssh_user,
                "ssh_private_key": ssh_private_key,
                "command": command,
            },
        }
        
        response = await self._client.post(
            f"/spaces/{self.space}/environments",
            json=payload,
        )
        response.raise_for_status()
        
        data = response.json()
        return data["id"]
    
    async def get_environment_status(self, environment_id: str) -> dict:
        """
        Get environment status and details.
        
        Args:
            environment_id: Environment ID
            
        Returns:
            Environment details dict
        """
        response = await self._client.get(
            f"/spaces/{self.space}/environments/{environment_id}"
        )
        response.raise_for_status()
        return response.json()
    
    async def end_environment(self, environment_id: str) -> None:
        """
        End/terminate an environment.
        
        Args:
            environment_id: Environment ID
        """
        response = await self._client.delete(
            f"/spaces/{self.space}/environments/{environment_id}"
        )
        # 404 is ok - environment may have already ended
        if response.status_code != 404:
            response.raise_for_status()
    
    async def wait_for_environment(
        self,
        environment_id: str,
        timeout: Optional[int] = None,
    ) -> EnvironmentResult:
        """
        Wait for environment to complete and return results.
        
        Args:
            environment_id: Environment ID
            timeout: Optional timeout override
            
        Returns:
            EnvironmentResult with command output
        """
        timeout = timeout or self.timeout
        start_time = time.time()
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                return EnvironmentResult(
                    environment_id=environment_id,
                    status="timeout",
                    error=f"Environment did not complete within {timeout} seconds",
                )
            
            env_data = await self.get_environment_status(environment_id)
            status = env_data.get("computed_status", env_data.get("status", "unknown"))
            
            # Check if environment has completed
            if status in ("Active", "active", "active_with_error"):
                # Environment deployed - extract outputs
                outputs = env_data.get("outputs", {})
                command_output = outputs.get("command_output", "")
                exit_code_str = outputs.get("exit_code", "0")
                
                try:
                    exit_code = int(exit_code_str)
                except (ValueError, TypeError):
                    exit_code = 0
                
                return EnvironmentResult(
                    environment_id=environment_id,
                    status="completed",
                    command_output=command_output,
                    exit_code=exit_code,
                )
            
            elif status in ("Ended", "ended", "EndedWithError", "ended_with_error", "Ending", "ending"):
                return EnvironmentResult(
                    environment_id=environment_id,
                    status="failed",
                    error=f"Environment ended unexpectedly with status: {status}",
                )
            
            elif status in ("Error", "error", "Failed", "failed"):
                errors = env_data.get("errors", [])
                error_msg = "; ".join(errors) if errors else f"Environment failed with status: {status}"
                return EnvironmentResult(
                    environment_id=environment_id,
                    status="failed",
                    error=error_msg,
                )
            
            # Still running - wait and poll again
            await asyncio.sleep(self.poll_interval)
    
    async def execute_remote_command(
        self,
        target_ip: str,
        ssh_user: str,
        ssh_private_key: str,
        command: str,
        agent: Optional[str] = None,
        auto_cleanup: bool = True,
    ) -> EnvironmentResult:
        """
        Execute a remote command and wait for result.
        
        This is the main high-level method that:
        1. Starts an environment
        2. Waits for completion
        3. Returns the command output
        4. Optionally cleans up the environment
        
        Args:
            target_ip: Target host IP/hostname
            ssh_user: SSH username
            ssh_private_key: SSH private key content
            command: Command to execute
            agent: Agent name (uses default if not specified)
            auto_cleanup: Whether to automatically end the environment after completion
            
        Returns:
            EnvironmentResult with command output
        """
        environment_id = await self.start_environment(
            target_ip=target_ip,
            ssh_user=ssh_user,
            ssh_private_key=ssh_private_key,
            command=command,
            agent=agent,
        )
        
        try:
            result = await self.wait_for_environment(environment_id)
            return result
        finally:
            if auto_cleanup:
                try:
                    await self.end_environment(environment_id)
                except Exception:
                    pass  # Ignore cleanup errors
