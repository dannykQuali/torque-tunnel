"""
Torque API Client for interacting with Quali Torque REST API.
"""

import asyncio
import base64
import sys
import time
from typing import Optional, Callable, Awaitable
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
    LOCAL_BLUEPRINT_NAME = "local-shell-executor"
    
    def __init__(
        self,
        base_url: str,
        token: str,
        space: str,
        default_agent: Optional[str] = None,
        timeout: int = 1800,  # 30 minutes default
        poll_interval: int = 2,
        init_commands: Optional[str] = None,
        finally_commands: Optional[str] = None,
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
            init_commands: Commands to run before every SSH command (e.g., proxy setup)
            finally_commands: Commands to run after every SSH command (cleanup)
        """
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.space = space
        self.default_agent = default_agent
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.init_commands = init_commands or ""
        self.finally_commands = finally_commands or ""
        
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
        init_commands: Optional[str] = None,
        finally_commands: Optional[str] = None,
    ) -> str:
        """
        Start a new environment to execute remote command.
        
        Args:
            target_ip: Target host IP/hostname
            ssh_user: SSH username
            ssh_private_key: SSH private key (raw PEM format)
            command: Command to execute
            agent: Agent name (uses default if not specified)
            environment_name: Optional name for the environment
            init_commands: Optional commands to run before main command (overrides instance default)
            finally_commands: Optional cleanup commands (overrides instance default)
            
        Returns:
            Environment ID
        """
        agent_name = agent or self.default_agent
        if not agent_name:
            raise ValueError("Agent name must be provided either as argument or default")
        
        # Generate environment name if not provided
        if not environment_name:
            environment_name = f"shell-cmd-{int(time.time())}"
        
        # Use per-call values if provided, otherwise fall back to instance defaults
        effective_init = init_commands if init_commands is not None else self.init_commands
        effective_finally = finally_commands if finally_commands is not None else self.finally_commands
        
        # Calculate timeout in minutes (round up, minimum 5 minutes for Torque)
        timeout_minutes = max(5, (self.timeout + 59) // 60)
        
        inputs = {
            "agent": agent_name,
            "target_ip": target_ip,
            "ssh_user": ssh_user,
            "ssh_private_key": ssh_private_key,
            "command_b64": base64.b64encode(command.encode()).decode(),
            "timeout_minutes": str(timeout_minutes),
        }
        # Only include optional inputs if they have values
        if effective_init:
            inputs["init_commands_b64"] = base64.b64encode(effective_init.encode()).decode()
        if effective_finally:
            inputs["finally_commands_b64"] = base64.b64encode(effective_finally.encode()).decode()
        
        payload = {
            "blueprint_name": self.BLUEPRINT_NAME,
            "environment_name": environment_name,
            "duration": "PT8H",  # 8 hours (irrelevant for workflows, they auto-terminate)
            "inputs": inputs,
        }
        
        response = await self._client.post(
            f"/spaces/{self.space}/environments",
            json=payload,
        )
        response.raise_for_status()
        
        data = response.json()
        return data["id"]
    
    async def start_local_environment(
        self,
        command: str,
        agent: Optional[str] = None,
        environment_name: Optional[str] = None,
        init_commands: Optional[str] = None,
    ) -> str:
        """
        Start a new environment to execute command locally on the agent container.
        
        Args:
            command: Command to execute
            agent: Agent name (uses default if not specified)
            environment_name: Optional name for the environment
            init_commands: Optional commands to run before the main command (prepended to global init_commands)
            
        Returns:
            Environment ID
        """
        agent_name = agent or self.default_agent
        if not agent_name:
            raise ValueError("Agent name must be provided either as argument or default")
        
        # Generate environment name if not provided
        if not environment_name:
            environment_name = f"local-cmd-{int(time.time())}"
        
        # Combine per-call init_commands with global init_commands
        combined_init = None
        if init_commands and self.init_commands:
            combined_init = f"{init_commands}\n{self.init_commands}"
        elif init_commands:
            combined_init = init_commands
        elif self.init_commands:
            combined_init = self.init_commands
        
        # Calculate timeout in minutes (round up, minimum 5 minutes for Torque)
        timeout_minutes = max(5, (self.timeout + 59) // 60)
        
        inputs = {
            "agent": agent_name,
            "command_b64": base64.b64encode(command.encode()).decode(),
            "timeout_minutes": str(timeout_minutes),
        }
        # Only include optional inputs if they have values
        if combined_init:
            inputs["init_commands_b64"] = base64.b64encode(combined_init.encode()).decode()
        if self.finally_commands:
            inputs["finally_commands_b64"] = base64.b64encode(self.finally_commands.encode()).decode()
        
        payload = {
            "blueprint_name": self.LOCAL_BLUEPRINT_NAME,
            "environment_name": environment_name,
            "duration": "PT8H",  # 8 hours (irrelevant for workflows, they auto-terminate)
            "inputs": inputs,
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
    
    async def end_environment(self, environment_id: str, force: bool = False) -> None:
        """
        End/terminate a running environment (stops execution but keeps it in the system).
        
        Args:
            environment_id: Environment ID
            force: Whether to force termination (for environments in transitional state)
        """
        # Build URL with optional force parameter
        url = f"/spaces/{self.space}/environments/{environment_id}"
        if force:
            url += "?force=true"
        
        response = await self._client.delete(url)
        
        # 404 is ok - environment may have already ended
        if response.status_code == 404:
            return
        
        # 400 Bad Request - workflow already completed/terminated (can't end twice)
        if response.status_code == 400:
            return
        
        # 409 Conflict - environment is in a transitional state (Launching/Deploying)
        # Log warning but don't raise - environment will eventually time out on Torque's side
        if response.status_code == 409:
            print(f"[WARNING] Could not terminate environment {environment_id} (409 Conflict - in transitional state)", file=sys.stderr)
            return
        
        response.raise_for_status()
    
    async def delete_environment(self, environment_id: str) -> None:
        """
        Delete an environment from the system (remove from history/DB).
        Uses the /remove_state endpoint to fully purge from Torque.
        
        Args:
            environment_id: Environment ID
        """
        # First, wait for environment to be in ended/terminated state
        for _ in range(10):  # Wait up to 50 seconds
            try:
                env_data = await self.get_environment_status(environment_id)
                status = env_data.get("details", {}).get("computed_status", "").lower().replace(" ", "_")
                if status in ("ended", "terminating", "terminated"):
                    break
            except Exception as e:
                print(f"[WARNING] Error getting environment status (may be gone): {e}", file=sys.stderr)
                return  # Environment may already be gone
            await asyncio.sleep(5)
        
        # Use the /remove_state endpoint to fully delete from DB
        response = await self._client.delete(
            f"/spaces/{self.space}/environments/{environment_id}/remove_state"
        )
        # 404 is ok - environment may have already been deleted
        if response.status_code != 404:
            response.raise_for_status()
        # 404 is ok - environment may have already been deleted
        if response.status_code != 404:
            response.raise_for_status()
    
    async def get_grain_log(self, environment_id: str) -> Optional[str]:
        """
        Get the grain activity log for an environment.
        
        Args:
            environment_id: Environment ID
            
        Returns:
            Log content as string, or None if not available
        """
        try:
            env_data = await self.get_environment_status(environment_id)
            grains = env_data.get("details", {}).get("state", {}).get("grains", [])
            
            if not grains:
                return None
            
            # Find the Deploy activity log URL
            grain = grains[0]
            stages = grain.get("state", {}).get("stages", [])
            
            for stage in stages:
                if stage.get("name") == "Deploy":
                    activities = stage.get("activities", [])
                    for activity in activities:
                        if activity.get("name") == "Deploy" and activity.get("log"):
                            log_url = activity["log"]
                            # Strip /api prefix if present - our client base_url already includes /api
                            if log_url.startswith("/api/"):
                                log_url = log_url[4:]  # Remove "/api" prefix
                            # Fetch the log content
                            response = await self._client.get(log_url)
                            if response.status_code == 200:
                                return response.text
            return None
        except Exception:
            return None
    
    async def wait_for_environment(
        self,
        environment_id: str,
        timeout: Optional[int] = None,
        log_callback: Optional[Callable[[str], Awaitable[None]]] = None,
    ) -> EnvironmentResult:
        """
        Wait for environment to complete and return results.
        
        Args:
            environment_id: Environment ID
            timeout: Optional timeout override
            log_callback: Optional async callback function that receives log updates
            
        Returns:
            EnvironmentResult with command output
        """
        timeout = timeout or self.timeout
        start_time = time.time()
        last_log_content = ""  # Track actual content to detect rotation
        consecutive_errors = 0  # Track consecutive errors to avoid infinite loops
        max_consecutive_errors = 10  # Give up after this many consecutive errors
        
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                return EnvironmentResult(
                    environment_id=environment_id,
                    status="timeout",
                    error=f"Environment did not complete within {timeout} seconds",
                )
            
            try:
                env_data = await self.get_environment_status(environment_id)
                consecutive_errors = 0  # Reset on success
            except httpx.HTTPStatusError as e:
                status_code = e.response.status_code
                # 4xx client errors - return immediately (won't be fixed by retrying)
                if 400 <= status_code < 500:
                    if status_code == 404:
                        return EnvironmentResult(
                            environment_id=environment_id,
                            status="deleted",
                            error=f"Environment {environment_id} was deleted or not found. It may have been auto-cleaned by Torque.",
                        )
                    return EnvironmentResult(
                        environment_id=environment_id,
                        status="error",
                        error=f"HTTP {status_code} error: {e}",
                    )
                # 5xx server errors - log and retry
                consecutive_errors += 1
                print(f"[WARNING] HTTP {status_code} error polling environment {environment_id} ({consecutive_errors}/{max_consecutive_errors}): {e}", file=sys.stderr)
                if consecutive_errors >= max_consecutive_errors:
                    return EnvironmentResult(
                        environment_id=environment_id,
                        status="error",
                        error=f"Too many consecutive errors while polling environment: {e}",
                    )
                await asyncio.sleep(self.poll_interval)
                continue
            except Exception as e:
                # Network errors, connection issues, etc.
                consecutive_errors += 1
                print(f"[WARNING] Error polling environment {environment_id} ({consecutive_errors}/{max_consecutive_errors}): {e}", file=sys.stderr)
                if consecutive_errors >= max_consecutive_errors:
                    return EnvironmentResult(
                        environment_id=environment_id,
                        status="error",
                        error=f"Too many consecutive errors while polling environment: {e}",
                    )
                await asyncio.sleep(self.poll_interval)
                continue
            
            # If we have a log callback, fetch and stream the log
            if log_callback:
                try:
                    log_content = await self.get_grain_log(environment_id)
                    if log_content:
                        if not last_log_content:
                            # First fetch - send everything
                            await log_callback(log_content)
                            last_log_content = log_content
                        elif log_content.startswith(last_log_content):
                            # Log grew without rotation - send only new part
                            if len(log_content) > len(last_log_content):
                                new_content = log_content[len(last_log_content):]
                                await log_callback(new_content)
                                last_log_content = log_content
                        else:
                            # Log rotation detected - try to find overlap with last 10 lines
                            # Find position of 10th-to-last newline efficiently (no split)
                            pos = len(last_log_content)
                            for _ in range(10):
                                pos = last_log_content.rfind('\n', 0, pos)
                                if pos == -1:
                                    break
                            overlap_text = last_log_content[pos + 1:] if pos != -1 else last_log_content
                            
                            overlap_pos = log_content.find(overlap_text)
                            if overlap_pos != -1:
                                # Found overlap - continue from after the matched portion
                                resume_pos = overlap_pos + len(overlap_text)
                                if resume_pos < len(log_content):
                                    await log_callback(log_content[resume_pos:])
                            else:
                                # No overlap found - show rotation marker and full new content
                                await log_callback("\n... [log rotated] ...\n")
                                await log_callback(log_content)
                            last_log_content = log_content
                except Exception:
                    pass  # Ignore log fetch errors
            
            # Status can be in different places depending on API version
            details = env_data.get("details", {})
            raw_status = details.get("computed_status") or env_data.get("computed_status") or env_data.get("status", "unknown")
            current_state = details.get("state", {}).get("current_state", "")
            
            # Normalize status: lowercase and replace spaces with underscores
            status = raw_status.lower().replace(" ", "_")
            
            # Debug: print status for troubleshooting
            # print(f"Environment {environment_id}: status={status}, current_state={current_state}")
            
            # Check if environment has completed successfully
            # - "active" = blueprint completed deployment
            # - "success" = workflow completed successfully (auto-terminated)
            if status in ("active", "success"):
                # Environment/workflow completed - extract outputs
                outputs = self._extract_outputs(env_data)
                command_output_b64 = outputs.get("command_output", "")
                exit_code_str = outputs.get("exit_code", "0")
                
                # Decode base64 output
                try:
                    command_output = base64.b64decode(command_output_b64).decode('utf-8') if command_output_b64 else ""
                except Exception:
                    command_output = command_output_b64  # Fallback to raw if decode fails
                
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
            
            # Environment ended - could be success or failure, check outputs
            elif status in ("ended", "inactive") or current_state == "inactive":
                outputs = self._extract_outputs(env_data)
                command_output_b64 = outputs.get("command_output", "")
                exit_code_str = outputs.get("exit_code", "")
                
                # Decode base64 output
                try:
                    command_output = base64.b64decode(command_output_b64).decode('utf-8') if command_output_b64 else ""
                except Exception:
                    command_output = command_output_b64  # Fallback to raw if decode fails
                
                # If we have outputs, consider it a success
                if command_output or exit_code_str:
                    try:
                        exit_code = int(exit_code_str) if exit_code_str else 0
                    except (ValueError, TypeError):
                        exit_code = 0
                    
                    return EnvironmentResult(
                        environment_id=environment_id,
                        status="completed",
                        command_output=command_output,
                        exit_code=exit_code,
                    )
                else:
                    return EnvironmentResult(
                        environment_id=environment_id,
                        status="ended",
                        error=f"Environment ended without outputs. Status: {raw_status}",
                    )
            
            # Error states - check for errors in the environment
            elif status in ("active_with_error", "ended_with_error", "error", "failed", "terminating_failed"):
                # Get errors from state.errors array
                state_errors = details.get("state", {}).get("errors", [])
                error_messages = []
                for err in state_errors:
                    if isinstance(err, dict) and err.get("message"):
                        error_messages.append(err["message"])
                    elif isinstance(err, str):
                        error_messages.append(err)
                
                # Fallback to root-level errors
                if not error_messages:
                    root_errors = env_data.get("errors", [])
                    error_messages = [str(e) for e in root_errors if e]
                
                error_msg = "; ".join(error_messages) if error_messages else f"Environment failed with status: {raw_status}"
                return EnvironmentResult(
                    environment_id=environment_id,
                    status="failed",
                    error=error_msg,
                )
            
            # Still launching/deploying - wait and poll again
            await asyncio.sleep(self.poll_interval)
    
    def _extract_outputs(self, env_data: dict) -> dict:
        """Extract outputs from environment data.
        
        Outputs are in details.state.outputs as an array of {name, value} objects.
        If exit_code is 0, outputs should always be present there.
        
        Note: When a command produces no output, Torque may return the unresolved
        template string instead of an empty value. We detect these specific templates
        and treat them as empty strings.
        """
        # Known unresolved templates that indicate empty output
        EMPTY_OUTPUT_TEMPLATES = {
            "{{ .grains.remote_executor.activities.deploy.commands.run_ssh.outputs.command_output }}",
            "{{ .grains.local_executor.activities.deploy.commands.run_local.outputs.command_output }}",
        }
        
        outputs = {}
        
        state_outputs = env_data.get("details", {}).get("state", {}).get("outputs", [])
        if isinstance(state_outputs, list):
            for output_item in state_outputs:
                if isinstance(output_item, dict) and "name" in output_item:
                    value = output_item.get("value", "")
                    # Detect specific unresolved templates (Torque returns these when output is empty)
                    if value in EMPTY_OUTPUT_TEMPLATES:
                        value = ""  # Treat as empty output
                    outputs[output_item["name"]] = value
        
        return outputs
    
    async def execute_remote_command(
        self,
        target_ip: str,
        ssh_user: str,
        ssh_private_key: str,
        command: str,
        agent: Optional[str] = None,
        auto_cleanup: bool = True,
        timeout: Optional[int] = None,
        log_callback: Optional[Callable[[str], Awaitable[None]]] = None,
        init_commands: Optional[str] = None,
        finally_commands: Optional[str] = None,
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
            timeout: Optional timeout override in seconds
            log_callback: Optional async callback for streaming log updates
            init_commands: Optional commands to run before main command (overrides instance default)
            finally_commands: Optional cleanup commands (overrides instance default)
            
        Returns:
            EnvironmentResult with command output
        """
        environment_id = await self.start_environment(
            target_ip=target_ip,
            ssh_user=ssh_user,
            ssh_private_key=ssh_private_key,
            command=command,
            agent=agent,
            init_commands=init_commands,
            finally_commands=finally_commands,
        )
        
        result = None
        try:
            result = await self.wait_for_environment(environment_id, timeout=timeout, log_callback=log_callback)
            return result
        finally:
            # Workflows auto-terminate on completion (status="success"), so only call
            # end_environment if it timed out or failed (not completed)
            if result is None or result.status != "completed":
                force_terminate = result is not None and result.status == "timeout"
                try:
                    await self.end_environment(environment_id, force=force_terminate)
                except Exception as e:
                    pass  # Ignore errors - workflow may have already auto-terminated
            
            # Delete the environment only if auto_cleanup is enabled
            if auto_cleanup:
                try:
                    await self.delete_environment(environment_id)
                except Exception as e:
                    print(f"[WARNING] Failed to delete environment {environment_id}: {e}", file=sys.stderr)
    
    async def execute_local_command(
        self,
        command: str,
        agent: Optional[str] = None,
        auto_cleanup: bool = True,
        timeout: Optional[int] = None,
        log_callback: Optional[Callable[[str], Awaitable[None]]] = None,
        init_commands: Optional[str] = None,
    ) -> EnvironmentResult:
        """
        Execute a command locally on the Torque agent container.
        
        This method runs commands directly on the agent without SSH to any remote host.
        Useful for running scripts, tools, or commands that don't require a target machine.
        
        Args:
            command: Command to execute
            agent: Agent name (uses default if not specified)
            auto_cleanup: Whether to automatically delete the environment after completion
            timeout: Optional timeout override in seconds
            log_callback: Optional async callback for streaming log updates
            init_commands: Optional commands to run before the main command
            
        Returns:
            EnvironmentResult with command output
        """
        environment_id = await self.start_local_environment(
            command=command,
            agent=agent,
            init_commands=init_commands,
        )
        
        result = None
        try:
            result = await self.wait_for_environment(environment_id, timeout=timeout, log_callback=log_callback)
            return result
        finally:
            # Workflows auto-terminate on completion (status="success"), so only call
            # end_environment if it timed out or failed (not completed)
            if result is None or result.status != "completed":
                force_terminate = result is not None and result.status == "timeout"
                try:
                    await self.end_environment(environment_id, force=force_terminate)
                except Exception as e:
                    pass  # Ignore errors - workflow may have already auto-terminated
            
            # Delete the environment only if auto_cleanup is enabled
            if auto_cleanup:
                try:
                    await self.delete_environment(environment_id)
                except Exception as e:
                    print(f"[WARNING] Failed to delete environment {environment_id}: {e}", file=sys.stderr)
