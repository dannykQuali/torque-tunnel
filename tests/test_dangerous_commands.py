"""Tests for check_dangerous_command in mcp_tool."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel.mcp_tool import check_dangerous_command


# ---------------------------------------------------------------------------
# True positives — must be caught
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    # bare patterns
    "docker restart",
    "docker stop",
    "docker kill",
    "docker rm",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "init 0",
    "init 6",
    "systemctl restart docker",
    "systemctl stop docker",
    "service docker restart",
    "service docker stop",
    # with container/args appended
    "docker rm mycontainer",
    "docker rm -f mycontainer",
    "docker rm -f $(docker ps -aq)",
    "docker stop mycontainer",
    "docker kill mycontainer",
    "docker restart mycontainer",
    "systemctl restart docker --now",
    "systemctl stop docker.service",
    # with leading whitespace / mixed case
    "  docker rm mycontainer",
    "Docker RM mycontainer",
    "DOCKER STOP mycontainer",
    "REBOOT",
    "SHUTDOWN -h now",
    # embedded in a shell pipeline
    "echo foo && docker rm mycontainer",
    "docker rm mycontainer; echo done",
    "sudo docker rm mycontainer",
])
def test_dangerous_caught(cmd):
    assert check_dangerous_command(cmd) is not None, f"Expected danger for: {cmd!r}"


# ---------------------------------------------------------------------------
# False positives — must NOT be caught
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    # docker rmi must not match "docker rm"
    "docker rmi myimage",
    "docker rmi -f myimage",
    "docker rmi $(docker images -q)",
    # unrelated docker commands
    "docker run myimage",
    "docker ps",
    "docker build .",
    "docker pull nginx",
    "docker exec -it mycontainer bash",
    "docker logs mycontainer",
    "docker inspect mycontainer",
    "docker network ls",
    "docker volume ls",
    # single-word patterns (reboot, shutdown, halt, …) match anywhere they appear
    # as a whole word — including inside echo arguments — so those are intentionally
    # NOT listed here; the detector is conservative by design.
    "cat /etc/docker/daemon.json",
    "grep restart /etc/crontab",
    "systemctl status docker",
    "systemctl enable docker",
    "service docker status",
    "service docker start",
    # init with unrelated numbers
    "init 3",
    "init 5",
])
def test_safe_not_caught(cmd):
    assert check_dangerous_command(cmd) is None, f"Unexpected danger for: {cmd!r}"
