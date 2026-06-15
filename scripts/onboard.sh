#!/usr/bin/env bash
#
# One-command onboarding for the torque-tunnel MCP server (Linux / macOS).
#
# Builds the Python virtual environment, installs torque-tunnel, then registers
# the MCP server with your AI client(s). All arguments are passed through to the
# `register-mcp-client` subcommand. With no arguments it auto-detects installed
# clients and runs the interactive setup. Examples:
#
#   ./scripts/onboard.sh                       # build + auto-detect + setup
#   ./scripts/onboard.sh --list                # just list supported clients
#   ./scripts/onboard.sh --client claude-code  # register one client, no setup
#   ./scripts/onboard.sh --all --dry-run       # preview changes for all clients
#
# Note: --run-setup opens a browser; on a headless server pass explicit
# --client/--all flags instead (the browser step is then skipped).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
VENV="$REPO/.venv"
VENV_PY="$VENV/bin/python"

if [ ! -x "$VENV_PY" ]; then
    echo "Creating virtual environment in $VENV ..."
    if command -v python3 >/dev/null 2>&1; then BOOT=python3
    elif command -v python >/dev/null 2>&1; then BOOT=python
    else echo "No Python found on PATH. Install Python 3.10+ first." >&2; exit 1
    fi
    "$BOOT" -m venv "$VENV"
fi

echo "Installing torque-tunnel ..."
"$VENV_PY" -m pip install --upgrade pip --quiet
"$VENV_PY" -m pip install -e "$REPO" --quiet

if [ "$#" -eq 0 ]; then
    set -- --run-setup
fi

echo "Registering MCP server with AI client(s) ..."
exec "$VENV_PY" -m torque_tunnel.mcp_tool register-mcp-client "$@"
