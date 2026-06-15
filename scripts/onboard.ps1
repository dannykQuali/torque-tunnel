<#
.SYNOPSIS
  One-command onboarding for the torque-tunnel MCP server (Windows / PowerShell).

.DESCRIPTION
  Builds the Python virtual environment, installs torque-tunnel, then registers
  the MCP server with your AI client(s) and (by default) launches the interactive
  Torque setup.

  All arguments are passed through to the `configure` subcommand. With no
  arguments it auto-detects installed clients and runs setup. Examples:

    .\scripts\onboard.ps1                       # build + auto-detect + setup
    .\scripts\onboard.ps1 --list                # just list supported clients
    .\scripts\onboard.ps1 --client claude-code  # configure one client, no setup
    .\scripts\onboard.ps1 --all --dry-run       # preview changes for all clients
#>
$ErrorActionPreference = "Stop"

$repo   = Split-Path -Parent $PSScriptRoot
$venv   = Join-Path $repo ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $venvPy)) {
    Write-Host "Creating virtual environment in $venv ..."
    $pyExe = $null; $pyArgs = @()
    if (Get-Command py -ErrorAction SilentlyContinue)          { $pyExe = "py"; $pyArgs = @("-3") }
    elseif (Get-Command python -ErrorAction SilentlyContinue)  { $pyExe = "python" }
    elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $pyExe = "python3" }
    else { Write-Error "No Python found on PATH. Install Python 3.10+ first."; exit 1 }
    & $pyExe @pyArgs -m venv $venv
    if ($LASTEXITCODE -ne 0) { Write-Error "Failed to create virtual environment."; exit 1 }
}

Write-Host "Installing torque-tunnel ..."
& $venvPy -m pip install --upgrade pip --quiet
& $venvPy -m pip install -e $repo --quiet
if ($LASTEXITCODE -ne 0) { Write-Error "Installation failed."; exit 1 }

$rest = $args
if (-not $rest -or $rest.Count -eq 0) { $rest = @("--run-setup") }

Write-Host "Configuring AI client(s) ..."
& $venvPy -m torque_tunnel.mcp_tool configure @rest
exit $LASTEXITCODE
