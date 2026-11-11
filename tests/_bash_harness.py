"""Shared helpers for tests that execute generated shell scripts.

The scripts run on Linux agent containers, so on Windows they are tested under **WSL**
(a real Linux bash with GNU coreutils), never Git Bash (DannyK, 2026-11-03). Git
Bash differs from Linux where it matters here: msys prepends /usr/bin to PATH (so a
fake `ssh`/`getent` on PATH loses to the real one), and every process it spawns is
expensive. With many parallel test workers that made a 2s test take 40s.
Elsewhere, the native bash is used.

Use `run_script()` rather than calling bash directly. It takes care of what WSL does
not do by itself:
- Windows environment variables do not reach WSL processes, so `env` is exported from
  a small launcher script. Values that are Windows paths are translated.
- Paths have to be Linux paths inside the script: embed them with `shell_path()`.
- A no-op `getent` sits on PATH behind the test's own fakes, so the DNS warm-up in the
  generated scripts never does a real lookup (WSL has a real getent, Git Bash didn't).
  A test that fakes `getent` itself just puts its fake earlier on PATH.

Coreutils fakes (`timeout`, ...) stay shell FUNCTIONS prepended to the script: they
work the same everywhere.
"""

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def _wsl_available() -> bool:
    if sys.platform != "win32" or not shutil.which("wsl.exe"):
        return False
    try:
        return subprocess.run(["wsl.exe", "-e", "true"], capture_output=True,
                              timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


if sys.platform == "win32":
    RUNNER = "wsl" if _wsl_available() else None
else:
    RUNNER = "native" if shutil.which("bash") else None

needs_bash = pytest.mark.skipif(
    RUNNER is None, reason="needs WSL (on Windows) or bash, to run the generated shell")

_WINDOWS_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_mount_root = None


def _wsl_mount_root() -> str:
    """Where WSL mounts Windows drives ("/mnt/" by default; it is configurable)."""
    global _mount_root
    if _mount_root is None:
        out = subprocess.run(["wsl.exe", "-e", "wslpath", "-u", "C:\\"],
                             capture_output=True, text=True, timeout=60).stdout.strip()
        _mount_root = out[:-2] if out.endswith("/c/") or out.endswith("/c") else "/mnt/"
        if not _mount_root.endswith("/"):
            _mount_root += "/"
    return _mount_root


def shell_path(path) -> str:
    """The path as the script sees it (C:\\x\\y -> /mnt/c/x/y under WSL)."""
    text = str(path)
    if RUNNER != "wsl" or not _WINDOWS_PATH.match(text):
        return text.replace("\\", "/") if RUNNER == "wsl" else text
    drive, rest = text[0].lower(), text[2:].replace("\\", "/")
    return f"{_wsl_mount_root()}{drive}{rest}"


def _translate(value: str) -> str:
    return shell_path(value) if _WINDOWS_PATH.match(value) else value


def start_script(script, *, env=None, prepend_path=()):
    """Like run_script, but returns the running subprocess.Popen (text, stdout piped,
    stderr into stdout) so a test can read its output while it runs."""
    script = Path(script)
    harness_bin = script.parent / ".harness-bin"
    harness_bin.mkdir(exist_ok=True)
    make_executable(harness_bin / "getent", "#!/bin/sh\nexit 0\n")
    path_dirs = [shell_path(p) for p in prepend_path] + [shell_path(harness_bin)]
    if RUNNER == "wsl":
        lines = [f"export {k}={shlex.quote(_translate(str(v)))}" for k, v in (env or {}).items()]
        lines.append(f'export PATH={shlex.quote(":".join(path_dirs))}:"$PATH"')
        lines.append(f"exec bash {shlex.quote(shell_path(script))}")
        launcher = script.with_name(script.name + ".launch.sh")
        write_text(launcher, "\n".join(lines) + "\n")
        argv, run_env = ["wsl.exe", "-e", "bash", shell_path(launcher)], None
    else:
        run_env = dict(os.environ)
        run_env.update({k: str(v) for k, v in (env or {}).items()})
        run_env["PATH"] = os.pathsep.join(path_dirs + [run_env.get("PATH", "")])
        argv = ["bash", str(script)]
    return subprocess.Popen(argv, env=run_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")


def run_script(script, *, env=None, prepend_path=(), cwd=None, timeout=120, input=None):
    """Run a bash script file; returns subprocess.CompletedProcess (text, utf-8).

    Args:
        script: path of the script (LF endings; see write_text).
        env: extra environment variables. Values that are Windows paths are translated.
        prepend_path: directories (e.g. fake bins) to put first on PATH, in order.
        cwd: working directory for the script.
        input: text for the script's stdin (stdin is empty otherwise).
    """
    script = Path(script)
    harness_bin = script.parent / ".harness-bin"
    harness_bin.mkdir(exist_ok=True)
    make_executable(harness_bin / "getent", "#!/bin/sh\nexit 0\n")
    path_dirs = [shell_path(p) for p in prepend_path] + [shell_path(harness_bin)]

    if RUNNER == "wsl":
        lines = [f"export {k}={shlex.quote(_translate(str(v)))}" for k, v in (env or {}).items()]
        lines.append(f'export PATH={shlex.quote(":".join(path_dirs))}:"$PATH"')
        if cwd is not None:
            lines.append(f"cd {shlex.quote(shell_path(cwd))} || exit 97")
        lines.append(f"exec bash {shlex.quote(shell_path(script))}")
        launcher = script.with_name(script.name + ".launch.sh")
        write_text(launcher, "\n".join(lines) + "\n")
        argv, run_env = ["wsl.exe", "-e", "bash", shell_path(launcher)], None
    else:
        run_env = dict(os.environ)
        run_env.update({k: str(v) for k, v in (env or {}).items()})
        run_env["PATH"] = os.pathsep.join(path_dirs + [run_env.get("PATH", "")])
        argv = ["bash", str(script)]

    return subprocess.run(
        argv, cwd=None if RUNNER == "wsl" else cwd, env=run_env, input=input,
        stdin=None if input is not None else subprocess.DEVNULL,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )


def write_text(path, content):
    """Write a shell/text file with LF endings and no BOM."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def make_executable(path, content):
    """Write an executable script (LF, no BOM) and mark it +x."""
    write_text(path, content)
    Path(path).chmod(0o755)
