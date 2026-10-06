"""Shared helpers for tests that execute generated shell under bash.

On Windows, ``shutil.which("bash")`` often finds WSL's ``bash.exe``, which
mangles Windows paths; Git Bash is what these tests need. Coreutils cannot be
shimmed through PATH under Git Bash either, so fakes for ``timeout`` and the
like are shell functions prepended to the script, not files on PATH.
"""

import shutil
import sys
from pathlib import Path

import pytest


def find_bash():
    """Locate a bash that accepts Windows paths (Git Bash) - NOT WSL bash."""
    if sys.platform != "win32":
        return shutil.which("bash")
    candidates = []
    git = shutil.which("git")
    if git:
        git_root = Path(git).parent.parent
        candidates += [git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe"]
    candidates += [
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None


BASH = find_bash()

needs_bash = pytest.mark.skipif(BASH is None, reason="Git Bash not available")


def write_text(path, content):
    """Write a shell/text file with LF endings and no BOM."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


def make_executable(path, content):
    """Write an executable script (LF, no BOM) and mark it +x."""
    write_text(path, content)
    Path(path).chmod(0o755)
