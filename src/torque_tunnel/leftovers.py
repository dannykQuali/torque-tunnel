"""Remove the temp folders of file transfers whose owner is gone.

Every upload stages its files in a ``torque_croc_*`` folder and every download receives
into a ``torque_dl_*`` folder, both under the system temp dir. The process that made one
removes it when the transfer ends. A folder outlives that only when the process did not
get to it: it was restarted or killed mid-transfer (the worktogether broker restarts its
MCP servers with every agent restart), or an async run ended and nobody polled it.

Each folder therefore names its users in an owner file (``OWNER_FILE``): the
torque-tunnel process that made it, plus the croc sender or receive wrapper it started.
A folder is stale only when none of them is running any more. That matters because:
- several torque-tunnel instances can share one temp dir (one per Claude session on a
  laptop), and each one's folders are live while it runs;
- a croc sender outlives a restarted torque-tunnel and still completes its upload
  (measured on wt-agent-dannyk, 16 Nov), so its folder must stay until it exits.

A process is matched by its PID and its start time, so a reused PID is not mistaken for
the original process.

Folders from versions before the owner file (and croc send logs, which used to sit next
to them) have no owners to check: they go once they are older than a day, unless a
running process still refers to them (checked where /proc exists).

See docs/croc-file-transfer.md, "Temp folders and their clean-up".
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from typing import Optional

OWNER_FILE = ".tt-owner"
DIR_PREFIXES = ("torque_croc_", "torque_dl_")
# Files with no owner to check, removed once older than LEGACY_AGE_SECONDS (prefix,
# suffix): croc send logs of versions before 2026-11-16, which kept them in the temp
# dir itself, and a Piping Server archive whose build was cut short
# (mcp_tool.prepare_files_with_croc builds it there, then moves it into the staging dir)
LOOSE_FILES = (("torque_croc_send_", ".log"), ("tt_piping_", ".enc"))
# How old a folder with no owner file (from an older version) must be before it goes
LEGACY_AGE_SECONDS = 24 * 3600


# --- processes ----------------------------------------------------------------------

def process_started(pid) -> Optional[str]:
    """When process ``pid`` started, as an opaque token; "" when it runs but its start
    time cannot be read; None when it does not run (or is a zombie)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return None
    if os.name == "nt":
        return _windows_started(pid)
    if os.path.isdir("/proc/self"):
        return _proc_started(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except (PermissionError, OSError):
        return ""
    return ""


def _proc_started(pid: int) -> Optional[str]:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as f:
            stat = f.read()
    except FileNotFoundError:
        return None
    except OSError:
        return ""
    # The command name (field 2) may hold spaces or ')': the fields after it follow
    # the last ')'. Field 3 is the state, field 22 the start time.
    fields = stat.rsplit(")", 1)[-1].split()
    if not fields or fields[0] in ("Z", "X"):
        return None
    return fields[19] if len(fields) > 19 else ""


def _windows_started(pid: int) -> Optional[str]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    process_query_limited_information = 0x1000
    error_invalid_parameter = 87   # what OpenProcess says for a PID nobody has
    still_active = 259

    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return None if ctypes.get_last_error() == error_invalid_parameter else ""
    try:
        code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != still_active:
            return None
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            return ""
        return str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
    finally:
        kernel32.CloseHandle(handle)


# --- owner files --------------------------------------------------------------------

def _read_owners(directory: str) -> Optional[list]:
    try:
        with open(os.path.join(directory, OWNER_FILE), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    owners = data.get("processes") if isinstance(data, dict) else None
    return owners if isinstance(owners, list) else None


def _write_owners(directory: str, owners: list) -> None:
    path = os.path.join(directory, OWNER_FILE)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump({"processes": owners}, f)
    os.replace(temp, path)


def claim(directory: str) -> None:
    """Mark ``directory`` as this process's. Call right after creating it."""
    try:
        _write_owners(directory, [[os.getpid(), process_started(os.getpid()) or ""]])
    except OSError as e:
        print(f"[torque-tunnel] could not mark {directory} as in use: {e}", file=sys.stderr)


def add_process(directory: str, pid) -> None:
    """Record that process ``pid`` (a croc sender or receive wrapper this process
    started) uses ``directory``, so the folder stays while it runs, even after this
    process is gone."""
    if not directory or not isinstance(pid, int) or isinstance(pid, bool):
        return
    owners = _read_owners(directory) or [[os.getpid(), process_started(os.getpid()) or ""]]
    owners.append([pid, process_started(pid) or ""])
    try:
        _write_owners(directory, owners)
    except OSError as e:
        print(f"[torque-tunnel] could not record process {pid} for {directory}: {e}", file=sys.stderr)


def _anyone_running(owners: list) -> bool:
    for entry in owners:
        if not (isinstance(entry, list) and len(entry) == 2):
            return True   # not ours to judge
        pid, started = entry
        now = process_started(pid)
        if now is None:
            continue
        if not started or not now or now == started:
            return True
    return False


# --- referenced by a running process (folders without an owner file) ----------------

def _referenced_by_a_process(path: str) -> bool:
    """Does a running process name ``path`` in its command line, work in it, or hold
    it (or a file in it) open? Only where /proc exists; elsewhere nothing can be told,
    and False is returned."""
    if not os.path.isdir("/proc/self"):
        return False

    def inside(target: str) -> bool:
        return target == path or target.startswith(path + os.sep)

    needle = path.encode()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as f:
                if needle in f.read():
                    return True
            if inside(os.readlink(f"/proc/{name}/cwd")):
                return True
            fd_dir = f"/proc/{name}/fd"
            for fd in os.listdir(fd_dir):
                try:
                    if inside(os.readlink(f"{fd_dir}/{fd}")):
                        return True
                except OSError:
                    continue
        except OSError:
            continue
    return False


# --- the sweep ----------------------------------------------------------------------

def is_stale(directory: str, *, legacy_age: float = LEGACY_AGE_SECONDS,
             now: Optional[float] = None) -> bool:
    """May ``directory`` (a transfer's temp folder) be removed?"""
    owners = _read_owners(directory)
    if owners is not None:
        return not _anyone_running(owners)
    now = time.time() if now is None else now
    try:
        age = now - os.stat(directory).st_mtime
    except OSError:
        return False
    return age > legacy_age and not _referenced_by_a_process(directory)


def sweep(temp_dir: Optional[str] = None, *, legacy_age: float = LEGACY_AGE_SECONDS,
          now: Optional[float] = None) -> list[str]:
    """Remove the stale transfer folders (and old loose files, LOOSE_FILES) in
    ``temp_dir`` (default: the system temp dir). Returns what was removed."""
    temp_dir = temp_dir or tempfile.gettempdir()
    now = time.time() if now is None else now
    removed = []
    try:
        entries = list(os.scandir(temp_dir))
    except OSError:
        return removed
    for entry in entries:
        try:
            if entry.name.startswith(DIR_PREFIXES) and entry.is_dir(follow_symlinks=False):
                if is_stale(entry.path, legacy_age=legacy_age, now=now):
                    shutil.rmtree(entry.path, ignore_errors=True)
                    if not os.path.exists(entry.path):
                        removed.append(entry.path)
            elif (any(entry.name.startswith(p) and entry.name.endswith(s) for p, s in LOOSE_FILES)
                  and entry.is_file(follow_symlinks=False)):
                if now - entry.stat().st_mtime > legacy_age and not _referenced_by_a_process(entry.path):
                    os.remove(entry.path)
                    removed.append(entry.path)
        except OSError:
            continue
    return removed
