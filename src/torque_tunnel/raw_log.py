"""How much of Torque's raw grain log torque-tunnel may hand out (--raw-log).

A grain log has three parts:

  1. Torque's echo of the whole rendered grain script ("Executing command: ..."). The
     script carries every blueprint input - the SSH private key among them - in plain
     text. This is the raw log that must not leak.
  2. The job's setup output: remote-shell-executor's container pre-commands (croc
     uploads, the transfer tool's whole work, their errors), from SETUP_START up to the
     decoded-commands dump (COMMANDS_DUMP). The dump shows the decoded command text,
     which may hold secrets of its own, so it counts as raw.
  3. The command's own output, after the "=== Beginning of execution ===" marker.

What a caller gets is decided by the mode the user started torque-tunnel with:

  off       (default) part 3 once the marker is there; before that (a job still in
            setup, or cancelled, failed or timed out there) part 2. Never part 1.
  fallback  as off, but a log without the marker is returned whole, part 1 included.
            This was torque-tunnel's behavior before the flag existed.
  always    the whole raw log everywhere, streaming included.

The mode is set ONLY from the --raw-log command-line flag (see main()); never from the
config file, a profile, an environment variable or a tool argument, so nothing a caller
or a shared config controls can turn it on. Every place that turns a grain log into
output goes through this module.
"""

import re

OFF = "off"
FALLBACK = "fallback"
ALWAYS = "always"
MODES = (OFF, FALLBACK, ALWAYS)

# Matches both "=== Beginning of execution ===" and "=== Beginning of local execution ===".
# Requires 50+ trailing = chars and the end of the line, so neither user output nor the
# marker's own `echo "..."` line in the echoed script source matches.
EXECUTION_MARKER = re.compile(r'=== Beginning of (?:local )?execution ={50,}\n')

# Lines the blueprint scripts print, matched as whole lines: in the echoed script source
# these texts sit inside `echo "..."`, so they cannot match there.
_TIMESTAMP = r'^(?:\[\d{2}:\d{2}:\d{2}\.\d{3}\] )?'
SETUP_START = re.compile(_TIMESTAMP + r'=== Running container pre-commands ===$', re.MULTILINE)
COMMANDS_DUMP = re.compile(_TIMESTAMP + r'=== Commands \(decoded for visibility\) ={50,}$',
                           re.MULTILINE)

# Shown where a log was withheld, so the user knows how to see it when troubleshooting.
HIDDEN_NOTE = ("(no output yet - the job had not printed anything of its own. Torque's raw "
               "log is at the Environment link; to have it returned here, start "
               "torque-tunnel with --raw-log fallback)")

_mode = OFF


def set_mode(mode: str) -> None:
    """Set the mode; called once at startup from the --raw-log flag."""
    global _mode
    if mode not in MODES:
        raise ValueError(f"--raw-log must be one of {', '.join(MODES)}, not {mode!r}")
    _mode = mode


def get_mode() -> str:
    return _mode


def stream_preamble() -> bool:
    """Whether log streamers pass the preamble through instead of waiting for the marker."""
    return _mode == ALWAYS


def command_output(log: str, marker: "re.Pattern[str]" = EXECUTION_MARKER) -> str:
    """The part of a grain log that may be returned: what follows ``marker``.

    Without the marker: the whole log in fallback mode, the job's setup output ("" if
    it has none) in off mode. In always mode the whole log.
    """
    if not log or _mode == ALWAYS:
        return log
    match = marker.search(log)
    if match:
        return log[match.end():]
    if _mode == FALLBACK:
        return log
    return _setup_output(log)


def withheld(log: str, marker: "re.Pattern[str]" = EXECUTION_MARKER) -> bool:
    """Whether ``command_output`` dropped a non-empty log entirely: off mode, no marker,
    and no setup output."""
    return (bool(log) and _mode == OFF and not marker.search(log)
            and not _setup_output(log))


def _setup_output(log: str) -> str:
    start = SETUP_START.search(log)
    if not start:
        return ""
    dump = COMMANDS_DUMP.search(log, start.end())
    return log[start.start():dump.start() if dump else len(log)]
