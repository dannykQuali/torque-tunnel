# Testing

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -n 16 --dist worksteal     # whole suite, ~20-25 s
python -m pytest tests/test_remote_transfer_tool.py  # one file, serially
```

On the 22-core dev laptop the suite takes **~20-25 s in parallel** and ~1:45 serially
(2026-11-06; it was ~57 s / ~3:15 before, and ~6 min before 2026-11-03). Of the parallel
time, ~8 s is startup: xdist has every worker import and collect every test module, and
16 of them doing so at once take ~9 s where one takes ~3 s. 8 to 16 workers end up within
noise of each other; `--dist worksteal` keeps a slow file from trailing at the end.

## Where the time went (profiled 2026-11-06)

- **Opening a file costs ~5 ms here** (each new file is scanned). The onboarding property
  suites (Hypothesis, thousands of examples) opened four per example and spent ~80% of
  their time in `open()`: ~83 s of a 196 s serial run, and a 21 s test that capped the
  parallel run. They now run the real `merge_entry` against an in-memory file
  (`_onboarding_invariants.MemoryPath`); its disk side is covered by the real-file tests.
  Do not go back to per-example files on disk.
- **Every `TorqueClient` built its own SSL context**, loading the whole CA bundle (~15 ms,
  more per proxy transport): ~2 s per 8 tool-level tests. It is now built once per
  process (`torque_client._shared_ssl_context`), which also helps production, where a
  tool call creates several clients.
- **Fixed waits in timing-based code** are module constants so tests can shrink them:
  the send monitor's tick, the relay monitor's tick, and the local receive wrapper's
  polls and startup pause (`CROC_RECEIVE_GATE_POLL_SECONDS`,
  `CROC_RECEIVE_CROC_POLL_SECONDS`, `CROC_RECEIVE_STARTUP_CHECK_SECONDS`). A harness that
  runs generated croc commands must shrink every tick its scripts use - one left at the
  production 0.5 s made each sender test ~0.5 s slower.
- What is left is mostly the WSL-run shell tests (~half of the parallel busy time): their
  scripts and fakes live under `/mnt/c`, which WSL serves over 9P, and that contends
  under 16 workers. WSL launches themselves are not the problem (~0.15 s, and they run
  concurrently).
- `PYTHONDONTWRITEBYTECODE=1` (set in some agent shells) stops pytest caching rewritten
  test modules, but it measured within noise of an unset run at 16 workers.

## Shell scripts run under WSL

Many tests execute the generated shell for real: croc send/receive wrappers, the croc
install, the blueprint's own script, and remote-to-remote transfers. Those scripts run
on Linux agent containers, so on Windows they are executed under **WSL**, never Git
Bash (DannyK, 2026-11-03). Elsewhere the native bash is used. Without WSL, these tests
are skipped (`needs_bash`).

Git Bash was replaced for two reasons:
- **Behaviour.** msys prepends `/usr/bin` to PATH, so a fake `ssh`/`getent` on PATH lost
  to the real one, and coreutils differ from Linux.
- **Speed.** Its process spawning is slow, and under parallel workers it contended so
  badly that 2 s tests took 40 s.

Use `tests/_bash_harness.py`:
- **`run_script(script, env=..., prepend_path=[fake_bin], cwd=...)`.** Windows
  environment variables don't reach WSL, so `env` is exported by a small launcher
  script. Values that are Windows paths are translated to `/mnt/c/...`.
- **`shell_path(path)`** for any path embedded in a script (`C:\x` → `/mnt/c/x`).
- **A no-op `getent`** is on PATH behind the test's own fakes. The generated DNS warm-up
  then never does a real lookup. A test that fakes `getent` puts its own earlier on PATH.
- **Coreutils fakes** (`timeout`, `ssh` in the transfer tests) are shell functions
  prepended to the script.

## Keeping timing-based tests fast

The croc monitors poll on a tick and decide in "checks" of 10 ticks
(`CROC_SEND_MONITOR_TICK_SECONDS`, `RELAY_MONITOR_TICK_SECONDS`, production 0.5 s).
Tests set the tick to 0.05 s, so stall and hang rules fire within a second or two
instead of minutes, with the same check counts. A fake croc that "waits" or "hangs"
only needs to outlast the shortened window; use `exec sleep` so the monitor's kill
reaches it.

Hypothesis suites must not touch the disk per example: `tmp_path_factory.mktemp()` scans
every existing numbered directory (quadratic over thousands of examples), and even plain
files cost ~5 ms per open. Use `_onboarding_invariants.memory_path()` with `run_merge()`.

## Live tests

Live croc transfers go through the public relay's per-IP admission limit, so they are
run once, never in loops. Unit tests use a fake croc and can be repeated freely.
