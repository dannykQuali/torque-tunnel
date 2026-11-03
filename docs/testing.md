# Testing

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -n 16 --dist worksteal     # whole suite, ~50 s
python -m pytest tests/test_remote_transfer_tool.py  # one file, serially
```

On the 22-core dev laptop the suite takes **~50 s in parallel** and ~3 min serially (it
took ~6 min before 2026-11-03). `--dist worksteal` matters: the long Hypothesis tests
otherwise tend to start late and trail at the end. 16 workers beat `-n auto` (22): with
more workers, Windows file I/O contention slows everything.

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

Hypothesis suites must not call `tmp_path_factory.mktemp()` per example. It scans every
existing numbered directory, which is quadratic over thousands of examples. Use
`_onboarding_invariants.fresh_path()`: one parent directory per test, a plain `mkdir`
per example. What is left in those suites is real file I/O through the code under test.

## Live tests

Live croc transfers go through the public relay's per-IP admission limit, so they are
run once, never in loops. Unit tests use a fake croc and can be repeated freely.
