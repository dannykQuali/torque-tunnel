"""Remote-to-remote file transfer: the parts that need no Torque connection.

A transfer copies files from a SOURCE machine to a DESTINATION machine that cannot
reach each other. With croc it uses two Torque environments - the sender's (stage +
croc send) and the receiver's (croc receive + verify + place) - which report through
sentinel lines in their grain logs. When both endpoints sit behind the same agent, one
environment copies directly (ssh to ssh) and reports with the receiver's sentinels.

This module reads those logs and decides what the pair's state is. It is stateless on
purpose: the status tool re-reads both full logs on every call, so nothing has to
survive between calls (an MCP server restart loses nothing).
See docs/design-remote-to-remote-transfer.md.
"""

import os
import re
from dataclasses import dataclass, field
from typing import Optional

from . import croc_manager


def _sentinel_lines(log: str, sentinel: str):
    """Yield the text after ``sentinel`` on each line that carries it.

    A line where the sentinel follows ``echo`` is a command being shown, not emitted.
    """
    for raw in (log or "").splitlines():
        idx = raw.find(sentinel)
        if idx < 0:
            continue
        if re.search(r"echo\s+[\"']?$", raw[:idx]):
            continue
        yield raw[idx + len(sentinel):].strip()


@dataclass
class SenderReport:
    """What the sender environment has reported so far."""
    sizes: dict = field(default_factory=dict)    # croc_filename -> bytes
    hashes: dict = field(default_factory=dict)   # croc_filename -> md5 hex
    dirs: set = field(default_factory=set)       # croc_filenames staged as a tar.gz
    ready: bool = False      # the relay room is registered NOW (no RETRY after it)
    done: bool = False
    failure: str = ""        # the FAILED sentinel's payload, "" when none
    # Transports the sender offers ("croc", "piping"); empty: a sender from before
    # offers existed, which means croc (docs/piping-transport.md)
    offers: list = field(default_factory=list)
    # The Piping Server archive's (encrypted bytes, sha256), from the sender's log: the
    # receiver's reference, which never goes through the Piping Server
    piping_archive: Optional[tuple] = None


def parse_archive_line(payload: str) -> Optional[tuple]:
    """``<bytes> <sha256>`` after croc_manager.PIPING_ARCHIVE_SENTINEL, or None."""
    parts = (payload or "").split()
    if len(parts) == 2 and parts[0].isdigit() and int(parts[0]) > 0 and re.fullmatch(r"[0-9a-f]{64}", parts[1]):
        return int(parts[0]), parts[1]
    return None


def parse_sender_log(log: str) -> SenderReport:
    report = SenderReport()
    events = []  # ("ready" | "retry", position) in log order
    for raw in (log or "").splitlines():
        line = raw.strip()
        if croc_manager.CROC_SENTINEL_READY in line:
            events.append("ready")
        elif croc_manager.CROC_SENTINEL_RETRY in line:
            events.append("retry")
    report.ready = bool(events) and events[-1] == "ready"
    for payload in _sentinel_lines(log, croc_manager.CROC_SENTINEL_SIZE):
        size, _, name = payload.partition(" ")
        if size.isdigit() and name.strip():
            report.sizes[name.strip()] = int(size)
    for payload in _sentinel_lines(log, croc_manager.CROC_SENTINEL_MD5):
        md5, _, name = payload.partition(" ")
        if re.fullmatch(r"[0-9a-fA-F]{32}", md5) and name.strip():
            report.hashes[name.strip()] = md5.lower()
    for payload in _sentinel_lines(log, croc_manager.CROC_SENTINEL_DIR):
        if payload:
            report.dirs.add(payload)
    report.done = any(True for _ in _sentinel_lines(log, croc_manager.CROC_SENTINEL_DONE))
    failures = list(_sentinel_lines(log, croc_manager.CROC_SENTINEL_FAILED))
    if failures:
        report.failure = failures[-1] or "exit_code=unknown"
    offers = list(_sentinel_lines(log, croc_manager.TRANSPORT_OFFER_SENTINEL))
    if offers:
        report.offers = [t for t in offers[-1].split() if t in croc_manager.TRANSPORTS]
    archives = [a for a in map(parse_archive_line, _sentinel_lines(log, croc_manager.PIPING_ARCHIVE_SENTINEL)) if a]
    if archives:
        report.piping_archive = archives[-1]
    return report


@dataclass
class ReceiverReport:
    """What the receiver (or direct-copy) environment has reported so far."""
    placed: list = field(default_factory=list)   # destination paths, in order
    done: bool = False
    failure: str = ""
    progress: str = ""       # the latest progress/heartbeat line, for humans


def parse_receiver_log(log: str) -> ReceiverReport:
    report = ReceiverReport()
    for payload in _sentinel_lines(log, croc_manager.CROC_RX_SENTINEL_PLACED):
        if payload and payload not in report.placed:
            report.placed.append(payload)
    report.done = any(True for _ in _sentinel_lines(log, croc_manager.CROC_RX_SENTINEL_DONE))
    failures = list(_sentinel_lines(log, croc_manager.CROC_RX_SENTINEL_FAILED))
    if failures:
        report.failure = failures[-1] or "exit_code=unknown"
    for raw in (log or "").splitlines():
        for marker in ("[croc receive]", "[direct copy]", "[piping receive]", "[piping]"):
            idx = raw.find(marker)
            if idx >= 0 and not re.search(r"echo\s+[\"']?$", raw[:idx]):
                report.progress = raw[idx:].strip()
    return report


def croc_filename(index: int, source_path: str) -> str:
    """Unique staging name for one file of a transfer."""
    base = os.path.basename(source_path.rstrip("/\\")) or "file"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return f"_croc_rl_{index}_{base}"


def build_manifest(files: list[dict], report: SenderReport) -> tuple[list[dict], list[str]]:
    """The receiver's manifest from the transfer's files and the sender's report.

    Returns (manifest, errors). A file without a reported size cannot be verified, so it
    is an error rather than an entry that would accept anything.
    """
    manifest, errors = [], []
    for f in files:
        name = f["croc_filename"]
        if name not in report.sizes:
            errors.append(f"the sender did not report the size of {f['source_path']}")
            continue
        manifest.append({
            "croc_filename": name,
            "size": report.sizes[name],
            "md5": report.hashes.get(name),
            "is_dir": name in report.dirs,
            "destination_path": f["destination_path"],
            "mode": f.get("mode"),
        })
    return manifest, errors


def choose_relay(source_settings: dict, destination_settings: dict) -> dict:
    """The one relay both sides use, resolved from each endpoint's profile.

    Both profiles agree (the normal case, including both unset = croc's public relay):
    that relay. They disagree: the SOURCE profile's - the sender registers the room
    there, and the receiver joins it. Its password travels with it. ``transfers`` is
    the sender's (only croc send takes it).
    """
    return {
        "relay": source_settings["relay"],
        "relay_password": source_settings["relay_password"],
        "transfers": source_settings["transfers"],
        # The Piping Server fallback (docs/piping-transport.md): the source's server
        # (both sides must use the same); each side may use only its own allowed ones.
        "piping_server": source_settings.get("piping_server", ""),
        "sender_transports": source_settings.get("transports", ["croc", "piping"]),
        "receiver_transports": destination_settings.get("transports", ["croc", "piping"]),
        "relays_differ": (croc_manager.effective_relay(source_settings["relay"])
                          != croc_manager.effective_relay(destination_settings["relay"])),
    }


@dataclass
class PairState:
    """The transfer's overall state, and what the status call must do about it."""
    status: str                         # "RUNNING" | "COMPLETED" | "FAILED"
    reason: str = ""
    end_sender: bool = False
    end_receiver: bool = False


def evaluate_pair(receiver: ReceiverReport, receiver_status: str, receiver_ended: bool,
                  sender: Optional[SenderReport] = None, sender_status: str = "",
                  sender_ended: bool = False) -> PairState:
    """Decide the pair's state from both environments' reports and Torque statuses.

    ``sender`` is None for a direct copy (one environment). The transfer is finished
    when the RECEIVER is: the sender's job ends when croc send does, before the files
    are verified and placed.
    """
    if receiver.done:
        if not receiver_ended:
            # The files are placed; the environment is still wrapping up (its own
            # command and outputs). Blueprints don't end themselves, so the pair is
            # ended once it is done - by the next poll.
            return PairState("RUNNING", "all files placed; the receiving environment is finishing")
        return PairState("COMPLETED", end_sender=sender is not None, end_receiver=True)
    if receiver.failure:
        if sender is not None and sender.failure:
            # Both failed: the sender's failure is the cause. The receiver only joins
            # the sender's room, so its error ("room not ready, maybe peer
            # disconnected") is what the sender's failure looks like from there
            # (2026-11-09: the sender could not reach the relay at all).
            return PairState("FAILED",
                             f"sender: {describe_failure(sender.failure)}; "
                             f"the receiver then failed too: {describe_failure(receiver.failure)}",
                             end_sender=True, end_receiver=True)
        return PairState("FAILED", describe_failure(receiver.failure),
                         end_sender=sender is not None, end_receiver=True)
    if sender is not None and sender.failure:
        return PairState("FAILED", "sender: " + describe_failure(sender.failure),
                         end_sender=True, end_receiver=True)
    if receiver_ended:
        return PairState("FAILED",
                         f"the receiving environment ended ({receiver_status}) without reporting a result",
                         end_sender=sender is not None, end_receiver=True)
    if sender is not None and sender_ended and not sender.done:
        return PairState("FAILED",
                         f"the sending environment ended ({sender_status}) before the transfer finished",
                         end_sender=True, end_receiver=True)
    return PairState("RUNNING")


def describe_failure(payload: str) -> str:
    """A FAILED sentinel's payload (``exit_code=N reason=...``) in plain words."""
    match = re.search(r"exit_code=(\S+)(?:\s+reason=(.*))?", payload or "")
    if not match:
        return payload or "unknown error"
    code, reason = match.group(1), (match.group(2) or "").strip()
    if code.lstrip("-").isdigit():
        text = f"exit code {code}" + (f": {reason}" if reason else "")
    else:
        text = reason or f"failed during {code}"
    hint = croc_manager.describe_croc_error(reason)
    return text + (f" ({hint})" if hint else "")
