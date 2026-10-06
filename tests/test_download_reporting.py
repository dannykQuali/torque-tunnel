"""How a download's outcome is reported back to the caller.

The 2026-09-23 report showed ``Duration: 0.2s`` for a call whose download spent
46 seconds failing: Duration is the command's own run time, and the transfer
happens afterwards, so it was invisible. The summary now carries the transfer's
own duration.

The download summary was also built by hand in several handlers, and they had
drifted: the async status path labelled failed downloads ``WARNING:`` while the
blocking handlers (and the CLI, which exits non-zero) treat them as failures.
One formatter now serves all of them.
"""

import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager
from torque_tunnel import mcp_tool
from torque_tunnel.mcp_tool import DownloadPlan, format_download_summary


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


def _plan(tmp_path):
    plan = DownloadPlan(needs_download=True, croc_code="c", croc_receive_dir=str(tmp_path))
    plan.file_mappings = [{"croc_filename": "_croc_dl_0_f",
                           "local_destination_path": str(tmp_path / "out" / "f")}]
    return plan


class TestFormatDownloadSummary:
    def test_nothing_to_report_is_empty(self):
        assert format_download_summary([], [], None) == ""

    def test_successes_failures_and_time_are_all_shown(self):
        text = format_download_summary(["Downloaded: C:\\a"], ["file not received (x)"], 12.34)
        assert "**Files Downloaded:**" in text
        assert "- Downloaded: C:\\a" in text
        assert "- DOWNLOAD FAILED: file not received (x)" in text
        assert "Transfer time: 12.3s" in text

    def test_failures_are_never_softened_to_warnings(self):
        text = format_download_summary([], ["file not received (x)"], None)
        assert "DOWNLOAD FAILED" in text
        assert "WARNING" not in text

    def test_long_transfers_read_in_minutes(self):
        assert "Transfer time: 2m 5.0s" in format_download_summary(["Downloaded: a"], [], 125.0)

    def test_unknown_time_is_simply_omitted(self):
        assert "Transfer time" not in format_download_summary(["Downloaded: a"], [], None)


class TestTransferTimeIsMeasured:
    @pytest.mark.asyncio
    async def test_time_runs_from_the_senders_first_report_to_completion(self, tmp_path, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(mcp_tool.time, "monotonic", clock)
        plan = _plan(tmp_path)

        plan.observe_output(f"{croc_manager.CROC_SENTINEL_SIZE} 5 _croc_dl_0_f\n")
        clock.now += 30
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_READY}\n")
        clock.now += 16
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_FAILED} exit_code=1\n")

        await mcp_tool.complete_download(plan, None)
        assert plan.transfer_seconds == pytest.approx(46.0)

    @pytest.mark.asyncio
    async def test_a_transfer_that_never_started_has_no_time(self, tmp_path):
        plan = _plan(tmp_path)
        await mcp_tool.complete_download(plan, None)
        assert plan.transfer_seconds is None

    @pytest.mark.asyncio
    async def test_only_the_first_report_starts_the_clock(self, tmp_path, monkeypatch):
        clock = FakeClock()
        monkeypatch.setattr(mcp_tool.time, "monotonic", clock)
        plan = _plan(tmp_path)

        plan.observe_output(f"{croc_manager.CROC_SENTINEL_READY}\n")
        clock.now += 10
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_RETRY} (retrying once)\n")
        clock.now += 5
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_READY}\n")
        clock.now += 5

        await mcp_tool.complete_download(plan, None)
        assert plan.transfer_seconds == pytest.approx(20.0)

    @pytest.mark.asyncio
    async def test_ordinary_output_does_not_start_the_clock(self, tmp_path, monkeypatch):
        """Command output streams through the same observer; it isn't the transfer."""
        clock = FakeClock()
        monkeypatch.setattr(mcp_tool.time, "monotonic", clock)
        plan = _plan(tmp_path)

        plan.observe_output("build step 1 of 40\n")
        clock.now += 300
        plan.observe_output(f"{croc_manager.CROC_SENTINEL_READY}\n")
        clock.now += 4

        await mcp_tool.complete_download(plan, None)
        assert plan.transfer_seconds == pytest.approx(4.0)
