"""Tests for the persistent-container idle timeout fix.

Background (2026-07-29 report, Defect 4): the "2h idle timeout" was never real —
containers were created with a hardcoded PT24H duration and every command called
Torque's ADDITIVE /extend (+2h), so lifetime only ever accumulated. The fix uses
the absolute scheduled_end_time endpoint: after each command the end is set to
now + idle_timeout (idle semantics), and at command start it is armed to
now + max(idle, command_timeout + slack) so a container can't die under a
running command.
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import mcp_tool
from torque_tunnel.mcp_tool import _format_iso_duration, _container_deadline
from torque_tunnel.torque_client import TorqueClient


# ============================================================================
# _format_iso_duration
# ============================================================================

class TestFormatIsoDuration:
    def test_whole_hours(self):
        assert _format_iso_duration(7200) == "PT2H"
        assert _format_iso_duration(3600) == "PT1H"

    def test_hours_and_minutes(self):
        assert _format_iso_duration(5400) == "PT1H30M"
        assert _format_iso_duration(9000) == "PT2H30M"

    def test_minutes_only(self):
        assert _format_iso_duration(1800) == "PT30M"
        assert _format_iso_duration(60) == "PT1M"

    def test_sub_minute_floors_to_one_minute(self):
        assert _format_iso_duration(30) == "PT1M"
        assert _format_iso_duration(0) == "PT1M"


# ============================================================================
# Default idle timeout
# ============================================================================

class TestDefaultIdleTimeout:
    def test_default_is_24_hours(self):
        assert mcp_tool._CONFIG_DEFAULTS["container_idle_timeout"] == 86400


# ============================================================================
# _container_deadline
# ============================================================================

class TestContainerDeadline:
    def test_completion_uses_idle_window(self):
        """No command timeout → plain idle window from now."""
        before = datetime.now(timezone.utc)
        deadline = _container_deadline(7200)
        after = datetime.now(timezone.utc)
        assert before + timedelta(seconds=7200) <= deadline <= after + timedelta(seconds=7200)

    def test_short_command_still_gets_idle_window(self):
        """A command shorter than the idle window must not shrink it."""
        deadline = _container_deadline(7200, command_timeout=600)
        expected = datetime.now(timezone.utc) + timedelta(seconds=7200)
        assert abs((deadline - expected).total_seconds()) < 5

    def test_long_command_extends_past_idle_window(self):
        """A command longer than the idle window gets timeout + slack protection."""
        deadline = _container_deadline(7200, command_timeout=14400)  # 4h command
        expected = datetime.now(timezone.utc) + timedelta(
            seconds=14400 + mcp_tool.CONTAINER_COMMAND_SLACK_SECONDS
        )
        assert abs((deadline - expected).total_seconds()) < 5

    def test_none_timeout_treated_as_completion(self):
        deadline = _container_deadline(7200, command_timeout=None)
        expected = datetime.now(timezone.utc) + timedelta(seconds=7200)
        assert abs((deadline - expected).total_seconds()) < 5


# ============================================================================
# TorqueClient.set_scheduled_end_time
# ============================================================================

def _make_client():
    return TorqueClient(base_url="https://example.qtorque.io", token="t", space="TestSpace")


class TestSetScheduledEndTime:
    def _run(self, coro):
        return asyncio.run(coro)

    def test_sends_absolute_end_time(self):
        client = _make_client()
        response = mock.Mock(status_code=200)
        with mock.patch.object(client, "_request_with_retry", new=mock.AsyncMock(return_value=response)) as req:
            end = datetime(2026, 7, 30, 12, 30, 0)
            self._run(client.set_scheduled_end_time("env123", end))
            args, kwargs = req.call_args
            assert args[0] == "PUT"
            assert args[1] == "/spaces/TestSpace/environments/env123/scheduled_end_time"
            assert kwargs["params"] == {"value": "2026-07-30T12:30:00Z"}

    def test_aware_datetime_converted_to_utc(self):
        client = _make_client()
        response = mock.Mock(status_code=200)
        with mock.patch.object(client, "_request_with_retry", new=mock.AsyncMock(return_value=response)) as req:
            # UTC+3 → 09:00 UTC
            end = datetime(2026, 7, 30, 12, 0, 0, tzinfo=timezone(timedelta(hours=3)))
            self._run(client.set_scheduled_end_time("env123", end))
            assert req.call_args.kwargs["params"] == {"value": "2026-07-30T09:00:00Z"}

    def test_tolerates_gone_environment(self):
        """404/400 (already terminated / wrong state) must not raise."""
        client = _make_client()
        for status in (404, 400):
            response = mock.Mock(status_code=status)
            with mock.patch.object(client, "_request_with_retry", new=mock.AsyncMock(return_value=response)):
                self._run(client.set_scheduled_end_time("gone", datetime(2026, 1, 1)))

    def test_raises_on_server_error(self):
        client = _make_client()
        response = mock.Mock(status_code=500)
        response.raise_for_status.side_effect = RuntimeError("boom")
        with mock.patch.object(client, "_request_with_retry", new=mock.AsyncMock(return_value=response)):
            with pytest.raises(RuntimeError):
                self._run(client.set_scheduled_end_time("env", datetime(2026, 1, 1)))


# ============================================================================
# Persistent container creation duration
# ============================================================================

class TestCreationDuration:
    def test_duration_passed_into_payload(self):
        client = _make_client()
        with mock.patch.object(
            client, "_create_environment_idempotent", new=mock.AsyncMock(return_value="env-1")
        ) as create:
            with mock.patch.object(client, "_load_standalone_blueprint", return_value="e30="):
                asyncio.run(client.start_persistent_container(agent="a1", duration="PT2H"))
            payload = create.call_args.args[0]
            assert payload["duration"] == "PT2H"

    def test_no_hardcoded_24h_default(self):
        """The old PT24H default made the documented 2h idle timeout a fiction."""
        client = _make_client()
        with mock.patch.object(
            client, "_create_environment_idempotent", new=mock.AsyncMock(return_value="env-1")
        ) as create:
            with mock.patch.object(client, "_load_standalone_blueprint", return_value="e30="):
                asyncio.run(client.start_persistent_container(agent="a1"))
            payload = create.call_args.args[0]
            assert payload["duration"] != "PT24H"
