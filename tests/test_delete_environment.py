"""Tests for TorqueClient.delete_environment (the `auto_delete_environments` path).

`delete_environment` calls Torque's `/remove_state` endpoint, which is an admin-only,
unmaintained raw DB purge (Devbox.Api EnvironmentController -> DeleteEnvConsumer): it
deletes operations/threads/grains/env/workflow rows without checking status and without
releasing any provisioned resources. So the purge must only ever be issued once the
environment's teardown is CONFIRMED COMPLETE - never while it is still terminating, and
never just because we got bored waiting.

These drive the REAL TorqueClient via httpx.MockTransport (same approach as
test_resilience.py); only asyncio.sleep is patched out so the tests stay fast.
"""

import os
import sys

import httpx
import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import torque_client as tc
from torque_tunnel.torque_client import TorqueClient


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def env_response(computed_status):
    return {"id": "env-1", "details": {"computed_status": computed_status}}


class Recorder:
    """Serves a programmed sequence of computed_status values and records requests."""

    def __init__(self, statuses, delete_status_code=200):
        # statuses: list of computed_status strings; the last one repeats forever.
        self._statuses = list(statuses)
        self._delete_status_code = delete_status_code
        self.status_polls = 0
        self.deletes = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method == "DELETE" and request.url.path.endswith("/remove_state"):
            self.deletes.append(str(request.url))
            return httpx.Response(self._delete_status_code, json={})
        if request.method == "GET":
            idx = min(self.status_polls, len(self._statuses) - 1)
            self.status_polls += 1
            status = self._statuses[idx]
            if status == "__404__":
                return httpx.Response(404, json={"errors": [{"message": "not found"}]})
            return httpx.Response(200, json=env_response(status))
        return httpx.Response(500, text=f"unexpected {request.method} {request.url}")

    @property
    def deleted(self):
        return len(self.deletes) > 0


def make_client(handler):
    client = TorqueClient(
        base_url="https://torque.example",
        token="tok",
        space="sp",
        default_agent="agent-1",
        poll_interval=1,
    )
    client._client = httpx.AsyncClient(
        base_url="https://torque.example/api",
        transport=httpx.MockTransport(handler),
    )
    return client


@pytest.fixture
def no_sleep(monkeypatch):
    """Make asyncio.sleep a no-op so the status-wait loop doesn't actually wait."""
    async def _fast_sleep(_seconds):
        return None
    monkeypatch.setattr(tc.asyncio, "sleep", _fast_sleep)


# --------------------------------------------------------------------------------------
# Purge only after a confirmed-complete teardown
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDeleteOnlyWhenTornDown:

    @pytest.mark.parametrize("status", [
        "Ended", "Inactive", "Terminated", "Force Terminated", "Released", "Cancelled",
    ])
    async def test_purges_when_teardown_complete(self, no_sleep, status):
        rec = Recorder([status])
        await make_client(rec).delete_environment("env-1")
        assert rec.deleted, f"{status!r} is a completed teardown; purge should be issued"

    async def test_does_not_purge_while_still_terminating(self, no_sleep):
        """Teardown in flight: purging now orphans whatever is still being released."""
        rec = Recorder(["Terminating"])
        await make_client(rec).delete_environment("env-1")
        assert not rec.deleted, "purged an environment that was still terminating"

    async def test_does_not_purge_when_wait_times_out(self, no_sleep):
        """The wait loop expiring is not permission to purge a live environment."""
        rec = Recorder(["Active"])
        await make_client(rec).delete_environment("env-1")
        assert not rec.deleted, "purged an environment that never finished tearing down"
        assert rec.status_polls > 1, "should have polled repeatedly before giving up"

    async def test_does_not_purge_when_teardown_failed(self, no_sleep):
        """Terminating Failed means resources leaked - keep the record for diagnosis."""
        rec = Recorder(["Terminating Failed"])
        await make_client(rec).delete_environment("env-1")
        assert not rec.deleted, "purged an environment whose teardown failed"

    async def test_waits_through_termination_then_purges(self, no_sleep):
        """Still purges once termination actually completes - the wait is not wasted."""
        rec = Recorder(["Terminating", "Terminating", "Ended"])
        await make_client(rec).delete_environment("env-1")
        assert rec.deleted, "should purge once the environment reached Ended"

    async def test_status_is_case_and_space_insensitive(self, no_sleep):
        rec = Recorder(["force terminated"])
        await make_client(rec).delete_environment("env-1")
        assert rec.deleted


# --------------------------------------------------------------------------------------
# Error tolerance - auto-delete is best-effort and must never blow up the caller
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDeleteErrorHandling:

    async def test_missing_environment_is_not_purged_and_does_not_raise(self, no_sleep):
        rec = Recorder(["__404__"])
        await make_client(rec).delete_environment("env-1")
        assert not rec.deleted

    async def test_404_on_purge_is_tolerated(self, no_sleep):
        """Already purged elsewhere - not an error."""
        rec = Recorder(["Ended"], delete_status_code=404)
        await make_client(rec).delete_environment("env-1")
        assert rec.deleted

    async def test_purge_targets_the_remove_state_endpoint(self, no_sleep):
        rec = Recorder(["Ended"])
        await make_client(rec).delete_environment("env-1")
        assert rec.deletes == ["https://torque.example/api/spaces/sp/environments/env-1/remove_state"]

    async def test_auto_cleanup_defaults_to_off(self):
        """A caller that forgets `auto_cleanup` must not get the purge by accident."""
        import inspect
        for name in ("execute_remote_command", "execute_local_command"):
            sig = inspect.signature(getattr(TorqueClient, name))
            assert sig.parameters["auto_cleanup"].default is False, \
                f"{name} defaults to purging environments"

    async def test_missing_computed_status_is_not_purged(self, no_sleep):
        """A response we can't interpret is not a confirmed teardown."""
        def handler(request):
            if request.method == "DELETE":
                return httpx.Response(200, json={})
            return httpx.Response(200, json={"id": "env-1", "details": {}})
        rec_deletes = []

        def recording(request):
            if request.method == "DELETE":
                rec_deletes.append(str(request.url))
            return handler(request)

        await make_client(recording).delete_environment("env-1")
        assert rec_deletes == []
