"""Tests for API resilience: transient-error retries, idempotent creates, the
two-budget wait model, and environment naming.

These drive the REAL TorqueClient via httpx.MockTransport (built into httpx, no extra
dep) with programmed response sequences, so the real retry/reconcile/naming code runs.
asyncio.sleep is patched out (or made to advance a fake clock) to keep tests fast and
non-flaky per the project's testing guidelines.
"""

import base64
import json
import os
import re
import sys

import httpx
import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import torque_client as tc
from torque_tunnel.torque_client import (
    TorqueClient,
    build_environment_name,
    generate_idempotency_key,
    sanitize_description,
    _is_transient_status,
    LABEL_KEY,
    PARENT_LABEL_KEY,
)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def make_client(handler, **kwargs):
    """Build a TorqueClient whose HTTP layer is a MockTransport running `handler`."""
    client = TorqueClient(
        base_url="https://torque.example",
        token="tok",
        space="sp",
        default_agent="agent-1",
        poll_interval=1,
        **kwargs,
    )
    # Replace the real AsyncClient with one backed by a mock transport.
    client._client = httpx.AsyncClient(
        base_url="https://torque.example/api",
        transport=httpx.MockTransport(handler),
    )
    return client


def active_env_response(command_output="hi", exit_code="0"):
    """An environment-details dict in a completed ('Active') state with outputs."""
    b64 = base64.b64encode(command_output.encode()).decode()
    return {
        "id": "env-1",
        "details": {
            "computed_status": "Active",
            "state": {
                "current_state": "active",
                "outputs": [
                    {"name": "command_output", "value": b64},
                    {"name": "exit_code", "value": exit_code},
                ],
            },
        },
    }


def launching_env_response():
    """An environment still deploying (non-terminal)."""
    return {
        "id": "env-1",
        "details": {"computed_status": "Launching", "state": {"current_state": "launching"}},
    }


@pytest.fixture
def no_sleep(monkeypatch):
    """Make asyncio.sleep a no-op so retries/backoff don't actually wait."""
    async def _fast_sleep(_seconds):
        return None
    monkeypatch.setattr(tc.asyncio, "sleep", _fast_sleep)


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t

    def advance(self, dt):
        self.t += dt


@pytest.fixture
def fake_clock(monkeypatch):
    """Deterministic monotonic clock; asyncio.sleep advances it instead of waiting."""
    clock = FakeClock()
    monkeypatch.setattr(tc.time, "monotonic", clock.monotonic)

    async def _advancing_sleep(seconds):
        clock.advance(seconds)
    monkeypatch.setattr(tc.asyncio, "sleep", _advancing_sleep)
    return clock


# --------------------------------------------------------------------------------------
# Pure helpers: key generation + naming
# --------------------------------------------------------------------------------------

class TestKeyAndNaming:
    def test_key_is_lowercase_base32_and_unique(self):
        keys = {generate_idempotency_key() for _ in range(1000)}
        assert len(keys) == 1000  # unique
        for k in keys:
            assert re.fullmatch(r"[a-z2-7]+", k), k
            assert len(k) == 26

    def test_build_name_with_description(self):
        name = build_environment_name("ssh", "Monitor vcenter", "abcdef")
        assert name == "tunneled-Monitor vcenter-ssh-abcdef"
        assert name.endswith("-abcdef")

    def test_build_name_without_description(self):
        assert build_environment_name("persistent-container", None, "xyz") == "tunneled-persistent-container-xyz"
        assert build_environment_name("ssh", "   ", "xyz") == "tunneled-ssh-xyz"

    def test_sanitize_collapses_and_caps(self):
        assert sanitize_description("a\n\nb\tc") == "a b c"
        long = "x" * 200
        assert len(sanitize_description(long)) == 60
        assert sanitize_description(None) == ""


class TestTransientClassification:
    @pytest.mark.parametrize("code", [500, 502, 503, 504, 401, 429])
    def test_transient(self, code):
        assert _is_transient_status(code) is True

    @pytest.mark.parametrize("code", [200, 400, 403, 404, 422])
    def test_permanent(self, code):
        assert _is_transient_status(code) is False


# --------------------------------------------------------------------------------------
# wait_for_environment: retries + two-budget model
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
class TestWaitForEnvironment:
    async def test_retries_500_then_completes(self, no_sleep):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] <= 3:
                return httpx.Response(500, text="boom")
            return httpx.Response(200, json=active_env_response())

        client = make_client(handler)
        result = await client.wait_for_environment("env-1", timeout=100)
        assert result.status == "completed"
        assert result.command_output == "hi"
        assert calls["n"] == 4

    async def test_retries_401_then_completes(self, no_sleep):
        """Regression: a transient 401 during a redeploy must NOT abort the run."""
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(401, text="Unauthorized")
            return httpx.Response(200, json=active_env_response())

        client = make_client(handler)
        result = await client.wait_for_environment("env-1", timeout=100)
        assert result.status == "completed"

    async def test_403_fails_fast(self, no_sleep):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(403, text="Forbidden")

        client = make_client(handler)
        result = await client.wait_for_environment("env-1", timeout=100)
        assert result.status == "error"
        assert "403" in result.error
        assert calls["n"] == 1  # not retried

    async def test_404_deleted(self, no_sleep):
        def handler(request):
            return httpx.Response(404, text="gone")

        client = make_client(handler)
        result = await client.wait_for_environment("env-1", timeout=100)
        assert result.status == "deleted"

    async def test_outage_exceeds_budget(self, fake_clock):
        def handler(request):
            return httpx.Response(500, text="down")

        client = make_client(handler, retry_budget_seconds=30)
        result = await client.wait_for_environment("env-1", timeout=100000)
        assert result.status == "error"
        assert "unreachable" in result.error.lower()

    async def test_outage_time_excluded_from_wait_timeout(self, fake_clock):
        """A long outage must not consume the caller's (healthy) wait budget."""
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            # First 5 polls fail (an outage far longer than the wait timeout),
            # then the environment reports completed.
            if calls["n"] <= 5:
                return httpx.Response(503, text="deploying")
            return httpx.Response(200, json=active_env_response())

        # Small wait timeout, large outage budget: if outage counted against the wait
        # timeout this would time out; with Option B it completes.
        client = make_client(handler, retry_budget_seconds=100000)
        result = await client.wait_for_environment("env-1", timeout=5)
        assert result.status == "completed"

    async def test_suspend_does_not_trip_outage_budget(self, monkeypatch):
        """A system suspend (huge gap between polls) must not abort a still-running op.

        Regression for: `outage 3s` jumping to `unreachable for 3261s` after a laptop sleep.
        """
        clock = FakeClock()
        monkeypatch.setattr(tc.time, "monotonic", clock.monotonic)
        state = {"suspended": False}

        async def sleeper(sec):
            clock.advance(sec)
            if not state["suspended"]:
                state["suspended"] = True
                clock.advance(3000)  # simulate laptop sleep during the first backoff
        monkeypatch.setattr(tc.asyncio, "sleep", sleeper)

        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(503, text="down")  # opens an outage, then we "sleep"
            return httpx.Response(200, json=active_env_response())  # recovers after wake

        # Budget far smaller than the 3000s suspend: without exclusion this would abort.
        client = make_client(handler, retry_budget_seconds=30)
        result = await client.wait_for_environment("env-1", timeout=100000)
        assert result.status == "completed"

    async def test_retry_disabled_errors_on_transient(self, no_sleep):
        def handler(request):
            return httpx.Response(500, text="down")

        client = make_client(handler, retry_enabled=False)
        result = await client.wait_for_environment("env-1", timeout=100)
        assert result.status == "error"


# --------------------------------------------------------------------------------------
# Idempotent create + reconcile
# --------------------------------------------------------------------------------------

@pytest.mark.asyncio
class TestIdempotentCreate:
    async def test_create_success_sets_label_and_name(self, no_sleep):
        captured = {}

        def handler(request):
            if request.method == "POST":
                captured["payload"] = json.loads(request.content)
                return httpx.Response(200, json={"id": "env-new"})
            raise AssertionError("no other calls expected")

        client = make_client(handler)
        env_id = await client.start_environment(
            target_ip="1.2.3.4", ssh_user="root", command="echo hi",
            command_description="do a thing",
        )
        assert env_id == "env-new"
        payload = captured["payload"]
        # Label carries the idempotency id
        labels = {l["key"]: l["value"] for l in payload["labels"]}
        assert LABEL_KEY in labels
        key = labels[LABEL_KEY]
        # Name is human-facing (description leads) and ends with the key
        assert payload["environment_name"].startswith("tunneled-do a thing-ssh-")
        assert payload["environment_name"].endswith(f"-{key}")

    async def test_transient_then_reconcile_adopts_without_second_post(self, no_sleep):
        counts = {"post": 0, "get": 0}

        def handler(request):
            if request.method == "POST":
                counts["post"] += 1
                return httpx.Response(500, text="boom")
            # reconcile GET /environments?labels=...
            counts["get"] += 1
            assert "labels" in request.url.params
            assert request.url.params.get("match_all_labels") == "true"
            return httpx.Response(200, json=[{"id": "env-landed"}])

        client = make_client(handler)
        env_id = await client.start_environment(
            target_ip="1.2.3.4", ssh_user="root", command="echo hi",
        )
        assert env_id == "env-landed"
        assert counts["post"] == 1          # NOT re-posted -> at-most-once
        assert counts["get"] >= 1

    async def test_transient_then_absent_then_repost(self, no_sleep):
        counts = {"post": 0, "get": 0}

        def handler(request):
            if request.method == "POST":
                counts["post"] += 1
                if counts["post"] == 1:
                    return httpx.Response(500, text="boom")
                return httpx.Response(200, json={"id": "env-second"})
            counts["get"] += 1
            return httpx.Response(200, json=[])  # confirmed absent

        client = make_client(handler)
        env_id = await client.start_environment(
            target_ip="1.2.3.4", ssh_user="root", command="echo hi",
        )
        assert env_id == "env-second"
        assert counts["post"] == 2

    async def test_reconcile_ambiguous_fails_safe(self, no_sleep):
        """If the label filter is ignored (many results), never adopt a random env."""
        counts = {"post": 0}

        def handler(request):
            if request.method == "POST":
                counts["post"] += 1
                return httpx.Response(500, text="boom")
            return httpx.Response(200, json=[{"id": "a"}, {"id": "b"}])

        client = make_client(handler)
        with pytest.raises(RuntimeError):
            await client.start_environment(target_ip="1.2.3.4", ssh_user="root", command="x")
        assert counts["post"] == 1  # did not re-POST

    async def test_permanent_error_fails_fast(self, no_sleep):
        counts = {"post": 0, "get": 0}

        def handler(request):
            if request.method == "POST":
                counts["post"] += 1
                return httpx.Response(400, text="bad blueprint")
            counts["get"] += 1
            return httpx.Response(200, json=[])

        client = make_client(handler)
        with pytest.raises(RuntimeError):
            await client.start_environment(
                target_ip="1.2.3.4", ssh_user="root", command="echo hi",
            )
        assert counts["post"] == 1
        assert counts["get"] == 0  # no reconcile on permanent error

    async def test_persistent_command_carries_parent_label(self, no_sleep):
        captured = {}

        def handler(request):
            captured["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"id": "env-cmd"})

        client = make_client(handler)
        await client.start_environment(
            target_ip="10.0.0.5", ssh_user="root", command="uptime",
            environment_kind="persistent-command", parent_env_id="container-env-9",
            command_description="uptime check",
        )
        labels = {l["key"]: l["value"] for l in captured["payload"]["labels"]}
        assert labels[PARENT_LABEL_KEY] == "container-env-9"
        assert captured["payload"]["environment_name"].startswith("tunneled-uptime check-persistent-command-")

    async def test_local_and_persistent_container_names(self, no_sleep):
        seen = {}

        def handler(request):
            payload = json.loads(request.content)
            seen[payload["blueprint_name"]] = payload["environment_name"]
            return httpx.Response(200, json={"id": "x"})

        client = make_client(handler)
        await client.start_local_environment(command="ls", command_description="listing")
        await client.start_persistent_container(container_description="my session")
        assert seen[client.LOCAL_BLUEPRINT_NAME].startswith("tunneled-listing-disposable-container-")
        assert seen[client.PERSISTENT_CONTAINER_BLUEPRINT].startswith("tunneled-my session-persistent-container-")

    async def test_empty_description_is_accepted(self, no_sleep):
        """Description is required in the MCP schema but an empty value must never fail;
        it simply yields a kind-only name."""
        captured = {}

        def handler(request):
            captured["payload"] = json.loads(request.content)
            return httpx.Response(200, json={"id": "env-empty"})

        client = make_client(handler)
        env_id = await client.start_environment(
            target_ip="1.2.3.4", ssh_user="root", command="echo hi",
            command_description="",  # explicitly empty
        )
        assert env_id == "env-empty"
        name = captured["payload"]["environment_name"]
        # No description segment: tunneled-<kind>-<key>
        assert name.startswith("tunneled-ssh-")
        assert "--" not in name  # no empty segment left dangling

    async def test_retry_disabled_single_post(self, no_sleep):
        counts = {"post": 0, "get": 0}

        def handler(request):
            if request.method == "POST":
                counts["post"] += 1
                return httpx.Response(500, text="boom")
            counts["get"] += 1
            return httpx.Response(200, json=[{"id": "env-x"}])

        client = make_client(handler, retry_enabled=False)
        with pytest.raises(RuntimeError):
            await client.start_environment(target_ip="1.2.3.4", ssh_user="root", command="x")
        assert counts["post"] == 1
        assert counts["get"] == 0  # no reconcile when retries disabled


# --------------------------------------------------------------------------------------
# Backoff
# --------------------------------------------------------------------------------------

class TestBackoff:
    def test_backoff_grows_and_caps(self):
        client = TorqueClient("https://h", "t", "sp", retry_max_backoff_seconds=15)
        delays = [client._backoff_delay(a) for a in range(1, 12)]
        # Non-decreasing-ish growth, always within the cap.
        assert all(0 <= d <= 15 for d in delays)
        assert max(delays) <= 15
        # Late attempts hit the cap.
        assert client._backoff_delay(20) == 15
