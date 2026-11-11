"""A failed upload names this machine's croc sender when it is the cause.

An upload has two sides: this machine's `croc send` and the agent's `croc receive`.
The result used to quote only the receiving side's error from the grain log; when the
sender was what failed (it gave up on the relay, was rate limited, lost the
connection), that was only the symptom - "room not ready, maybe peer disconnected" -
and the sender's own words were in a temp file deleted unread. Same rule as a
remote-to-remote transfer: the sender's failure first, the receiver's as context.

Also: get_execution_status said only "Command failed" for an async run whose upload
failed; it now lists the upload failure like the blocking tools do.
"""

import asyncio
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel import croc_manager, mcp_tool

SECRET = "1234-secret-code-words"
SENDER_OUTPUT = (f"Sending 'big.bin' (500 kB)\nCode is: {SECRET}\n"
                 "could not connect to croc.schollz.com:9009: comm.NewConnection failed: "
                 "dial tcp 142.132.189.179:9009: i/o timeout\n")
RECEIVER_LINE = ("[15:49:42.997] ERROR: croc file receive failed (exit code: 1): securing channel..."
                 "room (secure channel) not ready, maybe peer disconnected")


class ExitedSender:
    """What start_croc_send returns, after croc exited."""

    def __init__(self, returncode=1, output=SENDER_OUTPUT):
        fd, self.croc_log_path = tempfile.mkstemp(prefix="tt_test_croc_")
        with os.fdopen(fd, "w") as f:
            f.write(output)
        self.returncode = returncode
        self.croc_secret = SECRET

    def remove(self):
        if os.path.exists(self.croc_log_path):   # the code under test may have cleaned up
            os.remove(self.croc_log_path)


@pytest.fixture
def sender():
    made = []

    def make(**kw):
        s = ExitedSender(**kw)
        made.append(s)
        return s

    yield make
    for s in made:
        s.remove()


def test_a_failed_sender_says_why_without_its_code(sender):
    text = croc_manager.local_send_failure(sender())
    assert text.startswith("this machine's croc send failed (exit code 1): ")
    assert "dial tcp 142.132.189.179:9009: i/o timeout" in text
    assert SECRET not in text


@pytest.mark.parametrize("returncode", [None, 0])
def test_a_sender_that_is_running_or_succeeded_is_not_a_failure(sender, returncode):
    assert croc_manager.local_send_failure(sender(returncode=returncode)) == ""


@pytest.mark.parametrize("process", [None, object()])
def test_anything_else_is_not_a_failure(process):
    assert croc_manager.local_send_failure(process) == ""


def test_the_senders_failure_comes_first_with_the_receivers_as_context(sender):
    lines = mcp_tool.upload_failures(RECEIVER_LINE, croc_manager.local_send_failure(sender()))
    assert len(lines) == 1, lines
    assert lines[0].startswith("this machine's croc send failed")
    assert lines[0].index("i/o timeout") < lines[0].index("the receiving side then reported: croc file receive failed")


def test_without_a_sender_failure_the_receivers_error_is_reported_as_before():
    lines = mcp_tool.upload_failures(RECEIVER_LINE, "")
    assert lines == ["croc file receive failed (exit code: 1): securing channel...room (secure channel) "
                     "not ready, maybe peer disconnected"]


def test_the_files_deployed_block_carries_it(sender):
    block = mcp_tool.format_upload_summary(["big.bin → /tmp/big.bin"], RECEIVER_LINE,
                                           croc_manager.local_send_failure(sender()))
    assert "- UPLOAD FAILED: this machine's croc send failed" in block


# ---------------------------------------------------------------------------
# get_execution_status of an async run whose upload failed
# ---------------------------------------------------------------------------

class FakeTorque:
    exit_code = "1"
    status = "active"

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_environment_status(self, env_id):
        return {"details": {"computed_status": FakeTorque.status}}

    async def get_grain_log(self, env_id):
        return RECEIVER_LINE + "\n"

    def _extract_outputs(self, env_data):
        return {"command_output": "", "exit_code": FakeTorque.exit_code}

    async def end_environment(self, env_id, force=False):
        pass

    async def delete_environment(self, env_id):
        pass


@pytest.fixture
def async_upload(monkeypatch, sender):
    monkeypatch.setattr(mcp_tool, "TorqueClient", FakeTorque)
    monkeypatch.setattr(mcp_tool, "_config", dict(
        mcp_tool._config, torque_url="https://t.example", torque_token="t", torque_space="S",
        auto_delete_environments=False))
    monkeypatch.setattr(mcp_tool, "_async_env_connections", {})
    monkeypatch.setattr(mcp_tool, "_streamer_cache", {})
    proc = sender()
    proc.returncode = 1
    monkeypatch.setattr(mcp_tool, "_croc_async_state", {"env-1": {"process": proc, "staging_dir": ""}})
    FakeTorque.status, FakeTorque.exit_code = "active", "1"

    def status():
        result = asyncio.run(mcp_tool.handle_get_execution_status({"environment_id": "env-1", "wait": 0}))
        return result[0].text

    return status


def test_async_status_names_the_upload_failure(async_upload):
    text = async_upload()
    assert "**Upload:**" in text, text
    assert "- UPLOAD FAILED: this machine's croc send failed (exit code 1)" in text
    assert "the receiving side then reported: croc file receive failed" in text


def test_async_status_of_an_error_state_names_it_too(async_upload):
    FakeTorque.status = "ended_with_error"
    text = async_upload()
    assert "- UPLOAD FAILED: this machine's croc send failed" in text, text


def test_async_status_of_a_successful_run_has_no_upload_section(async_upload):
    FakeTorque.exit_code = "0"
    assert "**Upload:**" not in async_upload()
