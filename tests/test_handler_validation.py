"""Tests for handler input validation — command/upload_files/download_files requirement.

Each run_on_tunneled_* handler must:
- Return an error when NONE of command, upload_files, or download_files is supplied.
- NOT return that error when ONLY download_files is supplied (pass the check).
- Include 'download_files' in the error message so callers know it's a valid option.
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from torque_tunnel.mcp_tool import (
    handle_run_on_tunneled_ssh,
    handle_run_on_tunneled_ssh_async,
    handle_run_on_tunneled_disposable_container,
    handle_run_on_tunneled_disposable_container_async,
    handle_run_on_tunneled_persistent_container,
    handle_run_on_tunneled_persistent_container_async,
)

# The exact prefix every handler should return when nothing is supplied
_MUST_PROVIDE = "Error: Must provide either 'command', 'upload_files', or 'download_files'"

# Minimal download_files value that will satisfy the check but not actually transfer files
# (the handler will fail later on Torque config / host checks — that's fine)
_DOWNLOAD_ONLY = {
    "download_files": [
        {"remote_source_path": "/tmp/file.txt", "local_destination_path": "./file.txt"}
    ]
}

# Helpers -------------------------------------------------------------------

def run(coro):
    return asyncio.run(coro)


def first_text(result) -> str:
    return result[0].text if result else ""


# All handlers under test ---------------------------------------------------

ALL_HANDLERS = [
    handle_run_on_tunneled_ssh,
    handle_run_on_tunneled_ssh_async,
    handle_run_on_tunneled_disposable_container,
    handle_run_on_tunneled_disposable_container_async,
    handle_run_on_tunneled_persistent_container,
    handle_run_on_tunneled_persistent_container_async,
]

HANDLER_IDS = [h.__name__ for h in ALL_HANDLERS]


# ---------------------------------------------------------------------------
# No args at all → must-provide error
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("handler", ALL_HANDLERS, ids=HANDLER_IDS)
def test_empty_args_returns_must_provide_error(handler):
    result = run(handler({}))
    text = first_text(result)
    assert text.startswith(_MUST_PROVIDE), (
        f"{handler.__name__}: expected must-provide error, got: {text!r}"
    )


# ---------------------------------------------------------------------------
# The error message must mention all three options
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("handler", ALL_HANDLERS, ids=HANDLER_IDS)
def test_must_provide_error_mentions_download_files(handler):
    result = run(handler({}))
    text = first_text(result)
    assert "download_files" in text, (
        f"{handler.__name__}: error message does not mention 'download_files': {text!r}"
    )
    assert "upload_files" in text, (
        f"{handler.__name__}: error message does not mention 'upload_files': {text!r}"
    )
    assert "command" in text, (
        f"{handler.__name__}: error message does not mention 'command': {text!r}"
    )


# ---------------------------------------------------------------------------
# Only download_files supplied → must NOT hit the must-provide error
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("handler", ALL_HANDLERS, ids=HANDLER_IDS)
def test_download_files_only_passes_validation(handler):
    result = run(handler(_DOWNLOAD_ONLY))
    text = first_text(result)
    # The handler will fail for some other reason (no Torque config, no host, etc.)
    # but it must NOT fail with the must-provide error.
    assert not text.startswith(_MUST_PROVIDE), (
        f"{handler.__name__}: incorrectly rejected download_files-only call: {text!r}"
    )
