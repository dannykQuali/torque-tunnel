"""Shared test setup.

The croc relay check (croc_manager.check_relay) opens real TCP connections to the
relay - croc.schollz.com by default. No test may depend on the network, so it is
replaced for every test by one that reports the relay reachable. Tests of the check
itself are marked ``real_relay_check`` and run it against a local fake relay
(tests/test_relay_check.py).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import croc_manager  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_relay_check: run croc_manager.check_relay for real (against a local fake relay)")


@pytest.fixture(autouse=True)
def _no_real_relay_check(request, monkeypatch):
    if request.node.get_closest_marker("real_relay_check") is None:
        monkeypatch.setattr(croc_manager, "check_relay", lambda relay="", timeout=None: "")
