"""Shared test setup.

The croc relay check (croc_manager.check_relay) opens real TCP connections to the
relay - croc.schollz.com by default - and the Piping Server check (piping.check_server)
to https://ppng.io. No test may depend on the network, so for every test the relay is
reported reachable and the Piping Server not (croc alone, as before the Piping Server
transport). Tests of the checks themselves are marked ``real_relay_check`` /
``real_piping_check`` and run against local fakes (tests/test_relay_check.py,
tests/test_piping*.py).
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from torque_tunnel import croc_manager, piping  # noqa: E402

# What every test sees of the Piping Server check: not reachable, so only croc is
# offered and chosen, as before the Piping Server transport existed. Tests of that
# transport mark themselves real_piping_check and use tests/_fake_piping_server.py.
NO_PIPING_IN_TESTS = "the Piping Server is not used in tests"


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_relay_check: run croc_manager.check_relay for real (against a local fake relay)")
    config.addinivalue_line(
        "markers", "real_piping_check: run piping.check_server for real (against a local fake server)")


@pytest.fixture(autouse=True)
def _no_real_relay_check(request, monkeypatch):
    if request.node.get_closest_marker("real_relay_check") is None:
        monkeypatch.setattr(croc_manager, "check_relay", lambda relay="", timeout=None: "")
    if request.node.get_closest_marker("real_piping_check") is None:
        monkeypatch.setattr(piping, "check_server", lambda server="", timeout=None: NO_PIPING_IN_TESTS)
