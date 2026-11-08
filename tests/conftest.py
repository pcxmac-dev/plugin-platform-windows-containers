"""Nothing in these tests starts a process or reaches the network: subprocess and a connection out are refused (each test
hands the plugin a stand-in for powershell.exe), and LIMINAL_ELEVATE and LIMINAL_PLATFORM_DIR are cleared."""
from __future__ import annotations

import socket
import subprocess

import pytest


@pytest.fixture(autouse=True)
def nothing_runs(monkeypatch):
    def refused(*a, **k):
        raise AssertionError("a test started a process or reached for the network")
    monkeypatch.setattr(subprocess, "run", refused)
    monkeypatch.setattr(subprocess, "Popen", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.delenv("LIMINAL_ELEVATE", raising=False)
    monkeypatch.delenv("LIMINAL_PLATFORM_DIR", raising=False)
