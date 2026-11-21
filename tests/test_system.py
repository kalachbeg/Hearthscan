import os
import sys

import pytest

from hearthscan import system


def test_windows_tool_falls_back_to_system_root(monkeypatch):
    monkeypatch.setattr(system, "IS_WINDOWS", False)
    monkeypatch.setenv("SYSTEMROOT", "D:\\Win")
    assert system.windows_tool("arp.exe") == "D:\\Win\\System32\\arp.exe"


def test_windows_tool_without_system_root(monkeypatch):
    monkeypatch.setattr(system, "IS_WINDOWS", False)
    monkeypatch.delenv("SYSTEMROOT", raising=False)
    assert system.windows_tool("route.exe") == "C:\\Windows\\System32\\route.exe"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_windows_tool_finds_the_real_programs(monkeypatch, tmp_path):
    # Neither a planted copy in the current directory nor SYSTEMROOT matters.
    (tmp_path / "arp.exe").write_bytes(b"MZ")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path))
    for name in ("arp.exe", "route.exe"):
        path = system.windows_tool(name)
        assert os.path.isabs(path)
        assert os.path.isfile(path)
        assert os.path.dirname(path).lower() != str(tmp_path).lower()
