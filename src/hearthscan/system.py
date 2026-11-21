from __future__ import annotations

import subprocess
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

# Keeps `route` from popping up a console window of its own when we run
# without one (under pythonw.exe, for example).
_CREATIONFLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Windows console tools print in the OEM code page (cp437, cp857, ...), not UTF-8.
_ENCODING = "oem" if IS_WINDOWS else "utf-8"


def run(args: list[str], timeout: float = 10.0) -> str:
    """Run a command and return what it printed, or an empty string if it failed."""
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=_CREATIONFLAGS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.decode(_ENCODING, errors="replace")


def sandbox() -> str | None:
    """Return "wsl" or "container" when we probably sit on a virtual network.

    WSL 2 in its default NAT mode and Docker-style containers get a private
    network of their own, which looks exactly like a home LAN from the inside.
    """
    if not IS_LINUX:
        return None
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        release = ""
    # WSL 1 reports "Microsoft" too, but it shares the Windows network stack.
    if "microsoft-standard" in release:
        return "wsl"
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return "container"
    return None
