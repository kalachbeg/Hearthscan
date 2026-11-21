"""The desktop interface: a web page served on 127.0.0.1, shown in a window or a browser."""

from __future__ import annotations

from .server import GuiServer, start_server
from .window import open_window

__all__ = ["GuiServer", "open_window", "start_server"]
