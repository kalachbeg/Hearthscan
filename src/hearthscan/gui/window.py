"""Show the interface in a desktop window, or in the web browser when there is none.

The window comes from pywebview, an optional extra (hearthscan[window]).
"""

from __future__ import annotations

import sys
import time
import webbrowser

from .. import i18n
from ..i18n import t
from .server import start_server

TITLE = "Hearthscan"
SIZE = (1100, 800)
MIN_SIZE = (760, 560)

_BROWSER_ONLY = "This version of Hearthscan opens in your web browser."
_WINDOW_MISSING = (
    'The desktop window needs pywebview (pip install "hearthscan[window]"), '
    "so Hearthscan opens in your web browser instead."
)
_WINDOW_FAILED = "The window could not be opened ({reason}); opening your browser instead."
_BROWSER_HINT = "Hearthscan is open in your web browser: {url}\nPress Ctrl+C here to stop it."


def _text(key: str, fallback: str, **params: object) -> str:
    # The window's texts may not be in every language file yet.
    if i18n.has(key):
        return t(key, **params)
    return fallback.format(**params)


def open_window(*, prefer_window: bool = True) -> int:
    """Start the server and show it until the window closes or Ctrl+C. Returns 0."""
    server = start_server()
    try:
        if prefer_window and _in_window(server.url):
            return 0
        _in_browser(server.url)
    finally:
        server.shutdown()
    return 0


def _in_window(url: str) -> bool:
    """Show `url` in a window until it is closed. False when no window could open."""
    try:
        import webview
    except ImportError:
        # A ready-made download cannot install anything, so it only says what happens.
        if getattr(sys, "frozen", False):
            message = _text("gui.browser_only", _BROWSER_ONLY)
        else:
            message = _text("gui.window_missing", _WINDOW_MISSING)
        print(message, file=sys.stderr, flush=True)
        return False
    settings = getattr(webview, "settings", None)
    if isinstance(settings, dict):
        # Without this the window refuses the report and JSON downloads.
        settings["ALLOW_DOWNLOADS"] = True
    try:
        webview.create_window(
            TITLE, url, width=SIZE[0], height=SIZE[1], min_size=MIN_SIZE, text_select=True
        )
        webview.start()
    except Exception as exc:
        # pywebview raises when the system has no web engine it can drive,
        # which happens on Linux without GTK or Qt bindings.
        reason = str(exc) or type(exc).__name__
        message = _text("gui.window_failed", _WINDOW_FAILED, reason=reason)
        print(message, file=sys.stderr, flush=True)
        return False
    return True


def _in_browser(url: str) -> None:
    """Open `url` in the default browser and keep serving until Ctrl+C."""
    print(_text("gui.browser_hint", _BROWSER_HINT, url=url), flush=True)
    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(t("ui.stopped"), flush=True)
