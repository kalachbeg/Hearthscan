import http.client
import socket
import subprocess
import sys
import threading
import types
from urllib.parse import urlsplit

import pytest

from hearthscan.gui import server, window

PAGE = b"<!DOCTYPE html><title>stand-in page</title>"


@pytest.fixture
def web(tmp_path, monkeypatch):
    folder = tmp_path / "web"
    folder.mkdir()
    (folder / "index.html").write_bytes(PAGE)
    (folder / "app.js").write_bytes(b"")
    (folder / "styles.css").write_bytes(b"")
    monkeypatch.setattr(server, "web_folder", lambda: folder)
    return folder


@pytest.fixture
def threads():
    """The threads running before the test; none may be added by the end of it."""
    before = set(threading.enumerate())
    yield before
    assert set(threading.enumerate()) <= before


def fetch(url):
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    try:
        connection.request("GET", f"{parts.path}?{parts.query}")
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


class FakeWebview(types.ModuleType):
    """Enough of pywebview: the window "shows" the page by fetching it."""

    def __init__(self, fail=None):
        super().__init__("webview")
        self.settings = {"ALLOW_DOWNLOADS": False}
        self.windows = []
        self.pages = []
        self.fail = fail

    def create_window(self, title, url, **options):
        self.windows.append((title, url, options))

    def start(self, *args, **kwargs):
        if self.fail is not None:
            raise self.fail
        for _, url, _ in self.windows:
            self.pages.append(fetch(url))


class FakeBrowser:
    def __init__(self, monkeypatch):
        self.opened = []
        self.pages = []
        monkeypatch.setattr(window, "webbrowser", types.SimpleNamespace(open=self.open))
        monkeypatch.setattr(window, "time", types.SimpleNamespace(sleep=self.sleep))

    def open(self, url):
        self.opened.append(url)
        return True

    def sleep(self, seconds):
        # Serving until Ctrl+C: look at the page once, then press it.
        self.pages.append(fetch(self.opened[-1]))
        raise KeyboardInterrupt


def test_opens_a_window_and_stops_the_server_after(web, monkeypatch, threads):
    webview = FakeWebview()
    monkeypatch.setitem(sys.modules, "webview", webview)
    browser = FakeBrowser(monkeypatch)
    assert window.open_window() == 0

    [(title, url, options)] = webview.windows
    assert title == "Hearthscan"
    assert url.startswith("http://127.0.0.1:") and "/?token=" in url
    assert (options["width"], options["height"]) == (1100, 800)
    assert options["min_size"] == window.MIN_SIZE
    assert webview.pages == [(200, PAGE)]
    assert webview.settings["ALLOW_DOWNLOADS"] is True
    assert browser.opened == []
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", urlsplit(url).port), timeout=3).close()


def test_without_pywebview_it_opens_the_browser(web, monkeypatch, capsys, threads):
    monkeypatch.setitem(sys.modules, "webview", None)  # import webview fails
    browser = FakeBrowser(monkeypatch)
    assert window.open_window() == 0

    [url] = browser.opened
    assert url.startswith("http://127.0.0.1:") and "/?token=" in url
    assert browser.pages == [(200, PAGE)]
    out, err = capsys.readouterr()
    assert url in out
    assert window._text("gui.window_missing", window._WINDOW_MISSING) in err


def test_the_browser_on_request(web, monkeypatch, capsys, threads):
    webview = FakeWebview()
    monkeypatch.setitem(sys.modules, "webview", webview)
    browser = FakeBrowser(monkeypatch)
    assert window.open_window(prefer_window=False) == 0
    assert webview.windows == []
    assert browser.pages == [(200, PAGE)]
    out, err = capsys.readouterr()
    assert browser.opened[0] in out
    assert err == ""


def test_a_window_that_cannot_start_falls_back_to_the_browser(web, monkeypatch, capsys, threads):
    webview = FakeWebview(fail=RuntimeError("no GTK or Qt found"))
    monkeypatch.setitem(sys.modules, "webview", webview)
    browser = FakeBrowser(monkeypatch)
    assert window.open_window() == 0
    assert browser.pages == [(200, PAGE)]
    assert "no GTK or Qt found" in capsys.readouterr().err


def test_ctrl_c_in_the_window_still_stops_the_server(web, monkeypatch, threads):
    monkeypatch.setitem(sys.modules, "webview", FakeWebview(fail=KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        window.open_window()


def test_english_until_the_texts_exist(monkeypatch):
    monkeypatch.setattr(window.i18n, "has", lambda key: False)
    hint = window._text("gui.browser_hint", window._BROWSER_HINT, url="http://127.0.0.1:1/")
    assert hint == (
        "Hearthscan is open in your web browser: http://127.0.0.1:1/\nPress Ctrl+C here to stop it."
    )
    monkeypatch.setattr(window.i18n, "has", lambda key: True)
    monkeypatch.setattr(window, "t", lambda key, **params: f"{key} {params}")
    assert window._text("gui.browser_hint", "unused", url="x") == "gui.browser_hint {'url': 'x'}"


def test_nothing_imports_pywebview_up_front():
    code = (
        "import sys, hearthscan.cli, hearthscan.gui, hearthscan.gui.window; "
        "print('webview' in sys.modules)"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "False"


def test_a_ready_made_download_without_pywebview_does_not_suggest_pip(monkeypatch, capsys):
    import builtins

    real_import = builtins.__import__

    def no_webview(name, *args, **kwargs):
        if name == "webview":
            raise ImportError("no webview")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_webview)
    monkeypatch.setattr(window.sys, "frozen", True, raising=False)
    assert window._in_window("http://127.0.0.1:1/?token=x") is False
    err = capsys.readouterr().err
    assert "pip" not in err
    assert "browser" in err
