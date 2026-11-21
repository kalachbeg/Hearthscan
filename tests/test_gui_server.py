import asyncio
import contextlib
import http.client
import io
import json
import re
import socket
import threading
import time
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

import hearthscan.audit
from hearthscan import __version__, i18n, serialize
from hearthscan.gui import server
from hearthscan.models import Device, Finding, ScanResult, Service
from hearthscan.netinfo import Interface, NetworkInfo

ETH = Interface("eth0", "Ethernet", ip_address("192.168.1.50"), ip_network("192.168.1.0/24"))
INFO = NetworkInfo(ETH, "192.168.1.1")
STARTED = "2026-01-02T03:04:05+00:00"
I18N_DIR = Path(i18n.__file__).parent

PAGE = b"<!DOCTYPE html><title>stand-in page</title>"
SCRIPT = b"document.title = 'stand-in';"
STYLE = b"body { margin: 0; }"
SECRET = b"never handed out"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def result():
    router = Device(
        "192.168.1.1",
        mac="a4:83:e7:00:00:01",
        vendor="Acme",
        kind="router",
        services=[Service(23, name="telnet")],
        confirmed=True,
        is_gateway=True,
    )
    return ScanResult(
        version="2.0.0",
        started=STARTED,
        finished="2026-01-02T03:04:15+00:00",
        interface="Ethernet",
        address="192.168.1.50",
        network="192.168.1.0/24",
        gateway="192.168.1.1",
        devices=[router],
        findings=[Finding("telnet-open", "high", "192.168.1.1", 23, {"port": "23"})],
        score=85,
        ports=[23],
    )


def as_json(value):
    return json.loads(json.dumps(value))


@pytest.fixture(autouse=True)
def keep_language():
    previous = i18n.language()
    yield
    i18n.set_language(previous)


@pytest.fixture
def web(tmp_path, monkeypatch):
    """Small stand-ins for the page, so the tests never depend on the real one."""
    folder = tmp_path / "web"
    folder.mkdir()
    (folder / "index.html").write_bytes(PAGE)
    (folder / "app.js").write_bytes(SCRIPT)
    (folder / "styles.css").write_bytes(STYLE)
    (tmp_path / "secret.txt").write_bytes(SECRET)
    monkeypatch.setattr(server, "web_folder", lambda: folder)
    return folder


@pytest.fixture
def gui(web, monkeypatch):
    monkeypatch.setattr(server, "local_network", lambda: INFO)
    running = server.start_server()
    yield running
    running.shutdown()


class FakeAudit:
    """Stands in for audit(): some progress and a note, then a result once let go."""

    def __init__(self, monkeypatch, *, hold=False):
        self.result = result()
        self.calls = []
        self.started = threading.Event()
        self.release = threading.Event()
        self.cancelled = threading.Event()
        if not hold:
            self.release.set()
        monkeypatch.setattr(hearthscan.audit, "audit", self)

    async def __call__(self, info, **kwargs):
        self.calls.append((info, kwargs))
        progress = kwargs["on_progress"]
        progress("discover", 0, 0)
        progress("ports", 0, 4)
        kwargs["on_note"]("mdns", "mdns did not run")
        progress("ports", 4, 4)
        self.started.set()
        try:
            while not self.release.is_set():
                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        progress("checks", 0, 0)
        progress("done", 0, 0)
        return self.result


class Reply:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body)


def call(gui, method, path, body=None, *, token=True, headers=None):
    sent = {}
    if token:
        sent[server.TOKEN_HEADER] = gui.token
    if body is not None and not isinstance(body, bytes):
        body = json.dumps(body).encode()
        sent["Content-Type"] = "application/json"
    sent.update(headers or {})
    connection = http.client.HTTPConnection("127.0.0.1", gui.port, timeout=10)
    try:
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        return Reply(response.status, response.headers, response.read())
    finally:
        connection.close()


def get(gui, path, **kwargs):
    return call(gui, "GET", path, **kwargs)


def post(gui, path, body=None, **kwargs):
    return call(gui, "POST", path, {} if body is None else body, **kwargs)


def raw(gui, request):
    """Send `request` as it is, for what http.client will not send."""
    with socket.create_connection(("127.0.0.1", gui.port), timeout=10) as connection:
        connection.sendall(request)
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    status, _, rest = head.partition(b"\r\n")
    headers = http.client.parse_headers(io.BytesIO(rest + b"\r\n\r\n"))
    return Reply(int(status.split()[1]), headers, body)


class Events:
    """Reads the event stream more or less the way EventSource does."""

    def __init__(self, gui, token=None):
        self.connection = http.client.HTTPConnection("127.0.0.1", gui.port, timeout=10)
        self.connection.request("GET", f"/api/events?token={token or gui.token}")
        self.response = self.connection.getresponse()

    def next(self):
        """The next event as (name, data). A comment comes back as (":", text)."""
        name = data = None
        while True:
            line = self.response.readline()
            if not line:
                raise EOFError("the stream ended")
            line = line.decode().rstrip("\r\n")
            if line.startswith(":"):
                return ":", line[1:].strip()
            if not line:
                if name is not None:
                    return name, json.loads(data)
                continue
            field, _, value = line.partition(": ")
            if field == "event":
                name = value
            elif field == "data":
                data = value

    def until(self, wanted):
        seen = []
        while True:
            seen.append(self.next())
            if seen[-1][0] == wanted:
                return seen

    def close(self):
        self.connection.close()


def wait_for(check, seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.02)
    pytest.fail("timed out")


def finish_scan(gui):
    """Run a scan through the API and wait for its end."""
    assert post(gui, "/api/scan").status == 202  # "scanning" is set before this answer
    wait_for(lambda: not get(gui, "/api/info").json()["scanning"])


def load(code):
    return json.loads((I18N_DIR / f"{code}.json").read_text(encoding="utf-8"))


# Starting and stopping


def test_address_and_token(gui):
    assert gui.url == f"http://127.0.0.1:{gui.port}/?token={gui.token}"
    assert re.fullmatch(r"[A-Za-z0-9_-]{32}", gui.token)
    assert gui._server.socket.getsockname()[0] == "127.0.0.1"
    other = server.start_server()
    try:
        assert other.port != gui.port and other.token != gui.token
    finally:
        other.shutdown()


def test_a_chosen_port(web):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    running = server.start_server(port=port)
    try:
        assert running.port == port
        assert get(running, "/", token=False).body == PAGE
    finally:
        running.shutdown()


def test_shutdown_stops_everything(web, monkeypatch):
    monkeypatch.setattr(server, "local_network", lambda: INFO)
    audit = FakeAudit(monkeypatch, hold=True)
    before = set(threading.enumerate())
    running = server.start_server()
    events = Events(running)
    assert events.next() == ("idle", {})
    assert post(running, "/api/scan").status == 202
    assert audit.started.wait(10)

    started = time.monotonic()
    running.shutdown()
    assert time.monotonic() - started < 5
    assert audit.cancelled.is_set()
    assert set(threading.enumerate()) <= before
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", running.port), timeout=3).close()
    running.shutdown()  # a second time does nothing
    events.close()


def test_shutdown_does_not_wait_for_idle_connections(web):
    before = set(threading.enumerate())
    running = server.start_server()
    # Browsers open spare connections that may never carry a request.
    idle = socket.create_connection(("127.0.0.1", running.port), timeout=10)
    half = socket.create_connection(("127.0.0.1", running.port), timeout=10)
    half.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1")
    assert get(running, "/", token=False).status == 200  # both are being handled by now
    started = time.monotonic()
    running.shutdown()
    # At once on Linux and macOS; Windows sits out the short wait for a request.
    assert time.monotonic() - started < server.REQUEST_TIMEOUT + 1.5
    assert set(threading.enumerate()) <= before
    idle.close()
    half.close()


# The page


def test_serves_the_three_files(gui):
    files = [
        ("/", PAGE, "text/html"),
        ("/app.js", SCRIPT, "text/javascript"),
        ("/styles.css", STYLE, "text/css"),
    ]
    for path, body, kind in files:
        reply = get(gui, path, token=False)
        assert reply.status == 200
        assert reply.body == body
        assert reply.headers["Content-Type"] == f"{kind}; charset=utf-8"
    # The window opens the page with the token in its address.
    assert get(gui, f"/?token={gui.token}", token=False).body == PAGE


@pytest.mark.parametrize(
    "path",
    [
        "/index.html",
        "/secret.txt",
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/..%5csecret.txt",
        "/web/app.js",
        "/web/",
        "/app.js/",
        "/APP.JS",
        "/app.js%00",
        "/favicon.ico",
    ],
)
def test_nothing_else_is_served(gui, path):
    reply = get(gui, path, token=False)
    assert reply.status == 404
    assert reply.json() == {"error": "not_found"}


def test_a_missing_file_is_not_found(gui, web):
    (web / "styles.css").unlink()
    assert get(gui, "/styles.css", token=False).status == 404


# Who may ask


def test_the_api_needs_the_token(gui):
    assert get(gui, "/api/info").status == 200
    for headers in ({}, {server.TOKEN_HEADER: "x" * 32}, {server.TOKEN_HEADER: gui.token[:-1]}):
        reply = get(gui, "/api/info", token=False, headers=headers)
        assert reply.status == 403
        assert reply.json() == {"error": "bad_token"}
    assert get(gui, "/api/info", token=False, headers={server.TOKEN_HEADER: "\xe9"}).status == 403
    # Only the event stream may carry it in the address.
    assert get(gui, f"/api/info?token={gui.token}", token=False).status == 403
    assert post(gui, "/api/scan", token=False).status == 403
    assert post(gui, "/api/language", {"language": "tr"}, token=False).status == 403


def test_two_tokens_are_one_too_many(gui):
    request = (
        f"GET /api/info HTTP/1.0\r\nHost: 127.0.0.1:{gui.port}\r\n"
        f"{server.TOKEN_HEADER}: {gui.token}\r\n{server.TOKEN_HEADER}: {gui.token}\r\n\r\n"
    )
    assert raw(gui, request.encode()).status == 403


def test_the_event_stream_takes_the_token_from_the_address(gui):
    events = Events(gui)
    assert events.next() == ("idle", {})
    events.close()
    assert get(gui, "/api/events?token=wrong", token=False).status == 403
    assert get(gui, "/api/events?token=", token=False).status == 403
    assert get(gui, "/api/events", token=False).status == 403


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        "evil.example:{port}",
        "127.0.0.1",
        "127.0.0.1:1",
        "localhost",
        "[::1]:{port}",
        "0.0.0.0:{port}",
        "127.0.0.1:{port}.evil.example",
    ],
)
def test_other_host_names_are_refused(gui, host):
    headers = {"Host": host.format(port=gui.port)}
    for path in ("/", "/api/info"):
        reply = get(gui, path, headers=headers)
        assert reply.status == 421
        assert reply.json() == {"error": "bad_host"}


def test_both_local_names_are_fine(gui):
    for name in ("127.0.0.1", "localhost"):
        assert get(gui, "/api/info", headers={"Host": f"{name}:{gui.port}"}).status == 200


def test_no_host_or_two_hosts(gui):
    assert raw(gui, b"GET / HTTP/1.0\r\n\r\n").status == 421
    host = f"Host: 127.0.0.1:{gui.port}\r\n"
    assert raw(gui, f"GET / HTTP/1.0\r\n{host}{host}\r\n".encode()).status == 421


@pytest.mark.parametrize(
    "origin",
    [
        "http://evil.example",
        "null",
        "https://127.0.0.1:{port}",
        "http://127.0.0.1:1",
        "http://127.0.0.1:{port}/",
        "http://LOCALHOST:{port}",
    ],
)
def test_other_origins_are_refused(gui, origin):
    headers = {"Origin": origin.format(port=gui.port)}
    reply = post(gui, "/api/stop", headers=headers)
    assert reply.status == 403
    assert reply.json() == {"error": "bad_origin"}
    assert get(gui, "/", token=False, headers=headers).status == 403


def test_the_page_own_origin_is_fine(gui):
    for name in ("127.0.0.1", "localhost"):
        reply = post(gui, "/api/stop", headers={"Origin": f"http://{name}:{gui.port}"})
        assert reply.status == 200


def test_post_bodies_are_small_json_objects(gui):
    body = b'{"language": "tr"}'
    for kind in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
        reply = post(gui, "/api/language", body, headers={"Content-Type": kind})
        assert reply.status == 415
        assert reply.json() == {"error": "need_json"}
    assert post(gui, "/api/language", body).status == 415  # no type at all

    json_type = {"Content-Type": "application/json"}
    too_big = json.dumps({"language": "tr", "pad": "x" * server.MAX_BODY}).encode()
    reply = post(gui, "/api/language", too_big, headers=json_type)
    assert reply.status == 413
    assert reply.json() == {"error": "too_large"}
    for broken in (b"{", b"[]", b'"tr"', b"\xff\xfe", b"[" * 3000):
        reply = post(gui, "/api/language", broken, headers=json_type)
        assert reply.status == 400
        assert reply.json() == {"error": "bad_json"}

    padded = {"language": "tr", "pad": ""}
    padded["pad"] = "x" * (server.MAX_BODY - len(json.dumps(padded).encode()))
    exact = json.dumps(padded).encode()
    assert len(exact) == server.MAX_BODY
    assert post(gui, "/api/language", exact, headers=json_type).status == 200
    with_charset = {"Content-Type": "application/json; charset=utf-8"}
    assert post(gui, "/api/language", body, headers=with_charset).status == 200
    assert i18n.language() == "tr"


def test_post_bodies_need_a_plain_length(gui):
    start = f"POST /api/stop HTTP/1.0\r\nHost: 127.0.0.1:{gui.port}\r\n"
    start += f"{server.TOKEN_HEADER}: {gui.token}\r\nContent-Type: application/json\r\n"
    # Only the head: the server answers before any of the body would be read.
    chunked = start + "Transfer-Encoding: chunked\r\n\r\n"
    assert raw(gui, chunked.encode()).status == 411
    for length in ("-1", "abc", "1_0", "\u00b2"):
        request = (start + f"Content-Length: {length}\r\n\r\n").encode("utf-8")
        assert raw(gui, request).status == 400
    # No body at all counts as {}, with or without a type.
    reply = raw(gui, (start + "Content-Length: 0\r\n\r\n").encode())
    assert reply.status == 200
    assert json.loads(reply.body) == {"stopped": False}
    bare = f"POST /api/stop HTTP/1.0\r\nHost: 127.0.0.1:{gui.port}\r\n"
    bare += f"{server.TOKEN_HEADER}: {gui.token}\r\n\r\n"
    assert raw(gui, bare.encode()).status == 200
    reply = call(gui, "POST", "/api/stop")  # what fetch sends for a POST without a body
    assert reply.status == 200
    assert reply.json() == {"stopped": False}
    plain = {"Content-Type": "text/plain"}
    assert call(gui, "POST", "/api/stop", b" ", headers=plain).status == 415


def test_too_many_query_fields(gui):
    query = "&".join(f"f{number}=1" for number in range(server.MAX_FIELDS + 1))
    assert get(gui, f"/api/texts?{query}").status == 400


def test_security_headers_on_every_answer(gui):
    json_type = {"Content-Type": "application/json"}
    replies = [
        get(gui, "/", token=False),
        get(gui, "/app.js", token=False),
        get(gui, "/nothing-here", token=False),
        get(gui, "/api/info"),
        get(gui, "/api/info", token=False),
        get(gui, "/api/result"),
        get(gui, "/api/info", headers={"Host": "evil.example"}),
        get(gui, "/api/info", headers={"Origin": "http://evil.example"}),
        post(gui, "/api/language", b"x" * 5000, headers=json_type),
        post(gui, "/api/info"),
        raw(gui, b"BREW / HTTP/1.0\r\n\r\n"),
        raw(gui, b"GET / HTTP/1.0\r\n" + b"X-Filler: 1\r\n" * 101 + b"\r\n"),
    ]
    events = Events(gui)
    replies.append(Reply(events.response.status, events.response.headers, b""))
    for reply in replies:
        for name, value in SECURITY_HEADERS.items():
            assert reply.headers[name] == value, (reply.status, name)
    events.close()


def test_wrong_methods_and_unknown_calls(gui):
    reply = get(gui, "/api/scan")
    assert reply.status == 405 and reply.headers["Allow"] == "POST"
    reply = post(gui, "/api/info")
    assert reply.status == 405 and reply.headers["Allow"] == "GET"
    assert post(gui, "/", token=False).status == 405
    for path in ("/api/", "/api/nothing", "/api/info/", "/api/INFO"):
        reply = get(gui, path)
        assert reply.status == 404
        assert reply.json() == {"error": "not_found"}
    for method in (b"PUT", b"DELETE", b"OPTIONS", b"HEAD"):
        request = method + f" /api/info HTTP/1.0\r\nHost: 127.0.0.1:{gui.port}\r\n\r\n".encode()
        assert raw(gui, request).status == 501


# What the page asks


def test_info(gui):
    i18n.set_language("en")
    assert get(gui, "/api/info").json() == {
        "version": __version__,
        "language": "en",
        "languages": ["en", "tr"],
        "network": {
            "interface": "Ethernet",
            "address": "192.168.1.50",
            "network": "192.168.1.0/24",
            "scan_network": "192.168.1.0/24",
            "gateway": "192.168.1.1",
        },
        "sandbox": None,
        "scanning": False,
        "has_result": False,
    }


def test_info_with_a_large_network_in_wsl(gui, monkeypatch):
    big = Interface("eth0", "eth0", ip_address("10.0.5.20"), ip_network("10.0.0.0/16"))
    monkeypatch.setattr(server, "local_network", lambda: NetworkInfo(big, None, "wsl"))
    data = get(gui, "/api/info").json()
    assert data["network"] == {
        "interface": "eth0",
        "address": "10.0.5.20",
        "network": "10.0.0.0/16",
        "scan_network": "10.0.5.0/24",
        "gateway": None,
    }
    assert data["sandbox"] == "wsl"


def test_info_without_a_network(gui, monkeypatch):
    monkeypatch.setattr(server, "local_network", lambda: None)
    monkeypatch.setattr(server.system, "sandbox", lambda: "container")
    data = get(gui, "/api/info").json()
    assert data["network"] is None
    assert data["sandbox"] == "container"


def test_texts_in_each_language(gui):
    english, turkish = load("en"), load("tr")
    data = get(gui, "/api/texts?lang=tr").json()
    assert data["language"] == "tr"
    assert set(data["texts"]) == set(english)
    assert data["texts"]["ui.stopped"] == turkish["ui.stopped"] != english["ui.stopped"]
    assert get(gui, "/api/texts?lang=en").json() == {"language": "en", "texts": english}
    i18n.set_language("tr")
    assert get(gui, "/api/texts").json()["language"] == "tr"


def test_texts_fall_back_to_english(gui, monkeypatch):
    tables = {
        "en": {"menu.scan": "Check", "menu.quit": "Quit"},
        "tr": {"menu.scan": "Denetle", "only.here": "not an English key"},
    }
    monkeypatch.setattr(i18n, "_texts", lambda code: tables.get(code, {}))
    assert get(gui, "/api/texts?lang=tr").json() == {
        "language": "tr",
        "texts": {"menu.scan": "Denetle", "menu.quit": "Quit"},
    }


@pytest.mark.parametrize("query", ["lang=xx", "lang=", "lang=TR", "lang=en&lang=tr"])
def test_texts_in_other_languages_are_refused(gui, query):
    reply = get(gui, f"/api/texts?{query}")
    assert reply.status == 400
    assert reply.json() == {"error": "bad_language"}


def test_the_language_choice_sticks(gui):
    i18n.set_language("en")
    assert post(gui, "/api/language", {"language": "tr"}).json() == {"language": "tr"}
    assert i18n.language() == "tr"
    assert get(gui, "/api/info").json()["language"] == "tr"
    assert get(gui, "/api/texts").json()["language"] == "tr"


@pytest.mark.parametrize(
    "body", [{}, {"language": "xx"}, {"language": None}, {"language": ["tr"]}, {"language": "TR"}]
)
def test_other_languages_are_refused(gui, body):
    i18n.set_language("en")
    reply = post(gui, "/api/language", body)
    assert reply.status == 400
    assert reply.json() == {"error": "bad_language"}
    assert i18n.language() == "en"


# Scanning


def test_a_scan_reports_progress_a_note_and_the_result(gui, monkeypatch):
    audit = FakeAudit(monkeypatch)
    events = Events(gui)
    assert events.next() == ("idle", {})
    reply = post(gui, "/api/scan", {"probe": False})
    assert reply.status == 202
    assert reply.json() == {"started": True}

    expected = as_json(serialize.to_dict(audit.result))
    assert events.until("result") == [
        ("progress", {"stage": "discover", "done": 0, "total": 0}),
        ("progress", {"stage": "ports", "done": 0, "total": 4}),
        ("note", {"source": "mdns", "message": "mdns did not run"}),
        ("progress", {"stage": "ports", "done": 4, "total": 4}),
        ("progress", {"stage": "checks", "done": 0, "total": 0}),
        ("progress", {"stage": "done", "done": 0, "total": 0}),
        ("result", {"result": expected, "probed": False}),
    ]
    events.close()
    info, options = audit.calls[0]
    assert info == INFO
    assert options["probe"] is False
    data = get(gui, "/api/info").json()
    assert data["scanning"] is False and data["has_result"] is True
    assert get(gui, "/api/result").json() == expected


def test_probes_are_on_unless_turned_off(gui, monkeypatch):
    audit = FakeAudit(monkeypatch)
    finish_scan(gui)
    assert audit.calls[0][1]["probe"] is True
    for body in ({"probe": "no"}, {"probe": 0}, {"probe": None}):
        reply = post(gui, "/api/scan", body)
        assert reply.status == 400
        assert reply.json() == {"error": "bad_request"}


def test_progress_of_one_stage_is_thinned_out(gui, monkeypatch):
    async def busy(info, **kwargs):
        for done in range(1, 1001):
            kwargs["on_progress"]("ports", done, 1000)
        return result()

    monkeypatch.setattr(hearthscan.audit, "audit", busy)
    events = Events(gui)
    events.next()
    post(gui, "/api/scan")
    progress = [data for name, data in events.until("result") if name == "progress"]
    events.close()
    assert progress[0] == {"stage": "ports", "done": 1, "total": 1000}
    assert progress[-1] == {"stage": "ports", "done": 1000, "total": 1000}
    assert len(progress) < 100


def test_one_scan_at_a_time(gui, monkeypatch):
    audit = FakeAudit(monkeypatch, hold=True)
    assert post(gui, "/api/scan").status == 202
    assert audit.started.wait(10)
    reply = post(gui, "/api/scan")
    assert reply.status == 409
    assert reply.json() == {"error": "busy"}
    assert get(gui, "/api/info").json()["scanning"] is True

    audit.release.set()
    wait_for(lambda: get(gui, "/api/info").json()["has_result"])
    finish_scan(gui)
    assert len(audit.calls) == 2


def test_no_network_no_scan(gui, monkeypatch):
    audit = FakeAudit(monkeypatch)
    monkeypatch.setattr(server, "local_network", lambda: None)
    reply = post(gui, "/api/scan")
    assert reply.status == 503
    assert reply.json() == {"error": "no_network"}
    assert get(gui, "/api/info").json()["scanning"] is False
    assert audit.calls == []


def test_stop_cancels_the_scan(gui, monkeypatch):
    audit = FakeAudit(monkeypatch, hold=True)
    events = Events(gui)
    events.next()
    assert post(gui, "/api/scan").status == 202
    assert audit.started.wait(10)

    assert post(gui, "/api/stop").json() == {"stopped": True}
    seen = events.until("stopped")
    assert seen[-1] == ("stopped", {})
    assert "result" not in [name for name, _ in seen]
    assert audit.cancelled.is_set()
    data = get(gui, "/api/info").json()
    assert data["scanning"] is False and data["has_result"] is False
    assert post(gui, "/api/stop").json() == {"stopped": False}

    # Nothing is left in the way of the next scan.
    audit.release.set()
    assert post(gui, "/api/scan").status == 202
    assert events.until("result")[-1][0] == "result"
    events.close()


def test_stop_straight_after_the_start(gui, monkeypatch):
    FakeAudit(monkeypatch, hold=True)
    events = Events(gui)
    events.next()
    assert post(gui, "/api/scan").status == 202
    assert post(gui, "/api/stop").json() == {"stopped": True}
    assert events.until("stopped")[-1] == ("stopped", {})
    events.close()
    assert get(gui, "/api/info").json()["scanning"] is False


def test_a_scan_that_fails(gui, monkeypatch):
    async def broken(info, **kwargs):
        kwargs["on_progress"]("discover", 0, 0)
        raise RuntimeError("the neighbor table could not be read")

    monkeypatch.setattr(hearthscan.audit, "audit", broken)
    events = Events(gui)
    events.next()
    post(gui, "/api/scan")
    seen = events.until("error")
    events.close()
    assert seen[-1] == ("error", {"message": "the neighbor table could not be read"})
    data = get(gui, "/api/info").json()
    assert data["scanning"] is False and data["has_result"] is False


def test_a_late_page_hears_the_state_first(gui, monkeypatch):
    audit = FakeAudit(monkeypatch, hold=True)
    assert post(gui, "/api/scan").status == 202
    assert audit.started.wait(10)
    during = Events(gui)
    assert during.next() == ("progress", {"stage": "ports", "done": 4, "total": 4})

    audit.release.set()
    during.until("result")
    during.close()
    after = Events(gui)
    name, data = after.next()
    after.close()
    assert name == "result"
    assert data["result"] == as_json(serialize.to_dict(audit.result))


def test_every_page_hears_every_event(gui, monkeypatch):
    FakeAudit(monkeypatch)
    pages = [Events(gui) for _ in range(3)]
    for page in pages:
        assert page.next() == ("idle", {})
    post(gui, "/api/scan")
    seen = [page.until("result") for page in pages]
    for page in pages:
        page.close()
    assert seen[0] == seen[1] == seen[2]
    assert len(seen[0]) == 7


def test_keepalive_comments(gui, monkeypatch):
    monkeypatch.setattr(server, "KEEPALIVE", 0.05)
    events = Events(gui)
    assert events.next() == ("idle", {})
    assert events.next() == (":", "keepalive")
    events.close()


def test_a_page_that_falls_behind_is_cut_off(monkeypatch):
    monkeypatch.setattr(server, "QUEUE_SIZE", 2)
    hub = server._Hub()
    near, far = socket.socketpair()
    with near, far:
        listener = hub.listen(near)  # the idle event fills one place
        hub.publish("note", {"source": "test", "message": "one"})
        assert not listener.closed
        started = time.monotonic()
        hub.publish("note", {"source": "test", "message": "two"})
        assert time.monotonic() - started < 1
        assert listener.closed
        assert listener not in hub.listeners
        far.settimeout(5)
        assert far.recv(1) == b""  # its connection was shut


def test_a_page_that_stops_reading_does_not_hold_up_the_scan(gui, monkeypatch):
    monkeypatch.setattr(server, "QUEUE_SIZE", 8)
    message = "x" * (128 * 1024)

    async def chatty(info, **kwargs):
        for _ in range(128):
            kwargs["on_note"]("test", message)
        return result()

    monkeypatch.setattr(hearthscan.audit, "audit", chatty)
    stuck = socket.socket()
    stuck.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    stuck.settimeout(10)
    stuck.connect(("127.0.0.1", gui.port))
    request = f"GET /api/events?token={gui.token} HTTP/1.1\r\nHost: 127.0.0.1:{gui.port}\r\n\r\n"
    stuck.sendall(request.encode())
    received = b""
    while b"event: idle" not in received:
        received += stuck.recv(1024)

    # From here on it reads nothing.
    started = time.monotonic()
    assert post(gui, "/api/scan").status == 202
    wait_for(lambda: get(gui, "/api/info").json()["has_result"])
    assert time.monotonic() - started < 5
    # It was cut off: what is left of its stream ends instead of waiting for more.
    with contextlib.suppress(ConnectionError):
        while stuck.recv(65536):
            pass
    stuck.close()


# Downloads


def test_nothing_to_download_before_the_first_scan(gui):
    for path in ("/api/result", "/api/report", "/api/result.json"):
        reply = get(gui, path)
        assert reply.status == 404
        assert reply.json() == {"error": "none"}


def test_report_and_json_downloads(gui, monkeypatch):
    FakeAudit(monkeypatch)
    finish_scan(gui)
    i18n.set_language("en")
    stamp = datetime.fromisoformat(STARTED).astimezone().strftime("%Y%m%d-%H%M")

    reply = get(gui, "/api/report?lang=tr")
    assert reply.status == 200
    assert reply.headers["Content-Type"] == "text/html; charset=utf-8"
    disposition = f'attachment; filename="hearthscan-report-{stamp}.html"'
    assert reply.headers["Content-Disposition"] == disposition
    page = reply.body.decode()
    assert page.startswith("<!DOCTYPE html>")
    assert '<html lang="tr">' in page and "Telnet a\u00e7\u0131k" in page
    assert i18n.language() == "en"  # the report did not change it
    assert '<html lang="en">' in get(gui, "/api/report").body.decode()
    assert get(gui, "/api/report?lang=xx").status == 400

    reply = get(gui, "/api/result.json")
    assert reply.status == 200
    assert reply.headers["Content-Type"] == "application/json"
    assert reply.headers["Content-Disposition"] == f'attachment; filename="hearthscan-{stamp}.json"'
    assert serialize.loads(reply.body.decode()).score == 85
    assert json.loads(reply.body) == get(gui, "/api/result").json()
