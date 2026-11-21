"""The local web server behind the desktop window.

It listens on 127.0.0.1 only, on a random port. Every API call needs the
random token that comes with the page's address, and requests that name
another host or come from another site are turned away, so web pages open
elsewhere cannot reach it. The page itself is three static files from the
web folder next to this module.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import queue
import secrets
import socket
import socketserver
import sys
import threading
import time
from collections.abc import Callable, Coroutine
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import parse_qs, urlsplit

from .. import __version__, i18n, serialize, system
from ..models import ScanResult
from ..netinfo import NetworkInfo, local_network
from ..report import html_report
from ..runner import run

if TYPE_CHECKING:
    from importlib.resources.abc import Traversable

HOST = "127.0.0.1"
TOKEN_HEADER = "X-Hearthscan-Token"
MAX_BODY = 4 * 1024
MAX_DRAIN = 64 * 1024  # an unread body up to this size is read before the connection closes
MAX_FIELDS = 16  # query parameters in one request

KEEPALIVE = 15.0  # seconds between keepalive comments on the event stream
QUEUE_SIZE = 256  # events waiting for one page before it is cut off
PROGRESS_EVERY = 0.1  # seconds between two progress events of the same stage
REQUEST_TIMEOUT = 2.0  # seconds a new connection may sit idle before its request arrives
SOCKET_TIMEOUT = 10.0  # seconds a body read or a write may stall
STOP_WAIT = 30.0  # how long shutdown() waits for a stopped scan to wind down

POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

# The only files the server hands out: path -> (file in the web folder, content type).
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}

# Guards the global language while a report is rendered in another one.
_language_lock = threading.Lock()


def web_folder() -> Traversable:
    """The folder that holds index.html, app.js and styles.css."""
    return resources.files("hearthscan.gui") / "web"


def texts(code: str) -> dict[str, str]:
    """Every English text key, in language `code` where it has the key."""
    return i18n.table(code)


def _report_in(result: ScanResult, code: str) -> str:
    """The HTML report in language `code`, leaving the language in use as it was."""
    with _language_lock:
        previous = i18n.language()
        i18n.set_language(code)
        try:
            return html_report(result)
        finally:
            i18n.set_language(previous)


def _stamp(result: ScanResult) -> str:
    """When the scan started, in local time, as YYYYMMDD-HHMM for a file name."""
    try:
        moment = datetime.fromisoformat(result.started.replace("Z", "+00:00"))
        if moment.tzinfo is not None:
            moment = moment.astimezone()
    except (AttributeError, ValueError, OverflowError, OSError):
        moment = datetime.now()
    return moment.strftime("%Y%m%d-%H%M")


def _event(name: str, data: dict[str, Any]) -> bytes:
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return f"event: {name}\ndata: {body}\n\n".encode()


class _Listener:
    """One page on the event stream. Its own queue keeps it from holding up the scan."""

    def __init__(self, connection: socket.socket) -> None:
        self.queue: queue.Queue[bytes | None] = queue.Queue(QUEUE_SIZE)
        self.connection = connection
        self.closed = False

    def send(self, event: bytes) -> bool:
        """Queue `event`. False when the page has fallen too far behind to take it."""
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            return False
        return True

    def close(self) -> None:
        self.closed = True
        with contextlib.suppress(queue.Full):
            self.queue.put_nowait(None)
        # Ends the stream for the page. On Linux and macOS it also wakes a handler
        # stuck writing to a page that stopped reading; Windows waits for the timeout.
        with contextlib.suppress(OSError):
            self.connection.shutdown(socket.SHUT_RDWR)


class _Hub:
    """The scan, its last result, and the pages listening for events."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.listeners: set[_Listener] = set()
        self.result: ScanResult | None = None
        self.scanning = False
        self.closed = False
        self._result_event: bytes | None = None
        self._progress: dict[str, Any] | None = None
        self._progress_sent = 0.0
        self._worker: threading.Thread | None = None
        self._cancel: Callable[[], object] | None = None
        self._stop = False

    # Events

    def listen(self, connection: socket.socket) -> _Listener:
        """A new listener, with the current state already queued for it."""
        listener = _Listener(connection)
        with self.lock:
            if self.closed:
                listener.close()
                return listener
            if self.scanning and self._progress is not None:
                listener.send(_event("progress", self._progress))
            elif self._result_event is not None:
                listener.send(self._result_event)
            else:
                listener.send(_event("idle", {}))
            self.listeners.add(listener)
        return listener

    def unlisten(self, listener: _Listener) -> None:
        with self.lock:
            self.listeners.discard(listener)

    def _publish(self, event: bytes) -> None:
        # Called with the lock held. Nothing here waits for a page.
        for listener in list(self.listeners):
            if not listener.send(event):
                # It reconnects on its own and then gets the current state.
                self.listeners.discard(listener)
                listener.close()

    def publish(self, name: str, data: dict[str, Any]) -> None:
        with self.lock:
            self._publish(_event(name, data))

    def _on_progress(self, stage: str, done: int, total: int) -> None:
        data = {"stage": stage, "done": done, "total": total}
        now = time.monotonic()
        with self.lock:
            same_stage = self._progress is not None and self._progress["stage"] == stage
            self._progress = data
            # The port scan counts every connection; the page needs a few updates a second.
            if same_stage and done < total and now - self._progress_sent < PROGRESS_EVERY:
                return
            self._progress_sent = now
            self._publish(_event("progress", data))

    def _on_note(self, source: str, message: str) -> None:
        self.publish("note", {"source": source, "message": message})

    # The scan

    def start(self, *, probe: bool = True) -> str | None:
        """Start a scan in the background. Returns why not: "busy" or "no_network"."""
        with self.lock:
            if self.scanning or self.closed:
                return "busy"
            self.scanning = True
            self._stop = False
            self._progress = {"stage": "discover", "done": 0, "total": 0}
        info = local_network()
        with self.lock:
            if info is None or self.closed:
                self.scanning = False
                self._progress = None
                return "no_network" if info is None else "busy"
            self._worker = threading.Thread(
                target=self._work, args=(info, probe), name="hearthscan-scan", daemon=True
            )
            self._worker.start()
        return None

    def stop(self) -> bool:
        """Cancel the running scan. False when there is none."""
        with self.lock:
            if not self.scanning:
                return False
            self._stop = True
            cancel = self._cancel
        if cancel is not None:
            # The scan may have finished and closed its loop in the meantime.
            with contextlib.suppress(RuntimeError):
                cancel()
        return True

    def _work(self, info: NetworkInfo, probe: bool) -> None:
        from ..audit import audit

        job = audit(info, probe=probe, on_progress=self._on_progress, on_note=self._on_note)
        result: ScanResult | None = None
        data: dict[str, Any] = {}
        try:
            result = run(self._cancellable(job))
            # The page warns when the services were not checked; a page that
            # connects later cannot know that from the result alone.
            name, data = "result", {"result": serialize.to_dict(result), "probed": probe}
        except KeyboardInterrupt:
            # What runner.run raises for a cancelled scan.
            name, result = "stopped", None
        except Exception as exc:
            name, result = "error", None
            data = {"message": str(exc) or type(exc).__name__}
        with self.lock:
            if result is not None:
                self.result = result
                self._result_event = _event(name, data)
            self.scanning = False
            self._progress = None
            self._stop = False
            self._publish(_event(name, data))

    async def _cancellable(self, job: Coroutine[Any, Any, ScanResult]) -> ScanResult:
        task = asyncio.current_task()
        loop = asyncio.get_running_loop()
        with self.lock:
            stop_now = self._stop
            if not stop_now and task is not None:
                self._cancel = lambda: loop.call_soon_threadsafe(task.cancel)
        if stop_now:
            job.close()
            raise asyncio.CancelledError
        try:
            return await job
        finally:
            with self.lock:
                self._cancel = None

    def close(self) -> None:
        """Stop the scan, let every listener go, and wait for the scan to wind down."""
        with self.lock:
            self.closed = True
            worker = self._worker
            for listener in self.listeners:
                listener.close()
            self.listeners.clear()
        self.stop()
        if worker is not None:
            worker.join(STOP_WAIT)


class _Server(ThreadingHTTPServer):
    daemon_threads = False  # so server_close() waits for the handlers
    allow_reuse_address = False

    def __init__(self, port: int) -> None:
        self.token = secrets.token_urlsafe(24)
        self.hub = _Hub()
        self.connections: set[socket.socket] = set()
        self.connections_lock = threading.Lock()
        super().__init__((HOST, port), _Handler)
        port = self.server_address[1]
        self.hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})
        self.origins = frozenset(f"http://{host}" for host in self.hosts)

    def close_connections(self) -> None:
        """Shut every open connection, so no handler is left waiting on a page.

        On Linux and macOS this wakes a handler blocked on its socket at once.
        Windows does not wake it, so there the socket timeouts bound the wait.
        """
        with self.connections_lock:
            still_open = list(self.connections)
        for connection in still_open:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)

    def server_bind(self) -> None:
        # On Windows another program could otherwise bind the same port and listen in.
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        # HTTPServer.server_bind looks our own name up in DNS, which can take seconds.
        socketserver.TCPServer.server_bind(self)
        self.server_name = HOST
        self.server_port = self.server_address[1]

    def handle_error(self, request: Any, client_address: Any) -> None:
        # A page that went away halfway through an answer is not worth a traceback.
        if isinstance(sys.exc_info()[1], OSError):
            return
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    query: dict[str, list[str]]
    timeout = REQUEST_TIMEOUT  # browsers open spare connections that may never be used
    server_version = "Hearthscan"
    _unread = 0  # bytes of the request body nobody has read

    def setup(self) -> None:
        super().setup()
        with self.server.connections_lock:
            self.server.connections.add(self.connection)

    def finish(self) -> None:
        with self.server.connections_lock:
            self.server.connections.discard(self.connection)
        super().finish()

    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        pass  # the terminal is for the user, not for a request log

    def end_headers(self) -> None:
        self.send_header("Content-Security-Policy", POLICY)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    # Answers

    def _send(
        self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: object, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(data, ensure_ascii=False).encode()
        self._send(status, body, "application/json", headers)

    def _download(self, body: bytes, content_type: str, name: str) -> None:
        disposition = f'attachment; filename="{name}"'
        self._send(200, body, content_type, {"Content-Disposition": disposition})

    # Checks

    def _dispatch(self, method: str) -> None:
        self.connection.settimeout(SOCKET_TIMEOUT)
        length = self.headers.get("Content-Length", "").strip()
        self._unread = int(length) if length.isascii() and length.isdigit() else 0
        try:
            self._answer(method)
        finally:
            # Closing a socket with unread data makes some systems reset the
            # connection, and the page would see that instead of the answer.
            if 0 < self._unread <= MAX_DRAIN:
                with contextlib.suppress(OSError):
                    self.rfile.read(self._unread)

    def _answer(self, method: str) -> None:
        if not self._trusted():
            return
        parts = urlsplit(self.path)
        try:
            self.query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=MAX_FIELDS)
        except ValueError:
            self._json(400, {"error": "bad_request"})
            return
        path = parts.path
        if not path.startswith("/api/"):
            self._static(method, path)
            return
        if not self._has_token(path):
            self._json(403, {"error": "bad_token"})
            return
        route = self.ROUTES.get(path)
        if route is None:
            self._json(404, {"error": "not_found"})
        elif route[0] != method:
            self._json(405, {"error": "method_not_allowed"}, {"Allow": route[0]})
        else:
            route[1](self)

    def _trusted(self) -> bool:
        """Check Host and Origin. Answers and returns False when they are wrong.

        A page from another site can make the browser send requests here, and
        with DNS rebinding even under a name of its own. Neither gets past this.
        """
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or hosts[0] not in self.server.hosts:
            self._json(421, {"error": "bad_host"})
            return False
        origins = self.headers.get_all("Origin") or []
        if origins and (len(origins) != 1 or origins[0] not in self.server.origins):
            self._json(403, {"error": "bad_origin"})
            return False
        return True

    def _has_token(self, path: str) -> bool:
        given = self.headers.get_all(TOKEN_HEADER) or []
        if not given and path == "/api/events":
            # EventSource cannot set headers.
            given = self.query.get("token", [])
        if len(given) != 1:
            return False
        return hmac.compare_digest(given[0].encode(), self.server.token.encode())

    def _body(self) -> dict[str, Any] | None:
        """The JSON object sent with a POST, or None after answering with an error.

        A POST without a body counts as {}. A body has to be JSON.
        """
        if "Transfer-Encoding" in self.headers:
            self._json(411, {"error": "need_length"})
            return None
        length = self.headers.get("Content-Length", "0").strip()
        if not (length.isascii() and length.isdigit()):
            self._json(400, {"error": "bad_request"})
            return None
        size = int(length)
        if size == 0:
            return {}
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "need_json"})
            return None
        if size > MAX_BODY:
            self._json(413, {"error": "too_large"})
            return None
        raw = self.rfile.read(size)
        self._unread = 0
        if len(raw) != size:
            self._json(400, {"error": "bad_request"})
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            data = None
        if not isinstance(data, dict):
            self._json(400, {"error": "bad_json"})
            return None
        return data

    def _language(self) -> str | None:
        """The ?lang= of the request, or the language in use. None after a 400."""
        asked = self.query.get("lang")
        if asked is None:
            return i18n.language()
        if len(asked) != 1 or asked[0] not in i18n.LANGUAGES:
            self._json(400, {"error": "bad_language"})
            return None
        return asked[0]

    # The page

    def _static(self, method: str, path: str) -> None:
        entry = STATIC.get(path)
        if entry is None:
            self._json(404, {"error": "not_found"})
            return
        if method != "GET":
            self._json(405, {"error": "method_not_allowed"}, {"Allow": "GET"})
            return
        name, content_type = entry
        try:
            body = (web_folder() / name).read_bytes()
        except OSError:
            self._json(404, {"error": "not_found"})
            return
        self._send(200, body, content_type)

    # The API

    def _info(self) -> None:
        info = local_network()
        network = None
        if info is not None:
            network = {
                "interface": info.interface.label,
                "address": str(info.address),
                "network": str(info.network),
                "scan_network": str(info.scan_network()),
                "gateway": info.gateway,
            }
        hub = self.server.hub
        data = {
            "version": __version__,
            "language": i18n.language(),
            "languages": list(i18n.LANGUAGES),
            "network": network,
            "sandbox": info.sandbox if info is not None else system.sandbox(),
            "scanning": hub.scanning,
            "has_result": hub.result is not None,
        }
        self._json(200, data)

    def _texts(self) -> None:
        code = self._language()
        if code is not None:
            self._json(200, {"language": code, "texts": texts(code)})

    def _set_language(self) -> None:
        data = self._body()
        if data is None:
            return
        code = data.get("language")
        if not isinstance(code, str) or code not in i18n.LANGUAGES:
            self._json(400, {"error": "bad_language"})
            return
        with _language_lock:
            i18n.set_language(code)
        self._json(200, {"language": code})

    def _scan(self) -> None:
        data = self._body()
        if data is None:
            return
        probe = data.get("probe", True)
        if not isinstance(probe, bool):
            self._json(400, {"error": "bad_request"})
            return
        problem = self.server.hub.start(probe=probe)
        if problem == "busy":
            self._json(409, {"error": "busy"})
        elif problem == "no_network":
            self._json(503, {"error": "no_network"})
        else:
            self._json(202, {"started": True})

    def _stop(self) -> None:
        if self._body() is not None:
            self._json(200, {"stopped": self.server.hub.stop()})

    def _events(self) -> None:
        hub = self.server.hub
        listener = hub.listen(self.connection)
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            while not listener.closed:
                try:
                    event = listener.queue.get(timeout=KEEPALIVE)
                except queue.Empty:
                    event = b": keepalive\n\n"
                if event is None or listener.closed:
                    break
                self.wfile.write(event)
        except OSError:
            pass  # the page went away, or was too slow and got cut off
        finally:
            hub.unlisten(listener)

    def _result(self) -> None:
        result = self.server.hub.result
        if result is None:
            self._json(404, {"error": "none"})
            return
        self._json(200, serialize.to_dict(result))

    def _report(self) -> None:
        code = self._language()
        if code is None:
            return
        result = self.server.hub.result
        if result is None:
            self._json(404, {"error": "none"})
            return
        body = _report_in(result, code).encode()
        name = f"hearthscan-report-{_stamp(result)}.html"
        self._download(body, "text/html; charset=utf-8", name)

    def _result_file(self) -> None:
        result = self.server.hub.result
        if result is None:
            self._json(404, {"error": "none"})
            return
        body = serialize.dumps(result).encode()
        self._download(body, "application/json", f"hearthscan-{_stamp(result)}.json")

    ROUTES: ClassVar[dict[str, tuple[str, Callable[[_Handler], None]]]] = {
        "/api/info": ("GET", _info),
        "/api/texts": ("GET", _texts),
        "/api/events": ("GET", _events),
        "/api/result": ("GET", _result),
        "/api/report": ("GET", _report),
        "/api/result.json": ("GET", _result_file),
        "/api/language": ("POST", _set_language),
        "/api/scan": ("POST", _scan),
        "/api/stop": ("POST", _stop),
    }


class GuiServer:
    """A running server. Call shutdown() when done with it."""

    def __init__(self, server: _Server) -> None:
        self._server = server
        self._lock = threading.Lock()
        self._closed = False
        self.port: int = server.server_address[1]
        self.token: str = server.token
        self.url = f"http://{HOST}:{self.port}/?token={self.token}"
        self._thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.1},
            name="hearthscan-server",
            daemon=True,
        )
        self._thread.start()

    def shutdown(self) -> None:
        """Stop serving, cancel a running scan and wait for every thread to finish."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._server.hub.close()
        self._server.shutdown()
        self._thread.join()
        self._server.close_connections()
        # Closes the listening socket and waits for the request handlers.
        self._server.server_close()


def start_server(*, port: int = 0) -> GuiServer:
    """Serve the interface on 127.0.0.1 in a background thread. Port 0 picks a free one."""
    return GuiServer(_Server(port))
