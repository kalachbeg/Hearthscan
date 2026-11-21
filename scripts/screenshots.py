"""Draw the pictures in the README from a made-up home network.

Every name, address and MAC address in the pictures comes from the network that
made_up_result() builds below. Nothing on the network of the computer running
this script is looked at. The findings and the score are what rules.py and
scoring.py make of that network, so the pictures show the checks as they are.

    uv run python scripts/screenshots.py
    uv run python scripts/screenshots.py --only terminal --lang en
    uv run python scripts/screenshots.py --browser "/path/to/chrome"

It writes terminal.svg, window-light.png and window-dark.png to docs/img, and
the same with -tr in the name for the Turkish README.

The terminal pictures need nothing beyond Hearthscan's own dependencies. The
window pictures need Microsoft Edge, Google Chrome or Chromium: the script runs
it headless and talks to it over the DevTools protocol with a small WebSocket
client of its own, so no extra Python package is needed.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import http.client
import io
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock

from rich.console import Console
from rich.terminal_theme import TerminalTheme
from rich.text import Text

from hearthscan import __version__, i18n, render, rules, scoring
from hearthscan import audit as audit_module
from hearthscan.discovery import classify, oui
from hearthscan.gui import server as server_module
from hearthscan.models import (
    Device,
    MdnsInfo,
    NetbiosInfo,
    PortMapping,
    RouterInfo,
    ScanResult,
    Service,
    UpnpInfo,
    UpnpService,
)
from hearthscan.netinfo import Interface, NetworkInfo
from hearthscan.ports import HOME_PORTS, SERVICE_NAMES

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "img"

# The pictures are for the release, so a development build shows its release number.
VERSION = re.sub(r"\.dev\d+$", "", __version__)

NETWORK = "192.168.1.0/24"
GATEWAY = "192.168.1.1"
ADDRESS = "192.168.1.10"  # FAMILY-PC, the computer Hearthscan runs on in the pictures
INTERFACE = "Wi-Fi"
# No time zone, so every computer shows the same time.
STARTED = "2026-11-21T19:42:07"
FINISHED = "2026-11-21T19:42:58"
ELAPSED = 51.0

TERMINAL_WIDTH = 100
# The browser's page size. The pictures are as wide and end below the first finding.
WINDOW_SIZE = (1200, 1000)
LANGUAGES = ("en", "tr")

# --- The made-up network --------------------------------------------------------------


def _service(port: int, name: str | None = None, **fields: Any) -> Service:
    """A service as the probes leave it: the usual name for the port unless they saw another."""
    return Service(port, name=SERVICE_NAMES.get(port, "") if name is None else name, **fields)


def _web(port: int, title: str | None = None, server: str | None = None) -> Service:
    """A web page that answered, without a login form the probe could see."""
    tls = port in (443, 5001)
    return _service(
        port,
        "https" if tls else None,
        title=title,
        product=server,
        tls=tls,
        tls_version="TLSv1.3" if tls else None,
        facts={"status": "200"},
    )


def _devices() -> list[Device]:
    seen = {"arp", "tcp"}
    return [
        Device(
            GATEWAY,
            mac="00:04:0e:5a:21:c3",
            dns_name="fritz.box",
            upnp=UpnpInfo(
                server="FRITZ!Box 7590 UPnP/1.0 AVM FRITZ!Box 7590 154.07.57",
                location="http://192.168.1.1:49000/igddesc.xml",
                device_types={
                    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
                    "urn:schemas-upnp-org:device:WANDevice:2",
                    "urn:schemas-upnp-org:device:WANConnectionDevice:2",
                },
                friendly_name="FRITZ!Box 7590",
                manufacturer="AVM Berlin",
                model_name="FRITZ!Box 7590",
                services=[
                    UpnpService(
                        "urn:schemas-upnp-org:service:WANIPConnection:2",
                        "http://192.168.1.1:49000/igdupnp/control/WANIPConn1",
                    )
                ],
            ),
            services=[_service(53), _web(80, "FRITZ!Box"), _web(443, "FRITZ!Box")],
            seen_by={*seen, "ssdp"},
            confirmed=True,
            is_gateway=True,
        ),
        Device(
            ADDRESS,
            dns_name="FAMILY-PC",
            services=[_service(135), _service(139), _service(445, facts={"smb1": "no"})],
            seen_by={"local", "tcp"},
            confirmed=True,
            is_self=True,
        ),
        Device(
            "192.168.1.11",
            mac="00:03:93:7d:42:18",
            mdns=MdnsInfo(
                hostname="MacBook-Air.local",
                services={"_companion-link._tcp", "_airplay._tcp", "_device-info._tcp"},
                txt={"_device-info._tcp": {"model": "MacBookAir10,1"}},
            ),
            services=[_service(7000)],
            seen_by={*seen, "mdns"},
            confirmed=True,
        ),
        Device(
            "192.168.1.12",
            mac="da:3f:91:2c:5e:07",  # made up by the phone itself, as phones do
            mdns=MdnsInfo(
                hostname="iPhone.local",
                services={"_apple-mobdev2._tcp", "_companion-link._tcp"},
            ),
            services=[_service(62078)],
            seen_by={*seen, "mdns"},
            confirmed=True,
        ),
        Device(
            "192.168.1.13",
            mac="7e:c4:12:88:3a:d1",  # also made up by the phone
            dns_name="Galaxy-S23.fritz.box",
            seen_by={"arp"},
            confirmed=False,  # asleep: only the neighbor table knows it
        ),
        Device(
            "192.168.1.20",
            mac="00:07:ab:3e:91:5c",
            upnp=UpnpInfo(
                server="Samsung-Linux/4.1, UPnP/1.0, Samsung_UPnP_SDK/1.0",
                device_types={
                    "urn:schemas-upnp-org:device:MediaRenderer:1",
                    "urn:dial-multiscreen-org:device:dial:1",
                },
                friendly_name="[TV] Living Room",
                manufacturer="Samsung Electronics",
                model_name="QE55Q60B",
            ),
            mdns=MdnsInfo(services={"_airplay._tcp"}),
            services=[_service(7000)],
            seen_by={*seen, "ssdp", "mdns"},
            confirmed=True,
        ),
        Device(
            "192.168.1.21",
            mac="00:1b:a9:6c:30:e2",
            mdns=MdnsInfo(
                hostname="Office-Printer.local",
                services={"_ipp._tcp", "_pdl-datastream._tcp", "_printer._tcp", "_http._tcp"},
                instances={"_ipp._tcp": "Brother HL-L2350DW series"},
                txt={"_ipp._tcp": {"ty": "Brother HL-L2350DW series"}},
            ),
            services=[
                _web(80, "Brother HL-L2350DW series", server="debut/1.30"),
                _web(443, "Brother HL-L2350DW series", server="debut/1.30"),
                _web(631, server="debut/1.30"),
                _service(9100),
            ],
            seen_by={*seen, "mdns"},
            confirmed=True,
        ),
        Device(
            "192.168.1.25",
            mac="3c:91:5e:2a:6f:04",
            dns_name="garden-cam.fritz.box",
            services=[
                # The stream answers DESCRIBE without asking for a password.
                _service(554, product="Rtsp Server/3.0", auth="none", facts={"describe": "200"}),
            ],
            seen_by={*seen},
            confirmed=True,
        ),
        Device(
            "192.168.1.30",
            # A prefix no maker has registered, so no real brand ends up next
            # to the SMB1 finding in the pictures.
            mac="74:a9:12:a4:19:5d",
            mdns=MdnsInfo(
                hostname="backup-nas.local",
                services={"_smb._tcp", "_adisk._tcp", "_http._tcp"},
            ),
            netbios=NetbiosInfo(
                name="BACKUP-NAS", workgroup="WORKGROUP", mac="74:a9:12:a4:19:5d", file_server=True
            ),
            upnp=UpnpInfo(
                device_types={"urn:schemas-upnp-org:device:Basic:1"},
                friendly_name="Backup NAS",
                model_name="NAS-2 Bay",
            ),
            services=[
                _service(139),
                _service(445, facts={"smb1": "yes"}),  # still lets SMB1 in
                _web(5000, "Backup NAS", server="nginx"),
                _web(5001, "Backup NAS", server="nginx"),
                _service(32400, auth="required", facts={"status": "401"}),
            ],
            seen_by={*seen, "mdns", "netbios", "ssdp"},
            confirmed=True,
        ),
        Device(
            "192.168.1.40",
            mac="28:cd:c1:0b:6e:94",
            dns_name="raspberrypi.fritz.box",
            services=[
                _service(
                    22, banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", product="OpenSSH 9.2p1"
                )
            ],
            seen_by={*seen},
            confirmed=True,
        ),
        Device(
            "192.168.1.50",
            mac="84:00:ec:7c:87:ce",
            mdns=MdnsInfo(
                hostname="shellyplug-7C87CE.local", services={"_http._tcp", "_shelly._tcp"}
            ),
            services=[_web(80, "Shelly Plug")],
            seen_by={*seen, "mdns"},
            confirmed=True,
        ),
    ]


def _router() -> RouterInfo:
    return RouterInfo(
        external_ip="203.0.113.57",  # an address set aside for examples
        connection="IP_Routed",
        status="Connected",
        uptime=12 * 86400 + 5 * 3600,
        mappings=[
            # The camera opened this one itself, over UPnP.
            PortMapping("TCP", 8554, "192.168.1.25", 554, "IPCAM RTSP"),
            PortMapping("TCP", 32400, "192.168.1.30", 32400, "Plex Media Server"),
        ],
    )


def made_up_result() -> ScanResult:
    """A home network that never existed, judged by the real rules."""
    devices = _devices()
    for device in devices:
        device.vendor = oui.lookup(device.mac)
        classify.classify(device)
    devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
    router = _router()
    findings = rules.evaluate(devices, gateway=GATEWAY, router=router)
    return ScanResult(
        version=VERSION,
        started=STARTED,
        finished=FINISHED,
        interface=INTERFACE,
        address=ADDRESS,
        network=NETWORK,
        gateway=GATEWAY,
        devices=devices,
        findings=findings,
        score=scoring.score(findings),
        ports=list(HOME_PORTS),
        router=router,
    )


def made_up_network() -> NetworkInfo:
    interface = Interface(
        name="wlan0",
        label=INTERFACE,
        address=ipaddress.IPv4Address(ADDRESS),
        network=ipaddress.IPv4Network(NETWORK),
    )
    return NetworkInfo(interface=interface, gateway=GATEWAY)


# --- The terminal ---------------------------------------------------------------------

# Close to the window's dark colours. Rich draws "bold red" and the like with
# these, and 256-colour names such as dark_orange with the standard palette.
THEME = TerminalTheme(
    (23, 25, 29),
    (222, 221, 216),
    [
        (44, 47, 54),
        (240, 104, 98),
        (129, 199, 132),
        (236, 196, 94),
        (122, 162, 247),
        (199, 146, 234),
        (110, 200, 214),
        (200, 203, 208),
    ],
    [
        (92, 99, 112),
        (255, 138, 128),
        (160, 220, 150),
        (245, 214, 130),
        (150, 184, 255),
        (220, 170, 245),
        (140, 222, 232),
        (255, 255, 255),
    ],
)

# Rich's own template loads Fira Code from a CDN. Pictures in a README cannot
# load fonts, so this one sticks to the monospace fonts already on the reader's
# computer. Rich sets the width of every run of text, so columns stay straight.
SVG_TEMPLATE = """\
<svg class="rich-terminal" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">
    <style>
    .{unique_id}-matrix {{
        font-family: ui-monospace, "Cascadia Mono", "SF Mono", Menlo, Consolas,
            "DejaVu Sans Mono", "Liberation Mono", monospace;
        font-size: {char_height}px;
        line-height: {line_height}px;
        font-variant-east-asian: full-width;
    }}
    .{unique_id}-title {{
        font-size: 16px;
        font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    }}
    {styles}
    </style>
    <defs>
    <clipPath id="{unique_id}-clip-terminal">
      <rect x="0" y="0" width="{terminal_width}" height="{terminal_height}" />
    </clipPath>
    {lines}
    </defs>
    {chrome}
    <g transform="translate({terminal_x}, {terminal_y})"
       clip-path="url(#{unique_id}-clip-terminal)">
    {backgrounds}
    <g class="{unique_id}-matrix">
    {matrix}
    </g>
    </g>
</svg>
"""


def terminal_svg(result: ScanResult, language: str) -> str:
    """What `hearthscan scan` prints for the made-up network, as an SVG picture."""
    i18n.set_language(language)
    console = Console(
        record=True,
        width=TERMINAL_WIDTH,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
        highlight=False,
        legacy_windows=False,
    )
    parts = render.result_view(result, ELAPSED, notes=False, width=TERMINAL_WIDTH)
    # All of it is over a hundred lines. The window picture shows the score and the
    # first risks, so this one shows what a terminal holds once the scan is done:
    # the end, from the "good to know" list down to the devices.
    fyi = i18n.t("ui.findings.fyi")
    start = next(i for i, part in enumerate(parts) if isinstance(part, Text) and part.plain == fyi)
    for part in parts[start:]:
        console.print(part)
    command = "hearthscan scan" if language == "en" else f"hearthscan scan --lang {language}"
    return console.export_svg(title=command, theme=THEME, code_format=SVG_TEMPLATE)


# --- The window -----------------------------------------------------------------------

BROWSERS = (
    "msedge",
    "microsoft-edge",
    "microsoft-edge-stable",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
    "chromium",
    "chromium-browser",
)
BROWSER_PATHS = (
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
)

# Keep the browser quiet: no updates, sync, telemetry or other calls home.
BROWSER_FLAGS = (
    "--headless=new",
    "--remote-debugging-port=0",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-domain-reliability",
    "--disable-extensions",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-pings",
    "--mute-audio",
    "--hide-scrollbars",
    "--force-device-scale-factor=1",
)

# The result view is up, with its device table, and the fonts are in.
READY = """(() => {
  const view = document.getElementById('view-result');
  const rows = document.querySelectorAll('#device-table tbody tr');
  return Boolean(view && !view.hidden && rows.length && document.fonts.status === 'loaded');
})()"""

# Where the first finding ends. The picture stops a little below it, on a whole card.
FIRST_CARD_BOTTOM = """(() => {
  const card = document.querySelector('#finding-list .finding');
  return card ? card.getBoundingClientRect().bottom + window.scrollY : 0;
})()"""


def find_browser(given: str | None = None) -> str | None:
    if given:
        return given
    for name in BROWSERS:
        found = shutil.which(name)
        if found:
            return found
    for candidate in BROWSER_PATHS:
        path = os.path.expandvars(candidate)
        if "%" not in path and os.path.isfile(path):
            return path
    return None


def _xor_mask(data: bytes, key: bytes) -> bytes:
    repeated = (key * (len(data) // 4 + 1))[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(repeated, "big")).to_bytes(
        len(data), "big"
    )


class WebSocket:
    """The client side of RFC 6455, as much as DevTools needs: text messages, no extensions."""

    def __init__(self, url: str, timeout: float = 60.0) -> None:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname or "127.0.0.1", parts.port or 80
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buffer = bytearray()
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {parts.path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        status = self._head().split(b"\r\n", 1)[0]
        if status.split(b" ")[1:2] != [b"101"]:
            raise ConnectionError(f"the browser refused the DevTools connection: {status!r}")

    def _fill(self, size: int) -> None:
        while len(self.buffer) < size:
            chunk = self.sock.recv(1 << 20)
            if not chunk:
                raise ConnectionError("the browser closed the DevTools connection")
            self.buffer += chunk

    def _head(self) -> bytes:
        while b"\r\n\r\n" not in self.buffer:
            self._fill(len(self.buffer) + 1)
        head, _, rest = bytes(self.buffer).partition(b"\r\n\r\n")
        self.buffer = bytearray(rest)
        return head

    def _take(self, size: int) -> bytes:
        self._fill(size)
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    def _frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])
        size = len(payload)
        if size < 126:
            header.append(0x80 | size)
        elif size < 1 << 16:
            header += bytes([0x80 | 126]) + size.to_bytes(2, "big")
        else:
            header += bytes([0x80 | 127]) + size.to_bytes(8, "big")
        key = os.urandom(4)
        self.sock.sendall(bytes(header) + key + _xor_mask(payload, key))

    def send(self, text: str) -> None:
        self._frame(0x1, text.encode())

    def receive(self) -> str:
        message = bytearray()
        while True:
            first, second = self._take(2)
            size = second & 0x7F
            if size == 126:
                size = int.from_bytes(self._take(2), "big")
            elif size == 127:
                size = int.from_bytes(self._take(8), "big")
            key = self._take(4) if second & 0x80 else None
            payload = self._take(size)
            if key:
                payload = _xor_mask(payload, key)
            opcode = first & 0x0F
            if opcode == 0x8:
                raise ConnectionError("the browser closed the DevTools connection")
            if opcode == 0x9:
                self._frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            message += payload
            if first & 0x80:
                return message.decode()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._frame(0x8, b"")
        self.sock.close()


def _get_json(port: int, path: str, headers: dict[str, str] | None = None) -> Any:
    # http.client rather than urllib: urllib would hand 127.0.0.1 to a system proxy.
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"GET {path} answered {response.status}")
        return json.loads(body)
    finally:
        connection.close()


class Browser:
    """A headless Edge, Chrome or Chromium with a throwaway profile, driven over DevTools."""

    def __init__(self, executable: str, size: tuple[int, int] = WINDOW_SIZE) -> None:
        self.size = size
        self.profile = tempfile.mkdtemp(prefix="hearthscan-shots-")
        args = [
            executable,
            *BROWSER_FLAGS,
            f"--user-data-dir={self.profile}",
            f"--window-size={size[0]},{size[1]}",
            "about:blank",
        ]
        self.process = subprocess.Popen(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        self.ids = 0
        self.port: int | None = None
        self.endpoint: str | None = None  # the browser's own DevTools address
        self.socket: WebSocket | None = None
        try:
            port, path = self._devtools()
            self.port, self.endpoint = port, f"ws://127.0.0.1:{port}{path}"
            page = next(t for t in _get_json(port, "/json/list") if t.get("type") == "page")
            self.socket = WebSocket(page["webSocketDebuggerUrl"])
        except BaseException:
            self.close()
            raise

    def _devtools(self, timeout: float = 30.0) -> tuple[int, str]:
        """The DevTools port and browser path, from the file the browser writes into its profile."""
        marker = Path(self.profile) / "DevToolsActivePort"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with contextlib.suppress(OSError, ValueError):
                port, path = marker.read_text(encoding="utf-8").split()[:2]
                return int(port), path
            # Edge on Windows may hand over to another process and exit with 0 at once.
            if self.process.poll() not in (None, 0):
                raise RuntimeError(f"the browser quit (exit status {self.process.returncode})")
            time.sleep(0.1)
        raise TimeoutError("the browser did not open its DevTools port")

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        self.ids += 1
        ident = self.ids
        self.socket.send(json.dumps({"id": ident, "method": method, "params": params}))
        while True:
            message = json.loads(self.socket.receive())
            if message.get("id") != ident:
                continue  # an event
            if "error" in message:
                raise RuntimeError(f"{method}: {message['error'].get('message')}")
            return message.get("result", {})

    def evaluate(self, expression: str) -> Any:
        found = self.call("Runtime.evaluate", expression=expression, returnByValue=True)
        return found.get("result", {}).get("value")

    def wait_for(self, expression: str, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while not self.evaluate(expression):
            if time.monotonic() > deadline:
                raise TimeoutError(f"the page never got to: {expression[:60]}")
            time.sleep(0.1)

    def screenshot(self, url: str, *, scheme: str) -> bytes:
        width, height = self.size
        self.call(
            "Emulation.setDeviceMetricsOverride",
            width=width,
            height=height,
            deviceScaleFactor=1,
            mobile=False,
        )
        self.call(
            "Emulation.setEmulatedMedia",
            media="screen",
            features=[
                {"name": "prefers-color-scheme", "value": scheme},
                {"name": "prefers-reduced-motion", "value": "reduce"},
            ],
        )
        # Through a blank page, so the last picture's page cannot pass for this one.
        self.call("Page.navigate", url="about:blank")
        self.wait_for("location.href === 'about:blank' && document.readyState === 'complete'")
        self.call("Page.navigate", url=url)
        self.wait_for(READY)
        time.sleep(0.5)
        bottom = self.evaluate(FIRST_CARD_BOTTOM) or height
        clip = {"x": 0, "y": 0, "width": width, "height": min(round(bottom) + 28, height)}
        shot = self.call("Page.captureScreenshot", format="png", clip={**clip, "scale": 1})
        return base64.b64decode(shot["data"])

    def close(self) -> None:
        if self.socket is not None:
            self.socket.close()
        if self.endpoint is not None:
            # The process started here may not be the browser any more, so ask it to quit.
            with contextlib.suppress(OSError):
                control = WebSocket(self.endpoint, timeout=5)
                control.send(json.dumps({"id": 1, "method": "Browser.close"}))
                with contextlib.suppress(OSError):
                    control.receive()
                control.close()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(10)
        # Gone once its DevTools port stops answering. Pulling the profile away
        # sooner can leave its crash handler process behind.
        deadline = time.monotonic() + 10
        while self.port is not None and time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
            except OSError:
                break
            time.sleep(0.2)
        time.sleep(1)
        # The browser holds on to its profile for a moment after it quits.
        for _ in range(40):
            shutil.rmtree(self.profile, ignore_errors=True)
            if not os.path.exists(self.profile):
                break
            time.sleep(0.25)


@contextlib.contextmanager
def made_up_server(result: ScanResult, language: str) -> Iterator[server_module.GuiServer]:
    """The real window server, with the made-up network in place of a real check."""

    async def audit(info: NetworkInfo, *, on_progress: Any = None, **_: Any) -> ScanResult:
        for stage in ("discover", "ports", "probes", "router", "checks", "done"):
            if on_progress:
                on_progress(stage, 0, 0)
        return copy.deepcopy(result)

    i18n.set_language(language)
    with (
        mock.patch.object(audit_module, "audit", audit),
        mock.patch.object(server_module, "local_network", made_up_network),
        mock.patch.object(server_module, "__version__", VERSION),
    ):
        gui = server_module.start_server()
        try:
            headers = {server_module.TOKEN_HEADER: gui.token}
            connection = http.client.HTTPConnection("127.0.0.1", gui.port, timeout=10)
            try:
                connection.request("POST", "/api/scan", body=b"", headers=headers)
                answer = connection.getresponse()
                answer.read()
            finally:
                connection.close()
            if answer.status != 202:
                raise RuntimeError(f"the made-up check did not start ({answer.status})")
            deadline = time.monotonic() + 10
            while not _get_json(gui.port, "/api/info", headers)["has_result"]:
                if time.monotonic() > deadline:
                    raise TimeoutError("the made-up check never finished")
                time.sleep(0.05)
            yield gui
        finally:
            gui.shutdown()


def window_pictures(result: ScanResult, browser: Browser, language: str) -> dict[str, bytes]:
    pictures = {}
    with made_up_server(result, language) as gui:
        for scheme in ("light", "dark"):
            pictures[scheme] = browser.screenshot(gui.url, scheme=scheme)
    return pictures


# --- Running it -----------------------------------------------------------------------


def _suffix(language: str) -> str:
    return "" if language == "en" else f"-{language}"


def _write(path: Path, data: bytes | str) -> None:
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8", newline="\n")
    else:
        path.write_bytes(data)
    size = path.stat().st_size
    print(
        f"  {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}  {size / 1024:.0f} KB"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", choices=("terminal", "window"), help="draw only these pictures")
    parser.add_argument(
        "--lang", choices=LANGUAGES, action="append", help="only this language (repeatable)"
    )
    parser.add_argument("--browser", help="the Edge, Chrome or Chromium program to use")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="where to put the pictures")
    args = parser.parse_args(argv)
    languages = args.lang or list(LANGUAGES)
    args.output.mkdir(parents=True, exist_ok=True)

    result = made_up_result()
    print(
        f"Made-up network: {len(result.devices)} devices, {len(result.findings)} findings, "
        f"score {result.score}"
    )

    if args.only in (None, "terminal"):
        for language in languages:
            _write(args.output / f"terminal{_suffix(language)}.svg", terminal_svg(result, language))

    if args.only in (None, "window"):
        executable = find_browser(args.browser)
        if executable is None:
            print("No Edge, Chrome or Chromium found; pass --browser.", file=sys.stderr)
            return 1
        browser = Browser(executable)
        try:
            for language in languages:
                for scheme, png in window_pictures(result, browser, language).items():
                    _write(args.output / f"window-{scheme}{_suffix(language)}.png", png)
        finally:
            browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
