"""Ask open ports what is listening on them.

Each probe speaks just enough of one protocol to name the service, read its
version and see whether it lets anyone in without credentials. None of them
logs in, sends a password or changes anything. Printers get no bytes at all:
whatever reaches a raw print port comes out on paper.

What the probes put in Service.facts:

    http        status of GET /, login ("form", "basic" or "digest") when the
                page asks for one, redirect when / sends us somewhere else
    smb         smb1: "yes" or "no"
    rsync       modules: how many modules the server lists
    vnc         security: the offered security types, like "None,VNC Authentication"
    mqtt        connack: the CONNACK return code
    rtsp        describe: the status of a DESCRIBE without credentials
    socks       version: "5"
    adb         state: "device" or "unauthorized"
    postgresql  ssl: "S" or "N", the answer to an SSLRequest
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import ipaddress
import json
import math
import random
import re
import struct
import unicodedata
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import TypeVar

from . import http
from .models import Service
from .ports import SERVICE_NAMES
from .scope import ScopeError, is_local

T = TypeVar("T")

MAX_READ = 64 * 1024  # per probe, over all its raw connections
MAX_BANNER = 200
MAX_TITLE = 120
MAX_PRODUCT = 80
MAX_FACT = 120

# How long a port we know nothing about gets to speak first before it is
# asked for a web page.
LISTEN = 1.0

_WEB_PORTS = (
    80, 81, 631, 3000, 5000, 5357, 7547, 8000, 8008, 8080, 8081, 8888, 9000, 10000, 32400, 49152,
)  # fmt: skip
_TLS_WEB_PORTS = (443, 5001, 8443)
# A raw print port prints whatever arrives: 9100 and up (JetDirect boxes and
# p910nd put more printers on 9101, 9102...) and 515. The rest have nothing a
# light probe could learn.
_LEFT_ALONE = (9100, 9101, 9102, 9103, 515, 62078, 8009, 135, 139, 7000)

# The probe each port gets. Other known ports are only listened to, and so are
# ports missing here ("unknown"): sending a web request to a port we know
# nothing about could land on a printer or a console waiting for a login.
PROBES: dict[int, str] = {
    **dict.fromkeys(SERVICE_NAMES, "listen"),
    21: "banner",
    22: "banner",
    23: "telnet",
    110: "banner",
    143: "banner",
    445: "smb",
    554: "rtsp",
    873: "rsync",
    1080: "socks",
    1883: "mqtt",
    2375: "docker",
    3306: "mysql",
    5432: "postgresql",
    5555: "adb",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    **dict.fromkeys(_WEB_PORTS, "web"),
    **dict.fromkeys(_TLS_WEB_PORTS, "tls-web"),
    **dict.fromkeys(_LEFT_ALONE, "none"),
}

# Probes for services that are expected to speak first. They get the whole
# timeout for it, not just LISTEN.
_PATIENT = {"banner", "telnet", "rsync", "mysql", "vnc"}

_CHUNK = 4096
_MAX_GREETING = 4096
_MAX_LINE = 4096
_MAX_HEADERS = 64
_BODY_LIMIT = 32 * 1024  # per web request
_RSYNC_LINES = 256
_RTSP_BODY = 16 * 1024
_ADB_BANNER = 4096

# What a broken or hostile device can make the probes raise. probe() keeps it all in.
_TROUBLE = (OSError, EOFError, ValueError, LookupError, struct.error)

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# Separators, not category C, but they still break the line they are printed on.
_LINE_BREAKS = "\u2028\u2029"

# Other lines may come before the version line, and the server's key exchange
# often comes right after it, in the same packet.
_SSH_LINE = re.compile(r"^SSH-[\d.]{1,8}-(\S+)[^\r\n]*", re.MULTILINE)
_SSH_LINE_DONE = re.compile(rb"^SSH-[^\n]{0,255}\n", re.MULTILINE)
# Dropbear names its own key exchange extensions after its author's domain.
_DROPBEAR_KEX = "@matt.ucc.asn.au"
_FTP_REPLY = re.compile(r"220[ -]")
_CONTINUED = re.compile(rb"\d{3}-")

# Products a greeting names, with the version when it gives one.
_GREETING_PRODUCTS = tuple(
    (re.compile(pattern, re.IGNORECASE), name)
    for pattern, name in (
        (r"\bvsFTPd ([0-9][\w.]{0,30})", "vsFTPd"),
        (r"\bProFTPD(?: ([0-9][\w.]{0,30}))?", "ProFTPD"),
        (r"\bPure-FTPd\b", "Pure-FTPd"),
        (r"\bFileZilla Server(?: version)?(?: ([0-9][\w.]{0,30}))?", "FileZilla Server"),
        (r"\bMicrosoft FTP Service\b", "Microsoft FTP Service"),
        (r"\bbftpd ([0-9][\w.]{0,30})", "bftpd"),
        (r"\bBusyBox v([0-9][\w.]{0,30})", "BusyBox"),
        (r"\bDovecot\b", "Dovecot"),
        (r"\bPostfix\b", "Postfix"),
        (r"\bExim ([0-9][\w.]{0,30})", "Exim"),
    )
)

_IAC, _DONT, _DO, _WONT, _WILL, _SB, _SE = 255, 254, 253, 252, 251, 250, 240
# How BusyBox telnetd opens: DO ECHO, DO NAWS, WILL ECHO, WILL SGA.
_BUSYBOX_TELNETD = bytes((_IAC, _DO, 1, _IAC, _DO, 31, _IAC, _WILL, 1, _IAC, _WILL, 3))
_MAX_SUBNEGOTIATION = 512
_PROMPT = re.compile(rb"[:>#$%][ \t]*\Z")
_LOGIN_PROMPT = re.compile(rb"(?i)(?:login|user ?name|password)[ \t]*:[ \t]*\Z")

_TITLE_START = re.compile(r"<title\b[^>]{0,200}>", re.IGNORECASE)
_TITLE_END = re.compile(r"</title\s*>", re.IGNORECASE)
_PASSWORD_INPUT = re.compile(r"""<input\b[^>]{0,300}?\btype\s*=\s*["']?password\b""", re.IGNORECASE)
_META_REFRESH = re.compile(
    r"""<meta\b[^>]{0,500}?http-equiv\s*=\s*["']?refresh\b[^>]{0,500}>""", re.IGNORECASE
)
_REFRESH_URL = re.compile(r"""\burl\s*=\s*["']?\s*([^"'\s>]{1,2048})""", re.IGNORECASE)
_BASIC = re.compile(r"(?:^|,)\s*basic\b", re.IGNORECASE)
_DIGEST = re.compile(r"(?:^|,)\s*digest\b", re.IGNORECASE)
_REDIRECTS = (301, 302, 303, 307, 308)
_DEFAULT_PORTS = {"http": 80, "https": 443}
# What web servers say when plain HTTP reaches a port that wants TLS.
_TLS_HINT = re.compile(
    rb"(?i)running in SSL mode|plain HTTP request was sent to HTTPS"
    rb"|speaking plain HTTP to an SSL|HTTP request to an HTTPS server"
)

_RTSP_STATUS = re.compile(rb"RTSP/1\.\d[ \t]+(\d{3})\b")
_CONTENT_LENGTH = re.compile(rb"[0-9]{1,9}")
_REDIS_LOCKED = re.compile(rb"(?i)NOAUTH|WRONGPASS|DENIED|auth|password|not permitted")
_MEMCACHED_VERSION = re.compile(rb"VERSION ([\w.+-]{1,40})")
_RSYNCD = re.compile(rb"@RSYNCD: \d{1,4}(?:\.\d{1,4})?(?: [\w-]{1,32}){0,16}")
_RFB = re.compile(rb"RFB (\d{3})\.(\d{3})\n")
_VERSION_NUMBER = re.compile(r"\d+\.\d+(?:\.\d+)?")

_VNC_SECURITY = {
    1: "None",
    2: "VNC Authentication",
    5: "RA2",
    6: "RA2ne",
    16: "Tight",
    17: "Ultra",
    18: "TLS",
    19: "VeNCrypt",
    20: "SASL",
    21: "MD5",
    22: "xvp",
    30: "Apple Remote Desktop",
}

# Security types that always check a password or key.
_VNC_SECRET = frozenset({2, 5, 6, 21, 30})

_ADB_CNXN = 0x4E584E43
_ADB_AUTH = 0x48545541
_ADB_STLS = 0x534C5453
_ADB_VERSION = 0x01000001
_ADB_MAXDATA = 256 * 1024

_POSTGRES_SSL_REQUEST = struct.pack(">II", 8, 80877103)


def _smb1_negotiate() -> bytes:
    """An SMB1 NEGOTIATE that offers "NT LM 0.12" and nothing else."""
    dialects = b"\x02NT LM 0.12\x00"
    # Flags: case-insensitive, canonical paths. Flags2: NT status codes, long names.
    header = struct.pack(
        "<4sBIBHH8sHHHHH", b"\xffSMB", 0x72, 0, 0x18, 0x4001, 0, bytes(8), 0, 0, 0, 0, 0
    )
    message = header + struct.pack("<BH", 0, len(dialects)) + dialects
    return b"\x00" + len(message).to_bytes(3, "big") + message


_SMB1_NEGOTIATE = _smb1_negotiate()


@dataclass(slots=True)
class _Job:
    ip: str
    port: int
    service: Service
    deadline: float  # event loop time
    budget: int = MAX_READ

    def left(self) -> float:
        return self.deadline - asyncio.get_running_loop().time()


class _Conn:
    """A TCP connection of one probe. Every byte read counts against its budget."""

    def __init__(
        self, job: _Job, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.job = job
        self.service = job.service
        self.reader = reader
        self.writer = writer
        self.buffer = bytearray()
        self.ended = False

    async def fill(self, wait: float | None = None) -> bool:
        """Add whatever arrives next to the buffer. False at the end of the stream or budget.

        Raises TimeoutError when nothing arrives within `wait` seconds.
        """
        if self.ended or self.job.budget <= 0:
            self.ended = True
            return False
        read = self.reader.read(min(_CHUNK, self.job.budget))
        data = await (read if wait is None else _within(read, wait))
        if not data:
            self.ended = True
            return False
        self.job.budget -= len(data)
        self.buffer += data
        return True

    async def exactly(self, count: int) -> bytes:
        while len(self.buffer) < count:
            if not await self.fill():
                raise EOFError("connection closed early")
        data = bytes(self.buffer[:count])
        del self.buffer[:count]
        return data

    async def line(self, limit: int = _MAX_LINE) -> bytes:
        """The next line, without its line ending."""
        while (end := self.buffer.find(b"\n")) < 0:
            if len(self.buffer) >= limit:
                raise ValueError(f"line longer than {limit} bytes")
            if not await self.fill():
                raise EOFError("connection closed early")
        line = bytes(self.buffer[:end])
        del self.buffer[: end + 1]
        return line.rstrip(b"\r")

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()


async def _within(job: Awaitable[T], seconds: float) -> T:
    """Await `job` for up to `seconds`, then cancel it and raise TimeoutError.

    Built like ports._connect_within, without asyncio.wait_for, so that a
    cancellation from outside is never lost.
    """
    task = asyncio.ensure_future(job)
    try:
        await asyncio.wait({task}, timeout=max(seconds, 0))
    finally:
        if not task.done():
            task.cancel()
            await asyncio.wait({task})
        elif not task.cancelled():
            task.exception()  # mark it as seen, even when we are unwinding
    if task.cancelled():
        raise TimeoutError
    return task.result()


@contextlib.asynccontextmanager
async def _connect(job: _Job) -> AsyncIterator[_Conn]:
    reader, writer = await asyncio.open_connection(job.ip, job.port, limit=MAX_READ)
    try:
        yield _Conn(job, reader, writer)
    finally:
        # abort() and not close(), for the reasons given in http._exchange.
        writer.transport.abort()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _clean(value: str | bytes | None, limit: int) -> str | None:
    """Text safe to show: no escape sequences, control or format characters, spaces collapsed."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value[: limit * 8]).decode("utf-8", errors="replace")
    text = _ANSI_ESCAPE.sub(" ", value[: limit * 8])
    text = "".join(
        " " if unicodedata.category(ch)[0] == "C" or ch in _LINE_BREAKS else ch for ch in text
    )
    return " ".join(text.split())[:limit].rstrip() or None


# Greetings: services that speak first


def _ssh_product(text: str) -> str | None:
    """Turn "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3" into "OpenSSH 9.6p1"."""
    match = _SSH_LINE.search(text)
    if not match:
        return None
    software = match.group(1).replace("_", " ")
    if software.lower() in ("ssh", "sshd"):  # a vendor hiding what it runs
        return "Dropbear" if _DROPBEAR_KEX in text else None
    return _clean(software, MAX_PRODUCT)


def _product_from_text(text: str) -> str | None:
    for pattern, name in _GREETING_PRODUCTS:
        match = pattern.search(text)
        if match:
            version = (match.group(1) or "").rstrip(".") if match.groups() else ""
            return _clean(f"{name} {version}" if version else name, MAX_PRODUCT)
    return None


def _name_from_greeting(text: str) -> str | None:
    if _SSH_LINE.search(text):
        return "ssh"
    start = text.lstrip()
    if _FTP_REPLY.match(start):
        first = start[:400].upper()
        if "FTP" in first or "FILEZILLA" in first:
            return "ftp"
        if "SMTP" in first:
            return "smtp"
    elif start.startswith("+OK"):
        return "pop3"
    elif start.startswith("* OK"):
        return "imap"
    return None


def _note_greeting(service: Service, data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    ssh = _SSH_LINE.search(text)
    banner = _clean(ssh.group(0) if ssh else text, MAX_BANNER)
    if not banner:
        return
    service.banner = banner
    name = _name_from_greeting(text)
    if name:
        service.name = name
    product = _ssh_product(text) or _product_from_text(text)
    if product:
        service.product = product


def _complete(data: bytes | bytearray) -> bool:
    """A greeting ends with a line, unless that line says an FTP style reply goes on."""
    if _SSH_LINE_DONE.search(data):
        return True
    if not data.strip() or not data.endswith(b"\n"):
        return False
    last = data.rstrip(b"\r\n").rsplit(b"\n", 1)[-1]
    return not _CONTINUED.match(last)


async def _text_greeting(conn: _Conn, end: float) -> None:
    loop = asyncio.get_running_loop()
    try:
        while len(conn.buffer) < _MAX_GREETING and not _complete(conn.buffer):
            left = end - loop.time()
            if left <= 0 or not await conn.fill(left):
                break
    except TimeoutError:
        pass
    finally:
        # Also when the probe's deadline cuts us off.
        _note_greeting(conn.service, bytes(conn.buffer[:_MAX_GREETING]))


def _telnet_split(data: bytes) -> tuple[bytes, list[tuple[int, int]], bytes]:
    """Split telnet input into text, the DO and WILL requests in it, and a partial command."""
    text = bytearray()
    asks: list[tuple[int, int]] = []
    i = 0
    while i < len(data):
        command_at = data.find(_IAC, i)
        if command_at < 0:
            text += data[i:]
            return bytes(text), asks, b""
        text += data[i:command_at]
        i = command_at
        if i + 1 == len(data):
            break
        command = data[i + 1]
        if command == _IAC:
            text.append(_IAC)
            i += 2
        elif command in (_DO, _DONT, _WILL, _WONT):
            if i + 2 == len(data):
                break
            if command in (_DO, _WILL):
                asks.append((command, data[i + 2]))
            i += 3
        elif command == _SB:
            end = data.find(bytes((_IAC, _SE)), i + 2)
            if end < 0:
                if len(data) - i > _MAX_SUBNEGOTIATION:
                    return bytes(text), asks, b""  # it is not going to end
                break
            i = end + 2
        else:
            i += 2
    return bytes(text), asks, data[i:]


def _note_telnet(service: Service, opening: bytes, text: bytes) -> None:
    service.banner = _clean(text, MAX_BANNER) or service.banner
    product = _product_from_text(text.decode("utf-8", errors="replace"))
    if not product and opening.startswith(_BUSYBOX_TELNETD):
        product = "BusyBox telnetd"
    if product:
        service.product = product
    if _LOGIN_PROMPT.search(text[-64:]):
        service.auth = "required"


async def _telnet(conn: _Conn, end: float) -> None:
    """Refuse every option the server asks about, so it gets on with its banner."""
    service = conn.service
    loop = asyncio.get_running_loop()
    opening = bytearray()
    text = bytearray()
    rest = b""
    answered: set[tuple[int, int]] = set()
    try:
        while True:
            fresh = bytes(conn.buffer)
            conn.buffer.clear()
            opening += fresh[: len(_BUSYBOX_TELNETD) - len(opening)]
            visible, asks, rest = _telnet_split(rest + fresh)
            text += visible
            if opening[:1] == bytes((_IAC,)):
                service.name = "telnet"
            reply = bytearray()
            for command, option in asks:
                if (command, option) not in answered:
                    answered.add((command, option))
                    reply += bytes((_IAC, _WONT if command == _DO else _DONT, option))
            if reply:
                await conn.send(bytes(reply))
            if len(text) >= _MAX_GREETING or _PROMPT.search(text[-64:]):
                break
            left = end - loop.time()
            if left <= 0 or not await conn.fill(left):
                break
    except TimeoutError:
        pass
    finally:
        _note_telnet(service, bytes(opening), bytes(text[:_MAX_GREETING]))


async def _vnc(conn: _Conn) -> None:
    """Read the security types on offer and hang up before choosing one."""
    service = conn.service
    hello = await conn.exactly(12)
    match = _RFB.fullmatch(hello)
    if not match:
        _note_greeting(service, hello + conn.buffer)
        return
    service.name = "vnc"
    service.banner = _clean(hello, MAX_BANNER)
    version = (int(match.group(1)), int(match.group(2)))
    # Servers that report anything older than 3.7 get treated as 3.3, as the
    # RFB spec says, and Apple's 3.889 as 3.8.
    if version >= (3, 8):
        reply = (3, 8)
    elif version >= (3, 7):
        reply = (3, 7)
    else:
        reply = (3, 3)
    await conn.send(b"RFB %03d.%03d\n" % reply)
    if reply == (3, 3):
        (chosen,) = struct.unpack(">I", await conn.exactly(4))
        offered = [chosen] if chosen else []
    else:
        count = (await conn.exactly(1))[0]
        offered = list(await conn.exactly(count))
    if not offered:
        return  # a refusal with a reason; it says nothing about authentication
    names = dict.fromkeys(_VNC_SECURITY.get(kind, f"type {kind}") for kind in offered)
    security = _clean(",".join(names), MAX_FACT)
    if security:
        service.facts["security"] = security
    if 1 in offered:
        service.auth = "none"
    elif all(kind in _VNC_SECRET for kind in offered):
        service.auth = "required"
    # Otherwise only wrappers were offered (TLS, VeNCrypt, Tight, SASL), and
    # what they carry inside is not known without picking one.


async def _rsync(conn: _Conn) -> None:
    service = conn.service
    hello = await conn.line()
    match = _RSYNCD.match(hello)
    if not match:
        _note_greeting(service, hello)
        return
    service.name = "rsync"
    service.banner = _clean(hello, MAX_BANNER)
    await conn.send(match.group(0) + b"\n#list\n")
    # Module lines are "name<tab>comment". A message of the day may come first.
    modules = 0
    for _ in range(_RSYNC_LINES):
        try:
            entry = await conn.line()
        except EOFError:
            break  # servers older than protocol 25 just hang up
        if entry.startswith((b"@RSYNCD: EXIT", b"@ERROR")):
            break
        if b"\t" in entry and not entry.startswith(b"@"):
            modules += 1
    service.facts["modules"] = str(modules)


def _mysql_like(first: bytes) -> bool:
    """A MySQL packet header followed by a greeting (10) or an error (0xff)."""
    return (
        len(first) >= 5
        and first[3] == 0
        and first[4] in (0x0A, 0xFF)
        and 0 < int.from_bytes(first[:3], "little") <= 4096
    )


def _mysql_product(version: str) -> str | None:
    """Product from the version in a MySQL greeting.

    "8.0.36-0ubuntu0.22.04.1" is "MySQL 8.0.36", "11.4.2-MariaDB" is "MariaDB 11.4.2".
    """
    if "mariadb" in version.lower():
        # MariaDB puts a fake "5.5.5-" in front for old clients.
        match = _VERSION_NUMBER.match(version.removeprefix("5.5.5-"))
        return f"MariaDB {match.group(0)}" if match else "MariaDB"
    match = _VERSION_NUMBER.match(version)
    return f"MySQL {match.group(0)}" if match else None


async def _mysql(conn: _Conn) -> None:
    service = conn.service
    head = await conn.exactly(4)
    length = int.from_bytes(head[:3], "little")
    if head[3] != 0 or not 0 < length <= 4096:
        _note_greeting(service, head + conn.buffer)
        return
    payload = await conn.exactly(length)
    if payload[0] == 0x0A:
        version = _clean(payload[1:].split(b"\0", 1)[0][:64], MAX_PRODUCT)
        if version and version[0].isdigit():
            service.name = "mysql"
            service.banner = version
            service.product = _mysql_product(version)
    elif payload[0] == 0xFF:
        # "Host ... is not allowed to connect", "Too many connections"
        message = payload[3:]
        if message.startswith(b"#"):
            message = message[6:]  # SQL state marker and code
        text = _clean(message, MAX_BANNER)
        if text:
            service.name = "mysql"
            service.banner = text


async def _greeting(job: _Job, kind: str) -> bool:
    """Hear out a service that may speak first. True when it stayed open and silent."""
    loop = asyncio.get_running_loop()
    async with _connect(job) as conn:
        wait = job.left() if kind in _PATIENT else min(LISTEN, job.left())
        end = loop.time() + wait
        try:
            if not await conn.fill(wait):
                return False
        except TimeoutError:
            return True
        first = bytes(conn.buffer[:8])
        if kind == "vnc" or first.startswith(b"RFB "):
            await _vnc(conn)
        elif kind == "rsync" or first.startswith(b"@RSYNCD:"):
            await _rsync(conn)
        elif kind == "mysql" or _mysql_like(first):
            await _mysql(conn)
        elif first[0] == _IAC or (kind == "telnet" and not first.startswith(b"SSH-")):
            await _telnet(conn, end)
        else:
            await _text_greeting(conn, end)
    return False


# Services that wait for the client


def _url_host(ip: str, *, zone: bool = True) -> str:
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return ip
    text = ip if zone else str(type(address)(int(address)))
    return "[" + text.replace("%", "%25") + "]"


def _rtsp_request(method: str, url: str, sequence: int) -> bytes:
    lines = [f"{method} {url} RTSP/1.0", f"CSeq: {sequence}", f"User-Agent: {http.USER_AGENT}"]
    if method == "DESCRIBE":
        lines.append("Accept: application/sdp")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


async def _rtsp_answer(conn: _Conn) -> tuple[int, dict[str, str]] | None:
    line = b""
    for _ in range(4):  # blank lines left over from an earlier answer
        line = await conn.line()
        if line.strip():
            break
    match = _RTSP_STATUS.match(line)
    if not match:
        return None
    headers: dict[str, str] = {}
    for _ in range(_MAX_HEADERS):
        line = await conn.line()
        if not line.strip():
            break
        name, colon, value = line.partition(b":")
        if colon:
            headers[name.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
    return int(match.group(1)), headers


async def _rtsp(conn: _Conn) -> None:
    """OPTIONS, then DESCRIBE without credentials: a 200 hands out the stream to anyone."""
    service = conn.service
    url = f"rtsp://{_url_host(conn.job.ip, zone=False)}:{conn.job.port}/"
    await conn.send(_rtsp_request("OPTIONS", url, 1))
    answer = await _rtsp_answer(conn)
    if answer is None:
        return
    service.name = "rtsp"
    _, headers = answer
    service.product = _clean(headers.get("server"), MAX_PRODUCT)
    length = headers.get("content-length", "0").strip().encode("latin-1")
    if not _CONTENT_LENGTH.fullmatch(length) or int(length) > _RTSP_BODY:
        return
    await conn.exactly(int(length))

    await conn.send(_rtsp_request("DESCRIBE", url, 2))
    answer = await _rtsp_answer(conn)
    if answer is None:
        return
    status, headers = answer
    service.product = service.product or _clean(headers.get("server"), MAX_PRODUCT)
    service.facts["describe"] = str(status)
    if status == 200:
        service.auth = "none"
    elif status == 401:
        service.auth = "required"


async def _redis(conn: _Conn) -> None:
    await conn.send(b"PING\r\n")
    reply = (await conn.line()).strip()
    if reply.startswith(b"+PONG"):
        conn.service.name = "redis"
        conn.service.auth = "none"
    elif reply.startswith(b"-") and _REDIS_LOCKED.search(reply):
        conn.service.name = "redis"
        conn.service.auth = "required"


async def _memcached(conn: _Conn) -> None:
    await conn.send(b"version\r\n")
    reply = (await conn.line()).strip()
    match = _MEMCACHED_VERSION.fullmatch(reply)
    if match:
        conn.service.name = "memcached"
        conn.service.banner = _clean(reply, MAX_BANNER)
        conn.service.product = _clean(b"memcached " + match.group(1), MAX_PRODUCT)
        conn.service.auth = "none"


async def _mqtt(conn: _Conn) -> None:
    """CONNECT without a user name or password, read CONNACK, DISCONNECT. Nothing else."""
    client = f"hearthscan{random.randrange(1_000_000):06d}".encode()
    # Protocol "MQTT", level 4 (3.1.1), clean session, keep alive 60 s.
    body = b"\x00\x04MQTT\x04\x02\x00\x3c" + struct.pack(">H", len(client)) + client
    await conn.send(bytes((0x10, len(body))) + body)
    ack = await conn.exactly(4)
    if ack[:2] != b"\x20\x02":
        return
    code = ack[3]
    conn.service.name = "mqtt"
    conn.service.facts["connack"] = str(code)
    if code == 0:
        conn.service.auth = "none"
    elif code in (4, 5):  # bad user name or password, not authorized
        conn.service.auth = "required"
    with contextlib.suppress(OSError):
        await conn.send(b"\xe0\x00")


def _adb_message(command: int, arg0: int, arg1: int, payload: bytes) -> bytes:
    checksum = sum(payload) & 0xFFFFFFFF
    magic = command ^ 0xFFFFFFFF
    return struct.pack("<6I", command, arg0, arg1, len(payload), checksum, magic) + payload


def _adb_model(banner: bytes) -> str | None:
    """The model from "device::ro.product.name=x;ro.product.model=y;features=..."."""
    _, _, listing = banner.decode("utf-8", errors="replace").partition("::")
    props = {}
    for item in listing.split(";"):
        key, _, value = item.partition("=")
        props[key.strip()] = value
    return _clean(props.get("ro.product.model") or props.get("ro.product.name"), MAX_PRODUCT)


async def _adb(conn: _Conn) -> None:
    """Send CNXN and see whether the device answers in kind or asks us to authenticate.

    It stops there. Answering AUTH with a key would put an "Allow USB
    debugging?" prompt on the device's screen.
    """
    await conn.send(_adb_message(_ADB_CNXN, _ADB_VERSION, _ADB_MAXDATA, b"host::\0"))
    command, _, _, length, _, magic = struct.unpack("<6I", await conn.exactly(24))
    if magic != command ^ 0xFFFFFFFF:
        return
    service = conn.service
    if command == _ADB_CNXN:
        service.name = "adb"
        service.auth = "none"
        service.facts["state"] = "device"
        service.product = _adb_model(await conn.exactly(min(length, _ADB_BANNER)))
    elif command in (_ADB_AUTH, _ADB_STLS):
        # STLS: wireless debugging, which needs pairing first.
        service.name = "adb"
        service.auth = "required"
        service.facts["state"] = "unauthorized"


async def _smb(conn: _Conn) -> None:
    """Offer only SMB1 and read the header of the answer. No session setup."""
    service = conn.service
    try:
        await conn.send(_SMB1_NEGOTIATE)
        session = await conn.exactly(4)
        reply = await conn.exactly(min(int.from_bytes(session[1:], "big"), 64))
    except (EOFError, ConnectionError):
        # Windows and Samba hang up on an SMB1 negotiate when SMB1 is off.
        service.facts["smb1"] = "no"
        return
    if reply.startswith(b"\xfeSMB"):
        service.facts["smb1"] = "no"
    elif reply.startswith(b"\xffSMB") and len(reply) >= 32:
        status = int.from_bytes(reply[5:9], "little")
        # The first word is the index of the chosen dialect; 0xffff means none.
        chosen = len(reply) >= 35 and reply[32] > 0 and reply[33:35] != b"\xff\xff"
        accepted = reply[4] == 0x72 and status == 0 and chosen
        service.facts["smb1"] = "yes" if accepted else "no"


async def _socks(conn: _Conn) -> None:
    """Offer SOCKS5 without authentication. No CONNECT follows."""
    await conn.send(b"\x05\x01\x00")
    reply = await conn.exactly(2)
    if reply[0] != 5:
        return
    conn.service.name = "socks"
    conn.service.facts["version"] = "5"
    conn.service.auth = "none" if reply[1] == 0 else "required"


async def _postgresql(conn: _Conn) -> None:
    await conn.send(_POSTGRES_SSL_REQUEST)
    reply = await conn.exactly(1)
    if reply in (b"S", b"N"):
        conn.service.name = "postgresql"
        conn.service.facts["ssl"] = reply.decode()


_ASKERS: dict[str, Callable[[_Conn], Awaitable[None]]] = {
    "rtsp": _rtsp,
    "redis": _redis,
    "memcached": _memcached,
    "mqtt": _mqtt,
    "adb": _adb,
    "smb": _smb,
    "socks": _socks,
    "postgresql": _postgresql,
}


# Web


async def _get(job: _Job, path: str, tls: bool) -> http.Response:
    left = job.left()
    if left <= 0:
        raise TimeoutError
    url = f"{'https' if tls else 'http'}://{_url_host(job.ip)}:{job.port}{path}"
    return await http.fetch(url, timeout=left, limit=_BODY_LIMIT)


async def _get_either(job: _Job, path: str, tls: bool) -> http.Response:
    """GET `path`, switching once between plain HTTP and TLS when the port wants the other."""
    try:
        response = await _get(job, path, tls)
    except OSError as exc:
        if isinstance(exc, TimeoutError):
            raise
        # A TLS alert, garbage or a hang-up in answer to plain HTTP means the
        # port wants TLS. A failed handshake means it does not.
        return await _get(job, path, not tls)
    if not tls and _TLS_HINT.search(response.body[:4096]):
        with contextlib.suppress(OSError):
            return await _get(job, path, True)
    return response


def _title(markup: str) -> str | None:
    """The first <title>, entities decoded and whitespace collapsed."""
    start = _TITLE_START.search(markup)
    if not start:
        return None
    end = _TITLE_END.search(markup, start.end())
    if not end:
        return None
    return _clean(html.unescape(markup[start.end() : end.start()][:4096]), MAX_TITLE)


def _same_origin(response: http.Response, location: str) -> str | None:
    """The path and query of `location` when it stays on the same scheme, host and port."""
    location = location.strip()
    if not location or len(location) > 2048 or any(ord(ch) < 0x21 for ch in location):
        return None
    try:
        base = urllib.parse.urlsplit(response.url)
        target = urllib.parse.urlsplit(urllib.parse.urljoin(response.url, location))
        if target.scheme != base.scheme or not target.hostname or not base.hostname:
            return None
        default = _DEFAULT_PORTS[base.scheme]
        if (target.port or default) != (base.port or default):
            return None
        here = ipaddress.ip_address(urllib.parse.unquote(base.hostname))
        there = ipaddress.ip_address(urllib.parse.unquote(target.hostname))
    except ValueError:
        return None
    if here != there:
        return None
    path = target.path or "/"
    if target.query:
        path = f"{path}?{target.query}"
    return path if path != (base.path or "/") else None


def _next_page(
    service: Service, response: http.Response, text: str, has_password: bool
) -> str | None:
    """Where the login page may be: a redirect or a meta refresh to the same origin."""
    if response.status in _REDIRECTS:
        location = response.headers.get("location", "")
        redirect = _clean(location, MAX_FACT)
        if redirect:
            service.facts["redirect"] = redirect
    elif response.status == 200 and not has_password:
        refresh = _META_REFRESH.search(text)
        target = _REFRESH_URL.search(refresh.group(0)) if refresh else None
        if not target:
            return None
        location = html.unescape(target.group(1))
    else:
        return None
    return _same_origin(response, location)


def _note_http(service: Service, response: http.Response) -> None:
    # Ports named after what runs on them (ipp, webmin, plex) keep that name.
    if service.name in ("", "http", "https"):
        service.name = "https" if response.tls else "http"
    service.tls = response.tls
    service.tls_version = _clean(response.tls_version, 16) if response.tls else None
    service.facts["status"] = str(response.status)
    server = _clean(response.headers.get("server"), MAX_PRODUCT)
    if server:
        service.product = server


def _note_page(service: Service, response: http.Response, text: str, has_password: bool) -> None:
    title = _title(text)
    if title:
        service.title = title
    login = None
    if response.status == 401:
        challenge = response.headers.get("www-authenticate", "")
        if _BASIC.search(challenge):
            login = "basic"
        elif _DIGEST.search(challenge):
            login = "digest"
        service.auth = "required"
    elif has_password:
        login = "form"
        service.auth = "required"
    if login:
        service.facts["login"] = login


async def _web(job: _Job, *, tls: bool) -> None:
    service = job.service
    first = await _get_either(job, "/", tls)
    _note_http(service, first)
    text = first.text()
    # Searched once per page: a crafted page makes this regex slow-ish.
    has_password = bool(_PASSWORD_INPUT.search(text))
    _note_page(service, first, text, has_password)
    path = _next_page(service, first, text, has_password)
    if path:
        with contextlib.suppress(OSError):
            page = await _get(job, path, first.tls)
            text = page.text()
            _note_page(service, page, text, bool(_PASSWORD_INPUT.search(text)))


def _json(response: http.Response) -> dict | None:
    if response.truncated:
        return None
    try:
        document = json.loads(response.body)
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


async def _elasticsearch(job: _Job) -> None:
    service = job.service
    response = await _get_either(job, "/", False)
    _note_http(service, response)
    if response.status in (401, 403):
        service.auth = "required"
        return
    document = _json(response)
    if response.status != 200 or document is None:
        return
    version = document.get("version")
    version = version if isinstance(version, dict) else {}
    number = version.get("number")
    if "cluster_name" not in document and not isinstance(number, str):
        return
    flavor = "OpenSearch" if version.get("distribution") == "opensearch" else "Elasticsearch"
    service.name = "elasticsearch"
    service.auth = "none"
    product = f"{flavor} {number}" if isinstance(number, str) else flavor
    service.product = _clean(product, MAX_PRODUCT)


async def _docker(job: _Job) -> None:
    service = job.service
    response = await _get_either(job, "/version", False)
    _note_http(service, response)
    document = _json(response)
    if response.status != 200 or document is None or "ApiVersion" not in document:
        return
    version = document.get("Version")
    product = f"Docker {version}" if isinstance(version, str) else "Docker"
    service.name = "docker"
    service.auth = "none"
    service.product = _clean(product, MAX_PRODUCT)


# Running the probes


async def _run(job: _Job, kind: str) -> None:
    if kind in ("web", "tls-web"):
        await _web(job, tls=kind == "tls-web")
    elif kind == "elasticsearch":
        await _elasticsearch(job)
    elif kind == "docker":
        await _docker(job)
    elif kind in _ASKERS:
        async with _connect(job) as conn:
            await _ASKERS[kind](conn)
    else:
        await _greeting(job, kind)


def _check_timeout(timeout: float) -> None:
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"timeout must be a positive number of seconds, not {timeout!r}")


def _check_port(port: int) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"not a valid port: {port!r}")


def _address(ip: str) -> str:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"not an IP address: {ip!r}") from None
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if not is_local(address):
        raise ScopeError(f"{address} is not on a private network")
    return str(address)


async def probe(ip: str, port: int, *, timeout: float = 2.0) -> Service:
    """Find out what listens on an open TCP port of a local device.

    Returns what the service gave away within `timeout` seconds, and at least
    Service(port, name=...) with the usual name for the port. Never raises for
    what the network or the device does. Raises ValueError for bad arguments
    and ScopeError for addresses outside the local network.
    """
    _check_timeout(timeout)
    _check_port(port)
    address = _address(ip)
    service = Service(port, name=SERVICE_NAMES.get(port, ""))
    kind = PROBES.get(port, "unknown")
    if kind == "none":
        return service
    job = _Job(address, port, service, asyncio.get_running_loop().time() + timeout)
    # The probes fill in `service` as they go, so a timeout keeps what they found.
    with contextlib.suppress(*_TROUBLE):
        await _within(_run(job, kind), timeout)
    return service


async def probe_all(
    targets: Iterable[tuple[str, int]],
    *,
    timeout: float = 2.0,
    concurrency: int = 32,
    on_done: Callable[[str, Service], None] | None = None,
) -> dict[tuple[str, int], Service]:
    """Probe every (ip, port) pair, `concurrency` at a time. Results come in input order.

    Checks all targets before probing any. `on_done(ip, service)` is called as
    each probe finishes; if it raises, the other probes are cancelled.
    """
    _check_timeout(timeout)
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
        raise ValueError(f"concurrency must be a positive whole number, not {concurrency!r}")
    jobs = list(dict.fromkeys((ip, port) for ip, port in targets))
    for ip, port in jobs:
        _check_port(port)
        _address(ip)

    results: dict[tuple[str, int], Service] = {}
    pending = iter(jobs)

    async def worker() -> None:
        # Workers share one iterator, so each pair is handed out exactly once.
        for ip, port in pending:
            service = await probe(ip, port, timeout=timeout)
            results[ip, port] = service
            if on_done:
                on_done(ip, service)

    workers = [asyncio.ensure_future(worker()) for _ in range(min(concurrency, len(jobs)))]
    try:
        await asyncio.gather(*workers)
    except BaseException:
        # A callback blew up or we were cancelled. Don't leave the others running.
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise
    return {job: results[job] for job in jobs}
