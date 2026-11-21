"""A small HTTP/1.1 client for devices on the local network.

It only talks to literal local IP addresses: no DNS, no proxies, no redirects.
"""

from __future__ import annotations

import asyncio
import codecs
import contextlib
import functools
import ipaddress
import math
import re
import ssl
import urllib.parse
from dataclasses import dataclass

from . import __version__
from .scope import ScopeError, is_local

USER_AGENT = f"Hearthscan/{__version__}"

MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 100
# Some devices send "100 Continue" before the real answer, asked for or not.
_MAX_INTERIM = 5
_MAX_REASON = 200
_READ_SIZE = 64 * 1024

_STATUS_LINE = re.compile(r"HTTP/1\.\d[ \t]+([1-5]\d\d)(?:[ \t]+(.*))?")
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_CONTENT_LENGTH = re.compile(r"[0-9]{1,18}")
_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}")
_CHARSET = re.compile(r"""charset\s*=\s*["']?([^\s"';,]+)""", re.IGNORECASE)
# Everything a request target may carry as is. The rest gets percent-encoded.
_TARGET_SAFE = "/?:@!$&'()*+,;=%[]"
_DEFAULT_PORTS = {"http": 80, "https": 443}
_RESERVED_HEADERS = {"connection", "content-length", "transfer-encoding"}


class HttpError(OSError):
    """The device answered with something that is not valid HTTP."""


@dataclass(slots=True)
class Response:
    url: str
    status: int
    reason: str
    headers: dict[str, str]  # lowercase names, repeated headers joined with ", "
    body: bytes
    truncated: bool = False  # the body stopped short: at the limit, or the device hung up
    tls: bool = False
    tls_version: str | None = None  # as OpenSSL names it: "TLSv1", "TLSv1.2", ...
    tls_cipher: str | None = None  # the OpenSSL name of the negotiated suite

    def text(self) -> str:
        """The body as text, in the charset Content-Type names, else UTF-8."""
        match = _CHARSET.search(self.headers.get("content-type", ""))
        codec = _document_codec(match.group(1)) if match else None
        return self.body.decode(codec or "utf-8", errors="replace")


@dataclass(slots=True)
class _Request:
    host: str  # the address to connect to, IPv6 zone included
    port: int
    tls: bool
    server_name: str  # the address without a zone, for TLS
    data: bytes
    head_only: bool


async def fetch(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = 3.0,
    limit: int = 256 * 1024,
) -> Response:
    """Send one request to a device on the local network and read the answer.

    Raises ValueError for a URL we will not fetch, TimeoutError when there is
    no complete answer within `timeout` seconds, and OSError (HttpError for
    broken HTTP) when the connection fails. Reads at most `limit` body bytes.
    """
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"timeout must be a positive number of seconds, not {timeout!r}")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise ValueError(f"limit must be a number of bytes, not {limit!r}")
    request = _prepare(url, method, headers, body)

    # The same pattern as ports._connect_within, for the same reason: no
    # asyncio.wait_for, so a cancellation is never lost.
    attempt = asyncio.ensure_future(_exchange(url, request, limit))
    try:
        await asyncio.wait({attempt}, timeout=timeout)
    finally:
        if not attempt.done():
            attempt.cancel()
            await asyncio.wait({attempt})
        elif not attempt.cancelled():
            attempt.exception()  # mark it as seen, even when we are unwinding
    if attempt.cancelled():
        raise TimeoutError(f"no complete answer from {url} within {timeout:g} s")
    return attempt.result()


def _prepare(url: str, method: str, headers: dict[str, str] | None, body: bytes | None) -> _Request:
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError(f"only http and https URLs can be fetched, not {url!r}")
    if "@" in parts.netloc:
        raise ValueError("credentials in URLs are not supported")  # and not repeated here
    if not parts.hostname:
        raise ValueError(f"no host in {url!r}")
    # A zone in a URL is written fe80::1%25eth0.
    host = urllib.parse.unquote(parts.hostname)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"{host!r} is not an IP address; fetch does not look up names") from None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not is_local(ip):
        raise ScopeError(f"{ip} is not on a private network")

    default_port = _DEFAULT_PORTS[scheme]
    port = parts.port  # raises ValueError when out of range
    if port is None:
        port = default_port
    elif port == 0:
        raise ValueError(f"port 0 in {url!r}")

    if not isinstance(method, str) or not _TOKEN.fullmatch(method):
        raise ValueError(f"not a valid HTTP method: {method!r}")

    bare = str(type(ip)(int(ip)))  # without the zone
    host_field = f"[{bare}]" if ip.version == 6 else bare
    if port != default_port:
        host_field = f"{host_field}:{port}"

    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    target = urllib.parse.quote(target, safe=_TARGET_SAFE)

    fields = {
        "host": ("Host", host_field),
        "user-agent": ("User-Agent", USER_AGENT),
        "accept": ("Accept", "*/*"),
    }
    for name, value in (headers or {}).items():
        if not isinstance(name, str) or not _TOKEN.fullmatch(name):
            raise ValueError(f"not a valid header name: {name!r}")
        if not isinstance(value, str) or any(ch in value for ch in "\r\n\0"):
            raise ValueError(f"not a valid value for {name}: {value!r}")
        if name.lower() in _RESERVED_HEADERS:
            raise ValueError(f"fetch sets {name} itself")
        fields[name.lower()] = (name, value)
    fields["connection"] = ("Connection", "close")
    if body is not None:
        body = bytes(body)
        fields["content-length"] = ("Content-Length", str(len(body)))

    lines = [f"{method} {target} HTTP/1.1", *(f"{n}: {v}" for n, v in fields.values())]
    try:
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    except UnicodeEncodeError:
        raise ValueError("header values must be Latin-1 text") from None

    return _Request(
        host=str(ip),
        port=port,
        tls=scheme == "https",
        server_name=bare,
        data=head + (body or b""),
        head_only=method == "HEAD",
    )


# Python also knows codecs like punycode or the zlib transforms. A device
# naming one of those as its charset gets UTF-8 instead: some are very slow
# on crafted input, and none of them is how a web page is written.
_DOCUMENT_CODECS = frozenset(
    {
        "ascii",
        "big5",
        "big5hkscs",
        "cp932",
        "cp949",
        "cp950",
        "euc_jis_2004",
        "euc_jp",
        "euc_kr",
        "gb18030",
        "gb2312",
        "gbk",
        "iso2022_jp",
        "iso2022_kr",
        "shift_jis",
        "utf-8",
        "utf-8-sig",
        "utf-16",
        "utf-16-be",
        "utf-16-le",
        "utf-32",
        "utf-32-be",
        "utf-32-le",
    }
)
_DOCUMENT_PREFIXES = ("iso8859-", "cp12", "cp8", "koi8-", "mac-")


def _document_codec(label: str) -> str | None:
    try:
        name = codecs.lookup(label.strip()).name
    except (LookupError, ValueError):
        return None
    if name in _DOCUMENT_CODECS or name.startswith(_DOCUMENT_PREFIXES):
        return name
    return None


@functools.cache
def _tls_context() -> ssl.SSLContext:
    # Home devices use self-signed certificates, so there is nothing to check
    # them against. The connection is encrypted but not authenticated.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Older devices offer only TLS 1.0 or 1.1, or only RSA key exchange and
    # CBC suites. With no authentication, refusing them protects nothing.
    # Python warns about TLSv1 as a minimum but not about MINIMUM_SUPPORTED,
    # which leaves the limit to the security level.
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    # OpenSSL 3 also refuses servers that predate secure renegotiation (RFC
    # 5746), which old printers and cameras do. OpenSSL 1.1.1 allowed them.
    context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    with contextlib.suppress(ssl.SSLError):
        # Anonymous suites stay out: a device must still show a certificate.
        context.set_ciphers("ALL:!aNULL:@SECLEVEL=0")
    return context


def _tls_details(writer: asyncio.StreamWriter) -> tuple[str | None, str | None]:
    tls = writer.get_extra_info("ssl_object")
    if tls is None:
        return None, None
    cipher = tls.cipher()
    return tls.version(), cipher[0] if cipher else None


async def _exchange(url: str, request: _Request, limit: int) -> Response:
    extra = {"ssl": _tls_context(), "server_hostname": request.server_name} if request.tls else {}
    reader, writer = await asyncio.open_connection(
        request.host, request.port, limit=MAX_HEADER_BYTES, **extra
    )
    try:
        tls_version, tls_cipher = _tls_details(writer)
        writer.write(request.data)
        await writer.drain()
        status, reason, headers = await _read_final_head(reader)
        body = bytearray()
        truncated = False
        if not (request.head_only or status < 200 or status in (204, 304)):
            try:
                truncated = await _read_body(reader, headers, body, limit)
            except (ConnectionResetError, ConnectionAbortedError):
                truncated = True
        return Response(
            url=url,
            status=status,
            reason=reason,
            headers=headers,
            body=bytes(body),
            truncated=truncated,
            tls=request.tls,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
        )
    finally:
        # abort() and not close(): close() first flushes whatever the device
        # has not read yet, and over TLS it waits for the device to answer the
        # goodbye. Either can take as long as the device likes.
        writer.transport.abort()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    """One line, newline included. Shorter, without the newline, at the end of the stream."""
    try:
        return await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        return exc.partial
    except asyncio.LimitOverrunError:
        raise HttpError(f"line longer than {MAX_HEADER_BYTES} bytes") from None


async def _read_final_head(reader: asyncio.StreamReader) -> tuple[int, str, dict[str, str]]:
    for _ in range(_MAX_INTERIM + 1):
        status, reason, headers = await _read_head(reader)
        # 101 means the protocol changes, so there is nothing more to read.
        if status >= 200 or status == 101:
            return status, reason, headers
    raise HttpError("too many interim responses")


async def _read_head(reader: asyncio.StreamReader) -> tuple[int, str, dict[str, str]]:
    lines: list[bytes] = []
    size = 0
    while True:
        line = await _read_line(reader)
        size += len(line)
        if size > MAX_HEADER_BYTES:
            raise HttpError(f"header section is over {MAX_HEADER_BYTES} bytes")
        if not line.endswith(b"\n"):
            if not lines and not line:
                raise HttpError("connection closed without an answer")
            raise HttpError("connection closed in the middle of the headers")
        if line.strip(b"\r\n"):
            lines.append(line)
            if len(lines) > MAX_HEADERS + 1:
                raise HttpError(f"more than {MAX_HEADERS} headers")
        elif lines:
            break
        # Blank lines before the status line are left over from earlier answers. Skip them.
    status, reason = _parse_status(lines[0])
    return status, reason, _parse_headers(lines[1:])


def _parse_status(line: bytes) -> tuple[int, str]:
    text = line.decode("latin-1").rstrip("\r\n")
    match = _STATUS_LINE.fullmatch(text)
    if not match:
        raise HttpError(f"malformed status line: {text[:80]!r}")
    return int(match.group(1)), (match.group(2) or "").strip()[:_MAX_REASON]


def _parse_headers(lines: list[bytes]) -> dict[str, str]:
    headers: dict[str, str] = {}
    last = None
    for line in lines:
        text = line.decode("latin-1").rstrip("\r\n")
        if text[0] in " \t":
            # Obsolete line folding: the value goes on from the line before.
            if last is None:
                raise HttpError("header section starts with a continuation line")
            headers[last] = f"{headers[last]} {text.strip()}"
            continue
        name, colon, value = text.partition(":")
        name = name.rstrip(" \t")
        if not colon or not _TOKEN.fullmatch(name):
            raise HttpError(f"malformed header line: {text[:80]!r}")
        key = name.lower()
        value = value.strip(" \t")
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
        last = key
    return headers


def _content_length(headers: dict[str, str]) -> int | None:
    value = headers.get("content-length")
    if value is None:
        return None
    # "5, 5" happens when a header is repeated by a proxy. Different numbers do not.
    values = {part.strip() for part in value.split(",")}
    if len(values) != 1:
        raise HttpError(f"conflicting Content-Length: {value[:80]!r}")
    (length,) = values
    if not _CONTENT_LENGTH.fullmatch(length):
        raise HttpError(f"bad Content-Length: {length[:80]!r}")
    return int(length)


async def _read_body(
    reader: asyncio.StreamReader, headers: dict[str, str], body: bytearray, limit: int
) -> bool:
    """Read the body into `body`. Returns True when it stopped short."""
    encoding = headers.get("transfer-encoding")
    if encoding is not None:
        codings = [c.strip().lower() for c in encoding.split(",")]
        if codings[-1] == "chunked":
            return await _read_chunked(reader, body, limit)
        # Any other transfer coding runs until the connection closes.
        return await _read_until_close(reader, body, limit)
    length = _content_length(headers)
    if length is None:
        return await _read_until_close(reader, body, limit)
    complete = await _read_into(reader, body, min(length, limit))
    return not complete or length > limit


async def _read_into(reader: asyncio.StreamReader, body: bytearray, count: int) -> bool:
    """Append `count` bytes. Returns False if the connection closed first."""
    while count > 0:
        data = await reader.read(min(count, _READ_SIZE))
        if not data:
            return False
        body += data
        count -= len(data)
    return True


async def _read_until_close(reader: asyncio.StreamReader, body: bytearray, limit: int) -> bool:
    # One byte past the limit is enough to know there was more.
    await _read_into(reader, body, limit + 1 - len(body))
    if len(body) > limit:
        del body[limit:]
        return True
    return False


async def _read_chunked(reader: asyncio.StreamReader, body: bytearray, limit: int) -> bool:
    while True:
        line = await _read_line(reader)
        if not line.endswith(b"\n"):
            return True
        size_text = line.split(b";", 1)[0].strip()  # drop chunk extensions
        if not _CHUNK_SIZE.fullmatch(size_text):
            raise HttpError(f"bad chunk size: {line[:40]!r}")
        size = int(size_text, 16)
        if size == 0:
            await _skip_trailers(reader)
            return False
        room = limit - len(body)
        if size > room:
            await _read_into(reader, body, room)
            return True
        if not await _read_into(reader, body, size):
            return True
        end = await _read_line(reader)
        if end.strip():
            raise HttpError("chunk is longer than its size")
        if not end.endswith(b"\n"):
            return True


async def _skip_trailers(reader: asyncio.StreamReader) -> None:
    # The body is complete by now, so junk here is not worth an error.
    size = 0
    for _ in range(MAX_HEADERS + 1):
        line = await _read_line(reader)
        size += len(line)
        if not line.strip() or size > MAX_HEADER_BYTES:
            return
