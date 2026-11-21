import asyncio
import contextlib
import re
import socket
import ssl
import time
import warnings
from pathlib import Path

import pytest

from hearthscan import __version__, http
from hearthscan.http import MAX_HEADER_BYTES, HttpError, Response, fetch
from hearthscan.scope import ScopeError

CERT = Path(__file__).parent / "data" / "http_selfsigned.pem"
RSA_CERT = Path(__file__).parent / "data" / "http_rsa.pem"


def has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
    except OSError:
        return False
    return True


async def read_request(reader: asyncio.StreamReader) -> bytes:
    head = await reader.readuntil(b"\r\n\r\n")
    length = re.search(rb"(?im)^content-length: *(\d+)", head)
    body = await reader.readexactly(int(length.group(1))) if length else b""
    return head + body


async def hold(reader: asyncio.StreamReader) -> None:
    """Keep the connection open until the client goes away."""
    with contextlib.suppress(ConnectionError):
        await reader.read()


def keep_open(data: bytes):
    async def answer(reader, writer):
        writer.write(data)
        await writer.drain()
        await hold(reader)

    return answer


def roundtrip(answer, path="/", *, host="127.0.0.1", tls=False, **kwargs):
    """Fetch from a one-shot server on loopback. Returns (response, request).

    `answer` is what the server sends before closing, or a coroutine function
    taking (reader, writer) for anything fancier. `tls` may be the server's
    SSLContext instead of True.
    """
    requests = []

    async def handle(reader, writer):
        try:
            with contextlib.suppress(ConnectionError, asyncio.IncompleteReadError):
                requests.append(await read_request(reader))
                if callable(answer):
                    await answer(reader, writer)
                else:
                    writer.write(answer)
                    await writer.drain()
        finally:
            writer.close()

    async def main():
        context = None
        if isinstance(tls, ssl.SSLContext):
            context = tls
        elif tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(CERT)
        server = await asyncio.start_server(handle, host, 0, ssl=context)
        port = server.sockets[0].getsockname()[1]
        name = f"[{host}]" if ":" in host else host
        url = f"{'https' if tls else 'http'}://{name}:{port}{path}"
        async with server:
            return await fetch(url, **kwargs)

    response = asyncio.run(main())
    return response, requests[0] if requests else None


def test_content_length_body_and_headers():
    answer = keep_open(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"X-Thing: one\r\n"
        b"x-thing: two\r\n"
        b"Content-Length: 5\r\n"
        b"\r\n"
        b"hello"
    )
    response, _ = roundtrip(answer)
    assert response.status == 200
    assert response.reason == "OK"
    assert response.headers["content-type"] == "text/plain"
    assert response.headers["x-thing"] == "one, two"
    assert response.body == b"hello"
    assert not response.truncated
    assert not response.tls


def test_request_format():
    answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    response, request = roundtrip(answer, "/status?x=1#frag")
    head = request.decode("latin-1")
    port = response.url.split(":")[2].split("/")[0]
    assert head.startswith("GET /status?x=1 HTTP/1.1\r\n")
    assert f"\r\nHost: 127.0.0.1:{port}\r\n" in head
    assert f"\r\nUser-Agent: Hearthscan/{__version__}\r\n" in head
    assert "\r\nAccept: */*\r\n" in head
    assert "\r\nConnection: close\r\n" in head
    assert "content-length" not in head.lower()


def test_post_with_body_and_custom_headers():
    answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    body = b"<s:Envelope/>"
    response, request = roundtrip(
        answer,
        "/ctl/IPConn",
        method="POST",
        headers={"SOAPAction": '"urn:test#GetStatus"', "User-Agent": "Custom/1"},
        body=body,
    )
    head, _, sent = request.partition(b"\r\n\r\n")
    assert head.startswith(b"POST /ctl/IPConn HTTP/1.1\r\n")
    assert b'\r\nSOAPAction: "urn:test#GetStatus"' in head
    assert b"\r\nUser-Agent: Custom/1" in head
    assert b"Hearthscan" not in head
    assert f"\r\nContent-Length: {len(body)}".encode() in head
    assert sent == body
    assert response.body == b"ok"


def test_odd_characters_in_the_path_are_encoded():
    answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    _, request = roundtrip(answer, "/a b/\u00fc?q=1 2")
    assert request.startswith(b"GET /a%20b/%C3%BC?q=1%202 HTTP/1.1\r\n")


def test_chunked_with_extensions_and_trailers():
    answer = keep_open(
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5;name=value\r\nhello\r\n"
        b"A  \r\n world 123\r\n"
        b"0\r\n"
        b"X-Checksum: abc\r\n"
        b"\r\n"
    )
    response, _ = roundtrip(answer)
    assert response.body == b"hello world 123"
    assert not response.truncated


def test_transfer_encoding_wins_over_content_length():
    answer = keep_open(
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"2\r\nok\r\n0\r\n\r\n"
    )
    response, _ = roundtrip(answer)
    assert response.body == b"ok"


def test_close_delimited_body():
    response, _ = roundtrip(b"HTTP/1.0 200 OK\r\nServer: Tiny\r\n\r\n" + b"x" * 5000)
    assert response.body == b"x" * 5000
    assert not response.truncated


def test_lf_only_line_endings():
    response, _ = roundtrip(b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok")
    assert response.status == 200
    assert response.body == b"ok"


def test_folded_header_lines_are_joined():
    response, _ = roundtrip(b"HTTP/1.1 200 OK\r\nX-Long: first\r\n second\r\n\r\n")
    assert response.headers["x-long"] == "first second"


def test_head_has_no_body():
    answer = keep_open(b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n")
    started = time.perf_counter()
    response, request = roundtrip(answer, method="HEAD", timeout=5.0)
    assert request.startswith(b"HEAD / HTTP/1.1\r\n")
    assert response.body == b""
    assert not response.truncated
    assert time.perf_counter() - started < 2.0


@pytest.mark.parametrize("status", [204, 304])
def test_no_body_statuses(status):
    answer = keep_open(f"HTTP/1.1 {status} Nothing\r\nContent-Length: 10\r\n\r\n".encode())
    started = time.perf_counter()
    response, _ = roundtrip(answer, timeout=5.0)
    assert response.status == status
    assert response.body == b""
    assert time.perf_counter() - started < 2.0


def test_interim_responses_are_skipped():
    response, _ = roundtrip(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone"
    )
    assert response.status == 200
    assert response.body == b"done"


def test_limit_with_content_length():
    answer = keep_open(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"a" * 1000)
    response, _ = roundtrip(answer, limit=100)
    assert response.body == b"a" * 100
    assert response.truncated


def test_limit_with_chunked():
    chunk = b"64\r\n" + b"b" * 100 + b"\r\n"
    answer = keep_open(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk * 3)
    response, _ = roundtrip(answer, limit=150)
    assert response.body == b"b" * 150
    assert response.truncated


def test_limit_with_close_delimited_body():
    response, _ = roundtrip(b"HTTP/1.1 200 OK\r\n\r\n" + b"c" * 1000, limit=100)
    assert response.body == b"c" * 100
    assert response.truncated

    response, _ = roundtrip(b"HTTP/1.1 200 OK\r\n\r\n" + b"c" * 100, limit=100)
    assert response.body == b"c" * 100
    assert not response.truncated


def test_early_close_marks_the_body_truncated():
    response, _ = roundtrip(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly this")
    assert response.body == b"only this"
    assert response.truncated

    response, _ = roundtrip(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort")
    assert response.body == b"short"
    assert response.truncated


def test_slow_server_hits_the_deadline():
    async def drip(reader, writer):
        writer.write(b"HTTP/1.1 200 OK\r\n")
        # Older Pythons do not raise in drain() once the client is gone.
        while not writer.is_closing():
            writer.write(b"X-Drip: 1\r\n")
            await writer.drain()
            await asyncio.sleep(0.05)

    started = time.perf_counter()
    with pytest.raises(TimeoutError):
        roundtrip(drip, timeout=0.5)
    assert 0.4 < time.perf_counter() - started < 2.0


def test_silent_server_hits_the_deadline():
    async def silent(reader, writer):
        await hold(reader)

    started = time.perf_counter()
    with pytest.raises(TimeoutError):
        roundtrip(silent, timeout=0.3)
    assert time.perf_counter() - started < 2.0


@pytest.mark.parametrize(
    "answer",
    [
        b"SSH-2.0-Tiny_1.0\r\n",
        b"HTTP/1.1 OK\r\n\r\n",
        b"HTTP/1.1 999 Odd\r\n\r\n",
        b"HTTP/2 200\r\n\r\n",
        b"",
        b"HTTP/1.1 200 OK\r\nServer: cut off",
    ],
)
def test_malformed_status_or_early_close_is_an_http_error(answer):
    with pytest.raises(HttpError):
        roundtrip(answer)


@pytest.mark.parametrize(
    "headers",
    [
        b"No colon here\r\n",
        b"Bad Name: x\r\n",
        b": empty name\r\n",
        b" leading continuation\r\n",
        b"Content-Length: 5, 6\r\n",
        b"Content-Length: five\r\n",
        b"Content-Length: -1\r\n",
        b"Content-Length: 99999999999999999999999\r\n",
    ],
)
def test_malformed_headers_are_an_http_error(headers):
    with pytest.raises(HttpError):
        roundtrip(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\nhello")


@pytest.mark.parametrize(
    "size_line", [b"zz", b"0x5", b"-5", b"+5", b"1_0", b"", b"12345678901234567"]
)
def test_bad_chunk_sizes_are_an_http_error(size_line):
    with pytest.raises(HttpError):
        roundtrip(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + size_line + b"\r\n")


def test_chunk_longer_than_its_size_is_an_http_error():
    with pytest.raises(HttpError):
        roundtrip(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\ntoo long\r\n0\r\n\r\n"
        )


def test_oversized_header_section_is_an_http_error():
    filler = b"".join(b"X-Filler-%05d: %s\r\n" % (i, b"f" * 60) for i in range(90))
    filler *= 1 + MAX_HEADER_BYTES // len(filler)
    with pytest.raises(HttpError):
        roundtrip(keep_open(b"HTTP/1.1 200 OK\r\n" + filler + b"\r\n"))


def test_overlong_header_line_is_an_http_error():
    line = b"X-Big: " + b"y" * (MAX_HEADER_BYTES + 10) + b"\r\n"
    with pytest.raises(HttpError):
        roundtrip(keep_open(b"HTTP/1.1 200 OK\r\n" + line + b"\r\n"))


def test_too_many_headers_is_an_http_error():
    many = b"".join(b"X-H%d: v\r\n" % i for i in range(101))
    with pytest.raises(HttpError):
        roundtrip(b"HTTP/1.1 200 OK\r\n" + many + b"\r\n")
    response, _ = roundtrip(b"HTTP/1.1 200 OK\r\n" + many[: many.index(b"X-H100")] + b"\r\n")
    assert len(response.headers) == 100


def test_too_many_interim_responses_is_an_http_error():
    with pytest.raises(HttpError):
        roundtrip(keep_open(b"HTTP/1.1 100 Continue\r\n\r\n" * 10))


def test_http_error_is_an_os_error():
    assert issubclass(HttpError, OSError)


def test_cancelling_closes_the_connection():
    async def main():
        got_request = asyncio.Event()
        closed = asyncio.Event()

        async def handle(reader, writer):
            await read_request(reader)
            got_request.set()
            await hold(reader)
            closed.set()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            task = asyncio.ensure_future(fetch(f"http://127.0.0.1:{port}/", timeout=30))
            await asyncio.wait_for(got_request.wait(), 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(closed.wait(), 2)

    asyncio.run(main())


def test_tls_fetch_accepts_a_self_signed_certificate():
    answer = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret"
    response, request = roundtrip(answer, "/admin", tls=True)
    assert response.tls
    assert response.tls_version in ("TLSv1.2", "TLSv1.3")
    assert response.tls_cipher
    assert response.status == 200
    assert response.body == b"secret"
    assert request.startswith(b"GET /admin HTTP/1.1\r\n")


def test_plain_http_has_no_tls_details():
    response, _ = roundtrip(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    assert response.tls_version is None
    assert response.tls_cipher is None


def legacy_server(version: ssl.TLSVersion, cipher: str) -> ssl.SSLContext:
    """A server that speaks only `version`, with the RSA certificate and one cipher."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(RSA_CERT)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        context.set_ciphers(f"{cipher}:@SECLEVEL=0")
    except (ValueError, ssl.SSLError) as exc:
        pytest.skip(f"the local OpenSSL cannot serve {version.name} with {cipher}: {exc}")
    return context


@pytest.mark.parametrize(
    ("version", "name"),
    [(ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (ssl.TLSVersion.TLSv1, "TLSv1")],
)
def test_tls_with_an_old_device(version, name):
    # Static RSA key exchange with AES-CBC and SHA-1, as older routers and
    # printers offer. Python's default client settings refuse all of it.
    server = legacy_server(version, "AES128-SHA")
    answer = b"HTTP/1.1 200 OK\r\nServer: OldBox/1.0\r\nContent-Length: 2\r\n\r\nok"
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        http._tls_context.cache_clear()  # so building it again happens in here
        response, _ = roundtrip(answer, tls=server)
    assert response.status == 200
    assert response.headers["server"] == "OldBox/1.0"
    assert response.tls_version == name
    assert response.tls_cipher == "AES128-SHA"


def test_tls_on_the_default_port_leaves_it_out_of_host():
    request = http._prepare("https://192.168.1.1/", "GET", None, None)
    assert request.tls
    assert request.port == 443
    assert b"\r\nHost: 192.168.1.1\r\n" in request.data


@pytest.mark.skipif(not has_ipv6_loopback(), reason="no IPv6 loopback")
def test_ipv6_literal():
    answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nv6"
    response, request = roundtrip(answer, host="::1")
    port = response.url.rsplit(":", 1)[1].split("/")[0]
    assert response.body == b"v6"
    assert f"\r\nHost: [::1]:{port}\r\n".encode() in request


def test_ipv6_zone_is_kept_for_connecting_but_not_sent():
    request = http._prepare("http://[fe80::1%25eth0]:8080/x", "GET", None, None)
    assert request.host == "fe80::1%eth0"
    assert b"\r\nHost: [fe80::1]:8080\r\n" in request.data


@pytest.mark.parametrize(
    "url",
    [
        "http://203.0.113.10/",
        "https://198.51.100.7:8443/",
        "http://[2001:db8::1]/",
        "http://100.64.0.1/",
        "http://router.lan/",
        "http://localhost/",
        "ftp://192.168.1.1/",
        "file:///etc/hosts",
        "//192.168.1.1/",
        "192.168.1.1",
        "http:///path",
        "http://user:secret@192.168.1.1/",
        "http://192.168.1.1:0/",
        "http://192.168.1.1:99999/",
        "http://192.168.1.010/",
        "http://[::1/",
    ],
)
def test_urls_we_refuse(url):
    with pytest.raises(ValueError):
        asyncio.run(fetch(url))


def test_public_address_is_a_scope_error():
    with pytest.raises(ScopeError):
        asyncio.run(fetch("http://203.0.113.10/"))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"headers": {"X-Test": "a\r\nInjected: 1"}},
        {"headers": {"Bad Name": "x"}},
        {"headers": {"Connection": "keep-alive"}},
        {"headers": {"content-length": "5"}},
        {"headers": {"Transfer-Encoding": "chunked"}},
        {"headers": {"X-Name": "\u0130stanbul"}},
        {"method": "GET /x"},
        {"method": ""},
        {"timeout": 0},
        {"timeout": float("nan")},
        {"limit": -1},
    ],
)
def test_bad_arguments(kwargs):
    with pytest.raises(ValueError):
        asyncio.run(fetch("http://192.168.1.1/", **kwargs))


def make_response(body: bytes, content_type: str | None = None) -> Response:
    headers = {"content-type": content_type} if content_type else {}
    return Response("http://192.168.1.1/", 200, "OK", headers, body)


def test_text_uses_the_charset_from_content_type():
    body = "\u0130stanbul \u015fehir".encode("iso-8859-9")
    assert make_response(body, "text/html; charset=ISO-8859-9").text() == "\u0130stanbul \u015fehir"
    assert make_response(b"caf\xc3\xa9", 'text/plain; charset="utf-8"').text() == "caf\u00e9"


@pytest.mark.parametrize("charset", ["no-such-codec", "rot13", "base64", "idna"])
def test_text_falls_back_to_utf8(charset):
    response = make_response(b"caf\xc3\xa9 \xff", f"text/plain; charset={charset}")
    assert response.text() == "caf\u00e9 \ufffd"


def test_text_without_content_type():
    assert make_response(b"ok \xfe").text() == "ok \ufffd"


def test_servers_from_before_secure_renegotiation_are_accepted():
    import ssl

    from hearthscan import http

    assert http._tls_context().options & getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
