import asyncio
import contextlib
import json
import math
import random
import re
import socket
import ssl
import struct
import time
from pathlib import Path

import pytest

from hearthscan import ports, probes
from hearthscan.models import Service
from hearthscan.probes import probe, probe_all
from hearthscan.scope import ScopeError

CERT = Path(__file__).parent / "data" / "http_selfsigned.pem"

BUSYBOX_OPTIONS = b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03"

LOGIN_PAGE = b"""<!doctype html>
<html><head><title>
   Attic  Router &amp; Co
</title><title>second title</title></head>
<body><form method="post" action="/login.cgi">
<input name="user"><input name="pw" type="password">
</form></body></html>"""


def server_tls() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT)
    return context


async def record(reader: asyncio.StreamReader, into: bytearray) -> None:
    """Read until the client goes away, keeping what it sent."""
    with contextlib.suppress(ConnectionError):
        while chunk := await reader.read(4096):
            into += chunk


def guarded(handler):
    async def handle(reader, writer):
        try:
            with contextlib.suppress(ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
                await handler(reader, writer)
        finally:
            writer.close()

    return handle


async def start(handler, *, tls: bool = False, host: str = "127.0.0.1"):
    context = server_tls() if tls else None
    server = await asyncio.start_server(guarded(handler), host, 0, ssl=context)
    return server, server.sockets[0].getsockname()[1]


def has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
    except OSError:
        return False
    return True


def claim(monkeypatch, port: int, kind: str | None) -> None:
    """Make `port` get the probe `kind`. None makes it a port nobody knows."""
    # The OS may hand out a port with a meaning of its own, like 49152.
    monkeypatch.delitem(ports.SERVICE_NAMES, port, raising=False)
    if kind is None:
        monkeypatch.delitem(probes.PROBES, port, raising=False)
    else:
        monkeypatch.setitem(probes.PROBES, port, kind)


def run_probe(
    monkeypatch, handler, kind=None, *, timeout=2.0, tls=False, host="127.0.0.1"
) -> Service:
    """Probe a loopback server that runs `handler` for each connection."""

    async def main():
        server, port = await start(handler, tls=tls, host=host)
        claim(monkeypatch, port, kind)
        async with server:
            return await probe(host, port, timeout=timeout)

    return asyncio.run(main())


def greet(data: bytes, into: bytearray | None = None):
    async def handler(reader, writer):
        writer.write(data)
        await writer.drain()
        await record(reader, bytearray() if into is None else into)

    return handler


def page(status: str = "200 OK", body: bytes = b"", **headers: str) -> bytes:
    lines = [f"HTTP/1.1 {status}", f"Content-Length: {len(body)}"]
    lines += [f"{name.replace('_', '-')}: {value}" for name, value in headers.items()]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def site(pages: dict[str, bytes], seen: list[str] | None = None):
    """An HTTP server with fixed answers per path."""

    async def handler(reader, writer):
        first = await reader.readexactly(1)
        if not first.isalpha():
            # A TLS ClientHello, say. Real servers answer that with a 400 too.
            writer.write(page("400 Bad Request"))
            await writer.drain()
            return
        head = first + await reader.readuntil(b"\r\n\r\n")
        path = head.split(b" ", 2)[1].decode()
        if seen is not None:
            seen.append(path)
        writer.write(pages.get(path, page("404 Not Found")))
        await writer.drain()

    return handler


# Services that speak first


def test_ftp_greeting(monkeypatch):
    service = run_probe(monkeypatch, greet(b"220 (vsFTPd 3.0.3)\r\n"))
    assert service.name == "ftp"
    assert service.product == "vsFTPd 3.0.3"
    assert service.banner == "220 (vsFTPd 3.0.3)"
    assert service.auth is None


def test_multiline_ftp_greeting_is_read_to_its_last_line(monkeypatch):
    async def handler(reader, writer):
        writer.write(b"220-Welcome to the attic box\r\n")
        await writer.drain()
        await asyncio.sleep(0.1)
        writer.write(b"220 ProFTPD 1.3.8 Server ready.\r\n")
        await writer.drain()
        await record(reader, bytearray())

    service = run_probe(monkeypatch, handler, "banner")
    assert service.name == "ftp"
    assert service.banner == "220-Welcome to the attic box 220 ProFTPD 1.3.8 Server ready."
    assert service.product == "ProFTPD 1.3.8"


def test_ssh_banner(monkeypatch):
    sent = bytearray()
    service = run_probe(monkeypatch, greet(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", sent))
    assert service.name == "ssh"
    assert service.product == "OpenSSH 9.6p1"
    assert service.banner == "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
    assert sent == b""


def test_ssh_on_the_telnet_port_is_called_ssh(monkeypatch):
    started = time.perf_counter()
    service = run_probe(monkeypatch, greet(b"SSH-2.0-OpenSSH_9.6p1\r\n"), "telnet", timeout=3.0)
    assert time.perf_counter() - started < 1.5
    assert service.name == "ssh"
    assert service.product == "OpenSSH 9.6p1"


def test_ssh_key_exchange_after_the_banner_is_left_out(monkeypatch):
    kex_names = b"curve25519-sha256,kexguess2@matt.ucc.asn.au,kex-strict-s-v00@openssh.com"
    payload = b"\x14" + bytes(range(16)) + struct.pack(">I", len(kex_names)) + kex_names
    packet = struct.pack(">IB", len(payload) + 5, 4) + payload + bytes(4)

    started = time.perf_counter()
    service = run_probe(monkeypatch, greet(b"SSH-2.0-ssh\r\n" + packet), "banner")
    assert time.perf_counter() - started < 1  # no waiting for a line end that never comes
    assert service.name == "ssh"
    assert service.banner == "SSH-2.0-ssh"
    assert service.product == "Dropbear"


@pytest.mark.parametrize(
    ("kind", "greeting"),
    [("banner", b"220-Still starting up"), ("telnet", b"\xff\xfb\x01Still starting up")],
)
def test_greeting_cut_off_by_the_deadline_is_kept(monkeypatch, kind, greeting):
    service = run_probe(monkeypatch, greet(greeting), kind, timeout=0.5)
    assert service.banner.endswith("Still starting up")


def test_known_port_waits_longer_than_a_second_for_its_greeting(monkeypatch):
    async def handler(reader, writer):
        await asyncio.sleep(1.3)  # an FTP server busy with reverse DNS
        writer.write(b"220 Microsoft FTP Service\r\n")
        await writer.drain()
        await record(reader, bytearray())

    service = run_probe(monkeypatch, handler, "banner", timeout=3.0)
    assert service.product == "Microsoft FTP Service"


def test_telnet_options_are_refused_so_the_banner_arrives(monkeypatch):
    replies = []

    async def handler(reader, writer):
        writer.write(BUSYBOX_OPTIONS)
        await writer.drain()
        replies.append(await reader.readexactly(12))
        writer.write(b"\r\n\x1b[1mattic-router\x1b[0m login: ")
        await writer.drain()
        await record(reader, bytearray())

    started = time.perf_counter()
    service = run_probe(monkeypatch, handler)
    assert time.perf_counter() - started < 1.5  # the prompt ends the wait
    # DO is answered with WONT, WILL with DONT.
    assert replies == [b"\xff\xfc\x01\xff\xfc\x1f\xff\xfe\x01\xff\xfe\x03"]
    assert service.name == "telnet"
    assert service.banner == "attic-router login:"
    assert service.product == "BusyBox telnetd"
    assert service.auth == "required"


def test_telnet_banner_naming_busybox(monkeypatch):
    greeting = (
        b"\xff\xfd\x18\xff\xfa\x18\x01\xff\xf0"
        b"\r\n\r\nBusyBox v1.36.1 (2024-03-01 00:00:00 UTC) built-in shell (ash)\r\n\r\n# "
    )
    service = run_probe(monkeypatch, greet(greeting), "telnet")
    assert service.product == "BusyBox 1.36.1"
    assert service.banner == "BusyBox v1.36.1 (2024-03-01 00:00:00 UTC) built-in shell (ash) #"
    assert service.auth is None


def test_telnet_split():
    data = b"\xff\xfb\x01hi \xff\xff\xff\xfa\x18\x01\xff\xf0there\xff\xf1!\xff\xfd"
    text, asks, rest = probes._telnet_split(data)
    assert text == b"hi \xffthere!"
    assert asks == [(251, 1)]
    assert rest == b"\xff\xfd"
    # A subnegotiation that never ends is dropped rather than kept forever.
    assert probes._telnet_split(b"ok\xff\xfa" + b"x" * 1000) == (b"ok", [], b"")


@pytest.mark.parametrize(
    ("version", "security", "answer", "auth", "names"),
    [
        (b"RFB 003.008\n", b"\x02\x01\x02", b"RFB 003.008\n", "none", "None,VNC Authentication"),
        (b"RFB 003.008\n", b"\x01\x02", b"RFB 003.008\n", "required", "VNC Authentication"),
        (b"RFB 003.007\n", b"\x01\x01", b"RFB 003.007\n", "none", "None"),
        (b"RFB 003.003\n", b"\x00\x00\x00\x02", b"RFB 003.003\n", "required", "VNC Authentication"),
        (
            b"RFB 003.889\n",
            b"\x02\x1e\x02",
            b"RFB 003.008\n",
            "required",
            "Apple Remote Desktop,VNC Authentication",
        ),
        # Unknown types and wrappers like VeNCrypt may hide a no-password mode.
        (b"RFB 003.889\n", b"\x02\x1e\x23", b"RFB 003.008\n", None, "Apple Remote Desktop,type 35"),
        (b"RFB 003.008\n", b"\x01\x13", b"RFB 003.008\n", None, "VeNCrypt"),
        (b"RFB 003.008\n", b"\x02\x12\x10", b"RFB 003.008\n", None, "TLS,Tight"),
    ],
)
def test_vnc_security_types(monkeypatch, version, security, answer, auth, names):
    seen = []
    rest = bytearray()

    async def handler(reader, writer):
        writer.write(version)
        await writer.drain()
        seen.append(await reader.readexactly(12))
        writer.write(security)
        await writer.drain()
        await record(reader, rest)

    service = run_probe(monkeypatch, handler)
    assert seen == [answer]
    assert rest == b""  # no security type chosen, no authentication tried
    assert service.name == "vnc"
    assert service.banner == version.decode().strip()
    assert service.auth == auth
    assert service.facts == {"security": names}


def test_vnc_refusal_says_nothing_about_auth(monkeypatch):
    async def handler(reader, writer):
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        await reader.readexactly(12)
        reason = b"Too many security failures"
        writer.write(b"\x00" + struct.pack(">I", len(reason)) + reason)
        await writer.drain()
        await record(reader, bytearray())

    service = run_probe(monkeypatch, handler, "vnc")
    assert service.name == "vnc"
    assert service.auth is None
    assert service.facts == {}


def test_rsync_module_list(monkeypatch):
    seen = []

    async def handler(reader, writer):
        writer.write(b"@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\n")
        await writer.drain()
        seen.append(await reader.readline())
        seen.append(await reader.readline())
        writer.write(
            b"Welcome to the attic mirror\n\n"
            b"photos         \tFamily photos\n"
            b"backup         \tNightly backups\n"
            b"@RSYNCD: EXIT\n"
        )
        await writer.drain()
        await record(reader, bytearray())

    service = run_probe(monkeypatch, handler)
    assert seen == [b"@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\n", b"#list\n"]
    assert service.name == "rsync"
    assert service.banner == "@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4"
    assert service.facts == {"modules": "2"}


def test_rsync_without_modules(monkeypatch):
    async def handler(reader, writer):
        writer.write(b"@RSYNCD: 30.0\n")
        await writer.drain()
        await reader.readline()
        await reader.readline()
        writer.write(b"@RSYNCD: EXIT\n")
        await writer.drain()
        await record(reader, bytearray())

    assert run_probe(monkeypatch, handler, "rsync").facts == {"modules": "0"}


def mysql_greeting(version: bytes) -> bytes:
    payload = (
        b"\x0a"
        + version
        + b"\x00"
        + struct.pack("<I", 8)
        + b"abcdefgh\x00"
        + struct.pack("<HBHH", 0xF7FF, 0x21, 2, 0x81FF)
        + bytes(11)
    )
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


@pytest.mark.parametrize(
    ("version", "product"),
    [
        (b"8.0.36", "MySQL 8.0.36"),
        (b"5.5.5-10.11.6-MariaDB-0ubuntu0.24.04.1", "MariaDB 10.11.6"),
        (b"11.4.2-MariaDB", "MariaDB 11.4.2"),
    ],
)
def test_mysql_greeting(monkeypatch, version, product):
    service = run_probe(monkeypatch, greet(mysql_greeting(version)))
    assert service.name == "mysql"
    assert service.product == product
    assert service.banner == version.decode()


def test_mysql_refusal(monkeypatch):
    payload = b"\xff\x6a\x04Host 'attic' is not allowed to connect to this MySQL server"
    packet = len(payload).to_bytes(3, "little") + b"\x00" + payload
    service = run_probe(monkeypatch, greet(packet), "mysql")
    assert service.name == "mysql"
    assert service.banner == "Host 'attic' is not allowed to connect to this MySQL server"
    assert service.product is None


# Web


def test_web_login_form(monkeypatch):
    answer = page(body=LOGIN_PAGE, Server="lighttpd/1.4.59", Content_Type="text/html")
    service = run_probe(monkeypatch, site({"/": answer}), "web")
    assert service.name == "http"
    assert service.title == "Attic Router & Co"
    assert service.product == "lighttpd/1.4.59"
    assert service.facts == {"status": "200", "login": "form"}
    assert service.auth == "required"
    assert not service.tls
    assert service.tls_version is None


@pytest.mark.parametrize(
    ("challenge", "login"),
    [
        ('Basic realm="attic"', "basic"),
        ('Digest realm="attic", qop="auth", nonce="abc"', "digest"),
        ('Digest realm="attic", nonce="abc", Basic realm="attic"', "basic"),
    ],
)
def test_web_http_authentication(monkeypatch, challenge, login):
    answer = page("401 Unauthorized", b"<title>401</title>", WWW_Authenticate=challenge)
    service = run_probe(monkeypatch, site({"/": answer}), "web")
    assert service.facts == {"status": "401", "login": login}
    assert service.auth == "required"


def test_web_page_without_login(monkeypatch):
    answer = page(body=b"<html><title>Printer status</title></html>")
    service = run_probe(monkeypatch, site({"/": answer}), "web")
    assert service.title == "Printer status"
    assert service.facts == {"status": "200"}
    assert service.auth is None


def test_same_host_redirect_leads_to_the_login_page(monkeypatch):
    seen = []
    pages = {
        "/": page("302 Found", b"<title>Moved</title>", Location="/cgi-bin/login.html"),
        "/cgi-bin/login.html": page(body=LOGIN_PAGE),
    }
    service = run_probe(monkeypatch, site(pages, seen), "web")
    assert seen == ["/", "/cgi-bin/login.html"]
    assert service.facts == {"status": "302", "redirect": "/cgi-bin/login.html", "login": "form"}
    assert service.title == "Attic Router & Co"
    assert service.auth == "required"


def test_only_one_redirect_is_followed(monkeypatch):
    seen = []
    pages = {
        "/": page("302 Found", Location="/a"),
        "/a": page("302 Found", Location="/b"),
        "/b": page(body=LOGIN_PAGE),
    }
    service = run_probe(monkeypatch, site(pages, seen), "web")
    assert seen == ["/", "/a"]
    assert "login" not in service.facts


def test_redirect_to_another_host_is_not_followed(monkeypatch):
    seen = []
    pages = {"/": page("301 Moved Permanently", Location="https://192.168.1.1/login")}
    service = run_probe(monkeypatch, site(pages, seen), "web")
    assert seen == ["/"]
    assert service.facts == {"status": "301", "redirect": "https://192.168.1.1/login"}


def test_meta_refresh_counts_as_a_redirect(monkeypatch):
    seen = []
    refresh = b"<html><head><meta content=\"0; URL='/login.htm'\" http-equiv=refresh></head></html>"
    pages = {"/": page(body=refresh), "/login.htm": page(body=LOGIN_PAGE)}
    service = run_probe(monkeypatch, site(pages, seen), "web")
    assert seen == ["/", "/login.htm"]
    assert service.facts == {"status": "200", "login": "form"}


def test_https_port(monkeypatch):
    answer = page(body=b"<title>Attic NAS</title>")
    service = run_probe(monkeypatch, site({"/": answer}), "tls-web", tls=True)
    assert service.name == "https"
    assert service.tls
    assert service.tls_version in ("TLSv1.2", "TLSv1.3")
    assert service.title == "Attic NAS"


def test_https_port_that_speaks_plain_http(monkeypatch):
    answer = page(body=b"<title>Attic NAS</title>")
    service = run_probe(monkeypatch, site({"/": answer}), "tls-web")
    assert service.name == "http"
    assert not service.tls
    assert service.title == "Attic NAS"


def test_http_port_that_speaks_tls_is_asked_again_over_tls(monkeypatch):
    answer = page(body=b"<title>Webmin</title>", Server="MiniServ/2.105")
    service = run_probe(monkeypatch, site({"/": answer}), "web", tls=True)
    assert service.name == "https"
    assert service.tls
    assert service.title == "Webmin"
    assert service.product == "MiniServ/2.105"


def test_tls_alert_makes_the_probe_try_tls(monkeypatch):
    openings = []

    async def handler(reader, writer):
        openings.append(await reader.read(1))
        writer.write(b"\x15\x03\x01\x00\x02\x02\x46")
        await writer.drain()

    service = run_probe(monkeypatch, handler, "web")
    assert openings == [b"G", b"\x16"]  # GET, then a TLS ClientHello
    assert not service.tls


def test_ssl_mode_notice_makes_the_probe_try_tls(monkeypatch):
    openings = []
    notice = page(
        body=b"<h1>Error - Document follows</h1>\n"
        b"<p>This web server is running in SSL mode. Try https://attic:10000/ instead.</p>"
    )

    async def handler(reader, writer):
        first = await reader.read(1)
        openings.append(first)
        if first == b"G":
            await reader.readuntil(b"\r\n\r\n")
            writer.write(notice)
            await writer.drain()

    service = run_probe(monkeypatch, handler, "web")
    assert openings == [b"G", b"\x16"]
    # The TLS attempt failed, so what plain HTTP said stands.
    assert service.facts == {"status": "200"}
    assert not service.tls


@pytest.mark.skipif(not has_ipv6_loopback(), reason="no IPv6 loopback")
def test_web_probe_over_ipv6(monkeypatch):
    seen = []
    pages = {"/": page("302 Found", Location="/login"), "/login": page(body=LOGIN_PAGE)}
    service = run_probe(monkeypatch, site(pages, seen), "web", host="::1")
    assert seen == ["/", "/login"]
    assert service.facts["login"] == "form"


def test_quiet_unknown_port_is_only_listened_to(monkeypatch):
    # It could be a printer that prints whatever arrives, or a console that
    # would take a web request for a user name.
    received = bytearray()

    async def handler(reader, writer):
        await record(reader, received)

    service = run_probe(monkeypatch, handler, timeout=1.5)
    assert received == b""
    assert service.facts == {}


def test_quiet_known_port_is_not_asked_for_a_web_page(monkeypatch):
    seen = []
    service = run_probe(monkeypatch, site({"/": page()}, seen), "listen", timeout=1.5)
    assert seen == []
    assert service.name == ""
    assert service.facts == {}


def test_title_parsing():
    assert probes._title("<TITLE lang=en>\n a &lt;b&gt;\t c </TITLE>") == "a <b> c"
    assert probes._title("<title>one</title><title>two</title>") == "one"
    assert probes._title("<title>Bell\x07 &#8203;and\u202e text</title>") == "Bell and text"
    assert probes._title("<title>no end") is None
    assert probes._title("<p>none</p>") is None
    assert probes._title("<title>" + "x" * 500 + "</title>") == "x" * probes.MAX_TITLE


def test_title_search_stays_fast_on_hostile_markup():
    started = time.perf_counter()
    probes._title("<title " * 20000)
    probes._PASSWORD_INPUT.search("<input " * 20000)
    probes._META_REFRESH.search("<meta http-equiv=refresh " * 5000)
    assert time.perf_counter() - started < 1


# Services that wait for the client


def rtsp_camera(describe: bytes, seen: list[bytes]):
    async def handler(reader, writer):
        options = (
            b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
            b"Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n"
            b"Server: Attic Cam RTSP 1.2\r\n\r\n"
        )
        for answer in (options, describe):
            seen.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(answer)
            await writer.drain()
        await record(reader, bytearray())

    return handler


@pytest.mark.parametrize(
    ("describe", "status", "auth"),
    [
        (
            b"RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n"
            b"Content-Length: 12\r\n\r\nv=0\r\no=- 0 0",
            "200",
            "none",
        ),
        (
            b'RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\nWWW-Authenticate: Digest realm="cam"\r\n\r\n',
            "401",
            "required",
        ),
    ],
)
def test_rtsp_describe_without_credentials(monkeypatch, describe, status, auth):
    seen = []
    service = run_probe(monkeypatch, rtsp_camera(describe, seen), "rtsp")
    assert re.match(rb"OPTIONS rtsp://127\.0\.0\.1:\d+/ RTSP/1\.0\r\nCSeq: 1\r\n", seen[0])
    assert re.match(rb"DESCRIBE rtsp://127\.0\.0\.1:\d+/ RTSP/1\.0\r\nCSeq: 2\r\n", seen[1])
    for request in seen:
        assert b"\r\nUser-Agent: Hearthscan/" in request
        assert b"authorization" not in request.lower()
    assert service.name == "rtsp"
    assert service.product == "Attic Cam RTSP 1.2"
    assert service.facts == {"describe": status}
    assert service.auth == auth


@pytest.mark.skipif(not has_ipv6_loopback(), reason="no IPv6 loopback")
def test_rtsp_over_ipv6(monkeypatch):
    seen = []
    describe = b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n"
    service = run_probe(monkeypatch, rtsp_camera(describe, seen), "rtsp", host="::1")
    assert re.match(rb"OPTIONS rtsp://\[::1\]:\d+/ RTSP/1\.0\r\n", seen[0])
    assert service.auth == "required"


@pytest.mark.parametrize(
    ("reply", "auth"),
    [
        (b"+PONG\r\n", "none"),
        (b"-NOAUTH Authentication required.\r\n", "required"),
        (b"-DENIED Redis is running in protected mode\r\n", "required"),
    ],
)
def test_redis_ping(monkeypatch, reply, auth):
    sent = bytearray()

    async def handler(reader, writer):
        sent.extend(await reader.readuntil(b"\r\n"))
        writer.write(reply)
        await writer.drain()
        await record(reader, sent)

    service = run_probe(monkeypatch, handler, "redis")
    assert sent == b"PING\r\n"
    assert service.name == "redis"
    assert service.auth == auth


def test_memcached_version(monkeypatch):
    sent = bytearray()

    async def handler(reader, writer):
        sent.extend(await reader.readuntil(b"\r\n"))
        writer.write(b"VERSION 1.6.21\r\n")
        await writer.drain()
        await record(reader, sent)

    service = run_probe(monkeypatch, handler, "memcached")
    assert sent == b"version\r\n"
    assert service.name == "memcached"
    assert service.product == "memcached 1.6.21"
    assert service.auth == "none"


def test_elasticsearch_open(monkeypatch):
    root = {"name": "attic-node", "cluster_name": "attic", "version": {"number": "8.11.1"}}
    answer = page(body=json.dumps(root).encode(), Content_Type="application/json")
    service = run_probe(monkeypatch, site({"/": answer}), "elasticsearch")
    assert service.name == "elasticsearch"
    assert service.product == "Elasticsearch 8.11.1"
    assert service.auth == "none"
    assert service.facts == {"status": "200"}


def test_opensearch_is_named_as_such(monkeypatch):
    root = {"cluster_name": "attic", "version": {"distribution": "opensearch", "number": "2.11.0"}}
    service = run_probe(
        monkeypatch, site({"/": page(body=json.dumps(root).encode())}), "elasticsearch"
    )
    assert service.product == "OpenSearch 2.11.0"


def test_elasticsearch_with_security(monkeypatch):
    answer = page("401 Unauthorized", WWW_Authenticate='Basic realm="security" charset="UTF-8"')
    service = run_probe(monkeypatch, site({"/": answer}), "elasticsearch")
    assert service.auth == "required"
    assert service.product is None


def test_elasticsearch_port_with_something_else_on_it(monkeypatch):
    answer = page(body=b'["not", "a", "cluster"]')
    service = run_probe(monkeypatch, site({"/": answer}), "elasticsearch")
    assert service.auth is None
    assert service.name == "http"


def test_docker_api_open(monkeypatch):
    seen = []
    version = {"Version": "24.0.7", "ApiVersion": "1.43", "Os": "linux"}
    answer = page(body=json.dumps(version).encode(), Server="Docker/24.0.7 (linux)")
    service = run_probe(monkeypatch, site({"/version": answer}, seen), "docker")
    assert seen == ["/version"]
    assert service.name == "docker"
    assert service.product == "Docker 24.0.7"
    assert service.auth == "none"


@pytest.mark.parametrize(("code", "auth"), [(0, "none"), (5, "required"), (4, "required")])
def test_mqtt_connect_without_credentials(monkeypatch, code, auth):
    packets = []
    rest = bytearray()

    async def handler(reader, writer):
        head = await reader.readexactly(2)
        packets.append(head + await reader.readexactly(head[1]))
        writer.write(bytes((0x20, 2, 0, code)))
        await writer.drain()
        await record(reader, rest)

    service = run_probe(monkeypatch, handler, "mqtt")
    connect = packets[0]
    assert connect[0] == 0x10
    body = connect[2:]
    assert body[:7] == b"\x00\x04MQTT\x04"
    assert body[7] == 0x02  # clean session; no user name, password or will
    (length,) = struct.unpack(">H", body[10:12])
    assert re.fullmatch(rb"hearthscan\d+", body[12 : 12 + length])
    assert len(body) == 12 + length
    assert rest == b"\xe0\x00"  # DISCONNECT and nothing else
    assert service.name == "mqtt"
    assert service.facts == {"connack": str(code)}
    assert service.auth == auth


def test_mqtt_port_with_something_else_on_it(monkeypatch):
    service = run_probe(monkeypatch, greet(b"HTTP/1.1 400 Bad Request\r\n\r\n"), "mqtt")
    assert service.auth is None
    assert service.facts == {}


def adb_message(command: bytes, arg0: int, arg1: int, payload: bytes) -> bytes:
    (number,) = struct.unpack("<I", command)
    header = struct.pack("<6I", number, arg0, arg1, len(payload), sum(payload), number ^ 0xFFFFFFFF)
    return header + payload


def adb_device(answer: bytes, requests: list[bytes], rest: bytearray):
    async def handler(reader, writer):
        header = await reader.readexactly(24)
        requests.append(header + await reader.readexactly(struct.unpack("<6I", header)[3]))
        writer.write(answer)
        await writer.drain()
        await record(reader, rest)

    return handler


def test_adb_device_that_lets_anyone_in(monkeypatch):
    requests, rest = [], bytearray()
    banner = b"device::ro.product.name=attic_tab;ro.product.model=Attic Tab 10;features=shell_v2"
    answer = adb_message(b"CNXN", 0x01000001, 4096, banner)
    service = run_probe(monkeypatch, adb_device(answer, requests, rest), "adb")
    assert requests == [adb_message(b"CNXN", 0x01000001, 256 * 1024, b"host::\0")]
    assert rest == b""
    assert service.name == "adb"
    assert service.auth == "none"
    assert service.facts == {"state": "device"}
    assert service.product == "Attic Tab 10"


def test_adb_device_that_asks_for_a_key_gets_nothing_more(monkeypatch):
    requests, rest = [], bytearray()
    answer = adb_message(b"AUTH", 1, 0, bytes(range(20)))
    service = run_probe(monkeypatch, adb_device(answer, requests, rest), "adb")
    assert len(requests) == 1
    assert rest == b""  # no AUTH packet, no public key
    assert service.auth == "required"
    assert service.facts == {"state": "unauthorized"}
    assert service.product is None


def test_adb_answer_with_a_bad_magic_is_ignored(monkeypatch):
    answer = bytearray(adb_message(b"CNXN", 0x01000001, 4096, b"device::"))
    answer[20] ^= 0xFF
    service = run_probe(monkeypatch, adb_device(bytes(answer), [], bytearray()), "adb")
    assert service.auth is None


def smb_header(protocol: bytes, status: int = 0) -> bytes:
    return protocol + b"\x72" + struct.pack("<I", status) + b"\x98\x53\xc8" + bytes(20)


def netbios(message: bytes) -> bytes:
    return b"\x00" + len(message).to_bytes(3, "big") + message


SMB1_ACCEPTED = netbios(smb_header(b"\xffSMB") + b"\x11" + struct.pack("<H", 0) + bytes(34))
SMB1_NO_DIALECT = netbios(smb_header(b"\xffSMB") + b"\x01" + b"\xff\xff" + b"\x00\x00")
SMB1_REFUSED = netbios(smb_header(b"\xffSMB", 0xC00000BB) + b"\x00\x00\x00")
SMB2_ANSWER = netbios(b"\xfeSMB" + bytes(60))


@pytest.mark.parametrize(
    ("answer", "smb1"),
    [
        (SMB1_ACCEPTED, "yes"),
        (SMB1_NO_DIALECT, "no"),
        (SMB1_REFUSED, "no"),
        (SMB2_ANSWER, "no"),
        (None, "no"),
    ],
)
def test_smb1_negotiate(monkeypatch, answer, smb1):
    requests = []

    async def handler(reader, writer):
        head = await reader.readexactly(4)
        requests.append(head + await reader.readexactly(int.from_bytes(head[1:], "big")))
        if answer is not None:  # None: hang up, like Windows with SMB1 off
            writer.write(answer)
            await writer.drain()
            await record(reader, bytearray())

    service = run_probe(monkeypatch, handler, "smb")
    request = requests[0]
    assert request[4:9] == b"\xffSMB\x72"
    assert request[36] == 0  # no parameter words
    (count,) = struct.unpack("<H", request[37:39])
    assert request[39:] == b"\x02NT LM 0.12\x00"
    assert count == len(request) - 39
    assert service.facts == {"smb1": smb1}


@pytest.mark.parametrize(("reply", "auth"), [(b"\x05\x00", "none"), (b"\x05\xff", "required")])
def test_socks5_methods(monkeypatch, reply, auth):
    sent = bytearray()

    async def handler(reader, writer):
        sent.extend(await reader.readexactly(3))
        writer.write(reply)
        await writer.drain()
        await record(reader, sent)

    service = run_probe(monkeypatch, handler, "socks")
    assert sent == b"\x05\x01\x00"  # no CONNECT after the method choice
    assert service.name == "socks"
    assert service.facts == {"version": "5"}
    assert service.auth == auth


@pytest.mark.parametrize("answer", [b"S", b"N"])
def test_postgresql_ssl_request(monkeypatch, answer):
    sent = bytearray()

    async def handler(reader, writer):
        sent.extend(await reader.readexactly(8))
        writer.write(answer)
        await writer.drain()
        await record(reader, sent)

    service = run_probe(monkeypatch, handler, "postgresql")
    assert sent == struct.pack(">II", 8, 80877103)
    assert service.name == "postgresql"
    assert service.facts == {"ssl": answer.decode()}


# Ports left alone


def test_printer_ports_get_no_probe():
    for port in (9100, 515, 62078, 8009, 135, 139, 7000):
        assert probes.PROBES[port] == "none"


def test_left_alone_port_gets_no_connection(monkeypatch):
    connections = []

    async def handler(reader, writer):
        connections.append(await reader.read(100))

    service = run_probe(monkeypatch, handler, "none")
    assert connections == []
    assert service == Service(service.port)


@pytest.mark.parametrize("port", [9101, 9102, 9103])
def test_more_raw_print_ports_are_left_alone(port):
    assert probes.PROBES[port] == "none"


def test_port_9100_gets_no_bytes():
    connections = []

    async def handler(reader, writer):
        connections.append(await reader.read(100))
        writer.close()

    async def main():
        try:
            server = await asyncio.start_server(handler, "127.0.0.1", 9100)
        except OSError:
            pytest.skip("port 9100 is taken on this machine")
        async with server:
            service = await probe("127.0.0.1", 9100)
            await asyncio.sleep(0.2)
        return service

    service = asyncio.run(main())
    assert connections == []
    assert service == Service(9100, name="jetdirect")


# Hostile services


def test_endless_data_is_cut_off(monkeypatch):
    async def handler(reader, writer):
        chunk = b"A" * 65536
        for _ in range(1024):
            if writer.is_closing():
                break
            writer.write(chunk)
            await writer.drain()

    started = time.perf_counter()
    service = run_probe(monkeypatch, handler, timeout=2.0)
    assert time.perf_counter() - started < 2.5
    assert service.banner == "A" * probes.MAX_BANNER


@pytest.mark.parametrize("kind", ["web", "rsync", "redis", "memcached", "rtsp", "telnet"])
def test_huge_line_is_cut_off(monkeypatch, kind):
    async def handler(reader, writer):
        writer.write(b"x" * (1 << 20))
        await writer.drain()
        await record(reader, bytearray())

    started = time.perf_counter()
    service = run_probe(monkeypatch, handler, kind, timeout=2.0)
    assert time.perf_counter() - started < 2.5
    assert service.banner is None or len(service.banner) <= probes.MAX_BANNER


KINDS = sorted({*probes.PROBES.values(), "unknown"} - {"none"})


@pytest.mark.parametrize("kind", KINDS)
def test_garbage_never_escapes(monkeypatch, kind):
    noise = random.Random(kind).randbytes(2048)

    started = time.perf_counter()
    service = run_probe(monkeypatch, greet(noise), kind, timeout=1.0)
    assert time.perf_counter() - started < 1.5
    assert isinstance(service, Service)
    assert service.auth is None
    for text in (service.banner, service.product, service.title, *service.facts.values()):
        assert text is None or text.isprintable()


@pytest.mark.parametrize("kind", KINDS)
def test_silent_service_returns_by_the_deadline(monkeypatch, kind):
    async def handler(reader, writer):
        await record(reader, bytearray())

    started = time.perf_counter()
    service = run_probe(monkeypatch, handler, kind, timeout=0.4)
    assert time.perf_counter() - started < 0.9
    assert service.auth is None


def test_closed_port_returns_the_plain_service(monkeypatch):
    async def main():
        server, port = await start(lambda reader, writer: asyncio.sleep(0))
        server.close()
        await server.wait_closed()
        monkeypatch.setitem(probes.PROBES, port, "redis")
        return port, await probe("127.0.0.1", port, timeout=1.0)

    port, service = asyncio.run(main())
    assert service == Service(port, name=ports.SERVICE_NAMES.get(port, ""))


def test_clean():
    assert probes._clean("  a\x00b\r\n\x1b[31mred\x1b[0m\u2028c  ", 50) == "a b red c"
    assert probes._clean(b"caf\xc3\xa9 \xff", 50) == "caf\u00e9 \ufffd"
    assert probes._clean("\x00\x01 ", 50) is None
    assert probes._clean("x" * 10, 4) == "xxxx"
    assert probes._clean(None, 4) is None


@pytest.mark.parametrize(
    ("banner", "product"),
    [
        ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "OpenSSH 9.6p1"),
        ("SSH-2.0-dropbear_2022.83", "dropbear 2022.83"),
        ("SSH-2.0-OpenSSH_for_Windows_9.5", "OpenSSH for Windows 9.5"),
        ("SSH-1.99-Cisco-1.25", "Cisco-1.25"),
        ("SSH-2.0-ROSSSH", "ROSSSH"),
        ("SSH-2.0-ssh", None),
        ("Please wait\r\nSSH-2.0-OpenSSH_8.4", "OpenSSH 8.4"),
    ],
)
def test_ssh_product(banner, product):
    assert probes._ssh_product(banner + "\r\n") == product


@pytest.mark.parametrize(
    ("banner", "name", "product"),
    [
        ("220 (vsFTPd 3.0.5)", "ftp", "vsFTPd 3.0.5"),
        ("220 ProFTPD Server (Debian) [::ffff:192.168.1.2]", "ftp", "ProFTPD"),
        ("220---------- Welcome to Pure-FTPd [privsep] ----------", "ftp", "Pure-FTPd"),
        (
            "220-FileZilla Server 1.8.0\r\n220 Please visit the project page",
            "ftp",
            "FileZilla Server 1.8.0",
        ),
        ("220 attic.lan ESMTP Postfix (Debian)", "smtp", "Postfix"),
        ("+OK Dovecot ready.", "pop3", "Dovecot"),
        ("* OK [CAPABILITY IMAP4rev1] Dovecot ready.", "imap", "Dovecot"),
        ("220 Operation successful", None, None),
    ],
)
def test_greeting_name_and_product(banner, name, product):
    service = Service(2121)
    probes._note_greeting(service, banner.encode() + b"\r\n")
    assert service.name == (name or "")
    assert service.product == product


# Arguments


@pytest.mark.parametrize("ip", ["8.8.8.8", "2001:4860:4860::8888", "100.64.0.1", "::ffff:8.8.8.8"])
def test_public_addresses_are_refused(ip):
    with pytest.raises(ScopeError):
        asyncio.run(probe(ip, 80))


@pytest.mark.parametrize("ip", ["attic.local", "", "192.168.1", "192.168.1.300"])
def test_names_and_garbage_addresses_are_refused(ip):
    with pytest.raises(ValueError):
        asyncio.run(probe(ip, 80))


@pytest.mark.parametrize("port", [0, -1, 65536, True, "80", 80.0])
def test_bad_ports_are_refused(port):
    with pytest.raises(ValueError):
        asyncio.run(probe("192.168.1.2", port))


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf, "2"])
def test_bad_timeouts_are_refused(timeout):
    with pytest.raises(ValueError):
        asyncio.run(probe("192.168.1.2", 22, timeout=timeout))


# probe_all


def test_probe_all_keys_results_by_target(monkeypatch):
    done = []

    async def main():
        ssh, ssh_port = await start(greet(b"SSH-2.0-dropbear_2022.83\r\n"))
        redis, redis_port = await start(greet(b"+PONG\r\n"))
        claim(monkeypatch, ssh_port, None)
        claim(monkeypatch, redis_port, "redis")
        targets = [("127.0.0.1", redis_port), ("127.0.0.1", ssh_port), ("127.0.0.1", 9100)]
        async with ssh, redis:
            results = await probe_all(
                targets + targets[:1], timeout=2.0, on_done=lambda ip, s: done.append((ip, s.port))
            )
        return targets, results

    targets, results = asyncio.run(main())
    assert list(results) == targets
    assert results[targets[0]].auth == "none"
    assert results[targets[1]].product == "dropbear 2022.83"
    assert results[targets[2]] == Service(9100, name="jetdirect")
    assert sorted(done) == sorted((ip, port) for ip, port in targets)


def test_probe_all_respects_concurrency(monkeypatch):
    running = 0
    most = 0

    async def fake_probe(ip, port, *, timeout):
        nonlocal running, most
        running += 1
        most = max(most, running)
        await asyncio.sleep(0.02)
        running -= 1
        return Service(port)

    monkeypatch.setattr(probes, "probe", fake_probe)
    targets = [("192.168.1.2", port) for port in range(1, 21)]
    results = asyncio.run(probe_all(targets, concurrency=3))
    assert most == 3
    assert list(results) == targets


def test_cancelling_probe_all_leaves_nothing_running(monkeypatch):
    async def slow_probe(ip, port, *, timeout):
        await asyncio.sleep(30)

    monkeypatch.setattr(probes, "probe", slow_probe)

    async def main():
        task = asyncio.ensure_future(probe_all([("192.168.1.2", p) for p in range(1, 100)]))
        await asyncio.sleep(0.1)
        started = time.perf_counter()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        leftovers = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        return time.perf_counter() - started, leftovers

    elapsed, leftovers = asyncio.run(main())
    assert elapsed < 1
    assert leftovers == []


def test_cancelling_probe_all_closes_the_connections(monkeypatch):
    async def main():
        connected = asyncio.Event()
        closed = []

        async def handler(reader, writer):
            connected.set()
            await record(reader, bytearray())
            closed.append(True)

        servers = [await start(handler) for _ in range(3)]
        for _, port in servers:
            claim(monkeypatch, port, "redis")
        targets = [("127.0.0.1", port) for _, port in servers]
        task = asyncio.ensure_future(probe_all(targets, timeout=30))
        await asyncio.wait_for(connected.wait(), 5)
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        for server, _ in servers:
            server.close()
        deadline = time.perf_counter() + 2
        while len(closed) < 3 and time.perf_counter() < deadline:
            await asyncio.sleep(0.02)
        return len(closed)

    assert asyncio.run(main()) == 3


def test_a_failing_callback_stops_the_other_probes(monkeypatch):
    async def quick_probe(ip, port, *, timeout):
        await asyncio.sleep(0.01)
        return Service(port)

    def explode(ip, service):
        raise RuntimeError("callback broke")

    monkeypatch.setattr(probes, "probe", quick_probe)

    async def main():
        with pytest.raises(RuntimeError):
            await probe_all([("192.168.1.2", p) for p in range(1, 100)], on_done=explode)
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []


def test_probe_all_checks_every_target_first(monkeypatch):
    called = []

    async def fake_probe(ip, port, *, timeout):
        called.append(ip)
        return Service(port)

    monkeypatch.setattr(probes, "probe", fake_probe)
    with pytest.raises(ScopeError):
        asyncio.run(probe_all([("192.168.1.2", 22), ("8.8.8.8", 22)]))
    with pytest.raises(ValueError):
        asyncio.run(probe_all([("192.168.1.2", 0)]))
    for concurrency in (0, -1, 1.5, True):
        with pytest.raises(ValueError):
            asyncio.run(probe_all([("192.168.1.2", 22)], concurrency=concurrency))
    assert called == []
    assert asyncio.run(probe_all([])) == {}


def test_a_slow_charset_is_not_honoured():
    from hearthscan import http

    body = b"-" + b"9" * 32766 + b"a"
    response = http.Response(
        "http://192.168.1.2/", 200, "OK", {"content-type": "text/html; charset=punycode"}, body
    )
    started = time.perf_counter()
    assert response.text().startswith("-999")
    assert time.perf_counter() - started < 0.1


@pytest.mark.parametrize(
    ("charset", "text"),
    [("iso-8859-9", "\u015fifre"), ("windows-1254", "\u015fifre"), ("utf-8", "\u015fifre")],
)
def test_real_page_charsets_are_still_used(charset, text):
    from hearthscan import http

    response = http.Response(
        "http://192.168.1.2/",
        200,
        "OK",
        {"content-type": f"text/html; charset={charset}"},
        text.encode(charset if charset != "windows-1254" else "cp1254"),
    )
    assert response.text() == text


def test_password_search_stays_fast_on_crafted_pages():
    page_text = "<input" * 6000
    started = time.perf_counter()
    probes._PASSWORD_INPUT.search(page_text)
    assert time.perf_counter() - started < 0.1
