import asyncio
import errno
import math
import socket
import sys
import time

import pytest

from hearthscan import ports
from hearthscan.ports import PortResult, PortState, parse_ports, probe, scan
from hearthscan.scope import ScopeError

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


def unused_port(host: str = "127.0.0.1") -> int:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
    except OSError:
        return False
    return True


async def listener(host: str = "127.0.0.1"):
    server = await asyncio.start_server(lambda r, w: w.close(), host, 0)
    return server, server.sockets[0].getsockname()[1]


def test_parse_ports_keeps_order_and_drops_duplicates():
    assert parse_ports("443, 22,8000-8002,22") == [443, 22, 8000, 8001, 8002]


@pytest.mark.parametrize("spec", ["", " , ", "0", "65536", "90-80", "http", "1-2-3"])
def test_parse_ports_rejects_garbage(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_probe_open_and_closed():
    async def main():
        server, port = await listener()
        async with server:
            return await probe("127.0.0.1", port, 2.0), await probe("127.0.0.1", unused_port(), 2.0)

    opened, closed = asyncio.run(main())
    assert opened.state is PortState.OPEN
    assert closed.state is PortState.CLOSED


@pytest.mark.skipif(not has_ipv6_loopback(), reason="no IPv6 loopback")
def test_probe_ipv6():
    async def main():
        server, port = await listener("::1")
        async with server:
            return await probe("::1", port, 2.0), await probe("::1", unused_port("::1"), 2.0)

    opened, closed = asyncio.run(main())
    assert opened.state is PortState.OPEN
    assert closed.state is PortState.CLOSED


def test_ipv4_mapped_address_is_probed_as_ipv4():
    async def main():
        server, port = await listener()
        async with server:
            return await probe("::ffff:127.0.0.1", port, 2.0)

    result = asyncio.run(main())
    assert result.state is PortState.OPEN
    assert result.host == "127.0.0.1"


@windows_only
def test_refused_port_is_reported_quickly_on_windows():
    result = asyncio.run(probe("127.0.0.1", unused_port(), 1.0))
    assert result.state is PortState.CLOSED
    assert result.rtt < 0.5


def test_timeout_means_filtered(monkeypatch):
    async def silence(sock, address):
        await asyncio.sleep(10)

    monkeypatch.setattr(ports, "_connect", silence)
    result = asyncio.run(probe("127.0.0.1", 9, 0.05))
    assert result.state is PortState.FILTERED
    assert result.reason == "timeout"


@pytest.mark.parametrize(
    "code, reason",
    [
        (errno.EHOSTUNREACH, "unreachable"),
        (errno.ETIMEDOUT, "timeout"),
        (errno.EACCES, "blocked"),
        (errno.EINVAL, "EINVAL"),
    ],
)
def test_connect_errors_are_filtered(monkeypatch, code, reason):
    async def fail(sock, address):
        raise OSError(code, "nope")

    monkeypatch.setattr(ports, "_connect", fail)
    result = asyncio.run(probe("192.168.77.77", 80, 1.0))
    assert (result.state, result.reason) == (PortState.FILTERED, reason)


@windows_only
@pytest.mark.parametrize("winerror, reason", [(121, "timeout"), (1231, "unreachable")])
def test_windows_connect_errors_are_filtered(monkeypatch, winerror, reason):
    async def fail(sock, address):
        raise OSError(None, "nope", None, winerror)

    monkeypatch.setattr(ports, "_connect", fail)
    result = asyncio.run(probe("192.168.77.77", 80, 1.0))
    assert (result.state, result.reason) == (PortState.FILTERED, reason)


def test_reset_right_after_the_handshake_still_counts_as_open(monkeypatch):
    async def reset(sock, address):
        raise ConnectionResetError(errno.ECONNRESET, "Connection reset by peer")

    monkeypatch.setattr(ports, "_connect", reset)
    result = asyncio.run(probe("192.168.1.10", 8080, 1.0))
    assert result.state is PortState.OPEN


def test_scan_against_real_listeners():
    async def main():
        server_a, open_a = await listener()
        server_b, open_b = await listener()
        closed = unused_port()
        async with server_a, server_b:
            results = await scan(["127.0.0.1"], [open_a, closed, open_b], timeout=2.0)
        return results, [open_a, closed, open_b]

    results, wanted = asyncio.run(main())
    assert [r.port for r in results] == wanted
    assert [r.state for r in results] == [PortState.OPEN, PortState.CLOSED, PortState.OPEN]


def test_scan_retries_filtered_ports_only_on_hosts_that_answer(monkeypatch):
    calls = []

    async def fake_probe(host, port, timeout):
        calls.append((host, port))
        if (host, port) == ("10.0.0.1", 22):
            return PortResult(host, port, PortState.OPEN, 0.001)
        if (host, port) == ("10.0.0.1", 80) and calls.count((host, port)) == 2:
            return PortResult(host, port, PortState.CLOSED, 0.001)
        return PortResult(host, port, PortState.FILTERED, reason="timeout")

    monkeypatch.setattr(ports, "probe", fake_probe)
    opened = []
    progress = []
    results = asyncio.run(
        scan(
            ["10.0.0.1", "10.0.0.2"],
            [22, 80],
            on_open=opened.append,
            on_progress=lambda *t: progress.append(t),
        )
    )

    assert [(r.host, r.port, r.state) for r in results] == [
        ("10.0.0.1", 22, PortState.OPEN),
        ("10.0.0.1", 80, PortState.CLOSED),
        ("10.0.0.2", 22, PortState.FILTERED),
        ("10.0.0.2", 80, PortState.FILTERED),
    ]
    assert calls.count(("10.0.0.1", 80)) == 2
    assert calls.count(("10.0.0.2", 22)) == 1
    assert [r.port for r in opened] == [22]
    assert progress[-1] == (4, 4)


def test_scan_backs_off_when_out_of_sockets(monkeypatch):
    attempts = []

    async def starved(host, port, timeout):
        attempts.append(port)
        if len(attempts) < 3:
            raise OSError(errno.EMFILE, "Too many open files")
        return PortResult(host, port, PortState.OPEN, 0.001)

    monkeypatch.setattr(ports, "probe", starved)
    monkeypatch.setattr(ports, "_BACKOFF", 0)
    results = asyncio.run(scan(["192.168.1.5"], [80]))
    assert results[0].state is PortState.OPEN
    assert len(attempts) == 3


def test_scan_gives_up_when_sockets_never_come_back(monkeypatch):
    async def starved(host, port, timeout):
        raise OSError(errno.EMFILE, "Too many open files")

    monkeypatch.setattr(ports, "probe", starved)
    monkeypatch.setattr(ports, "_BACKOFF", 0)
    (result,) = asyncio.run(scan(["192.168.1.5"], [80]))
    assert (result.state, result.reason) == (PortState.FILTERED, "out of sockets")


def test_scan_respects_concurrency(monkeypatch):
    running = peak = 0

    async def slow_probe(host, port, timeout):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1
        return PortResult(host, port, PortState.CLOSED, 0.01)

    monkeypatch.setattr(ports, "probe", slow_probe)
    asyncio.run(scan(["192.168.0.10"], range(1, 41), concurrency=8))
    assert peak <= 8


def test_cancelling_a_scan_stops_it_quickly(monkeypatch):
    async def silence(sock, address):
        await asyncio.sleep(30)

    monkeypatch.setattr(ports, "_connect", silence)

    async def main():
        task = asyncio.ensure_future(scan(["192.168.1.2"], range(1, 200), timeout=20))
        await asyncio.sleep(0.2)
        started = time.perf_counter()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        leftovers = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        return time.perf_counter() - started, leftovers

    elapsed, leftovers = asyncio.run(main())
    assert elapsed < 2
    assert leftovers == []


def test_a_failing_callback_stops_the_other_workers(monkeypatch):
    async def fake_probe(host, port, timeout):
        await asyncio.sleep(0.01)
        return PortResult(host, port, PortState.OPEN, 0.01)

    def explode(result):
        raise RuntimeError("callback broke")

    monkeypatch.setattr(ports, "probe", fake_probe)

    async def main():
        with pytest.raises(RuntimeError):
            await scan(["192.168.1.3"], range(1, 100), on_open=explode)
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf])
def test_bad_timeouts_are_rejected(timeout):
    with pytest.raises(ValueError):
        asyncio.run(scan(["192.168.1.1"], [80], timeout=timeout))


@pytest.mark.parametrize("port", [0, 65536, True, "80"])
def test_bad_ports_are_rejected(port):
    with pytest.raises(ValueError):
        asyncio.run(scan(["192.168.1.1"], [port]))


def test_too_many_probes_are_rejected(monkeypatch):
    monkeypatch.setattr(ports, "MAX_PAIRS", 10)
    with pytest.raises(ValueError, match="probes"):
        asyncio.run(scan(["192.168.1.1", "192.168.1.2"], range(1, 7)))


def test_scan_refuses_public_hosts():
    with pytest.raises(ScopeError):
        asyncio.run(scan(["192.168.1.1", "1.1.1.1"], [80]))
