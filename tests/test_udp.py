import asyncio
import socket

import pytest

from hearthscan.discovery import _udp


def test_exchange_collects_replies_from_several_hosts():
    async def main():
        loop = asyncio.get_running_loop()

        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.transport.sendto(b"re:" + data, addr)

        servers = []
        for _ in range(2):
            transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
            servers.append(transport)
        try:
            seen = []
            packets = [
                (b"one", servers[0].get_extra_info("sockname")),
                (b"two", servers[1].get_extra_info("sockname")),
            ]
            replies = await _udp.exchange(
                packets,
                local="127.0.0.1",
                listen=0.3,
                spacing=0.01,
                on_reply=lambda data, host: seen.append(data),
            )
        finally:
            for t in servers:
                t.close()
        return replies, seen

    replies, seen = asyncio.run(main())
    assert sorted(replies) == [(b"re:one", "127.0.0.1"), (b"re:two", "127.0.0.1")]
    assert sorted(seen) == [b"re:one", b"re:two"]


def test_unreachable_ports_do_not_break_the_socket():
    def closed_udp_port():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    async def main():
        loop = asyncio.get_running_loop()

        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.transport.sendto(data, addr)

        server, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        try:
            dead = ("127.0.0.1", closed_udp_port())
            packets = [(b"x", dead)] * 5 + [(b"alive", server.get_extra_info("sockname"))]
            return await _udp.exchange(packets, local="127.0.0.1", listen=0.3, spacing=0.01)
        finally:
            server.close()

    assert asyncio.run(main()) == [(b"alive", "127.0.0.1")]


def test_multicast_socket_options():
    sock = _udp.open_socket("127.0.0.1", multicast_ttl=255)
    try:
        ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL)
        assert ttl == 255
    finally:
        sock.close()


def test_spacing_follows_a_schedule_not_a_sleep_per_packet():
    import time

    async def main():
        packets = [(b"x", ("127.0.0.1", 9))] * 200
        started = time.perf_counter()
        await _udp.exchange(packets, local="127.0.0.1", listen=0, spacing=0.001)
        return time.perf_counter() - started

    # 200 packets 1 ms apart: about 0.2 s, not 200 timer ticks (3 s on Windows).
    assert asyncio.run(main()) < 1.0


class Echo(asyncio.DatagramProtocol):
    """Answers every datagram with `copies` numbered replies."""

    def __init__(self, copies=1):
        self.copies = copies

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        for i in range(self.copies):
            self.transport.sendto(data + b"%d" % i, addr)


def test_collector_caps_replies_overall_and_per_sender():
    seen = []
    collector = _udp._Collector(lambda data, host: seen.append(host), max_replies=5, per_sender=2)
    for host in ["10.0.0.1"] * 4 + ["10.0.0.2"] * 4 + ["10.0.0.3"] * 4:
        collector.datagram_received(b"x", (host, 5353))
    kept = ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.3"]
    assert [host for _, host in collector.replies] == kept
    assert seen == kept
    assert collector.received == 12


def test_exchange_applies_the_caps():
    async def main():
        loop = asyncio.get_running_loop()
        server, _ = await loop.create_datagram_endpoint(
            lambda: Echo(copies=20), local_addr=("127.0.0.1", 0)
        )
        try:
            address = server.get_extra_info("sockname")
            plain = await _udp.exchange([(b"go", address)], local="127.0.0.1", listen=0.3)
            per_sender = await _udp.exchange(
                [(b"go", address)], local="127.0.0.1", listen=0.3, per_sender=7
            )
            overall = await _udp.exchange(
                [(b"go", address)], local="127.0.0.1", listen=0.3, max_replies=3
            )
        finally:
            server.close()
        return plain, per_sender, overall

    plain, per_sender, overall = asyncio.run(main())
    assert len(plain) == 20
    assert len(per_sender) == 7
    assert len(overall) == 3


# Broadcast without SO_BROADCAST: the OS refuses every one of these sends.
REFUSED = ("255.255.255.255", 9)


def test_exchange_raises_when_the_os_refuses_every_send():
    async def main():
        await _udp.exchange([(b"x", REFUSED)] * 5, local="127.0.0.1", listen=0.05)

    with pytest.raises(OSError):
        asyncio.run(main())


def test_exchange_keeps_quiet_when_some_sends_get_through():
    async def main():
        loop = asyncio.get_running_loop()
        server, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        try:
            packets = [(b"x", REFUSED)] * 3 + [(b"alive", server.get_extra_info("sockname"))]
            return await _udp.exchange(packets, local="127.0.0.1", listen=0.3)
        finally:
            server.close()

    assert asyncio.run(main()) == [(b"alive0", "127.0.0.1")]


def test_socket_is_released_with_sends_still_queued(monkeypatch):
    # The transport closes its socket right after connection_lost. Without that
    # call the socket stays open until the transport is garbage collected.
    lost = []

    class Collector(_udp._Collector):
        def connection_lost(self, exc):
            lost.append(exc)

    monkeypatch.setattr(_udp, "_Collector", Collector)

    async def main():
        # A burst the transport cannot send at once, then no time to drain it.
        packets = [(b"x" * 1024, ("127.0.0.1", 9))] * 20
        await _udp.exchange(packets, local="127.0.0.1", listen=0)
        await asyncio.sleep(0.1)

    asyncio.run(main())
    assert lost == [None]


class RecordingSocket:
    """Stands in for socket.socket and remembers what was set on it."""

    fail_on = None

    def __init__(self, *args):
        self.calls = []

    def setblocking(self, flag):
        pass

    def setsockopt(self, level, option, value):
        if option == self.fail_on:
            raise OSError("not allowed")
        self.calls.append(("setsockopt", level, option, value))

    def bind(self, address):
        self.calls.append(("bind", address))

    def close(self):
        self.calls.append(("close",))


@pytest.fixture
def recording_socket(monkeypatch):
    monkeypatch.setattr(_udp, "IS_WINDOWS", False)
    reuse_port = getattr(socket, "SO_REUSEPORT", 0x0200)
    monkeypatch.setattr(socket, "SO_REUSEPORT", reuse_port, raising=False)
    monkeypatch.setattr(socket, "socket", RecordingSocket)


@pytest.mark.parametrize("linux", [True, False])
def test_shared_port_socket_joins_the_group(monkeypatch, recording_socket, linux):
    monkeypatch.setattr(_udp, "IS_LINUX", linux)
    sock = _udp.open_socket("192.168.1.10", multicast_ttl=255, join=("224.0.0.251", 5353))
    calls = sock.calls
    bind = calls.index(("bind", ("0.0.0.0", 5353)))
    assert calls.index(("setsockopt", socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)) < bind
    reuse_port = ("setsockopt", socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    if linux:
        assert reuse_port not in calls
    else:
        assert calls.index(reuse_port) < bind
    group = socket.inet_aton("224.0.0.251") + socket.inet_aton("192.168.1.10")
    assert ("setsockopt", socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group) in calls
    interface = socket.inet_aton("192.168.1.10")
    assert ("setsockopt", socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface) in calls
    assert ("close",) not in calls


def test_shared_port_socket_is_closed_when_joining_fails(monkeypatch, recording_socket):
    monkeypatch.setattr(RecordingSocket, "fail_on", socket.IP_ADD_MEMBERSHIP)
    closed = []
    monkeypatch.setattr(RecordingSocket, "close", lambda self: closed.append(self))
    with pytest.raises(OSError):
        _udp.open_socket("192.168.1.10", multicast_ttl=255, join=("224.0.0.251", 5353))
    assert len(closed) == 1
