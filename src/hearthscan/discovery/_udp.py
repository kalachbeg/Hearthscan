"""Send a batch of datagrams from one socket and collect what comes back."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Callable, Iterable

from .. import _winsock
from ..system import IS_LINUX, IS_WINDOWS

# Nothing on a LAN should flood us, but a broken or hostile device could try.
MAX_REPLIES = 8192
MAX_DATAGRAM = 9000

# Linux's IP_MULTICAST_ALL from <linux/in.h>; the socket module does not have it.
_IP_MULTICAST_ALL = 49


class _Collector(asyncio.DatagramProtocol):
    def __init__(
        self,
        on_reply: Callable[[bytes, str], None] | None,
        *,
        max_replies: int = MAX_REPLIES,
        per_sender: int | None = None,
    ) -> None:
        self.replies: list[tuple[bytes, str]] = []
        self.on_reply = on_reply
        self.max_replies = max_replies
        self.per_sender = per_sender
        self.from_sender: dict[str, int] = {}
        self.received = 0
        self.errors = 0
        self.last_error: OSError | None = None

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.received += 1
        if len(self.replies) >= self.max_replies or len(data) > MAX_DATAGRAM:
            return
        sender = addr[0]
        if self.per_sender is not None:
            count = self.from_sender.get(sender, 0)
            if count >= self.per_sender:
                return
            self.from_sender[sender] = count + 1
        self.replies.append((data, sender))
        if self.on_reply:
            self.on_reply(data, sender)

    def error_received(self, exc: Exception) -> None:
        # Unreachable hosts and ports, mostly. Counted so that a socket the OS
        # will not let send at all can be told apart from a quiet network.
        if isinstance(exc, OSError):
            self.errors += 1
            self.last_error = exc


def open_socket(
    local: str,
    *,
    multicast_ttl: int | None = None,
    join: tuple[str, int] | None = None,
) -> socket.socket:
    """A non-blocking UDP socket bound to `local` on a random port.

    With `multicast_ttl` set, multicast goes out of the interface that owns
    `local`. Without that the OS picks by routing table, and a VPN that grabs
    the default route would swallow the query.

    With `join`, a (group, port) pair, the socket is bound to that port on all
    addresses instead, shared with whatever else holds it, and joins the group
    on the interface that owns `local`.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        if IS_WINDOWS:
            _winsock.ignore_udp_resets(sock)
        if join is None:
            sock.bind((local, 0))
        else:
            group, port = join
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Linux shares the port among sockets that all set SO_REUSEADDR, as
            # Avahi does. On macOS and the BSDs mDNSResponder holds it with
            # SO_REUSEPORT, so that is needed as well.
            if not IS_LINUX and hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("0.0.0.0", port))
            if IS_LINUX:
                # Otherwise Linux hands us the group's traffic from every
                # interface some other program joined it on.
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_IP, _IP_MULTICAST_ALL, 0)
            membership = socket.inet_aton(group) + socket.inet_aton(local)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        if multicast_ttl is not None:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, multicast_ttl)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    except BaseException:
        sock.close()
        raise
    return sock


async def exchange(
    packets: Iterable[tuple[bytes, tuple[str, int]]],
    *,
    local: str,
    listen: float,
    spacing: float = 0.0,
    multicast_ttl: int | None = None,
    on_reply: Callable[[bytes, str], None] | None = None,
    max_replies: int = MAX_REPLIES,
    per_sender: int | None = None,
    join: tuple[str, int] | None = None,
) -> list[tuple[bytes, str]]:
    """Send every packet, then keep listening for `listen` seconds.

    Returns (payload, sender address) pairs in arrival order, at most
    `max_replies` of them and at most `per_sender` from any one address.
    `spacing` puts a pause between sends so a sweep of a whole /24 does not go
    out as one burst that cheap routers and Wi-Fi drop. `join` is passed on to
    open_socket.

    Send errors (a host that is gone, say) are ignored, this being best effort
    by nature. Only when every send failed and nothing came back is the last
    error raised, since then the OS is blocking us and the caller should say so.
    """
    loop = asyncio.get_running_loop()
    sock = open_socket(local, multicast_ttl=multicast_ttl, join=join)
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _Collector(on_reply, max_replies=max_replies, per_sender=per_sender),
            sock=sock,
        )
    except BaseException:
        sock.close()
        raise
    try:
        # Pace against a schedule instead of sleeping `spacing` each time:
        # Windows timers tick every 15.6 ms, so sleep(0.002) really takes 15.
        started = loop.time()
        sent = 0
        for i, (payload, address) in enumerate(packets):
            if spacing:
                ahead = started + i * spacing - loop.time()
                if ahead > 0:
                    await asyncio.sleep(ahead)
            # The transport reports send errors to error_received; this only
            # catches one raised before the datagram reaches it.
            try:
                transport.sendto(payload, address)
            except OSError as exc:
                protocol.error_received(exc)
            sent += 1
        await asyncio.sleep(listen)
        error = protocol.last_error
        if sent and error is not None and protocol.errors >= sent and not protocol.received:
            raise error
        return list(protocol.replies)
    finally:
        # Not close(): on the Windows proactor loop that leaves the socket open
        # while a send is still in flight or after one failed.
        transport.abort()
