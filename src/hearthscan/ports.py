"""Asynchronous TCP connect scanner.

It needs no raw sockets, so it runs without admin rights on every platform.
A port is open when the handshake completes, closed when the host answers with
a reset, and filtered when nothing usable comes back before the timeout.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import math
import socket
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

from . import _winsock
from .scope import ScopeError, is_local
from .system import IS_WINDOWS


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass(slots=True)
class PortResult:
    host: str
    port: int
    state: PortState
    rtt: float | None = None
    reason: str | None = None


# What tends to listen on a home network: remote access, file sharing,
# printers, cameras and recorders, router management, media boxes, and the
# odd database or dev server someone forgot about.
SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    81: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    515: "lpd",
    548: "afp",
    554: "rtsp",
    631: "ipp",
    873: "rsync",
    1080: "socks",
    1433: "mssql",
    1723: "pptp",
    1883: "mqtt",
    1900: "upnp",
    2049: "nfs",
    3000: "http",
    3306: "mysql",
    3389: "rdp",
    5000: "http",
    5001: "https",
    5060: "sip",
    5357: "wsdapi",
    5432: "postgresql",
    5555: "adb",
    5900: "vnc",
    6379: "redis",
    7000: "airplay",
    7547: "cwmp",
    8000: "http",
    8008: "http",
    8009: "cast",
    8080: "http",
    8081: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9100: "jetdirect",
    9200: "elasticsearch",
    10000: "webmin",
    11211: "memcached",
    27017: "mongodb",
    32400: "plex",
    34567: "dvr",
    37777: "dahua-dvr",
    49152: "upnp",
    62078: "iphone-sync",
}
HOME_PORTS: tuple[int, ...] = tuple(SERVICE_NAMES)

# Every pair gets a result kept in memory, so "all ports on every host" has to
# be stopped before it eats gigabytes.
MAX_PAIRS = 1 << 18

# Windows reports error 121 (ERROR_SEM_TIMEOUT) when a connect without SYN
# retransmissions runs out of time. 1231 and 1232 come from ConnectEx.
_TIMEOUT_ERRORS = {errno.ETIMEDOUT, 121}
_UNREACHABLE_ERRORS = {
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EHOSTDOWN,
    errno.ENETDOWN,
    1231,
    1232,
}
# A local firewall or OS policy said no (Windows refuses TCP to port 137, for one).
_BLOCKED_ERRORS = {errno.EACCES, errno.EPERM, 10013}
_OUT_OF_SOCKETS = {errno.EMFILE, errno.ENFILE, errno.ENOBUFS}
if not IS_WINDOWS:
    # Linux and macOS say this when the ephemeral ports run out. On Windows the
    # same name means the target address itself is invalid.
    _OUT_OF_SOCKETS.add(errno.EADDRNOTAVAIL)

_WINDOWS_GRACE = 0.25
_BACKOFF = 0.1


def parse_ports(spec: str) -> list[int]:
    """Parse "22,80,8000-8100" style lists. Keeps the order, drops duplicates."""
    ports: dict[int, None] = {}
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        low, dash, high = chunk.partition("-")
        try:
            start = int(low)
            end = int(high) if dash else start
        except ValueError:
            raise ValueError(f"not a port or port range: {chunk!r}") from None
        if not 1 <= start <= end <= 65535:
            raise ValueError(f"bad port range: {chunk!r}")
        ports.update(dict.fromkeys(range(start, end + 1)))
    if not ports:
        raise ValueError("no ports given")
    return list(ports)


def _check_timeout(timeout: float) -> None:
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError(f"timeout must be a positive number of seconds, not {timeout!r}")


def _check_port(port: int) -> None:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"not a valid port: {port!r}")


def _plain(host: str) -> str:
    ip = ipaddress.ip_address(host)
    if ip.version == 6 and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)
    return host


def _codes(exc: OSError) -> set[int]:
    return {code for code in (exc.errno, getattr(exc, "winerror", None)) if code is not None}


def _reason(exc: OSError) -> str:
    """A short, untranslated reason. strerror comes in the system language."""
    codes = _codes(exc)
    if codes & _TIMEOUT_ERRORS:
        return "timeout"
    if codes & _UNREACHABLE_ERRORS:
        return "unreachable"
    if codes & _BLOCKED_ERRORS:
        return "blocked"
    for code in (getattr(exc, "winerror", None), exc.errno):
        if code in errno.errorcode:
            return errno.errorcode[code]
    return f"error {min(codes)}" if codes else "error"


async def _connect(sock: socket.socket, address: tuple) -> None:
    await asyncio.get_running_loop().sock_connect(sock, address)


async def _connect_within(sock: socket.socket, address: tuple, deadline: float) -> bool:
    """Connect, giving up after `deadline` seconds. Returns False on timeout.

    This avoids asyncio.wait_for on purpose: before Python 3.12 it can swallow a
    cancellation that lands just as the connect completes, and a stopped scan
    then keeps going.
    """
    attempt = asyncio.ensure_future(_connect(sock, address))
    try:
        await asyncio.wait({attempt}, timeout=deadline)
    finally:
        if not attempt.done():
            attempt.cancel()
            # Let the cancellation reach the OS before the socket gets closed.
            await asyncio.wait({attempt})
        elif not attempt.cancelled():
            attempt.exception()  # mark it as seen, even when we are unwinding
    if attempt.cancelled():
        return False
    attempt.result()
    return True


async def probe(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """Try one TCP handshake with a numeric address.

    Raises OSError only when the system runs out of sockets, which says
    nothing about the port and should be retried.
    """
    _check_timeout(timeout)
    _check_port(port)
    host = _plain(host)
    # The proactor loop on Windows passes the address straight to ConnectEx,
    # which reads any 2-tuple as IPv4. getaddrinfo gives IPv6 the 4-tuple it
    # needs, scope id included.
    family, _, _, _, address = socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST
    )[0]
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as exc:
        if _codes(exc) & _OUT_OF_SOCKETS:
            raise
        return PortResult(host, port, PortState.FILTERED, reason=_reason(exc))

    try:
        sock.setblocking(False)
        deadline = timeout
        if IS_WINDOWS:
            if _winsock.fail_fast(sock, timeout):
                deadline = timeout + _WINDOWS_GRACE
            else:
                # Without the ioctl a reset takes ~2 s to show up. Don't call that silence.
                deadline = max(timeout, 2.5)

        started = time.perf_counter()
        try:
            connected = await _connect_within(sock, address, deadline)
        except ConnectionRefusedError:
            return PortResult(host, port, PortState.CLOSED, time.perf_counter() - started)
        except (ConnectionResetError, BrokenPipeError):
            # The handshake went through and the service hung up before we looked.
            elapsed = time.perf_counter() - started
            return PortResult(host, port, PortState.OPEN, elapsed, "reset after connect")
        except OSError as exc:
            if _codes(exc) & _OUT_OF_SOCKETS:
                raise
            return PortResult(host, port, PortState.FILTERED, reason=_reason(exc))

        if not connected:
            return PortResult(host, port, PortState.FILTERED, reason="timeout")
        return PortResult(host, port, PortState.OPEN, time.perf_counter() - started)
    finally:
        sock.close()


async def _probe_patiently(host: str, port: int, timeout: float) -> PortResult:
    for attempt in range(6):
        try:
            return await probe(host, port, timeout)
        except OSError:
            # Out of sockets or buffer space. Give the OS a moment to recycle some.
            await asyncio.sleep(_BACKOFF * (attempt + 1))
    return PortResult(host, port, PortState.FILTERED, reason="out of sockets")


def _usable_concurrency(wanted: int) -> int:
    """Fit the number of parallel connects under the open file limit.

    macOS starts processes with a soft limit of 256 descriptors, which a scan
    hits fast, so the soft limit gets raised when the hard limit allows it.
    """
    try:
        import resource
    except ImportError:  # Windows
        return max(1, wanted)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = wanted + 64
    if soft != resource.RLIM_INFINITY and soft < needed:
        target = needed if hard == resource.RLIM_INFINITY else min(needed, hard)
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
        except (ValueError, OSError):
            pass
    if soft == resource.RLIM_INFINITY:
        return max(1, wanted)
    return max(1, min(wanted, soft - 64))


async def scan(
    hosts: Iterable[str],
    ports: Iterable[int],
    *,
    timeout: float = 1.0,
    concurrency: int = 256,
    retry_filtered: bool = True,
    on_open: Callable[[PortResult], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[PortResult]:
    """Probe every host/port pair. Returns one result per pair, in input order.

    `hosts` must be IP addresses on a local network (see scope.expand).
    Filtered ports get a second probe, but only on hosts that answered on some
    other port: a lost SYN on a live host is worth retrying, a host that drops
    everything is not. `on_progress(done, total)` counts the first pass only;
    the retry pass after it is short and reports nothing but open ports.
    """
    _check_timeout(timeout)
    hosts = list(dict.fromkeys(_plain(host) for host in hosts))
    for host in hosts:
        if not is_local(host):
            raise ScopeError(f"{host} is not on a private network")
    ports = list(dict.fromkeys(ports))
    for port in ports:
        _check_port(port)
    if len(hosts) * len(ports) > MAX_PAIRS:
        raise ValueError(
            f"{len(hosts)} hosts x {len(ports)} ports is more than {MAX_PAIRS} probes; "
            "scan fewer hosts or ports at a time"
        )

    jobs = [(host, port) for host in hosts for port in ports]
    limit = _usable_concurrency(concurrency)
    done = 0

    def first_pass(result: PortResult) -> None:
        nonlocal done
        done += 1
        if on_open and result.state is PortState.OPEN:
            on_open(result)
        if on_progress:
            on_progress(done, len(jobs))

    def second_pass(result: PortResult) -> None:
        if on_open and result.state is PortState.OPEN:
            on_open(result)

    results = await _run(jobs, timeout, limit, first_pass)
    if retry_filtered:
        alive = {r.host for r in results.values() if r.state is not PortState.FILTERED}
        again = [
            key for key, r in results.items() if r.state is PortState.FILTERED and r.host in alive
        ]
        if again:
            results.update(await _run(again, timeout, limit, second_pass))
    return [results[job] for job in jobs]


async def _run(
    jobs: list[tuple[str, int]],
    timeout: float,
    limit: int,
    record: Callable[[PortResult], None],
) -> dict[tuple[str, int], PortResult]:
    results: dict[tuple[str, int], PortResult] = {}
    pending = iter(jobs)

    async def worker() -> None:
        # Workers share one iterator, so each pair is handed out exactly once.
        for host, port in pending:
            result = await _probe_patiently(host, port, timeout)
            results[host, port] = result
            record(result)

    workers = [asyncio.ensure_future(worker()) for _ in range(min(limit, len(jobs)))]
    try:
        await asyncio.gather(*workers)
    except BaseException:
        # A callback blew up or we were cancelled. Don't leave the others running.
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise
    return results
