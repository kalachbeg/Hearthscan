"""The whole audit: find the devices, scan their ports, look closer at what
answers, and judge what it exposes.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from . import __version__, discovery, probes, router, rules, scoring
from . import ports as portscan
from .discovery import classify
from .models import Device, RouterInfo, ScanResult, Service
from .netinfo import NetworkInfo
from .ports import HOME_PORTS, SERVICE_NAMES, PortState

# Probes shake hands over TLS and read pages, which takes longer than a connect.
PROBE_TIMEOUT = 3.0

# Some boxes accept a connection on every port. Past this many open ports the
# rest are dropped rather than probed one by one.
MAX_SERVICES = 512

Progress = Callable[[str, int, int], None]
Note = Callable[[str, str], None]


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _check_timeout(timeout: float) -> None:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(f"timeout must be a positive number of seconds, not {timeout!r}")


def _port_list(ports: Sequence[int]) -> list[int]:
    unique = list(dict.fromkeys(ports))
    for port in unique:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"not a valid port: {port!r}")
    return unique


async def audit(
    info: NetworkInfo,
    *,
    ports: Sequence[int] = HOME_PORTS,
    timeout: float = 1.0,
    probe: bool = True,
    on_progress: Progress | None = None,
    on_note: Note | None = None,
) -> ScanResult:
    """Audit the network `info` describes and return everything found.

    `on_progress(stage, done, total)` hears "discover", "ports", "probes"
    (only with `probe`), "router" (only when the router answers UPnP questions
    about its internet connection), "checks" and "done", in that order.
    "ports" and "probes" start at (0, total) and count up; the others are
    (0, 0).
    `on_note(source, message)` hears about anything that could not run, and
    the result keeps every note too. `timeout` is the TCP connect timeout.

    A device that answers on some port, open or closed, counts as confirmed.
    One known only from a neighbor table entry that stays silent is left out
    when the entry is gone by the end of the port scan.
    """
    _check_timeout(timeout)
    port_list = _port_list(ports)
    started = _now()
    notes: list[tuple[str, str]] = []

    def progress(stage: str, done: int, total: int) -> None:
        if on_progress:
            on_progress(stage, done, total)

    def note(source: str, message: str) -> None:
        notes.append((source, message))
        if on_note:
            on_note(source, message)

    progress("discover", 0, 0)
    devices = await discovery.discover(info, on_note=note)

    answered, open_ports = await _scan([d.ip for d in devices], port_list, timeout, progress)
    for device in devices:
        if device.ip in answered:
            device.confirmed = True
            device.seen_by.add("tcp")
    # The connects made the OS look for the silent ones again, so the neighbor
    # table now knows whether they are still around.
    devices = await discovery.recheck(devices, info)

    for device in devices:
        found = sorted(open_ports.get(device.ip, ()))
        if len(found) > MAX_SERVICES:
            message = f"{device.ip} accepts connections on {len(found)} ports"
            note("ports", f"{message}; kept the first {MAX_SERVICES}")
            found = found[:MAX_SERVICES]
        device.services = [Service(port, name=SERVICE_NAMES.get(port, "")) for port in found]

    if probe:
        await _probe(devices, timeout, progress, note)

    for device in devices:
        # Discovery already knows this machine for what it is.
        if not device.is_self:
            classify.classify(device)

    devices.sort(key=lambda d: ipaddress.ip_address(d.ip))
    router_info = await _ask_router(devices, progress, note)
    progress("checks", 0, 0)
    findings = rules.evaluate(devices, gateway=info.gateway, router=router_info)
    score = scoring.score(findings)
    result = ScanResult(
        version=__version__,
        started=started,
        finished=_now(),
        interface=info.interface.label,
        address=str(info.address),
        network=str(info.scan_network()),
        gateway=info.gateway,
        devices=devices,
        findings=findings,
        score=score,
        ports=port_list,
        notes=notes,
        router=router_info,
    )
    progress("done", 0, 0)
    return result


async def _scan(
    hosts: list[str], port_list: list[int], timeout: float, progress: Progress
) -> tuple[set[str], dict[str, list[int]]]:
    """Hosts that answered at all, and the open ports of each."""
    total = len(hosts) * len(port_list)
    progress("ports", 0, total)
    answered: set[str] = set()
    open_ports: dict[str, list[int]] = {}
    if not total:
        return answered, open_ports

    offset = 0

    def report(done: int, _total: int) -> None:
        progress("ports", offset + done, total)

    # ports.scan takes at most MAX_PAIRS pairs per call, so a long port list
    # goes a few hosts at a time.
    per_call = max(1, portscan.MAX_PAIRS // len(port_list))
    for start in range(0, len(hosts), per_call):
        batch = hosts[start : start + per_call]
        results = await portscan.scan(batch, port_list, timeout=timeout, on_progress=report)
        offset += len(batch) * len(port_list)
        for result in results:
            if result.state is not PortState.FILTERED:
                answered.add(result.host)
            if result.state is PortState.OPEN:
                open_ports.setdefault(result.host, []).append(result.port)
    return answered, open_ports


async def _probe(devices: list[Device], timeout: float, progress: Progress, note: Note) -> None:
    """Swap the plain services for what the probes found out about them."""
    targets = [(device.ip, service.port) for device in devices for service in device.services]
    total = len(targets)
    progress("probes", 0, total)
    if not targets:
        return
    done = 0

    def advance(*_: object) -> None:
        nonlocal done
        done = min(done + 1, total)
        progress("probes", done, total)

    try:
        found = await probes.probe_all(
            targets, timeout=max(PROBE_TIMEOUT, timeout), on_done=advance
        )
    except Exception as exc:
        # The plain services from the port scan are still worth checking.
        note("probes", f"service probes failed ({type(exc).__name__}: {exc})")
        return
    for device in devices:
        device.services = [_probed(found, device.ip, service) for service in device.services]


async def _ask_router(devices: list[Device], progress: Progress, note: Note) -> RouterInfo | None:
    """What the gateway says about its internet side, or None when it does not say."""
    gateway = next((d for d in devices if d.is_gateway), None)
    if gateway is None or router.wan_service(gateway) is None:
        return None
    progress("router", 0, 0)
    try:
        return await router.query(gateway)
    except Exception as exc:
        # The devices and their findings are still worth showing.
        note("router", f"router check failed ({type(exc).__name__}: {exc})")
        return None


def _probed(found: dict[tuple[str, int], Service], ip: str, plain: Service) -> Service:
    service = found.get((ip, plain.port))
    if isinstance(service, Service) and service.port == plain.port:
        return service
    return plain
