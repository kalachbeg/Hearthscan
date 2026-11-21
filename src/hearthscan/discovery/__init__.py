"""Find the devices on the local network without admin rights.

The sweep sends a NetBIOS status query to every address. Windows PCs and NAS
boxes answer with their names, and each of those datagrams also makes the OS
resolve the neighbor, so afterwards the ARP table lists every device that is
switched on, firewall or not. mDNS and SSDP listen at the same time and pick up
names and models, and reverse DNS asks the router what it calls each device.

A neighbor table entry can outlive its device by hours, so a device only
counts as confirmed when it answered something or the OS heard from it
moments ago.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import socket
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from ..models import Device, MdnsInfo
from ..netinfo import NetworkInfo
from ..scope import ScopeError, is_local
from ..system import IS_LINUX
from . import arp, classify, mdns, netbios, oui, rdns, ssdp

T = TypeVar("T")

# Whatever answers inside our own network counts. The sweep itself only covers
# NetworkInfo.scan_network(), which is smaller on oversized networks.
MAX_DEVICES = 4096

# How often the neighbor table is read while waiting for the OS to finish
# checking the entries the sweep touched.
SETTLE_INTERVAL = 0.5


async def _together(*jobs: Awaitable[Any]) -> list[Any]:
    tasks = [asyncio.ensure_future(job) for job in jobs]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def _unconfirmed_arp_only(device: Device) -> bool:
    # Every other source confirms a device, so this is a bare table entry.
    return not device.confirmed and "arp" in device.seen_by


async def _recheck(
    devices: dict[str, Device],
    info: NetworkInfo,
    deadline: float,
    on_wait: Callable[[], None],
) -> None:
    """Read the neighbor table again and act on what the OS learned since.

    Bare entries that are gone now (failed, timed out) are dropped and those
    that turned reachable are confirmed. While some are still stale or being
    probed, read again every SETTLE_INTERVAL until `deadline`.
    """
    loop = asyncio.get_running_loop()
    while True:
        table = await asyncio.to_thread(arp.neighbors)
        now = {n.ip: n for n in arp.on_network(table, info.network, own_ip=info.address)}
        if not now:
            # Reading the table failed outright (arp missing from PATH, say).
            # That is no reason to throw away what the first read found.
            return
        waiting = False
        for ip, found in list(devices.items()):
            if not _unconfirmed_arp_only(found):
                continue
            entry = now.get(ip)
            if entry is None:
                del devices[ip]
            elif entry.state == "reachable":
                found.confirmed = True
                found.mac = entry.mac
            elif entry.state in ("stale", "probing"):
                waiting = True
        left = deadline - loop.time()
        if not waiting or left <= 0:
            return
        on_wait()
        await asyncio.sleep(min(SETTLE_INTERVAL, left))


async def recheck(devices: list[Device], info: NetworkInfo) -> list[Device]:
    """Read the neighbor table once more and return the devices still on it.

    Only devices known from nothing but an unconfirmed table entry are looked
    at: those whose entry is gone are left out, and those the OS now calls
    reachable come back confirmed. When the table cannot be read at all,
    every device is kept.
    """
    found = {device.ip: device for device in devices}
    if any(_unconfirmed_arp_only(device) for device in found.values()):
        await _recheck(found, info, asyncio.get_running_loop().time(), lambda: None)
    return [device for device in devices if found.get(device.ip) is device]


async def discover(
    info: NetworkInfo,
    *,
    settle: float = 0.0,
    on_stage: Callable[[str], None] | None = None,
    on_note: Callable[[str, str], None] | None = None,
) -> list[Device]:
    """Sweep the network and return what is on it, sorted by address.

    Takes about four seconds on a /24. `on_stage` is called with "sweep",
    "names" and "done", and with "settle" while waiting on the OS (see below).
    `on_note(source, message)` hears about sources that could not run at all
    and about answers that look blocked.

    Devices known only from a neighbor table entry that the OS has not
    confirmed come back with `confirmed` False; they may have left. On the
    last read of the table, those whose entry is gone are dropped. With
    `settle`, reading goes on for up to that many seconds after the sweep, as
    long as some of them are still stale or being probed. The OS takes six to
    eight seconds to give up on a device that left.
    """
    if not isinstance(settle, (int, float)) or not math.isfinite(settle) or settle < 0:
        raise ValueError(f"settle must be zero or a positive number of seconds, not {settle!r}")
    if not is_local(info.network.network_address):
        raise ScopeError(f"{info.network} is not a private network")
    loop = asyncio.get_running_loop()
    local = str(info.address)
    sweep_hosts = [str(ip) for ip in info.scan_network().hosts() if ip != info.address]
    failed: set[str] = set()
    waited = False

    def stage(name: str) -> None:
        if on_stage:
            on_stage(name)

    def note(source: str, message: str) -> None:
        if on_note:
            on_note(source, message)

    def settling() -> None:
        nonlocal waited
        if not waited:
            waited = True
            stage("settle")

    async def best_effort(source: str, job: Awaitable[T], empty: T) -> T:
        # One source failing (no multicast on this interface, say) should not sink the rest.
        try:
            return await job
        except OSError as exc:
            failed.add(source)
            note(source, f"{source} did not run ({exc})")
            return empty

    stage("sweep")
    nb, found_mdns, found_ssdp = await _together(
        best_effort("netbios", netbios.query(local, sweep_hosts), {}),
        best_effort("mdns", mdns.browse(local), {}),
        best_effort("ssdp", ssdp.search(local, network=info.network), {}),
    )
    swept = loop.time()
    table = await asyncio.to_thread(arp.neighbors)
    neighbors = arp.on_network(table, info.network, own_ip=local)

    # Replies to our multicast queries come back as unicast from each device,
    # and stock ufw and firewalld rules only let in traffic sent to the group.
    # Our own responder and off-network addresses (a Docker bridge) get through
    # either way, so only answers from other devices here count.
    answered = {
        ip
        for ip in (*found_mdns, *found_ssdp)
        if ip != local and ipaddress.ip_address(ip) in info.network
    }
    if (
        IS_LINUX
        and len(neighbors) >= 2
        and not answered
        and not failed.intersection({"mdns", "ssdp"})
    ):
        note(
            "firewall",
            f"no device answered mDNS or SSDP, though {len(neighbors)} are in the neighbor table. "
            "A host firewall (ufw, firewalld) may be dropping the replies to multicast queries.",
        )

    devices: dict[str, Device] = {}

    def device(ip: str) -> Device | None:
        if ip in devices:
            return devices[ip]
        if len(devices) >= MAX_DEVICES or ipaddress.ip_address(ip) not in info.network:
            return None
        devices[ip] = Device(ip)
        return devices[ip]

    for entry in neighbors:
        if found := device(entry.ip):
            found.mac = entry.mac
            found.seen_by.add("arp")
            found.confirmed = entry.state == "reachable"
    for ip, record in nb.items():
        if found := device(ip):
            found.netbios = record
            found.mac = found.mac or record.mac
            found.seen_by.add("netbios")
            found.confirmed = True
    for ip, record in found_mdns.items():
        if found := device(ip):
            found.mdns = record
            found.seen_by.add("mdns")
            found.confirmed = True
    for ip in found_ssdp:
        if found := device(ip):
            found.seen_by.add("ssdp")
            found.confirmed = True

    if info.gateway and (gateway := device(info.gateway)):
        gateway.is_gateway = True
    devices.pop(local, None)
    me = Device(
        local,
        dns_name=socket.gethostname() or None,
        is_self=True,
        seen_by={"local"},
        confirmed=True,
    )
    devices[local] = me

    stage("names")
    others = [ip for ip in devices if ip != local]
    unnamed = [ip for ip in others if not (devices[ip].mdns and devices[ip].mdns.hostname)]
    upnp_hosts = {ip: r for ip, r in found_ssdp.items() if ip in devices and ip != local}
    servers = rdns.nameservers(info.gateway, interface=info.interface.name)
    dns_names, upnp, mdns_names = await _together(
        best_effort("dns", rdns.lookup(local, others, servers), {}),
        best_effort("upnp", ssdp.describe(upnp_hosts), {}),
        best_effort("mdns", mdns.reverse_names(local, unnamed), {}),
    )
    for ip, name in dns_names.items():
        if ip in devices:
            devices[ip].dns_name = name
    for ip, record in upnp.items():
        if ip in devices:
            devices[ip].upnp = record
    for ip, name in mdns_names.items():
        if ip in devices:
            found = devices[ip]
            if found.mdns is None:
                found.mdns = MdnsInfo()
            found.mdns.hostname = found.mdns.hostname or name
            found.seen_by.add("mdns")
            found.confirmed = True

    if any(_unconfirmed_arp_only(d) for d in devices.values()):
        await _recheck(devices, info, swept + settle, settling)

    for found in devices.values():
        found.vendor = oui.lookup(found.mac)
        classify.classify(found)

    stage("done")
    return sorted(devices.values(), key=lambda d: ipaddress.ip_address(d.ip))
