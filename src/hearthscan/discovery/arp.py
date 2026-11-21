"""Read the operating system's neighbor (ARP) table.

A UDP sweep makes the OS resolve every address on the network first, so the
table then lists every device that is switched on, and we never send raw ARP.
"""

from __future__ import annotations

import ctypes
import functools
import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import ifaddr

from ..models import is_unicast_mac, normalize_mac
from ..system import IS_LINUX, IS_WINDOWS, run, windows_tool

# Far more than a home network holds. The caps keep a broken table or a
# runaway command from filling memory.
MAX_NEIGHBORS = 8192
_MAX_TEXT = 4_000_000
_MAX_LINE = 1024
_MAX_NAME = 64

_PROC_NET_ARP = Path("/proc/net/arp")

_IPV4 = r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"
# "Interface: 192.168.1.20 --- 0x11". The word in front is translated
# (Schnittstelle, Arabirim, ...), so only the shape of the line counts.
_WIN_HEADER = re.compile(rf":\s*({_IPV4})\s+---\s+0x[0-9a-fA-F]+\s*$")

# Flags in /proc/net/arp, from linux/if_arp.h.
_ATF_COM = 0x02
_ATF_PERM = 0x04

_IP_NEIGH_STATES = {
    "REACHABLE": "reachable",
    "PERMANENT": "reachable",
    "NOARP": "reachable",
    "STALE": "stale",
    "DELAY": "probing",
    "PROBE": "probing",
}
_IP_NEIGH_SKIP = frozenset({"FAILED", "INCOMPLETE"})

# NL_NEIGHBOR_STATE from netioapi.h: Probe (2), Delay (3), Stale (4),
# Reachable (5), Permanent (6). Unreachable (0) and Incomplete (1) are skipped.
_WIN_STATES = {2: "probing", 3: "probing", 4: "stale", 5: "reachable", 6: "reachable"}

_STATE_RANK = {"reachable": 3, "probing": 2, "stale": 1}

# FreeBSD prints "expires in N seconds". The countdown restarts at max_age
# (1200 s unless changed by sysctl) only when an ARP packet from that host
# arrives, so nearly the full lifetime left means the host spoke within the
# last half minute, about as long as Linux and Windows call a neighbor reachable.
_BSD_EXPIRES = re.compile(r"\bexpires in ([0-9]{1,9}) seconds\b")
_BSD_MAX_AGE = 1200
_BSD_FRESH = 30


@dataclass(frozen=True, slots=True)
class Neighbor:
    ip: str
    mac: str  # normalized, "aa:bb:cc:dd:ee:ff"
    # Device name on Linux and macOS (eth0, en0). On Windows the local IPv4
    # address of the interface, or its index when the address is unknown.
    interface: str | None = None
    # "reachable": the OS heard from it in the last half minute or so.
    # "stale": it has not checked lately. "probing": it is checking right now.
    # "unknown": the OS does not say (macOS, /proc/net/arp).
    state: str = "unknown"


class _BadEntry(ValueError):
    """A line or table row that does not describe a usable neighbor."""


def _ipv4(text: str) -> str:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise _BadEntry(text) from None


def _mac(text: str, *, padded: bool = True) -> str:
    # Only macOS and the BSDs drop leading zeros. Elsewhere a short MAC means
    # the line was cut off.
    if padded and len(text) != 17:
        raise _BadEntry(text)
    mac = normalize_mac(text)
    if mac is None:
        raise _BadEntry(text)
    return mac


def _name(text: str) -> str:
    return text[:_MAX_NAME]


def _after(fields: list[str], word: str) -> str | None:
    if word in fields[:-1]:
        return fields[fields.index(word) + 1]
    return None


def _lines(text: str) -> list[str]:
    return [line for line in text[:_MAX_TEXT].splitlines() if len(line) <= _MAX_LINE]


def _parse(text: str, parse_line: Callable[[list[str]], Neighbor]) -> list[Neighbor]:
    found = []
    for line in _lines(text):
        try:
            found.append(parse_line(line.split()))
        except _BadEntry:
            continue
        if len(found) >= MAX_NEIGHBORS:
            break
    return found


def parse_arp_windows(text: str) -> list[Neighbor]:
    """Parse `arp -a` from Windows, in any display language."""
    found = []
    interface = None
    for line in _lines(text):
        header = _WIN_HEADER.search(line)
        if header:
            try:
                interface = _ipv4(header.group(1))
            except _BadEntry:
                interface = None
            continue
        fields = line.split()
        # Address, MAC and a type word (dynamic, statisk, dinamik, ...).
        if len(fields) < 3:
            continue
        try:
            found.append(Neighbor(_ipv4(fields[0]), _mac(fields[1]), interface))
        except _BadEntry:
            continue
        if len(found) >= MAX_NEIGHBORS:
            break
    return found


def _bsd_entry(fields: list[str]) -> Neighbor:
    # OpenBSD prints a table instead: address, MAC, interface, expiry, flags.
    if len(fields) >= 3 and not fields[0].startswith("("):
        try:
            ip = _ipv4(fields[0])
        except _BadEntry:
            pass
        else:
            mac = _mac(fields[1], padded=False)
            return Neighbor(ip, mac, _name(fields[2]), _bsd_state(fields[3:]))

    # "? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]"
    if len(fields) < 4 or fields[2] != "at":
        raise _BadEntry
    address = fields[1]
    if not (address.startswith("(") and address.endswith(")")):
        raise _BadEntry
    ip = _ipv4(address[1:-1])
    mac = _mac(fields[3], padded=False)  # "(incomplete)" fails here
    interface = None
    rest = fields[4:]
    if len(fields) > 5 and fields[4] == "on":
        interface = _name(fields[5])
        rest = fields[6:]
    return Neighbor(ip, mac, interface, _bsd_state(rest))


def _bsd_state(fields: list[str]) -> str:
    if "permanent" in fields:
        return "reachable"
    expires = _BSD_EXPIRES.search(" ".join(fields))
    if expires and _BSD_MAX_AGE - _BSD_FRESH <= int(expires.group(1)) <= _BSD_MAX_AGE:
        return "reachable"
    return "unknown"


def parse_arp_macos(text: str) -> list[Neighbor]:
    """Parse `arp -an` from macOS and the BSDs."""
    return _parse(text, _bsd_entry)


def _proc_entry(fields: list[str]) -> Neighbor:
    # IP address, HW type, Flags, HW address, Mask, Device
    if len(fields) < 6:
        raise _BadEntry
    ip = _ipv4(fields[0])
    try:
        flags = int(fields[2], 16)
    except ValueError:
        raise _BadEntry(fields[2]) from None
    if flags < 0 or not flags & (_ATF_COM | _ATF_PERM):
        raise _BadEntry(fields[2])
    state = "reachable" if flags & _ATF_PERM else "unknown"
    return Neighbor(ip, _mac(fields[3]), _name(fields[5]), state)


def parse_proc_net_arp(text: str) -> list[Neighbor]:
    """Parse Linux /proc/net/arp. Incomplete entries (flags 0x0) are skipped."""
    return _parse(text, _proc_entry)


def _ip_neigh_entry(fields: list[str]) -> Neighbor:
    # "192.168.1.1 dev wlp2s0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE"
    if not fields:
        raise _BadEntry
    ip = _ipv4(fields[0])
    if _IP_NEIGH_SKIP.intersection(fields):
        raise _BadEntry
    lladdr = _after(fields, "lladdr")
    if lladdr is None:
        raise _BadEntry
    mac = _mac(lladdr)
    dev = _after(fields, "dev")
    state = next((_IP_NEIGH_STATES[f] for f in fields if f in _IP_NEIGH_STATES), "unknown")
    return Neighbor(ip, mac, _name(dev) if dev else None, state)


def parse_ip_neigh(text: str) -> list[Neighbor]:
    """Parse Linux `ip -4 neigh show`. Failed and incomplete entries are skipped."""
    return _parse(text, _ip_neigh_entry)


class _SockaddrIn(ctypes.Structure):
    _fields_ = (
        ("family", ctypes.c_uint16),
        ("port", ctypes.c_uint16),
        ("addr", ctypes.c_ubyte * 4),
        ("zero", ctypes.c_ubyte * 8),
    )


class _SockaddrInet(ctypes.Union):
    # SOCKADDR_INET also holds a sockaddr_in6, which makes it 28 bytes,
    # aligned to 4.
    _fields_ = (("ipv4", _SockaddrIn), ("raw", ctypes.c_uint32 * 7))


class _MibIpnetRow2(ctypes.Structure):
    """MIB_IPNET_ROW2 from netioapi.h, 88 bytes."""

    _fields_ = (
        ("address", _SockaddrInet),
        ("interface_index", ctypes.c_uint32),
        ("interface_luid", ctypes.c_uint64),
        ("physical_address", ctypes.c_ubyte * 32),
        ("physical_address_length", ctypes.c_uint32),
        ("state", ctypes.c_int32),
        ("flags", ctypes.c_ubyte),  # IsRouter and IsUnreachable bits
        ("reachability_time", ctypes.c_uint32),
    )


class _MibIpnetTable2(ctypes.Structure):
    _fields_ = (("num_entries", ctypes.c_uint32), ("table", _MibIpnetRow2 * 1))


_AF_INET = 2
_ERROR_NOT_FOUND = 1168


@functools.cache
def _iphlpapi() -> tuple[Callable, Callable]:
    dll = ctypes.WinDLL("iphlpapi")
    get_table = dll.GetIpNetTable2
    get_table.argtypes = (ctypes.c_uint16, ctypes.POINTER(ctypes.POINTER(_MibIpnetTable2)))
    get_table.restype = ctypes.c_uint32
    free_table = dll.FreeMibTable
    free_table.argtypes = (ctypes.c_void_p,)
    free_table.restype = None
    return get_table, free_table


def _row_entry(row: _MibIpnetRow2) -> tuple[str, str, int, str]:
    state = _WIN_STATES.get(row.state)
    if state is None or row.address.ipv4.family != _AF_INET:
        raise _BadEntry
    if row.physical_address_length != 6:
        raise _BadEntry
    ip = str(ipaddress.IPv4Address(bytes(row.address.ipv4.addr)))
    mac = _mac(":".join(f"{b:02x}" for b in row.physical_address[:6]))
    return ip, mac, row.interface_index, state


def _interface_addresses() -> dict[int, list[ipaddress.IPv4Interface]]:
    found: dict[int, list[ipaddress.IPv4Interface]] = {}
    try:
        adapters = ifaddr.get_adapters()
    except OSError:
        return found
    for adapter in adapters:
        if adapter.index is None:
            continue
        for ip in adapter.ips:
            if not isinstance(ip.ip, str):
                continue
            try:
                iface = ipaddress.IPv4Interface(f"{ip.ip}/{ip.network_prefix}")
            except ValueError:
                continue
            found.setdefault(adapter.index, []).append(iface)
    return found


def _interface_label(index: int, ip: str, local: dict[int, list[ipaddress.IPv4Interface]]) -> str:
    """Name an interface the way `arp -a` does: by our own address on it."""
    choices = local.get(index)
    if not choices:
        return str(index)
    address = ipaddress.IPv4Address(ip)
    for iface in choices:
        if address in iface.network:
            return str(iface.ip)
    return str(choices[0].ip)


def _read_ipnet_table2() -> list[Neighbor]:
    get_table, free_table = _iphlpapi()
    table = ctypes.POINTER(_MibIpnetTable2)()
    status = get_table(_AF_INET, ctypes.byref(table))
    if status == _ERROR_NOT_FOUND:
        return []
    if status != 0:
        raise OSError(status, "GetIpNetTable2 failed")
    if not table:
        return []
    entries = []
    try:
        count = table.contents.num_entries
        start = ctypes.addressof(table.contents) + _MibIpnetTable2.table.offset
        for row in (_MibIpnetRow2 * count).from_address(start):
            try:
                entries.append(_row_entry(row))
            except _BadEntry:
                continue
            if len(entries) >= MAX_NEIGHBORS:
                break
    finally:
        free_table(table)
    local = _interface_addresses()
    return [
        Neighbor(ip, mac, _interface_label(index, ip, local), state)
        for ip, mac, index, state in entries
    ]


def _windows_neighbors() -> list[Neighbor]:
    try:
        return _read_ipnet_table2()
    except Exception:
        # Whatever went wrong with the API, `arp -a` reads the same table.
        return parse_arp_windows(run([windows_tool("arp.exe"), "-a"]))


def _proc_net_arp() -> list[Neighbor]:
    try:
        text = _PROC_NET_ARP.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_proc_net_arp(text)


def neighbors() -> list[Neighbor]:
    """Read the neighbor table of the running OS. Returns [] when it can't be read."""
    if IS_WINDOWS:
        return _windows_neighbors()
    if IS_LINUX:
        return parse_ip_neigh(run(["ip", "-4", "neigh", "show"])) or _proc_net_arp()
    return parse_arp_macos(run(["arp", "-an"]))


def on_network(
    entries: Iterable[Neighbor],
    network: ipaddress.IPv4Network,
    own_ip: str | ipaddress.IPv4Address | None = None,
) -> list[Neighbor]:
    """Keep the unicast neighbors on `network`, one per address, sorted by address.

    Drops the network and broadcast addresses, our own address and multicast.
    When an address shows up twice, the entry the OS heard from most recently
    wins: reachable, then probing, then stale, then unknown.
    """
    skip = set()
    # A /31 or /32 has no network or broadcast address.
    if network.prefixlen <= 30:
        skip = {network.network_address, network.broadcast_address}
    if own_ip is not None:
        skip.add(ipaddress.IPv4Address(own_ip))

    best: dict[ipaddress.IPv4Address, Neighbor] = {}
    for entry in entries:
        try:
            ip = ipaddress.IPv4Address(entry.ip)
        except ValueError:
            continue
        if ip not in network or ip in skip or ip.is_multicast:
            continue
        mac = normalize_mac(entry.mac)
        if mac is None or not is_unicast_mac(mac):
            continue
        current = best.get(ip)
        if current is None or _rank(entry) > _rank(current):
            best[ip] = entry
    return [best[ip] for ip in sorted(best)]


def _rank(entry: Neighbor) -> int:
    return _STATE_RANK.get(entry.state, 0)
