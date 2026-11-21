"""Reverse DNS for the hosts we find, asking the router and the configured nameservers.

Home routers usually know the names their DHCP clients sent, and answer PTR
queries for them even when nothing else does.
"""

from __future__ import annotations

import ipaddress
import random
import re
from collections.abc import Iterable

from ..scope import is_local
from ..system import IS_WINDOWS
from . import _udp
from .dnswire import (
    PTR,
    DnsError,
    Labels,
    Message,
    build_query,
    name_key,
    name_text,
    parse_message,
    reverse_name,
)

DNS_PORT = 53
MAX_SERVERS = 3
MAX_QUERIES = 0xFFFF  # each one needs an id of its own
SPACING = 0.002

# systemd-resolved points /etc/resolv.conf at its stub on 127.0.0.53, which a
# socket bound to the LAN address cannot reach. The second file lists the
# servers it forwards to.
RESOLV_CONF_FILES = ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf")
_MAX_FILE = 64 * 1024

# Where Windows keeps each adapter's IPv4 settings, under its GUID.
TCPIP_INTERFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
_GUID = re.compile(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}")
# Servers set by hand come first, as Windows prefers them to those from DHCP.
_REGISTRY_VALUES = ("NameServer", "DhcpNameServer")

_random = random.SystemRandom()


def _private_ipv4(text: str | None) -> str | None:
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    if not is_local(ip) or ip.is_loopback:
        return None
    return str(ip)


def parse_resolv_conf(text: str) -> list[str]:
    """The nameserver entries of a resolv.conf, in order."""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            found.append(fields[1])
    return found


def _read(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(_MAX_FILE).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _registry_values(guid: str) -> list[str]:
    """The DNS server values of one adapter in the Windows registry, as stored."""
    try:
        import winreg
    except ImportError:
        return []
    found = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{TCPIP_INTERFACES}\\{guid}") as key:
            for name in _REGISTRY_VALUES:
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                except OSError:
                    continue
                if isinstance(value, str):
                    found.append(value)
                elif isinstance(value, list):  # REG_MULTI_SZ
                    found.extend(item for item in value if isinstance(item, str))
    except OSError:
        return []
    return found


def windows_nameservers(interface: str | None) -> list[str]:
    """The DNS servers Windows has for the adapter with this GUID, in order.

    Returns an empty list for anything that is not a GUID, or when the
    registry has nothing for it.
    """
    if not isinstance(interface, str) or not _GUID.fullmatch(interface):
        return []
    found = []
    for value in _registry_values(interface):
        found.extend(value.replace(",", " ").split())
    return found


def nameservers(gateway: str | None, interface: str | None = None) -> list[str]:
    """DNS servers worth asking: the gateway first, then the private ones configured.

    Those come from resolv.conf, or on Windows from the registry entry of
    `interface`, the adapter GUID. Loopback and public servers are left out,
    as is IPv6. At most MAX_SERVERS.
    """
    candidates = [gateway]
    if IS_WINDOWS:
        candidates.extend(windows_nameservers(interface))
    else:
        for path in RESOLV_CONF_FILES:
            candidates.extend(parse_resolv_conf(_read(path)))
    found: list[str] = []
    for candidate in candidates:
        address = _private_ipv4(candidate)
        if address is not None and address not in found:
            found.append(address)
    return found[:MAX_SERVERS]


def _ipv4(text: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def _answer(message: Message, name: Labels, ip: str) -> str | None:
    for record in message.answers:
        if record.rtype != PTR or name_key(record.name) != name:
            continue
        labels = record.data
        if not labels or name_key(labels[-2:]) == ("in-addr", "arpa"):
            continue
        host = name_text(labels)
        # Some resolvers answer with the address itself when they know no name.
        if host == ip or host.startswith(ip + "."):
            continue
        return host
    return None


async def lookup(
    local: str, ips: Iterable[str], servers: Iterable[str], *, timeout: float = 1.5
) -> dict[str, str]:
    """Reverse DNS names for `ips`, asking every server at once.

    Returns ip -> name without the trailing dot. When several servers answer
    for the same address, the one listed first wins.
    """
    targets = list(dict.fromkeys(ip for ip in map(_ipv4, ips) if ip))
    order = list(dict.fromkeys(server for server in map(_ipv4, servers) if server))
    queries = [(rank, server, ip) for ip in targets for rank, server in enumerate(order)]
    queries = queries[:MAX_QUERIES]
    if not queries:
        return {}

    ids = _random.sample(range(1, 0x10000), len(queries))
    pending: dict[int, tuple[int, str, str, Labels]] = {}
    packets = []
    for query_id, (rank, server, ip) in zip(ids, queries, strict=True):
        name = reverse_name(ip)
        pending[query_id] = (rank, server, ip, name_key(name))
        query = build_query([(name, PTR)], query_id=query_id, recursion_desired=True)
        packets.append((query, (server, DNS_PORT)))

    replies = await _udp.exchange(packets, local=local, listen=timeout, spacing=SPACING)

    best: dict[str, tuple[int, str]] = {}
    for data, sender in replies:
        try:
            message = parse_message(data)
        except DnsError:
            continue
        query = pending.get(message.id)
        if query is None or not message.is_response:
            continue
        rank, server, ip, name = query
        if sender != server or [name_key(q) for q, _ in message.questions] != [name]:
            continue
        del pending[message.id]
        host = _answer(message, name, ip)
        if host is not None and (ip not in best or rank < best[ip][0]):
            best[ip] = (rank, host)
    return {ip: best[ip][1] for ip in targets if ip in best}
