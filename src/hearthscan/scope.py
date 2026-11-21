"""Hearthscan is meant for your own network. These checks keep it there."""

from __future__ import annotations

import ipaddress
import re
import socket

# Private, link-local and loopback ranges. Carrier-grade NAT space
# (100.64.0.0/10) is left out on purpose: it is shared with other customers of
# the same ISP, and it is also where Tailscale hands out addresses.
LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)

# Room for a /20. Home networks are nearly always a /24.
MAX_HOSTS = 4096

_LINK_LOCAL_V6 = ipaddress.ip_network("fe80::/10")
_MAPPED_V4 = ipaddress.ip_network("::ffff:0:0/96")
_NUMERIC_LABEL = re.compile(r"[0-9]+|0[xX][0-9a-fA-F]*")


class ScopeError(ValueError):
    """The target lies outside the networks Hearthscan is willing to scan."""


def _parent_network(net):
    for local in LOCAL_NETWORKS:
        if local.version == net.version and net.subnet_of(local):
            return local
    return None


def _unmap(ip):
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _bare(ip):
    """The same address without a zone, e.g. fe80::1 for fe80::1%eth0."""
    return type(ip)(int(ip))


def _split_zone(text: str) -> tuple[str, str]:
    if ":" in text and "%" in text:
        address, _, zone = text.partition("%")
        return address, zone
    return text, ""


def _with_zone(ips: list, zone: str) -> list:
    if not zone:
        return ips
    return [ipaddress.ip_address(f"{ip}%{zone}") for ip in ips]


def _require_zone(ip) -> None:
    # Linux refuses to connect to fe80:: without knowing the interface.
    if ip.version == 6 and ip in _LINK_LOCAL_V6 and not ip.scope_id:
        raise ValueError(f"{ip} is link-local; add the interface, like {ip}%eth0")


def is_local(address) -> bool:
    ip = _unmap(ipaddress.ip_address(address))
    return any(ip in local for local in LOCAL_NETWORKS if local.version == ip.version)


def expand(spec: str) -> list[str]:
    """Turn a target list into addresses.

    Takes addresses or host names, CIDR blocks (192.168.1.0/24) and ranges
    (192.168.1.20-40 or 192.168.1.20-192.168.1.40), separated by commas.
    Raises ScopeError for anything outside a private network and ValueError
    for anything that doesn't parse.
    """
    addresses: dict[str, None] = {}
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        for ip in _expand_part(part):
            addresses[str(ip)] = None
        if len(addresses) > MAX_HOSTS:
            raise ScopeError(f"more than {MAX_HOSTS} addresses in total; narrow it down")
    if not addresses:
        raise ValueError("no targets given")
    return list(addresses)


def _expand_part(part: str) -> list:
    if "/" in part:
        return _expand_network(part)

    try:
        ip = _unmap(ipaddress.ip_address(part))
    except ValueError:
        ip = None
    if ip is not None:
        if not is_local(ip):
            raise ScopeError(f"{ip} is not on a private network")
        _require_zone(ip)
        return [ip]

    left, dash, right = part.partition("-")
    if dash:
        try:
            start = ipaddress.ip_address(left)
        except ValueError:
            start = None  # a host name with a dash in it
        if start is not None:
            return _expand_range(_unmap(start), right, part)

    if all(_NUMERIC_LABEL.fullmatch(label) for label in part.split(".")):
        # getaddrinfo would happily read 192.168.1.010 as octal, or 10.1 as 10.0.0.1.
        raise ValueError(f"not a valid IP address: {part!r}")
    ip = _resolve(part)
    if not is_local(ip):
        raise ScopeError(f"{part} resolves to {ip}, which is not on a private network")
    _require_zone(ip)
    return [ip]


def _expand_network(part: str) -> list:
    address, _, prefix = part.partition("/")
    address, zone = _split_zone(address)
    try:
        net = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    except ValueError:
        raise ValueError(f"not a network: {part!r}") from None
    if net.version == 6 and net.subnet_of(_MAPPED_V4):
        net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
    if _parent_network(net) is None:
        raise ScopeError(f"{net} is not a private network")
    if net.num_addresses > MAX_HOSTS + 2:
        raise ScopeError(f"{net} has {net.num_addresses} addresses; the limit is {MAX_HOSTS}")
    # /31 and /32 (and /127, /128) have no network or broadcast address to skip.
    hosts = list(net) if net.num_addresses <= 2 else list(net.hosts())
    hosts = _with_zone(hosts, zone)
    _require_zone(hosts[0])
    return hosts


def _expand_range(start, right: str, part: str) -> list:
    try:
        if right.isdigit() and start.version == 4:
            last = int(right)
            if last > 255:
                raise ValueError
            end = ipaddress.ip_address((int(start) & ~0xFF) | last)
        else:
            end = _unmap(ipaddress.ip_address(right))
    except ValueError:
        raise ValueError(f"not a range: {part!r}") from None
    if end.version != start.version or int(end) < int(start):
        raise ValueError(f"not a range: {part!r}")

    count = int(end) - int(start) + 1
    if count > MAX_HOSTS:
        raise ScopeError(f"{part} has {count} addresses; the limit is {MAX_HOSTS}")
    first, last_ip = _bare(start), _bare(end)
    parent = _parent_network(ipaddress.ip_network(first))
    if parent is None or last_ip not in parent:
        raise ScopeError(f"{part} is not entirely on a private network")
    zone = start.scope_id if start.version == 6 and start.scope_id else ""
    hosts = _with_zone([first + offset for offset in range(count)], zone)
    _require_zone(hosts[0])
    return hosts


def _resolve(name: str):
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise ValueError(f"can't resolve {name!r}") from None
    found = []
    for family, _, _, _, sockaddr in infos:
        host = sockaddr[0]
        if family == socket.AF_INET6 and sockaddr[3] and "%" not in host:
            host = f"{host}%{sockaddr[3]}"
        found.append(_unmap(ipaddress.ip_address(host)))
    if not found:
        raise ValueError(f"can't resolve {name!r}")
    # Prefer IPv4. A host that also has a global IPv6 address would otherwise
    # be refused as public.
    found.sort(key=lambda ip: ip.version)
    return found[0]
