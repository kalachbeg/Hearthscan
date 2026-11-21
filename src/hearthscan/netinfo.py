"""Work out the local network: interfaces, the default gateway, what to scan."""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import ifaddr

from . import system
from .scope import is_local
from .system import IS_LINUX, IS_MACOS, IS_WINDOWS, run, windows_tool

# A Hyper-V external switch moves the host's LAN address onto a virtual NIC.
# It is still the home network when it carries the default route.
_VSWITCH_WORDS = ("hyper-v virtual ethernet adapter", "vethernet")
# VPN clients, hypervisors and container runtimes add adapters that look just
# like a LAN. Descriptions (mostly Windows) are matched on these words...
_VIRTUAL_WORDS = (
    "virtual",
    "vmware",
    "docker",
    "wsl",
    "loopback",
    "pseudo",
    "bluetooth",
    "tunnel",
    "wintun",
    "wireguard",
    "nordlynx",
    "openvpn",
    "tap-",
    "tailscale",
    "zerotier",
    "npcap",
)
# ...and system names (Linux, macOS, BSD) on these prefixes.
_VIRTUAL_PREFIXES = (
    "lo",
    "docker",
    "br-",
    "veth",
    "virbr",
    "vmnet",
    "vboxnet",
    "tun",
    "tap",
    "wg",
    "tailscale",
    "zt",
    "ipsec",
    "ppp",
    "cni",
    "flannel",
    "lxcbr",
    "lxdbr",
    "incusbr",
    "podman",
)
# Only on macOS. Some Linux distributions call a real host bridge "bridge0".
_MACOS_PREFIXES = ("utun", "awdl", "llw", "bridge", "anpi", "gif", "stf", "feth")

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

# Default route rows of `route print`. The headers are translated on
# non-English Windows, so only the shape of the row is matched.
_WIN_DEFAULT_ROUTE = re.compile(
    rf"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+({_IPV4})\s+({_IPV4})\s+(\d+)\s*$", re.MULTILINE
)
_IP_ROUTE_DEFAULT = re.compile(
    rf"^default via ({_IPV4}) dev (\S+)(?:.*?\smetric (\d+))?", re.MULTILINE
)


@dataclass(frozen=True)
class Interface:
    name: str  # what the OS calls it: eth0, en0, or a GUID on Windows
    label: str  # what a person would recognise: Ethernet, Wi-Fi, en0
    address: ipaddress.IPv4Address
    network: ipaddress.IPv4Network
    kind: str = "physical"  # or "vswitch", or "virtual"

    @property
    def virtual(self) -> bool:
        return self.kind != "physical"


@dataclass(frozen=True)
class Route:
    gateway: str
    interface: str  # interface name on Linux and macOS, local address on Windows
    metric: int = 0


@dataclass(frozen=True)
class NetworkInfo:
    interface: Interface
    gateway: str | None
    sandbox: str | None = None  # "wsl" or "container", see system.sandbox()

    @property
    def address(self) -> ipaddress.IPv4Address:
        return self.interface.address

    @property
    def network(self) -> ipaddress.IPv4Network:
        return self.interface.network

    def scan_network(self) -> ipaddress.IPv4Network:
        """The block worth sweeping. Oversized networks shrink to our own /24."""
        if self.network.prefixlen >= 22:
            return self.network
        return ipaddress.ip_network(f"{self.address}/24", strict=False)


def adapter_kind(description: str, system_name: str = "") -> str:
    text = description.lower()
    if any(word in text for word in _VSWITCH_WORDS):
        return "vswitch"
    if any(word in text for word in _VIRTUAL_WORDS):
        return "virtual"
    prefixes = _VIRTUAL_PREFIXES + _MACOS_PREFIXES if IS_MACOS else _VIRTUAL_PREFIXES
    if system_name and system_name.lower().startswith(prefixes):
        return "virtual"
    return "physical"


def interfaces() -> list[Interface]:
    """IPv4 interfaces with a usable address (no loopback, no 169.254.x.x)."""
    found = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            if not isinstance(ip.ip, str):  # IPv6 addresses come as tuples
                continue
            try:
                iface = ipaddress.ip_interface(f"{ip.ip}/{ip.network_prefix}")
            except ValueError:
                continue
            if iface.ip.is_loopback or iface.ip.is_link_local or iface.ip.is_unspecified:
                continue
            if IS_WINDOWS:
                # Friendly names like "Local Area Connection" say nothing useful
                # and must not hit the prefix list, so only words count.
                kind = adapter_kind(f"{adapter.nice_name} {ip.nice_name}")
            else:
                kind = adapter_kind(adapter.nice_name or adapter.name, adapter.name)
            label = ip.nice_name or adapter.nice_name or adapter.name
            found.append(Interface(adapter.name, label, iface.ip, iface.network, kind))
    return found


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def parse_route_print(text: str) -> list[Route]:
    routes = [
        Route(gateway, iface, int(metric))
        for gateway, iface, metric in _WIN_DEFAULT_ROUTE.findall(text)
        if _is_ipv4(gateway)
    ]
    return sorted(routes, key=lambda r: r.metric)


def parse_proc_net_route(text: str) -> list[Route]:
    """Parse /proc/net/route, where addresses are hex in host byte order."""
    routes = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        iface, destination, gateway, flags, metric, mask = (
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            fields[6],
            fields[7],
        )
        try:
            flags_value = int(flags, 16)
            address = socket.inet_ntoa(struct.pack("=I", int(gateway, 16)))
            metric_value = int(metric)
        except (ValueError, struct.error):
            continue
        # A default route needs RTF_UP and RTF_GATEWAY.
        if destination != "00000000" or mask != "00000000" or flags_value & 0x3 != 0x3:
            continue
        routes.append(Route(address, iface, metric_value))
    return sorted(routes, key=lambda r: r.metric)


def parse_ip_route(text: str) -> list[Route]:
    routes = [
        Route(gateway, dev, int(metric or 0))
        for gateway, dev, metric in _IP_ROUTE_DEFAULT.findall(text)
        if _is_ipv4(gateway)
    ]
    return sorted(routes, key=lambda r: r.metric)


def parse_netstat_rn(text: str) -> list[Route]:
    """Parse `netstat -rn -f inet` on macOS and the BSDs, in preference order."""
    routes = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] != "default" or not _is_ipv4(fields[1]):
            continue
        # Older macOS releases have Refs and Use columns before Netif.
        netif = next((f for f in fields[3:] if not f.isdigit()), "")
        routes.append(Route(fields[1], netif, len(routes)))
    return routes


def default_routes() -> list[Route]:
    """Default IPv4 routes, best first."""
    if IS_WINDOWS:
        return parse_route_print(run([windows_tool("route.exe"), "print", "-4"]))
    if IS_LINUX:
        try:
            routes = parse_proc_net_route(Path("/proc/net/route").read_text())
        except OSError:
            routes = []
        return routes or parse_ip_route(run(["ip", "-4", "route", "show", "default"]))
    return parse_netstat_rn(run(["netstat", "-rn", "-f", "inet"]))


def _owner(route: Route, ifaces: list[Interface]) -> Interface | None:
    gateway = ipaddress.ip_address(route.gateway)
    named = [i for i in ifaces if route.interface in (i.name, str(i.address))]
    # An interface with a second address shows up twice under the same name;
    # pick the one whose subnet holds the gateway.
    for iface in named:
        if gateway in iface.network:
            return iface
    if named:
        return named[0]
    return next((i for i in ifaces if gateway in i.network), None)


def local_network() -> NetworkInfo | None:
    """Figure out which network someone means by "my network"."""
    ifaces = interfaces()
    where = system.sandbox()
    for route in default_routes():
        iface = _owner(route, ifaces)
        # A VPN that takes over the default route is not the home network.
        if iface is None or iface.kind == "virtual" or not is_local(route.gateway):
            continue
        return NetworkInfo(iface, route.gateway, where)
    # No usable default route: offline, or only a VPN route is left.
    for iface in ifaces:
        if iface.kind == "physical" and is_local(iface.address):
            return NetworkInfo(iface, None, where)
    return None
