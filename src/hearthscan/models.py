"""What a scan finds out about the devices on a network."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")

KINDS = (
    "router",
    "computer",
    "phone",
    "tablet",
    "printer",
    "camera",
    "tv",
    "speaker",
    "media",
    "nas",
    "console",
    "smart-home",
    "unknown",
)

_MAC_SEPARATORS = re.compile(r"[:\-.]")

# Google Cast devices and some others use a UUID or a hex string as their mDNS
# host name. It names nothing a person would recognise.
_MACHINE_LABEL = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{12,}", re.IGNORECASE
)

# Routers tack their local domain onto DHCP names. In a device list it is noise.
_HOME_DOMAINS = sorted(
    (
        ".lan",
        ".home",
        ".local",
        ".localdomain",
        ".home.arpa",
        ".fritz.box",
        ".router",
        ".gateway",
        ".domain",
        ".internal",
        ".station",
        ".speedport.ip",
    ),
    key=len,
    reverse=True,
)


def normalize_mac(text: str | None) -> str | None:
    """Turn the many ways tools print a MAC into "aa:bb:cc:dd:ee:ff".

    Accepts dashes (Windows), colons with dropped leading zeros (macOS prints
    0:1a:2b:...), Cisco style dots and bare hex. Returns None for anything else
    and for the all-zero address that incomplete ARP entries show.
    """
    if not text:
        return None
    text = text.strip().lower()
    parts = _MAC_SEPARATORS.split(text)
    if len(parts) == 6:
        if not all(1 <= len(p) <= 2 for p in parts):
            return None
        parts = [p.zfill(2) for p in parts]
    elif len(parts) == 3 and all(len(p) == 4 for p in parts):
        joined = "".join(parts)
        parts = [joined[i : i + 2] for i in range(0, 12, 2)]
    elif len(parts) == 1 and len(text) == 12:
        parts = [text[i : i + 2] for i in range(0, 12, 2)]
    else:
        return None
    if not all(re.fullmatch(r"[0-9a-f]{2}", p) for p in parts):
        return None
    mac = ":".join(parts)
    if mac == "00:00:00:00:00:00":
        return None
    return mac


def is_unicast_mac(mac: str) -> bool:
    """False for broadcast and multicast addresses (lowest bit of the first byte)."""
    return not int(mac[:2], 16) & 0x01


def is_random_mac(mac: str | None) -> bool:
    """Locally administered: phones and laptops make one up per network for privacy."""
    if not mac:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def _short_name(name: str) -> str:
    lowered = name.lower()
    for suffix in _HOME_DOMAINS:
        if lowered.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)]
    return name


@dataclass(slots=True)
class Service:
    port: int
    protocol: str = "tcp"
    name: str = ""  # "ssh", "http", from the port number or what the probe saw
    banner: str | None = None  # first thing the service said, cleaned up and capped
    product: str | None = None  # "OpenSSH 9.6", "lighttpd/1.4.59"
    tls: bool = False
    tls_version: str | None = None
    title: str | None = None  # HTML <title> of a web page
    auth: str | None = None  # "none" when it let us in without credentials, "required", or unknown
    facts: dict[str, str] = field(default_factory=dict)  # probe specific, see probes.py


@dataclass(slots=True)
class MdnsInfo:
    hostname: str | None = None  # "Living-Room.local", no trailing dot
    services: set[str] = field(default_factory=set)  # "_airplay._tcp"
    instances: dict[str, str] = field(default_factory=dict)  # service type -> instance name
    txt: dict[str, dict[str, str]] = field(default_factory=dict)  # service type -> TXT pairs


@dataclass(slots=True)
class UpnpService:
    service_type: str  # "urn:schemas-upnp-org:service:WANIPConnection:1"
    control_url: str  # absolute
    scpd_url: str | None = None


@dataclass(slots=True)
class UpnpInfo:
    server: str | None = None  # SERVER header of the SSDP reply
    location: str | None = None
    device_types: set[str] = field(default_factory=set)  # root and embedded devices
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    services: list[UpnpService] = field(default_factory=list)


@dataclass(slots=True)
class NetbiosInfo:
    name: str | None = None
    workgroup: str | None = None
    mac: str | None = None
    file_server: bool = False  # registered the <20> name


@dataclass(slots=True)
class Device:
    ip: str
    mac: str | None = None
    vendor: str | None = None
    dns_name: str | None = None
    mdns: MdnsInfo | None = None
    upnp: UpnpInfo | None = None
    netbios: NetbiosInfo | None = None
    model: str | None = None
    kind: str = "unknown"
    evidence: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    seen_by: set[str] = field(default_factory=set)  # "arp", "mdns", "ssdp", "netbios", "tcp"
    # It answered us, or the OS heard from it moments ago. Otherwise all we
    # have is a neighbor table entry, which can outlive the device by hours.
    confirmed: bool = False
    is_gateway: bool = False
    is_self: bool = False

    @property
    def name(self) -> str | None:
        """The most useful name we have. Names a device picks itself come first."""
        if self.mdns:
            cast_name = (self.mdns.txt.get("_googlecast._tcp", {}).get("fn") or "").strip()
            if cast_name:
                return cast_name
            if self.mdns.hostname:
                host = self.mdns.hostname.removesuffix(".local")
                if not _MACHINE_LABEL.fullmatch(host.split(".", 1)[0]):
                    return host
        if self.netbios and self.netbios.name:
            return self.netbios.name
        if self.dns_name:
            return _short_name(self.dns_name)
        if self.upnp and self.upnp.friendly_name:
            return self.upnp.friendly_name
        if self.mdns and self.mdns.instances:
            return next(iter(self.mdns.instances.values()))
        return None

    @property
    def random_mac(self) -> bool:
        return is_random_mac(self.mac)


@dataclass(slots=True)
class Finding:
    rule: str  # rules.py id, also the key of its texts: rule.<id>.title and so on
    severity: str  # one of SEVERITIES
    ip: str
    port: int | None = None
    params: dict[str, str] = field(default_factory=dict)  # filled into the texts
    evidence: str | None = None  # short and technical, not translated


@dataclass(slots=True)
class PortMapping:
    """A port forward on the router, as its UPnP service lists it."""

    protocol: str  # "TCP" or "UDP"
    external_port: int
    internal_client: str  # the device it forwards to
    internal_port: int
    description: str = ""
    enabled: bool = True
    lease: int = 0  # seconds left, 0 for permanent
    remote_host: str = ""  # empty when anyone on the internet may connect


@dataclass(slots=True)
class RouterInfo:
    """What the router says about itself over UPnP. Every field may be missing."""

    external_ip: str | None = None
    connection: str | None = None  # "IP_Routed", "PPPoE" ...
    status: str | None = None  # "Connected", "Disconnected" ...
    uptime: int | None = None  # seconds
    mappings: list[PortMapping] = field(default_factory=list)
    mappings_complete: bool = True  # False when the list was cut short


@dataclass(slots=True)
class ScanResult:
    version: str  # Hearthscan version that made it
    started: str  # ISO 8601, UTC
    finished: str
    interface: str
    address: str
    network: str
    gateway: str | None
    devices: list[Device] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 100
    ports: list[int] = field(default_factory=list)  # what was scanned
    notes: list[tuple[str, str]] = field(default_factory=list)  # (source, message)
    router: RouterInfo | None = None

    def device(self, ip: str) -> Device | None:
        return next((d for d in self.devices if d.ip == ip), None)
