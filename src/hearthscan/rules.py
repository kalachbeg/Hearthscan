"""Security rules: turn what a scan saw into findings.

Every rule looks at one device at a time. Rule ids and the params of each
finding are shared with the texts that explain them, so neither may change
without the other.

The router rules read what the router said about itself over UPnP. A port
forward is reported on the device it leads to, or on the router when that is
no device on the network. The router's internet address is reported on the
router.

A service is matched by the name a probe gave it as well as by its port, so a
service on an unusual port still counts. A port only stops counting for its
usual protocol when a probe saw another protocol there that these rules know
by name: "ssh" on port 23 is not telnet.
"""

from __future__ import annotations

import ipaddress
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import NamedTuple

from .models import SEVERITIES, Device, Finding, PortMapping, RouterInfo, Service

MAX_EVIDENCE = 200
_MAX_PART = 120
_MAX_PARAM = 80
_MAX_FACT = 64

# More port forwards than any home router keeps. The rest are not looked at.
MAX_FORWARDS = 1024

OLD_TLS = ("TLSv1", "TLSv1.1")

_LOGINS = {
    "form": "login form",
    "basic": "HTTP Basic authentication",
    "digest": "HTTP Digest authentication",
}
_WEB_NAMES = frozenset({"http", "https"})
_PORT_MAPPING = ("wanipconnection", "wanpppconnection")

# Services that should never be forwarded from the internet, by internal port.
_RISKY_PORTS = frozenset(
    {21, 23, 135, 139, 445, 554, 1433, 2375, 3306, 3389, 5432, 5555, 5900, 6379, 9200, 11211}
    | {27017, 34567, 37777}
)
_PRIVATE = tuple(
    ipaddress.IPv4Network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_SHARED = (ipaddress.IPv4Network("100.64.0.0/10"),)


@dataclass(frozen=True, slots=True)
class _Protocol:
    names: frozenset[str]
    ports: frozenset[int]
    label: str = ""  # how texts name it, for database-open


def _protocol(names: str, ports: Iterable[int], label: str = "") -> _Protocol:
    return _Protocol(frozenset(names.split()), frozenset(ports), label)


# Names as ports.SERVICE_NAMES and the probes give them.
_TELNET = _protocol("telnet", [23])
_FTP = _protocol("ftp", [21])
_VNC = _protocol("vnc", [5900])
_RDP = _protocol("rdp", [3389])
_ADB = _protocol("adb", [5555])
_REDIS = _protocol("redis", [6379], "Redis")
_DOCKER = _protocol("docker", [2375])
_MEMCACHED = _protocol("memcached", [11211])
_ELASTICSEARCH = _protocol("elasticsearch", [9200], "Elasticsearch")
_MYSQL = _protocol("mysql", [3306], "MySQL")
_POSTGRESQL = _protocol("postgresql", [5432], "PostgreSQL")
_MSSQL = _protocol("mssql", [1433], "SQL Server")
_MONGODB = _protocol("mongodb", [27017], "MongoDB")
_MQTT = _protocol("mqtt", [1883])
_RTSP = _protocol("rtsp", [554])
_SMB = _protocol("smb", [445])
_SOCKS = _protocol("socks", [1080])
_DVR = _protocol("dvr dahua-dvr", [34567, 37777])
_WINBOX = _protocol("winbox", [8291])
_PPTP = _protocol("pptp", [1723])
_WEBMIN = _protocol("webmin", [10000])
_NFS = _protocol("nfs", [2049])
_RSYNC = _protocol("rsync", [873])
_TR069 = _protocol("cwmp", [7547])
_JETDIRECT = _protocol("jetdirect", [9100])
_SSH = _protocol("ssh", [22])

_PROTOCOLS = (
    _TELNET,
    _FTP,
    _VNC,
    _RDP,
    _ADB,
    _REDIS,
    _DOCKER,
    _MEMCACHED,
    _ELASTICSEARCH,
    _MYSQL,
    _POSTGRESQL,
    _MSSQL,
    _MONGODB,
    _MQTT,
    _RTSP,
    _SMB,
    _SOCKS,
    _DVR,
    _WINBOX,
    _PPTP,
    _WEBMIN,
    _NFS,
    _RSYNC,
    _TR069,
    _JETDIRECT,
    _SSH,
)
_KNOWN_NAMES = frozenset().union(*(p.names for p in _PROTOCOLS))

# Always a finding when reachable, with or without a password.
_DATABASES = (_MYSQL, _POSTGRESQL, _MSSQL, _MONGODB)
# These get a rule of their own when they let anyone in.
_GUARDED_DATABASES = (_REDIS, _ELASTICSEARCH)


class Hit(NamedTuple):
    """One thing a rule found on a device, before it becomes a Finding."""

    port: int | None
    params: dict[str, str]
    evidence: str | None = None


@dataclass(frozen=True, slots=True)
class Forward:
    """An enabled port forward from the router, cleaned up."""

    protocol: str
    external_port: int
    client: str  # the address it leads to, or the cleaned text when that is no address
    internal_port: int
    description: str = ""
    remote_host: str = ""
    target: str | None = None  # the device on the network it leads to, None for the router


@dataclass(frozen=True, slots=True)
class Context:
    """What rules need to know beyond the device itself.

    `addresses` are the devices on the network: a port forward to any other
    address is reported on the router. `forwards` is made from `router`.
    """

    gateway: str | None = None
    router: RouterInfo | None = None
    addresses: frozenset[str] = frozenset()
    forwards: tuple[Forward, ...] = field(init=False, default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        known = frozenset(filter(None, map(_address, self.addresses)))
        object.__setattr__(self, "forwards", _forwards(self.router, known))

    def is_gateway(self, device: Device) -> bool:
        if device.is_gateway:
            return True
        return self.gateway is not None and _same_address(device.ip, self.gateway)


Check = Callable[[Device, Context], Iterable[Hit]]


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: str
    check: Check
    # False for the port forward rules: several forwards can lead to one port.
    per_port: bool = True

    def identity(self, finding: Finding) -> tuple:
        """What tells two findings of this rule apart."""
        if self.per_port:
            return (finding.ip, finding.port)
        return (finding.ip, finding.port, tuple(sorted(finding.params.items())), finding.evidence)

    def apply(self, device: Device, context: Context) -> list[Finding]:
        """Run the rule on one device.

        Each port is reported once at most, or for a rule that is not per port,
        each distinct finding once.
        """
        findings: list[Finding] = []
        seen: set[tuple] = set()
        for hit in self.check(device, context):
            finding = Finding(
                self.id, self.severity, device.ip, hit.port, dict(hit.params), hit.evidence
            )
            key = self.identity(finding)
            if key not in seen:
                seen.add(key)
                findings.append(finding)
        return findings


def _clean(value: object, limit: int) -> str:
    """Printable text from untrusted input: control characters gone, spaces collapsed, capped."""
    if value is None:
        return ""
    text = str(value)[: limit * 4]
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in text)
    return " ".join(text.split())[:limit].rstrip()


def _labeled(label: str, value: object) -> str:
    text = _clean(value, _MAX_PART)
    return f"{label}: {text}" if text else ""


def _evidence(*parts: str) -> str | None:
    return _clean("; ".join(part for part in parts if part), MAX_EVIDENCE) or None


def _number(value: object) -> str:
    """Digits only, as a canonical decimal. Empty for anything else."""
    text = _clean(value, 12)
    return str(int(text)) if text.isascii() and text.isdigit() else ""


def _port(value: object, lowest: int = 1) -> int | None:
    """A port number from `lowest` to 65535, else None."""
    text = "" if isinstance(value, bool) else _number(value)
    return int(text) if text and lowest <= int(text) <= 65535 else None


def _address(value: object) -> str | None:
    """The canonical form of an IP address, None for anything else."""
    try:
        return str(ipaddress.ip_address(_clean(value, 64)))
    except ValueError:
        return None


def _name(service: Service) -> str:
    return _clean(service.name, 40).lower()


def _fact(service: Service, key: str) -> str:
    facts = service.facts if isinstance(service.facts, dict) else {}
    return _clean(facts.get(key), _MAX_FACT)


def _is_tcp(service: Service) -> bool:
    return str(service.protocol or "tcp").lower() == "tcp"


def _speaks(service: Service, protocol: _Protocol) -> bool:
    name = _name(service)
    if name in protocol.names:
        return True
    return _is_tcp(service) and service.port in protocol.ports and name not in _KNOWN_NAMES


def _services(device: Device, protocol: _Protocol) -> list[Service]:
    return [service for service in device.services if _speaks(service, protocol)]


def _which(service: Service, protocols: Iterable[_Protocol]) -> _Protocol | None:
    """The protocol a service speaks. The name a probe saw beats the port."""
    protocols = tuple(protocols)
    name = _name(service)
    for protocol in protocols:
        if name in protocol.names:
            return protocol
    for protocol in protocols:
        if _speaks(service, protocol):
            return protocol
    return None


def _is_web(service: Service) -> bool:
    return _name(service) in _WEB_NAMES or bool(_fact(service, "login") or _fact(service, "status"))


def _no_auth(service: Service) -> bool:
    return service.auth == "none"


def _auth_or_unknown(service: Service) -> bool:
    return service.auth != "none"


def _seen(service: Service) -> str:
    """The most telling thing a service said about itself."""
    if _is_web(service):
        return _labeled("server", service.product) or _labeled("banner", service.banner)
    return _labeled("banner", service.banner) or _labeled("product", service.product)


def _seen_evidence(service: Service) -> str | None:
    return _evidence(_seen(service))


def _ftp_evidence(service: Service) -> str | None:
    return _evidence(_seen(service), "anonymous login accepted" if _no_auth(service) else "")


def _vnc_evidence(service: Service) -> str | None:
    types = [_clean(item, 40) for item in _fact(service, "security").split(",")[:8]]
    listed = ", ".join(item for item in types if item)
    return _evidence(_seen(service), f"security types: {listed}" if listed else "")


def _adb_evidence(service: Service) -> str | None:
    return _evidence(_labeled("state", _fact(service, "state")), _seen(service))


def _mqtt_evidence(service: Service) -> str | None:
    code = _number(_fact(service, "connack"))
    return _evidence(f"CONNACK return code {code}" if code else "", _seen(service))


def _rtsp_evidence(service: Service) -> str | None:
    status = _number(_fact(service, "describe"))
    return _evidence(f"DESCRIBE answered {status}" if status else "", _seen(service))


def _socks_evidence(service: Service) -> str | None:
    version = _number(_fact(service, "version"))
    return _evidence(f"SOCKS{version}" if version else "", "no authentication required")


def _exposed(
    protocol: _Protocol,
    *,
    when: Callable[[Service], bool] | None = None,
    product: bool = False,
    gateway_only: bool = False,
    evidence: Callable[[Service], str | None] = _seen_evidence,
) -> Check:
    """A rule for a service that should not be reachable, or not without a password."""

    def check(device: Device, context: Context) -> Iterator[Hit]:
        if gateway_only and not context.is_gateway(device):
            return
        for service in _services(device, protocol):
            if when is not None and not when(service):
                continue
            params = {"port": str(service.port)}
            if product:
                params["product"] = _clean(service.product, _MAX_PARAM)
            yield Hit(service.port, params, evidence(service))

    return check


def _database_open(device: Device, context: Context) -> Iterator[Hit]:
    for service in device.services:
        protocol = _which(service, (*_DATABASES, *_GUARDED_DATABASES))
        if protocol is None or (protocol in _GUARDED_DATABASES and _no_auth(service)):
            continue
        params = {"port": str(service.port), "service": protocol.label}
        unlocked = "answered without credentials" if _no_auth(service) else ""
        yield Hit(service.port, params, _evidence(_seen(service), unlocked))


def _smb1_enabled(device: Device, context: Context) -> Iterator[Hit]:
    # SMB1 is a setting of the server, so one finding per device is enough.
    services = [s for s in device.services if _fact(s, "smb1") == "yes"]
    if services:
        service = min(services, key=lambda s: (not _speaks(s, _SMB), s.port))
        evidence = _evidence("server accepts SMB1", _seen(service))
        yield Hit(service.port, {"port": str(service.port)}, evidence)


def _rsync_open(device: Device, context: Context) -> Iterator[Hit]:
    for service in _services(device, _RSYNC):
        modules = _number(_fact(service, "modules")) or "0"
        listed = ""
        if modules != "0":
            listed = f"{modules} module listed" if modules == "1" else f"{modules} modules listed"
        params = {"port": str(service.port), "modules": modules}
        yield Hit(service.port, params, _evidence(_seen(service), listed))


def _login_over_http(device: Device, context: Context) -> Iterator[Hit]:
    # One plain-text login page tells the story. Routers often have several.
    services = [s for s in device.services if not s.tls and _fact(s, "login") in _LOGINS]
    if services:
        service = min(services, key=lambda s: s.port)
        evidence = _evidence(_LOGINS[_fact(service, "login")], _seen(service))
        yield Hit(service.port, {"port": str(service.port)}, evidence)


def _old_tls(device: Device, context: Context) -> Iterator[Hit]:
    for service in device.services:
        version = service.tls_version
        if version in OLD_TLS:
            yield Hit(service.port, {"port": str(service.port), "version": version}, version)


def _urn_parts(urn: object) -> list[str]:
    """["schemas-upnp-org", "device", "InternetGatewayDevice", "1"] from its URN."""
    parts = _clean(urn, 200).split(":")
    if len(parts) >= 5 and parts[0].lower() == "urn":
        return parts[1:5]
    return []


def _upnp_igd(device: Device, context: Context) -> Iterator[Hit]:
    upnp = device.upnp
    if upnp is None or not context.is_gateway(device):
        return
    gateways = sorted(
        f"{parts[2]}:{parts[3]}"
        for parts in map(_urn_parts, upnp.device_types)
        if parts and parts[1].lower() == "device" and parts[2].lower() == "internetgatewaydevice"
    )
    if not gateways:
        return
    mapping = sorted(
        {
            f"{parts[2]}:{parts[3]}"
            for parts in (_urn_parts(service.service_type) for service in upnp.services)
            if parts and parts[2].lower() in _PORT_MAPPING
        }
    )
    services = f"services: {', '.join(mapping)}" if mapping else ""
    yield Hit(None, {}, _evidence(gateways[0], services))


def _unknown_device(device: Device, context: Context) -> Iterator[Hit]:
    if device.kind == "unknown" and not device.is_self:
        yield Hit(None, {}, _evidence(_labeled("vendor", device.vendor)))


def _forwards(router: RouterInfo | None, addresses: frozenset[str]) -> tuple[Forward, ...]:
    """The enabled forwards a router listed, each once, with the device each leads to."""
    if router is None or not isinstance(router.mappings, (list, tuple)):
        return ()
    forwards: dict[tuple, Forward] = {}
    for mapping in router.mappings[:MAX_FORWARDS]:
        if not isinstance(mapping, PortMapping) or not mapping.enabled:
            continue
        external = _port(mapping.external_port, lowest=0)
        internal = _port(mapping.internal_port)
        if external is None or internal is None:
            continue
        protocol = _clean(mapping.protocol, 8).upper()
        text = _clean(mapping.internal_client, 64)
        address = _address(text)
        client = address or text
        remote = _clean(mapping.remote_host, 64)
        key = (protocol, external, client, internal, remote)
        if key not in forwards:
            forwards[key] = Forward(
                protocol,
                external,
                client,
                internal,
                description=_clean(mapping.description, _MAX_PARAM),
                remote_host=remote,
                target=address if address in addresses else None,
            )
    return tuple(forwards.values())


def _forward_hit(forward: Forward) -> Hit:
    params = {
        "external_port": str(forward.external_port),
        "internal_port": str(forward.internal_port),
        "protocol": forward.protocol,
        "description": forward.description,
    }
    client = f"[{forward.client}]" if ":" in forward.client else forward.client
    seen = f"{forward.protocol} {forward.external_port} to {client}:{forward.internal_port}"
    if forward.description:
        seen += f" ({forward.description})"
    evidence = _evidence(seen, _labeled("only from", forward.remote_host))
    return Hit(forward.internal_port, params, evidence)


def _port_forward(*, risky: bool) -> Check:
    """A rule for the router's port forwards, to risky services or to anything else."""

    def check(device: Device, context: Context) -> Iterator[Hit]:
        here = _address(device.ip)
        gateway = context.is_gateway(device)
        for forward in context.forwards:
            leads_here = gateway if forward.target is None else forward.target == here
            if leads_here and (forward.internal_port in _RISKY_PORTS) == risky:
                yield _forward_hit(forward)

    return check


def _ipv4(value: object) -> ipaddress.IPv4Address | None:
    try:
        address = ipaddress.ip_address(_clean(value, 64))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        return address.ipv4_mapped
    return address


def _external_in(networks: tuple[ipaddress.IPv4Network, ...]) -> Check:
    """A rule for a router whose internet address is in one of `networks`."""

    def check(device: Device, context: Context) -> Iterator[Hit]:
        router = context.router
        if router is None or not context.is_gateway(device):
            return
        address = _ipv4(router.external_ip)
        if address is not None and any(address in network for network in networks):
            connection = _labeled("connection", router.connection)
            evidence = _evidence(f"external IP: {address}", connection)
            yield Hit(None, {"external_ip": str(address)}, evidence)

    return check


_ROUTER_RULES: tuple[Rule, ...] = (
    Rule("port-forward-risky", "high", _port_forward(risky=True), per_port=False),
    Rule("port-forward", "low", _port_forward(risky=False), per_port=False),
    Rule("double-nat", "info", _external_in(_PRIVATE)),
    Rule("cgnat", "info", _external_in(_SHARED)),
)

RULES: tuple[Rule, ...] = (
    Rule("telnet-open", "high", _exposed(_TELNET)),
    Rule("ftp-open", "medium", _exposed(_FTP, product=True, evidence=_ftp_evidence)),
    Rule("vnc-no-auth", "critical", _exposed(_VNC, when=_no_auth, evidence=_vnc_evidence)),
    Rule("vnc-open", "medium", _exposed(_VNC, when=_auth_or_unknown, evidence=_vnc_evidence)),
    Rule("rdp-open", "medium", _exposed(_RDP)),
    Rule(
        "adb-open",
        "critical",
        _exposed(_ADB, when=_no_auth, product=True, evidence=_adb_evidence),
    ),
    Rule("adb-exposed", "medium", _exposed(_ADB, when=_auth_or_unknown, evidence=_adb_evidence)),
    Rule("redis-no-auth", "critical", _exposed(_REDIS, when=_no_auth)),
    Rule("docker-api-open", "critical", _exposed(_DOCKER, when=_no_auth, product=True)),
    Rule("memcached-open", "high", _exposed(_MEMCACHED)),
    Rule("elasticsearch-no-auth", "high", _exposed(_ELASTICSEARCH, when=_no_auth, product=True)),
    Rule("database-open", "medium", _database_open),
    Rule("mqtt-anonymous", "high", _exposed(_MQTT, when=_no_auth, evidence=_mqtt_evidence)),
    Rule("rtsp-no-auth", "high", _exposed(_RTSP, when=_no_auth, evidence=_rtsp_evidence)),
    Rule("smb1-enabled", "high", _smb1_enabled),
    Rule("socks-no-auth", "high", _exposed(_SOCKS, when=_no_auth, evidence=_socks_evidence)),
    Rule("dvr-port-open", "high", _exposed(_DVR)),
    Rule("winbox-open", "medium", _exposed(_WINBOX)),
    Rule("pptp-open", "medium", _exposed(_PPTP)),
    Rule("webmin-open", "medium", _exposed(_WEBMIN)),
    Rule("nfs-open", "medium", _exposed(_NFS)),
    Rule("rsync-open", "medium", _rsync_open),
    Rule("login-over-http", "medium", _login_over_http),
    Rule("old-tls", "low", _old_tls),
    Rule("upnp-igd", "medium", _upnp_igd),
    Rule("tr069-open", "low", _exposed(_TR069, gateway_only=True)),
    Rule("jetdirect-open", "low", _exposed(_JETDIRECT)),
    Rule("smb-open", "info", _exposed(_SMB)),
    Rule("ssh-open", "info", _exposed(_SSH, product=True)),
    Rule("unknown-device", "info", _unknown_device),
    *_ROUTER_RULES,
)
RULE_IDS: tuple[str, ...] = tuple(r.id for r in RULES)

_BY_ID = {r.id: r for r in RULES}
_RULE_RANK = {rule_id: rank for rank, rule_id in enumerate(RULE_IDS)}
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}


def rule(rule_id: str) -> Rule:
    """The rule with this id. Raises KeyError for an unknown one."""
    try:
        return _BY_ID[rule_id]
    except KeyError:
        raise KeyError(f"no such rule: {rule_id!r}") from None


def _same_address(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return a == b


def _address_key(ip: str) -> tuple[int, int, str]:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return (99, 0, ip)
    return (address.version, int(address), ip)


def _order(finding: Finding) -> tuple:
    params = finding.params
    return (
        _SEVERITY_RANK.get(finding.severity, len(SEVERITIES)),
        _address_key(finding.ip),
        finding.port is not None,
        finding.port or 0,
        _RULE_RANK.get(finding.rule, len(RULES)),
        # Several port forwards can lead to one port.
        _port(params.get("external_port"), lowest=0) or 0,
        params.get("protocol", ""),
        finding.evidence or "",
    )


def evaluate(
    devices: Iterable[Device],
    *,
    gateway: str | None = None,
    router: RouterInfo | None = None,
) -> list[Finding]:
    """Run every rule on every device.

    `router` is what the gateway said about itself over UPnP. Findings that
    belong on the router go to the device marked as the gateway, or to the
    `gateway` address when no device is; without either they are dropped.

    Returns the findings most severe first, then by address and port. A rule
    reports a device and port once, even if the device is listed twice. The
    port forward rules report each forward once.
    """
    devices = list(devices)
    context = Context(gateway, router, frozenset(device.ip for device in devices))
    checks = [(device, RULES) for device in devices]
    if router is not None and gateway and not any(context.is_gateway(d) for d in devices):
        # The router answered but is not in the list. Its findings still need a place.
        checks.append((Device(gateway, kind="router", is_gateway=True), _ROUTER_RULES))
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for device, items in checks:
        for item in items:
            for finding in item.apply(device, context):
                key = (item.id, *item.identity(finding))
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
    findings.sort(key=_order)
    return findings
