"""Find UPnP devices with SSDP and read the device descriptions they point to."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import math
import re
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import defusedxml.ElementTree

from .. import http
from ..models import UpnpInfo, UpnpService
from ..scope import is_local
from . import _udp

SSDP_GROUP = ("239.255.255.250", 1900)

MAX_VALUE = 512
MAX_REPLIES_PER_HOST = 64
MAX_DESCRIPTION = 128 * 1024
MAX_TEXT = 200
MAX_URL = 2048
MAX_DEPTH = 6
MAX_DEVICES = 64
MAX_DEVICE_TYPES = 32
MAX_SERVICES = 64
MAX_FETCHES = 8
MAX_LOCATIONS = 4  # descriptions read per host
FETCH_TIMEOUT = 0.75  # seconds for one description
# Less time than this left is not worth starting a fetch for. Timers on Windows
# tick every 15.6 ms, so a wait can end a hair before the deadline.
MIN_FETCH = 0.05

_MAX_MESSAGE = 16 * 1024
_MAX_LINES = 64
# The ssdp:all answers list everything, rootdevice catches stacks that skip them.
_TARGETS = ("ssdp:all", "upnp:rootdevice")
_SPACING = 0.15

_RESPONSE = re.compile(r"HTTP/1\.\d 200(?: .*)?")
_NOTIFY = re.compile(r"NOTIFY \* HTTP/1\.\d")
# Separators, not category C, but they still break the line they are printed on.
_LINE_BREAKS = "\u2028\u2029"
_DEVICE_TYPE = re.compile(r"urn:[^:\s]+:device:[^:\s]+:\d+")
# Expat rebuilds "uri}name" for every element, so one long namespace URI makes
# a small document slow to parse.
# XML puts whitespace before every attribute. Anchoring on it keeps runs of
# "xmlns:" in element text from overlapping, which made the search quadratic.
_LONG_NAMESPACE = re.compile(rb"\sxmlns(?::[^\s=]*)?\s*=\s*(?:\"[^\"]{256}|'[^']{256})")


class DescriptionError(ValueError):
    """A device description that is too big, not well-formed, or costly to parse."""


@dataclass(slots=True)
class SsdpReply:
    ip: str
    location: str | None
    server: str | None
    st: str | None  # NT for a NOTIFY
    usn: str | None


def _clean(text: str, limit: int) -> str | None:
    """Text safe to print: control, format and unassigned characters become spaces."""
    text = "".join(
        " " if unicodedata.category(ch)[0] == "C" or ch in _LINE_BREAKS else ch for ch in text
    )
    return " ".join(text.split())[:limit] or None


def parse_reply(data: bytes, ip: str) -> SsdpReply | None:
    """Read an M-SEARCH response or a NOTIFY announcement. None for anything else."""
    lines = data[:_MAX_MESSAGE].decode("utf-8", errors="replace").split("\n")
    start = " ".join(lines[0].split()).upper()
    if _RESPONSE.fullmatch(start):
        notify = False
    elif _NOTIFY.fullmatch(start):
        notify = True
    else:
        return None

    headers: dict[str, str | None] = {}
    for line in lines[1:_MAX_LINES]:
        name, colon, value = line.partition(":")
        name = name.strip().lower()
        if colon and name and name not in headers:
            headers[name] = _clean(value[: MAX_VALUE * 2], MAX_VALUE)
    if notify and (headers.get("nts") or "").lower() == "ssdp:byebye":
        return None  # the device is leaving
    return SsdpReply(
        ip=ip,
        location=headers.get("location"),
        server=headers.get("server"),
        st=headers.get("nt" if notify else "st"),
        usn=headers.get("usn"),
    )


def _msearch(target: str) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_GROUP[0]}:{SSDP_GROUP[1]}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {target}\r\n"
        "\r\n"
    ).encode()


def _wanted(sender: str, network: ipaddress.IPv4Network | None) -> bool:
    try:
        address = ipaddress.ip_address(sender)
    except ValueError:
        return False
    return is_local(address) and (network is None or address in network)


async def search(
    local: str, *, duration: float = 2.5, network: ipaddress.IPv4Network | None = None
) -> dict[str, list[SsdpReply]]:
    """Ask the UPnP devices on the network to answer, and collect what they say.

    `local` is our own LAN address; the queries go out of that interface. Each
    query is sent twice, since multicast over Wi-Fi gets lost. Returns replies
    grouped by sender, local addresses only. With `network` given, senders
    outside it are dropped too, so describe() never fetches from them.
    """
    if not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration <= 0:
        raise ValueError(f"duration must be a positive number of seconds, not {duration!r}")
    packets = [(_msearch(target), SSDP_GROUP) for target in _TARGETS] * 2
    listen = max(duration - _SPACING * (len(packets) - 1), 0.1)
    raw = await _udp.exchange(
        packets, local=local, listen=listen, spacing=_SPACING, multicast_ttl=2
    )

    found: dict[str, list[SsdpReply]] = {}
    seen: set[tuple[str | None, ...]] = set()
    for data, sender in raw:
        if not _wanted(sender, network):
            continue
        reply = parse_reply(data, sender)
        if reply is None:
            continue
        key = (sender, reply.location, reply.server, reply.st, reply.usn)
        replies = found.setdefault(sender, [])
        if key in seen or len(replies) >= MAX_REPLIES_PER_HOST:
            continue
        seen.add(key)
        replies.append(reply)
    return found


def _text(element: ET.Element | None, limit: int = MAX_TEXT) -> str | None:
    if element is None or element.text is None:
        return None
    return _clean(element.text, limit)


def _host_key(url: str) -> object:
    """What to compare to decide whether two URLs point at the same host."""
    host = urllib.parse.urlsplit(url).hostname
    if not host:
        raise ValueError(f"no host in {url!r}")
    host = urllib.parse.unquote(host)
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return host


def _absolute(base: str, reference: str, host: object) -> str | None:
    """`reference` made absolute, or None when it leads to another host."""
    try:
        url = urllib.parse.urljoin(base, reference)
        scheme = urllib.parse.urlsplit(url).scheme
        same_host = _host_key(url) == host
    except ValueError:
        return None
    if scheme not in ("http", "https") or not same_host or len(url) > MAX_URL:
        return None
    return url


def _service(element: ET.Element, base: str, host: object) -> UpnpService | None:
    service_type = _text(element.find("serviceType"))
    control = _text(element.find("controlURL"), MAX_URL + 1)
    if not service_type or not control:
        return None
    control_url = _absolute(base, control, host)
    if control_url is None:
        return None
    scpd = _text(element.find("SCPDURL"), MAX_URL + 1)
    return UpnpService(service_type, control_url, _absolute(base, scpd, host) if scpd else None)


def parse_description(xml: bytes, base_url: str) -> UpnpInfo:
    """Read a UPnP device description: names, device types and services.

    `base_url` is where the description came from. Service URLs are made
    absolute, and services that point at another host are left out. Raises
    DescriptionError for documents that are too big, not well-formed, or
    built to make the parser slow or hungry (a DTD, a long namespace URI).
    """
    return _read_description(xml, base_url)[0]


def _read_description(xml: bytes, base_url: str) -> tuple[UpnpInfo, str | None]:
    """parse_description, plus the deviceType of the root device."""
    if len(xml) > MAX_DESCRIPTION:
        raise DescriptionError(f"description is over {MAX_DESCRIPTION} bytes")
    # UPnP descriptions are UTF-8. NUL bytes mean UTF-16, which would get a
    # long namespace past the check below.
    if b"\x00" in xml:
        raise DescriptionError("description has NUL bytes")
    if _LONG_NAMESPACE.search(xml):
        raise DescriptionError("description has a namespace URI over 255 bytes")
    try:
        root = defusedxml.ElementTree.fromstring(xml, forbid_dtd=True)
    except (ET.ParseError, ValueError, LookupError, RecursionError) as exc:
        # defusedxml refuses a DTD with a ValueError subclass.
        raise DescriptionError(f"not a usable description: {exc}") from None

    # Plenty of devices get the namespace wrong or leave it out.
    for element in root.iter():
        if isinstance(element.tag, str):
            element.tag = element.tag.rpartition("}")[2]
    device = root if root.tag == "device" else root.find("device")
    if device is None:
        raise DescriptionError("no device element")

    try:
        host = _host_key(base_url)
    except ValueError:
        host = None
    base = base_url
    url_base = _text(root.find("URLBase"), MAX_URL + 1)
    if url_base:
        with contextlib.suppress(ValueError):
            base = urllib.parse.urljoin(base_url, url_base)

    info = UpnpInfo(
        friendly_name=_text(device.find("friendlyName")),
        manufacturer=_text(device.find("manufacturer")),
        model_name=_text(device.find("modelName")),
        model_number=_text(device.find("modelNumber")),
    )
    # Depth first, in document order, without recursion.
    stack = [(device, 0)]
    walked = 0
    while stack and walked < MAX_DEVICES:
        current, depth = stack.pop()
        walked += 1
        device_type = _text(current.find("deviceType"))
        if device_type and len(info.device_types) < MAX_DEVICE_TYPES:
            info.device_types.add(device_type)
        for element in current.iterfind("serviceList/service"):
            if len(info.services) >= MAX_SERVICES:
                break
            service = _service(element, base, host) if host is not None else None
            if service is not None and service not in info.services:
                info.services.append(service)
        if depth < MAX_DEPTH:
            children = current.findall("deviceList/device")
            stack.extend((child, depth + 1) for child in reversed(children))
    return info, _text(device.find("deviceType"))


def _rank(device_type: str | None) -> int:
    """How well a root device's description names its host. Lower is better.

    Routers run a WPS daemon (WFADevice) and often a media server next to the
    gateway, and those descriptions carry chipset or software names.
    """
    if not device_type or not _DEVICE_TYPE.fullmatch(device_type):
        return 2
    _, domain, _, kind, _ = device_type.lower().split(":")
    if domain == "schemas-upnp-org":
        if kind == "internetgatewaydevice":
            return 0
        return 3 if kind == "mediaserver" else 1
    if domain == "schemas-wifialliance-org" and kind == "wfadevice":
        return 3
    return 2


def _reply_types(reply: SsdpReply) -> list[str]:
    """The device types a reply names in its ST (NT) or at the end of its USN."""
    candidates = (reply.st, reply.usn.rpartition("::")[2] if reply.usn else None)
    return [c for c in candidates if c and _DEVICE_TYPE.fullmatch(c)]


def _types_from_replies(replies: list[SsdpReply]) -> set[str]:
    types: set[str] = set()
    for reply in replies:
        for device_type in _reply_types(reply):
            types.add(device_type)
            if len(types) >= MAX_DEVICE_TYPES:
                return types
    return types


def _points_at(url: str, sender: object) -> bool:
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        return scheme in ("http", "https") and _host_key(url) == sender
    except ValueError:
        return False


def _locations_for(ip: str, replies: list[SsdpReply]) -> list[str]:
    """The http(s) LOCATIONs that point back at the host that sent them.

    Best first, going by the device types named in the replies that carried
    each one, so a router's gateway description is read before its WPS one.
    Ties keep the order they arrived in.
    """
    try:
        sender = ipaddress.ip_address(ip)
    except ValueError:
        return []
    if not is_local(sender):
        return []
    types: dict[str, set[str]] = {}
    for reply in replies:
        if reply.location:
            types.setdefault(reply.location, set()).update(_reply_types(reply))
    found = [location for location in types if _points_at(location, sender)]
    found.sort(key=lambda location: min(map(_rank, types[location]), default=2))
    return found[:MAX_LOCATIONS]


def _merge(info: UpnpInfo, found: UpnpInfo) -> None:
    """Add what one more description says. Names already set stay."""
    info.friendly_name = info.friendly_name or found.friendly_name
    info.manufacturer = info.manufacturer or found.manufacturer
    # A model number goes with the model name from the same description.
    if not info.model_name and not info.model_number:
        info.model_name, info.model_number = found.model_name, found.model_number
    for device_type in found.device_types:
        if len(info.device_types) < MAX_DEVICE_TYPES:
            info.device_types.add(device_type)
    for service in found.services:
        if len(info.services) < MAX_SERVICES and service not in info.services:
            info.services.append(service)


async def describe(
    replies: dict[str, list[SsdpReply]], *, timeout: float = 2.0
) -> dict[str, UpnpInfo]:
    """Fetch and read the device descriptions of every host that answered.

    A router often runs several UPnP root devices, each with a description of
    its own, so up to MAX_LOCATIONS of them are read per host, best first and
    one at a time. The names and the location come from the best description
    that has a name or model; the others add device types and services and
    only fill gaps. A host whose descriptions cannot be fetched or read still
    gets what its SSDP replies said. The whole thing takes about `timeout`
    seconds at most.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    gate = asyncio.Semaphore(MAX_FETCHES)

    async def read(location: str) -> tuple[UpnpInfo, str | None] | None:
        async with gate:
            left = deadline - loop.time()
            if left < MIN_FETCH:
                return None
            try:
                response = await http.fetch(
                    location, timeout=min(left, FETCH_TIMEOUT), limit=MAX_DESCRIPTION
                )
                if response.status != 200 or response.truncated:
                    return None
                return _read_description(response.body, location)
            except (OSError, ValueError):
                return None

    async def one(ip: str, host_replies: list[SsdpReply]) -> UpnpInfo:
        server = next((r.server for r in host_replies if r.server), None)
        info = UpnpInfo(server=server, device_types=_types_from_replies(host_replies))
        locations = _locations_for(ip, host_replies)
        if not locations:
            return info
        parsed: list[tuple[int, str, UpnpInfo]] = []
        # One at a time, so a host that never answers holds one slot, not four.
        for location in locations:
            described = await read(location)
            if described is not None:
                found, root_type = described
                parsed.append((_rank(root_type), location, found))
        parsed.sort(key=lambda item: item[0])
        for index, (_, _, found) in enumerate(parsed):
            if found.friendly_name or found.model_name:
                parsed.insert(0, parsed.pop(index))
                break
        # The location belongs with the description the names came from.
        info.location = parsed[0][1] if parsed else locations[0]
        for _, _, found in parsed:
            _merge(info, found)
        return info

    tasks = [asyncio.ensure_future(one(ip, host_replies)) for ip, host_replies in replies.items()]
    try:
        results = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    return dict(zip(replies, results, strict=True))
