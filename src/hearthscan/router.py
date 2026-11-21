"""Ask the router about its internet connection and its port forwards over UPnP.

The gateway's WANIPConnection or WANPPPConnection service answers SOAP
requests. Only four actions are ever sent, and all of them read: the external
address, the connection status, the connection type and the port mapping
list, one entry at a time. Nothing on the router is added, changed or deleted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Mapping
from typing import Any
from xml.sax.saxutils import escape

import defusedxml.ElementTree

from . import http
from .models import Device, PortMapping, RouterInfo, UpnpService

# Best first.
WAN_SERVICES = (
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)

# Every other action of these services changes something on the router.
READ_ACTIONS = frozenset(
    {
        "GetExternalIPAddress",
        "GetStatusInfo",
        "GetConnectionTypeInfo",
        "GetGenericPortMappingEntry",
    }
)

MAX_RESPONSE = 64 * 1024
MAX_MAPPINGS = 256
MAX_FIELDS = 32  # arguments read from one answer
MAX_TEXT = 200
MAX_NAME = 64  # connection status and type, remote host
MAX_PROTOCOL = 8
MAX_TRIED = 3  # WAN services asked while looking for the one in use
REQUEST_TIMEOUT = 2.0  # seconds, at most, for one request
# Less time left than this is not worth starting a request for.
MIN_REQUEST = 0.05

# SpecifiedArrayIndexInvalid and NoSuchEntryInArray: past the end of the list.
_END_OF_LIST = (713, 714)
_UINT32_MAX = 0xFFFFFFFF

_SOAP_ENVELOPE = "http://schemas.xmlsoap.org/soap/envelope/"
_SOAP_ENCODING = "http://schemas.xmlsoap.org/soap/encoding/"
_ARGUMENT = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
_NUMBER = re.compile(r"[0-9]{1,10}")
_LINE_BREAKS = "\u2028\u2029"
# The same guard as in discovery.ssdp: expat rebuilds "uri}name" for every
# element, so one long namespace URI makes a small document slow to parse.
_LONG_NAMESPACE = re.compile(rb"\sxmlns(?::[^\s=]*)?\s*=\s*(?:\"[^\"]{256}|'[^']{256})")


class SoapError(ValueError):
    """An answer that is not the expected SOAP response: broken, too big or something else."""


class UpnpError(SoapError):
    """The router turned the request down with a SOAP fault."""

    def __init__(self, code: int | None, description: str = "") -> None:
        self.code = code
        self.description = description
        message = f"UPnP error {code}" if code is not None else "UPnP error without a code"
        super().__init__(f"{message}: {description}" if description else message)


def _clean(text: str | None, limit: int = MAX_TEXT) -> str:
    """Text safe to show: control, format and unassigned characters become spaces."""
    if not text:
        return ""
    text = "".join(
        " " if unicodedata.category(ch)[0] == "C" or ch in _LINE_BREAKS else ch
        for ch in text[: limit * 8]
    )
    return " ".join(text.split())[:limit].rstrip()


def _local(tag: object) -> str:
    """An element name without its namespace, whatever prefix the router used."""
    return tag.rpartition("}")[2] if isinstance(tag, str) else ""


def _unmap(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _on_host(url: str, host: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return False
        return _unmap(ipaddress.ip_address(urllib.parse.unquote(parts.hostname))) == host
    except ValueError:
        return False


def _wan_services(device: Device) -> list[UpnpService]:
    """Every WAN connection service the device offers on its own address, best first."""
    if device.upnp is None:
        return []
    try:
        own = _unmap(ipaddress.ip_address(device.ip))
    except ValueError:
        return []
    found: list[UpnpService] = []
    for service_type in WAN_SERVICES:
        for service in device.upnp.services:
            if (
                service.service_type == service_type
                and _on_host(service.control_url, own)
                and service not in found
            ):
                found.append(service)
    return found


def wan_service(device: Device) -> UpnpService | None:
    """The best WAN connection service of the device whose control URL is on its own IP."""
    services = _wan_services(device)
    return services[0] if services else None


def _envelope(service_type: str, action: str, arguments: Mapping[str, str]) -> bytes:
    parts = []
    for name, value in arguments.items():
        if not isinstance(name, str) or not _ARGUMENT.fullmatch(name):
            raise ValueError(f"not a valid argument name: {name!r}")
        if not isinstance(value, str):
            raise ValueError(f"argument {name} should be text, not {value!r}")
        parts.append(f"<{name}>{escape(value)}</{name}>")
    return (
        '<?xml version="1.0" encoding="utf-8"?>\r\n'
        f'<s:Envelope xmlns:s="{_SOAP_ENVELOPE}" s:encodingStyle="{_SOAP_ENCODING}">'
        f'<s:Body><u:{action} xmlns:u="{service_type}">{"".join(parts)}</u:{action}></s:Body>'
        "</s:Envelope>\r\n"
    ).encode()


def _parse_xml(body: bytes) -> ET.Element:
    if len(body) > MAX_RESPONSE:
        raise SoapError(f"answer is over {MAX_RESPONSE} bytes")
    # SOAP answers are UTF-8. NUL bytes mean UTF-16, which would get a long
    # namespace past the check below.
    if b"\x00" in body:
        raise SoapError("answer has NUL bytes")
    if _LONG_NAMESPACE.search(body):
        raise SoapError("answer has a namespace URI over 255 bytes")
    try:
        return defusedxml.ElementTree.fromstring(body, forbid_dtd=True)
    except (ET.ParseError, ValueError, LookupError, RecursionError) as exc:
        # defusedxml refuses a DTD with a ValueError subclass.
        raise SoapError(f"not a usable answer: {exc}") from None


def _fault(fault: ET.Element) -> UpnpError:
    code = None
    description = ""
    for element in fault.iter():
        name = _local(element.tag)
        if name == "errorCode" and code is None:
            text = _clean(element.text, 16)
            if _NUMBER.fullmatch(text):
                code = int(text)
        elif name == "errorDescription" and not description:
            description = _clean(element.text, 120)
    return UpnpError(code, description)


def parse_response(body: bytes, action: str, *, status: int = 200) -> dict[str, str]:
    """The arguments of a SOAP answer to `action`, by name, as cleaned text.

    Raises UpnpError for a SOAP fault (its code is None when the fault names
    none) and SoapError for anything else that is not the answer expected.
    """
    try:
        root = _parse_xml(body)
    except SoapError:
        if status != 200:
            raise SoapError(f"HTTP status {status} without a SOAP fault") from None
        raise
    wanted = f"{action}Response"
    answer = None
    for element in root.iter():
        name = _local(element.tag)
        if name == "Fault":
            raise _fault(element)
        if name == wanted and answer is None:
            answer = element
    if status != 200:
        raise SoapError(f"HTTP status {status} without a SOAP fault")
    if answer is None:
        raise SoapError(f"no {wanted} in the answer")
    values: dict[str, str] = {}
    for child in answer:
        name = _local(child.tag)
        if not name or name in values:
            continue
        if len(values) >= MAX_FIELDS:
            break
        values[name] = _clean(child.text)
    return values


async def call(
    service: UpnpService,
    action: str,
    arguments: Mapping[str, str] | None = None,
    *,
    timeout: float = REQUEST_TIMEOUT,
) -> dict[str, str]:
    """Send one read-only action to a WAN connection service and return its answer.

    Raises ValueError for an action outside READ_ACTIONS or a service outside
    WAN_SERVICES, before anything is sent. Otherwise raises UpnpError for a
    SOAP fault, SoapError for another unusable answer, and what http.fetch
    raises.
    """
    if not isinstance(action, str) or action not in READ_ACTIONS:
        raise ValueError(f"{action!r} is not one of the read-only actions")
    if service.service_type not in WAN_SERVICES:
        raise ValueError(f"{service.service_type!r} is not a WAN connection service")
    body = _envelope(service.service_type, action, arguments or {})
    response = await http.fetch(
        service.control_url,
        method="POST",
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service.service_type}#{action}"',
        },
        body=body,
        timeout=timeout,
        limit=MAX_RESPONSE,
    )
    if response.truncated:
        raise SoapError(f"answer to {action} is over {MAX_RESPONSE} bytes or cut short")
    return parse_response(response.body, action, status=response.status)


async def _within(
    service: UpnpService,
    action: str,
    deadline: float,
    arguments: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """call() with the time left before `deadline`, REQUEST_TIMEOUT at most."""
    left = deadline - asyncio.get_running_loop().time()
    if left < MIN_REQUEST:
        raise TimeoutError(f"no time left for {action}")
    return await call(service, action, arguments, timeout=min(left, REQUEST_TIMEOUT))


async def _ask(service: UpnpService, action: str, deadline: float) -> dict[str, str]:
    """_within(), with an empty answer when it failed for any reason."""
    try:
        return await _within(service, action, deadline)
    except (OSError, ValueError):
        return {}


async def _together(*jobs: Awaitable[Any]) -> list[Any]:
    tasks = [asyncio.ensure_future(job) for job in jobs]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def _short(value: str | None, limit: int) -> str:
    return (value or "")[:limit].rstrip()


def _number(value: str | None) -> int | None:
    if not value or not _NUMBER.fullmatch(value):
        return None
    number = int(value)
    return number if number <= _UINT32_MAX else None


def _port(value: str | None) -> int | None:
    number = _number(value)
    return number if number is not None and 1 <= number <= 65535 else None


def _address(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = _unmap(ipaddress.ip_address(value))
    except ValueError:
        return None
    # A router that is not connected says 0.0.0.0.
    return None if ip.is_unspecified else str(ip)


def _flag(value: str | None) -> bool:
    # Unclear means enabled: a forward that may be open is worth showing.
    return (value or "").lower() not in ("0", "false", "no")


def _mapping(entry: dict[str, str]) -> PortMapping | None:
    """One entry of the list, or None when its ports or internal client make no sense."""
    external = _port(entry.get("NewExternalPort"))
    internal = _port(entry.get("NewInternalPort"))
    client = _address(entry.get("NewInternalClient"))
    if external is None or internal is None or client is None:
        return None
    return PortMapping(
        protocol=_short((entry.get("NewProtocol") or "").upper(), MAX_PROTOCOL),
        external_port=external,
        internal_client=client,
        internal_port=internal,
        description=entry.get("NewPortMappingDescription") or "",
        enabled=_flag(entry.get("NewEnabled")),
        lease=_number(entry.get("NewLeaseDuration")) or 0,
        remote_host=_short(entry.get("NewRemoteHost"), MAX_NAME),
    )


async def _connection(service: UpnpService, deadline: float) -> RouterInfo:
    """External address, status and type. Each answer stands on its own."""
    address, status, kind = await _together(
        _ask(service, "GetExternalIPAddress", deadline),
        _ask(service, "GetStatusInfo", deadline),
        _ask(service, "GetConnectionTypeInfo", deadline),
    )
    return RouterInfo(
        external_ip=_address(address.get("NewExternalIPAddress")),
        connection=_short(kind.get("NewConnectionType"), MAX_NAME) or None,
        status=_short(status.get("NewConnectionStatus"), MAX_NAME) or None,
        uptime=_number(status.get("NewUptime")),
    )


def _in_use(info: RouterInfo) -> bool:
    return info.external_ip is not None or (info.status or "").lower() == "connected"


async def _mappings(service: UpnpService, deadline: float) -> tuple[list[PortMapping], bool]:
    """The port mapping list, and whether it was read to the end."""
    mappings: list[PortMapping] = []
    previous: dict[str, str] | None = None
    for index in range(MAX_MAPPINGS):
        try:
            entry = await _within(
                service,
                "GetGenericPortMappingEntry",
                deadline,
                {"NewPortMappingIndex": str(index)},
            )
        except UpnpError as exc:
            # Other faults (not authorized, action failed) leave the rest unknown.
            return mappings, exc.code in _END_OF_LIST
        except (OSError, ValueError):
            return mappings, False
        # Some routers answer every index past the end with the last entry.
        if entry == previous:
            return mappings, True
        previous = entry
        mapping = _mapping(entry)
        if mapping is not None:
            mappings.append(mapping)
    return mappings, False


async def query(device: Device, *, timeout: float = 4.0) -> RouterInfo | None:
    """Ask the gateway about its internet connection and the ports it forwards.

    None when `device` offers no WAN connection service on its own address.
    Otherwise whatever the router answered within `timeout` seconds in all:
    fields it did not answer stay None, and mappings_complete is False when
    the mapping list was cut short. Network problems and broken answers never
    raise; a bad `timeout` raises ValueError.
    """
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError(f"timeout must be a positive number of seconds, not {timeout!r}")
    services = _wan_services(device)[:MAX_TRIED]
    if not services:
        return None
    deadline = asyncio.get_running_loop().time() + timeout

    # A router with a DSL modem often lists an IP and a PPP connection, and
    # only one of them is in use. The first that is wins; failing that, the
    # best one. miniupnpc chooses the same way.
    chosen = services[0]
    info = await _connection(chosen, deadline)
    if not _in_use(info):
        for service in services[1:]:
            other = await _connection(service, deadline)
            if _in_use(other):
                chosen, info = service, other
                break
    info.mappings, info.mappings_complete = await _mappings(chosen, deadline)
    return info
