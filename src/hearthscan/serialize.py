"""Save a scan result as JSON and read it back.

The file carries a schema number. Readers ignore fields they do not know, so
adding a field keeps the number; renaming or removing one bumps it.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable, Iterable
from dataclasses import fields, is_dataclass
from typing import Any, TypeVar

from .models import (
    SEVERITIES,
    Device,
    Finding,
    MdnsInfo,
    NetbiosInfo,
    ScanResult,
    Service,
    UpnpInfo,
    UpnpService,
    normalize_mac,
)

SCHEMA = 1
TOOL = "hearthscan"

T = TypeVar("T")


def to_dict(result: ScanResult) -> dict[str, Any]:
    """Plain data for json.dump. Devices also get their derived name and random_mac."""
    data: dict[str, Any] = {"schema": SCHEMA, "tool": TOOL}
    data.update(_plain(result))
    data["notes"] = [{"source": source, "message": message} for source, message in result.notes]
    return data


def devices_to_list(devices: Iterable[Device]) -> list[dict[str, Any]]:
    """Devices alone in the same shape as in to_dict, for `hearthscan devices --json`."""
    return [_plain(device) for device in devices]


def from_dict(data: dict[str, Any]) -> ScanResult:
    """Rebuild a ScanResult from to_dict output.

    Missing optional fields get their defaults and unknown ones are ignored.
    Raises ValueError for anything that is not a result of this schema.
    """
    if not isinstance(data, dict) or data.get("tool") != TOOL:
        raise ValueError("not a Hearthscan result")
    schema = data.get("schema")
    if not _is_int(schema):
        raise ValueError("not a Hearthscan result: the schema number is missing")
    if schema != SCHEMA:
        raise ValueError(
            f"this result uses schema {schema}; this version of Hearthscan reads schema {SCHEMA}"
        )
    top = _Object(data, "")
    return ScanResult(
        version=top.get("version", _TEXT),
        started=top.get("started", _TEXT),
        finished=top.get("finished", _TEXT),
        interface=top.get("interface", _TEXT),
        address=top.get("address", _ADDRESS),
        network=top.get("network", _NETWORK),
        gateway=top.get("gateway", _ADDRESS, None),
        devices=[_device(item) for item in top.objects("devices")],
        findings=[_finding(item) for item in top.objects("findings")],
        score=top.get("score", _SCORE, 100),
        ports=top.items("ports", _PORT),
        notes=[
            (item.get("source", _TEXT), item.get("message", _TEXT)) for item in top.objects("notes")
        ],
    )


def dumps(result: ScanResult, *, indent: int | None = 2) -> str:
    """The result as JSON text. Non-ASCII characters are escaped, so any encoding can hold it."""
    return json.dumps(to_dict(result), indent=indent)


def loads(text: str) -> ScanResult:
    """Read a result saved by dumps. Raises ValueError for anything else."""
    try:
        data = json.loads(text)
    except RecursionError:
        raise ValueError("not a Hearthscan result: nested too deeply") from None
    return from_dict(data)


def _plain(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        data = {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
        if isinstance(value, Device):
            data["name"] = value.name
            data["random_mac"] = value.random_mac
        return data
    if isinstance(value, (set, frozenset)):
        return sorted(_plain(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


def _device(obj: _Object) -> Device:
    # name and random_mac are derived from the rest and not read back.
    return Device(
        ip=obj.get("ip", _ADDRESS),
        mac=obj.get("mac", _MAC, None),
        vendor=obj.get("vendor", _TEXT, None),
        dns_name=obj.get("dns_name", _TEXT, None),
        mdns=obj.child("mdns", _mdns),
        upnp=obj.child("upnp", _upnp),
        netbios=obj.child("netbios", _netbios),
        model=obj.get("model", _TEXT, None),
        kind=obj.get("kind", _TEXT, "unknown"),
        evidence=obj.items("evidence", _TEXT),
        services=[_service(item) for item in obj.objects("services")],
        seen_by=set(obj.items("seen_by", _TEXT)),
        confirmed=obj.get("confirmed", _FLAG, False),
        is_gateway=obj.get("is_gateway", _FLAG, False),
        is_self=obj.get("is_self", _FLAG, False),
    )


def _mdns(obj: _Object) -> MdnsInfo:
    return MdnsInfo(
        hostname=obj.get("hostname", _TEXT, None),
        services=set(obj.items("services", _TEXT)),
        instances=obj.pairs("instances"),
        txt={name: table.pairs() for name, table in obj.tables("txt").items()},
    )


def _upnp(obj: _Object) -> UpnpInfo:
    return UpnpInfo(
        server=obj.get("server", _TEXT, None),
        location=obj.get("location", _TEXT, None),
        device_types=set(obj.items("device_types", _TEXT)),
        friendly_name=obj.get("friendly_name", _TEXT, None),
        manufacturer=obj.get("manufacturer", _TEXT, None),
        model_name=obj.get("model_name", _TEXT, None),
        model_number=obj.get("model_number", _TEXT, None),
        services=[
            UpnpService(
                service_type=item.get("service_type", _TEXT),
                control_url=item.get("control_url", _TEXT),
                scpd_url=item.get("scpd_url", _TEXT, None),
            )
            for item in obj.objects("services")
        ],
    )


def _netbios(obj: _Object) -> NetbiosInfo:
    return NetbiosInfo(
        name=obj.get("name", _TEXT, None),
        workgroup=obj.get("workgroup", _TEXT, None),
        mac=obj.get("mac", _MAC, None),
        file_server=obj.get("file_server", _FLAG, False),
    )


def _service(obj: _Object) -> Service:
    return Service(
        port=obj.get("port", _PORT),
        protocol=obj.get("protocol", _TEXT, "tcp"),
        name=obj.get("name", _TEXT, ""),
        banner=obj.get("banner", _TEXT, None),
        product=obj.get("product", _TEXT, None),
        tls=obj.get("tls", _FLAG, False),
        tls_version=obj.get("tls_version", _TEXT, None),
        title=obj.get("title", _TEXT, None),
        auth=obj.get("auth", _TEXT, None),
        facts=obj.pairs("facts"),
    )


def _finding(obj: _Object) -> Finding:
    return Finding(
        rule=obj.get("rule", _TEXT),
        severity=obj.get("severity", _SEVERITY),
        ip=obj.get("ip", _ADDRESS),
        port=obj.get("port", _PORT, None),
        params=obj.pairs("params"),
        evidence=obj.get("evidence", _TEXT, None),
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_address(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_network(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


# What a field must be: a test and how an error message names it.
_Check = tuple[Callable[[Any], bool], str]

_TEXT: _Check = (lambda value: isinstance(value, str), "a string")
_FLAG: _Check = (lambda value: isinstance(value, bool), "true or false")
_PORT: _Check = (lambda value: _is_int(value) and 0 < value < 65536, "a port number")
_SCORE: _Check = (lambda value: _is_int(value) and 0 <= value <= 100, "a score from 0 to 100")
_SEVERITY: _Check = (lambda value: value in SEVERITIES, "one of " + ", ".join(SEVERITIES))
_ADDRESS: _Check = (_is_address, "an IP address")
_MAC: _Check = (
    lambda value: isinstance(value, str) and normalize_mac(value) == value,
    "a MAC address like aa:bb:cc:dd:ee:ff",
)
_NETWORK: _Check = (_is_network, "a network such as 192.168.1.0/24")
_LIST: _Check = (lambda value: isinstance(value, list), "a list")
_OBJECT: _Check = (lambda value: isinstance(value, dict), "an object")

_REQUIRED: Any = object()


class _Object:
    """One JSON object from a saved result, read with checks.

    A missing field and null are the same thing. Errors name the path of the
    offending field, like devices[2].services[0].port.
    """

    def __init__(self, data: object, path: str) -> None:
        if not isinstance(data, dict):
            raise ValueError(f"{path or 'the result'} should be an object")
        self._data = data
        self._path = path

    def _where(self, key: str) -> str:
        return f"{self._path}.{key}" if self._path else key

    def get(self, key: str, check: _Check, default: Any = _REQUIRED) -> Any:
        """The field `key`. Without a default it must be there."""
        value = self._data.get(key)
        if value is None:
            if default is _REQUIRED:
                raise ValueError(f"{self._where(key)} is missing")
            return default
        test, expected = check
        if not test(value):
            raise ValueError(f"{self._where(key)} should be {expected}")
        return value

    def items(self, key: str, check: _Check) -> list[Any]:
        """A list field, each item passing `check`. Missing means empty."""
        values = self.get(key, _LIST, [])
        test, expected = check
        for index, value in enumerate(values):
            if not test(value):
                raise ValueError(f"{self._where(key)}[{index}] should be {expected}")
        return list(values)

    def objects(self, key: str) -> list[_Object]:
        values = self.get(key, _LIST, [])
        return [
            _Object(value, f"{self._where(key)}[{index}]") for index, value in enumerate(values)
        ]

    def child(self, key: str, read: Callable[[_Object], T]) -> T | None:
        value = self._data.get(key)
        if value is None:
            return None
        return read(_Object(value, self._where(key)))

    def tables(self, key: str) -> dict[str, _Object]:
        """An object field whose values are objects themselves."""
        table = _Object(self.get(key, _OBJECT, {}), self._where(key))
        return {name: _Object(value, table._where(name)) for name, value in table._data.items()}

    def pairs(self, key: str | None = None) -> dict[str, str]:
        """String to string pairs, from the field `key` or from this object itself."""
        source = self if key is None else _Object(self.get(key, _OBJECT, {}), self._where(key))
        for name, value in source._data.items():
            if not isinstance(value, str):
                raise ValueError(f"{source._where(name)} should be a string")
        return dict(source._data)
