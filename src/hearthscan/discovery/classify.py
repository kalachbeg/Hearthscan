"""Guess what kind of device something is from the clues discovery collected.

Every clue adds a weight to one kind, and the kind with the highest total wins.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from itertools import islice

from ..models import Device, is_random_mac, normalize_mac

MAX_MODEL = 80
MAX_EVIDENCE = 4

# Ties go to the kind listed first.
_PRIORITY = (
    "router",
    "printer",
    "camera",
    "nas",
    "console",
    "tv",
    "speaker",
    "media",
    "computer",
    "phone",
    "tablet",
    "smart-home",
)

# A rough scale for the weights below: 12 for a hardware model the device
# states itself, 8 or 9 for service and device types that one kind of device
# offers, 4 to 7 for vendors, ports and names, 1 to 3 for hints that many kinds
# of devices share. Only the strongest clue from each source counts per kind,
# so a printer announcing four printer services does not get four votes.

# Hardware identifiers that Apple devices put in their mDNS TXT records.
_APPLE_MODELS = tuple(
    (re.compile(pattern, re.IGNORECASE), name, kind)
    for pattern, name, kind in (
        (r"iPhone\d+,\d+", "iPhone", "phone"),
        (r"iPad\d+,\d+", "iPad", "tablet"),
        (r"MacBookPro\d+,\d+", "MacBook Pro", "computer"),
        (r"MacBookAir\d+,\d+", "MacBook Air", "computer"),
        (r"MacBook\d+,\d+", "MacBook", "computer"),
        (r"iMacPro\d+,\d+", "iMac Pro", "computer"),
        (r"iMac\d+,\d+", "iMac", "computer"),
        (r"Macmini\d+,\d+", "Mac mini", "computer"),
        (r"MacPro\d+,\d+", "Mac Pro", "computer"),
        (r"Mac\d+,\d+", "Mac", "computer"),
        (r"AppleTV\d+,\d+", "Apple TV", "media"),
        (r"AudioAccessory5,\d+", "HomePod mini", "speaker"),
        (r"AudioAccessory\d+,\d+", "HomePod", "speaker"),
    )
)

# Samba and NAS boxes borrow these so Finder shows a server icon.
_PLACEHOLDER_MODELS = {"xserve", "macsamba", "rackmac"}

# UPnP model names that describe software rather than the device.
_SOFTWARE_MODEL = re.compile(r"windows media|media server|media renderer|\bupnp\b|\bdlna\b")

# Where mDNS TXT records keep a model string, best first.
_TXT_MODELS = (
    ("_device-info._tcp", "model"),
    ("_airplay._tcp", "model"),
    ("_raop._tcp", "am"),
    ("_googlecast._tcp", "md"),
)
_PRINTER_SERVICES = ("_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp")
_HAP_SERVICES = ("_hap._tcp", "_hap._udp")

_MDNS_SERVICES: dict[str, tuple[tuple[str, int], ...]] = {
    "_ipp._tcp": (("printer", 8),),
    "_ipps._tcp": (("printer", 8),),
    "_printer._tcp": (("printer", 8),),
    "_pdl-datastream._tcp": (("printer", 8),),
    "_uscan._tcp": (("printer", 6),),
    "_uscans._tcp": (("printer", 6),),
    "_scanner._tcp": (("printer", 5),),
    "_sonos._tcp": (("speaker", 8),),
    "_spotify-connect._tcp": (("speaker", 4),),
    "_raop._tcp": (("speaker", 3),),
    # Chromecasts, Google speakers and TVs with Cast built in all offer this.
    "_googlecast._tcp": (("media", 4), ("speaker", 3), ("tv", 3)),
    "_androidtvremote2._tcp": (("tv", 5), ("media", 4)),
    "_airplay._tcp": (("media", 3), ("speaker", 2)),
    "_amzn-wplay._tcp": (("media", 6),),
    "_mediaremotetv._tcp": (("media", 6),),
    "_apple-mobdev2._tcp": (("phone", 6), ("tablet", 5)),
    "_hue._tcp": (("smart-home", 8),),
    "_esphomelib._tcp": (("smart-home", 8),),
    "_shelly._tcp": (("smart-home", 8),),
    "_hap._tcp": (("smart-home", 7),),
    "_hap._udp": (("smart-home", 7),),
    "_matter._tcp": (("smart-home", 6),),
    "_matterc._udp": (("smart-home", 6),),
    "_axis-video._tcp": (("camera", 8),),
    "_rtsp._tcp": (("camera", 3),),
    "_adisk._tcp": (("nas", 4),),
    "_afpovertcp._tcp": (("nas", 3), ("computer", 1)),
    "_smb._tcp": (("computer", 2), ("nas", 1)),
    "_workstation._tcp": (("computer", 3),),
    "_rfb._tcp": (("computer", 3),),
    "_ssh._tcp": (("computer", 1),),
    "_sftp-ssh._tcp": (("computer", 1),),
}

# HomeKit accessory categories for IP cameras and video doorbells.
_HAP_CAMERAS = {"17", "18"}

_UPNP_TYPES: dict[str, tuple[tuple[str, int], ...]] = {
    "internetgatewaydevice": (("router", 9),),
    "wandevice": (("router", 8),),
    "wanconnectiondevice": (("router", 8),),
    "wfadevice": (("router", 5),),
    "printer": (("printer", 9),),
    "digitalsecuritycamera": (("camera", 9),),
    "zoneplayer": (("speaker", 9),),
    "dial": (("tv", 4), ("media", 4)),
    "mediarenderer": (("tv", 3), ("speaker", 2)),
    "mediaserver": (("nas", 3),),
}

# Services that show a device plays video. They make a TV maker's device count
# as a TV and an Amazon device as a Fire TV.
_TV_UPNP = {"mediarenderer", "dial"}
_TV_MDNS = {"_androidtvremote2._tcp", "_googlecast._tcp", "_airplay._tcp", "_amzn-wplay._tcp"}

_NEEDS_TV = "tv"
_NEEDS_XBOX = "xbox"

# Matched against the lower-case vendor; the first match wins.
_VENDORS = tuple(
    (re.compile(pattern), kind, weight, needs)
    for pattern, kind, weight, needs in (
        (r"sony interactive|sony computer entertainment", "console", 6, None),
        (r"nintendo", "console", 6, None),
        (r"\bvalve\b", "console", 4, None),
        (r"microsoft", "console", 6, _NEEDS_XBOX),
        (r"synology|qnap", "nas", 5, None),
        (r"hikvision|dahua|reolink|\baxis\b|ezviz|amcrest", "camera", 5, None),
        (r"brother|canon|epson|xerox|kyocera|lexmark|ricoh", "printer", 4, None),
        (r"sonos", "speaker", 6, None),
        (r"\bbose\b", "speaker", 5, None),
        (
            r"espressif|tuya|shelly|allterco|sonoff|itead|signify|philips lighting|\bwiz\b"
            r"|lumi united|aqara",
            "smart-home",
            4,
            None,
        ),
        (r"raspberry", "computer", 5, None),
        # Mostly players. Roku TVs give themselves away by name or model.
        (r"\broku\b", "media", 5, None),
        # Echo speakers and Fire TV sticks come from the same blocks.
        (r"^amazon\b", "media", 5, _NEEDS_TV),
        # These also make phones, tablets and fridges.
        (r"samsung|\blg\b|\bsony\b|\btcl\b|hisense|vizio", "tv", 6, _NEEDS_TV),
        (r"\bavm\b|mikrotik|routerboard|ubiquiti|netgear|zyxel", "router", 3, None),
    )
)

_PORTS = (
    (9100, "printer", 6),
    (515, "printer", 4),
    (631, "printer", 3),
    # Apple's sync service, open on iPhones and iPads.
    (62078, "phone", 6),
    (62078, "tablet", 5),
    (3389, "computer", 6),
    (5357, "computer", 3),
    (445, "computer", 2),
    (22, "computer", 1),
    (548, "nas", 3),
    (8009, "media", 4),
    (8009, "speaker", 3),
    (8009, "tv", 3),
    (8008, "media", 4),
    (8008, "speaker", 3),
    (8008, "tv", 3),
    (32400, "media", 4),
    (554, "camera", 3),
    (37777, "camera", 6),
    (34567, "camera", 5),
    (7547, "router", 3),
)

# Matched against names squashed to lower-case letters, digits and dashes
# ("Kitchen_iPad" becomes "kitchen-ipad"). The first match decides.
_NAME_PATTERNS = tuple(
    (re.compile(pattern), kind, weight, label)
    for pattern, kind, weight, label in (
        (r"iphone", "phone", 6, "an iPhone"),
        (r"ipad", "tablet", 6, "an iPad"),
        (r"apple-?tv", "media", 6, "an Apple TV"),
        (r"homepod", "speaker", 6, "a HomePod"),
        (r"macbook|imac|mac-?mini|mac-?pro|mac-?studio", "computer", 6, "a Mac"),
        (r"galaxy-?tab|kindle|matepad", "tablet", 5, "a tablet"),
        (
            r"tasmota|shelly|sonoff|tuya|espressif|esphome|esp32|esp8266|wled|yeelink|zhimi"
            r"|miio|roborock|vacuum|hue-?bridge|^esp-?[0-9a-f]{6}$",
            "smart-home",
            5,
            "a smart home device",
        ),
        (r"chromecast", "media", 6, "a Chromecast"),
        (r"google-?tv|fire-?tv|fire-?stick|\bshield\b", "media", 5, "a streaming stick"),
        (r"roku-?tv", "tv", 6, "a Roku TV"),
        (r"\broku\b", "media", 5, "a Roku"),
        (r"android-?tv|\btv\b|television|bravia|webos", "tv", 5, "a TV"),
        (
            r"android|galaxy|pixel|oneplus|xiaomi|redmi|huawei|\bhonor\b|\boppo\b|\bvivo\b"
            r"|realme|motorola|\bmoto\b",
            "phone",
            6,
            "an Android phone",
        ),
        (r"^desktop-|^laptop-", "computer", 6, "a Windows PC"),
        (r"\bpc\b|thinkpad|workstation", "computer", 5, "a PC"),
        (r"raspberry-?pi|\braspi\b|\brpi\d*\b", "computer", 6, "a Raspberry Pi"),
        (
            r"printer|laserjet|officejet|deskjet|^br[nw][0-9a-f]{12}$|^npi[0-9a-f]{6}$"
            r"|^hp[0-9a-f]{6}$|^epson[0-9a-f]{6}$",
            "printer",
            6,
            "a printer",
        ),
        (r"diskstation|rackstation|\bnas\d*\b|synology|qnap|truenas|readynas", "nas", 6, "a NAS"),
        # What Echo speakers send over DHCP. Some Fire TV sticks do too, so it counts for less.
        (r"^amazon-[0-9a-f]{6,}$", "speaker", 4, "an Amazon device"),
        (r"\becho\b|alexa|google-?home|nest-?(mini|audio|hub)|sonos", "speaker", 5, "a speaker"),
        (r"playstation|\bps[345]\b", "console", 6, "a PlayStation"),
        (r"xbox", "console", 6, "an Xbox"),
        (r"nintendo|^switch(-\d+)?$", "console", 5, "a Nintendo Switch"),
        (
            r"\b(ip-?)?cam(era)?\d*\b|ipcam|webcam|doorbell|\b[nd]vr\d*\b",
            "camera",
            5,
            "a camera",
        ),
        (r"ubuntu|debian|fedora|linux", "computer", 2, "a Linux machine"),
    )
)

_NOT_NAME_CHARS = re.compile(r"[^0-9a-z]+")


@dataclass(slots=True)
class _Clue:
    weight: int
    evidence: str
    order: int


class _Tally:
    """The strongest clue per kind and source."""

    def __init__(self) -> None:
        self.clues: dict[tuple[str, str], _Clue] = {}
        self.count = 0

    def add(self, kind: str, source: str, weight: int, evidence: str) -> None:
        self.count += 1
        best = self.clues.get((kind, source))
        if best is None or weight > best.weight:
            self.clues[kind, source] = _Clue(weight, evidence, self.count)

    def winner(self) -> str:
        totals: dict[str, int] = {}
        for (kind, _), clue in self.clues.items():
            totals[kind] = totals.get(kind, 0) + clue.weight
        if not totals:
            return "unknown"
        rank = {kind: i for i, kind in enumerate(_PRIORITY)}
        return min(totals, key=lambda kind: (-totals[kind], rank.get(kind, len(rank)), kind))

    def evidence(self, kind: str) -> list[str]:
        clues = sorted(
            (clue for (k, _), clue in self.clues.items() if k == kind),
            key=lambda clue: (-clue.weight, clue.order),
        )
        found: list[str] = []
        for clue in clues:
            if clue.evidence not in found:
                found.append(clue.evidence)
        return found[:MAX_EVIDENCE]


def classify(device: Device) -> None:
    """Set device.kind, device.model and device.evidence from what discovery found.

    Missing or malformed fields are skipped, so this never raises.
    """
    mdns = getattr(device, "mdns", None)
    upnp = getattr(device, "upnp", None)
    netbios = getattr(device, "netbios", None)
    txt = _txt_index(getattr(mdns, "txt", None))
    services = _mdns_services(getattr(mdns, "services", None))
    upnp_types = _upnp_types(getattr(upnp, "device_types", None))
    ports = _open_ports(getattr(device, "services", None))
    models = _model_candidates(txt, upnp)
    names = _names(device, mdns, netbios, upnp, txt)
    server = _clean(getattr(upnp, "server", None), 200).lower()

    tally = _Tally()
    gateway = getattr(device, "is_gateway", False) is True
    if gateway:
        tally.add("router", "gateway", 100, "default gateway")
    if getattr(device, "is_self", False) is True:
        tally.add("computer", "self", 8, "this computer")

    for text, own in models:
        if own:
            _score_model(tally, text)

    for name, entries in _UPNP_TYPES.items():
        if name in upnp_types:
            for kind, weight in entries:
                tally.add(kind, "upnp", weight, f"UPnP {upnp_types[name]}")

    for service, entries in _MDNS_SERVICES.items():
        if service in services:
            for kind, weight in entries:
                tally.add(kind, "mdns", weight, f"mDNS {service}")
    if any(_txt(txt, service, "ci", 8) in _HAP_CAMERAS for service in _HAP_SERVICES):
        tally.add("camera", "mdns", 8, "HomeKit camera")

    tv_hint = not (_TV_UPNP.isdisjoint(upnp_types) and _TV_MDNS.isdisjoint(services))
    hints = " ".join([*names, *(text.lower() for text, _ in models), server])
    vendor_kinds = set()
    for raw, prefix in (
        (getattr(device, "vendor", None), "vendor"),
        (getattr(upnp, "manufacturer", None), "UPnP manufacturer"),
    ):
        vendor = _clean(raw, 64)
        rule = _vendor_rule(vendor)
        if rule is None:
            continue
        kind, weight, needs = rule
        vendor_kinds.add(kind)
        if needs == _NEEDS_TV and not tv_hint:
            continue
        if needs == _NEEDS_XBOX and "xbox" not in hints:
            continue
        tally.add(kind, "vendor", weight, f"{prefix} {_clean(vendor, 40)}")

    _score_ports(tally, ports, vendor_kinds)

    for name in names:
        match = _match_name(name)
        if match is not None:
            kind, weight, label = match
            tally.add(kind, "name", weight, f"name looks like {label}")

    if getattr(netbios, "file_server", False) is True:
        tally.add("computer", "netbios", 3, "NetBIOS file server")
    elif _clean(getattr(netbios, "name", None)):
        tally.add("computer", "netbios", 2, "answers NetBIOS")

    # "Linux" in the server header says nothing: nearly every box runs it.
    if "windows" in server:
        tally.add("computer", "server", 2, "UPnP server runs Windows")
    if "roku" in server:
        tally.add("media", "server", 3, "UPnP server says Roku")

    if _random_mac(getattr(device, "mac", None)):
        # Phones make up a MAC per network by default; most devices that do are phones.
        tally.add("phone", "mac", 1, "randomized MAC")

    kind = "router" if gateway else tally.winner()
    device.kind = kind
    device.model = _pick_model(models)
    device.evidence = tally.evidence(kind) if kind != "unknown" else []


def _score_model(tally: _Tally, text: str) -> None:
    evidence = f"model {_clean(text, 40)}"
    apple = _apple_model(text)
    if apple is not None:
        tally.add(apple[1], "model", 12, evidence)
        return
    match = _match_name(_name_key(text))
    if match is not None:
        kind, weight, _ = match
        tally.add(kind, "model", weight + 4, evidence)


def _score_ports(tally: _Tally, ports: set[int], vendor_kinds: set[str]) -> None:
    for port, kind, weight in _PORTS:
        if port in ports:
            tally.add(kind, "ports", weight, f"port {port} open")
    if 445 in ports and 135 in ports:
        tally.add("computer", "ports", 6, "ports 445 and 135 open")
    if "nas" in vendor_kinds:
        for port in (5000, 5001):
            if port in ports:
                tally.add("nas", "ports", 7, f"port {port} open")
                break
    if "camera" in vendor_kinds:
        if 554 in ports:
            tally.add("camera", "ports", 7, "port 554 open")
        elif 80 in ports:
            tally.add("camera", "ports", 5, "port 80 open")


def _vendor_rule(vendor: str) -> tuple[str, int, str | None] | None:
    lowered = vendor.lower()
    for pattern, kind, weight, needs in _VENDORS:
        if pattern.search(lowered):
            return kind, weight, needs
    return None


def _match_name(key: str) -> tuple[str, int, str] | None:
    if not key:
        return None
    for pattern, kind, weight, label in _NAME_PATTERNS:
        if pattern.search(key):
            return kind, weight, label
    return None


def _apple_model(text: str) -> tuple[str, str] | None:
    """("MacBook Pro", "computer") for "MacBookPro18,3"."""
    for pattern, name, kind in _APPLE_MODELS:
        if pattern.fullmatch(text):
            return name, kind
    return None


def _model_candidates(txt: dict[str, dict[str, object]], upnp: object) -> list[tuple[str, bool]]:
    """Model strings in order of preference, each flagged with whether it describes
    the device itself. A computer that shares a printer advertises the printer's model.
    """
    found: list[tuple[str, bool]] = []
    for service, key in _TXT_MODELS:
        text = _txt(txt, service, key)
        if text and text.lower() not in _PLACEHOLDER_MODELS:
            found.append((text, True))
    for service in _PRINTER_SERVICES:
        for key in ("ty", "usb_mdl"):
            text = _txt(txt, service, key)
            if text:
                found.append((text, False))
    for service in _HAP_SERVICES:
        text = _txt(txt, service, "md")
        if text:
            found.append((text, True))
    text = _upnp_model(upnp)
    if text:
        found.append((text, True))
    return found


def _upnp_model(upnp: object) -> str:
    name = _clean(getattr(upnp, "model_name", None))
    if not name or _SOFTWARE_MODEL.search(name.lower()):
        return ""
    number = _clean(getattr(upnp, "model_number", None))
    # Plenty of devices put "1" or "1.0" there, which tells nobody anything.
    informative = number and (
        any(ch.isalpha() for ch in number) or sum(ch.isdigit() for ch in number) >= 3
    )
    if informative and number.lower() not in name.lower():
        name = f"{name} {number}"
    return name[:MAX_MODEL].rstrip()


def _pick_model(candidates: list[tuple[str, bool]]) -> str | None:
    for text, _ in candidates:
        apple = _apple_model(text)
        if apple is not None:
            return apple[0]
    return candidates[0][0] if candidates else None


def _names(
    device: object,
    mdns: object,
    netbios: object,
    upnp: object,
    txt: dict[str, dict[str, object]],
) -> list[str]:
    raw: list[object] = [
        _first_label(getattr(mdns, "hostname", None)),
        getattr(netbios, "name", None),
        _first_label(getattr(device, "dns_name", None)),
        getattr(upnp, "friendly_name", None),
        txt.get("_googlecast._tcp", {}).get("fn"),
    ]
    instances = getattr(mdns, "instances", None)
    if isinstance(instances, dict):
        for service, name in islice(instances.items(), 32):
            # A shared printer is announced under the printer's name, not the host's.
            if _service_name(service) not in _PRINTER_SERVICES:
                raw.append(name)
    keys: list[str] = []
    for value in raw:
        key = _name_key(value)
        if key and key not in keys:
            keys.append(key)
    return keys


def _first_label(value: object) -> object:
    if isinstance(value, str):
        return value[:256].split(".", 1)[0]
    return None


def _name_key(value: object) -> str:
    return _NOT_NAME_CHARS.sub("-", _clean(value, 128).lower()).strip("-")


def _txt_index(value: object) -> dict[str, dict[str, object]]:
    """TXT pairs by normalized service type, with lower-case keys."""
    index: dict[str, dict[str, object]] = {}
    if not isinstance(value, dict):
        return index
    for service, pairs in islice(value.items(), 64):
        name = _service_name(service)
        if not name or not isinstance(pairs, dict):
            continue
        entry = index.setdefault(name, {})
        for key, item in islice(pairs.items(), 64):
            if isinstance(key, str):
                entry.setdefault(key[:64].strip().lower(), item)
    return index


def _txt(txt: dict[str, dict[str, object]], service: str, key: str, limit: int = MAX_MODEL) -> str:
    return _clean(txt.get(service, {}).get(key), limit)


def _service_name(value: object) -> str:
    """'_ipp._tcp' for '_ipp._tcp', '_universal._sub._ipp._tcp.local.' and the like."""
    if not isinstance(value, str):
        return ""
    labels = value[:256].strip().lower().rstrip(".").split(".")
    if labels[-1] == "local":
        labels.pop()
    if len(labels) >= 2 and labels[-1] in ("_tcp", "_udp") and labels[-2].startswith("_"):
        return f"{labels[-2]}.{labels[-1]}"
    return ""


def _mdns_services(value: object) -> set[str]:
    return {name for item in _items(value, 256) if (name := _service_name(item))}


def _upnp_types(value: object) -> dict[str, str]:
    """Device type names from URNs, lower-case to as written:
    'mediarenderer' -> 'MediaRenderer' for urn:schemas-upnp-org:device:MediaRenderer:1.
    """
    found: dict[str, str] = {}
    urns = sorted(item[:256] for item in _items(value, 64) if isinstance(item, str))
    for urn in urns:
        parts = urn.split(":")
        if len(parts) >= 4 and parts[0].lower() == "urn" and parts[2].lower() == "device":
            name = _clean(parts[3], 40)
            if name:
                found.setdefault(name.lower(), name)
    return found


def _open_ports(value: object) -> set[int]:
    ports: set[int] = set()
    for service in _items(value, 4096):
        port = getattr(service, "port", None)
        if getattr(service, "protocol", "tcp") == "udp":
            continue
        if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
            ports.add(port)
    return ports


def _random_mac(value: object) -> bool:
    mac = normalize_mac(value[:64]) if isinstance(value, str) else None
    return mac is not None and is_random_mac(mac)


def _items(value: object, limit: int) -> list:
    if isinstance(value, (set, frozenset, list, tuple, dict)):
        return list(islice(value, limit))
    return []


def _clean(value: object, limit: int = MAX_MODEL) -> str:
    """Printable text from untrusted input: control characters gone, spaces collapsed, capped."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value[:1024]).decode("utf-8", "replace")
    if not isinstance(value, str):
        return ""
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in value[:1024])
    return " ".join(text.split())[:limit].rstrip()
