"""NetBIOS node status queries (NBSTAT over UDP 137, RFC 1002).

Windows PCs, Samba servers and many NAS boxes answer with their computer name,
workgroup and MAC address.
"""

from __future__ import annotations

import codecs
import ctypes
import ipaddress
import math
import random
import struct
from collections.abc import Iterable

from ..models import NetbiosInfo, is_unicast_mac, normalize_mac
from ..scope import ScopeError, is_local
from ..system import IS_WINDOWS
from . import _udp

PORT = 137

# Each address gets its queries at least this far apart. The first datagram to
# a neighbor the OS has not resolved yet can be dropped while ARP runs.
ROUND_GAP = 0.25

_NBSTAT = 0x0021
_CLASS_IN = 0x0001

_RESPONSE = 0x8000
_OPCODE = 0x7800
_RCODE = 0x000F
_GROUP = 0x8000

_ENTRY_SIZE = 18  # 15 name bytes, the suffix, 2 flag bytes
_MAX_NAME_BYTES = 255
_MAX_TRANSACTIONS = 0x10000


class NetbiosError(ValueError):
    """The packet is not a node status response we can read."""


def _encode_name(name: bytes) -> bytes:
    """RFC 1001 first-level encoding: pad to 16 bytes, each nibble becomes "A" + nibble."""
    encoded = bytearray()
    for byte in name.ljust(16, b"\0"):
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    return bytes(encoded)


_WILDCARD = b"\x20" + _encode_name(b"*") + b"\x00"


def build_status_query(transaction_id: int) -> bytes:
    """A NODE STATUS REQUEST for the wildcard name "*", without recursion."""
    if (
        isinstance(transaction_id, bool)
        or not isinstance(transaction_id, int)
        or not 0 <= transaction_id <= 0xFFFF
    ):
        raise ValueError(f"transaction id must fit in 16 bits, not {transaction_id!r}")
    header = struct.pack("!6H", transaction_id, 0, 1, 0, 0, 0)
    return header + _WILDCARD + struct.pack("!2H", _NBSTAT, _CLASS_IN)


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise NetbiosError("packet ends early")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def byte(self) -> int:
        return self.take(1)[0]

    def skip_name(self) -> None:
        # The name itself is of no use to us, so a pointer is stepped over
        # rather than followed, and a pointer loop cannot trap us.
        total = 0
        while True:
            length = self.byte()
            if length == 0:
                return
            if length & 0xC0 == 0xC0:
                self.take(1)
                return
            if length & 0xC0:
                raise NetbiosError("unknown label type")
            total += length + 1
            if total > _MAX_NAME_BYTES:
                raise NetbiosError("name too long")
            self.take(length)


def _codec(code_page: int | None) -> str:
    """The Python codec for a Windows code page, or cp437 when Python has none."""
    if code_page:
        name = f"cp{code_page}"
        try:
            codecs.lookup(name)
        except LookupError:
            pass
        else:
            return name
    return "cp437"


def _oem_code_page() -> int | None:
    if not IS_WINDOWS:
        return None
    try:
        return int(ctypes.windll.kernel32.GetOEMCP())
    except (AttributeError, OSError):
        return None


# Windows sends names in its OEM code page (cp857 on Turkish systems, cp850 in
# much of Western Europe), and the PCs on one home network usually share ours.
# Elsewhere we cannot know it, and cp437 at least decodes every byte.
_CODEC = _codec(_oem_code_page())


def _clean(raw: bytes) -> str:
    text = raw.decode(_CODEC, errors="replace")
    return "".join(ch for ch in text if ch.isprintable()).strip()


def _parse_names(rdata: bytes) -> NetbiosInfo:
    if not rdata:
        raise NetbiosError("empty node status")
    claimed = rdata[0]
    fits = (len(rdata) - 1) // _ENTRY_SIZE
    count = min(claimed, fits)
    info = NetbiosInfo()
    for i in range(count):
        entry = rdata[1 + i * _ENTRY_SIZE : 1 + (i + 1) * _ENTRY_SIZE]
        name = _clean(entry[:15])
        if not name:
            continue
        suffix = entry[15]
        group = bool(int.from_bytes(entry[16:18], "big") & _GROUP)
        if suffix == 0x00:
            if group:
                info.workgroup = info.workgroup or name
            else:
                info.name = info.name or name
        elif suffix == 0x20 and not group:
            info.file_server = True

    # When the name count overstates the data, whatever follows is not the
    # statistics block.
    stats = rdata[1 + count * _ENTRY_SIZE :]
    if claimed <= fits and len(stats) >= 6:
        mac = normalize_mac(stats[:6].hex())
        if mac and is_unicast_mac(mac):
            info.mac = mac
    return info


def _parse(data: bytes) -> NetbiosInfo:
    reader = _Reader(data)
    _, flags, questions, answers, _, _ = struct.unpack("!6H", reader.take(12))
    if not flags & _RESPONSE or flags & (_OPCODE | _RCODE):
        raise NetbiosError("not a positive query response")
    for _ in range(questions):
        reader.skip_name()
        reader.take(4)
    for _ in range(answers):
        reader.skip_name()
        rtype, _, _, rdlength = struct.unpack("!2HIH", reader.take(10))
        rdata = reader.take(rdlength)
        if rtype == _NBSTAT:
            return _parse_names(rdata)
    raise NetbiosError("no node status in the answers")


def parse_status_reply(data: bytes) -> NetbiosInfo | None:
    """Read a NODE STATUS RESPONSE. Returns None for anything else.

    The MAC comes from the unit ID in the statistics block; Samba fills that
    with zeros, which gives None.
    """
    try:
        return _parse(bytes(data))
    except NetbiosError:
        return None


def _check_seconds(name: str, value: float) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{name} must be a non-negative number of seconds, not {value!r}")


def _targets(ips: Iterable[str]) -> list[str]:
    targets: dict[str, None] = {}
    for text in ips:
        ip = ipaddress.ip_address(text)
        if ip.version == 6:
            if ip.ipv4_mapped is None:
                continue  # NetBIOS over TCP/IP only runs on IPv4
            ip = ip.ipv4_mapped
        if not is_local(ip):
            raise ScopeError(f"{ip} is not on a private network")
        targets[str(ip)] = None
    return list(targets)


async def query(
    local: str,
    ips: Iterable[str],
    *,
    listen: float = 1.0,
    spacing: float = 0.002,
    rounds: int = 2,
) -> dict[str, NetbiosInfo]:
    """Ask every address for its NetBIOS names. Returns ip -> what it answered.

    Each address gets `rounds` queries at least ROUND_GAP seconds apart, all
    from one socket bound to `local`. With only a few addresses the sends are
    spread out further than `spacing` to keep that gap. IPv6 addresses are
    skipped; anything outside a private network raises ScopeError.
    """
    _check_seconds("listen", listen)
    _check_seconds("spacing", spacing)
    if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
        raise ValueError(f"rounds must be a positive whole number, not {rounds!r}")
    targets = _targets(ips)
    if not targets:
        return {}
    if len(targets) * rounds > _MAX_TRANSACTIONS:
        raise ValueError(f"{len(targets)} addresses x {rounds} rounds needs too many queries")

    first = random.randrange(_MAX_TRANSACTIONS)
    sent: dict[str, set[int]] = {ip: set() for ip in targets}
    packets = []
    for number in range(rounds):
        for i, ip in enumerate(targets):
            transaction_id = (first + number * len(targets) + i) % _MAX_TRANSACTIONS
            sent[ip].add(transaction_id)
            packets.append((build_status_query(transaction_id), (ip, PORT)))
    if rounds > 1:
        spacing = max(spacing, ROUND_GAP / len(targets))

    replies = await _udp.exchange(packets, local=local, listen=listen, spacing=spacing)

    found: dict[str, NetbiosInfo] = {}
    for data, sender in replies:
        if sender in found or sender not in sent or len(data) < 2:
            continue
        if int.from_bytes(data[:2], "big") not in sent[sender]:
            continue
        info = parse_status_reply(data)
        if info is not None:
            found[sender] = info
    return {ip: found[ip] for ip in targets if ip in found}
