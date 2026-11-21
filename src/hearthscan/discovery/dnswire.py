"""Just enough of the DNS message format (RFC 1035) for mDNS browsing and reverse lookups."""

from __future__ import annotations

import ipaddress
import struct
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field

A = 1
PTR = 12
TXT = 16
AAAA = 28
SRV = 33
ANY = 255
IN = 1

# The top bit of the class field is "cache flush" in mDNS answers and "unicast
# response wanted" (QU) in mDNS questions.
CLASS_TOP_BIT = 0x8000

FLAG_RESPONSE = 0x8000
FLAG_TRUNCATED = 0x0200
FLAG_RECURSION_DESIRED = 0x0100

MAX_LABEL = 63
MAX_NAME = 255
# Real messages need two or three; the limit only matters for hostile ones.
MAX_JUMPS = 16
MAX_RECORDS = 512
MAX_TXT_ITEMS = 64
MAX_TXT_VALUE = 255
MAX_RAW = 512

_HEADER = struct.Struct("!HHHHHH")
_QUESTION = struct.Struct("!HH")
_RECORD = struct.Struct("!HHIH")
_SRV = struct.Struct("!HHH")

# The smallest possible question (root name, type, class) and record.
_MIN_QUESTION = 1 + _QUESTION.size
_MIN_RECORD = 1 + _RECORD.size

Labels = tuple[str, ...]
# A and AAAA: address text. PTR: labels. SRV: (priority, weight, port, target).
# TXT: lowercased keys to values. Anything else: the raw bytes.
RData = str | Labels | tuple[int, int, int, Labels] | dict[str, str] | bytes

# Every label start already read in the message being parsed, mapped to the
# labels of the name it was read in, the index where this suffix begins, the
# suffix's size on the wire, the pointers it follows, and the offset just past
# the bytes of its own run.
_Seen = dict[int, tuple[Labels, int, int, int, int]]


class DnsError(ValueError):
    """A DNS message that is truncated or otherwise malformed."""


@dataclass(frozen=True, slots=True)
class Record:
    name: Labels
    rtype: int
    rclass: int  # without the mDNS cache-flush bit
    ttl: int
    data: RData


@dataclass(slots=True)
class Message:
    id: int
    flags: int
    questions: list[tuple[Labels, int]] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)

    @property
    def records(self) -> list[Record]:
        return [*self.answers, *self.authorities, *self.additionals]

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def opcode(self) -> int:
        return (self.flags >> 11) & 0xF

    @property
    def rcode(self) -> int:
        return self.flags & 0xF


def name_key(labels: Iterable[str]) -> Labels:
    """Names compare without regard to case; use this as a dictionary key."""
    return tuple(label.lower() for label in labels)


def display_text(text: str) -> str:
    """Replace control and format characters with "?".

    A hostile name then cannot drive the terminal, and bidi overrides or
    zero-width characters cannot reorder or hide what is printed next to it.
    """
    if text.isprintable():
        return text
    return "".join("?" if _hidden(char) else char for char in text)


def _hidden(char: str) -> bool:
    return unicodedata.category(char)[0] == "C" or char in "\u2028\u2029"


def name_text(labels: Iterable[str]) -> str:
    """Labels joined with dots for display, without the trailing dot."""
    return display_text(".".join(labels))


def reverse_name(ip: str) -> Labels:
    """The PTR name of an IPv4 address: 192.168.1.20 -> 20.1.168.192.in-addr.arpa.

    Raises ValueError for anything that is not an IPv4 address.
    """
    octets = str(ipaddress.IPv4Address(ip)).split(".")
    return (*reversed(octets), "in-addr", "arpa")


def encode_name(name: str | Iterable[str]) -> bytes:
    """Encode a name without compression.

    A string is split on dots. Anything else is taken as the labels themselves,
    since a service instance name may contain dots of its own.
    """
    if isinstance(name, str):
        text = name.removesuffix(".")
        labels: Iterable[str] = text.split(".") if text else ()
    else:
        labels = name
    out = bytearray()
    for label in labels:
        raw = label.encode("utf-8")
        if not raw:
            raise DnsError(f"empty label in {name!r}")
        if len(raw) > MAX_LABEL:
            raise DnsError(f"label longer than {MAX_LABEL} bytes: {label!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    if len(out) > MAX_NAME:
        raise DnsError(f"name longer than {MAX_NAME} bytes")
    return bytes(out)


def build_query(
    questions: Iterable[tuple[str | Labels, int]],
    *,
    query_id: int = 0,
    recursion_desired: bool = False,
    unicast_response: bool = False,
) -> bytes:
    """A query for (name, type) pairs, all in class IN.

    `unicast_response` sets the mDNS QU bit on every question.
    """
    if not 0 <= query_id <= 0xFFFF:
        raise DnsError(f"query id out of range: {query_id}")
    qclass = IN | (CLASS_TOP_BIT if unicast_response else 0)
    body = bytearray()
    count = 0
    for name, qtype in questions:
        body += encode_name(name)
        body += _QUESTION.pack(qtype, qclass)
        count += 1
    flags = FLAG_RECURSION_DESIRED if recursion_desired else 0
    return _HEADER.pack(query_id, flags, count, 0, 0, 0) + bytes(body)


def encode_record(record: Record) -> bytes:
    """Encode one resource record without compression. Bytes data goes out as is."""
    rdata = _encode_rdata(record.rtype, record.data)
    if len(rdata) > 0xFFFF:
        raise DnsError("record data too long")
    fixed = _RECORD.pack(record.rtype, record.rclass, record.ttl, len(rdata))
    return encode_name(record.name) + fixed + rdata


def build_message(message: Message) -> bytes:
    """Encode a whole message without compression (questions in class IN)."""
    header = _HEADER.pack(
        message.id,
        message.flags,
        len(message.questions),
        len(message.answers),
        len(message.authorities),
        len(message.additionals),
    )
    out = bytearray(header)
    for name, qtype in message.questions:
        out += encode_name(name)
        out += _QUESTION.pack(qtype, IN)
    for record in message.records:
        out += encode_record(record)
    return bytes(out)


def _encode_rdata(rtype: int, data: RData) -> bytes:
    if isinstance(data, bytes):
        return data
    if rtype == A and isinstance(data, str):
        return ipaddress.IPv4Address(data).packed
    if rtype == AAAA and isinstance(data, str):
        return ipaddress.IPv6Address(data).packed
    if rtype == PTR and isinstance(data, tuple):
        return encode_name(data)
    if rtype == SRV and isinstance(data, tuple) and len(data) == 4:
        priority, weight, port, target = data
        return _SRV.pack(priority, weight, port) + encode_name(target)
    if rtype == TXT and isinstance(data, dict):
        out = bytearray()
        for key, value in data.items():
            item = (f"{key}={value}" if value else key).encode("utf-8")
            if len(item) > 0xFF:
                raise DnsError(f"TXT item longer than 255 bytes: {key!r}")
            out.append(len(item))
            out += item
        # A TXT record with nothing in it still holds one empty string (RFC 6763 6.1).
        return bytes(out) or b"\x00"
    raise DnsError(f"no encoding for {type(data).__name__} data in a type {rtype} record")


def read_header(data: bytes) -> tuple[int, int, int]:
    """The id, the flags and the number of entries in all sections, without decoding the rest.

    Raises DnsError for anything shorter than a header.
    """
    if len(data) < _HEADER.size:
        raise DnsError("shorter than a DNS header")
    msg_id, flags, *counts = _HEADER.unpack_from(data)
    return msg_id, flags, sum(counts)


def parse_message(data: bytes) -> Message:
    """Decode a DNS message. Raises DnsError for anything malformed."""
    try:
        return _parse(bytes(data))
    except (IndexError, struct.error) as exc:
        # Every read is bounds checked, so this would be a bug; it still must
        # not take a scan down.
        raise DnsError(f"malformed message: {exc}") from exc


def _parse(data: bytes) -> Message:
    if len(data) < _HEADER.size:
        raise DnsError("shorter than a DNS header")
    msg_id, flags, qdcount, ancount, nscount, arcount = _HEADER.unpack_from(data)
    total = qdcount + ancount + nscount + arcount
    if total > MAX_RECORDS:
        raise DnsError(f"{total} entries; the limit is {MAX_RECORDS}")
    room = len(data) - _HEADER.size
    if qdcount * _MIN_QUESTION + (total - qdcount) * _MIN_RECORD > room:
        raise DnsError("section counts do not fit the message")

    pos = _HEADER.size
    seen: _Seen = {}
    questions = []
    for _ in range(qdcount):
        name, pos = _read_name(data, pos, seen)
        if pos + _QUESTION.size > len(data):
            raise DnsError("truncated question")
        qtype, _qclass = _QUESTION.unpack_from(data, pos)
        pos += _QUESTION.size
        questions.append((name, qtype))

    sections: list[list[Record]] = []
    for count in (ancount, nscount, arcount):
        records = []
        for _ in range(count):
            record, pos = _read_record(data, pos, seen)
            records.append(record)
        sections.append(records)
    # Anything after the last record is padding some devices add; ignore it.
    return Message(msg_id, flags, questions, *sections)


def _read_name(data: bytes, offset: int, seen: _Seen) -> tuple[Labels, int]:
    """Read a possibly compressed name. Returns the labels and the offset after it.

    Names already read from this message come from `seen` instead of being
    walked again, which keeps parsing linear in the size of the message.
    Without that, every record could point into the same long chain of labels.
    """
    labels: list[str] = []
    tail: Labels = ()
    # Label start, then the labels, size and pointers before it.
    visited: list[tuple[int, int, int, int]] = []
    # For each run of labels: how many entries of `visited` it ends after, and
    # the offset just past its bytes.
    runs: list[tuple[int, int]] = []
    size = 1  # the root label
    pos = start = offset
    jumps = 0
    while True:
        known = seen.get(pos)
        if known is not None:
            names, index, more, deeper, run_end = known
            tail = names[index:]
            size += more - 1
            jumps += deeper
            if size > MAX_NAME:
                raise DnsError(f"name longer than {MAX_NAME} bytes")
            if jumps > MAX_JUMPS:
                raise DnsError("too many compression pointers")
            runs.append((len(visited), run_end))
            break
        if pos >= len(data):
            raise DnsError("name runs past the end of the message")
        length = data[pos]
        if length == 0:
            runs.append((len(visited), pos + 1))
            break
        kind = length & 0xC0
        if kind == 0xC0:
            if pos + 1 >= len(data):
                raise DnsError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            # Only pointing back before the current run of labels is allowed.
            # Every jump then lands earlier than the last, so loops cannot happen.
            if target < _HEADER.size or target >= start:
                raise DnsError(f"compression pointer to {target} from {pos}")
            jumps += 1
            if jumps > MAX_JUMPS:
                raise DnsError("too many compression pointers")
            runs.append((len(visited), pos + 2))
            pos = start = target
            continue
        if kind:
            # 0x40 and 0x80 are extended and reserved label types, or a label
            # length over 63; either way not something we can read.
            raise DnsError(f"unsupported label type {length:#04x}")
        end = pos + 1 + length
        if end > len(data):
            raise DnsError("label runs past the end of the message")
        visited.append((pos, len(labels), size, jumps))
        size += length + 1
        if size > MAX_NAME:
            raise DnsError(f"name longer than {MAX_NAME} bytes")
        labels.append(data[pos + 1 : end].decode("utf-8", errors="replace"))
        pos = end

    name = (*labels, *tail)
    first = 0
    for stop, run_end in runs:
        for label_start, index, size_before, jumps_before in visited[first:stop]:
            seen[label_start] = (name, index, size - size_before + 1, jumps - jumps_before, run_end)
        first = stop
    # The bytes of the name itself end with its first run.
    return name, runs[0][1]


def _read_record(data: bytes, offset: int, seen: _Seen) -> tuple[Record, int]:
    name, pos = _read_name(data, offset, seen)
    if pos + _RECORD.size > len(data):
        raise DnsError("truncated record header")
    rtype, rclass, ttl, rdlength = _RECORD.unpack_from(data, pos)
    pos += _RECORD.size
    end = pos + rdlength
    if end > len(data):
        raise DnsError("record data runs past the end of the message")
    rdata = _read_rdata(data, pos, end, rtype, seen)
    return Record(name, rtype, rclass & ~CLASS_TOP_BIT, ttl, rdata), end


def _read_rdata(data: bytes, start: int, end: int, rtype: int, seen: _Seen) -> RData:
    length = end - start
    if rtype == A:
        if length != 4:
            raise DnsError(f"A record with {length} bytes of data")
        return str(ipaddress.IPv4Address(data[start:end]))
    if rtype == AAAA:
        if length != 16:
            raise DnsError(f"AAAA record with {length} bytes of data")
        return str(ipaddress.IPv6Address(data[start:end]))
    if rtype == PTR:
        name, after = _read_name(data, start, seen)
        if after > end:
            raise DnsError("PTR name runs past its record")
        return name
    if rtype == SRV:
        if length < _SRV.size + 1:
            raise DnsError("SRV record too short")
        priority, weight, port = _SRV.unpack_from(data, start)
        target, after = _read_name(data, start + _SRV.size, seen)
        if after > end:
            raise DnsError("SRV target runs past its record")
        return (priority, weight, port, target)
    if rtype == TXT:
        return _read_txt(data[start:end])
    return data[start : min(end, start + MAX_RAW)]


def _read_txt(raw: bytes) -> dict[str, str]:
    """TXT strings as key/value pairs, following RFC 6763 section 6."""
    pairs: dict[str, str] = {}
    pos = 0
    while pos < len(raw):
        length = raw[pos]
        item = raw[pos + 1 : pos + 1 + length]
        if len(item) != length:
            raise DnsError("TXT string runs past its record")
        pos += 1 + length
        if not item or len(pairs) >= MAX_TXT_ITEMS:
            continue
        key, _, value = item.partition(b"=")
        if not key:
            continue  # "=value" has no key and is to be ignored
        text = key.decode("utf-8", errors="replace").lower()
        if text not in pairs:
            pairs[text] = value.decode("utf-8", errors="replace")[:MAX_TXT_VALUE]
    return pairs
