import contextlib
import random
import struct

import pytest

from hearthscan.discovery import dnswire
from hearthscan.discovery.dnswire import (
    AAAA,
    IN,
    MAX_JUMPS,
    MAX_RECORDS,
    PTR,
    SRV,
    TXT,
    A,
    DnsError,
    Message,
    Record,
    build_message,
    build_query,
    display_text,
    encode_name,
    name_key,
    name_text,
    parse_message,
    read_header,
    reverse_name,
)

UNKNOWN = 99
REPLACED = "\N{REPLACEMENT CHARACTER}"


def header(qd=0, an=0, ns=0, ar=0, *, msg_id=0x1234, flags=0x8400):
    return struct.pack("!HHHHHH", msg_id, flags, qd, an, ns, ar)


def fixed(rtype, length, rclass=IN, ttl=120):
    return struct.pack("!HHIH", rtype, rclass, ttl, length)


def pointer(offset):
    return struct.pack("!H", 0xC000 | offset)


def compressed_response():
    """A browse answer the way real responders send it, with compressed names."""
    question = b"\x05_http\x04_tcp\x05local\x00" + struct.pack("!HH", PTR, IN)
    local_at = 12 + 1 + 5 + 1 + 4  # the "local" label inside the question
    instance = b"\x0bLiving-Room" + pointer(12)
    answer = pointer(12) + fixed(PTR, len(instance), ttl=4500) + instance
    instance_at = 12 + len(question) + 2 + 10
    srv_data = struct.pack("!HHH", 0, 0, 8080) + b"\x0bLiving-Room" + pointer(local_at)
    srv = pointer(instance_at) + fixed(SRV, len(srv_data), rclass=0x8001) + srv_data
    host_at = 12 + len(question) + len(answer) + 2 + 10 + 6
    address = pointer(host_at) + fixed(A, 4, rclass=0x8001) + bytes([192, 168, 1, 20])
    return header(qd=1, an=1, ar=2) + question + answer + srv + address


def full_response():
    instance = ("Kitchen.Speaker", "_airplay", "_tcp", "local")
    return Message(
        7,
        0x8400,
        questions=[(("_airplay", "_tcp", "local"), PTR)],
        answers=[Record(("_airplay", "_tcp", "local"), PTR, IN, 4500, instance)],
        authorities=[Record(("Living-Room", "local"), UNKNOWN, IN, 120, b"\x01\x02\x03")],
        additionals=[
            Record(instance, SRV, IN, 120, (0, 0, 7000, ("Living-Room", "local"))),
            Record(instance, TXT, IN, 4500, {"model": "Speaker1", "flag": ""}),
            Record(("Living-Room", "local"), A, IN, 120, "192.168.1.20"),
            Record(("Living-Room", "local"), AAAA, IN, 120, "fd00::20"),
        ],
    )


def txt_of(raw):
    message = Message(0, 0x8400, answers=[Record(("x", "local"), TXT, IN, 120, raw)])
    return parse_message(build_message(message)).answers[0].data


def strings(*items):
    return b"".join(bytes([len(item)]) + item for item in items)


def test_query_round_trip_keeps_dots_inside_labels():
    packet = build_query(
        [("_airplay._tcp.local.", PTR), (("My.Printer", "_ipp", "_tcp", "local"), SRV)],
        query_id=0x4242,
        recursion_desired=True,
    )
    message = parse_message(packet)
    assert message.id == 0x4242
    assert message.flags == 0x0100
    assert not message.is_response
    assert message.questions == [
        (("_airplay", "_tcp", "local"), PTR),
        (("My.Printer", "_ipp", "_tcp", "local"), SRV),
    ]
    assert message.records == []


def test_unicast_response_sets_the_qu_bit():
    assert build_query([("Living-Room.local", A)])[-2:] == b"\x00\x01"
    assert build_query([("Living-Room.local", A)], unicast_response=True)[-2:] == b"\x80\x01"


def test_build_query_rejects_bad_input():
    with pytest.raises(DnsError):
        build_query([("a.local", A)], query_id=0x10000)
    with pytest.raises(DnsError):
        encode_name("a..local")
    with pytest.raises(DnsError):
        encode_name(("x" * 64, "local"))
    with pytest.raises(DnsError):
        encode_name(("x" * 63,) * 4 + ("local",))
    assert encode_name("") == b"\x00"
    assert encode_name(".") == b"\x00"


def test_full_response_round_trip():
    message = full_response()
    assert parse_message(build_message(message)) == message


def test_compressed_names():
    message = parse_message(compressed_response())
    assert message.is_response
    assert message.questions == [(("_http", "_tcp", "local"), PTR)]
    (answer,) = message.answers
    assert answer.name == ("_http", "_tcp", "local")
    assert answer.data == ("Living-Room", "_http", "_tcp", "local")
    srv, address = message.additionals
    assert srv.name == ("Living-Room", "_http", "_tcp", "local")
    assert srv.rclass == IN  # cache-flush bit stripped
    assert srv.data == (0, 0, 8080, ("Living-Room", "local"))
    assert address.name == ("Living-Room", "local")
    assert address.data == "192.168.1.20"
    assert len(message.records) == 3


@pytest.mark.parametrize(
    "name",
    [
        pointer(12),  # points at itself
        b"\x01a" + pointer(12),  # back to its own start: a loop
        pointer(40),  # forward
        pointer(0x3FFF),  # far outside the message
        pointer(2),  # into the header
    ],
)
def test_bad_compression_pointers(name):
    packet = header(qd=1) + name + struct.pack("!HH", A, IN) + b"\x00" * 30
    with pytest.raises(DnsError):
        parse_message(packet)


def pointer_chain(length):
    """A record whose name runs through `length` pointers before reaching the root."""
    base = 12 + 1 + 10  # data of the first record: root name, then fixed fields
    chain = bytearray(b"\x00")
    for i in range(length - 1):
        chain += pointer(base + (i * 2 - 1 if i else 0))
    first = b"\x00" + fixed(UNKNOWN, len(chain)) + bytes(chain)
    last_link = base + 1 + (length - 2) * 2 if length > 1 else base
    second = pointer(last_link) + fixed(UNKNOWN, 0)
    return header(an=2) + first + second


def test_long_pointer_chains_are_refused():
    assert parse_message(pointer_chain(MAX_JUMPS)).answers[1].name == ()
    with pytest.raises(DnsError):
        parse_message(pointer_chain(MAX_JUMPS + 1))


def label_chain(links):
    """Raw data holding labels "a", each followed by a pointer to the one before.

    Returns the record and where each of those labels starts.
    """
    base = 12 + 1 + 10
    chain = bytearray(b"\x01a\x00")
    starts = [base]
    for _ in range(links):
        starts.append(base + len(chain))
        chain += b"\x01a" + pointer(starts[-2])
    return b"\x00" + fixed(UNKNOWN, len(chain)) + bytes(chain), starts


def test_pointer_limit_counts_the_pointers_of_names_read_before():
    chain, starts = label_chain(16)

    def packet(top):
        # The first name walks 10 pointers of the chain; the second walks the
        # links above it and then the same 10 again.
        names = pointer(starts[10]) + fixed(UNKNOWN, 0) + pointer(starts[top]) + fixed(UNKNOWN, 0)
        return header(an=3) + chain + names

    parsed = parse_message(packet(15))
    assert parsed.answers[1].name == ("a",) * 11
    assert parsed.answers[2].name == ("a",) * 16
    with pytest.raises(DnsError):
        parse_message(packet(16))  # 17 pointers


def shared_suffixes():
    """Names that reuse each other's tails in the ways compression allows."""
    packet = bytearray(header(qd=1, an=4))
    packet += b"\x01x\x01y\x01z\x05local\x00" + struct.pack("!HH", PTR, IN)
    w_at = len(packet) + 2 + 10
    packet += pointer(14) + fixed(PTR, 4) + b"\x01w" + pointer(16)
    packet += pointer(12) + fixed(PTR, 2) + pointer(w_at)
    qq_at = len(packet)
    packet += b"\x02qq" + pointer(w_at) + fixed(PTR, 2) + pointer(18)
    packet += pointer(qq_at) + fixed(UNKNOWN, 0)
    return bytes(packet)


def test_names_sharing_tails():
    found = [(record.name, record.data) for record in parse_message(shared_suffixes()).answers]
    assert found == [
        (("y", "z", "local"), ("w", "z", "local")),
        (("x", "y", "z", "local"), ("w", "z", "local")),
        (("qq", "w", "z", "local"), ("local",)),
        (("qq", "w", "z", "local"), b""),
    ]


def names_into_one_run(labels, records):
    """PTR records whose owner and target point at the label starts of one long run in turn."""
    base = 12 + 1 + 10
    run = b"\x01a" * labels + b"\x00"
    packet = bytearray(header(an=records + 1) + b"\x00" + fixed(UNKNOWN, len(run)) + run)
    for i in range(records):
        name = pointer(base + 2 * (i % labels))
        packet += name + fixed(PTR, 2, ttl=4500) + name
    return bytes(packet)


def test_names_pointing_into_one_long_run_cost_no_more_than_the_message():
    packet = names_into_one_run(127, 511)
    reads = []

    class Counting(bytes):
        def __getitem__(self, index):
            reads.append(index)
            return super().__getitem__(index)

    message = dnswire._parse(Counting(packet))
    assert len(message.answers) == 512
    assert message.answers[1].name == ("a",) * 127
    assert message.answers[-1].data == ("a",) * (127 - 510 % 127)
    # Walking every label of each of the 1022 names would take over 250000 reads.
    assert len(reads) < len(packet)


def walk_name(data, offset, seen=None):
    """Name decoding without the cache: every pointer walked every time."""
    labels = []
    size = 1
    pos = start = offset
    after = None
    jumps = 0
    while True:
        if pos >= len(data):
            raise DnsError("past the end")
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(data):
                raise DnsError("truncated pointer")
            target = ((length & 0x3F) << 8) | data[pos + 1]
            if target < 12 or target >= start:
                raise DnsError("bad pointer")
            jumps += 1
            if jumps > MAX_JUMPS:
                raise DnsError("too many pointers")
            if after is None:
                after = pos + 2
            pos = start = target
            continue
        if length & 0xC0:
            raise DnsError("label type")
        end = pos + 1 + length
        if end > len(data):
            raise DnsError("past the end")
        size += length + 1
        if size > 255:
            raise DnsError("too long")
        labels.append(data[pos + 1 : end].decode("utf-8", errors="replace"))
        pos = end
    return tuple(labels), pos if after is None else after


def test_cached_names_match_walking_every_pointer(monkeypatch):
    rng = random.Random(1035)
    chain, starts = label_chain(MAX_JUMPS)
    seeds = [
        compressed_response(),
        build_message(full_response()),
        shared_suffixes(),
        header(an=3)
        + chain
        + pointer(starts[5])
        + fixed(UNKNOWN, 0)
        + pointer(starts[-1])
        + fixed(UNKNOWN, 0),
        names_into_one_run(20, 30),
    ]
    packets = list(seeds)
    for _ in range(3000):
        packet = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            packet[rng.randrange(len(packet))] = rng.randrange(256)
        packets.append(bytes(packet))

    def outcome(packet):
        try:
            return parse_message(packet)
        except DnsError:
            return None

    cached = [outcome(packet) for packet in packets]
    monkeypatch.setattr(dnswire, "_read_name", walk_name)
    walked = [outcome(packet) for packet in packets]
    assert cached == walked
    assert sum(message is not None for message in cached) > 300


def test_wire_label_and_name_limits():
    long_label = header(qd=1) + b"\x40" + b"a" * 64 + b"\x00" + struct.pack("!HH", A, IN)
    with pytest.raises(DnsError):
        parse_message(long_label)

    def question(labels):
        name = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
        return header(qd=1) + name + struct.pack("!HH", A, IN)

    longest = [b"a" * 63] * 3 + [b"b" * 61]  # exactly 255 bytes on the wire
    assert len(parse_message(question(longest)).questions[0][0]) == 4
    with pytest.raises(DnsError):
        parse_message(question([b"a" * 63] * 3 + [b"b" * 62]))


def test_section_counts_are_checked():
    with pytest.raises(DnsError):
        parse_message(header(an=0xFFFF))
    with pytest.raises(DnsError):
        parse_message(header(an=3) + b"\x00" + fixed(UNKNOWN, 0))
    tiny = b"\x00" + fixed(UNKNOWN, 0)
    assert len(parse_message(header(an=MAX_RECORDS) + tiny * MAX_RECORDS).answers) == MAX_RECORDS
    with pytest.raises(DnsError):
        parse_message(header(an=MAX_RECORDS + 1) + tiny * (MAX_RECORDS + 1))


@pytest.mark.parametrize("packet", [compressed_response(), build_message(full_response())])
def test_every_truncation_raises_dns_error(packet):
    parse_message(packet)
    for cut in range(len(packet)):
        with pytest.raises(DnsError):
            parse_message(packet[:cut])


def test_mangled_packets_never_raise_anything_else():
    rng = random.Random(6762)
    seeds = [compressed_response(), build_message(full_response())]
    for _ in range(3000):
        packet = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 4)):
            packet[rng.randrange(len(packet))] = rng.randrange(256)
        if rng.random() < 0.3:
            del packet[rng.randrange(len(packet)) :]
        with contextlib.suppress(DnsError):
            parse_message(bytes(packet))
    for _ in range(500):
        noise = bytes(rng.randrange(256) for _ in range(rng.randint(0, 200)))
        with contextlib.suppress(DnsError):
            parse_message(noise)


def test_record_data_must_match_its_type():
    bad_a = header(an=1) + b"\x00" + fixed(A, 3) + b"\x01\x02\x03"
    short_srv = header(an=1) + b"\x00" + fixed(SRV, 6) + b"\x00" * 6
    long_ptr = header(an=1) + b"\x00" + fixed(PTR, 3) + b"\x05hello\x00"
    for packet in (bad_a, short_srv, long_ptr):
        with pytest.raises(DnsError):
            parse_message(packet)


def test_unknown_types_keep_capped_raw_data():
    big = header(an=1) + b"\x00" + fixed(UNKNOWN, 600) + b"x" * 600
    assert parse_message(big).answers[0].data == b"x" * 512


def test_bad_utf8_in_labels_is_replaced():
    packet = header(qd=1) + b"\x03\xff\xfeA\x05local\x00" + struct.pack("!HH", A, IN)
    ((name, _),) = parse_message(packet).questions
    assert name == (REPLACED * 2 + "A", "local")


def test_txt_edge_cases():
    assert txt_of(b"\x00") == {}
    assert txt_of(b"") == {}
    pairs = txt_of(
        strings(b"Model=X1", b"model=Y2", b"flag", b"=junk", b"k==v", b"n=\xff\xfe", b"Empty=")
    )
    assert pairs == {"model": "X1", "flag": "", "k": "=v", "n": REPLACED * 2, "empty": ""}
    many = txt_of(strings(*(f"k{i}={i}".encode() for i in range(70))))
    assert len(many) == 64
    assert "k63" in many
    assert "k64" not in many
    with pytest.raises(DnsError):
        txt_of(b"\x05ab")


def test_reverse_name():
    assert reverse_name("192.168.1.20") == ("20", "1", "168", "192", "in-addr", "arpa")
    for bad in ("fe80::1", "192.168.1", "Living-Room"):
        with pytest.raises(ValueError):
            reverse_name(bad)


def test_read_header():
    assert read_header(header(1, 2, 3, 4, msg_id=7, flags=0x8400) + b"rest") == (7, 0x8400, 10)
    with pytest.raises(DnsError):
        read_header(b"\x00" * 11)


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("Kitchen\u202eVT moor", "Kitchen?VT moor"),  # right-to-left override
        ("a\u2066b\u2069c", "a?b?c"),  # isolates
        ("zero\u200bwidth\ufeff", "zero?width?"),
        ("line\u2028paragraph\u2029", "line?paragraph?"),
        ("private\ue000", "private?"),
        ("unassigned\u0378", "unassigned?"),
        ("bell\x07esc\x1b[2J\x9b", "bell?esc?[2J?"),
        ("Caf\u00e9 Speaker \u00e7", "Caf\u00e9 Speaker \u00e7"),
        ("no\u00a0break", "no\u00a0break"),
    ],
)
def test_display_text_hides_control_and_format_characters(raw, shown):
    assert display_text(raw) == shown


def test_name_helpers():
    assert name_text(("Kitchen.Speaker", "_airplay", "_tcp", "local")) == (
        "Kitchen.Speaker._airplay._tcp.local"
    )
    assert name_text(()) == ""
    assert name_text(("evil\x1b[2J", "local")) == "evil?[2J.local"
    assert name_text(("Kitchen\u202e", "local")) == "Kitchen?.local"
    assert name_key(("Living-Room", "LOCAL")) == ("living-room", "local")
