import asyncio
import random
import socket
import struct

import pytest

from hearthscan.discovery import _udp, netbios
from hearthscan.discovery.netbios import build_status_query, parse_status_reply, query
from hearthscan.models import NetbiosInfo
from hearthscan.scope import ScopeError

WILDCARD = b"\x20" + b"CK" + b"A" * 30 + b"\x00"
ACTIVE = 0x0400
MAC = bytes.fromhex("001a2b3c4d5e")


def encode(name: bytes, suffix: int) -> bytes:
    raw = name.ljust(15, b" ") + bytes([suffix])
    letters = bytes(c for byte in raw for c in (0x41 + (byte >> 4), 0x41 + (byte & 0x0F)))
    return b"\x20" + letters + b"\x00"


def entry(name, suffix: int, *, group: bool = False) -> bytes:
    raw = name.encode("cp437") if isinstance(name, str) else name
    flags = ACTIVE | (0x8000 if group else 0)
    return raw.ljust(15, b" ") + bytes([suffix]) + struct.pack("!H", flags)


def reply(
    entries,
    mac: bytes = bytes(6),
    *,
    tid: int = 0x1234,
    flags: int = 0x8400,
    name: bytes = WILDCARD,
    rtype: int = 0x21,
    count: int | None = None,
    stats: bool = True,
    questions: bytes = b"",
) -> bytes:
    rdata = bytes([len(entries) if count is None else count]) + b"".join(entries)
    if stats:
        rdata += mac + bytes(40)
    header = struct.pack("!6H", tid, flags, 1 if questions else 0, 1, 0, 0)
    answer = name + struct.pack("!2HIH", rtype, 1, 0, len(rdata)) + rdata
    return header + questions + answer


WINDOWS = [
    entry("DESKTOP-7Q1", 0x00),
    entry("WORKGROUP", 0x00, group=True),
    entry("DESKTOP-7Q1", 0x20),
    entry("WORKGROUP", 0x1E, group=True),
    entry("WORKGROUP", 0x1D),
    entry(b"\x01\x02__MSBROWSE__\x02", 0x01, group=True),
]
SAMBA = [
    entry("NAS-BOX", 0x00),
    entry("NAS-BOX", 0x03),
    entry("NAS-BOX", 0x20),
    entry("HOME", 0x00, group=True),
    entry("HOME", 0x1E, group=True),
]


def tid_of(payload: bytes) -> int:
    return struct.unpack("!H", payload[:2])[0]


def test_status_query_bytes():
    packet = build_status_query(0x1234)
    assert packet == (
        b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    assert len(packet) == 50


@pytest.mark.parametrize("tid", [-1, 0x10000, True, 1.5])
def test_status_query_rejects_bad_ids(tid):
    with pytest.raises(ValueError):
        build_status_query(tid)


def test_windows_reply():
    info = parse_status_reply(reply(WINDOWS, MAC))
    assert info == NetbiosInfo(
        name="DESKTOP-7Q1", workgroup="WORKGROUP", mac="00:1a:2b:3c:4d:5e", file_server=True
    )


def test_samba_reply_with_zero_mac():
    info = parse_status_reply(reply(SAMBA))
    assert info == NetbiosInfo(name="NAS-BOX", workgroup="HOME", mac=None, file_server=True)


def test_name_and_workgroup_pick_the_first_of_their_kind():
    entries = [
        entry("HOME", 0x00, group=True),
        entry("OFFICE", 0x00, group=True),
        entry("ALICE", 0x03),
        entry("PRINTER-2F", 0x00),
        entry("OTHER-NAME", 0x00),
        entry("SHARES", 0x20, group=True),
    ]
    info = parse_status_reply(reply(entries, MAC))
    assert info.name == "PRINTER-2F"
    assert info.workgroup == "HOME"
    assert info.file_server is False


def test_no_names_but_a_mac():
    assert parse_status_reply(reply([], MAC)) == NetbiosInfo(mac="00:1a:2b:3c:4d:5e")


@pytest.mark.parametrize("mac", ["ffffffffffff", "01005e0000fb"])
def test_broadcast_and_multicast_unit_ids_are_dropped(mac):
    info = parse_status_reply(reply(WINDOWS, bytes.fromhex(mac)))
    assert info.name == "DESKTOP-7Q1"
    assert info.mac is None


def test_name_count_larger_than_the_data():
    info = parse_status_reply(reply(WINDOWS[:2], count=40, stats=False))
    assert info == NetbiosInfo(name="DESKTOP-7Q1", workgroup="WORKGROUP")

    # The bytes after the real names are not a statistics block then.
    info = parse_status_reply(reply(WINDOWS[:2], MAC, count=40))
    assert info.name == "DESKTOP-7Q1"
    assert info.mac is None

    assert parse_status_reply(reply([], count=255, stats=False)) == NetbiosInfo()


def test_truncation_at_every_offset():
    packet = reply(WINDOWS, MAC)
    assert parse_status_reply(packet) is not None
    for end in range(len(packet)):
        assert parse_status_reply(packet[:end]) is None, end


def test_oem_names(monkeypatch):
    monkeypatch.setattr(netbios, "_CODEC", "cp437")
    entries = [
        entry(b"\x00" * 15, 0x00),
        entry(b"K\x99K-PC", 0x00),
        entry(b"EV\x00\x00\x07\xff", 0x00, group=True),
    ]
    info = parse_status_reply(reply(entries))
    assert info.name == "KÖK-PC"
    assert info.workgroup == "EV"


def test_names_use_the_local_oem_code_page(monkeypatch):
    monkeypatch.setattr(netbios, "_CODEC", "cp857")
    entries = [
        entry("ÇAĞRI-PC".encode("cp857"), 0x00),
        entry("İŞYERİ".encode("cp857"), 0x00, group=True),
    ]
    info = parse_status_reply(reply(entries))
    assert info.name == "ÇAĞRI-PC"
    assert info.workgroup == "İŞYERİ"


def test_codec_for_a_code_page():
    assert netbios._codec(857) == "cp857"
    assert netbios._codec(850) == "cp850"
    assert netbios._codec(65001) == "cp65001"
    assert netbios._codec(None) == "cp437"
    assert netbios._codec(0) == "cp437"
    assert netbios._codec(99999) == "cp437"


def test_oem_code_page_is_windows_only(monkeypatch):
    monkeypatch.setattr(netbios, "IS_WINDOWS", False)
    assert netbios._oem_code_page() is None


@pytest.mark.skipif(not netbios.IS_WINDOWS, reason="the OEM code page only exists on Windows")
def test_codec_follows_windows():
    import ctypes

    code_page = ctypes.windll.kernel32.GetOEMCP()
    assert netbios._oem_code_page() == code_page
    assert netbios._codec(code_page) == netbios._CODEC


def test_answer_name_need_not_be_the_wildcard():
    real = encode(b"DESKTOP-7Q1", 0x00)
    assert parse_status_reply(reply(WINDOWS, MAC, name=real)).name == "DESKTOP-7Q1"
    scoped = real[:-1] + b"\x04HOME\x00"
    assert parse_status_reply(reply(WINDOWS, MAC, name=scoped)).name == "DESKTOP-7Q1"
    # A pointer back to itself is stepped over, never followed.
    assert parse_status_reply(reply(WINDOWS, MAC, name=b"\xc0\x0c")).name == "DESKTOP-7Q1"


def test_echoed_question_is_skipped():
    question = WILDCARD + b"\x00\x21\x00\x01"
    info = parse_status_reply(reply(WINDOWS, MAC, questions=question))
    assert info.name == "DESKTOP-7Q1"


@pytest.mark.parametrize(
    "packet",
    [
        build_status_query(0x1234),
        reply(WINDOWS, MAC, flags=0x0000),  # request bit pattern
        reply(WINDOWS, MAC, flags=0x8403),  # negative response
        reply(WINDOWS, MAC, flags=0xA800),  # registration response
        reply(WINDOWS, MAC, rtype=0x20),  # name query answer, not node status
        reply(WINDOWS, MAC, name=b"\x40" + WILDCARD[1:]),  # unknown label type
        reply(WINDOWS, MAC, name=(b"\x3f" + b"A" * 63) * 5 + b"\x00"),  # name over 255 bytes
        b"",
        b"\x12\x34\x84\x00",
    ],
)
def test_not_a_node_status_response(packet):
    assert parse_status_reply(packet) is None


def test_absurd_counts_and_lengths():
    packet = bytearray(reply(WINDOWS, MAC))
    rdlength_at = 12 + len(WILDCARD) + 8

    huge_rdlength = bytearray(packet)
    huge_rdlength[rdlength_at : rdlength_at + 2] = b"\xff\xff"
    assert parse_status_reply(bytes(huge_rdlength)) is None

    many_answers = bytearray(reply(WINDOWS, MAC, rtype=0x20))
    many_answers[6:8] = b"\xff\xff"
    assert parse_status_reply(bytes(many_answers)) is None

    many_questions = bytearray(packet)
    many_questions[4:6] = b"\xff\xff"
    assert parse_status_reply(bytes(many_questions)) is None


def test_garbage_never_raises():
    rng = random.Random(1002)
    good = reply(WINDOWS, MAC)
    for _ in range(3000):
        packet = bytearray(good)
        for _ in range(rng.randint(1, 6)):
            packet[rng.randrange(len(packet))] = rng.randrange(256)
        if rng.random() < 0.3:
            packet = packet[: rng.randrange(len(packet))]
        if rng.random() < 0.1:
            packet = bytearray(rng.randbytes(rng.randrange(120)))
        info = parse_status_reply(bytes(packet))
        if info is not None:
            assert info.name is None or len(info.name) <= 15
            assert info.workgroup is None or len(info.workgroup) <= 15


class FakeExchange:
    def __init__(self, answer=lambda packets: []):
        self.answer = answer
        self.calls = []

    async def __call__(self, packets, *, local, listen, spacing=0.0, **kwargs):
        packets = list(packets)
        self.calls.append(
            {"packets": packets, "local": local, "listen": listen, "spacing": spacing}
        )
        return self.answer(packets)


def test_query_sends_one_query_per_address_per_round(monkeypatch):
    fake = FakeExchange()
    monkeypatch.setattr(_udp, "exchange", fake)
    ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    assert asyncio.run(query("192.168.1.2", ips, listen=0.5, rounds=3)) == {}

    (call,) = fake.calls
    assert call["local"] == "192.168.1.2"
    assert call["listen"] == 0.5
    assert [address for _, address in call["packets"]] == [(ip, 137) for ip in ips] * 3
    tids = [tid_of(payload) for payload, _ in call["packets"]]
    assert len(set(tids)) == 9
    for payload, _ in call["packets"]:
        assert payload[2:] == build_status_query(0)[2:]


def test_query_keeps_only_matching_replies(monkeypatch):
    a, b, c, d = "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"

    def answer(packets):
        sent = {}
        for payload, (ip, _) in packets:
            sent.setdefault(ip, []).append(tid_of(payload))
        used = {tid for tids in sent.values() for tid in tids}
        unused = next(tid for tid in range(0x10000) if tid not in used)
        return [
            (reply([entry("STRANGER", 0)], tid=sent[a][0]), "192.168.1.99"),
            (reply([entry("WRONG-ID", 0)], tid=unused), b),
            (reply([entry("SWAPPED", 0)], tid=sent[c][0]), b),
            (b"\x00", c),
            (build_status_query(sent[c][0]), c),
            (reply([entry("Living-Room", 0)], MAC, tid=sent[a][0]), a),
            (reply([entry("DUPLICATE", 0)], tid=sent[a][1]), a),
            (reply([entry("LATE-PC", 0)], tid=sent[d][1]), d),
        ]

    monkeypatch.setattr(_udp, "exchange", FakeExchange(answer))
    found = asyncio.run(query("192.168.1.2", [d, c, b, a]))

    assert list(found) == [d, a]
    assert found[a] == NetbiosInfo(name="Living-Room", mac="00:1a:2b:3c:4d:5e")
    assert found[d].name == "LATE-PC"


def test_short_lists_keep_the_rounds_apart(monkeypatch):
    fake = FakeExchange()
    monkeypatch.setattr(_udp, "exchange", fake)

    asyncio.run(query("10.0.0.2", ["10.0.0.7"], spacing=0.002))
    asyncio.run(query("10.0.0.2", [f"10.0.0.{i}" for i in range(1, 255)], spacing=0.002))
    asyncio.run(query("10.0.0.2", ["10.0.0.7"], spacing=0.002, rounds=1))

    assert [call["spacing"] for call in fake.calls] == [netbios.ROUND_GAP, 0.002, 0.002]


def test_query_cleans_up_its_targets(monkeypatch):
    fake = FakeExchange()
    monkeypatch.setattr(_udp, "exchange", fake)

    assert asyncio.run(query("10.0.0.2", [])) == {}
    assert fake.calls == []

    ips = ["10.0.0.5", "10.0.0.5", "fe80::1", "::ffff:10.0.0.6"]
    asyncio.run(query("10.0.0.2", ips, rounds=1))
    assert [address for _, address in fake.calls[0]["packets"]] == [
        ("10.0.0.5", 137),
        ("10.0.0.6", 137),
    ]


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"ips": ["8.8.8.8"]}, ScopeError),
        ({"ips": ["not-an-ip"]}, ValueError),
        ({"rounds": 0}, ValueError),
        ({"rounds": 1.5}, ValueError),
        ({"listen": -1}, ValueError),
        ({"spacing": float("nan")}, ValueError),
        ({"ips": [f"10.0.{i // 256}.{i % 256}" for i in range(40000)]}, ValueError),
    ],
)
def test_query_rejects_bad_arguments(monkeypatch, kwargs, error):
    monkeypatch.setattr(_udp, "exchange", FakeExchange())
    arguments = {"ips": ["10.0.0.5"], **kwargs}
    with pytest.raises(error):
        asyncio.run(query("10.0.0.2", arguments.pop("ips"), **arguments))


def unused_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_query_over_loopback(monkeypatch):
    async def main():
        loop = asyncio.get_running_loop()
        seen = []

        class Responder(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                seen.append(data)
                self.transport.sendto(reply(WINDOWS, MAC, tid=tid_of(data)), addr)

        server, _ = await loop.create_datagram_endpoint(Responder, local_addr=("127.0.0.1", 0))
        monkeypatch.setattr(netbios, "PORT", server.get_extra_info("sockname")[1])
        try:
            found = await query("127.0.0.1", ["127.0.0.1"], listen=0.3, rounds=1)
        finally:
            server.close()
        return found, seen

    found, seen = asyncio.run(main())
    assert found == {"127.0.0.1": parse_status_reply(reply(WINDOWS, MAC))}
    assert len(seen) == 1
    assert seen[0][2:] == build_status_query(0)[2:]


def test_cancelling_query_closes_the_socket(monkeypatch):
    opened = []
    real_open = _udp.open_socket

    def recording_open(*args, **kwargs):
        sock = real_open(*args, **kwargs)
        opened.append(sock)
        return sock

    monkeypatch.setattr(_udp, "open_socket", recording_open)
    monkeypatch.setattr(netbios, "PORT", unused_udp_port())

    async def main():
        task = asyncio.ensure_future(query("127.0.0.1", ["127.0.0.1"], listen=30, rounds=1))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.05)
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []
    assert len(opened) == 1
    assert opened[0].fileno() == -1
