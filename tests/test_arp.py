import ctypes
import ntpath
import random
import sys
from ipaddress import IPv4Address, IPv4Interface, ip_address, ip_network
from pathlib import Path

import pytest

from hearthscan import system
from hearthscan.discovery import arp
from hearthscan.discovery.arp import Neighbor, on_network
from hearthscan.models import normalize_mac

DATA = Path(__file__).parent / "data"

BROADCAST = "ff:ff:ff:ff:ff:ff"


def read(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


def test_windows_english():
    assert arp.parse_arp_windows(read("arp_windows_en.txt")) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", "192.168.1.20"),
        Neighbor("192.168.1.34", "02:5a:7c:19:3e:42", "192.168.1.20"),
        Neighbor("192.168.1.255", BROADCAST, "192.168.1.20"),
        Neighbor("224.0.0.22", "01:00:5e:00:00:16", "192.168.1.20"),
        Neighbor("224.0.0.251", "01:00:5e:00:00:fb", "192.168.1.20"),
        Neighbor("239.255.255.250", "01:00:5e:7f:ff:fa", "192.168.1.20"),
        Neighbor("255.255.255.255", BROADCAST, "192.168.1.20"),
        Neighbor("172.29.0.9", "02:15:5d:a0:0b:09", "172.29.0.1"),
        Neighbor("172.29.15.255", BROADCAST, "172.29.0.1"),
        Neighbor("224.0.0.22", "01:00:5e:00:00:16", "172.29.0.1"),
    ]


def test_windows_turkish_with_crlf():
    text = read("arp_windows_tr.txt").replace("\n", "\r\n")
    assert arp.parse_arp_windows(text) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", "192.168.1.34"),
        Neighbor("192.168.1.50", "02:7c:3e:19:5a:50", "192.168.1.34"),
        Neighbor("192.168.1.255", BROADCAST, "192.168.1.34"),
        Neighbor("224.0.0.251", "01:00:5e:00:00:fb", "192.168.1.34"),
        Neighbor("239.255.255.250", "01:00:5e:7f:ff:fa", "192.168.1.34"),
    ]


def test_windows_danish():
    text = (
        "\r\n"
        "Grænseflade: 10.0.0.12 --- 0x7\r\n"
        "  Internetadresse       Fysisk adresse        Type\r\n"
        "  10.0.0.1              ac-de-48-00-22-01     dynamisk  \r\n"
        "  10.0.0.255            ff-ff-ff-ff-ff-ff     statisk   \r\n"
    )
    assert arp.parse_arp_windows(text) == [
        Neighbor("10.0.0.1", "ac:de:48:00:22:01", "10.0.0.12"),
        Neighbor("10.0.0.255", BROADCAST, "10.0.0.12"),
    ]


@pytest.mark.parametrize(
    "header",
    [
        "Interface: 192.168.1.20 --- 0x11",
        "Schnittstelle: 192.168.1.20 --- 0xb",
        "Interface : 192.168.1.20 --- 0x5",
        "インターフェイス: 192.168.1.20 --- 0x1A",
    ],
)
def test_windows_headers_are_matched_by_shape(header):
    text = f"{header}\n  192.168.1.1  ac-de-48-00-11-01  dynamic\n"
    assert arp.parse_arp_windows(text) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", "192.168.1.20")
    ]


def test_windows_skips_broken_lines():
    text = (
        "  192.168.1.1           ac-de-48-00-11-01     dynamic\n"  # before any header
        "Interface: 192.168.1.20 --- 0x11\n"
        "  192.168.1.2           ac-de-48-00-11-0      dynamic\n"  # cut off
        "  192.168.1.3           ac-de-48-00-11-03\n"  # no type word
        "  192.168.01.4          ac-de-48-00-11-04     dynamic\n"
        "  192.168.1.5           zz-de-48-00-11-05     dynamic\n"
        "Interface: 999.168.1.20 --- 0x12\n"
        "  10.0.0.6              ac-de-48-00-11-06     dynamic\n"
    )
    assert arp.parse_arp_windows(text) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", None),
        Neighbor("10.0.0.6", "ac:de:48:00:11:06", None),
    ]


def test_macos_and_freebsd():
    assert arp.parse_arp_macos(read("arp_macos.txt")) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", "en0"),
        Neighbor("192.168.1.23", "02:5a:7c:19:3e:42", "en0"),
        Neighbor("192.168.1.50", "ac:de:48:00:11:50", "en0", "reachable"),
        Neighbor("192.168.1.255", BROADCAST, "en0"),
        Neighbor("169.254.12.7", "ac:de:48:00:33:07", "en0"),
        Neighbor("224.0.0.251", "01:00:5e:00:00:fb", "en0", "reachable"),
        Neighbor("239.255.255.250", "01:00:5e:7f:ff:fa", "en0", "reachable"),
        Neighbor("10.0.0.7", "ac:de:48:00:22:07", "em0", "reachable"),  # expires in 1180 s
        Neighbor("10.0.0.12", "ac:de:48:00:22:0c", "em0", "reachable"),
    ]


@pytest.mark.parametrize(
    "seconds, state",
    [
        (1200, "reachable"),
        (1171, "reachable"),
        (1169, "unknown"),
        (300, "unknown"),
        (1201, "unknown"),  # max_age was raised, so the age is anyone's guess
        (99999999999, "unknown"),
    ],
)
def test_freebsd_expiry_shows_a_fresh_entry(seconds, state):
    text = f"? (10.0.0.7) at ac:de:48:00:22:07 on em0 expires in {seconds} seconds [ethernet]\n"
    assert arp.parse_arp_macos(text) == [Neighbor("10.0.0.7", "ac:de:48:00:22:07", "em0", state)]


def test_macos_resolved_name_and_missing_interface():
    text = "Living-Room.lan (192.168.1.8) at ac:de:48:0:11:8 [ethernet]\n"
    assert arp.parse_arp_macos(text) == [Neighbor("192.168.1.8", "ac:de:48:00:11:08")]


def test_openbsd_table():
    text = (
        "Host                                 Ethernet Address   Netif Expire    Flags\n"
        "192.168.1.1                          ac:de:48:00:11:01  em0   19m51s\n"
        "192.168.1.20                         ac:de:48:00:11:14  em0   permanent l\n"
        "192.168.1.30                         (incomplete)       em0   expired\n"
    )
    assert arp.parse_arp_macos(text) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", "em0"),
        Neighbor("192.168.1.20", "ac:de:48:00:11:14", "em0", "reachable"),
    ]


def test_proc_net_arp():
    assert arp.parse_proc_net_arp(read("arp_proc_net_arp.txt")) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", "wlp2s0"),
        Neighbor("192.168.1.23", "02:5a:7c:19:3e:42", "wlp2s0"),
        Neighbor("192.168.1.60", "ac:de:48:00:11:3c", "wlp2s0", "reachable"),
        Neighbor("10.0.0.5", "ac:de:48:00:22:05", "eth0", "reachable"),
    ]


def test_proc_net_arp_bad_flags():
    text = (
        "192.168.1.2  0x1  -0x2  ac:de:48:00:11:02  *  eth0\n"
        "192.168.1.3  0x1  0xzz  ac:de:48:00:11:03  *  eth0\n"
        "192.168.1.4  0x1  0x8   ac:de:48:00:11:04  *  eth0\n"
    )
    assert arp.parse_proc_net_arp(text) == []


def test_ip_neigh_states():
    assert arp.parse_ip_neigh(read("arp_ip_neigh.txt")) == [
        Neighbor("192.168.1.1", "ac:de:48:00:11:01", "wlp2s0", "reachable"),
        Neighbor("192.168.1.23", "02:5a:7c:19:3e:42", "wlp2s0", "stale"),
        Neighbor("192.168.1.30", "ac:de:48:00:11:1e", "wlp2s0", "probing"),  # DELAY
        Neighbor("192.168.1.31", "ac:de:48:00:11:1f", "wlp2s0", "probing"),  # PROBE
        Neighbor("10.0.0.5", "ac:de:48:00:22:05", "eth0", "reachable"),
        Neighbor("10.0.0.6", "ac:de:48:00:22:06", "eth0", "reachable"),
        Neighbor("10.0.0.8", "ac:de:48:00:22:08", "eth0", "stale"),
    ]


def test_ip_neigh_without_a_state_word():
    text = "192.168.1.9 dev eth0 lladdr ac:de:48:00:11:09\n192.168.1.10 lladdr\n"
    assert arp.parse_ip_neigh(text) == [Neighbor("192.168.1.9", "ac:de:48:00:11:09", "eth0")]


def test_parsers_cap_what_they_keep():
    rows = "".join(
        f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255} dev eth0 lladdr ac:de:48:00:11:01 STALE\n"
        for i in range(arp.MAX_NEIGHBORS + 50)
    )
    assert len(arp.parse_ip_neigh(rows)) == arp.MAX_NEIGHBORS


def test_absurd_lines_and_names():
    long_name = "x" * 500
    text = (
        "192.168.1.1 dev eth0 lladdr ac:de:48:00:11:01 " + "STALE " * 400 + "\n"
        f"192.168.1.2 dev {long_name} lladdr ac:de:48:00:11:02 STALE\n"
    )
    assert arp.parse_ip_neigh(text) == [
        Neighbor("192.168.1.2", "ac:de:48:00:11:02", "x" * 64, "stale")
    ]


def garbage_lines(rng: random.Random, samples: list[str]) -> list[str]:
    alphabet = "0123456789abcdefABCDEF:.-()?x \t[]_ " + "ıİæøå\x00​\ud800"
    words = [
        "at",
        "on",
        "dev",
        "lladdr",
        "router",
        "proto",
        "permanent",
        "(incomplete)",
        "---",
        "0x",
        "0x2",
        "REACHABLE",
        "STALE",
        "Interface:",
        "?",
        "(192.168.1.1)",
        "192.168.1.1",
        "999.1.1.1",
        "ac:de:48:00:11:01",
        "ac-de-48-00-11-01",
        "1:2:3:4:5",
        "",
    ]
    lines = []
    for _ in range(3000):
        kind = rng.randrange(4)
        if kind == 0:
            lines.append("".join(rng.choice(alphabet) for _ in range(rng.randrange(80))))
        elif kind == 1:
            lines.append(" ".join(rng.choice(words) for _ in range(rng.randrange(12))))
        else:
            line = list(rng.choice(samples))
            for _ in range(rng.randrange(1, 6)):
                if not line:
                    break
                spot = rng.randrange(len(line))
                action = rng.randrange(3)
                if action == 0:
                    del line[spot:]
                elif action == 1:
                    del line[spot]
                else:
                    line.insert(spot, rng.choice(alphabet))
            lines.append("".join(line))
    lines.append("1" * 10_000)
    lines.append("Interface: " + "1." * 2000 + " --- 0x1")
    lines.append("Interface: " + "1." * 400 + " --- 0x1")
    return lines


def test_parsers_survive_garbage():
    rng = random.Random(4721)
    samples = [
        line
        for name in (
            "arp_windows_en.txt",
            "arp_windows_tr.txt",
            "arp_macos.txt",
            "arp_proc_net_arp.txt",
            "arp_ip_neigh.txt",
        )
        for line in read(name).splitlines()
        if line.strip()
    ]
    text = "\r\n".join(garbage_lines(rng, samples))
    for parse in (
        arp.parse_arp_windows,
        arp.parse_arp_macos,
        arp.parse_proc_net_arp,
        arp.parse_ip_neigh,
    ):
        found = parse(text)
        for entry in found:
            assert isinstance(entry, Neighbor)
            assert str(IPv4Address(entry.ip)) == entry.ip
            assert normalize_mac(entry.mac) == entry.mac
            assert entry.state in ("reachable", "probing", "stale", "unknown")
            assert entry.interface is None or len(entry.interface) <= 64
        on_network(found, ip_network("192.168.1.0/24"), "192.168.1.20")


def test_on_network_filters_and_sorts():
    entries = [
        Neighbor("192.168.1.0", "ac:de:48:00:11:00"),
        Neighbor("192.168.1.255", BROADCAST),
        Neighbor("192.168.1.20", "ac:de:48:00:11:14"),  # ourselves
        Neighbor("192.168.1.100", "ac:de:48:00:11:64", "eth0"),
        Neighbor("192.168.1.10", "ac:de:48:00:11:0a", "eth0"),
        Neighbor("192.168.1.9", "ac:de:48:00:11:09", "eth0"),
        Neighbor("192.168.2.5", "ac:de:48:00:12:05"),  # another network
        Neighbor("192.168.1.40", "01:00:5e:00:00:fb"),  # multicast MAC
        Neighbor("224.0.0.251", "01:00:5e:00:00:fb"),
        Neighbor("not an address", "ac:de:48:00:11:0b"),
        Neighbor("192.168.1.11", "not a mac"),
    ]
    assert on_network(entries, ip_network("192.168.1.0/24"), "192.168.1.20") == [
        Neighbor("192.168.1.9", "ac:de:48:00:11:09", "eth0"),
        Neighbor("192.168.1.10", "ac:de:48:00:11:0a", "eth0"),
        Neighbor("192.168.1.100", "ac:de:48:00:11:64", "eth0"),
    ]


def test_on_network_accepts_an_address_object_for_ourselves():
    entries = [Neighbor("10.0.0.2", "ac:de:48:00:22:02"), Neighbor("10.0.0.3", "02:00:00:00:00:03")]
    assert on_network(entries, ip_network("10.0.0.0/24"), ip_address("10.0.0.2")) == [
        Neighbor("10.0.0.3", "02:00:00:00:00:03")
    ]


def test_on_network_prefers_the_freshest_entry():
    entries = [
        Neighbor("192.168.1.5", "ac:de:48:00:11:05", "eth0", "stale"),
        Neighbor("192.168.1.5", "ac:de:48:00:11:55", "wlan0", "reachable"),
        Neighbor("192.168.1.6", "ac:de:48:00:11:06", "eth0", "unknown"),
        Neighbor("192.168.1.6", "ac:de:48:00:11:66", "eth0", "stale"),
        Neighbor("192.168.1.7", "ac:de:48:00:11:07", "eth0", "reachable"),
        Neighbor("192.168.1.7", "ac:de:48:00:11:77", "eth0", "unknown"),
        Neighbor("192.168.1.8", "ac:de:48:00:11:08", "eth0", "stale"),
        Neighbor("192.168.1.8", "ac:de:48:00:11:88", "eth0", "stale"),
        Neighbor("192.168.1.9", "ac:de:48:00:11:09", "eth0", "stale"),
        Neighbor("192.168.1.9", "ac:de:48:00:11:99", "eth0", "probing"),
        Neighbor("192.168.1.10", "ac:de:48:00:11:10", "eth0", "probing"),
        Neighbor("192.168.1.10", "ac:de:48:00:11:a0", "eth0", "reachable"),
    ]
    assert on_network(entries, ip_network("192.168.1.0/24")) == [
        Neighbor("192.168.1.5", "ac:de:48:00:11:55", "wlan0", "reachable"),
        Neighbor("192.168.1.6", "ac:de:48:00:11:66", "eth0", "stale"),
        Neighbor("192.168.1.7", "ac:de:48:00:11:07", "eth0", "reachable"),
        Neighbor("192.168.1.8", "ac:de:48:00:11:08", "eth0", "stale"),
        Neighbor("192.168.1.9", "ac:de:48:00:11:99", "eth0", "probing"),
        Neighbor("192.168.1.10", "ac:de:48:00:11:a0", "eth0", "reachable"),
    ]


@pytest.mark.parametrize(
    "network, kept",
    [
        ("10.0.0.0/30", ["10.0.0.1", "10.0.0.2"]),
        ("10.0.0.0/31", ["10.0.0.0", "10.0.0.1"]),
        ("10.0.0.3/32", ["10.0.0.3"]),
    ],
)
def test_on_network_small_prefixes(network, kept):
    entries = [Neighbor(f"10.0.0.{i}", f"ac:de:48:00:22:0{i}") for i in range(5)]
    assert [n.ip for n in on_network(entries, ip_network(network))] == kept


class FakeRun:
    def __init__(self, outputs: dict[tuple[str, ...], str]) -> None:
        self.outputs = outputs
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], timeout: float = 10.0) -> str:
        self.calls.append(args)
        return self.outputs.get(tuple(args), "")


def pretend(monkeypatch, name: str) -> None:
    monkeypatch.setattr(arp, "IS_WINDOWS", name == "windows")
    monkeypatch.setattr(arp, "IS_LINUX", name == "linux")


def test_neighbors_linux_uses_ip_neigh(monkeypatch, tmp_path):
    pretend(monkeypatch, "linux")
    fake = FakeRun({("ip", "-4", "neigh", "show"): read("arp_ip_neigh.txt")})
    monkeypatch.setattr(arp, "run", fake)
    monkeypatch.setattr(arp, "_PROC_NET_ARP", tmp_path / "missing")
    found = arp.neighbors()
    assert fake.calls == [["ip", "-4", "neigh", "show"]]
    assert found[0] == Neighbor("192.168.1.1", "ac:de:48:00:11:01", "wlp2s0", "reachable")


def test_neighbors_linux_falls_back_to_proc_net_arp(monkeypatch, tmp_path):
    pretend(monkeypatch, "linux")
    monkeypatch.setattr(arp, "run", FakeRun({}))
    proc = tmp_path / "arp"
    proc.write_text(read("arp_proc_net_arp.txt"), encoding="utf-8")
    monkeypatch.setattr(arp, "_PROC_NET_ARP", proc)
    assert [n.ip for n in arp.neighbors()] == [
        "192.168.1.1",
        "192.168.1.23",
        "192.168.1.60",
        "10.0.0.5",
    ]


def test_neighbors_linux_with_nothing_to_read(monkeypatch, tmp_path):
    pretend(monkeypatch, "linux")
    monkeypatch.setattr(arp, "run", FakeRun({}))
    monkeypatch.setattr(arp, "_PROC_NET_ARP", tmp_path / "missing")
    assert arp.neighbors() == []


def test_neighbors_macos(monkeypatch):
    pretend(monkeypatch, "macos")
    fake = FakeRun({("arp", "-an"): read("arp_macos.txt")})
    monkeypatch.setattr(arp, "run", fake)
    assert len(arp.neighbors()) == 9
    assert fake.calls == [["arp", "-an"]]


def test_neighbors_windows_prefers_the_api(monkeypatch):
    pretend(monkeypatch, "windows")
    fake = FakeRun({})
    monkeypatch.setattr(arp, "run", fake)
    table = [Neighbor("192.168.1.1", "ac:de:48:00:11:01", "192.168.1.20", "reachable")]
    monkeypatch.setattr(arp, "_read_ipnet_table2", lambda: table)
    assert arp.neighbors() == table
    assert fake.calls == []


def test_neighbors_windows_falls_back_to_arp_a(monkeypatch):
    pretend(monkeypatch, "windows")
    arp_exe = system.windows_tool("arp.exe")
    fake = FakeRun({(arp_exe, "-a"): read("arp_windows_en.txt").replace("\n", "\r\n")})
    monkeypatch.setattr(arp, "run", fake)

    def broken():
        raise OSError(87, "The parameter is incorrect")

    monkeypatch.setattr(arp, "_read_ipnet_table2", broken)
    found = arp.neighbors()
    # By full path: a bare "arp" would find an arp.exe in the current directory first.
    assert fake.calls == [[arp_exe, "-a"]]
    assert ntpath.isabs(arp_exe) and ntpath.basename(arp_exe) == "arp.exe"
    assert found[0] == Neighbor("192.168.1.1", "ac:de:48:00:11:01", "192.168.1.20")


def test_row_layout_matches_netioapi():
    row = arp._MibIpnetRow2
    assert ctypes.sizeof(row) == 88
    offsets = {name: getattr(row, name).offset for name, _ in row._fields_}
    assert offsets == {
        "address": 0,
        "interface_index": 28,
        "interface_luid": 32,
        "physical_address": 40,
        "physical_address_length": 72,
        "state": 76,
        "flags": 80,
        "reachability_time": 84,
    }
    assert arp._MibIpnetTable2.table.offset == 8
    assert arp._SockaddrIn.addr.offset == 4


def make_row(ip, mac="ac:de:48:00:11:01", state=5, index=6, family=2, length=6):
    row = arp._MibIpnetRow2()
    row.address.ipv4.family = family
    row.address.ipv4.addr[:] = list(IPv4Address(ip).packed)
    row.physical_address[:6] = list(bytes.fromhex(mac.replace(":", "")))
    row.physical_address_length = length
    row.state = state
    row.interface_index = index
    return row


def fake_iphlpapi(monkeypatch, rows, status=0):
    class Table(ctypes.Structure):
        _fields_ = (("num_entries", ctypes.c_uint32), ("table", arp._MibIpnetRow2 * len(rows)))

    table = Table(len(rows), (arp._MibIpnetRow2 * len(rows))(*rows))
    freed = []

    def get_table(family, out):
        assert family == 2
        if status == 0:
            # `out` is byref(pointer); point it at our table like the API would.
            out._obj.contents = ctypes.cast(
                ctypes.pointer(table), ctypes.POINTER(arp._MibIpnetTable2)
            ).contents
        return status

    def free_table(pointer):
        freed.append(ctypes.addressof(pointer.contents))

    monkeypatch.setattr(arp, "_iphlpapi", lambda: (get_table, free_table))
    return ctypes.addressof(table), freed


def test_api_rows_become_neighbors(monkeypatch):
    rows = [
        make_row("192.168.1.1", state=5),  # Reachable
        make_row("192.168.1.2", state=6),  # Permanent
        make_row("192.168.1.3", state=4),  # Stale
        make_row("192.168.1.4", state=3),  # Delay
        make_row("192.168.1.5", state=2),  # Probe
        make_row("192.168.1.6", state=1),  # Incomplete
        make_row("192.168.1.7", state=0),  # Unreachable
        make_row("192.168.1.8", length=0),
        make_row("192.168.1.9", mac="00:00:00:00:00:00"),
        make_row("192.168.1.10", family=23),
        make_row("10.0.0.11", index=9),
        make_row("172.16.0.12", index=12),
    ]
    address, freed = fake_iphlpapi(monkeypatch, rows)
    monkeypatch.setattr(
        arp,
        "_interface_addresses",
        lambda: {6: [IPv4Interface("192.168.1.20/24")], 9: [IPv4Interface("10.0.0.2/24")]},
    )
    mac = "ac:de:48:00:11:01"
    assert arp._read_ipnet_table2() == [
        Neighbor("192.168.1.1", mac, "192.168.1.20", "reachable"),
        Neighbor("192.168.1.2", mac, "192.168.1.20", "reachable"),
        Neighbor("192.168.1.3", mac, "192.168.1.20", "stale"),
        Neighbor("192.168.1.4", mac, "192.168.1.20", "probing"),
        Neighbor("192.168.1.5", mac, "192.168.1.20", "probing"),
        Neighbor("10.0.0.11", mac, "10.0.0.2", "reachable"),
        Neighbor("172.16.0.12", mac, "12", "reachable"),
    ]
    assert freed == [address]


def test_api_with_an_empty_table(monkeypatch):
    fake_iphlpapi(monkeypatch, [], status=1168)  # ERROR_NOT_FOUND
    assert arp._read_ipnet_table2() == []


def test_api_error_is_raised_for_the_fallback(monkeypatch):
    fake_iphlpapi(monkeypatch, [], status=5)
    with pytest.raises(OSError):
        arp._read_ipnet_table2()


def test_interface_label_picks_the_matching_address():
    local = {
        6: [IPv4Interface("10.0.0.2/24"), IPv4Interface("192.168.1.20/24")],
        7: [IPv4Interface("172.16.0.1/16")],
    }
    assert arp._interface_label(6, "192.168.1.9", local) == "192.168.1.20"
    assert arp._interface_label(6, "172.31.0.9", local) == "10.0.0.2"
    assert arp._interface_label(8, "192.168.1.9", local) == "8"


@pytest.mark.skipif(sys.platform != "win32", reason="GetIpNetTable2 is Windows only")
def test_real_ipnet_table_reads_without_raising():
    found = arp._read_ipnet_table2()
    assert isinstance(found, list)
    assert all(isinstance(entry, Neighbor) for entry in found)
    assert isinstance(arp.neighbors(), list)
