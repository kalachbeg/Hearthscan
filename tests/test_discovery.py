import asyncio
from ipaddress import ip_address, ip_network

import pytest

from hearthscan import discovery
from hearthscan.discovery import arp, classify, mdns, netbios, oui, rdns, ssdp
from hearthscan.models import MdnsInfo, NetbiosInfo, UpnpInfo
from hearthscan.netinfo import Interface, NetworkInfo
from hearthscan.scope import ScopeError

ETH = Interface("eth0", "eth0", ip_address("192.168.1.50"), ip_network("192.168.1.0/24"))
INFO = NetworkInfo(ETH, "192.168.1.1")


@pytest.fixture
def lan(monkeypatch):
    """A small fake network. Tests tweak `calls` and the returned data."""
    calls = {}

    async def query(local, ips, **kw):
        calls["netbios"] = (local, list(ips))
        return {"192.168.1.10": NetbiosInfo(name="DESKTOP-7Q1", mac="00:1a:2b:00:00:10")}

    async def browse(local, **kw):
        calls["mdns"] = local
        return {"192.168.1.20": MdnsInfo(hostname="Kitchen.local", services={"_airplay._tcp"})}

    async def search(local, **kw):
        calls["search"] = kw
        return {"192.168.1.1": ["reply"]}

    async def describe(replies, **kw):
        calls["describe"] = replies
        return {"192.168.1.1": UpnpInfo(friendly_name="Home Router")}

    async def lookup(local, ips, servers, **kw):
        calls["dns"] = sorted(ips)
        return {"192.168.1.30": "android-4f2a.lan", "10.9.9.9": "elsewhere"}

    async def reverse_names(local, ips, **kw):
        calls["reverse"] = sorted(ips)
        return {"192.168.1.30": "Pixel.local"}

    def nameservers(gateway, **kw):
        calls["nameservers"] = (gateway, kw)
        return [gateway]

    neighbors = [
        arp.Neighbor("192.168.1.1", "a4:83:e7:00:00:01"),
        arp.Neighbor("192.168.1.20", "a4:83:e7:00:00:20"),
        arp.Neighbor("192.168.1.30", "da:a1:19:00:00:30"),
        arp.Neighbor("192.168.1.50", "a4:83:e7:00:00:50"),
    ]
    monkeypatch.setattr(netbios, "query", query)
    monkeypatch.setattr(mdns, "browse", browse)
    monkeypatch.setattr(mdns, "reverse_names", reverse_names)
    monkeypatch.setattr(ssdp, "search", search)
    monkeypatch.setattr(ssdp, "describe", describe)
    monkeypatch.setattr(rdns, "lookup", lookup)
    monkeypatch.setattr(rdns, "nameservers", nameservers)
    monkeypatch.setattr(arp, "neighbors", lambda: neighbors)
    monkeypatch.setattr(oui, "lookup", lambda mac: "Acme" if mac and mac[1] == "4" else None)
    return calls


def test_discover_merges_every_source(lan):
    stages = []
    devices = asyncio.run(discovery.discover(INFO, on_stage=stages.append))
    by_ip = {d.ip: d for d in devices}

    assert [d.ip for d in devices] == [
        "192.168.1.1",
        "192.168.1.10",
        "192.168.1.20",
        "192.168.1.30",
        "192.168.1.50",
    ]
    assert stages == ["sweep", "names", "done"]

    local, swept = lan["netbios"]
    assert local == "192.168.1.50"
    assert len(swept) == 253 and "192.168.1.50" not in swept

    router = by_ip["192.168.1.1"]
    assert router.is_gateway and router.kind == "router"
    assert router.upnp.friendly_name == "Home Router"
    assert router.vendor == "Acme"
    assert lan["describe"] == {"192.168.1.1": ["reply"]}
    assert lan["search"] == {"network": ETH.network}
    assert lan["nameservers"] == ("192.168.1.1", {"interface": "eth0"})

    pc = by_ip["192.168.1.10"]
    assert pc.mac == "00:1a:2b:00:00:10"  # learned from NetBIOS, not in the ARP table
    assert pc.seen_by == {"netbios"}

    phone = by_ip["192.168.1.30"]
    assert phone.dns_name == "android-4f2a.lan"
    assert phone.mdns.hostname == "Pixel.local"
    assert phone.random_mac

    me = by_ip["192.168.1.50"]
    assert me.is_self and me.mac is None
    assert me.kind == "computer"
    assert me.evidence.count("this computer") == 1

    # Devices that already have an mDNS host name are not asked again.
    assert "192.168.1.20" not in lan["reverse"]
    assert "192.168.1.50" not in lan["dns"]

    # Each of them answered something, or is us.
    assert all(d.confirmed for d in devices)


def test_a_failing_source_is_reported_and_skipped(lan, monkeypatch):
    async def broken(local, **kw):
        raise OSError(99, "no multicast here")

    monkeypatch.setattr(mdns, "browse", broken)
    notes = []
    devices = asyncio.run(discovery.discover(INFO, on_note=lambda *note: notes.append(note)))
    assert notes == [("mdns", "mdns did not run ([Errno 99] no multicast here)")]
    assert any(d.ip == "192.168.1.10" for d in devices)


def test_cancelling_discovery_leaves_nothing_running(lan, monkeypatch):
    async def forever(local, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(ssdp, "search", forever)

    async def main():
        task = asyncio.ensure_future(discovery.discover(INFO))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []


def test_devices_outside_the_network_are_ignored(lan, monkeypatch):
    async def browse(local, **kw):
        return {"10.1.1.1": MdnsInfo(hostname="far.local")}

    monkeypatch.setattr(mdns, "browse", browse)
    devices = asyncio.run(discovery.discover(INFO))
    assert all(ip_address(d.ip) in ETH.network for d in devices)


def test_classify_runs_on_every_device(lan, monkeypatch):
    seen = []
    monkeypatch.setattr(classify, "classify", lambda d: seen.append(d.ip))
    devices = asyncio.run(discovery.discover(INFO))
    assert sorted(seen) == sorted(d.ip for d in devices)


def test_public_networks_are_refused(lan):
    public = Interface("eth0", "eth0", ip_address("203.0.113.5"), ip_network("203.0.113.0/24"))
    with pytest.raises(ScopeError):
        asyncio.run(discovery.discover(NetworkInfo(public, "203.0.113.1")))


@pytest.fixture
def silent(lan, monkeypatch):
    """Nothing answers, so every device is a bare neighbor table entry."""

    async def nothing(*args, **kw):
        return {}

    for module, name in (
        (netbios, "query"),
        (mdns, "browse"),
        (mdns, "reverse_names"),
        (ssdp, "search"),
        (ssdp, "describe"),
        (rdns, "lookup"),
    ):
        monkeypatch.setattr(module, name, nothing)
    return lan


def read_tables(monkeypatch, *tables):
    """Each read of the neighbor table gets the next table; the last one repeats."""
    reads = []

    def neighbors():
        reads.append(len(reads))
        return tables[min(len(reads), len(tables)) - 1]

    monkeypatch.setattr(arp, "neighbors", neighbors)
    return reads


def entry(last_octet, state):
    return arp.Neighbor(
        f"192.168.1.{last_octet}", f"a4:83:e7:00:00:{last_octet:02x}", "eth0", state
    )


ROUTER = entry(1, "reachable")


def test_bare_entries_are_rechecked_after_the_names(silent, monkeypatch):
    reads = read_tables(
        monkeypatch,
        [entry(2, "stale"), entry(3, "probing"), entry(4, "reachable"), entry(5, "unknown")],
        [entry(3, "reachable"), entry(4, "reachable"), entry(5, "unknown")],
    )
    stages = []
    devices = asyncio.run(discovery.discover(INFO, on_stage=stages.append))
    by_ip = {d.ip: d for d in devices}

    assert "192.168.1.2" not in by_ip  # gone by the second read
    assert by_ip["192.168.1.3"].confirmed  # turned reachable
    assert by_ip["192.168.1.4"].confirmed
    assert not by_ip["192.168.1.5"].confirmed  # still there, but nothing vouches for it
    assert by_ip["192.168.1.50"].confirmed
    assert len(reads) == 2
    assert stages == ["sweep", "names", "done"]


def test_without_settle_unsettled_entries_stay_unconfirmed(silent, monkeypatch):
    reads = read_tables(monkeypatch, [ROUTER, entry(2, "stale"), entry(3, "probing")])
    devices = asyncio.run(discovery.discover(INFO))
    unconfirmed = [d.ip for d in devices if not d.confirmed]
    assert unconfirmed == ["192.168.1.2", "192.168.1.3"]
    assert len(reads) == 2


def test_no_recheck_when_everything_is_confirmed(lan, monkeypatch):
    reads = read_tables(monkeypatch, [entry(1, "reachable"), entry(20, "stale")])
    devices = asyncio.run(discovery.discover(INFO, settle=5))
    assert all(d.confirmed for d in devices)
    assert len(reads) == 1


def test_settle_reads_until_the_os_has_decided(silent, monkeypatch):
    monkeypatch.setattr(discovery, "SETTLE_INTERVAL", 0.01)
    reads = read_tables(
        monkeypatch,
        [ROUTER, entry(2, "stale"), entry(3, "probing")],
        [ROUTER, entry(2, "probing"), entry(3, "probing")],
        [ROUTER, entry(2, "probing"), entry(3, "reachable")],
        [ROUTER, entry(3, "reachable")],
    )
    stages = []
    devices = asyncio.run(discovery.discover(INFO, settle=30, on_stage=stages.append))

    assert [(d.ip, d.confirmed) for d in devices] == [
        ("192.168.1.1", True),
        ("192.168.1.3", True),
        ("192.168.1.50", True),
    ]
    assert len(reads) == 4
    assert stages == ["sweep", "names", "settle", "done"]


def test_settle_gives_up_at_its_deadline(silent, monkeypatch):
    monkeypatch.setattr(discovery, "SETTLE_INTERVAL", 0.01)
    reads = read_tables(monkeypatch, [ROUTER, entry(2, "probing")])

    async def timed():
        loop = asyncio.get_running_loop()
        start = loop.time()
        devices = await discovery.discover(INFO, settle=0.2)
        return devices, loop.time() - start

    devices, took = asyncio.run(timed())
    assert [(d.ip, d.confirmed) for d in devices] == [
        ("192.168.1.1", True),
        ("192.168.1.2", False),
        ("192.168.1.50", True),
    ]
    assert len(reads) > 3
    assert took < 2


def test_settle_does_not_wait_for_entries_without_a_state(silent, monkeypatch):
    # macOS says nothing about state, so there is nothing to wait for.
    monkeypatch.setattr(discovery, "SETTLE_INTERVAL", 5)
    reads = read_tables(monkeypatch, [ROUTER, entry(2, "unknown"), entry(3, "unknown")])
    devices = asyncio.run(discovery.discover(INFO, settle=30))
    assert [d.ip for d in devices if not d.confirmed] == ["192.168.1.2", "192.168.1.3"]
    assert len(reads) == 2


@pytest.mark.parametrize("settle", [-1, float("nan"), float("inf"), "5"])
def test_settle_must_be_a_sane_number(lan, settle):
    with pytest.raises(ValueError):
        asyncio.run(discovery.discover(INFO, settle=settle))


def test_descriptions_are_only_fetched_from_devices_on_the_network(lan, monkeypatch):
    async def search(local, **kw):
        return {
            "192.168.1.1": ["router"],
            "192.168.1.50": ["us"],
            "10.20.30.40": ["elsewhere"],
        }

    monkeypatch.setattr(ssdp, "search", search)
    asyncio.run(discovery.discover(INFO))
    assert lan["describe"] == {"192.168.1.1": ["router"]}


def notes_from(**kw):
    notes = []
    asyncio.run(discovery.discover(INFO, on_note=lambda *note: notes.append(note), **kw))
    return notes


def test_linux_firewall_note_when_multicast_gets_no_answers(silent, monkeypatch):
    monkeypatch.setattr(discovery, "IS_LINUX", True)
    notes = notes_from()
    assert [source for source, _ in notes] == ["firewall"]
    assert "ufw" in notes[0][1] and "3 are in the neighbor table" in notes[0][1]


def test_no_firewall_note_elsewhere_or_with_answers(silent, monkeypatch):
    monkeypatch.setattr(discovery, "IS_LINUX", False)
    assert notes_from() == []

    monkeypatch.setattr(discovery, "IS_LINUX", True)

    async def one_answer(local, **kw):
        return {"192.168.1.20": MdnsInfo(hostname="Kitchen.local")}

    monkeypatch.setattr(mdns, "browse", one_answer)
    assert notes_from() == []


def test_no_firewall_note_on_a_tiny_network(silent, monkeypatch):
    monkeypatch.setattr(discovery, "IS_LINUX", True)
    read_tables(monkeypatch, [ROUTER])
    assert notes_from() == []


def test_no_firewall_note_when_multicast_could_not_run(silent, monkeypatch):
    monkeypatch.setattr(discovery, "IS_LINUX", True)

    async def broken(local, **kw):
        raise OSError(101, "Network is unreachable")

    monkeypatch.setattr(mdns, "browse", broken)
    assert [source for source, _ in notes_from()] == ["mdns"]


@pytest.mark.parametrize("answering", ["192.168.1.50", "172.17.0.1"])
def test_answers_from_ourselves_or_other_networks_still_get_the_note(
    silent, monkeypatch, answering
):
    monkeypatch.setattr(discovery, "IS_LINUX", True)

    async def browse(local, **kw):
        return {answering: MdnsInfo(hostname="self.local")}

    monkeypatch.setattr(mdns, "browse", browse)
    assert [source for source, _ in notes_from()] == ["firewall"]


def test_an_empty_second_read_does_not_wipe_the_first(silent, monkeypatch):
    read_tables(monkeypatch, [ROUTER, entry(2, "stale"), entry(3, "unknown")], [])
    devices = asyncio.run(discovery.discover(INFO))
    assert {"192.168.1.2", "192.168.1.3"} <= {d.ip for d in devices}
