import asyncio
import inspect

import pytest

from hearthscan.discovery import _udp, mdns
from hearthscan.discovery.dnswire import (
    AAAA,
    IN,
    PTR,
    SRV,
    TXT,
    A,
    Message,
    Record,
    build_message,
    build_query,
    parse_message,
    reverse_name,
)
from hearthscan.system import IS_WINDOWS

LOCAL = "192.168.1.10"
META = ("_services", "_dns-sd", "_udp", "local")
# Kept before any test swaps it out, so fakes can check their arguments against it.
EXCHANGE_SIGNATURE = inspect.signature(_udp.exchange)


def service_name(service):
    return (*service.split("."), "local")


def ptr(service, instance):
    return Record(service_name(service), PTR, IN, 4500, (instance, *service_name(service)))


def srv(service, instance, host, port):
    target = (host, "local")
    return Record((instance, *service_name(service)), SRV, 0x8001, 120, (0, 0, port, target))


def txt(service, instance, pairs):
    return Record((instance, *service_name(service)), TXT, 0x8001, 4500, pairs)


def a(host, address):
    return Record((host, "local"), A, 0x8001, 120, address)


def aaaa(host, address):
    return Record((host, "local"), AAAA, 0x8001, 120, address)


def meta(service):
    return Record(META, PTR, IN, 4500, service_name(service))


def reply(*answers, additionals=(), msg_id=0, flags=0x8400):
    """A response builder taking our query id. msg_id None echoes it, a callable derives one."""

    def build(query_id):
        if msg_id is None:
            real_id = query_id
        elif callable(msg_id):
            real_id = msg_id(query_id)
        else:
            real_id = msg_id
        message = Message(real_id, flags, answers=list(answers), additionals=list(additionals))
        return build_message(message)

    return build


class FakeExchange:
    """Stands in for _udp.exchange: one list of (reply, sender) per call."""

    def __init__(self, *rounds):
        self.rounds = list(rounds)
        self.calls = []

    async def __call__(self, packets, **kwargs):
        EXCHANGE_SIGNATURE.bind(packets, **kwargs)
        packets = list(packets)
        self.calls.append((packets, kwargs))
        query_id = parse_message(packets[0][0]).id
        script = self.rounds[len(self.calls) - 1] if len(self.calls) <= len(self.rounds) else []
        replies = []
        for payload, sender in script:
            data = payload(query_id) if callable(payload) else payload
            replies.append((data, sender))
            if kwargs.get("on_reply"):
                kwargs["on_reply"](data, sender)
        await asyncio.sleep(kwargs["listen"])
        return replies


def questions(packets):
    found = []
    for payload, _ in packets:
        found.extend(parse_message(payload).questions)
    return found


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(mdns, "SPACING", 0.0)
    monkeypatch.setattr(mdns, "LISTEN_ON_5353", False)
    monkeypatch.setattr(mdns, "UNICAST_SPACING", 0.0)


def browse_with(monkeypatch, fake, duration=0.2):
    monkeypatch.setattr(_udp, "exchange", fake)
    return asyncio.run(mdns.browse(LOCAL, duration=duration))


def test_browse(monkeypatch, fast):
    first = [
        (
            reply(
                ptr("_airplay._tcp", "Living Room"),
                additionals=[
                    srv("_airplay._tcp", "Living Room", "Living-Room", 7000),
                    txt("_airplay._tcp", "Living Room", {"model": "AppleTV5,3"}),
                    a("Living-Room", "192.168.1.20"),
                ],
                msg_id=None,
            ),
            "192.168.1.20",
        ),
        (
            reply(
                ptr("_companion-link._tcp", "Living Room"),
                additionals=[srv("_companion-link._tcp", "Living Room", "Living-Room", 49153)],
            ),
            "192.168.1.20",
        ),
        (reply(meta("_googlecast._tcp"), meta("_octoprint._tcp")), "192.168.1.30"),
        # A printer whose reply had no room for an address record. It gets
        # the service but not the name: the sender could be a proxy.
        (
            reply(
                ptr("_ipp._tcp", "Office.Printer"),
                additionals=[srv("_ipp._tcp", "Office.Printer", "printer-7q1", 631)],
            ),
            "192.168.1.40",
        ),
        (reply(ptr("_hap._tcp", "Hallway Sensor")), "192.168.1.50"),
        # A sleep proxy answering for a computer that is asleep.
        (
            reply(
                ptr("_smb._tcp", "DESKTOP-7Q1"),
                additionals=[
                    srv("_smb._tcp", "DESKTOP-7Q1", "DESKTOP-7Q1", 445),
                    a("DESKTOP-7Q1", "192.168.1.60"),
                ],
            ),
            "192.168.1.2",
        ),
        (b"\x12\x34garbage", "192.168.1.70"),
        (
            reply(
                ptr("_http._tcp", "Elsewhere"),
                additionals=[
                    srv("_http._tcp", "Elsewhere", "elsewhere", 80),
                    a("elsewhere", "192.168.1.80"),
                ],
            ),
            "203.0.113.9",
        ),
        (
            reply(
                ptr("_http._tcp", "Router Page"),
                additionals=[
                    srv("_http._tcp", "Router Page", "router-9z", 80),
                    a("router-9z", "198.51.100.7"),
                ],
            ),
            "192.168.1.90",
        ),
        (reply(ptr("_ssh._tcp", "Asking"), flags=0), "192.168.1.91"),
        # An id that is neither ours nor zero.
        (
            reply(ptr("_ssh._tcp", "Wrong Id"), msg_id=lambda ours: ours % 0xFFFF + 1),
            "192.168.1.92",
        ),
    ]
    second = [
        (
            reply(
                ptr("_octoprint._tcp", "Workshop 3D"),
                additionals=[
                    srv("_octoprint._tcp", "Workshop 3D", "octopi-3d", 80),
                    txt("_octoprint._tcp", "Workshop 3D", {"path": "/"}),
                    a("octopi-3d", "192.168.1.30"),
                ],
            ),
            "192.168.1.30",
        ),
        (
            reply(
                txt("_ipp._tcp", "Office.Printer", {"ty": "Office Printer 7", "rp": "ipp/print"})
            ),
            "192.168.1.40",
        ),
    ]
    fake = FakeExchange(first, second)
    found = browse_with(monkeypatch, fake)

    assert set(found) == {
        "192.168.1.20",
        "192.168.1.30",
        "192.168.1.40",
        "192.168.1.50",
        "192.168.1.60",
        "192.168.1.90",
    }
    tv = found["192.168.1.20"]
    assert tv.hostname == "Living-Room.local"
    assert tv.services == {"_airplay._tcp", "_companion-link._tcp"}
    assert tv.instances == {"_airplay._tcp": "Living Room", "_companion-link._tcp": "Living Room"}
    assert tv.txt == {"_airplay._tcp": {"model": "AppleTV5,3"}}

    octopi = found["192.168.1.30"]
    assert octopi.services == {"_googlecast._tcp", "_octoprint._tcp"}
    assert octopi.hostname == "octopi-3d.local"
    assert octopi.instances == {"_octoprint._tcp": "Workshop 3D"}

    printer = found["192.168.1.40"]
    assert printer.hostname is None
    assert printer.instances == {"_ipp._tcp": "Office.Printer"}
    assert printer.txt == {"_ipp._tcp": {"ty": "Office Printer 7", "rp": "ipp/print"}}

    assert found["192.168.1.50"].services == {"_hap._tcp"}
    assert found["192.168.1.50"].hostname is None
    assert found["192.168.1.60"].hostname == "DESKTOP-7Q1.local"
    assert found["192.168.1.60"].services == {"_smb._tcp"}
    assert found["192.168.1.90"].services == {"_http._tcp"}
    assert found["192.168.1.90"].hostname is None

    assert len(fake.calls) == 2
    for _, kwargs in fake.calls:
        assert kwargs["max_replies"] == 1024
        assert kwargs["per_sender"] == 32
        assert kwargs["join"] is None
    packets, kwargs = fake.calls[0]
    assert kwargs["multicast_ttl"] == 255
    assert kwargs["local"] == LOCAL
    assert {address for _, address in packets} == {mdns.MDNS_GROUP}
    ids = {parse_message(payload).id for payload, _ in packets}
    assert len(ids) == 1
    assert 0 not in ids
    assert all(len(parse_message(p).questions) <= mdns.QUESTIONS_PER_PACKET for p, _ in packets)
    asked = questions(packets)
    assert all(qtype == PTR for _, qtype in asked)
    assert sorted(name for name, _ in asked) == sorted(
        [META, *(service_name(s) for s in mdns.COMMON_SERVICES)]
    )

    packets, kwargs = fake.calls[1]
    assert kwargs["multicast_ttl"] == 255
    assert {parse_message(payload).id for payload, _ in packets} == ids
    follow_up = questions(packets)
    assert (("_octoprint", "_tcp", "local"), PTR) in follow_up
    assert (("_googlecast", "_tcp", "local"), PTR) not in follow_up
    assert (("Office.Printer", "_ipp", "_tcp", "local"), TXT) in follow_up
    assert (("Office.Printer", "_ipp", "_tcp", "local"), SRV) not in follow_up
    assert (("Hallway Sensor", "_hap", "_tcp", "local"), SRV) in follow_up
    assert (("Hallway Sensor", "_hap", "_tcp", "local"), TXT) in follow_up


def test_subtype_answers_and_hostile_text(monkeypatch, fast):
    subtype = Record(
        ("_universal", "_sub", "_ipp", "_tcp", "local"),
        PTR,
        IN,
        4500,
        ("Den\x1b[2J", "_ipp", "_tcp", "local"),
    )
    mismatched = Record(
        service_name("_ipp._tcp"), PTR, IN, 4500, ("Not A Printer", "_http", "_tcp", "local")
    )
    first = [
        (
            reply(
                subtype,
                mismatched,
                additionals=[txt("_ipp._tcp", "Den\x1b[2J", {"note": "a\x07b"})],
            ),
            "192.168.1.25",
        )
    ]
    found = browse_with(monkeypatch, FakeExchange(first))
    info = found["192.168.1.25"]
    assert info.services == {"_ipp._tcp"}
    assert info.instances == {"_ipp._tcp": "Den?[2J"}
    assert info.txt == {"_ipp._tcp": {"note": "a?b"}}


def test_services_proxied_for_ipv6_only_hosts_stay_off_the_sender(monkeypatch, fast):
    # A Thread border router answers for an accessory that has IPv6 addresses
    # only, then for itself.
    first = [
        (
            reply(
                ptr("_hap._udp", "Front Door Lock"),
                additionals=[
                    srv("_hap._udp", "Front Door Lock", "Front-Door-Lock", 5683),
                    txt("_hap._udp", "Front Door Lock", {"md": "Smart Lock X"}),
                    aaaa("Front-Door-Lock", "fd11:22::1"),
                ],
            ),
            "192.168.1.60",
        ),
        (
            reply(
                ptr("_meshcop._udp", "Home Hub"),
                additionals=[
                    srv("_meshcop._udp", "Home Hub", "homehub", 49154),
                    a("homehub", "192.168.1.60"),
                ],
            ),
            "192.168.1.60",
        ),
    ]
    found = browse_with(monkeypatch, FakeExchange(first))
    hub = found["192.168.1.60"]
    assert hub.hostname == "homehub.local"
    assert hub.services == {"_meshcop._udp"}
    assert hub.instances == {"_meshcop._udp": "Home Hub"}
    assert hub.txt == {}
    assert set(found) == {"192.168.1.60"}


def test_caps_on_hosts_and_services():
    findings = mdns._Findings(0)
    for i in range(300):
        packet = reply(ptr("_http._tcp", f"Box {i}"))(0)
        findings.add(packet, f"10.0.{i // 250}.{i % 250 + 1}")
    many_services = [meta(f"_svc{i}._tcp") for i in range(100)]
    many_instances = [ptr(f"_kind{i}._tcp", "Busy") for i in range(100)]
    findings.add(reply(*many_services, *many_instances)(0), "10.0.9.9")
    found = findings.results()
    assert len(found) == mdns.MAX_HOSTS
    findings = mdns._Findings(0)
    findings.add(reply(*many_services, *many_instances)(0), "10.0.9.9")
    busy = findings.results()["10.0.9.9"]
    assert len(busy.services) == mdns.MAX_SERVICES_PER_HOST
    assert len(busy.instances) <= mdns.MAX_SERVICES_PER_HOST


def test_reading_stops_when_the_record_budget_is_spent(monkeypatch):
    monkeypatch.setattr(mdns, "RECORD_BUDGET", 10)
    monkeypatch.setattr(mdns, "SENDER_SHARE", 1)
    findings = mdns._Findings(0)
    # Somebody else's query, heard on port 5353, is skipped without costing anything.
    findings.add(build_query([(service_name("_hap._tcp"), PTR)]), "192.168.1.9")
    for i in range(5):
        records = (ptr("_hap._tcp", f"Sensor {i}"), meta("_hap._tcp"), meta("_hap._udp"))
        findings.add(reply(*records)(0), f"192.168.1.{i + 20}")
    assert set(findings.results()) == {f"192.168.1.{i + 20}" for i in range(3)}


def test_one_sender_cannot_spend_the_whole_budget():
    findings = mdns._Findings(0)
    # Bare headers that claim 65535 answers each, all from one host.
    bogus = bytes(2) + (0x8400).to_bytes(2, "big") + bytes(4) + b"\xff\xff" * 2
    for _ in range(64):
        findings.add(bogus, "192.168.1.66")
    for _ in range(200):
        findings.add(reply(*(meta(f"_s{i}._tcp") for i in range(30)))(0), "192.168.1.67")
    findings.add(reply(ptr("_ipp._tcp", "Office"), meta("_ipp._tcp"))(0), "192.168.1.70")
    assert "192.168.1.70" in findings.results()


def test_browse_cancels_cleanly(monkeypatch, fast):
    started, closed = [], []

    async def stuck(packets, **kwargs):
        started.append(kwargs)
        try:
            await asyncio.sleep(3600)
        finally:
            closed.append(kwargs)

    async def main():
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(mdns.browse(LOCAL, duration=0.1), 0.3)
        return asyncio.all_tasks() - {asyncio.current_task()}

    async def stuck_with_replies(packets, **kwargs):
        # Round two needs something to ask about, so hand over one instance.
        kwargs["on_reply"](reply(ptr("_hap._tcp", "Hallway Sensor"))(0), "192.168.1.50")
        await stuck(packets, **kwargs)

    calls = iter([stuck_with_replies, stuck])

    async def dispatch(packets, **kwargs):
        await next(calls)(packets, **kwargs)

    monkeypatch.setattr(_udp, "exchange", dispatch)
    leftover = asyncio.run(main())
    assert leftover == set()
    assert len(started) == 2
    assert len(closed) == 2


def test_browse_passes_socket_errors_on(monkeypatch, fast):
    async def broken(packets, **kwargs):
        raise OSError("cannot bind")

    monkeypatch.setattr(_udp, "exchange", broken)
    with pytest.raises(OSError):
        asyncio.run(mdns.browse(LOCAL, duration=0.1))


def test_each_reply_is_parsed_once(monkeypatch, fast):
    parsed = []
    real_parse = mdns.parse_message

    def counting_parse(data):
        parsed.append(data)
        return real_parse(data)

    monkeypatch.setattr(mdns, "parse_message", counting_parse)
    first = [
        (reply(ptr("_hap._tcp", "Hallway Sensor")), "192.168.1.50"),
        (reply(ptr("_ipp._tcp", "Office")), "192.168.1.40"),
    ]
    second = [(reply(txt("_hap._tcp", "Hallway Sensor", {"md": "Sensor 2"})), "192.168.1.50")]
    found = browse_with(monkeypatch, FakeExchange(first, second))
    assert len(parsed) == 3
    assert found["192.168.1.50"].txt == {"_hap._tcp": {"md": "Sensor 2"}}


def test_round_two_failing_keeps_what_round_one_found(monkeypatch, fast):
    fake = FakeExchange([(reply(ptr("_hap._tcp", "Hallway Sensor")), "192.168.1.50")])
    calls = []

    async def dispatch(packets, **kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            raise OSError("network is unreachable")
        return await fake(packets, **kwargs)

    monkeypatch.setattr(_udp, "exchange", dispatch)
    found = asyncio.run(mdns.browse(LOCAL, duration=0.2))
    assert len(calls) == 2
    assert found["192.168.1.50"].services == {"_hap._tcp"}


def test_port_5353_is_shared_everywhere_but_windows():
    assert mdns.LISTEN_ON_5353 is not IS_WINDOWS


def shared_port_dispatch(monkeypatch, legacy, shared):
    async def dispatch(packets, **kwargs):
        if kwargs.get("join"):
            if isinstance(shared, Exception):
                raise shared
            return await shared(packets, **kwargs)
        return await legacy(packets, **kwargs)

    monkeypatch.setattr(mdns, "LISTEN_ON_5353", True)
    monkeypatch.setattr(_udp, "exchange", dispatch)


def test_browse_also_asks_from_port_5353(monkeypatch, fast):
    # Nothing comes back to the ephemeral port, as behind a Linux host firewall.
    legacy = FakeExchange([])
    shared = FakeExchange(
        [
            (
                reply(
                    ptr("_ipp._tcp", "Office"),
                    additionals=[
                        srv("_ipp._tcp", "Office", "printer-7q1", 631),
                        a("printer-7q1", "192.168.1.40"),
                    ],
                ),
                "192.168.1.40",
            )
        ]
    )
    shared_port_dispatch(monkeypatch, legacy, shared)
    found = asyncio.run(mdns.browse(LOCAL, duration=0.2))
    assert found["192.168.1.40"].hostname == "printer-7q1.local"
    assert found["192.168.1.40"].services == {"_ipp._tcp"}

    ((packets, kwargs),) = shared.calls
    assert kwargs["join"] == mdns.MDNS_GROUP
    assert kwargs["local"] == LOCAL
    assert kwargs["multicast_ttl"] == 255
    assert kwargs["max_replies"] == 1024
    assert kwargs["per_sender"] == 32
    assert {address for _, address in packets} == {mdns.MDNS_GROUP}
    # Standard queries: id 0, no QU bit, the same questions as the first round.
    for payload, _ in packets:
        assert payload == build_query(parse_message(payload).questions)
    assert questions(packets) == questions(legacy.calls[0][0])


def test_browse_carries_on_when_port_5353_cannot_be_shared(monkeypatch, fast):
    legacy = FakeExchange([(reply(ptr("_hap._tcp", "Hallway Sensor")), "192.168.1.50")])
    shared_port_dispatch(monkeypatch, legacy, OSError("address in use"))
    found = asyncio.run(mdns.browse(LOCAL, duration=0.2))
    assert found["192.168.1.50"].services == {"_hap._tcp"}


def test_reverse_names(monkeypatch, fast):
    def answer(ip, host):
        return Record(reverse_name(ip), PTR, IN, 120, (host, "local"))

    script = [
        (reply(answer("192.168.1.20", "Living-Room"), msg_id=None), "192.168.1.20"),
        (reply(answer("192.168.1.31", "Someone-Else")), "192.168.1.30"),
        (reply(answer("192.168.1.99", "Not-Asked")), "192.168.1.99"),
        (b"\xff" * 20, "192.168.1.40"),
        (reply(answer("192.168.1.40", "Impostor")), "192.168.1.41"),
        (reply(answer("192.168.1.41", "DESKTOP-7Q1")), "192.168.1.41"),
        (reply(answer("192.168.1.41", "Second-Answer")), "192.168.1.41"),
    ]
    fake = FakeExchange(script)
    monkeypatch.setattr(_udp, "exchange", fake)
    ips = ["192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.41", "192.168.1.20"]
    ips += ["203.0.113.5", "fe80::1", "not an address", "127.0.0.1"]
    names = asyncio.run(mdns.reverse_names(LOCAL, ips, duration=0.01))
    assert names == {"192.168.1.20": "Living-Room.local", "192.168.1.41": "DESKTOP-7Q1.local"}

    ((packets, kwargs),) = fake.calls
    assert kwargs.get("multicast_ttl") is None
    assert kwargs["max_replies"] == 1024
    assert kwargs["per_sender"] == 32
    assert [address for _, address in packets] == [
        ("192.168.1.20", 5353),
        ("192.168.1.30", 5353),
        ("192.168.1.40", 5353),
        ("192.168.1.41", 5353),
    ]
    for payload, (ip, _) in packets:
        assert parse_message(payload).questions == [(reverse_name(ip), PTR)]


def test_reverse_names_stop_reading_when_the_budget_is_spent(monkeypatch, fast):
    monkeypatch.setattr(mdns, "RECORD_BUDGET", 5)
    monkeypatch.setattr(mdns, "SENDER_SHARE", 1)
    ips = [f"192.168.1.{i}" for i in range(20, 26)]
    script = [
        (reply(Record(reverse_name(ip), PTR, IN, 120, (f"host-{ip[-2:]}", "local"))), ip)
        for ip in ips
    ]
    monkeypatch.setattr(_udp, "exchange", FakeExchange(script))
    names = asyncio.run(mdns.reverse_names(LOCAL, ips, duration=0.01))
    assert list(names) == ips[:5]


def test_reverse_names_without_usable_addresses(monkeypatch):
    fake = FakeExchange()
    monkeypatch.setattr(_udp, "exchange", fake)
    assert asyncio.run(mdns.reverse_names(LOCAL, ["8.8.8.8", "::1"])) == {}
    assert fake.calls == []
