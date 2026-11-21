import json

from hearthscan.diff import Diff, compare, to_dict
from hearthscan.models import Device, Finding, ScanResult


def scan(devices=(), findings=(), score=100, network="192.168.1.0/24"):
    return ScanResult(
        version="2.0.0",
        started="2026-01-02T03:04:05+00:00",
        finished="2026-01-02T03:04:15+00:00",
        interface="Ethernet",
        address="192.168.1.50",
        network=network,
        gateway="192.168.1.1",
        devices=list(devices),
        findings=list(findings),
        score=score,
    )


def telnet(ip, port=23):
    return Finding("telnet-open", "high", ip, port, {"port": str(port)})


def forward(ip, external, internal=80, protocol="TCP", rule="port-forward"):
    params = {
        "external_port": str(external),
        "internal_port": str(internal),
        "protocol": protocol,
        "description": "",
    }
    return Finding(rule, "low", ip, internal, params)


ROUTER = Device("192.168.1.1", mac="a4:83:e7:00:00:01", kind="router", is_gateway=True)
CAMERA = Device("192.168.1.60", mac="00:11:22:33:44:55", kind="camera")
PHONE = Device("192.168.1.23", mac="da:a1:19:00:00:30", kind="phone")


def moved(device, ip):
    return Device(ip, mac=device.mac, kind=device.kind, is_gateway=device.is_gateway)


def ips(devices):
    return [d.ip for d in devices]


def test_the_same_scan_twice_changes_nothing():
    old = scan([ROUTER, CAMERA], [telnet("192.168.1.1")], score=85)
    new = scan([ROUTER, CAMERA], [telnet("192.168.1.1")], score=85)
    changes = compare(old, new)
    assert changes == Diff(score_before=85, score_after=85)
    assert changes.unchanged


def test_new_and_gone_devices():
    changes = compare(scan([ROUTER, CAMERA]), scan([ROUTER, PHONE]))
    assert ips(changes.new_devices) == ["192.168.1.23"]
    assert ips(changes.gone_devices) == ["192.168.1.60"]
    assert not changes.unchanged


def test_a_device_that_moved_keeps_its_findings():
    old = scan([ROUTER, CAMERA], [telnet("192.168.1.60")])
    new = scan([ROUTER, moved(CAMERA, "192.168.1.61")], [telnet("192.168.1.61")])
    changes = compare(old, new)
    assert changes.new_devices == changes.gone_devices == []
    assert changes.new_findings == changes.fixed_findings == []


def test_findings_fixed_and_new():
    old = scan([ROUTER, CAMERA], [telnet("192.168.1.1"), telnet("192.168.1.60")], score=70)
    rtsp = Finding("rtsp-no-auth", "high", "192.168.1.60", 554, {"port": "554"})
    new = scan([ROUTER, CAMERA], [telnet("192.168.1.60"), rtsp], score=80)
    changes = compare(old, new)
    assert changes.fixed_findings == [telnet("192.168.1.1")]
    assert changes.new_findings == [rtsp]
    assert (changes.score_before, changes.score_after) == (70, 80)


def test_a_new_finding_on_a_device_that_moved():
    old = scan([CAMERA], [telnet("192.168.1.60")])
    new = scan(
        [moved(CAMERA, "192.168.1.70")], [telnet("192.168.1.70"), telnet("192.168.1.70", 2323)]
    )
    changes = compare(old, new)
    assert changes.new_findings == [telnet("192.168.1.70", 2323)]
    assert changes.fixed_findings == []


def test_an_address_handed_to_another_device():
    other = Device("192.168.1.60", mac="66:77:88:99:aa:bb", kind="camera")
    old = scan([CAMERA], [telnet("192.168.1.60")])
    new = scan([other], [telnet("192.168.1.60")])
    changes = compare(old, new)
    assert [d.mac for d in changes.gone_devices] == [CAMERA.mac]
    assert [d.mac for d in changes.new_devices] == [other.mac]
    # Same rule, port and address, but on another device: one fixed, one new.
    assert changes.fixed_findings == [telnet("192.168.1.60")]
    assert changes.new_findings == [telnet("192.168.1.60")]


def test_without_macs_devices_match_by_address():
    old = scan([Device("192.168.1.5"), Device("192.168.1.6")], [telnet("192.168.1.5")])
    new = scan([Device("192.168.1.5"), Device("192.168.1.7")], [telnet("192.168.1.5")])
    changes = compare(old, new)
    assert ips(changes.gone_devices) == ["192.168.1.6"]
    assert ips(changes.new_devices) == ["192.168.1.7"]
    assert changes.new_findings == changes.fixed_findings == []


def test_a_mac_learned_later_still_matches_by_address():
    old = scan([Device("192.168.1.5")], [telnet("192.168.1.5")])
    new = scan([Device("192.168.1.5", mac="00:11:22:33:44:66")], [telnet("192.168.1.5")])
    changes = compare(old, new)
    assert changes.unchanged


def test_one_mac_behind_two_addresses():
    # A device on two addresses, or a router answering ARP for another.
    a, b = Device("192.168.1.5", mac=CAMERA.mac), Device("192.168.1.6", mac=CAMERA.mac)
    old = scan([a, b], [telnet("192.168.1.6")])
    new = scan([b, a], [telnet("192.168.1.6")])
    changes = compare(old, new)
    assert changes.unchanged
    later = compare(old, scan([Device("192.168.1.6", mac=CAMERA.mac)], [telnet("192.168.1.6")]))
    assert ips(later.gone_devices) == ["192.168.1.5"]
    assert later.new_findings == later.fixed_findings == []


def test_duplicate_addresses_do_not_crash():
    twins = [Device("192.168.1.5"), Device("192.168.1.5"), Device("192.168.1.5", mac=PHONE.mac)]
    old = scan(twins, [telnet("192.168.1.5"), telnet("192.168.1.5")])
    new = scan(twins[:1], [telnet("192.168.1.5")])
    changes = compare(old, new)
    assert len(changes.gone_devices) == 2
    assert changes.new_devices == []
    assert changes.fixed_findings == [telnet("192.168.1.5")]
    assert changes.new_findings == []
    compare(new, old)
    compare(scan(), old)
    compare(old, scan())


def test_findings_without_a_device_match_by_address():
    old = scan([], [telnet("192.168.1.9")])
    new = scan([], [telnet("192.168.1.9"), telnet("192.168.1.10")])
    changes = compare(old, new)
    assert changes.new_findings == [telnet("192.168.1.10")]
    assert changes.fixed_findings == []


def test_repeated_findings_are_counted():
    old = scan([ROUTER], [telnet("192.168.1.1")] * 3)
    new = scan([ROUTER], [telnet("192.168.1.1")])
    assert compare(old, new).fixed_findings == [telnet("192.168.1.1")] * 2
    assert compare(new, old).new_findings == [telnet("192.168.1.1")] * 2


def test_port_forwards_are_told_apart_by_their_internet_port():
    old = scan([CAMERA], [forward("192.168.1.60", 8080), forward("192.168.1.60", 8081)])
    new = scan([CAMERA], [forward("192.168.1.60", 8081), forward("192.168.1.60", 8082)])
    changes = compare(old, new)
    assert changes.fixed_findings == [forward("192.168.1.60", 8080)]
    assert changes.new_findings == [forward("192.168.1.60", 8082)]


def test_port_forwards_by_protocol_and_rule():
    tcp, udp = forward("192.168.1.60", 554, 554), forward("192.168.1.60", 554, 554, "UDP")
    risky = forward("192.168.1.60", 554, 554, rule="port-forward-risky")
    changes = compare(scan([CAMERA], [tcp, udp]), scan([CAMERA], [udp, risky]))
    assert changes.fixed_findings == [tcp]
    assert changes.new_findings == [risky]


def test_port_forwards_follow_a_device_that_moved():
    old = scan([CAMERA], [forward("192.168.1.60", 8080)])
    new = scan([moved(CAMERA, "192.168.1.61")], [forward("192.168.1.61", 8080)])
    assert compare(old, new).unchanged


def test_other_rules_ignore_their_params():
    old = scan([ROUTER], [Finding("ssh-open", "info", "192.168.1.1", 22, {"product": "a"})])
    new = scan([ROUTER], [Finding("ssh-open", "info", "192.168.1.1", 22, {"product": "b"})])
    assert compare(old, new).unchanged


def test_addresses_in_other_spellings_match():
    old = scan([Device("fe80::0001")], [telnet("fe80::0001")])
    new = scan([Device("fe80::1")], [telnet("FE80::1")])
    assert compare(old, new).unchanged


def test_macs_in_other_spellings_match():
    old = scan([Device("192.168.1.5", mac="00:11:22:33:44:55")])
    new = scan([Device("192.168.1.9", mac="00-11-22-33-44-55")])
    assert compare(old, new).unchanged


def test_a_changed_score_alone_is_a_change():
    changes = compare(scan(score=90), scan(score=88))
    assert not changes.unchanged
    assert changes.new_findings == changes.new_devices == []


def test_to_dict_is_plain_json():
    old = scan([ROUTER, CAMERA], [telnet("192.168.1.1")], score=85)
    new = scan([ROUTER, PHONE], [forward("192.168.1.23", 8080)], score=98)
    data = json.loads(json.dumps(to_dict(compare(old, new))))
    assert data["score_before"] == 85 and data["score_after"] == 98
    assert [d["ip"] for d in data["new_devices"]] == ["192.168.1.23"]
    assert [d["ip"] for d in data["gone_devices"]] == ["192.168.1.60"]
    assert data["new_devices"][0]["random_mac"] is True
    assert data["fixed_findings"] == [
        {
            "rule": "telnet-open",
            "severity": "high",
            "ip": "192.168.1.1",
            "port": 23,
            "params": {"port": "23"},
            "evidence": None,
        }
    ]
    assert data["new_findings"][0]["params"]["external_port"] == "8080"
