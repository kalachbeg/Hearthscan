import pytest

from hearthscan.models import (
    Device,
    MdnsInfo,
    NetbiosInfo,
    UpnpInfo,
    is_random_mac,
    is_unicast_mac,
    normalize_mac,
)


@pytest.mark.parametrize(
    "text, mac",
    [
        ("AA-BB-CC-0D-0E-0F", "aa:bb:cc:0d:0e:0f"),
        ("aa:bb:cc:d:e:f", "aa:bb:cc:0d:0e:0f"),
        ("0:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d:5e"),
        ("aabb.cc0d.0e0f", "aa:bb:cc:0d:0e:0f"),
        ("AABBCC0D0E0F", "aa:bb:cc:0d:0e:0f"),
        (" aa:bb:cc:dd:ee:ff\n", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_normalize_mac(text, mac):
    assert normalize_mac(text) == mac


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "00-00-00-00-00-00",
        "(incomplete)",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:fg",
        "aaa:b:c:d:e:f",
    ],
)
def test_normalize_mac_rejects(text):
    assert normalize_mac(text) is None


def test_mac_bits():
    assert is_unicast_mac("a4:83:e7:00:00:01")
    assert not is_unicast_mac("01:00:5e:00:00:fb")
    assert not is_unicast_mac("ff:ff:ff:ff:ff:ff")
    assert is_random_mac("da:a1:19:00:00:01")
    assert not is_random_mac("a4:83:e7:00:00:01")
    assert not is_random_mac(None)


def test_name_prefers_what_the_device_calls_itself():
    device = Device("192.168.1.20", dns_name="android-4f2a.lan")
    assert device.name == "android-4f2a"
    device.upnp = UpnpInfo(friendly_name="Living Room TV")
    assert device.name == "android-4f2a"
    device.netbios = NetbiosInfo(name="DESKTOP-7Q1")
    assert device.name == "DESKTOP-7Q1"
    device.mdns = MdnsInfo(hostname="Office-PC.local")
    assert device.name == "Office-PC"


def test_name_falls_back_to_service_instance():
    device = Device("192.168.1.21", mdns=MdnsInfo(instances={"_airplay._tcp": "Kitchen"}))
    assert device.name == "Kitchen"
    assert Device("192.168.1.22").name is None


@pytest.mark.parametrize(
    "dns_name, short",
    [
        ("DESKTOP-7Q1.fritz.box", "DESKTOP-7Q1"),
        ("nas.home.arpa", "nas"),
        ("printer.example.org", "printer.example.org"),
        (".lan", ".lan"),
    ],
)
def test_router_domains_are_dropped_from_dns_names(dns_name, short):
    assert Device("192.168.1.30", dns_name=dns_name).name == short


CAST_HOST = "3f2a6c1e-7b4d-4e8a-9c0f-1d2e3f4a5b6c.local"


def test_google_cast_name_comes_from_txt():
    device = Device(
        "192.168.1.40",
        dns_name="chromecast.lan",
        mdns=MdnsInfo(
            hostname=CAST_HOST,
            instances={"_googlecast._tcp": "Chromecast-3f2a6c1e7b4d4e8a9c0f1d2e3f4a5b6c"},
            txt={"_googlecast._tcp": {"fn": "Den TV", "md": "Chromecast"}},
        ),
    )
    assert device.name == "Den TV"


def test_blank_cast_name_is_ignored():
    mdns = MdnsInfo(hostname="Den-Speaker.local", txt={"_googlecast._tcp": {"fn": "  "}})
    assert Device("192.168.1.41", mdns=mdns).name == "Den-Speaker"


@pytest.mark.parametrize(
    "hostname",
    [
        CAST_HOST,
        "3F2A6C1E-7B4D-4E8A-9C0F-1D2E3F4A5B6C.local",
        "3f2a6c1e7b4d4e8a9c0f1d2e3f4a5b6c.local",
        "02a1b2c3d4e5.local",
    ],
)
def test_machine_made_mdns_host_names_are_skipped(hostname):
    device = Device("192.168.1.42", dns_name="den-tv.lan", mdns=MdnsInfo(hostname=hostname))
    assert device.name == "den-tv"
    device.netbios = NetbiosInfo(name="DEN-TV")
    assert device.name == "DEN-TV"


@pytest.mark.parametrize("hostname", ["Kitchen-a1b2c3.local", "cafe.local", "beef-cafe-01.local"])
def test_host_names_with_some_hex_are_kept(hostname):
    device = Device("192.168.1.43", dns_name="other.lan", mdns=MdnsInfo(hostname=hostname))
    assert device.name == hostname.removesuffix(".local")


def test_devices_start_unconfirmed():
    assert Device("192.168.1.44").confirmed is False
