import pytest

from hearthscan.discovery import classify as classify_module
from hearthscan.discovery import oui
from hearthscan.discovery.classify import MAX_EVIDENCE, MAX_MODEL, classify
from hearthscan.models import KINDS, Device, MdnsInfo, NetbiosInfo, Service, UpnpInfo

RANDOM_MAC = "da:a1:19:00:00:01"
FIXED_MAC = "00:11:22:00:00:01"

IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
RENDERER = "urn:schemas-upnp-org:device:MediaRenderer:1"
MEDIA_SERVER = "urn:schemas-upnp-org:device:MediaServer:1"
ZONE_PLAYER = "urn:schemas-upnp-org:device:ZonePlayer:1"
DIAL = "urn:dial-multiscreen-org:device:dial:1"


def ports(*numbers):
    return [Service(port) for port in numbers]


def classified(device):
    classify(device)
    return device


def test_gateway_is_a_router():
    device = classified(
        Device(
            "192.168.1.1",
            mac=FIXED_MAC,
            is_gateway=True,
            upnp=UpnpInfo(device_types={IGD}, model_name="Home Router", model_number="X1"),
        )
    )
    assert device.kind == "router"
    assert device.evidence[:2] == ["default gateway", "UPnP InternetGatewayDevice"]
    assert device.model == "Home Router X1"


def test_gateway_wins_even_when_it_looks_like_something_else():
    device = classified(
        Device(
            "192.168.1.1",
            vendor="Synology",
            is_gateway=True,
            services=ports(5000, 445, 135),
            upnp=UpnpInfo(device_types={MEDIA_SERVER}),
        )
    )
    assert device.kind == "router"
    assert device.evidence == ["default gateway"]


def test_internet_gateway_device_alone_is_a_router():
    device = classified(Device("192.168.1.2", upnp=UpnpInfo(device_types={IGD})))
    assert device.kind == "router"
    assert device.evidence == ["UPnP InternetGatewayDevice"]


def test_windows_pc_from_netbios_and_smb_ports():
    device = classified(
        Device(
            "192.168.1.20",
            netbios=NetbiosInfo(name="DESKTOP-7Q1", workgroup="WORKGROUP", file_server=True),
            services=ports(135, 445),
        )
    )
    assert device.kind == "computer"
    assert "ports 445 and 135 open" in device.evidence
    assert "name looks like a Windows PC" in device.evidence
    assert "NetBIOS file server" in device.evidence


def test_remote_desktop_port_means_a_computer():
    device = classified(Device("192.168.1.21", services=ports(3389)))
    assert device.kind == "computer"
    assert device.evidence == ["port 3389 open"]


def test_iphone_from_random_mac_and_name():
    device = classified(Device("192.168.1.30", mac=RANDOM_MAC, dns_name="iPhone-7.lan"))
    assert device.kind == "phone"
    assert device.evidence == ["name looks like an iPhone", "randomized MAC"]
    assert device.model is None


def test_random_mac_alone_points_weakly_at_a_phone():
    device = classified(Device("192.168.1.31", mac=RANDOM_MAC))
    assert device.kind == "phone"
    assert device.evidence == ["randomized MAC"]


def test_random_mac_does_not_outweigh_a_real_clue():
    device = classified(Device("192.168.1.32", mac=RANDOM_MAC, dns_name="LAPTOP-AB12.fritz.box"))
    assert device.kind == "computer"
    assert device.evidence == ["name looks like a Windows PC"]


def test_ipad_with_apple_sync_port_is_a_tablet():
    device = classified(
        Device("192.168.1.33", mac=RANDOM_MAC, dns_name="Kitchen-iPad", services=ports(62078))
    )
    assert device.kind == "tablet"


def test_apple_sync_port_alone_means_a_phone():
    device = classified(Device("192.168.1.34", services=ports(62078)))
    assert device.kind == "phone"
    assert device.evidence == ["port 62078 open"]


def test_apple_tv_from_airplay_model():
    device = classified(
        Device(
            "192.168.1.40",
            vendor="Apple",
            mdns=MdnsInfo(
                hostname="Living-Room.local",
                services={"_airplay._tcp", "_raop._tcp"},
                txt={"_airplay._tcp": {"model": "AppleTV11,1"}},
            ),
        )
    )
    assert device.kind == "media"
    assert device.model == "Apple TV 4K (2nd generation)"
    assert device.evidence[0] == "model AppleTV11,1"


def test_homepod_mini_from_raop_model():
    device = classified(
        Device(
            "192.168.1.41",
            mdns=MdnsInfo(
                services={"_airplay._tcp", "_raop._tcp"},
                txt={"_raop._tcp": {"am": "AudioAccessory5,1"}},
            ),
        )
    )
    assert device.kind == "speaker"
    assert device.model == "HomePod mini"
    assert device.evidence == ["model AudioAccessory5,1", "mDNS _raop._tcp"]


def test_mac_from_device_info():
    device = classified(
        Device(
            "192.168.1.42",
            mdns=MdnsInfo(
                services={"_device-info._tcp", "_smb._tcp"},
                txt={"_device-info._tcp": {"model": "MacBookPro18,3", "osxvers": "24"}},
            ),
        )
    )
    assert device.kind == "computer"
    assert device.model == "MacBook Pro (14-inch, 2021)"


@pytest.mark.parametrize(
    "identifier, model, kind",
    [
        ("AppleTV11,1", "Apple TV 4K (2nd generation)", "media"),
        ("AppleTV99,1", "Apple TV", "media"),
        ("AudioAccessory5,1", "HomePod mini", "speaker"),
        ("AudioAccessory1,1", "HomePod", "speaker"),
        ("AudioAccessory6,1", "HomePod (2nd generation)", "speaker"),
        ("iPhone15,2", "iPhone 14 Pro", "phone"),
        ("iPhone16,1", "iPhone 15 Pro", "phone"),
        ("iPhone99,1", "iPhone", "phone"),
        ("iPad13,4", "iPad Pro 11-inch (3rd generation)", "tablet"),
        ("iPad99,1", "iPad", "tablet"),
        ("MacBookPro18,3", "MacBook Pro (14-inch, 2021)", "computer"),
        ("MacBookAir10,1", "MacBook Air (M1, 2020)", "computer"),
        ("MacBook10,1", "MacBook", "computer"),
        ("iMac21,1", "iMac (24-inch, M1, 2021)", "computer"),
        ("iMacPro1,1", "iMac Pro", "computer"),
        ("Macmini9,1", "Mac mini (M1, 2020)", "computer"),
        ("MacPro7,1", "Mac Pro", "computer"),
        ("Mac14,2", "MacBook Air (M2, 2022)", "computer"),
        ("Mac16,10", "Mac mini (2024)", "computer"),
        ("Mac99,1", "Mac", "computer"),
    ],
)
def test_apple_identifiers(identifier, model, kind):
    device = classified(
        Device("192.168.1.43", mdns=MdnsInfo(txt={"_device-info._tcp": {"model": identifier}}))
    )
    assert device.model == model
    assert device.kind == kind


def test_unknown_identifier_is_kept_as_written():
    device = classified(
        Device("192.168.1.44", mdns=MdnsInfo(txt={"_device-info._tcp": {"model": "Gadget3,1"}}))
    )
    assert device.model == "Gadget3,1"
    assert device.kind == "unknown"


def test_samba_placeholder_model_is_ignored():
    device = classified(
        Device(
            "192.168.1.45",
            vendor="Synology",
            services=ports(5000, 445),
            mdns=MdnsInfo(txt={"_device-info._tcp": {"model": "Xserve"}}),
            upnp=UpnpInfo(model_name="DS920+", model_number="DS920+"),
        )
    )
    assert device.kind == "nas"
    assert device.model == "DS920+"


def test_chromecast():
    device = classified(
        Device(
            "192.168.1.50",
            mdns=MdnsInfo(
                services={"_googlecast._tcp"},
                txt={"_googlecast._tcp": {"md": "Chromecast", "fn": "Living Room"}},
            ),
            services=ports(8008, 8009),
            upnp=UpnpInfo(device_types={DIAL}),
        )
    )
    assert device.kind == "media"
    assert device.model == "Chromecast"
    assert device.evidence[0] == "model Chromecast"


def test_google_speaker_is_not_a_streaming_stick():
    device = classified(
        Device(
            "192.168.1.51",
            mdns=MdnsInfo(
                services={"_googlecast._tcp"},
                txt={"_googlecast._tcp": {"md": "Google Nest Mini", "fn": "Kitchen"}},
            ),
            services=ports(8009),
            upnp=UpnpInfo(device_types={DIAL}),
        )
    )
    assert device.kind == "speaker"
    assert device.model == "Google Nest Mini"


def test_tv_with_cast_built_in():
    device = classified(
        Device(
            "192.168.1.52",
            vendor="Sony",
            mdns=MdnsInfo(
                services={"_googlecast._tcp", "_androidtvremote2._tcp"},
                txt={"_googlecast._tcp": {"md": "BRAVIA 4K VH2", "fn": "Bedroom"}},
            ),
            services=ports(8009),
        )
    )
    assert device.kind == "tv"
    assert device.model == "BRAVIA 4K VH2"


def test_brother_printer_from_ipp():
    device = classified(
        Device(
            "192.168.1.60",
            vendor="Brother",
            mdns=MdnsInfo(
                hostname="BRN0011220A0B0C.local",
                services={"_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"},
                txt={
                    "_ipp._tcp": {"ty": "Brother HL-L2350DW series", "usb_MDL": "HL-L2350DW"},
                },
            ),
            services=ports(80, 631, 9100),
        )
    )
    assert device.kind == "printer"
    assert device.model == "Brother HL-L2350DW series"
    assert device.evidence == [
        "mDNS _ipp._tcp",
        "port 9100 open",
        "name looks like a printer",
        "vendor Brother",
    ]


def test_printer_model_falls_back_to_usb_model_and_keys_ignore_case():
    device = classified(
        Device(
            "192.168.1.61",
            mdns=MdnsInfo(
                services={"_universal._sub._ipp._tcp.local."},
                txt={"_ipp._tcp.local": {"USB_MDL": "HL-L2350DW"}},
            ),
        )
    )
    assert device.kind == "printer"
    assert device.model == "HL-L2350DW"
    assert device.evidence == ["mDNS _ipp._tcp"]


def test_mac_sharing_a_printer_stays_a_computer():
    device = classified(
        Device(
            "192.168.1.62",
            mdns=MdnsInfo(
                hostname="Studio.local",
                services={"_device-info._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp"},
                instances={"_ipp._tcp": "HP LaserJet Pro M404 @ Studio"},
                txt={
                    "_device-info._tcp": {"model": "Mac14,2"},
                    "_ipp._tcp": {"ty": "HP LaserJet Pro M404"},
                },
            ),
            services=ports(631),
        )
    )
    assert device.kind == "computer"
    assert device.model == "MacBook Air (M2, 2022)"


def test_hikvision_camera_from_vendor_and_rtsp():
    device = classified(Device("192.168.1.70", vendor="Hikvision", services=ports(80, 554, 8000)))
    assert device.kind == "camera"
    assert device.evidence == ["port 554 open", "vendor Hikvision"]


def test_camera_vendor_with_only_a_web_port():
    device = classified(Device("192.168.1.71", vendor="Dahua", services=ports(80)))
    assert device.kind == "camera"
    assert device.evidence == ["vendor Dahua", "port 80 open"]


def test_generic_hints_do_not_beat_specific_ones():
    device = classified(
        Device(
            "192.168.1.72",
            vendor="Reolink",
            services=ports(22, 80, 554),
            upnp=UpnpInfo(server="Linux/4.9 UPnP/1.0 Cam/1.0"),
            dns_name="linux-box",
        )
    )
    assert device.kind == "camera"


def test_synology_nas():
    device = classified(
        Device(
            "192.168.1.80",
            vendor="Synology",
            netbios=NetbiosInfo(name="DISKSTATION", file_server=True),
            services=ports(139, 445, 5000, 5001),
            mdns=MdnsInfo(services={"_smb._tcp", "_adisk._tcp"}),
        )
    )
    assert device.kind == "nas"
    assert device.evidence[0] == "port 5000 open"
    assert "vendor Synology" in device.evidence


def test_sonos_speaker():
    device = classified(
        Device(
            "192.168.1.90",
            vendor="Sonos",
            upnp=UpnpInfo(
                device_types={ZONE_PLAYER, RENDERER, MEDIA_SERVER},
                manufacturer="Sonos, Inc.",
                model_name="Sonos One",
                model_number="S18",
            ),
            mdns=MdnsInfo(services={"_sonos._tcp", "_spotify-connect._tcp", "_airplay._tcp"}),
        )
    )
    assert device.kind == "speaker"
    assert device.model == "Sonos One S18"
    assert device.evidence[:2] == ["model Sonos One S18", "UPnP ZonePlayer"]


def test_espressif_smart_plug():
    device = classified(Device("192.168.1.100", vendor="Espressif", services=ports(80)))
    assert device.kind == "smart-home"
    assert device.evidence == ["vendor Espressif"]


def test_homekit_accessory():
    device = classified(
        Device(
            "192.168.1.101",
            mdns=MdnsInfo(
                services={"_hap._tcp"}, txt={"_hap._tcp": {"md": "Plug Mini", "ci": "7"}}
            ),
        )
    )
    assert device.kind == "smart-home"
    assert device.model == "Plug Mini"


def test_homekit_camera_category():
    device = classified(
        Device(
            "192.168.1.102",
            mdns=MdnsInfo(services={"_hap._tcp"}, txt={"_hap._tcp": {"ci": "17"}}),
        )
    )
    assert device.kind == "camera"
    assert device.evidence == ["HomeKit camera"]


def test_playstation():
    device = classified(
        Device(
            "192.168.1.110",
            vendor="Sony Interactive",
            dns_name="PS5-1A2B3C.lan",
            upnp=UpnpInfo(device_types={DIAL}),
        )
    )
    assert device.kind == "console"
    assert device.evidence[:2] == ["vendor Sony Interactive", "name looks like a PlayStation"]


def test_playstation_by_upnp_manufacturer():
    device = classified(
        Device(
            "192.168.1.114",
            upnp=UpnpInfo(device_types={DIAL}, manufacturer="Sony Computer Entertainment Inc."),
        )
    )
    assert device.kind == "console"
    assert device.evidence[0] == "UPnP manufacturer Sony Computer Entertainment Inc."


def test_microsoft_needs_an_xbox_hint():
    assert classified(Device("192.168.1.111", vendor="Microsoft")).kind == "unknown"
    device = classified(
        Device(
            "192.168.1.112",
            vendor="Microsoft",
            upnp=UpnpInfo(friendly_name="Xbox-Den"),
        )
    )
    assert device.kind == "console"
    assert device.evidence == ["vendor Microsoft", "name looks like an Xbox"]


def test_nintendo_by_vendor():
    device = classified(Device("192.168.1.113", vendor="Nintendo", mac=FIXED_MAC))
    assert device.kind == "console"


def test_samsung_tv_from_upnp_renderer_and_vendor():
    device = classified(
        Device(
            "192.168.1.120",
            vendor="Samsung",
            upnp=UpnpInfo(
                device_types={RENDERER},
                friendly_name="[TV] Living-Room",
                manufacturer="Samsung Electronics",
                model_name="UE55TU8000",
            ),
        )
    )
    assert device.kind == "tv"
    assert device.model == "UE55TU8000"
    assert device.evidence[0] == "vendor Samsung"
    assert "UPnP MediaRenderer" in device.evidence


def test_samsung_alone_is_not_a_tv():
    assert classified(Device("192.168.1.121", vendor="Samsung")).kind == "unknown"


def test_samsung_with_an_android_hostname_is_a_phone():
    device = classified(
        Device("192.168.1.122", vendor="Samsung", mac=RANDOM_MAC, dns_name="android-4f2a1c.lan")
    )
    assert device.kind == "phone"
    assert device.evidence == ["name looks like an Android phone", "randomized MAC"]


def test_roku_player_and_roku_tv():
    player = classified(
        Device(
            "192.168.1.123",
            vendor="Roku",
            upnp=UpnpInfo(device_types={DIAL}, model_name="Roku Ultra", model_number="4800X"),
        )
    )
    assert player.kind == "media"
    assert player.model == "Roku Ultra 4800X"
    tv = classified(
        Device(
            "192.168.1.124",
            vendor="Roku",
            upnp=UpnpInfo(device_types={DIAL}, model_name="Roku TV", model_number="7000X"),
        )
    )
    assert tv.kind == "tv"


def test_amazon_echo_from_its_dhcp_name():
    device = classified(Device("192.168.1.125", vendor="Amazon", dns_name="amazon-1a2b3c4d5.lan"))
    assert device.kind == "speaker"
    assert device.evidence == ["name looks like an Amazon device"]


def test_amazon_alone_is_not_a_streaming_stick():
    assert classified(Device("192.168.1.126", vendor="Amazon")).kind == "unknown"


def test_fire_tv_with_dial_beats_the_echo_name():
    device = classified(
        Device(
            "192.168.1.127",
            vendor="Amazon",
            dns_name="amazon-5e6f7a8b9.lan",
            upnp=UpnpInfo(device_types={DIAL}),
        )
    )
    assert device.kind == "media"
    assert device.evidence == ["vendor Amazon", "UPnP dial"]


def test_fire_tv_from_amazon_whisperplay():
    device = classified(
        Device("192.168.1.128", vendor="Amazon", mdns=MdnsInfo(services={"_amzn-wplay._tcp"}))
    )
    assert device.kind == "media"
    assert device.evidence == ["mDNS _amzn-wplay._tcp", "vendor Amazon"]


def test_raspberry_pi():
    device = classified(
        Device(
            "192.168.1.130",
            vendor="Raspberry Pi Trading Ltd",
            dns_name="raspberrypi.lan",
            services=ports(22),
        )
    )
    assert device.kind == "computer"
    assert device.evidence[:2] == [
        "name looks like a Raspberry Pi",
        "vendor Raspberry Pi Trading Ltd",
    ]


def test_this_computer():
    device = classified(Device("192.168.1.131", is_self=True))
    assert device.kind == "computer"
    assert device.evidence == ["this computer"]


def test_empty_device_is_unknown():
    device = classified(Device("192.168.1.140"))
    assert device.kind == "unknown"
    assert device.evidence == []
    assert device.model is None


def test_ties_follow_a_fixed_order():
    # DIAL counts the same for TVs and streaming sticks.
    device = classified(Device("192.168.1.141", upnp=UpnpInfo(device_types={DIAL})))
    assert device.kind == "tv"


def test_classify_is_deterministic_and_repeatable():
    def build(order):
        services = set()
        for name in order:
            services.add(name)
        return Device(
            "192.168.1.150",
            vendor="Brother",
            mdns=MdnsInfo(services=services),
            services=ports(9100, 631, 515),
        )

    names = ["_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"]
    first = classified(build(names))
    second = classified(build(list(reversed(names))))
    assert (first.kind, first.model, first.evidence) == (
        second.kind,
        second.model,
        second.evidence,
    )
    classify(first)
    assert first.evidence == second.evidence


def test_evidence_is_capped():
    device = classified(
        Device(
            "192.168.1.151",
            vendor="Brother",
            dns_name="printer-hall",
            netbios=NetbiosInfo(name="PRINTER-HALL"),
            mdns=MdnsInfo(services={"_ipp._tcp", "_uscan._tcp"}),
            upnp=UpnpInfo(
                device_types={"urn:schemas-upnp-org:device:Printer:1"},
                model_name="LaserJet 1000",
            ),
            services=ports(9100),
        )
    )
    assert device.kind == "printer"
    assert len(device.evidence) == MAX_EVIDENCE


def test_model_is_capped_and_cleaned():
    device = classified(
        Device(
            "192.168.1.152",
            upnp=UpnpInfo(model_name="Box\x00\x1b[31m‮" + "X" * 300, model_number="7"),
        )
    )
    assert len(device.model) <= MAX_MODEL
    assert device.model.startswith("Box [31m X")
    assert all(ch.isprintable() for ch in device.model)


def test_model_number_is_not_repeated():
    device = classified(
        Device("192.168.1.153", upnp=UpnpInfo(model_name="Hub HB-200", model_number="hb-200"))
    )
    assert device.model == "Hub HB-200"


def test_software_model_names_are_not_device_models():
    device = classified(
        Device(
            "192.168.1.154",
            upnp=UpnpInfo(
                device_types={MEDIA_SERVER},
                model_name="Windows Media Player Sharing",
                model_number="12.0",
                server="Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0",
            ),
        )
    )
    assert device.model is None


@pytest.fixture
def shipped_table():
    oui._table.cache_clear()
    yield
    oui._table.cache_clear()


# One block from the shipped vendor table per vendor rule, with the extra clue a
# rule may need. The vendor comes from oui.lookup(), so a rule written for a name
# the table never gives fails here.
SHIPPED_VENDORS = [
    ("f4:64:12:12:34:56", "Sony Interactive", "console", {"upnp": UpnpInfo(device_types={DIAL})}),
    ("00:22:a6:12:34:56", "Sony Interactive", "console", {}),
    ("00:09:bf:12:34:56", "Nintendo", "console", {}),
    ("44:4f:8e:12:34:56", "WiZ", "smart-home", {}),
    ("e0:31:9e:12:34:56", "Valve", "console", {}),
    ("00:0d:3a:12:34:56", "Microsoft", "console", {"dns_name": "xbox-den.lan"}),
    ("00:11:32:12:34:56", "Synology", "nas", {}),
    ("24:5e:be:12:34:56", "QNAP", "nas", {}),
    ("00:bc:99:12:34:56", "Hikvision", "camera", {}),
    ("00:1b:a9:12:34:56", "Brother", "printer", {}),
    ("00:0e:58:12:34:56", "Sonos", "speaker", {}),
    ("2c:41:a1:12:34:56", "Bose", "speaker", {}),
    ("24:0a:c4:12:34:56", "Espressif", "smart-home", {}),
    ("00:17:88:12:34:56", "Signify", "smart-home", {}),
    ("18:c2:3c:12:34:56", "Lumi United", "smart-home", {}),
    ("84:00:ec:12:34:56", "Shelly", "smart-home", {}),
    ("10:d5:61:12:34:56", "Tuya", "smart-home", {}),
    ("b8:27:eb:12:34:56", "Raspberry Pi", "computer", {}),
    ("08:05:81:12:34:56", "Roku", "media", {}),
    ("00:71:47:12:34:56", "Amazon", "media", {"upnp": UpnpInfo(device_types={DIAL})}),
    ("00:00:f0:12:34:56", "Samsung", "tv", {"upnp": UpnpInfo(device_types={RENDERER})}),
    ("00:22:a9:12:34:56", "LG", "tv", {"upnp": UpnpInfo(device_types={RENDERER})}),
    ("00:0a:d9:12:34:56", "Sony", "tv", {"upnp": UpnpInfo(device_types={DIAL})}),
    ("00:04:0e:12:34:56", "AVM", "router", {}),
    ("00:15:6d:12:34:56", "Ubiquiti", "router", {}),
]


@pytest.mark.parametrize(
    "mac, vendor, kind, clues",
    SHIPPED_VENDORS,
    ids=[f"{vendor}-{mac[:8]}" for mac, vendor, _, _ in SHIPPED_VENDORS],
)
def test_vendor_rules_match_names_from_the_shipped_table(shipped_table, mac, vendor, kind, clues):
    device = Device("192.168.1.170", mac=mac, vendor=oui.lookup(mac), **clues)
    assert device.vendor == vendor
    classify(device)
    assert device.kind == kind
    assert f"vendor {vendor}" in device.evidence


def test_every_vendor_rule_has_a_shipped_example(shipped_table):
    def first_rule(vendor):
        lowered = (vendor or "").lower()
        for index, (pattern, *_) in enumerate(classify_module._VENDORS):
            if pattern.search(lowered):
                return index
        return None

    covered = {first_rule(oui.lookup(mac)) for mac, *_ in SHIPPED_VENDORS}
    assert covered == set(range(len(classify_module._VENDORS)))


def test_every_rule_points_at_a_known_kind():
    kinds = set(KINDS) - {"unknown"}
    assert set(classify_module._PRIORITY) == kinds
    used = {kind for _, _, kind in classify_module._APPLE_MODELS}
    used |= {kind for entries in classify_module._MDNS_SERVICES.values() for kind, _ in entries}
    used |= {kind for entries in classify_module._UPNP_TYPES.values() for kind, _ in entries}
    used |= {kind for _, kind, _, _ in classify_module._VENDORS}
    used |= {kind for _, kind, _ in classify_module._PORTS}
    used |= {kind for _, kind, _, _ in classify_module._NAME_PATTERNS}
    assert used <= kinds


class Odd:
    def __repr__(self):
        return "odd"


ODD_DEVICES = [
    Device(
        None,
        mac=None,
        vendor=None,
        dns_name=None,
        mdns=None,
        upnp=None,
        netbios=None,
        services=None,
        evidence=None,
        seen_by=None,
        is_gateway=None,
        is_self=None,
    ),
    Device(
        "192.168.1.160",
        mdns=MdnsInfo(hostname=None, services=None, instances=None, txt=None),
        upnp=UpnpInfo(
            server=None,
            device_types=None,
            friendly_name=None,
            manufacturer=None,
            model_name=None,
            model_number=None,
            services=None,
        ),
        netbios=NetbiosInfo(name=None, workgroup=None, file_server=None),
    ),
    Device(
        "192.168.1.161",
        mac="zz:zz:zz:zz:zz:zz",
        vendor=12345,
        dns_name=b"\xff\xfe",
        mdns=MdnsInfo(
            hostname=42,
            services="_ipp._tcp",
            instances=["not", "a", "dict"],
            txt={
                "_device-info._tcp": {"model": None},
                "_airplay._tcp": {"model": b"\xffAppleTV\x00"},
                "_raop._tcp": {"am": ["AudioAccessory5,1"]},
                "_googlecast._tcp": {"md": {"nested": "dict"}, "fn": 3.5},
                "_ipp._tcp": "not a dict",
                None: {"model": "x"},
                7: {"ty": "y"},
                "": {},
                ".": {},
                "local": {},
                "_hap._tcp": {"ci": object(), None: "z", 9: "w"},
            },
        ),
        upnp=UpnpInfo(
            server=b"Linux",
            device_types={None, 3, "urn:", "urn:a:device", "::::", "urn:x:device::1", Odd()},
            friendly_name=["list"],
            manufacturer=Odd(),
            model_name="\x00\x01\x02",
            model_number=5,
        ),
        netbios=NetbiosInfo(name=b"\x00", file_server="yes"),
        services=[None, Odd(), Service(-1), Service(70000), Service(True), Service("80")],
    ),
    Device(
        "192.168.1.162",
        mac="AA-BB-CC-00-00-01" * 1000,
        vendor="\ud800" * 5000,
        dns_name="." * 10000,
        mdns=MdnsInfo(
            hostname="‮" * 10000 + ".local",
            services={"_tcp", "._tcp", "_a._b._c._tcp.local.", "x" * 100000},
            instances={i: "y" * 1000 for i in range(1000)},
            txt={f"_s{i}._tcp": {f"k{j}": "v" * 1000 for j in range(100)} for i in range(200)},
        ),
        upnp=UpnpInfo(device_types={f"urn:x:device:T{i}:1" for i in range(1000)}),
        services=ports(*range(1, 6000)),
    ),
]


@pytest.mark.parametrize("device", ODD_DEVICES)
def test_classify_never_raises(device):
    classify(device)
    assert device.kind in KINDS
    assert device.model is None or (
        isinstance(device.model, str) and len(device.model) <= MAX_MODEL
    )
    assert isinstance(device.evidence, list)
    assert len(device.evidence) <= MAX_EVIDENCE
    assert all(isinstance(item, str) and item.isprintable() for item in device.evidence)


@pytest.mark.parametrize(
    "number, model",
    [("1", "EX5000"), ("1.0", "EX5000"), ("3000", "EX5000 3000"), ("T2", "EX5000 T2")],
)
def test_model_numbers_that_say_nothing_are_left_out(number, model):
    device = Device("192.168.1.1", upnp=UpnpInfo(model_name="EX5000", model_number=number))
    classify(device)
    assert device.model == model


def test_identifier_with_a_colour_suffix():
    txt = {"_device-info._tcp": {"model": "iMac21,1@ECOLOR=226,213,214"}}
    device = classified(Device("192.168.1.46", mdns=MdnsInfo(txt=txt)))
    assert device.model == "iMac (24-inch, M1, 2021)"
    assert device.kind == "computer"
    assert device.evidence[0] == "model iMac21,1"


def test_model_from_companion_link():
    txt = {"_companion-link._tcp": {"rpMd": "MacBookPro18,1", "rpVr": "620.1"}}
    device = classified(
        Device("192.168.1.47", mdns=MdnsInfo(services={"_companion-link._tcp"}, txt=txt))
    )
    assert device.model == "MacBook Pro (16-inch, 2021)"
    assert device.kind == "computer"


def test_every_listed_apple_identifier_has_a_family():
    from hearthscan.discovery import apple, classify

    identifiers = [i for _, group in apple._GROUPS for i in group]
    assert len(identifiers) == len(set(identifiers)) == len(apple.NAMES)
    for identifier in identifiers:
        assert classify._apple_model(identifier) is not None, identifier
