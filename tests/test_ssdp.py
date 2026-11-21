import asyncio
import contextlib
import ipaddress
import time
from pathlib import Path

import pytest

from hearthscan import http
from hearthscan.discovery import _udp, ssdp
from hearthscan.discovery.ssdp import (
    MAX_DESCRIPTION,
    MAX_REPLIES_PER_HOST,
    SSDP_GROUP,
    DescriptionError,
    SsdpReply,
    describe,
    parse_description,
    parse_reply,
    search,
)
from hearthscan.http import HttpError, Response
from hearthscan.models import UpnpService

DATA = Path(__file__).parent / "data"

IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
RENDERER = "urn:schemas-upnp-org:device:MediaRenderer:1"
WFA = "urn:schemas-wifialliance-org:device:WFADevice:1"
MEDIA_SERVER = "urn:schemas-upnp-org:device:MediaServer:1"


def fixture(name: str) -> bytes:
    return (DATA / name).read_bytes()


def response(*lines: str, end: str = "\r\n") -> bytes:
    return (end.join(lines) + end + end).encode()


ROUTER_REPLY = response(
    "HTTP/1.1 200 OK",
    "CACHE-CONTROL: max-age=120",
    "EXT:",
    "LOCATION: http://192.168.1.1:5000/rootDesc.xml",
    "SERVER: Linux/5.4 UPnP/1.1 TinyUPnP/1.0",
    f"ST: {IGD}",
    f"USN: uuid:00000000-0000-0000-0000-00000000a001::{IGD}",
)


# parse_reply


def test_parse_msearch_response():
    reply = parse_reply(ROUTER_REPLY, "192.168.1.1")
    assert reply == SsdpReply(
        ip="192.168.1.1",
        location="http://192.168.1.1:5000/rootDesc.xml",
        server="Linux/5.4 UPnP/1.1 TinyUPnP/1.0",
        st=IGD,
        usn=f"uuid:00000000-0000-0000-0000-00000000a001::{IGD}",
    )


def test_parse_reply_lowercase_names_and_lf_endings():
    data = response(
        "http/1.0 200 ok",
        "location:http://192.168.1.30:49152/description.xml",
        "Server :  Example/1.0  ",
        "st: upnp:rootdevice",
        end="\n",
    )
    reply = parse_reply(data, "192.168.1.30")
    assert reply.location == "http://192.168.1.30:49152/description.xml"
    assert reply.server == "Example/1.0"
    assert reply.st == "upnp:rootdevice"
    assert reply.usn is None


def test_parse_reply_missing_values_and_junk_lines():
    data = response(
        "HTTP/1.1 200 OK",
        "LOCATION:",
        "SERVER",
        "no colon at all",
        ": no name",
        "ST: upnp:rootdevice",
        "ST: ignored, the first one counts",
    )
    reply = parse_reply(data, "192.168.1.30")
    assert reply.location is None
    assert reply.server is None
    assert reply.st == "upnp:rootdevice"


def test_parse_notify_uses_nt():
    data = response(
        "NOTIFY * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        "NT: urn:schemas-upnp-org:device:MediaRenderer:1",
        "NTS: ssdp:alive",
        "LOCATION: http://192.168.1.30:49152/description.xml",
        "USN: uuid:00000000-0000-0000-0000-00000000b001",
    )
    reply = parse_reply(data, "192.168.1.30")
    assert reply.st == RENDERER
    assert reply.location == "http://192.168.1.30:49152/description.xml"


def test_parse_notify_byebye_is_ignored():
    data = response("NOTIFY * HTTP/1.1", "NT: upnp:rootdevice", "NTS: SSDP:BYEBYE")
    assert parse_reply(data, "192.168.1.30") is None


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\r\n\r\n",
        b"\xff\xfe\x00junk",
        response("M-SEARCH * HTTP/1.1", "HOST: 239.255.255.250:1900", "ST: ssdp:all"),
        response("HTTP/1.1 404 Not Found", "LOCATION: http://192.168.1.1/"),
        response("HTTP/1.1 2000 OK"),
        response("RTSP/1.0 200 OK", "LOCATION: http://192.168.1.1/"),
        response("NOTIFY /path HTTP/1.1", "NT: upnp:rootdevice"),
    ],
)
def test_parse_reply_rejects_everything_else(data):
    assert parse_reply(data, "192.168.1.30") is None


def test_parse_reply_caps_and_cleans_values():
    data = (
        b"HTTP/1.1 200 OK\r\n"
        b"SERVER: Bad\x1b[31mColour\x00\xff\xfe\r\n"
        b"USN: " + b"u" * 2000 + b"\r\n\r\n"
    )
    reply = parse_reply(data, "192.168.1.30")
    assert reply.server == "Bad [31mColour \ufffd\ufffd"
    assert reply.usn == "u" * 512


def test_parse_reply_turns_bidi_and_invisible_characters_into_spaces():
    server = (
        "Kitchen\N{RIGHT-TO-LEFT OVERRIDE}VT moor"
        "\N{LEFT-TO-RIGHT ISOLATE}x\N{POP DIRECTIONAL ISOLATE}\N{ZERO WIDTH SPACE}y"
        "\N{LINE SEPARATOR}z\N{PARAGRAPH SEPARATOR}\N{ZERO WIDTH NO-BREAK SPACE}w"
    )
    data = f"HTTP/1.1 200 OK\r\nSERVER: {server}\r\n\r\n".encode()
    assert parse_reply(data, "192.168.1.30").server == "Kitchen VT moor x y z w"


def test_parse_reply_reads_only_the_start_of_huge_messages():
    padding = b"X-Pad: " + b"p" * 20000 + b"\r\n"
    data = b"HTTP/1.1 200 OK\r\n" + padding + b"LOCATION: http://192.168.1.1/\r\n\r\n"
    assert parse_reply(data, "192.168.1.1").location is None
    many = b"".join(b"X-%d: v\r\n" % i for i in range(100))
    data = b"HTTP/1.1 200 OK\r\n" + many + b"LOCATION: http://192.168.1.1/\r\n\r\n"
    assert parse_reply(data, "192.168.1.1").location is None


# search


def install_exchange(monkeypatch, replies):
    calls = []

    async def fake_exchange(packets, **kwargs):
        calls.append((list(packets), kwargs))
        return replies

    monkeypatch.setattr(_udp, "exchange", fake_exchange)
    return calls


def test_search_sends_both_queries_twice(monkeypatch):
    calls = install_exchange(monkeypatch, [])
    assert asyncio.run(search("192.168.1.50", duration=1.0)) == {}

    (packets, kwargs) = calls[0]
    assert kwargs["local"] == "192.168.1.50"
    assert kwargs["multicast_ttl"] == 2
    assert kwargs["spacing"] > 0
    assert 0 < kwargs["listen"] <= 1.0
    assert all(address == SSDP_GROUP for _, address in packets)
    targets = [payload.split(b"\r\nST: ")[1].split(b"\r\n")[0] for payload, _ in packets]
    assert sorted(targets) == [b"ssdp:all", b"ssdp:all", b"upnp:rootdevice", b"upnp:rootdevice"]
    for payload, _ in packets:
        assert payload.startswith(b"M-SEARCH * HTTP/1.1\r\n")
        assert b"\r\nHOST: 239.255.255.250:1900\r\n" in payload
        assert b'\r\nMAN: "ssdp:discover"\r\n' in payload
        assert b"\r\nMX: 2\r\n" in payload
        assert payload.endswith(b"\r\n\r\n")


def test_search_groups_dedupes_and_filters(monkeypatch):
    renderer = response(
        "HTTP/1.1 200 OK",
        "LOCATION: http://192.168.1.30:49152/description.xml",
        f"ST: {RENDERER}",
    )
    install_exchange(
        monkeypatch,
        [
            (ROUTER_REPLY, "192.168.1.1"),
            (renderer, "192.168.1.30"),
            (ROUTER_REPLY, "192.168.1.1"),  # the second copy of the query
            (ROUTER_REPLY, "203.0.113.9"),  # not local
            (b"garbage", "192.168.1.31"),
            (response("M-SEARCH * HTTP/1.1", "ST: ssdp:all"), "192.168.1.32"),
        ],
    )
    found = asyncio.run(search("192.168.1.50"))
    assert list(found) == ["192.168.1.1", "192.168.1.30"]
    assert len(found["192.168.1.1"]) == 1
    assert found["192.168.1.30"][0].st == RENDERER


def test_search_caps_replies_per_host(monkeypatch):
    flood = [(response("HTTP/1.1 200 OK", f"USN: uuid:{i}"), "192.168.1.66") for i in range(500)]
    install_exchange(monkeypatch, flood)
    found = asyncio.run(search("192.168.1.50"))
    assert len(found["192.168.1.66"]) == MAX_REPLIES_PER_HOST


def test_search_drops_senders_outside_the_network(monkeypatch):
    spoofed = response(
        "HTTP/1.1 200 OK",
        "LOCATION: http://10.20.30.40:8080/admin/set?dns=192.0.2.1",
        "ST: upnp:rootdevice",
    )
    install_exchange(
        monkeypatch,
        [
            (ROUTER_REPLY, "192.168.1.1"),
            (spoofed, "10.20.30.40"),
            (ROUTER_REPLY, "192.168.2.7"),
        ],
    )
    network = ipaddress.ip_network("192.168.1.0/24")
    found = asyncio.run(search("192.168.1.50", network=network))
    assert list(found) == ["192.168.1.1"]
    # Without a network every private sender stays.
    found = asyncio.run(search("192.168.1.50"))
    assert list(found) == ["192.168.1.1", "10.20.30.40", "192.168.2.7"]


@pytest.mark.parametrize("duration", [0, -1, float("inf")])
def test_search_rejects_bad_durations(duration):
    with pytest.raises(ValueError):
        asyncio.run(search("192.168.1.50", duration=duration))


# parse_description


def test_router_description():
    info = parse_description(fixture("ssdp_router.xml"), "http://192.168.1.1:5000/rootDesc.xml")
    assert info.friendly_name == "Acme HomeGate"
    assert info.manufacturer == "Acme Networks"
    assert info.model_name == "HomeGate 3000"
    assert info.model_number == "HG-3000"
    assert info.device_types == {
        IGD,
        "urn:schemas-upnp-org:device:WANDevice:1",
        "urn:schemas-upnp-org:device:WANConnectionDevice:1",
    }
    base = "http://192.168.1.1:5000"
    assert info.services == [
        UpnpService(
            "urn:schemas-upnp-org:service:Layer3Forwarding:1", f"{base}/ctl/L3F", f"{base}/L3F.xml"
        ),
        UpnpService(
            "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
            f"{base}/ctl/CmnIfCfg",
            f"{base}/WANCfg.xml",
        ),
        UpnpService(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            f"{base}/ctl/IPConn",
            f"{base}/WANIPCn.xml",
        ),
    ]
    assert info.server is None
    assert info.location is None


def test_media_renderer_with_relative_urls():
    info = parse_description(
        fixture("ssdp_renderer.xml"), "http://192.168.1.30:49152/description.xml"
    )
    assert info.friendly_name == "Living-Room Speaker"
    assert info.device_types == {RENDERER}
    assert [s.service_type.split(":")[-2] for s in info.services] == [
        "RenderingControl",
        "ConnectionManager",
        "AVTransport",
    ]
    assert info.services[0].control_url == "http://192.168.1.30:49152/RenderingControl/ctrl"
    assert info.services[0].scpd_url == "http://192.168.1.30:49152/RenderingControl/desc.xml"


def test_printer_text_is_tidied_and_services_deduplicated():
    info = parse_description(fixture("ssdp_printer.xml"), "http://192.168.1.60/upnp/desc.xml")
    assert info.friendly_name == "Office Printer (2nd floor)"
    assert info.model_name == "Inkwell LX-200"
    assert info.model_number == "LX-200"
    assert info.device_types == {"urn:schemas-upnp-org:device:Printer:1"}
    # The duplicate goes, and so does the service without a controlURL.
    assert info.services == [
        UpnpService(
            "urn:schemas-upnp-org:service:PrintBasic:1",
            "http://192.168.1.60/upnp/control/printbasic",
            "http://192.168.1.60/upnp/printbasic.xml",
        )
    ]


def test_url_base_wins_over_the_location():
    info = parse_description(fixture("ssdp_urlbase.xml"), "http://192.168.1.40:8201/rootDesc.xml")
    assert [s.control_url for s in info.services] == [
        "http://192.168.1.40:8200/ctl/ContentDir",
        "http://192.168.1.40:8200/upnp/control/cm",
    ]
    assert info.services[1].scpd_url == "http://192.168.1.40:8200/upnp/cm.xml"


def test_url_base_on_another_host_drops_the_services():
    info = parse_description(fixture("ssdp_urlbase.xml"), "http://192.168.1.41/rootDesc.xml")
    assert info.friendly_name == "Storage-Box Media"
    assert info.services == []


def test_description_without_namespace():
    info = parse_description(fixture("ssdp_nonamespace.xml"), "http://192.168.1.70:2869/desc")
    assert info.friendly_name == "DESKTOP-7Q1"
    assert info.device_types == {"urn:schemas-upnp-org:device:Basic:1"}
    assert info.services[0].control_url == "http://192.168.1.70:2869/sharing/control"


def test_services_on_other_hosts_are_dropped():
    info = parse_description(fixture("ssdp_foreign.xml"), "http://192.168.1.50/desc.xml")
    kept = {s.service_type.split(":")[-2]: s for s in info.services}
    assert set(kept) == {"Kept", "OtherPort", "ForeignScpd"}
    assert kept["Kept"].control_url == "http://192.168.1.50/ctl/kept"
    assert kept["OtherPort"].control_url == "https://192.168.1.50:8443/ctl/secure"
    assert kept["ForeignScpd"].scpd_url is None


@pytest.mark.parametrize("name", ["ssdp_malformed.xml", "ssdp_bomb.xml", "ssdp_attlist.xml"])
def test_bad_documents_are_refused(name):
    with pytest.raises(DescriptionError):
        parse_description(fixture(name), "http://192.168.1.50/desc.xml")


@pytest.mark.parametrize(
    "xml",
    [
        b"",
        b"not xml at all",
        b"<html><body>Not Found<br></body></html>",
        b"<html><body>Not Found</body></html>",
        b'<?xml version="1.0" encoding="x-no-such-encoding"?><root/>',
        b"<root><device><friendlyName>\xff\xfe</friendlyName></device></root>",
        b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/hosts">]>'
        b"<root><device><friendlyName>&x;</friendlyName></device></root>",
        b"<a>" * 20000 + b"</a>" * 20000,
    ],
)
def test_broken_or_hostile_xml_raises_description_error(xml):
    with pytest.raises(DescriptionError):
        parse_description(xml, "http://192.168.1.50/desc.xml")


def test_oversized_description_is_refused():
    xml = b"<root><device>" + b" " * MAX_DESCRIPTION + b"</device></root>"
    with pytest.raises(DescriptionError):
        parse_description(xml, "http://192.168.1.50/desc.xml")


def test_descriptions_over_128_kb_are_refused():
    # Real descriptions are a few KB; the cap bounds what a crafted one costs to parse.
    xml = b"<root><device>" + b" " * (200 * 1024) + b"</device></root>"
    with pytest.raises(DescriptionError):
        parse_description(xml, "http://192.168.1.50/desc.xml")


def namespaced(uri: bytes, declaration: bytes = b'xmlns="%s"') -> bytes:
    return (
        b"<root " + declaration.replace(b"%s", uri) + b">"
        b"<device><friendlyName>Long</friendlyName></device></root>"
    )


@pytest.mark.parametrize(
    "xml",
    [
        namespaced(b"u" * 256),
        namespaced(b"u" * 300, b"xmlns = '%s'"),
        namespaced(b"u" * 300, b'xmlns:dev="%s"'),
        # UTF-16 would hide the declaration from a check on the raw bytes.
        namespaced(b"u" * 300).decode().encode("utf-16"),
    ],
)
def test_long_namespace_uris_are_refused(xml):
    with pytest.raises(DescriptionError):
        parse_description(xml, "http://192.168.1.50/desc.xml")


def test_namespace_uri_of_255_bytes_is_fine():
    info = parse_description(namespaced(b"u" * 255), "http://192.168.1.50/desc.xml")
    assert info.friendly_name == "Long"


def test_description_text_loses_bidi_and_invisible_characters():
    xml = (
        "<root><device><friendlyName>"
        "Kitchen\N{RIGHT-TO-LEFT OVERRIDE}VT moor\N{ZERO WIDTH JOINER}"
        "</friendlyName></device></root>"
    ).encode()
    info = parse_description(xml, "http://192.168.1.50/desc.xml")
    assert info.friendly_name == "Kitchen VT moor"


def test_description_error_is_a_value_error():
    assert issubclass(DescriptionError, ValueError)


def test_device_nesting_and_text_length_are_capped():
    depth = 30
    xml = (
        "<root><device><friendlyName>"
        + "N" * 500
        + "</friendlyName>"
        + "".join(
            f"<deviceType>urn:example-com:device:Level{i}:1</deviceType><deviceList><device>"
            for i in range(depth)
        )
        + "</device></deviceList>" * depth
        + "</device></root>"
    ).encode()
    info = parse_description(xml, "http://192.168.1.50/desc.xml")
    assert len(info.friendly_name) == 200
    assert len(info.device_types) == ssdp.MAX_DEPTH + 1


def test_many_services_are_capped():
    service = (
        "<service><serviceType>urn:example-com:service:S{0}:1</serviceType>"
        "<controlURL>/ctl/{0}</controlURL></service>"
    )
    xml = (
        "<root><device><serviceList>"
        + "".join(service.format(i) for i in range(500))
        + "</serviceList></device></root>"
    ).encode()
    info = parse_description(xml, "http://192.168.1.50/desc.xml")
    assert len(info.services) == ssdp.MAX_SERVICES


def test_bare_device_root_is_accepted():
    xml = b"<device><deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType></device>"
    info = parse_description(xml, "http://192.168.1.50/desc.xml")
    assert info.device_types == {"urn:schemas-upnp-org:device:Basic:1"}


# describe


def ok(url: str, body: bytes, status: int = 200) -> Response:
    return Response(url, status, "OK", {"content-type": "text/xml"}, body)


def install_fetch(monkeypatch, pages):
    """`pages` maps URL to a Response, an exception, or a coroutine function."""
    fetched = []

    async def fake_fetch(url, **kwargs):
        fetched.append((url, kwargs))
        page = pages[url]
        if isinstance(page, BaseException):
            raise page
        if callable(page):
            return await page(url, **kwargs)
        return page

    monkeypatch.setattr(http, "fetch", fake_fetch)
    return fetched


def reply(ip, location=None, server=None, st=None, usn=None):
    return SsdpReply(ip, location, server, st, usn)


def test_describe_fills_in_server_and_location(monkeypatch):
    location = "http://192.168.1.1:5000/rootDesc.xml"
    fetched = install_fetch(monkeypatch, {location: ok(location, fixture("ssdp_router.xml"))})
    replies = {
        "192.168.1.1": [
            reply("192.168.1.1", None, None, "upnp:rootdevice"),
            reply("192.168.1.1", location, "Linux UPnP/1.1 TinyUPnP/1.0", IGD),
        ]
    }
    info = asyncio.run(describe(replies, timeout=2.0))["192.168.1.1"]
    assert info.friendly_name == "Acme HomeGate"
    assert info.server == "Linux UPnP/1.1 TinyUPnP/1.0"
    assert info.location == location
    assert IGD in info.device_types
    assert len(info.services) == 3
    ((url, kwargs),) = fetched
    assert url == location
    assert kwargs["limit"] == MAX_DESCRIPTION
    assert 0 < kwargs["timeout"] <= 2.0


def test_describe_falls_back_to_what_ssdp_said(monkeypatch):
    fetched = install_fetch(
        monkeypatch,
        {
            "http://192.168.1.10/fails.xml": HttpError("malformed status line"),
            "http://192.168.1.11/missing.xml": ok("http://192.168.1.11/missing.xml", b"", 404),
            "http://192.168.1.12/slow.xml": TimeoutError(),
            "http://192.168.1.13/broken.xml": ok(
                "http://192.168.1.13/broken.xml", fixture("ssdp_malformed.xml")
            ),
        },
    )
    usn_type = f"uuid:00000000-0000-0000-0000-00000000b001::{RENDERER}"
    replies = {
        "192.168.1.10": [reply("192.168.1.10", "http://192.168.1.10/fails.xml", "S/1", IGD)],
        "192.168.1.11": [
            reply("192.168.1.11", "http://192.168.1.11/missing.xml", None, None, usn_type)
        ],
        "192.168.1.12": [reply("192.168.1.12", "http://192.168.1.12/slow.xml")],
        "192.168.1.13": [reply("192.168.1.13", "http://192.168.1.13/broken.xml")],
        # Points somewhere else: never fetched.
        "192.168.1.14": [reply("192.168.1.14", "http://192.168.1.99/desc.xml", "S/2", RENDERER)],
        "192.168.1.15": [reply("192.168.1.15", "ftp://192.168.1.15/desc.xml")],
        "192.168.1.16": [reply("192.168.1.16", None, "S/3", "upnp:rootdevice", "uuid:1")],
    }
    infos = asyncio.run(describe(replies))
    assert list(infos) == list(replies)
    assert infos["192.168.1.10"].server == "S/1"
    assert infos["192.168.1.10"].device_types == {IGD}
    assert infos["192.168.1.10"].location == "http://192.168.1.10/fails.xml"
    assert infos["192.168.1.11"].device_types == {RENDERER}
    assert infos["192.168.1.12"].friendly_name is None
    assert infos["192.168.1.14"].location is None
    assert infos["192.168.1.14"].device_types == {RENDERER}
    assert infos["192.168.1.15"].location is None
    assert infos["192.168.1.16"].server == "S/3"
    assert infos["192.168.1.16"].device_types == set()
    assert sorted(url for url, _ in fetched) == [
        "http://192.168.1.10/fails.xml",
        "http://192.168.1.11/missing.xml",
        "http://192.168.1.12/slow.xml",
        "http://192.168.1.13/broken.xml",
    ]


def test_locations_must_point_at_the_sender():
    replies = [
        reply("192.168.1.20", "http://192.168.1.21/desc.xml"),
        reply("192.168.1.20", "not a url"),
        reply("192.168.1.20", "http://[bad/desc.xml"),
        reply("192.168.1.20", "https://192.168.1.20:8443/desc.xml"),
        reply("192.168.1.20", None),
        reply("192.168.1.20", "http://192.168.1.20/second.xml"),
        reply("192.168.1.20", "https://192.168.1.20:8443/desc.xml"),
    ]
    assert ssdp._locations_for("192.168.1.20", replies) == [
        "https://192.168.1.20:8443/desc.xml",
        "http://192.168.1.20/second.xml",
    ]
    assert ssdp._locations_for("203.0.113.9", [reply("203.0.113.9", "http://203.0.113.9/")]) == []
    many = [reply("192.168.1.20", f"http://192.168.1.20/{i}.xml") for i in range(20)]
    assert len(ssdp._locations_for("192.168.1.20", many)) == ssdp.MAX_LOCATIONS


WPS_DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-wifialliance-org:device:WFADevice:1</deviceType>
    <friendlyName>Acme WPS</friendlyName>
    <manufacturer>ChipCo</manufacturer>
    <modelName>Wireless Access Point</modelName>
    <modelNumber>WAP-1</modelNumber>
    <serviceList>
      <service>
        <serviceType>urn:schemas-wifialliance-org:service:WFAWLANConfig:1</serviceType>
        <controlURL>/wps_control</controlURL>
        <SCPDURL>/wps_scpd.xml</SCPDURL>
      </service>
    </serviceList>
  </device>
</root>
"""

GONE_URL = "http://192.168.1.1:49153/gone.xml"
WPS_URL = "http://192.168.1.1:49152/wps_device.xml"
IGD_URL = "http://192.168.1.1:5000/rootDesc.xml"


def gateway_description(*keep: str) -> bytes:
    """The router fixture with only the name elements in `keep` left in its root device."""
    xml = fixture("ssdp_router.xml")
    names = {
        "friendlyName": b"Acme HomeGate",
        "manufacturer": b"Acme Networks",
        "modelName": b"HomeGate 3000",
        "modelNumber": b"HG-3000",
    }
    for tag, value in names.items():
        if tag not in keep:
            element = b"<%s>%s</%s>" % (tag.encode(), value, tag.encode())
            assert element in xml
            xml = xml.replace(element, b"", 1)  # the root device's comes first
    return xml


@pytest.mark.parametrize(
    "order",
    [
        (GONE_URL, WPS_URL, IGD_URL),
        (WPS_URL, IGD_URL, GONE_URL),
        (IGD_URL, GONE_URL, WPS_URL),
    ],
)
def test_describe_takes_the_names_from_the_gateway_description(monkeypatch, order):
    install_fetch(
        monkeypatch,
        {
            GONE_URL: ConnectionResetError(),
            WPS_URL: ok(WPS_URL, WPS_DESCRIPTION),
            IGD_URL: ok(IGD_URL, fixture("ssdp_router.xml")),
        },
    )
    replies = {"192.168.1.1": [reply("192.168.1.1", url) for url in order]}
    info = asyncio.run(describe(replies))["192.168.1.1"]
    assert info.location == IGD_URL
    assert (info.friendly_name, info.manufacturer, info.model_name, info.model_number) == (
        "Acme HomeGate",
        "Acme Networks",
        "HomeGate 3000",
        "HG-3000",
    )
    assert info.device_types == {
        WFA,
        IGD,
        "urn:schemas-upnp-org:device:WANDevice:1",
        "urn:schemas-upnp-org:device:WANConnectionDevice:1",
    }
    controls = [s.control_url for s in info.services]
    assert controls == [
        "http://192.168.1.1:5000/ctl/L3F",
        "http://192.168.1.1:5000/ctl/CmnIfCfg",
        "http://192.168.1.1:5000/ctl/IPConn",
        "http://192.168.1.1:49152/wps_control",
    ]


def test_other_descriptions_only_fill_gaps(monkeypatch):
    install_fetch(
        monkeypatch,
        {
            WPS_URL: ok(WPS_URL, WPS_DESCRIPTION),
            IGD_URL: ok(IGD_URL, gateway_description("friendlyName", "modelName")),
        },
    )
    replies = {"192.168.1.1": [reply("192.168.1.1", url) for url in (WPS_URL, IGD_URL)]}
    info = asyncio.run(describe(replies))["192.168.1.1"]
    assert info.location == IGD_URL
    assert info.friendly_name == "Acme HomeGate"
    assert info.manufacturer == "ChipCo"  # the gateway left it out
    # The WPS model number would not belong to the gateway's model name.
    assert (info.model_name, info.model_number) == ("HomeGate 3000", None)


def test_a_nameless_gateway_description_gives_way(monkeypatch):
    install_fetch(
        monkeypatch,
        {
            WPS_URL: ok(WPS_URL, WPS_DESCRIPTION),
            IGD_URL: ok(IGD_URL, gateway_description("manufacturer")),
        },
    )
    replies = {"192.168.1.1": [reply("192.168.1.1", url) for url in (IGD_URL, WPS_URL)]}
    info = asyncio.run(describe(replies))["192.168.1.1"]
    assert info.location == WPS_URL
    assert (info.friendly_name, info.manufacturer, info.model_name, info.model_number) == (
        "Acme WPS",
        "ChipCo",
        "Wireless Access Point",
        "WAP-1",
    )
    assert IGD in info.device_types


def test_locations_are_ranked_before_the_cap():
    ip = "192.168.1.1"
    side = [reply(ip, f"http://{ip}:4915{i}/wps.xml", st=WFA) for i in range(3)]
    side.append(reply(ip, f"http://{ip}:8200/dlna.xml", st=MEDIA_SERVER))
    unknown = reply(ip, f"http://{ip}:1900/other.xml", st="upnp:rootdevice")
    gateway = [
        reply(ip, IGD_URL, st="upnp:rootdevice"),
        reply(ip, IGD_URL, usn=f"uuid:00000000-0000-0000-0000-00000000a001::{IGD}"),
    ]
    assert ssdp._locations_for(ip, [*side, unknown, *gateway]) == [
        IGD_URL,
        f"http://{ip}:1900/other.xml",
        f"http://{ip}:49150/wps.xml",
        f"http://{ip}:49151/wps.xml",
    ]


@pytest.mark.parametrize(
    ("device_type", "rank"),
    [
        (IGD, 0),
        ("urn:schemas-upnp-org:device:internetgatewaydevice:2", 0),
        (RENDERER, 1),
        ("urn:schemas-upnp-org:device:Basic:1", 1),
        ("urn:dial-multiscreen-org:device:dial:1", 2),
        (None, 2),
        ("not a device type", 2),
        (WFA, 3),
        (MEDIA_SERVER, 3),
    ],
)
def test_rank(device_type, rank):
    assert ssdp._rank(device_type) == rank


def test_describe_limits_parallel_fetches(monkeypatch):
    running = 0
    peak = 0

    async def slow(url, **kwargs):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.02)
        running -= 1
        return ok(url, fixture("ssdp_renderer.xml"))

    hosts = [f"192.168.1.{i}" for i in range(100, 120)]
    install_fetch(monkeypatch, {f"http://{ip}/desc.xml": slow for ip in hosts})
    replies = {ip: [reply(ip, f"http://{ip}/desc.xml")] for ip in hosts}
    infos = asyncio.run(describe(replies, timeout=5.0))
    assert peak == ssdp.MAX_FETCHES
    assert all(info.friendly_name == "Living-Room Speaker" for info in infos.values())


async def stuck(url, *, timeout, limit):
    await asyncio.sleep(timeout)  # what the real fetch does before giving up
    raise TimeoutError


def test_hosts_that_hang_do_not_starve_the_others(monkeypatch):
    pages = {}
    replies = {}
    for ip in ("192.168.1.2", "192.168.1.3"):
        urls = [f"http://{ip}:{port}/desc.xml" for port in range(8000, 8004)]
        pages.update(dict.fromkeys(urls, stuck))
        replies[ip] = [reply(ip, url) for url in urls]
    good = "http://192.168.1.4/desc.xml"
    pages[good] = ok(good, fixture("ssdp_renderer.xml"))
    replies["192.168.1.4"] = [reply("192.168.1.4", good)]
    fetched = install_fetch(monkeypatch, pages)
    infos = asyncio.run(describe(replies, timeout=0.3))
    assert infos["192.168.1.4"].friendly_name == "Living-Room Speaker"
    # A stuck host waits on one location at a time, so it never got past its first.
    assert sum(url.startswith("http://192.168.1.2:") for url, _ in fetched) == 1


def test_one_stuck_description_does_not_use_up_the_budget(monkeypatch):
    monkeypatch.setattr(ssdp, "FETCH_TIMEOUT", 0.05)
    first = "http://192.168.1.30:8000/stuck.xml"
    second = "http://192.168.1.30:8001/desc.xml"
    fetched = install_fetch(
        monkeypatch, {first: stuck, second: ok(second, fixture("ssdp_renderer.xml"))}
    )
    replies = {"192.168.1.30": [reply("192.168.1.30", url) for url in (first, second)]}
    info = asyncio.run(describe(replies, timeout=1.0))["192.168.1.30"]
    assert info.friendly_name == "Living-Room Speaker"
    assert [url for url, _ in fetched] == [first, second]
    assert all(kwargs["timeout"] <= 0.05 for _, kwargs in fetched)


def test_describe_keeps_to_its_time_budget(monkeypatch):
    hosts = [f"192.168.1.{i}" for i in range(100, 130)]
    install_fetch(monkeypatch, {f"http://{ip}/desc.xml": stuck for ip in hosts})
    replies = {ip: [reply(ip, f"http://{ip}/desc.xml", "S/1")] for ip in hosts}
    started = time.perf_counter()
    infos = asyncio.run(describe(replies, timeout=0.3))
    assert time.perf_counter() - started < 1.0
    assert len(infos) == len(hosts)
    assert all(info.server == "S/1" for info in infos.values())


def test_cancelling_describe_stops_the_fetches(monkeypatch):
    started = []
    stopped = []

    async def forever(url, **kwargs):
        started.append(url)
        try:
            await asyncio.sleep(3600)
        finally:
            stopped.append(url)

    hosts = [f"192.168.1.{i}" for i in range(100, 105)]
    install_fetch(monkeypatch, {f"http://{ip}/desc.xml": forever for ip in hosts})
    replies = {ip: [reply(ip, f"http://{ip}/desc.xml")] for ip in hosts}

    async def main():
        task = asyncio.ensure_future(describe(replies, timeout=3600))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []
    assert len(started) == 5
    assert sorted(stopped) == sorted(started)


def test_namespace_check_stays_fast_on_xmlns_runs_in_text():
    import time

    document = (
        b"<root><device><friendlyName>" + b"xmlns:" * 21000 + b"</friendlyName></device></root>"
    )
    started = time.perf_counter()
    with contextlib.suppress(ssdp.DescriptionError):
        ssdp.parse_description(document, "http://192.168.1.1/desc.xml")
    assert time.perf_counter() - started < 1.0
