import copy
import json
from dataclasses import MISSING, fields, is_dataclass

import pytest

from hearthscan import serialize
from hearthscan.models import (
    Device,
    Finding,
    MdnsInfo,
    NetbiosInfo,
    PortMapping,
    RouterInfo,
    ScanResult,
    Service,
    UpnpInfo,
    UpnpService,
)


def full_result():
    """A result with every field set to something other than its default."""
    router = Device(
        "192.168.1.1",
        mac="a4:83:e7:00:00:01",
        vendor="Acme Networks",
        dns_name="router.lan",
        mdns=MdnsInfo(
            hostname="router.local",
            services={"_http._tcp", "_ssh._tcp"},
            instances={"_http._tcp": "Router admin", "_ssh._tcp": "router"},
            txt={"_http._tcp": {"path": "/", "model": "HR-100"}, "_ssh._tcp": {}},
        ),
        upnp=UpnpInfo(
            server="Linux/5.4 UPnP/1.0 MiniUPnPd/2.2",
            location="http://192.168.1.1:5000/rootDesc.xml",
            device_types={
                "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                "urn:schemas-upnp-org:device:WANDevice:1",
            },
            friendly_name="Home Router",
            manufacturer="Acme",
            model_name="HR",
            model_number="100",
            services=[
                UpnpService(
                    "urn:schemas-upnp-org:service:WANIPConnection:1",
                    "http://192.168.1.1:5000/ctl/IPConn",
                    "http://192.168.1.1:5000/WANIPCn.xml",
                )
            ],
        ),
        netbios=NetbiosInfo(
            name="ROUTER", workgroup="HOME", mac="a4:83:e7:00:00:01", file_server=True
        ),
        model="HR-100",
        kind="router",
        evidence=["default gateway", "UPnP InternetGatewayDevice"],
        services=[
            Service(
                80,
                protocol="udp",
                name="http",
                banner="HTTP/1.1 200 OK",
                product="lighttpd/1.4.59",
                tls=True,
                tls_version="TLSv1.1",
                title="R\u00e9seau maison",
                auth="none",
                facts={"login": "form", "status": "200"},
            ),
            Service(23, name="telnet"),
        ],
        seen_by={"ssdp", "arp", "tcp"},
        confirmed=True,
        is_gateway=True,
        is_self=True,
    )
    phone = Device("192.168.1.30", mac="da:a1:19:00:00:30", seen_by={"arp"})
    return ScanResult(
        version="2.0.0",
        started="2026-01-02T03:04:05+00:00",
        finished="2026-01-02T03:05:06+00:00",
        interface="Wi-Fi",
        address="192.168.1.50",
        network="192.168.1.0/24",
        gateway="192.168.1.1",
        devices=[router, phone],
        findings=[
            Finding(
                "telnet-open",
                "high",
                "192.168.1.1",
                port=23,
                params={"port": "23"},
                evidence="banner: login:",
            ),
            Finding("upnp-igd", "medium", "192.168.1.1"),
        ],
        score=58,
        ports=[23, 80, 443],
        notes=[("mdns", "mdns did not run (no multicast)"), ("probes", "slow")],
        router=RouterInfo(
            external_ip="100.64.20.30",
            connection="IP_Routed",
            status="Connected",
            uptime=86400,
            mappings=[
                PortMapping(
                    "UDP",
                    3074,
                    "192.168.1.30",
                    3075,
                    description="Game console",
                    enabled=False,
                    lease=3600,
                    remote_host="203.0.113.9",
                ),
                PortMapping("TCP", 8080, "192.168.1.1", 80),
            ],
            mappings_complete=False,
        ),
    )


MODELS = (
    ScanResult,
    Device,
    MdnsInfo,
    UpnpInfo,
    UpnpService,
    NetbiosInfo,
    Service,
    Finding,
    RouterInfo,
    PortMapping,
)


def set_fields(value, found):
    """(class name, field name) of every field set to something other than its default."""
    if is_dataclass(value):
        for f in fields(value):
            item = getattr(value, f.name)
            default = f.default
            if f.default_factory is not MISSING:
                default = f.default_factory()
            if item != default:
                found.add((type(value).__name__, f.name))
            set_fields(item, found)
    elif isinstance(value, list):
        for item in value:
            set_fields(item, found)
    return found


def test_the_sample_sets_every_field():
    # A field added to the models must be added here, and to serialize.from_dict.
    everything = {(model.__name__, f.name) for model in MODELS for f in fields(model)}
    assert everything - set_fields(full_result(), set()) == set()


def test_round_trip_is_lossless():
    result = full_result()
    assert serialize.loads(serialize.dumps(result)) == result
    assert serialize.from_dict(serialize.to_dict(result)) == result
    assert serialize.loads(serialize.dumps(result, indent=None)) == result


def test_round_trip_keeps_order_where_it_matters():
    result = full_result()
    back = serialize.loads(serialize.dumps(result))
    router = back.devices[0]
    assert list(router.mdns.instances) == ["_http._tcp", "_ssh._tcp"]
    assert [s.port for s in router.services] == [80, 23]
    assert back.notes == [("mdns", "mdns did not run (no multicast)"), ("probes", "slow")]
    assert isinstance(back.notes[0], tuple)


def test_to_dict_is_plain_json_data():
    data = serialize.to_dict(full_result())
    assert json.loads(json.dumps(data)) == data
    assert data["schema"] == serialize.SCHEMA == 1
    assert data["tool"] == "hearthscan"
    assert list(data)[:2] == ["schema", "tool"]

    router = data["devices"][0]
    assert router["seen_by"] == ["arp", "ssdp", "tcp"]
    assert router["mdns"]["services"] == ["_http._tcp", "_ssh._tcp"]
    assert router["upnp"]["device_types"] == sorted(router["upnp"]["device_types"])
    assert router["services"][0]["facts"] == {"login": "form", "status": "200"}
    assert data["notes"][0] == {"source": "mdns", "message": "mdns did not run (no multicast)"}
    assert data["findings"][1]["port"] is None


def test_to_dict_adds_the_derived_device_fields():
    data = serialize.to_dict(full_result())
    router, phone = data["devices"]
    assert router["name"] == "router" and router["random_mac"] is False
    assert phone["name"] is None and phone["random_mac"] is True
    assert phone["mdns"] is None and phone["services"] == []


def test_dumps_is_ascii_and_indent_is_optional():
    text = serialize.dumps(full_result())
    assert text.isascii()
    assert "\\u00e9" in text
    assert "\n  " in text
    assert "\n" not in serialize.dumps(full_result(), indent=None)


def test_derived_fields_are_not_read_back():
    data = serialize.to_dict(full_result())
    data["devices"][0]["name"] = "something else"
    data["devices"][0]["random_mac"] = True
    assert serialize.from_dict(data) == full_result()


def test_unknown_fields_are_ignored():
    data = serialize.to_dict(full_result())
    data["future"] = {"anything": [1, 2]}
    data["devices"][0]["battery"] = 80
    data["devices"][0]["mdns"]["extra"] = True
    data["devices"][0]["upnp"]["services"][0]["events"] = "x"
    data["devices"][0]["netbios"]["roles"] = []
    data["devices"][0]["services"][0]["cves"] = ["X"]
    data["findings"][0]["fixed"] = False
    data["notes"][0]["when"] = "later"
    data["router"]["isp"] = "Acme Fiber"
    data["router"]["mappings"][0]["ttl"] = 5
    assert serialize.from_dict(data) == full_result()


def test_missing_optional_fields_get_defaults():
    minimal = {
        "schema": 1,
        "tool": "hearthscan",
        "version": "2.0.0",
        "started": "2026-01-02T03:04:05+00:00",
        "finished": "2026-01-02T03:04:09+00:00",
        "interface": "eth0",
        "address": "10.0.0.5",
        "network": "10.0.0.0/24",
        "devices": [{"ip": "10.0.0.1", "services": [{"port": 22}], "mdns": {}}],
        "findings": [{"rule": "ssh-open", "severity": "info", "ip": "10.0.0.1"}],
    }
    result = serialize.from_dict(minimal)
    assert result.gateway is None and result.score == 100
    assert result.ports == [] and result.notes == [] and result.router is None
    device = result.devices[0]
    assert device == Device("10.0.0.1", mdns=MdnsInfo(), services=[Service(22)])
    assert result.findings == [Finding("ssh-open", "info", "10.0.0.1")]


def test_null_reads_like_a_missing_field():
    data = serialize.to_dict(full_result())
    data["devices"][0]["services"] = None
    data["devices"][0]["seen_by"] = None
    data["devices"][0]["kind"] = None
    device = serialize.from_dict(data).devices[0]
    assert device.services == [] and device.seen_by == set() and device.kind == "unknown"


def test_router_is_saved_with_its_mappings():
    data = serialize.to_dict(full_result())
    assert data["router"] == {
        "external_ip": "100.64.20.30",
        "connection": "IP_Routed",
        "status": "Connected",
        "uptime": 86400,
        "mappings": [
            {
                "protocol": "UDP",
                "external_port": 3074,
                "internal_client": "192.168.1.30",
                "internal_port": 3075,
                "description": "Game console",
                "enabled": False,
                "lease": 3600,
                "remote_host": "203.0.113.9",
            },
            {
                "protocol": "TCP",
                "external_port": 8080,
                "internal_client": "192.168.1.1",
                "internal_port": 80,
                "description": "",
                "enabled": True,
                "lease": 0,
                "remote_host": "",
            },
        ],
        "mappings_complete": False,
    }
    back = serialize.from_dict(data)
    assert back.router == full_result().router
    assert [m.external_port for m in back.router.mappings] == [3074, 8080]


def test_results_without_a_router_still_load():
    # Saved before the router check existed, or with no UPnP router on the network.
    data = serialize.to_dict(full_result())
    del data["router"]
    assert serialize.from_dict(data).router is None
    data["router"] = None
    assert serialize.from_dict(data).router is None
    assert serialize.to_dict(serialize.from_dict(data))["router"] is None


def test_router_fields_missing_from_the_file_get_defaults():
    data = serialize.to_dict(full_result())
    data["router"] = {
        "mappings": [
            {
                "protocol": "TCP",
                "external_port": 22,
                "internal_client": "192.168.1.9",
                "internal_port": 22,
            }
        ]
    }
    assert serialize.from_dict(data).router == RouterInfo(
        mappings=[PortMapping("TCP", 22, "192.168.1.9", 22)]
    )
    data["router"] = {}
    assert serialize.from_dict(data).router == RouterInfo()


@pytest.mark.parametrize("schema", [2, 0, "1", 1.0, True, None])
def test_other_schemas_are_refused(schema):
    data = serialize.to_dict(full_result())
    data["schema"] = schema
    with pytest.raises(ValueError, match="schema"):
        serialize.from_dict(data)


def test_a_newer_schema_says_so():
    data = serialize.to_dict(full_result())
    data["schema"] = 2
    with pytest.raises(ValueError, match="uses schema 2"):
        serialize.from_dict(data)


@pytest.mark.parametrize(
    "data",
    [
        [],
        "hearthscan",
        None,
        {"schema": 1},
        {"schema": 1, "tool": "netshark"},
        {"tool": "hearthscan"},
    ],
)
def test_other_data_is_not_a_result(data):
    with pytest.raises(ValueError, match="not a Hearthscan result"):
        serialize.from_dict(data)


def broken(change):
    data = copy.deepcopy(serialize.to_dict(full_result()))
    change(data)
    return data


@pytest.mark.parametrize(
    "change, where",
    [
        (lambda d: d.pop("address"), "address is missing"),
        (lambda d: d.update(score="58"), "score should be"),
        (lambda d: d.update(score=True), "score should be"),
        (lambda d: d.update(devices={}), "devices should be a list"),
        (lambda d: d.update(ports=[80, "443"]), r"ports\[1\]"),
        (lambda d: d["devices"].append("192.168.1.9"), r"devices\[2\] should be an object"),
        (lambda d: d["devices"][0].pop("ip"), r"devices\[0\]\.ip is missing"),
        (lambda d: d["devices"][0].update(confirmed="yes"), "confirmed should be true or false"),
        (lambda d: d["devices"][0].update(seen_by=["arp", 3]), r"seen_by\[1\]"),
        (lambda d: d["devices"][0]["services"][1].update(port="23"), r"services\[1\]\.port"),
        (lambda d: d["devices"][0]["services"][0].update(facts={"x": 1}), r"facts\.x"),
        (lambda d: d["devices"][0]["services"][0].update(facts=[]), "facts should be an object"),
        (lambda d: d["devices"][0]["mdns"]["txt"].update(bad="x"), r"txt\.bad should be"),
        (lambda d: d["devices"][0]["mdns"]["txt"]["_ssh._tcp"].update(k=2), r"_ssh\._tcp\.k"),
        (lambda d: d["devices"][0].update(upnp=[]), r"upnp should be an object"),
        (lambda d: d["devices"][0]["upnp"]["services"][0].pop("control_url"), "control_url"),
        (lambda d: d["findings"][0].update(port=23.0), r"findings\[0\]\.port"),
        (lambda d: d["findings"][1].pop("rule"), r"findings\[1\]\.rule is missing"),
        (lambda d: d["notes"].append({"source": "x"}), r"notes\[2\]\.message is missing"),
        # Values a renderer would trip over later are refused up front.
        (lambda d: d.update(address="192.168.1.500"), "address should be an IP address"),
        (lambda d: d.update(gateway="router"), "gateway should be an IP address"),
        (lambda d: d.update(network="192.168.1.0/33"), "network should be a network"),
        (lambda d: d.update(score=101), "score should be a score from 0 to 100"),
        (lambda d: d.update(score=-1), "score should be"),
        (lambda d: d.update(ports=[0]), r"ports\[0\] should be a port number"),
        (lambda d: d["devices"][1].update(ip="phone"), r"devices\[1\]\.ip should be an IP"),
        (lambda d: d["devices"][0]["services"][0].update(port=65536), r"services\[0\]\.port"),
        (lambda d: d["findings"][0].update(ip=3232235777), r"findings\[0\]\.ip should be"),
        (lambda d: d["findings"][0].update(severity="urgent"), "severity should be one of"),
        (lambda d: d["devices"][0]["services"][0].update(facts={"x": None}), r"facts\.x"),
        (lambda d: d.update(router=[]), "router should be an object"),
        (lambda d: d["router"].update(external_ip="isp"), r"router\.external_ip should be an IP"),
        (lambda d: d["router"].update(connection=1), r"router\.connection should be a string"),
        (lambda d: d["router"].update(status=False), r"router\.status should be a string"),
        (lambda d: d["router"].update(uptime=-1), r"router\.uptime should be a whole number"),
        (lambda d: d["router"].update(uptime="60"), r"router\.uptime should be"),
        (lambda d: d["router"].update(uptime=1.5), r"router\.uptime should be"),
        (lambda d: d["router"].update(mappings={}), r"router\.mappings should be a list"),
        (lambda d: d["router"].update(mappings_complete="no"), "mappings_complete should be true"),
        (
            lambda d: d["router"]["mappings"].append(80),
            r"router\.mappings\[2\] should be an object",
        ),
        (
            lambda d: d["router"]["mappings"][0].pop("protocol"),
            r"mappings\[0\]\.protocol is missing",
        ),
        (
            lambda d: d["router"]["mappings"][0].update(external_port=0),
            "external_port should be a port",
        ),
        (
            lambda d: d["router"]["mappings"][1].update(internal_port="80"),
            r"mappings\[1\]\.internal_port",
        ),
        (lambda d: d["router"]["mappings"][0].pop("internal_port"), "internal_port is missing"),
        (
            lambda d: d["router"]["mappings"][0].update(internal_client="nas.lan"),
            "internal_client should be an IP",
        ),
        (
            lambda d: d["router"]["mappings"][0].update(description=5),
            "description should be a string",
        ),
        (
            lambda d: d["router"]["mappings"][0].update(enabled=1),
            "enabled should be true or false",
        ),
        (lambda d: d["router"]["mappings"][0].update(lease=-60), "lease should be a whole number"),
        (
            lambda d: d["router"]["mappings"][0].update(remote_host=[]),
            "remote_host should be a string",
        ),
    ],
)
def test_malformed_results_raise_value_error(change, where):
    with pytest.raises(ValueError, match=where):
        serialize.from_dict(broken(change))


@pytest.mark.parametrize("text", ["", "{", "[1, 2]", '"text"', "[" * 200_000])
def test_loads_refuses_text_that_is_not_a_result(text):
    with pytest.raises(ValueError):
        serialize.loads(text)


@pytest.mark.parametrize("mac", ["0:1a:2b:3c:4d:5e", "AA:BB:CC:DD:EE:FF", "not a mac"])
def test_macs_that_are_not_normalized_are_refused(mac):
    data = serialize.to_dict(
        ScanResult("2.0.0", "", "", "eth0", "192.168.1.5", "192.168.1.0/24", None)
    )
    data["devices"] = [{"ip": "192.168.1.9", "mac": mac}]
    with pytest.raises(ValueError, match="mac"):
        serialize.from_dict(data)
