import pytest

from hearthscan.models import (
    SEVERITIES,
    Device,
    PortMapping,
    RouterInfo,
    Service,
    UpnpInfo,
    UpnpService,
)
from hearthscan.ports import SERVICE_NAMES
from hearthscan.rules import (
    MAX_EVIDENCE,
    MAX_FORWARDS,
    RULE_IDS,
    RULES,
    Context,
    Rule,
    evaluate,
    rule,
)

FORWARD = {"external_port", "internal_port", "protocol", "description"}

CATALOG = (
    ("telnet-open", "high", {"port"}),
    ("ftp-open", "medium", {"port", "product"}),
    ("vnc-no-auth", "critical", {"port"}),
    ("vnc-open", "medium", {"port"}),
    ("rdp-open", "medium", {"port"}),
    ("adb-open", "critical", {"port", "product"}),
    ("adb-exposed", "medium", {"port"}),
    ("redis-no-auth", "critical", {"port"}),
    ("docker-api-open", "critical", {"port", "product"}),
    ("memcached-open", "high", {"port"}),
    ("elasticsearch-no-auth", "high", {"port", "product"}),
    ("database-open", "medium", {"port", "service"}),
    ("mqtt-anonymous", "high", {"port"}),
    ("rtsp-no-auth", "high", {"port"}),
    ("smb1-enabled", "high", {"port"}),
    ("socks-no-auth", "high", {"port"}),
    ("dvr-port-open", "high", {"port"}),
    ("winbox-open", "medium", {"port"}),
    ("pptp-open", "medium", {"port"}),
    ("webmin-open", "medium", {"port"}),
    ("nfs-open", "medium", {"port"}),
    ("rsync-open", "medium", {"port", "modules"}),
    ("login-over-http", "medium", {"port"}),
    ("old-tls", "low", {"port", "version"}),
    ("upnp-igd", "medium", set()),
    ("tr069-open", "low", {"port"}),
    ("jetdirect-open", "low", {"port"}),
    ("smb-open", "info", {"port"}),
    ("ssh-open", "info", {"port", "product"}),
    ("unknown-device", "info", set()),
    ("port-forward-risky", "high", FORWARD),
    ("port-forward", "low", FORWARD),
    ("double-nat", "info", {"external_ip"}),
    ("cgnat", "info", {"external_ip"}),
)

IGD = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
WAN_IP = "urn:schemas-upnp-org:service:WANIPConnection:1"


def host(*services, ip="192.168.1.20", kind="computer", **kwargs):
    return Device(ip, kind=kind, services=list(services), **kwargs)


def found(*devices, gateway=None, router=None):
    return evaluate(devices, gateway=gateway, router=router)


def only(rule_id, *devices, gateway=None, router=None):
    return [f for f in found(*devices, gateway=gateway, router=router) if f.rule == rule_id]


def ids(*devices, gateway=None, router=None):
    return {f.rule for f in found(*devices, gateway=gateway, router=router)}


def test_rules_follow_the_catalog():
    assert [(r.id, r.severity) for r in RULES] == [(i, s) for i, s, _ in CATALOG]
    catalog_ids = tuple(i for i, _, _ in CATALOG)
    assert catalog_ids == RULE_IDS
    assert all(isinstance(r, Rule) and r.severity in SEVERITIES for r in RULES)


def test_rule_lookup():
    assert rule("ssh-open") is RULES[RULE_IDS.index("ssh-open")]
    assert rule("cgnat") is RULES[-1]
    with pytest.raises(KeyError):
        rule("no-such-rule")


def every_rule_network():
    return [
        host(
            Service(23, name="telnet"),
            Service(22, name="ssh"),
            Service(80, name="http", facts={"login": "basic"}),
            Service(443, name="https", tls=True, tls_version="TLSv1"),
            Service(1723, name="pptp"),
            Service(7547, name="cwmp"),
            Service(8291, name="winbox"),
            ip="192.168.1.1",
            kind="router",
            is_gateway=True,
            upnp=UpnpInfo(device_types={IGD}),
        ),
        host(
            Service(21, name="ftp"),
            Service(445, name="smb", facts={"smb1": "yes"}),
            Service(873, name="rsync"),
            Service(2049, name="nfs"),
            Service(2375, name="docker", auth="none"),
            Service(3306, name="mysql"),
            Service(6379, name="redis", auth="none"),
            Service(9200, name="elasticsearch", auth="required"),
            Service(10000, name="webmin"),
            Service(11211, name="memcached"),
            ip="192.168.1.10",
            kind="nas",
        ),
        host(
            Service(554, name="rtsp", auth="none"),
            Service(5900, name="vnc", auth="none"),
            Service(34567, name="dvr"),
            ip="192.168.1.30",
            kind="camera",
        ),
        host(
            Service(1080, name="socks", auth="none"),
            Service(1883, name="mqtt", auth="none"),
            Service(3389, name="rdp"),
            Service(5555, name="adb", auth="none"),
            Service(5900, name="vnc", auth="required"),
            Service(9100, name="jetdirect"),
            ip="192.168.1.40",
        ),
        host(
            Service(5555, name="adb", auth="required"),
            Service(9200, name="elasticsearch", auth="none"),
            ip="192.168.1.50",
            kind="phone",
        ),
        host(ip="192.168.1.60", kind="unknown"),
    ]


def every_rule_router(external_ip):
    return RouterInfo(
        external_ip=external_ip,
        mappings=[
            PortMapping("TCP", 3389, "192.168.1.40", 3389, "Remote Desktop"),
            PortMapping("UDP", 3074, "192.168.1.50", 3074),
        ],
    )


def test_every_finding_has_the_catalog_params_as_strings():
    network = every_rule_network()
    findings = evaluate(network, router=every_rule_router("10.0.0.2"))
    findings += evaluate(network, router=every_rule_router("100.64.0.2"))
    assert {f.rule for f in findings} == set(RULE_IDS)
    params = {i: keys for i, _, keys in CATALOG}
    severities = {i: s for i, s, _ in CATALOG}
    for finding in findings:
        assert set(finding.params) == params[finding.rule], finding.rule
        assert all(isinstance(v, str) for v in finding.params.values())
        assert finding.severity == severities[finding.rule]
        if "port" in finding.params:
            assert finding.params["port"] == str(finding.port)
        elif "internal_port" in finding.params:
            assert finding.params["internal_port"] == str(finding.port)
        else:
            assert finding.port is None


def test_findings_are_sorted_by_severity_address_and_port():
    findings = evaluate(reversed(every_rule_network()))
    ranks = [SEVERITIES.index(f.severity) for f in findings]
    assert ranks == sorted(ranks)
    high = [(f.ip, f.port) for f in findings if f.severity == "high"]
    assert high[:3] == [("192.168.1.1", 23), ("192.168.1.10", 445), ("192.168.1.10", 11211)]
    info = [(f.rule, f.ip, f.port) for f in findings if f.severity == "info"]
    assert info == [
        ("ssh-open", "192.168.1.1", 22),
        ("smb-open", "192.168.1.10", 445),
        ("unknown-device", "192.168.1.60", None),
    ]


def test_addresses_sort_as_numbers():
    devices = [host(Service(23), ip=ip) for ip in ("192.168.1.100", "192.168.1.9", "10.0.0.2")]
    assert [f.ip for f in found(*devices)] == ["10.0.0.2", "192.168.1.9", "192.168.1.100"]


def test_device_level_findings_come_before_ports_and_ties_follow_the_catalog():
    device = host(
        Service(10000, name="webmin", facts={"login": "form"}),
        Service(8291, name="winbox"),
        ip="192.168.1.1",
        is_gateway=True,
        upnp=UpnpInfo(device_types={IGD}),
    )
    assert [(f.rule, f.port) for f in found(device)] == [
        ("upnp-igd", None),
        ("winbox-open", 8291),
        ("webmin-open", 10000),
        ("login-over-http", 10000),
    ]


def test_same_rule_and_port_is_reported_once():
    device = host(Service(23, name="telnet"), Service(23, name="telnet"), Service(2323, "tcp"))
    twin = host(Service(23, name="telnet"))
    findings = found(device, twin)
    assert [(f.rule, f.port) for f in findings] == [("telnet-open", 23)]


def test_rule_apply_works_on_its_own():
    device = host(Service(23, banner="BusyBox v1.31.1 login:"), Service(23))
    findings = rule("telnet-open").apply(device, Context())
    assert len(findings) == 1
    assert findings[0].evidence == "banner: BusyBox v1.31.1 login:"


def test_names_from_the_port_table_count_on_any_port():
    # How the scanner names a port has to match what the rules look for.
    expected = {
        21: "ftp-open",
        22: "ssh-open",
        23: "telnet-open",
        445: "smb-open",
        873: "rsync-open",
        1723: "pptp-open",
        2049: "nfs-open",
        3389: "rdp-open",
        8291: "winbox-open",
        9100: "jetdirect-open",
        10000: "webmin-open",
        11211: "memcached-open",
        34567: "dvr-port-open",
        37777: "dvr-port-open",
    }
    for port, rule_id in expected.items():
        device = host(Service(40000, name=SERVICE_NAMES[port]))
        assert only(rule_id, device), port
    for port in (5900, 5555, 1883, 554, 1080, 6379, 2375, 9200):
        device = host(Service(40000, name=SERVICE_NAMES[port], auth="none"))
        assert found(device), port
    for port in (3306, 5432, 1433, 27017):
        assert only("database-open", host(Service(40000, name=SERVICE_NAMES[port]))), port
    gateway = host(Service(40000, name=SERVICE_NAMES[7547]), is_gateway=True)
    assert only("tr069-open", gateway)


def test_a_protocol_the_rules_know_takes_the_port_from_its_usual_owner():
    assert ids(host(Service(23, name="ssh"))) == {"ssh-open"}
    # "http" says nothing against Docker: its API is HTTP.
    assert ids(host(Service(2375, name="http", auth="none"))) == {"docker-api-open"}
    assert only("telnet-open", host(Service(23, name="")))


def test_udp_ports_are_not_tcp_services():
    assert found(host(Service(2049, protocol="udp"), Service(23, protocol="udp"))) == []


# One test per rule from here on.


def test_telnet_open():
    device = host(Service(23, name="telnet", banner="BusyBox v1.31.1 (2023-01-01) built-in shell"))
    [finding] = found(device)
    assert (finding.rule, finding.severity, finding.ip, finding.port) == (
        "telnet-open",
        "high",
        "192.168.1.20",
        23,
    )
    assert finding.params == {"port": "23"}
    assert finding.evidence == "banner: BusyBox v1.31.1 (2023-01-01) built-in shell"
    assert only("telnet-open", host(Service(2323, name="telnet")))[0].port == 2323
    assert only("telnet-open", host(Service(22, name="ssh"))) == []


def test_ftp_open():
    service = Service(21, name="ftp", banner="220 (vsFTPd 3.0.5)", product="vsftpd 3.0.5")
    [finding] = only("ftp-open", host(service))
    assert finding.severity == "medium"
    assert finding.params == {"port": "21", "product": "vsftpd 3.0.5"}
    assert finding.evidence == "banner: 220 (vsFTPd 3.0.5)"

    anonymous = Service(2121, name="ftp", auth="none")
    [finding] = only("ftp-open", host(anonymous))
    assert finding.params == {"port": "2121", "product": ""}
    assert finding.evidence == "anonymous login accepted"
    assert only("ftp-open", host(Service(20, name="ftp-data"))) == []


def test_vnc_no_auth():
    service = Service(
        5900, name="vnc", banner="RFB 003.008", auth="none", facts={"security": "None"}
    )
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("vnc-no-auth", "critical")
    assert finding.params == {"port": "5900"}
    assert finding.evidence == "banner: RFB 003.008; security types: None"
    assert only("vnc-no-auth", host(Service(5900, name="vnc", auth="required"))) == []
    assert only("vnc-no-auth", host(Service(5901, name="vnc", auth="none")))[0].port == 5901


def test_vnc_open():
    service = Service(
        5900,
        name="vnc",
        banner="RFB 003.008",
        auth="required",
        facts={"security": "VNC Authentication,Tight"},
    )
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("vnc-open", "medium")
    assert finding.params == {"port": "5900"}
    assert finding.evidence == "banner: RFB 003.008; security types: VNC Authentication, Tight"
    # Not probed: the port is still open, but nobody knows about the password.
    assert ids(host(Service(5900))) == {"vnc-open"}
    assert only("vnc-open", host(Service(5900, auth="none"))) == []


def test_rdp_open():
    [finding] = found(host(Service(3389, name="rdp")))
    assert (finding.rule, finding.severity, finding.params) == (
        "rdp-open",
        "medium",
        {"port": "3389"},
    )
    assert finding.evidence is None
    assert only("rdp-open", host(Service(13389, name="rdp")))[0].port == 13389
    assert only("rdp-open", host(Service(3390))) == []


def test_adb_open():
    service = Service(5555, name="adb", auth="none", product="Pixel 7", facts={"state": "device"})
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("adb-open", "critical")
    assert finding.params == {"port": "5555", "product": "Pixel 7"}
    assert finding.evidence == "state: device; product: Pixel 7"
    [bare] = only("adb-open", host(Service(5556, name="adb", auth="none")))
    assert bare.params == {"port": "5556", "product": ""}
    assert bare.evidence is None
    assert only("adb-open", host(Service(5555, auth="required"))) == []


def test_adb_exposed():
    service = Service(5555, name="adb", auth="required", facts={"state": "unauthorized"})
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("adb-exposed", "medium")
    assert finding.params == {"port": "5555"}
    assert finding.evidence == "state: unauthorized"
    assert ids(host(Service(5555))) == {"adb-exposed"}
    assert only("adb-exposed", host(Service(5555, auth="none"))) == []


def test_redis_no_auth():
    service = Service(6379, name="redis", auth="none", product="Redis 7.2.4")
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("redis-no-auth", "critical")
    assert finding.params == {"port": "6379"}
    assert finding.evidence == "product: Redis 7.2.4"
    assert only("redis-no-auth", host(Service(6379, auth="required"))) == []
    assert only("redis-no-auth", host(Service(6379))) == []


def test_docker_api_open():
    service = Service(2375, name="docker", auth="none", product="Docker 27.3.1")
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("docker-api-open", "critical")
    assert finding.params == {"port": "2375", "product": "Docker 27.3.1"}
    assert finding.evidence == "product: Docker 27.3.1"
    assert found(host(Service(2375, name="docker", auth="required"))) == []
    assert found(host(Service(2375))) == []


def test_memcached_open():
    [finding] = found(host(Service(11211, name="memcached", banner="VERSION 1.6.21")))
    assert (finding.rule, finding.severity) == ("memcached-open", "high")
    assert finding.params == {"port": "11211"}
    assert finding.evidence == "banner: VERSION 1.6.21"
    assert only("memcached-open", host(Service(11212))) == []


def test_elasticsearch_no_auth():
    service = Service(9200, name="elasticsearch", auth="none", product="Elasticsearch 8.15.0")
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("elasticsearch-no-auth", "high")
    assert finding.params == {"port": "9200", "product": "Elasticsearch 8.15.0"}
    assert finding.evidence == "product: Elasticsearch 8.15.0"
    assert only("elasticsearch-no-auth", host(Service(9200, auth="required"))) == []


@pytest.mark.parametrize(
    "port, name, label",
    [
        (3306, "mysql", "MySQL"),
        (5432, "postgresql", "PostgreSQL"),
        (1433, "mssql", "SQL Server"),
        (27017, "mongodb", "MongoDB"),
    ],
)
def test_database_open(port, name, label):
    [finding] = found(host(Service(port, name=name, product=f"{label} 1.0")))
    assert (finding.rule, finding.severity) == ("database-open", "medium")
    assert finding.params == {"port": str(port), "service": label}
    assert finding.evidence == f"product: {label} 1.0"

    [unlocked] = found(host(Service(port, auth="none")))
    assert unlocked.params == {"port": str(port), "service": label}
    assert unlocked.evidence == "answered without credentials"
    assert only("database-open", host(Service(port + 1))) == []


def test_database_open_covers_guarded_redis_and_elasticsearch():
    device = host(
        Service(6379, name="redis", auth="required"),
        Service(9200, name="elasticsearch"),
        Service(6380, name="redis", auth="none"),
    )
    findings = only("database-open", device)
    assert [(f.port, f.params["service"]) for f in findings] == [
        (6379, "Redis"),
        (9200, "Elasticsearch"),
    ]


def test_database_open_trusts_the_name_over_the_port():
    [finding] = found(host(Service(6379, name="mysql", auth="none")))
    assert (finding.rule, finding.params["service"]) == ("database-open", "MySQL")


def test_mqtt_anonymous():
    service = Service(1883, name="mqtt", auth="none", facts={"connack": "0"})
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("mqtt-anonymous", "high")
    assert finding.params == {"port": "1883"}
    assert finding.evidence == "CONNACK return code 0"
    refused = Service(1883, name="mqtt", auth="required", facts={"connack": "5"})
    assert found(host(refused)) == []
    assert only("mqtt-anonymous", host(Service(8883, name="mqtt", tls=True, auth="none")))


def test_rtsp_no_auth():
    service = Service(
        554, name="rtsp", auth="none", product="H264DVR 1.0", facts={"describe": "200"}
    )
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("rtsp-no-auth", "high")
    assert finding.params == {"port": "554"}
    assert finding.evidence == "DESCRIBE answered 200; product: H264DVR 1.0"
    locked = Service(554, name="rtsp", auth="required", facts={"describe": "401"})
    assert found(host(locked)) == []
    assert only("rtsp-no-auth", host(Service(8554, name="rtsp", auth="none")))[0].port == 8554


def test_smb1_enabled_comes_with_smb_open():
    device = host(Service(445, name="smb", facts={"smb1": "yes"}))
    findings = found(device)
    assert [(f.rule, f.severity, f.port) for f in findings] == [
        ("smb1-enabled", "high", 445),
        ("smb-open", "info", 445),
    ]
    assert findings[0].params == {"port": "445"}
    assert findings[0].evidence == "server accepts SMB1"
    assert ids(host(Service(445, name="smb", facts={"smb1": "no"}))) == {"smb-open"}
    assert ids(host(Service(445))) == {"smb-open"}


def test_smb1_enabled_once_per_device():
    device = host(
        Service(139, name="netbios-ssn", facts={"smb1": "yes"}),
        Service(445, name="smb", facts={"smb1": "yes"}),
    )
    assert [f.port for f in only("smb1-enabled", device)] == [445]
    alone = host(Service(139, name="netbios-ssn", facts={"smb1": "yes"}))
    assert [f.port for f in only("smb1-enabled", alone)] == [139]


def test_socks_no_auth():
    service = Service(1080, name="socks", auth="none", facts={"version": "5"})
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("socks-no-auth", "high")
    assert finding.params == {"port": "1080"}
    assert finding.evidence == "SOCKS5; no authentication required"
    assert found(host(Service(1080, name="socks", auth="required"))) == []
    assert found(host(Service(1080))) == []


def test_dvr_port_open():
    device = host(Service(34567, name="dvr"), Service(37777, name="dahua-dvr"), kind="camera")
    findings = found(device)
    assert [(f.rule, f.severity, f.params) for f in findings] == [
        ("dvr-port-open", "high", {"port": "34567"}),
        ("dvr-port-open", "high", {"port": "37777"}),
    ]
    assert only("dvr-port-open", host(Service(34568))) == []


@pytest.mark.parametrize(
    "rule_id, severity, port, name",
    [
        ("winbox-open", "medium", 8291, "winbox"),
        ("pptp-open", "medium", 1723, "pptp"),
        ("webmin-open", "medium", 10000, "webmin"),
        ("nfs-open", "medium", 2049, "nfs"),
        ("jetdirect-open", "low", 9100, "jetdirect"),
        ("smb-open", "info", 445, "smb"),
    ],
)
def test_port_rules(rule_id, severity, port, name):
    for service in (Service(port), Service(port, name=name), Service(port + 7, name=name)):
        [finding] = only(rule_id, host(service))
        assert (finding.severity, finding.port) == (severity, service.port)
        assert finding.params == {"port": str(service.port)}
    [labeled] = found(host(Service(port, banner="hello there")))
    assert labeled.evidence == "banner: hello there"
    assert only(rule_id, host(Service(port + 1))) == []


def test_rsync_open():
    service = Service(873, name="rsync", banner="@RSYNCD: 31.0", facts={"modules": "3"})
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("rsync-open", "medium")
    assert finding.params == {"port": "873", "modules": "3"}
    assert finding.evidence == "banner: @RSYNCD: 31.0; 3 modules listed"

    one = Service(873, name="rsync", facts={"modules": "1"})
    assert found(host(one))[0].evidence == "1 module listed"
    for facts in ({}, {"modules": "0"}, {"modules": "lots"}, {"modules": "-1"}):
        [finding] = found(host(Service(8730, name="rsync", facts=facts)))
        assert finding.params == {"port": "8730", "modules": "0"}
        assert finding.evidence is None
    assert only("rsync-open", host(Service(874))) == []


def test_login_over_http_once_per_device():
    device = host(
        Service(8080, name="http", product="lighttpd/1.4.59", facts={"login": "form"}),
        Service(80, name="http", facts={"login": "basic"}),
        Service(81, name="http", facts={"status": "200"}),
    )
    [finding] = found(device)
    assert (finding.rule, finding.severity, finding.port) == ("login-over-http", "medium", 80)
    assert finding.params == {"port": "80"}
    assert finding.evidence == "HTTP Basic authentication"

    form = host(Service(8080, name="http", product="lighttpd/1.4.59", facts={"login": "form"}))
    assert found(form)[0].evidence == "login form; server: lighttpd/1.4.59"
    digest = host(Service(8000, name="http", facts={"login": "digest"}))
    assert found(digest)[0].evidence == "HTTP Digest authentication"


def test_login_over_http_needs_plain_http_and_a_login():
    over_tls = Service(443, name="https", tls=True, tls_version="TLSv1.3", facts={"login": "form"})
    no_login = Service(80, name="http", facts={"status": "200"})
    odd = Service(8080, name="http", facts={"login": "token"})
    assert found(host(over_tls, no_login, odd)) == []
    # Another device gets its own.
    a = host(Service(80, name="http", facts={"login": "form"}), ip="192.168.1.2")
    b = host(Service(80, name="http", facts={"login": "form"}), ip="192.168.1.3")
    assert [f.ip for f in found(a, b)] == ["192.168.1.2", "192.168.1.3"]


def test_old_tls():
    device = host(
        Service(443, name="https", tls=True, tls_version="TLSv1"),
        Service(8443, name="https", tls=True, tls_version="TLSv1.1"),
        Service(9443, name="https", tls=True, tls_version="TLSv1.2"),
        Service(993, name="imaps", tls=True, tls_version="TLSv1.3"),
    )
    findings = found(device)
    assert [(f.rule, f.severity, f.params, f.evidence) for f in findings] == [
        ("old-tls", "low", {"port": "443", "version": "TLSv1"}, "TLSv1"),
        ("old-tls", "low", {"port": "8443", "version": "TLSv1.1"}, "TLSv1.1"),
    ]


def test_upnp_igd_on_the_gateway_only():
    upnp = UpnpInfo(
        device_types={IGD, "urn:schemas-upnp-org:device:WANDevice:1"},
        services=[UpnpService(WAN_IP, "http://192.168.1.1:5000/ctl/IPConn")],
    )
    gateway = host(ip="192.168.1.1", kind="router", is_gateway=True, upnp=upnp)
    [finding] = found(gateway)
    assert (finding.rule, finding.severity, finding.port) == ("upnp-igd", "medium", None)
    assert finding.params == {}
    assert finding.evidence == "InternetGatewayDevice:1; services: WANIPConnection:1"

    by_argument = host(ip="192.168.1.1", kind="router", upnp=upnp)
    assert ids(by_argument, gateway="192.168.1.1") == {"upnp-igd"}
    assert found(by_argument) == []
    assert found(by_argument, gateway="192.168.1.254") == []
    plain = UpnpInfo(device_types={"urn:schemas-upnp-org:device:MediaServer:1"})
    assert found(host(ip="192.168.1.1", is_gateway=True, upnp=plain)) == []
    assert found(host(ip="192.168.1.1", is_gateway=True)) == []


def test_tr069_open_on_the_gateway_only():
    service = Service(7547, name="cwmp", product="RomPager/4.07")
    [finding] = found(host(service, ip="192.168.1.1", kind="router", is_gateway=True))
    assert (finding.rule, finding.severity) == ("tr069-open", "low")
    assert finding.params == {"port": "7547"}
    assert finding.evidence == "product: RomPager/4.07"
    assert ids(host(Service(7547), ip="192.168.1.1"), gateway="192.168.1.1") == {"tr069-open"}
    assert found(host(Service(7547), ip="192.168.1.5"), gateway="192.168.1.1") == []


def test_ssh_open():
    service = Service(22, name="ssh", banner="SSH-2.0-OpenSSH_9.6", product="OpenSSH 9.6")
    [finding] = found(host(service))
    assert (finding.rule, finding.severity) == ("ssh-open", "info")
    assert finding.params == {"port": "22", "product": "OpenSSH 9.6"}
    assert finding.evidence == "banner: SSH-2.0-OpenSSH_9.6"
    [other] = found(host(Service(2222, name="ssh")))
    assert other.params == {"port": "2222", "product": ""}
    assert found(host(Service(2222))) == []


def test_unknown_device_but_not_this_computer():
    [finding] = found(host(ip="192.168.1.77", kind="unknown", vendor="Espressif"))
    assert (finding.rule, finding.severity, finding.port) == ("unknown-device", "info", None)
    assert finding.params == {}
    assert finding.evidence == "vendor: Espressif"
    assert found(host(kind="unknown"))[0].evidence is None
    assert found(host(kind="unknown", is_self=True)) == []
    assert found(host(kind="printer")) == []


def test_web_services_show_the_server_header():
    service = Service(10000, name="http", product="MiniServ/2.105", banner="HTTP/1.0 200 OK")
    assert found(host(service))[0].evidence == "server: MiniServ/2.105"


def test_hostile_text_is_cleaned_and_capped():
    banner = "evil\x1b[31m\r\n‮banner\x00" + "A" * 5000
    product = "x\ny" + "B" * 500
    device = host(Service(22, name="ssh", banner=banner, product=product))
    [finding] = found(device)
    assert len(finding.evidence) <= MAX_EVIDENCE
    assert finding.evidence.startswith("banner: evil [31m banner")
    assert all(ch.isprintable() for ch in finding.evidence)
    assert finding.params["product"].startswith("x yBBB")
    assert len(finding.params["product"]) <= 80


def test_rules_never_mention_the_device_name():
    device = host(Service(23, name="telnet"), ip="192.168.1.8", kind="unknown", dns_name="kitchen")
    for finding in found(device):
        assert "kitchen" not in (finding.evidence or "")
        assert "kitchen" not in "".join(finding.params.values())


# The router rules.

RISKY = (21, 23, 135, 139, 445, 554, 1433, 2375, 3306, 3389, 5432, 5555, 5900, 6379)
RISKY += (9200, 11211, 27017, 34567, 37777)
PUBLIC = "203.0.113.7"


def gateway_device(*services):
    return host(*services, ip="192.168.1.1", kind="router", is_gateway=True)


def forward(external, internal, client="192.168.1.20", protocol="TCP", **kwargs):
    return PortMapping(protocol, external, client, internal, **kwargs)


def router(*mappings, external_ip=PUBLIC, **kwargs):
    return RouterInfo(external_ip=external_ip, mappings=list(mappings), **kwargs)


def forwards(*mappings, devices=None):
    """The port forward findings for these mappings on a small network."""
    devices = devices if devices is not None else [gateway_device(), host()]
    findings = evaluate(devices, router=router(*mappings))
    return [f for f in findings if f.rule.startswith("port-forward")]


def test_port_forward_risky():
    mapping = forward(3389, 3389, description="Remote Desktop")
    [finding] = forwards(mapping)
    assert (finding.rule, finding.severity, finding.ip, finding.port) == (
        "port-forward-risky",
        "high",
        "192.168.1.20",
        3389,
    )
    assert finding.params == {
        "external_port": "3389",
        "internal_port": "3389",
        "protocol": "TCP",
        "description": "Remote Desktop",
    }
    assert finding.evidence == "TCP 3389 to 192.168.1.20:3389 (Remote Desktop)"


@pytest.mark.parametrize("port", RISKY)
def test_every_risky_port(port):
    [finding] = forwards(forward(40000, port))
    assert (finding.rule, finding.port) == ("port-forward-risky", port)


def test_the_internal_port_decides_what_is_risky():
    [finding] = forwards(forward(3389, 8080))
    assert (finding.rule, finding.port) == ("port-forward", 8080)
    [finding] = forwards(forward(8080, 3389))
    assert (finding.rule, finding.port) == ("port-forward-risky", 3389)


def test_port_forward():
    [finding] = forwards(forward(3074, 3074, client="192.168.1.20", protocol="udp"))
    assert (finding.rule, finding.severity, finding.ip, finding.port) == (
        "port-forward",
        "low",
        "192.168.1.20",
        3074,
    )
    assert finding.params == {
        "external_port": "3074",
        "internal_port": "3074",
        "protocol": "UDP",
        "description": "",
    }
    assert finding.evidence == "UDP 3074 to 192.168.1.20:3074"


def test_no_router_no_router_findings():
    assert forwards() == []
    devices = [gateway_device(), host(Service(23, name="telnet"))]
    without = evaluate(devices)
    assert evaluate(devices, router=None) == without
    assert evaluate(devices, router=RouterInfo()) == without
    assert [f.rule for f in without] == ["telnet-open"]


def test_disabled_forwards_raise_nothing():
    mappings = [forward(3389, 3389, enabled=False), forward(8080, 80, enabled=False)]
    assert forwards(*mappings) == []


def test_identical_forwards_count_once():
    mapping = forward(8080, 80, description="web")
    twin = forward(8080, 80, description="web")
    assert len(forwards(mapping, twin)) == 1
    # A router that lists one forward with a new description or lease is still one forward.
    assert len(forwards(mapping, forward(8080, 80, description="other", lease=60))) == 1


def test_each_forward_is_its_own_finding():
    findings = forwards(
        forward(8081, 80),
        forward(8080, 80),
        forward(3074, 3074, protocol="UDP"),
        forward(3074, 3074, protocol="TCP"),
    )
    assert [(f.port, f.params["protocol"], f.params["external_port"]) for f in findings] == [
        (80, "TCP", "8080"),
        (80, "TCP", "8081"),
        (3074, "TCP", "3074"),
        (3074, "UDP", "3074"),
    ]


def test_forward_to_an_unknown_client_goes_on_the_gateway():
    [finding] = forwards(forward(8080, 80, client="192.168.1.99"))
    assert (finding.ip, finding.port) == ("192.168.1.1", 80)
    assert finding.evidence == "TCP 8080 to 192.168.1.99:80"
    [odd] = forwards(forward(2323, 23, client="cam\x00era\x1b[0m"))
    assert (odd.rule, odd.ip, odd.port) == ("port-forward-risky", "192.168.1.1", 23)
    assert odd.evidence == "TCP 2323 to cam era [0m:23"
    [empty] = forwards(forward(8080, 80, client=""))
    assert empty.ip == "192.168.1.1"


def test_forward_to_the_gateway_itself_is_reported_once():
    [finding] = forwards(forward(8443, 443, client="192.168.1.1"))
    assert (finding.ip, finding.port) == ("192.168.1.1", 443)


def test_forward_client_matches_the_device_in_any_spelling():
    devices = [gateway_device(), host(ip="fd00::20")]
    [finding] = forwards(forward(8080, 80, client="fd00:0:0::20"), devices=devices)
    assert finding.ip == "fd00::20"
    assert finding.evidence == "TCP 8080 to [fd00::20]:80"


def test_router_findings_without_a_listed_gateway():
    mappings = [forward(8080, 80, client="192.168.1.99"), forward(3389, 3389)]
    info = router(*mappings, external_ip="10.0.0.2")
    findings = evaluate([host()], gateway="192.168.1.1", router=info)
    assert [(f.rule, f.ip, f.port) for f in findings] == [
        ("port-forward-risky", "192.168.1.20", 3389),
        ("port-forward", "192.168.1.1", 80),
        ("double-nat", "192.168.1.1", None),
    ]
    # Nothing to put them on: only the forward to a known device is left.
    findings = evaluate([host()], router=info)
    assert [(f.rule, f.ip) for f in findings] == [("port-forward-risky", "192.168.1.20")]


def test_a_device_listed_twice_gets_its_forward_once():
    findings = forwards(forward(8080, 80), devices=[gateway_device(), host(), host()])
    assert len(findings) == 1


def test_remote_host_shows_in_the_evidence():
    [finding] = forwards(forward(22, 22, remote_host="198.51.100.4"))
    assert finding.evidence == "TCP 22 to 192.168.1.20:22; only from: 198.51.100.4"


def test_forward_text_from_the_router_is_cleaned_and_capped():
    mapping = forward(
        8080,
        80,
        protocol="tcp\x00‮" + "P" * 50,
        description="‮hostile\r\n\x1b[31m" + "D" * 500,
        remote_host="r" * 500,
    )
    [finding] = forwards(mapping)
    assert finding.params["protocol"] == "TCP PPPP"
    assert finding.params["description"].startswith("hostile [31mDDD")
    assert len(finding.params["description"]) <= 80
    assert len(finding.evidence) <= MAX_EVIDENCE
    for text in (*finding.params.values(), finding.evidence):
        assert all(ch.isprintable() for ch in text)


@pytest.mark.parametrize(
    "external, internal",
    [(8080, 0), (8080, 65536), (8080, -1), (8080, True), (-1, 80), (70000, 80), ("x", 80)],
)
def test_forwards_with_impossible_ports_are_skipped(external, internal):
    assert forwards(forward(external, internal)) == []


def test_ports_as_text_and_external_port_zero():
    [finding] = forwards(forward("8080", "80"))
    assert finding.params["external_port"] == "8080" and finding.port == 80
    [wildcard] = forwards(forward(0, 80))
    assert wildcard.params["external_port"] == "0"


def test_garbage_in_the_mapping_list_is_ignored():
    info = router("not a mapping", None, forward(8080, 80))
    findings = evaluate([gateway_device(), host()], router=info)
    assert [f.rule for f in findings] == ["port-forward"]
    assert evaluate([gateway_device()], router=RouterInfo(mappings="nonsense")) == []


def test_a_huge_mapping_list_is_capped():
    mappings = [forward(port, 8000) for port in range(1, 3001)]
    findings = forwards(*mappings)
    assert len(findings) == MAX_FORWARDS


@pytest.mark.parametrize(
    "external_ip, rule_id",
    [
        ("10.0.0.2", "double-nat"),
        ("10.255.255.254", "double-nat"),
        ("172.16.0.1", "double-nat"),
        ("172.31.255.1", "double-nat"),
        ("192.168.0.10", "double-nat"),
        ("100.64.0.1", "cgnat"),
        ("100.127.255.254", "cgnat"),
        (" 100.100.1.2 ", "cgnat"),
        ("::ffff:10.0.0.2", "double-nat"),
    ],
)
def test_double_nat_and_cgnat(external_ip, rule_id):
    info = RouterInfo(external_ip=external_ip, connection="IP_Routed")
    [finding] = found(gateway_device(), host(), router=info)
    assert (finding.rule, finding.ip, finding.port) == (rule_id, "192.168.1.1", None)
    address = external_ip.strip().removeprefix("::ffff:")
    assert finding.params == {"external_ip": address}
    assert finding.evidence == f"external IP: {address}; connection: IP_Routed"


@pytest.mark.parametrize(
    "external_ip",
    [
        PUBLIC,
        "172.32.0.1",
        "100.128.0.1",
        "100.63.255.255",
        "0.0.0.0",
        "169.254.10.1",
        "2001:db8::1",
        "fd00::1",
        "",
        None,
        "10.0.0.2 extra",
        "10.0.0.2\x00junk",
        "1" * 5000,
    ],
)
def test_no_nat_finding_for_other_addresses(external_ip):
    assert found(gateway_device(), router=RouterInfo(external_ip=external_ip)) == []


def test_nat_findings_go_on_the_gateway_only():
    info = RouterInfo(external_ip="10.0.0.2")
    assert found(host(), router=info) == []
    assert ids(gateway_device(), router=info) == {"double-nat"}
    assert ids(host(ip="192.168.1.1"), gateway="192.168.1.1", router=info) == {"double-nat"}
    [finding] = only("double-nat", gateway_device(), router=info)
    assert finding.evidence == "external IP: 10.0.0.2"


def test_router_findings_join_the_usual_order():
    gateway = gateway_device(Service(7547, name="cwmp"))
    camera = host(Service(554, name="rtsp", auth="none"), ip="192.168.1.30", kind="camera")
    pc = host(Service(22, name="ssh"), ip="192.168.1.20")
    info = router(
        forward(3074, 3074, client="192.168.1.20", protocol="UDP"),
        forward(8554, 554, client="192.168.1.30"),
        forward(2222, 22, client="192.168.1.20"),
        forward(8080, 80, client="192.168.1.99"),
        external_ip="100.70.1.2",
    )
    findings = evaluate([pc, camera, gateway], router=info)
    assert [(f.rule, f.ip, f.port) for f in findings] == [
        ("rtsp-no-auth", "192.168.1.30", 554),
        ("port-forward-risky", "192.168.1.30", 554),
        ("port-forward", "192.168.1.1", 80),
        ("tr069-open", "192.168.1.1", 7547),
        ("port-forward", "192.168.1.20", 22),
        ("port-forward", "192.168.1.20", 3074),
        ("cgnat", "192.168.1.1", None),
        ("ssh-open", "192.168.1.20", 22),
    ]


def test_router_rules_work_on_their_own():
    info = router(forward(8080, 80), forward(2323, 23, client="192.168.1.99"))
    context = Context(router=info, addresses=frozenset({"192.168.1.20"}))
    [finding] = rule("port-forward").apply(host(), context)
    assert finding.ip == "192.168.1.20"
    assert rule("port-forward-risky").apply(host(), context) == []
    [risky] = rule("port-forward-risky").apply(gateway_device(), context)
    assert (risky.ip, risky.port) == ("192.168.1.1", 23)
    assert rule("double-nat").apply(gateway_device(), context) == []
