import asyncio
import math
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

import pytest

from hearthscan import http, router
from hearthscan.http import HttpError, Response
from hearthscan.models import Device, PortMapping, RouterInfo, UpnpInfo, UpnpService
from hearthscan.router import (
    MAX_MAPPINGS,
    MAX_RESPONSE,
    MAX_TEXT,
    READ_ACTIONS,
    REQUEST_TIMEOUT,
    WAN_SERVICES,
    SoapError,
    UpnpError,
    call,
    parse_response,
    query,
    wan_service,
)

DATA = Path(__file__).parent / "data"

IP2, IP1, PPP = WAN_SERVICES
L3F = "urn:schemas-upnp-org:service:Layer3Forwarding:1"
COMMON = "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"
ENVELOPE = "http://schemas.xmlsoap.org/soap/envelope/"
ENCODING = "http://schemas.xmlsoap.org/soap/encoding/"
CONTROL = "http://192.168.1.1:5000/ctl/IPConn"
INFO_ACTIONS = ("GetExternalIPAddress", "GetStatusInfo", "GetConnectionTypeInfo")
ENTRY = "GetGenericPortMappingEntry"


def fixture(name: str) -> bytes:
    return (DATA / name).read_bytes()


def ok(body: bytes, status: int = 200, truncated: bool = False) -> Response:
    headers = {"content-type": 'text/xml; charset="utf-8"'}
    return Response(CONTROL, status, "OK", headers, body, truncated)


def soap(action: str, fields: dict[str, str], service: str = IP1) -> bytes:
    """An answer the way miniupnpd writes it."""
    args = "".join(f"<{name}>{escape(value)}</{name}>" for name, value in fields.items())
    return (
        '<?xml version="1.0"?>\r\n'
        f'<s:Envelope xmlns:s="{ENVELOPE}" s:encodingStyle="{ENCODING}"><s:Body>'
        f'<u:{action}Response xmlns:u="{service}">{args}</u:{action}Response>'
        "</s:Body></s:Envelope>\r\n"
    ).encode()


def fault(code: int | str, description: str = "Error") -> Response:
    detail = "" if code == "" else f"<errorCode>{code}</errorCode>"
    body = (
        '<?xml version="1.0"?>\r\n'
        f'<s:Envelope xmlns:s="{ENVELOPE}" s:encodingStyle="{ENCODING}"><s:Body>'
        "<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>"
        '<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">'
        f"{detail}<errorDescription>{description}</errorDescription>"
        "</UPnPError></detail></s:Fault></s:Body></s:Envelope>\r\n"
    ).encode()
    return ok(body, 500)


def entry(
    external: str | int,
    internal: str | int,
    client: str,
    protocol: str = "TCP",
    description: str = "",
    enabled: str = "1",
    lease: str = "0",
    remote: str = "",
    service: str = IP1,
) -> bytes:
    return soap(
        ENTRY,
        {
            "NewRemoteHost": remote,
            "NewExternalPort": str(external),
            "NewProtocol": protocol,
            "NewInternalPort": str(internal),
            "NewInternalClient": client,
            "NewEnabled": enabled,
            "NewPortMappingDescription": description,
            "NewLeaseDuration": lease,
        },
        service,
    )


def info_answers(external="203.0.113.45", status="Connected", uptime="600", kind="IP_Routed"):
    return {
        "GetExternalIPAddress": soap("GetExternalIPAddress", {"NewExternalIPAddress": external}),
        "GetStatusInfo": soap(
            "GetStatusInfo",
            {
                "NewConnectionStatus": status,
                "NewLastConnectionError": "ERROR_NONE",
                "NewUptime": uptime,
            },
        ),
        "GetConnectionTypeInfo": soap("GetConnectionTypeInfo", {"NewConnectionType": kind}),
    }


MINIUPNPD = {
    "GetExternalIPAddress": fixture("router_miniupnpd_ip.xml"),
    "GetStatusInfo": fixture("router_miniupnpd_status.xml"),
    "GetConnectionTypeInfo": fixture("router_miniupnpd_type.xml"),
}


async def hang(timeout):
    await asyncio.sleep(timeout)  # what the real fetch does before giving up
    raise TimeoutError


def slow(body: bytes, delay: float):
    async def answer(timeout):
        await asyncio.sleep(min(delay, timeout))
        if delay > timeout:
            raise TimeoutError
        return ok(body)

    return answer


@dataclass
class Sent:
    url: str
    service: str
    action: str
    arguments: dict[str, str]
    headers: dict[str, str]
    body: bytes
    timeout: float
    limit: int


def read_request(body: bytes) -> tuple[str, str, dict[str, str]]:
    """The service type, action and arguments of a SOAP request, checked on the way."""
    root = ET.fromstring(body)
    assert root.tag == f"{{{ENVELOPE}}}Envelope"
    assert root.get(f"{{{ENVELOPE}}}encodingStyle") == ENCODING
    (soap_body,) = list(root)
    assert soap_body.tag == f"{{{ENVELOPE}}}Body"
    (element,) = list(soap_body)
    service, _, action = element.tag[1:].partition("}")
    arguments = {}
    for child in element:
        assert "}" not in child.tag  # arguments have no namespace
        arguments[child.tag] = child.text or ""
    return service, action, arguments


class FakeRouter:
    """Answers SOAP requests like a router would.

    `answers` maps an action to its answer, `entries` gives the answer to
    GetGenericPortMappingEntry by index (a list, or a function of the index),
    and `end` is the answer past the end of a list. An answer is bytes (a 200
    with that body), a Response, an exception to raise, or a coroutine
    function that gets the request timeout. Every request is checked: only
    read actions, a SOAPAction header that matches the body.
    """

    def __init__(self, answers=None, entries=(), end=None):
        self.answers = answers or {}
        self.entries = entries
        self.end = end if end is not None else fault(713, "SpecifiedArrayIndexInvalid")
        self.sent: list[Sent] = []

    async def fetch(self, url, *, method="GET", headers=None, body=None, timeout=3.0, limit=0):
        service, action, arguments = read_request(body)
        assert method == "POST"
        assert action in READ_ACTIONS
        assert service in WAN_SERVICES
        assert headers == {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service}#{action}"',
        }
        self.sent.append(Sent(url, service, action, arguments, headers, body, timeout, limit))
        if action == ENTRY:
            text = arguments.get("NewPortMappingIndex", "")
            index = int(text) if text.isdigit() else None
            if index is None:
                answer = self.end
            elif callable(self.entries):
                answer = self.entries(index)
            else:
                answer = self.entries[index] if index < len(self.entries) else self.end
        else:
            answer = self.answers.get(action, fault(401, "Invalid Action"))
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return await answer(timeout)
        return answer if isinstance(answer, Response) else ok(answer)

    def actions(self) -> list[str]:
        return [sent.action for sent in self.sent]

    def indexes(self) -> list[int]:
        return [int(s.arguments["NewPortMappingIndex"]) for s in self.sent if s.action == ENTRY]


def install(monkeypatch, routers):
    """`routers` is one FakeRouter, or control URL -> FakeRouter."""

    async def fetch(url, **kwargs):
        target = routers[url] if isinstance(routers, dict) else routers
        return await target.fetch(url, **kwargs)

    monkeypatch.setattr(http, "fetch", fetch)


def service(service_type: str = IP1, url: str = CONTROL) -> UpnpService:
    return UpnpService(service_type, url, None)


def gateway(*services: UpnpService, ip: str = "192.168.1.1") -> Device:
    return Device(ip, upnp=UpnpInfo(services=list(services)), is_gateway=True)


def run_query(device, timeout=4.0):
    return asyncio.run(query(device, timeout=timeout))


# The services and the actions


def test_only_the_four_reading_actions_are_allowed():
    assert sorted(READ_ACTIONS) == [
        "GetConnectionTypeInfo",
        "GetExternalIPAddress",
        "GetGenericPortMappingEntry",
        "GetStatusInfo",
    ]
    assert isinstance(READ_ACTIONS, frozenset)
    assert WAN_SERVICES == (
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    )


def test_wan_service_prefers_the_newest_ip_connection():
    ppp = service(PPP, "http://192.168.1.1:5000/ctl/PPPConn")
    v1 = service(IP1)
    v2 = service(IP2, "http://192.168.1.1:5000/ctl/IPConn2")
    other = service(L3F, "http://192.168.1.1:5000/ctl/L3F")
    assert wan_service(gateway(other, ppp, v1, v2)) == v2
    assert wan_service(gateway(other, ppp, v1)) == v1
    assert wan_service(gateway(ppp, other)) == ppp


def test_wan_service_needs_a_control_url_on_the_device_itself():
    elsewhere = service(IP2, "http://192.168.1.2:5000/ctl/IPConn")
    here = service(IP1)
    assert wan_service(gateway(elsewhere, here)) == here
    assert wan_service(gateway(elsewhere)) is None
    for url in (
        "http://router.lan:5000/ctl/IPConn",
        "ftp://192.168.1.1/ctl/IPConn",
        "http://[::1/ctl",
        "/ctl/IPConn",
        "",
    ):
        assert wan_service(gateway(service(IP1, url))) is None, url
    mapped = service(IP1, "http://[::ffff:192.168.1.1]:5000/ctl/IPConn")
    assert wan_service(gateway(mapped)) == mapped
    assert wan_service(gateway(service(IP1, "https://192.168.1.1:5443/ctl"))) is not None


def test_wan_service_without_upnp_or_a_wan_service_is_none():
    assert wan_service(Device("192.168.1.1")) is None
    assert wan_service(gateway(service(L3F), service(COMMON))) is None
    assert wan_service(gateway(service("urn:schemas-upnp-org:service:WANIPConnection:3"))) is None
    assert wan_service(gateway(service(IP1), ip="not an address")) is None


# Whole routers


def test_query_reads_a_miniupnpd_router(monkeypatch):
    fake = FakeRouter(
        MINIUPNPD,
        [
            fixture("router_miniupnpd_entry.xml"),
            entry(3389, 3389, "192.168.1.40", description="Remote desktop", lease="7200"),
            entry(8080, 80, "192.168.1.50", protocol="UDP", enabled="0"),
        ],
        end=ok(fixture("router_miniupnpd_fault_713.xml"), 500),
    )
    install(monkeypatch, fake)
    info = run_query(gateway(service(L3F, "http://192.168.1.1:5000/ctl/L3F"), service()))
    assert info == RouterInfo(
        external_ip="203.0.113.45",
        connection="IP_Routed",
        status="Connected",
        uptime=86523,
        mappings=[
            PortMapping("TCP", 51413, "192.168.1.20", 51413, "Torrent client at 51413"),
            PortMapping("TCP", 3389, "192.168.1.40", 3389, "Remote desktop", lease=7200),
            PortMapping("UDP", 8080, "192.168.1.50", 80, enabled=False),
        ],
        mappings_complete=True,
    )
    assert sorted(fake.actions()[:3]) == sorted(INFO_ACTIONS)
    assert fake.actions()[3:] == [ENTRY] * 4
    assert fake.indexes() == [0, 1, 2, 3]
    assert {sent.url for sent in fake.sent} == {CONTROL}
    assert {sent.service for sent in fake.sent} == {IP1}
    assert all(sent.limit == MAX_RESPONSE for sent in fake.sent)
    assert all(0 < sent.timeout <= REQUEST_TIMEOUT for sent in fake.sent)


def test_requests_are_soap_envelopes_with_a_matching_soapaction(monkeypatch):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    with pytest.raises(UpnpError) as caught:
        asyncio.run(call(service(), ENTRY, {"NewPortMappingIndex": "7"}))
    assert caught.value.code == 713
    (sent,) = fake.sent
    assert sent.url == CONTROL
    assert sent.headers == {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"',
    }
    assert sent.body == (
        b'<?xml version="1.0" encoding="utf-8"?>\r\n'
        b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        b's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        b'<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        b"<NewPortMappingIndex>7</NewPortMappingIndex></u:GetGenericPortMappingEntry>"
        b"</s:Body></s:Envelope>\r\n"
    )


def test_actions_without_arguments_send_an_empty_element(monkeypatch):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    answer = asyncio.run(call(service(), "GetExternalIPAddress"))
    assert answer == {"NewExternalIPAddress": "203.0.113.45"}
    (sent,) = fake.sent
    assert b"<u:GetExternalIPAddress xmlns:u=" in sent.body
    assert b"></u:GetExternalIPAddress></s:Body>" in sent.body
    assert sent.arguments == {}


def test_query_reads_a_fritzbox_style_ppp_connection(monkeypatch):
    url = "http://192.168.178.1:49000/igdupnp/control/WANPPPConn1"
    fake = FakeRouter(
        {
            "GetExternalIPAddress": fixture("router_fritz_ip.xml"),
            "GetStatusInfo": fixture("router_fritz_status.xml"),
            "GetConnectionTypeInfo": fixture("router_fritz_type.xml"),
        },
        [fixture("router_fritz_entry.xml")],
        end=ok(fixture("router_fritz_fault_713.xml"), 500),
    )
    install(monkeypatch, fake)
    device = gateway(
        service(COMMON, "http://192.168.178.1:49000/igdupnp/control/WANCommonIFC1"),
        service(PPP, url),
        ip="192.168.178.1",
    )
    info = run_query(device)
    assert info == RouterInfo(
        external_ip="100.72.14.9",
        connection="IP_Routed",
        status="Connected",
        uptime=351217,
        mappings=[PortMapping("UDP", 3074, "192.168.178.31", 3074, "Game console", lease=3540)],
        mappings_complete=True,
    )
    assert {sent.service for sent in fake.sent} == {PPP}
    assert {sent.url for sent in fake.sent} == {url}


def test_no_mappings_ends_with_713_at_index_zero(monkeypatch):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info.mappings == [] and info.mappings_complete is True
    assert fake.indexes() == [0]


def test_714_also_ends_the_list(monkeypatch):
    fake = FakeRouter(
        MINIUPNPD,
        [entry(443, 443, "192.168.1.60")],
        end=ok(fixture("router_fault_714.xml"), 500),
    )
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info.mappings == [PortMapping("TCP", 443, "192.168.1.60", 443)]
    assert info.mappings_complete is True


def test_a_router_that_repeats_the_last_entry_forever(monkeypatch):
    entries = [entry(22, 22, "192.168.1.10"), entry(80, 80, "192.168.1.11")]
    fake = FakeRouter(MINIUPNPD, lambda index: entries[min(index, len(entries) - 1)])
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert [m.external_port for m in info.mappings] == [22, 80]
    assert info.mappings_complete is True
    assert fake.indexes() == [0, 1, 2]


def test_the_same_entry_twice_in_a_row_is_the_end_even_after_a_skipped_one(monkeypatch):
    bad = entry(0, 22, "192.168.1.10")
    fake = FakeRouter(MINIUPNPD, [entry(80, 80, "192.168.1.11"), bad, bad, bad])
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert [m.external_port for m in info.mappings] == [80]
    assert info.mappings_complete is True
    assert fake.indexes() == [0, 1, 2]


def test_a_router_that_never_answers(monkeypatch):
    fake = FakeRouter(dict.fromkeys(INFO_ACTIONS, hang), lambda index: hang)
    install(monkeypatch, fake)
    started = time.perf_counter()
    info = run_query(gateway(service()), timeout=0.3)
    assert time.perf_counter() - started < 1.0
    assert info == RouterInfo(mappings_complete=False)
    assert sorted(fake.actions()) == sorted(INFO_ACTIONS)  # no time was left for the list


def test_garbage_answers_leave_the_fields_empty(monkeypatch):
    fake = FakeRouter(
        {
            "GetExternalIPAddress": fixture("router_malformed.xml"),
            "GetStatusInfo": fixture("router_dtd.xml"),
            "GetConnectionTypeInfo": fixture("router_miniupnpd_type.xml"),
        },
        [b"<html><body>Not Found</body></html>"],
    )
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info == RouterInfo(connection="IP_Routed", mappings_complete=False)


def test_oversized_answers_are_refused(monkeypatch):
    big = soap(
        "GetExternalIPAddress", {"NewExternalIPAddress": "203.0.113.45", "Pad": "x" * 70_000}
    )
    fake = FakeRouter(
        {
            "GetExternalIPAddress": ok(big[:MAX_RESPONSE], truncated=True),
            "GetStatusInfo": fixture("router_miniupnpd_status.xml"),
        },
        [ok(fixture("router_miniupnpd_entry.xml"), truncated=True)],
    )
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info.external_ip is None
    assert info.status == "Connected"
    assert info.mappings == [] and info.mappings_complete is False
    with pytest.raises(SoapError, match="over"):
        asyncio.run(call(service(), "GetExternalIPAddress"))


def test_one_failing_question_does_not_stop_the_others(monkeypatch):
    fake = FakeRouter(
        {
            "GetExternalIPAddress": HttpError("malformed status line"),
            "GetStatusInfo": ConnectionResetError(),
            "GetConnectionTypeInfo": fixture("router_miniupnpd_type.xml"),
        },
        [fixture("router_miniupnpd_entry.xml")],
    )
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info.external_ip is None and info.status is None and info.uptime is None
    assert info.connection == "IP_Routed"
    assert len(info.mappings) == 1 and info.mappings_complete is True


def test_faults_with_other_codes(monkeypatch):
    answers = dict(MINIUPNPD, GetConnectionTypeInfo=fault(401, "Invalid Action"))
    fake = FakeRouter(answers, [entry(80, 80, "192.168.1.11"), fault(501, "Action Failed")])
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info.connection is None
    assert info.external_ip == "203.0.113.45" and info.uptime == 86523
    # The list stopped for some other reason than its end.
    assert len(info.mappings) == 1 and info.mappings_complete is False
    assert fake.indexes() == [0, 1]


def test_a_router_that_will_not_list_its_mappings(monkeypatch):
    fake = FakeRouter(MINIUPNPD, end=fault(606, "Action not authorized"))
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info.mappings == [] and info.mappings_complete is False


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError(),
        ConnectionRefusedError(),
        HttpError("connection closed without an answer"),
        ok(b"", 404),
        ok(b"<html>Internal error</html>", 500),
        fault("", "no code"),
        fault("abc", "not a number"),
    ],
)
def test_other_failures_cut_the_list_short(monkeypatch, failure):
    fake = FakeRouter(MINIUPNPD, [entry(80, 80, "192.168.1.11"), failure])
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert len(info.mappings) == 1 and info.mappings_complete is False


def test_control_url_on_another_host_gives_none(monkeypatch):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    assert run_query(gateway(service(IP1, "http://192.168.1.77:5000/ctl/IPConn"))) is None
    assert run_query(Device("192.168.1.1")) is None
    assert run_query(gateway(service(L3F))) is None
    assert fake.sent == []


def test_the_list_is_capped(monkeypatch):
    fake = FakeRouter(MINIUPNPD, lambda index: entry(1024 + index, 80, "192.168.1.11"))
    install(monkeypatch, fake)
    info = run_query(gateway(service()), timeout=30)
    assert len(info.mappings) == MAX_MAPPINGS == 256
    assert info.mappings_complete is False
    assert fake.indexes() == list(range(MAX_MAPPINGS))


def test_the_deadline_cuts_the_list_short(monkeypatch):
    fake = FakeRouter(MINIUPNPD, lambda index: slow(entry(1024 + index, 80, "192.168.1.11"), 0.05))
    install(monkeypatch, fake)
    started = time.perf_counter()
    info = run_query(gateway(service()), timeout=0.5)
    assert time.perf_counter() - started < 1.2
    assert 0 < len(info.mappings) < 20
    assert info.mappings_complete is False
    assert info.external_ip == "203.0.113.45"
    assert all(sent.timeout <= 0.5 for sent in fake.sent)


def test_each_request_gets_the_time_left_but_two_seconds_at_most(monkeypatch):
    fake = FakeRouter(MINIUPNPD, [entry(80, 80, "192.168.1.11")])
    install(monkeypatch, fake)
    run_query(gateway(service()), timeout=60)
    assert all(1.5 < sent.timeout <= REQUEST_TIMEOUT for sent in fake.sent)

    fake.sent.clear()
    run_query(gateway(service()), timeout=0.5)
    assert fake.sent and all(sent.timeout <= 0.5 for sent in fake.sent)


def test_a_slow_question_does_not_hold_up_the_others(monkeypatch):
    monkeypatch.setattr(router, "REQUEST_TIMEOUT", 0.3)
    answers = dict(MINIUPNPD, GetConnectionTypeInfo=hang)
    fake = FakeRouter(answers, [entry(80, 80, "192.168.1.11")])
    install(monkeypatch, fake)
    started = time.perf_counter()
    info = run_query(gateway(service()), timeout=4.0)
    elapsed = time.perf_counter() - started
    assert info.connection is None and info.status == "Connected"
    assert len(info.mappings) == 1 and info.mappings_complete is True
    # The three are asked at the same time, and only one of them waits.
    assert 0.25 < elapsed < 1.2
    assert all(sent.timeout <= 0.3 for sent in fake.sent)


def test_cancelling_query_stops_the_requests(monkeypatch):
    started = []
    stopped = []

    async def forever(timeout):
        started.append(timeout)
        try:
            await asyncio.sleep(3600)
        finally:
            stopped.append(timeout)

    fake = FakeRouter(dict.fromkeys(INFO_ACTIONS, forever))
    install(monkeypatch, fake)

    async def main():
        task = asyncio.ensure_future(query(gateway(service()), timeout=3600))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert len(started) == 3
    assert len(stopped) == 3


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf, True, "4", None])
def test_query_refuses_bad_timeouts(timeout):
    with pytest.raises(ValueError, match="timeout"):
        run_query(gateway(service()), timeout=timeout)


# Choosing between connections


def test_the_connection_in_use_wins(monkeypatch):
    ip_url = "http://192.168.1.1:49000/ctl/WANIPConn1"
    ppp_url = "http://192.168.1.1:49000/ctl/WANPPPConn1"
    unused = FakeRouter(info_answers(external="0.0.0.0", status="Unconfigured"))
    in_use = FakeRouter(
        info_answers(external="10.20.0.7", status="Connected", uptime="77"),
        [entry(25565, 25565, "192.168.1.70", service=PPP)],
    )
    install(monkeypatch, {ip_url: unused, ppp_url: in_use})
    info = run_query(gateway(service(PPP, ppp_url), service(IP1, ip_url)))
    assert info.external_ip == "10.20.0.7" and info.uptime == 77
    assert [m.external_port for m in info.mappings] == [25565]
    assert sorted(unused.actions()) == sorted(INFO_ACTIONS)  # never asked for its list


def test_the_best_connection_is_kept_when_it_is_in_use(monkeypatch):
    ip_url = "http://192.168.1.1:49000/ctl/WANIPConn1"
    ppp_url = "http://192.168.1.1:49000/ctl/WANPPPConn1"
    best = FakeRouter(info_answers(external="", status="Connected"))
    other = FakeRouter(info_answers())
    install(monkeypatch, {ip_url: best, ppp_url: other})
    info = run_query(gateway(service(PPP, ppp_url), service(IP1, ip_url)))
    assert info.status == "Connected" and info.external_ip is None
    assert other.sent == []


def test_the_best_connection_is_kept_when_none_is_in_use(monkeypatch):
    ip_url = "http://192.168.1.1:49000/ctl/WANIPConn1"
    ppp_url = "http://192.168.1.1:49000/ctl/WANPPPConn1"
    best = FakeRouter(info_answers(external="0.0.0.0", status="Disconnected", uptime="0"))
    other = FakeRouter(info_answers(external="0.0.0.0", status="Unconfigured"))
    install(monkeypatch, {ip_url: best, ppp_url: other})
    info = run_query(gateway(service(PPP, ppp_url), service(IP1, ip_url)))
    assert info == RouterInfo(connection="IP_Routed", status="Disconnected", uptime=0)
    assert other.indexes() == [] and best.indexes() == [0]


# What the answers say


def test_mapping_fields_are_checked_and_converted(monkeypatch):
    client = "192.168.1.11"
    entries = [
        entry(80, 8080, client, protocol="tcp", enabled="true", lease="120", remote="203.0.113.9"),
        entry(81, 81, client, protocol="udp", enabled="FALSE"),
        entry(82, 82, client, enabled="no"),
        entry(83, 83, client, enabled="yes"),
        entry(84, 84, client, enabled=""),
        entry(85, 85, client, enabled="maybe", lease="-5"),
        entry(86, 86, client, lease="99999999999"),
        entry(87, 87, "::ffff:192.168.1.12", protocol=""),
        entry(" 88 ", 88, f" {client} "),
        # Skipped: ports out of range or not numbers, and clients that are not addresses.
        entry(0, 80, client),
        entry(65536, 80, client),
        entry(80, 0, client),
        entry("-1", 80, client),
        entry("abc", 80, client),
        entry("", 80, client),
        entry("\u0663", 80, client),
        entry("1e3", 80, client),
        entry(80, "80.0", client),
        entry(80, 80, "router.lan"),
        entry(80, 80, ""),
        entry(80, 80, "192.168.1.300"),
        entry(80, 80, "0.0.0.0"),
        soap(ENTRY, {"NewExternalPort": "89", "NewInternalPort": "89"}),
        entry(90, 90, client, protocol="TCPUDPEXTRA"),
    ]
    fake = FakeRouter(MINIUPNPD, entries)
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    assert info.mappings == [
        PortMapping("TCP", 80, client, 8080, lease=120, remote_host="203.0.113.9"),
        PortMapping("UDP", 81, client, 81, enabled=False),
        PortMapping("TCP", 82, client, 82, enabled=False),
        PortMapping("TCP", 83, client, 83),
        PortMapping("TCP", 84, client, 84),
        PortMapping("TCP", 85, client, 85),
        PortMapping("TCP", 86, client, 86),
        PortMapping("", 87, "192.168.1.12", 87),
        PortMapping("TCP", 88, client, 88),
        PortMapping("TCPUDPEX", 90, client, 90),
    ]
    assert info.mappings_complete is True


def test_text_is_cleaned_and_capped(monkeypatch):
    sneaky = "Game\u202e server\u200b\tport\nforward " + "x" * 1000
    fake = FakeRouter(
        info_answers(status="Conn\u2028ected", kind="IP_\u200bRouted " + "y" * 200),
        [entry(80, 80, "192.168.1.11", description=sneaky, remote="\u202e" + "z" * 100)],
    )
    install(monkeypatch, fake)
    info = run_query(gateway(service()))
    (mapping,) = info.mappings
    assert mapping.description.startswith("Game server port forward xxx")
    assert len(mapping.description) == MAX_TEXT
    assert mapping.remote_host == "z" * 64
    assert info.status == "Conn ected"
    assert info.connection.startswith("IP_ Routed y") and len(info.connection) == 64
    texts = [mapping.description, mapping.remote_host, info.status, info.connection]
    assert not any(ch in text for text in texts for ch in "\u202e\u200b\u2028\t\n")


@pytest.mark.parametrize(
    "answer, expected",
    [
        ("203.0.113.45", "203.0.113.45"),
        ("10.0.0.2", "10.0.0.2"),
        ("100.64.12.34", "100.64.12.34"),
        ("::ffff:203.0.113.5", "203.0.113.5"),
        (" 203.0.113.45 ", "203.0.113.45"),
        ("0.0.0.0", None),
        ("", None),
        ("not an address", None),
        ("203.0.113.300", None),
    ],
)
def test_external_ip_must_be_an_address(monkeypatch, answer, expected):
    install(monkeypatch, FakeRouter(info_answers(external=answer)))
    assert run_query(gateway(service())).external_ip == expected


@pytest.mark.parametrize(
    "uptime, expected",
    [("86400", 86400), ("0", 0), ("-5", None), ("12h", None), ("99999999999", None), ("", None)],
)
def test_uptime_must_be_a_number(monkeypatch, uptime, expected):
    install(monkeypatch, FakeRouter(info_answers(uptime=uptime)))
    assert run_query(gateway(service())).uptime == expected


def test_empty_status_and_type_are_none(monkeypatch):
    install(monkeypatch, FakeRouter(info_answers(status=" ", kind="")))
    info = run_query(gateway(service()))
    assert info.status is None and info.connection is None


# call


@pytest.mark.parametrize(
    "action",
    [
        "AddPortMapping",
        "AddAnyPortMapping",
        "DeletePortMapping",
        "DeletePortMappingRange",
        "SetConnectionType",
        "RequestConnection",
        "RequestTermination",
        "ForceTermination",
        "SetAutoDisconnectTime",
        "getexternalipaddress",
        "GetExternalIPAddress ",
        "",
        None,
        ["GetStatusInfo"],
    ],
)
def test_call_refuses_every_other_action(monkeypatch, action):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    with pytest.raises(ValueError, match="read-only"):
        asyncio.run(call(service(), action))
    assert fake.sent == []


def test_call_refuses_other_services(monkeypatch):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    with pytest.raises(ValueError, match="not a WAN connection service"):
        asyncio.run(call(service(L3F), "GetStatusInfo"))
    assert fake.sent == []


@pytest.mark.parametrize(
    "arguments",
    [{"New<Index>": "1"}, {"": "1"}, {"1Index": "1"}, {"NewPortMappingIndex": 1}],
)
def test_call_refuses_bad_arguments(monkeypatch, arguments):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    with pytest.raises(ValueError, match="argument"):
        asyncio.run(call(service(), ENTRY, arguments))
    assert fake.sent == []


def test_argument_values_are_escaped(monkeypatch):
    fake = FakeRouter(MINIUPNPD)
    install(monkeypatch, fake)
    with pytest.raises(UpnpError):
        asyncio.run(call(service(), ENTRY, {"NewPortMappingIndex": "<1>&"}))
    (sent,) = fake.sent
    assert b"<NewPortMappingIndex>&lt;1&gt;&amp;</NewPortMappingIndex>" in sent.body
    assert sent.arguments == {"NewPortMappingIndex": "<1>&"}


# parse_response


def test_parse_response_returns_the_arguments_by_name():
    assert parse_response(fixture("router_miniupnpd_status.xml"), "GetStatusInfo") == {
        "NewConnectionStatus": "Connected",
        "NewLastConnectionError": "ERROR_NONE",
        "NewUptime": "86523",
    }


def test_parse_response_takes_any_prefix_and_strips_the_values():
    assert parse_response(fixture("router_prefixes.xml"), "GetStatusInfo") == {
        "NewConnectionStatus": "Connected",
        "NewLastConnectionError": "ERROR_NONE",
        "NewUptime": "4012",
    }
    plain = (
        b'<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/"><Body>'
        b'<GetExternalIPAddressResponse xmlns="urn:schemas-upnp-org:service:WANIPConnection:1">'
        b"<NewExternalIPAddress>\n  203.0.113.45\n</NewExternalIPAddress>"
        b"</GetExternalIPAddressResponse></Body></Envelope>"
    )
    assert parse_response(plain, "GetExternalIPAddress") == {"NewExternalIPAddress": "203.0.113.45"}


def test_parse_response_keeps_the_first_of_repeated_arguments_and_caps_their_number():
    fields = "".join(f"<Arg{i}>{i}</Arg{i}>" for i in range(100))
    body = soap("GetStatusInfo", {}).replace(
        b"</u:GetStatusInfoResponse>",
        f"<NewUptime>5</NewUptime><NewUptime>6</NewUptime>{fields}</u:GetStatusInfoResponse>".encode(),
    )
    values = parse_response(body, "GetStatusInfo")
    assert values["NewUptime"] == "5"
    assert len(values) == router.MAX_FIELDS


def test_parse_response_turns_faults_into_upnp_errors():
    with pytest.raises(UpnpError) as caught:
        parse_response(fixture("router_miniupnpd_fault_713.xml"), ENTRY, status=500)
    assert caught.value.code == 713
    assert caught.value.description == "SpecifiedArrayIndexInvalid"
    assert str(caught.value) == "UPnP error 713: SpecifiedArrayIndexInvalid"

    with pytest.raises(UpnpError) as caught:
        parse_response(fixture("router_fault_714.xml"), ENTRY, status=500)
    assert caught.value.code == 714

    # Some routers send their faults with 200 OK.
    with pytest.raises(UpnpError) as caught:
        parse_response(fixture("router_fritz_fault_713.xml"), ENTRY)
    assert caught.value.code == 713

    with pytest.raises(UpnpError) as caught:
        parse_response(fault("", "Odd").body, ENTRY, status=500)
    assert caught.value.code is None
    assert str(caught.value) == "UPnP error without a code: Odd"


def test_fault_text_is_cleaned():
    with pytest.raises(UpnpError) as caught:
        parse_response(fault(" 606 ", "Not\u202e allowed" + "!" * 500).body, ENTRY, status=500)
    assert caught.value.code == 606
    assert caught.value.description.startswith("Not allowed!!")
    assert len(caught.value.description) == 120


def test_upnp_errors_are_soap_errors_and_value_errors():
    assert issubclass(UpnpError, SoapError)
    assert issubclass(SoapError, ValueError)


@pytest.mark.parametrize(
    "body, status, message",
    [
        (fixture("router_malformed.xml"), 200, "not a usable answer"),
        (fixture("router_dtd.xml"), 200, "not a usable answer"),
        (b"", 200, "not a usable answer"),
        (b"<html><body>Not Found</body></html>", 404, "HTTP status 404"),
        (b"<html><body>Oops</body></html>", 500, "HTTP status 500"),
        (b"garbage", 500, "HTTP status 500"),
        (fixture("router_miniupnpd_ip.xml"), 500, "HTTP status 500"),
        (fixture("router_miniupnpd_status.xml"), 200, "no GetExternalIPAddressResponse"),
        (b"<Envelope><Body/></Envelope>", 200, "no GetExternalIPAddressResponse"),
        (fixture("router_miniupnpd_ip.xml").replace(b"?>", b"?>\x00", 1), 200, "NUL"),
    ],
)
def test_parse_response_refuses_what_is_not_the_answer(body, status, message):
    with pytest.raises(SoapError, match=message) as caught:
        parse_response(body, "GetExternalIPAddress", status=status)
    assert not isinstance(caught.value, UpnpError)


def test_parse_response_refuses_oversized_answers():
    body = soap("GetExternalIPAddress", {"NewExternalIPAddress": "203.0.113.45"})
    padded = body.replace(b"<s:Body>", b"<s:Body>" + b" " * MAX_RESPONSE)
    with pytest.raises(SoapError, match="over"):
        parse_response(padded, "GetExternalIPAddress")
    fits = body.replace(b"<s:Body>", b"<s:Body>" + b" " * (MAX_RESPONSE - len(body)))
    assert len(fits) == MAX_RESPONSE
    assert parse_response(fits, "GetExternalIPAddress") == {"NewExternalIPAddress": "203.0.113.45"}


def test_parse_response_refuses_long_namespace_uris():
    body = soap(
        "GetExternalIPAddress", {"NewExternalIPAddress": "203.0.113.45"}, "urn:" + "a" * 300
    )
    with pytest.raises(SoapError, match="namespace"):
        parse_response(body, "GetExternalIPAddress")
