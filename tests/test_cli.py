import builtins
import io
import json
from ipaddress import ip_address, ip_network

import pytest
from rich.console import Console

from hearthscan import cli, i18n, render, serialize
from hearthscan.i18n import t
from hearthscan.models import (
    Device,
    Finding,
    PortMapping,
    RouterInfo,
    ScanResult,
    Service,
    UpnpInfo,
    UpnpService,
)
from hearthscan.netinfo import Interface, NetworkInfo
from hearthscan.ports import PortResult, PortState

ETH = Interface("eth0", "Ethernet", ip_address("192.168.1.50"), ip_network("192.168.1.0/24"))
INFO = NetworkInfo(ETH, "192.168.1.1")


def result(*findings):
    router = Device(
        "192.168.1.1",
        mac="a4:83:e7:00:00:01",
        vendor="Acme",
        dns_name="router.lan",
        kind="router",
        services=[Service(23, name="telnet")],
        confirmed=True,
        is_gateway=True,
    )
    me = Device("192.168.1.50", dns_name="Office-PC", kind="computer", confirmed=True, is_self=True)
    return ScanResult(
        version="2.0.0",
        started="2026-01-02T03:04:05+00:00",
        finished="2026-01-02T03:04:15+00:00",
        interface="Ethernet",
        address="192.168.1.50",
        network="192.168.1.0/24",
        gateway="192.168.1.1",
        devices=[router, me],
        findings=list(findings),
        score=85,
        ports=[23],
    )


TEXT = "A" + chr(0x11F) + " " + chr(0x4E2D)
TELNET = Finding("telnet-open", "high", "192.168.1.1", 23, {"port": "23"})
SSH = Finding("ssh-open", "info", "192.168.1.1", 22, {"port": "22", "product": ""})


class Screens:
    def __init__(self, terminal=False, width=120):
        self.out_file = io.StringIO()
        self.err_file = io.StringIO()
        self.app = cli.App(
            out=Console(
                file=self.out_file, width=width, color_system=None, force_terminal=terminal
            ),
            err=Console(file=self.err_file, width=width, color_system=None),
        )

    @property
    def out(self):
        return self.out_file.getvalue()

    @property
    def err(self):
        return self.err_file.getvalue()


@pytest.fixture
def screens(monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    yield Screens()
    i18n.set_language("en")


def fake_audit(monkeypatch, scan_result, seen=None):
    async def audit(info, **kwargs):
        if seen is not None:
            seen.update(kwargs)
        kwargs["on_progress"]("discover", 0, 0)
        kwargs["on_progress"]("ports", 5, 10)
        kwargs["on_progress"]("done", 0, 0)
        return scan_result

    import hearthscan.audit

    monkeypatch.setattr(hearthscan.audit, "audit", audit)


def test_scan_shows_score_devices_and_findings(screens, monkeypatch):
    fake_audit(monkeypatch, result(TELNET, SSH))
    assert cli.main(["scan", "--lang", "en"], app=screens.app) == 0
    out = screens.out
    assert "85" in out and "Telnet is switched on" in out
    assert "router, Router (192.168.1.1), port 23" in out
    assert "SSH remote login is switched on" in out  # in the short "good to know" list
    assert "Office-PC" in out


def test_scan_in_turkish(screens, monkeypatch):
    fake_audit(monkeypatch, result(TELNET))
    assert cli.main(["--lang", "tr", "scan"], app=screens.app) == 0
    assert "Telnet açık" in screens.out  # noqa: RUF001
    assert "Neden önemli" in screens.out


def test_scan_json_and_output_file(screens, monkeypatch, tmp_path, capsys):
    fake_audit(monkeypatch, result(TELNET))
    target = tmp_path / "scan.json"
    assert cli.main(["scan", "--json", "-o", str(target)], app=screens.app) == 0
    printed = serialize.loads(capsys.readouterr().out)
    assert printed.findings[0].rule == "telnet-open"
    assert serialize.loads(target.read_text(encoding="utf-8")).score == 85


def test_scan_options_reach_the_audit(screens, monkeypatch):
    seen = {}
    fake_audit(monkeypatch, result(), seen)
    cli.main(["scan", "-p", "22,80", "-t", "2", "--no-probe"], app=screens.app)
    assert list(seen["ports"]) == [22, 80]
    assert seen["timeout"] == 2.0
    assert seen["probe"] is False


@pytest.mark.parametrize(
    "fail_on, findings, code",
    [("high", [TELNET], 3), ("critical", [TELNET], 0), ("low", [SSH], 0), ("info", [SSH], 3)],
)
def test_fail_on(screens, monkeypatch, fail_on, findings, code):
    fake_audit(monkeypatch, result(*findings))
    assert cli.main(["scan", "--fail-on", fail_on], app=screens.app) == code


def test_clean_network(screens, monkeypatch):
    fake_audit(monkeypatch, result())
    cli.main(["scan", "--lang", "en"], app=screens.app)
    assert "Nothing risky turned up" in screens.out


def test_ctrl_c_stops_with_130(screens, monkeypatch):
    def interrupted(job):
        job.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run", interrupted)
    assert cli.main(["scan", "--lang", "en"], app=screens.app) == 130
    assert "Stopped" in screens.err


def test_no_network(screens, monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: None)
    assert cli.main(["scan", "--lang", "en"], app=screens.app) == 1
    assert "No local network" in screens.err


def test_net(screens, capsys):
    assert cli.main(["net"], app=screens.app) == 0
    assert "192.168.1.50" in screens.out and "Ethernet" in screens.out
    cli.main(["net", "--json"], app=screens.app)
    data = json.loads(capsys.readouterr().out)
    assert data["gateway"] == "192.168.1.1"


def test_devices(screens, monkeypatch, capsys):
    async def discover(info, **kwargs):
        return result().devices

    import hearthscan.discovery

    monkeypatch.setattr(hearthscan.discovery, "discover", discover)
    assert cli.main(["devices", "--lang", "en"], app=screens.app) == 0
    assert "router" in screens.out and "devices: 2" in screens.out
    cli.main(["devices", "--json"], app=screens.app)
    data = json.loads(capsys.readouterr().out)
    assert [d["ip"] for d in data["devices"]] == ["192.168.1.1", "192.168.1.50"]
    assert data["devices"][0]["name"] == "router"


def test_ports(screens, monkeypatch):
    async def scan(hosts, ports, *, timeout, on_open):
        on_open(PortResult("192.168.1.1", 23, PortState.OPEN, 0.01))
        return [
            PortResult("192.168.1.1", 23, PortState.OPEN, 0.01),
            PortResult("192.168.1.1", 80, PortState.CLOSED, 0.01),
        ]

    monkeypatch.setattr(cli, "scan", scan)
    assert cli.main(["ports", "192.168.1.1", "-p", "23,80", "--lang", "en"], app=screens.app) == 0
    assert "23/tcp  open  telnet" in screens.out
    assert "open: 1, closed: 1, filtered: 0" in screens.out


def test_ports_refuses_public_targets(screens):
    assert cli.main(["ports", "8.8.8.8", "--lang", "en"], app=screens.app) == 2
    assert "Error" in screens.err


@pytest.mark.parametrize(
    "argv", [["scan", "-p", "0"], ["scan", "-t", "0"], ["scan", "-t", "nan"], ["--lang", "xx"]]
)
def test_bad_arguments_exit_with_2(screens, argv):
    with pytest.raises(SystemExit) as stop:
        cli.main(argv, app=screens.app)
    assert stop.value.code == 2


def test_menu_without_a_terminal_prints_help(screens, monkeypatch):
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: False, raising=False)
    assert cli.main([], app=screens.app) == 0
    assert "usage: hearthscan" in screens.err  # stdout is not a terminal here either


class Tty(io.StringIO):
    def isatty(self):
        return True


def test_menu_needs_a_terminal_on_stdout_too(screens, monkeypatch):
    # `hearthscan > report.txt` should not write a menu into the file and wait.
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    monkeypatch.setattr(builtins, "input", lambda *a: pytest.fail("prompted"))
    assert cli.main([], app=screens.app) == 0
    assert "usage: hearthscan" in screens.err
    assert screens.out == ""


def test_menu_runs_a_choice_and_quits(monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    screens = Screens(terminal=True)
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    answers = iter(["9", "3", "", "q"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    assert cli.main(["--lang", "en"], app=screens.app) == 0
    assert "192.168.1.50" in screens.out  # the network details from choice 3
    assert "Please choose one of the options" in screens.out


def test_menu_survives_a_lost_network(monkeypatch):
    networks = iter([INFO, None, INFO])
    monkeypatch.setattr(cli, "local_network", lambda: next(networks, INFO))
    screens = Screens(terminal=True)
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    answers = iter(["3", "", "q"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    assert cli.main(["--lang", "en"], app=screens.app) == 0
    assert "No local network" in screens.err


def test_menu_ctrl_c_quits(monkeypatch):
    def interrupt(*a):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    monkeypatch.setattr(builtins, "input", interrupt)
    assert cli.main([], app=Screens(terminal=True).app) == 0


def test_names_from_the_network_are_not_markup(screens, monkeypatch):
    scan_result = result(TELNET)
    scan_result.devices[0].dns_name = "Media [/] Server"
    scan_result.devices[1].dns_name = "[link=x]y[/link]"
    fake_audit(monkeypatch, scan_result)
    assert cli.main(["scan", "--lang", "en"], app=screens.app) == 0
    assert "Media [/] Server" in screens.out
    assert "[link=x]y[/link]" in screens.out
    assert "\x1b]8" not in screens.out


def test_a_bad_output_path_fails_before_the_scan(screens, monkeypatch, tmp_path):
    def no_scan(*args, **kwargs):
        pytest.fail("scanned anyway")

    import hearthscan.audit

    monkeypatch.setattr(hearthscan.audit, "audit", no_scan)
    missing = tmp_path / "nope" / "out.json"
    assert cli.main(["scan", "-o", str(missing), "--lang", "en"], app=screens.app) == 2
    assert "could not save" in screens.err
    assert cli.main(["scan", "-o", str(tmp_path), "--lang", "en"], app=screens.app) == 2


def test_a_failed_save_still_shows_the_result(screens, monkeypatch, tmp_path):
    fake_audit(monkeypatch, result(TELNET))
    target = tmp_path / "scan.json"

    def refuse(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(cli.Path, "write_text", refuse)
    assert cli.main(["scan", "-o", str(target), "--lang", "en"], app=screens.app) == 2
    assert "Telnet is switched on" in screens.out
    assert "could not save" in screens.err


def test_notes_are_shown_once(screens, monkeypatch):
    scan_result = result()
    scan_result.notes = [("mdns", "mdns did not run")]

    async def audit(info, **kwargs):
        kwargs["on_note"]("mdns", "mdns did not run")
        return scan_result

    import hearthscan.audit

    monkeypatch.setattr(hearthscan.audit, "audit", audit)
    cli.main(["scan", "--lang", "en"], app=screens.app)
    assert (screens.out + screens.err).count("mdns did not run") == 1


def test_urgent_line_and_skipped_probes(screens, monkeypatch):
    fake_audit(monkeypatch, result(TELNET))
    cli.main(["scan", "--no-probe", "--lang", "en"], app=screens.app)
    assert "Start with the items marked Critical or High" in screens.out
    assert "--no-probe" in screens.out


def test_findings_come_before_the_device_list(screens, monkeypatch):
    fake_audit(monkeypatch, result(TELNET))
    cli.main(["scan", "--lang", "en"], app=screens.app)
    assert screens.out.index("Telnet is switched on") < screens.out.index("Devices on your network")


def test_narrow_screens_keep_port_numbers_whole(monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    scan_result = result()
    scan_result.devices[0].services = [Service(p) for p in (49152, 62078, 8080)]
    fake_audit(monkeypatch, scan_result)
    screens = Screens(width=60)
    cli.main(["scan", "--lang", "en"], app=screens.app)
    assert "49152" in screens.out and "62078" in screens.out
    assert "Maker" not in screens.out  # dropped to make room


def test_ctrl_c_outside_the_scan(screens, monkeypatch):
    def interrupted():
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "local_network", interrupted)
    assert cli.main(["net", "--lang", "en"], app=screens.app) == 130
    assert "Stopped" in screens.err


@pytest.mark.parametrize("value", ["61", "1e9"])
def test_timeouts_are_capped(screens, value):
    with pytest.raises(SystemExit) as stop:
        cli.main(["scan", "-t", value], app=screens.app)
    assert stop.value.code == 2


def test_ports_refusal_is_translated(screens):
    assert cli.main(["ports", "8.8.8.8", "--lang", "tr"], app=screens.app) == 2
    assert "8.8.8.8 \u00f6zel bir a\u011fda de\u011fil" in screens.err


def test_redirected_output_is_utf8(monkeypatch):
    raw = io.BytesIO()
    narrow = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(cli.sys, "stdout", narrow)
    cli._plain_streams()
    print(TEXT, file=narrow)
    narrow.flush()
    assert raw.getvalue().decode("utf-8").startswith(TEXT)


def test_a_narrow_console_replaces_instead_of_crashing(monkeypatch):
    class Console1252(io.TextIOWrapper):
        def isatty(self):
            return True

    raw = io.BytesIO()
    console = Console1252(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(cli.sys, "stdout", console)
    cli._plain_streams()
    print(TEXT, file=console)
    console.flush()
    assert raw.getvalue().startswith(b"A? ?")


# The router command

WAN = UpnpService(
    "urn:schemas-upnp-org:service:WANIPConnection:1", "http://192.168.1.1:5000/ctl/IPConn"
)
RDP = PortMapping("TCP", 3389, "192.168.1.50", 3389, "Remote desktop")
GAME = PortMapping("UDP", 27015, "192.168.1.77", 27016, "Game server", enabled=False)
UPTIME = 3 * 86400 + 5 * 3600 + 59 * 60


def router_info(*mappings, complete=True):
    return RouterInfo(
        external_ip="10.20.30.40",
        connection="IP_Routed",
        status="Connected",
        uptime=UPTIME,
        mappings=list(mappings),
        mappings_complete=complete,
    )


def lan_devices(gateway=True):
    devices = result().devices
    devices[0].is_gateway = gateway
    devices[0].upnp = UpnpInfo(friendly_name="Acme Router", services=[WAN])
    return devices


def fake_router(monkeypatch, info, *, devices=None, wan=WAN):
    """Discovery and the router client, faked. Returns the devices the router was asked as."""
    devices = lan_devices() if devices is None else devices
    asked = []

    async def discover(net, **kwargs):
        return devices

    async def query(device, **kwargs):
        asked.append(device)
        return info

    import hearthscan.discovery
    import hearthscan.router

    monkeypatch.setattr(hearthscan.discovery, "discover", discover)
    monkeypatch.setattr(hearthscan.router, "wan_service", lambda device: wan)
    monkeypatch.setattr(hearthscan.router, "query", query)
    return asked


def rendered(parts, width=120):
    console = Console(file=io.StringIO(), width=width, color_system=None)
    for part in parts:
        console.print(part)
    return console.file.getvalue()


def test_router_shows_what_it_says_and_where_its_ports_lead(screens, monkeypatch):
    asked = fake_router(monkeypatch, router_info(RDP, GAME))
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 0
    out = screens.out
    assert [d.ip for d in asked] == ["192.168.1.1"]
    assert "Your router" in out
    assert "10.20.30.40" in out and "IP_Routed" in out and "Connected" in out
    assert "3 d 5 h" in out
    assert "Internet port" in out and "Goes to" in out
    # A device on the network by its name, anything else by address and port.
    assert "Office-PC (192.168.1.50), port 3389" in out
    assert "192.168.1.77:27016" in out
    assert "Remote desktop" in out and "Game server" in out
    assert "27015" in out and "UDP" in out
    assert "No ports are opened" not in out
    assert "only the first ones are shown" not in out


def test_router_leaves_out_what_it_did_not_say(screens, monkeypatch):
    fake_router(monkeypatch, RouterInfo(status="Connected"))
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 0
    out = screens.out
    assert "Connected" in out
    for label in ("Internet address", "Connection type", "Running for"):
        assert label not in out
    assert "No ports are opened to the internet through UPnP." in out


def test_router_with_a_cut_short_list(screens, monkeypatch):
    fake_router(monkeypatch, router_info(RDP, complete=False))
    cli.main(["router", "--lang", "en"], app=screens.app)
    assert t("ui.router.incomplete", count=1) in screens.out
    assert "Remote desktop" in screens.out


def test_a_list_that_broke_off_at_once_is_not_called_empty(screens, monkeypatch):
    fake_router(monkeypatch, router_info(complete=False))
    cli.main(["router", "--lang", "en"], app=screens.app)
    assert "No ports are opened" not in screens.out
    assert t("ui.router.incomplete", count=0) in screens.out


def test_router_without_a_gateway(screens, monkeypatch, capsys):
    asked = fake_router(monkeypatch, router_info(), devices=lan_devices(gateway=False))
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 0
    assert "The router does not answer UPnP questions" in screens.out
    assert asked == []
    assert cli.main(["router", "--json"], app=screens.app) == 0
    assert json.loads(capsys.readouterr().out) == {"router": None}


def test_router_without_upnp(screens, monkeypatch, capsys):
    asked = fake_router(monkeypatch, router_info(), wan=None)
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 0
    assert "The router does not answer UPnP questions" in screens.out
    assert "Your router" not in screens.out
    assert asked == []
    cli.main(["router", "--json"], app=screens.app)
    assert json.loads(capsys.readouterr().out) == {"router": None}


def test_router_that_answers_nothing_useful(screens, monkeypatch):
    fake_router(monkeypatch, None)
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 0
    assert "The router does not answer UPnP questions" in screens.out


def test_router_json(screens, monkeypatch, capsys):
    fake_router(monkeypatch, router_info(RDP, complete=False))
    assert cli.main(["router", "--json"], app=screens.app) == 0
    data = json.loads(capsys.readouterr().out)
    assert data == {
        "router": {
            "external_ip": "10.20.30.40",
            "connection": "IP_Routed",
            "status": "Connected",
            "uptime": UPTIME,
            "mappings": [
                {
                    "protocol": "TCP",
                    "external_port": 3389,
                    "internal_client": "192.168.1.50",
                    "internal_port": 3389,
                    "description": "Remote desktop",
                    "enabled": True,
                    "lease": 0,
                    "remote_host": "",
                }
            ],
            "mappings_complete": False,
        }
    }
    assert screens.out == ""


def test_router_in_turkish(screens, monkeypatch):
    fake_router(monkeypatch, router_info(RDP))
    assert cli.main(["router", "--lang", "tr"], app=screens.app) == 0
    out = screens.out
    assert "Modeminiz" in out
    assert "3 gün 5 saat" in out
    assert "Hedef" in out and "Remote desktop" in out


def test_router_without_upnp_in_turkish(screens, monkeypatch):
    fake_router(monkeypatch, router_info(), wan=None)
    assert cli.main(["router", "--lang", "tr"], app=screens.app) == 0
    assert "Modem UPnP sorularına yanıt vermiyor" in screens.out  # noqa: RUF001


def test_router_no_network(screens, monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: None)
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 1


def test_router_ctrl_c(screens, monkeypatch):
    fake_router(monkeypatch, router_info())

    def interrupted(job):
        job.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run", interrupted)
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 130


def test_menu_option_4_asks_the_router(monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    fake_router(monkeypatch, router_info(RDP))
    screens = Screens(terminal=True)
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    answers = iter(["4", "", "q"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    assert cli.main(["--lang", "en"], app=screens.app) == 0
    assert "4  Check my router" in screens.out
    assert "Remote desktop" in screens.out


def test_what_the_router_sends_is_not_markup(screens, monkeypatch):
    info = router_info(
        PortMapping("TCP", 8080, "192.168.1.60", 80, "[bold red]x[/] [/]"),
        PortMapping("TCP", 8081, "192.168.1.61", 80, "[link=http://192.168.1.9]y[/link]"),
    )
    info.status = "[blink]Connected"
    fake_router(monkeypatch, info)
    assert cli.main(["router", "--lang", "en"], app=screens.app) == 0
    out = screens.out
    assert "[bold red]x[/] [/]" in out
    assert "[link=http://192.168.1.9]y[/link]" in out
    assert "[blink]Connected" in out
    assert "\x1b]8" not in out


def test_narrow_screens_put_the_protocol_with_the_port():
    wide = rendered(render.router_view(router_info(RDP), lan_devices(), 120))
    assert "Protocol" in wide and "3389/TCP" not in wide
    narrow = rendered(render.router_view(router_info(RDP), lan_devices(), 60), width=60)
    assert "Protocol" not in narrow
    assert "3389/TCP" in narrow


def test_scan_result_shows_the_router_between_findings_and_devices(screens, monkeypatch):
    scan_result = result(TELNET)
    scan_result.router = router_info(RDP)
    fake_audit(monkeypatch, scan_result)
    assert cli.main(["scan", "--lang", "en"], app=screens.app) == 0
    out = screens.out
    title = out.index("Your router")
    assert out.index("Telnet is switched on") < title < out.index("Devices on your network")
    assert out.index("Remote desktop") < out.index("Devices on your network")


def test_result_view_without_a_router():
    out = rendered(render.result_view(result(TELNET), width=120))
    assert "Your router" not in out
    assert "Ports opened to the internet" not in out
    assert "Telnet is switched on" in out and "Devices on your network" in out
