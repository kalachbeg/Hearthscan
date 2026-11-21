import builtins
import copy
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
    answers = iter(["9", "6", "", "q"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    assert cli.main(["--lang", "en"], app=screens.app) == 0
    assert "192.168.1.50" in screens.out  # the network details from choice 6
    assert "Please choose one of the options" in screens.out


def test_menu_survives_a_lost_network(monkeypatch):
    networks = iter([INFO, None, INFO])
    monkeypatch.setattr(cli, "local_network", lambda: next(networks, INFO))
    screens = Screens(terminal=True)
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    answers = iter(["6", "", "q"])
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


def fake_window(monkeypatch):
    """Replaces the window. Returns how it was opened: (prefer_window, language)."""
    opened = []

    def open_window(*, prefer_window=True):
        opened.append((prefer_window, i18n.language()))
        return 0

    import hearthscan.gui.window

    monkeypatch.setattr(hearthscan.gui.window, "open_window", open_window)
    return opened


def test_menu_in_the_planned_order(monkeypatch):
    opened = fake_window(monkeypatch)
    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    screens = Screens(terminal=True)
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    answers = iter(["2", "", "q"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    assert cli.main(["--lang", "en"], app=screens.app) == 0
    labels = [
        "ui.menu.scan",
        "ui.menu.window",
        "ui.menu.watch",
        "ui.menu.devices",
        "ui.menu.router",
        "ui.menu.network",
    ]
    places = [screens.out.index(f"{n}  {t(label)}") for n, label in enumerate(labels, 1)]
    assert places == sorted(places)
    assert places[-1] < screens.out.index("q  Quit")
    assert opened == [(True, "en")]  # choice 2 opened the window


def test_gui_opens_the_window_or_the_browser(screens, monkeypatch):
    opened = fake_window(monkeypatch)
    assert cli.main(["gui", "--lang", "en"], app=screens.app) == 0
    assert cli.main(["gui", "--browser", "--lang", "tr"], app=screens.app) == 0
    assert opened == [(True, "en"), (False, "tr")]


def test_gui_is_in_the_help():
    assert "open the desktop window" in cli.build_parser().format_help()


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


def test_menu_option_5_asks_the_router(monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    fake_router(monkeypatch, router_info(RDP))
    screens = Screens(terminal=True)
    monkeypatch.setattr(cli.sys, "stdin", Tty())
    answers = iter(["5", "", "q"])
    monkeypatch.setattr(builtins, "input", lambda *a: next(answers))
    assert cli.main(["--lang", "en"], app=screens.app) == 0
    assert "5  Check my router" in screens.out
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


# HTML reports and comparing scans


def save(path, scan_result):
    path.write_text(serialize.dumps(scan_result), encoding="utf-8")
    return path


@pytest.mark.parametrize("name", ["report.html", "REPORT.HTM"])
def test_scan_saves_html_when_asked(screens, monkeypatch, tmp_path, name):
    fake_audit(monkeypatch, result(TELNET))
    target = tmp_path / name
    assert cli.main(["scan", "-o", str(target), "--lang", "en"], app=screens.app) == 0
    page = target.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert '<html lang="en">' in page and "Telnet is switched on" in page
    assert str(target) in flat(screens.err)


def test_scan_saves_html_in_the_chosen_language(screens, monkeypatch, tmp_path):
    fake_audit(monkeypatch, result(TELNET))
    target = tmp_path / "rapor.html"
    assert cli.main(["scan", "-o", str(target), "--lang", "tr"], app=screens.app) == 0
    page = target.read_text(encoding="utf-8")
    assert '<html lang="tr">' in page and "Telnet açık" in page  # noqa: RUF001


def test_scan_saves_json_for_any_other_name(screens, monkeypatch, tmp_path):
    fake_audit(monkeypatch, result(TELNET))
    target = tmp_path / "scan.txt"
    assert cli.main(["scan", "-o", str(target)], app=screens.app) == 0
    assert serialize.loads(target.read_text(encoding="utf-8")).score == 85


def test_a_bad_html_path_fails_before_the_scan(screens, monkeypatch, tmp_path):
    import hearthscan.audit

    monkeypatch.setattr(hearthscan.audit, "audit", lambda *a, **k: pytest.fail("scanned"))
    missing = tmp_path / "nope" / "report.html"
    assert cli.main(["scan", "-o", str(missing), "--lang", "en"], app=screens.app) == 2
    assert "could not save" in flat(screens.err)


def test_report_next_to_the_result(screens, tmp_path):
    source = save(tmp_path / "scan.json", result(TELNET))
    assert cli.main(["report", str(source), "--lang", "en"], app=screens.app) == 0
    target = tmp_path / "scan.html"
    page = target.read_text(encoding="utf-8")
    assert "Telnet is switched on" in page and "192.168.1.0/24" in page
    assert f"Report saved: {target}\n" in screens.out  # on one line, however long
    assert source.read_text(encoding="utf-8").startswith("{")


def test_report_to_a_chosen_file_in_turkish(screens, tmp_path):
    source = save(tmp_path / "scan.json", result(TELNET))
    target = tmp_path / "out" / "rapor.htm"
    target.parent.mkdir()
    argv = ["report", str(source), "-o", str(target), "--lang", "tr"]
    assert cli.main(argv, app=screens.app) == 0
    assert '<html lang="tr">' in target.read_text(encoding="utf-8")
    assert "Rapor kaydedildi" in screens.out
    assert not (tmp_path / "scan.html").exists()


def test_report_reads_a_file_with_a_byte_order_mark(screens, tmp_path):
    source = tmp_path / "scan.json"
    source.write_bytes(b"\xef\xbb\xbf" + serialize.dumps(result()).encode())
    assert cli.main(["report", str(source)], app=screens.app) == 0
    assert (tmp_path / "scan.html").exists()


@pytest.mark.parametrize(
    "content, reason",
    [
        (b"not json", "Expecting value"),
        (b'{"tool": "other", "schema": 1}', "not a Hearthscan result"),
        (b'{"tool": "hearthscan", "schema": 99}', "schema 99"),
        (b'{"tool": "hearthscan", "schema": 1, "version": 3}', "version should be a string"),
        # How deep the json module gets before it gives up depends on the
        # platform's stack, so only the refusal itself is checked here.
        (b"[" * 100000, ""),
        (b"\xff\xfe{\x00}\x00", "not UTF-8 text"),
        (b"", "Expecting value"),
    ],
)
def test_report_refuses_what_is_not_a_result(screens, tmp_path, content, reason):
    source = tmp_path / "scan.json"
    source.write_bytes(content)
    assert cli.main(["report", str(source), "--lang", "en"], app=screens.app) == 2
    assert "is not a scan result saved by Hearthscan" in flat(screens.err)
    assert reason in flat(screens.err)
    assert not (tmp_path / "scan.html").exists()


def test_report_errors_are_translated(screens, tmp_path):
    source = tmp_path / "scan.json"
    source.write_text("{}", encoding="utf-8")
    assert cli.main(["report", str(source), "--lang", "tr"], app=screens.app) == 2
    assert "Hata" in flat(screens.err)
    assert "Hearthscan ile kaydedilmi" in flat(screens.err)
    assert cli.main(["report", str(tmp_path / "yok.json"), "--lang", "tr"], app=screens.app) == 2
    assert "okunamad" in flat(screens.err)


def test_report_of_a_missing_file_or_a_folder(screens, tmp_path):
    assert cli.main(["report", str(tmp_path / "nope.json"), "--lang", "en"], app=screens.app) == 2
    assert "could not read" in flat(screens.err)
    assert cli.main(["report", str(tmp_path), "--lang", "en"], app=screens.app) == 2
    assert "it is a folder" in flat(screens.err)


def test_report_never_writes_over_the_result(screens, tmp_path):
    source = save(tmp_path / "scan.html", result(TELNET))  # a result with an odd name
    before = source.read_text(encoding="utf-8")
    assert cli.main(["report", str(source), "--lang", "en"], app=screens.app) == 2
    assert cli.main(["report", str(source), "-o", str(source)], app=screens.app) == 2
    assert source.read_text(encoding="utf-8") == before
    assert "could not save" in flat(screens.err)


def test_report_to_a_missing_folder(screens, tmp_path):
    source = save(tmp_path / "scan.json", result())
    argv = ["report", str(source), "-o", str(tmp_path / "nope" / "r.html"), "--lang", "en"]
    assert cli.main(argv, app=screens.app) == 2
    assert "could not save" in flat(screens.err)


def test_report_that_cannot_be_written(screens, monkeypatch, tmp_path):
    source = save(tmp_path / "scan.json", result())

    def refuse(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(cli.Path, "write_text", refuse)
    assert cli.main(["report", str(source), "--lang", "en"], app=screens.app) == 2
    assert "could not save" in flat(screens.err) and "Permission denied" in flat(screens.err)


def test_report_needs_a_file(screens):
    with pytest.raises(SystemExit) as stop:
        cli.main(["report"], app=screens.app)
    assert stop.value.code == 2


def flat(text):
    """Console output with line wrapping undone."""
    return " ".join(text.split())


def two_scans(tmp_path):
    old = result(TELNET, SSH)
    old.score = 70
    new = result(copy.copy(SSH), Finding("upnp-igd", "medium", "192.168.1.1", None, {}))
    new.score = 94
    # Office-PC has no MAC, so on another address it counts as a new device.
    new.devices[1].ip = "192.168.1.51"
    new.devices[1].vendor = "Acme"
    new.devices.append(Device("192.168.1.77", mac="da:a1:19:00:00:30", confirmed=True))
    # The router moved, its MAC stays: not new, and its findings stay its own.
    new.devices[0].ip = "192.168.1.254"
    new.gateway = "192.168.1.254"
    for finding in new.findings:
        finding.ip = "192.168.1.254"
    return save(tmp_path / "old.json", old), save(tmp_path / "new.json", new)


def test_diff_shows_what_came_and_went(screens, tmp_path):
    old, new = two_scans(tmp_path)
    assert cli.main(["diff", str(old), str(new), "--lang", "en"], app=screens.app) == 0
    out = screens.out
    assert "Changes between the two scans" in out
    assert "Network score  70 → 94  (+24)" in out
    assert "New findings (1)" in out
    assert " Medium   Devices can open ports on the router  router, Router (192.168.1.254)" in out
    assert "Fixed or no longer seen (1)" in out
    assert " High   Telnet is switched on  router, Router (192.168.1.1), port 23" in out
    assert "New devices (2)" in out
    assert "Office-PC (192.168.1.51)  Acme" in out
    assert "Unknown device (192.168.1.77)" in out
    assert "Devices no longer seen (1)" in out and "Office-PC (192.168.1.50)" in out
    assert "SSH remote login" not in out  # on the router before and after
    assert out.index("New findings") < out.index("New devices")
    assert screens.err == ""


def test_diff_as_json(screens, tmp_path, capsys):
    old, new = two_scans(tmp_path)
    assert cli.main(["diff", str(old), str(new), "--json"], app=screens.app) == 0
    data = json.loads(capsys.readouterr().out)
    assert (data["score_before"], data["score_after"]) == (70, 94)
    assert [f["rule"] for f in data["fixed_findings"]] == ["telnet-open"]
    assert [f["rule"] for f in data["new_findings"]] == ["upnp-igd"]
    assert [d["ip"] for d in data["new_devices"]] == ["192.168.1.51", "192.168.1.77"]
    assert [d["ip"] for d in data["gone_devices"]] == ["192.168.1.50"]
    assert screens.out == ""


def test_diff_of_the_same_scan(screens, tmp_path):
    old = save(tmp_path / "a.json", result(TELNET))
    assert cli.main(["diff", str(old), str(old), "--lang", "en"], app=screens.app) == 0
    assert "Network score  85 / 100  (unchanged)" in screens.out
    assert "No devices or findings came or went" in screens.out
    assert "New devices" not in screens.out


def test_diff_with_a_lower_score(screens, tmp_path):
    better, worse = result(), result(TELNET)
    better.score, worse.score = 100, 85
    a, b = save(tmp_path / "a.json", better), save(tmp_path / "b.json", worse)
    assert cli.main(["diff", str(a), str(b), "--lang", "en"], app=screens.app) == 0
    assert "100 → 85  (-15)" in screens.out


def test_diff_in_turkish(screens, tmp_path):
    old, new = two_scans(tmp_path)
    assert cli.main(["diff", str(old), str(new), "--lang", "tr"], app=screens.app) == 0
    out = screens.out
    assert "İki tarama arasındaki değişiklikler" in out  # noqa: RUF001
    assert "Yeni bulgular (1)" in out and "Yeni cihazlar (2)" in out
    assert "Yüksek" in out and "Telnet açık" in out  # noqa: RUF001


def test_diff_warns_about_different_networks(screens, tmp_path):
    other = result()
    other.network = "10.0.0.0/24"
    a, b = save(tmp_path / "a.json", result()), save(tmp_path / "b.json", other)
    assert cli.main(["diff", str(a), str(b), "--lang", "en"], app=screens.app) == 0
    assert "different networks: 192.168.1.0/24 and 10.0.0.0/24" in flat(screens.err)


def test_diff_refuses_a_bad_file(screens, tmp_path):
    good = save(tmp_path / "a.json", result())
    bad = tmp_path / "b.json"
    bad.write_text('{"devices": []}', encoding="utf-8")
    assert cli.main(["diff", str(good), str(bad), "--lang", "en"], app=screens.app) == 2
    assert "is not a scan result saved by Hearthscan" in flat(screens.err)
    assert cli.main(["diff", str(tmp_path / "x.json"), str(good)], app=screens.app) == 2
    assert "could not read" in flat(screens.err)


def test_diff_names_from_the_network_are_not_markup(screens, tmp_path):
    old, new = result(), result()
    new.devices.append(Device("192.168.1.9", dns_name="[bold]x[/] [link=y]z[/link]"))
    a, b = save(tmp_path / "a.json", old), save(tmp_path / "b.json", new)
    assert cli.main(["diff", str(a), str(b), "--lang", "en"], app=screens.app) == 0
    assert "[bold]x[/] [link=y]z[/link] (192.168.1.9)" in screens.out


def test_diff_needs_two_files(screens, tmp_path):
    with pytest.raises(SystemExit) as stop:
        cli.main(["diff", str(tmp_path / "a.json")], app=screens.app)
    assert stop.value.code == 2


# Watch mode and the list of known devices


def fake_watch(monkeypatch, rounds, seen=None):
    from hearthscan import watch as watcher

    async def watch(info, store, *, every, full, on_round, on_wait=None, on_note=None, **kw):
        if seen is not None:
            seen.update(every=every, full=full, store=store)
        for number, changes in enumerate(rounds, 1):
            devices = [change.device for change in changes if change.device is not None]
            store.update(devices)
            on_round(
                watcher.Round(
                    number,
                    "2026-01-02T03:04:05+00:00",
                    "2026-01-02T03:04:06+00:00",
                    devices,
                    changes,
                )
            )
            if on_wait:
                on_wait(every)

    monkeypatch.setattr(watcher, "watch", watch)


def test_watch_learns_first_then_reports_new_devices(monkeypatch, tmp_path):
    from hearthscan.watch import Change

    monkeypatch.setattr(cli, "local_network", lambda: INFO)
    screens = Screens(terminal=True)  # rich only beeps on a terminal

    monkeypatch.setenv("HEARTHSCAN_STATE_DIR", str(tmp_path))
    plug = Device("192.168.1.77", mac="a4:83:e7:00:00:77", vendor="Acme", confirmed=True)
    seen = {}
    fake_watch(
        monkeypatch,
        [[Change("new", device=result().devices[0])], [], [Change("new", device=plug)]],
        seen,
    )
    assert cli.main(["watch", "--every", "2", "--lang", "en"], app=screens.app) == 0
    out = screens.out
    assert "every 2 minutes" in out
    assert "first run" in out and "Remembered the devices on your network: 1" in out
    assert "nothing changed" in out
    assert "New" in out and "192.168.1.77" in out and "Acme" in out
    assert "\a" in out  # a beep for the new device
    assert seen["every"] == 120 and seen["full"] is False


def test_watch_ctrl_c(screens, monkeypatch, tmp_path):
    monkeypatch.setenv("HEARTHSCAN_STATE_DIR", str(tmp_path))

    def interrupted(job):
        job.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run", interrupted)
    assert cli.main(["watch", "--lang", "en"], app=screens.app) == 130


@pytest.mark.parametrize("every", ["0.1", "nan", "2000"])
def test_watch_interval_is_checked(screens, every):
    with pytest.raises(SystemExit) as stop:
        cli.main(["watch", "--every", every], app=screens.app)
    assert stop.value.code == 2


def known_store(tmp_path):
    from hearthscan.store import Known, KnownDevices

    records = [
        Known(
            "a4:83:e7:00:00:20",
            "2026-01-01T10:00:00+00:00",
            "2026-01-02T10:00:00+00:00",
            "192.168.1.20",
            "Kitchen-Speaker",
            "Acme",
            "speaker",
        ),
        Known(
            "da:a1:19:00:00:30",
            "2026-01-01T10:00:00+00:00",
            "2026-01-02T11:00:00+00:00",
            "192.168.1.30",
            "[b]Odd[/b]",
            None,
            "phone",
            random_mac=True,
        ),
    ]
    store = KnownDevices(tmp_path / "known.json", records)
    store.save()
    return store


def test_known_lists_trusts_forgets_and_clears(screens, monkeypatch, tmp_path, capsys):
    from hearthscan.store import KnownDevices

    monkeypatch.setenv("HEARTHSCAN_STATE_DIR", str(tmp_path))
    known_store(tmp_path)
    assert cli.main(["known", "--lang", "en"], app=screens.app) == 0
    assert "Kitchen-Speaker" in screens.out and "[b]Odd[/b]" in screens.out

    assert cli.main(["known", "--trust", "192.168.1.20", "--lang", "en"], app=screens.app) == 0
    assert KnownDevices.load(tmp_path / "known.json").get("a4:83:e7:00:00:20").trusted
    assert cli.main(["known", "--forget", "da:a1:19:00:00:30"], app=screens.app) == 0
    assert len(KnownDevices.load(tmp_path / "known.json")) == 1
    assert cli.main(["known", "--trust", "10.9.9.9", "--lang", "en"], app=screens.app) == 2
    assert "no remembered device" in screens.err

    cli.main(["known", "--json"], app=screens.app)
    data = json.loads(capsys.readouterr().out)
    assert [r["name"] for r in data["known"]] == ["Kitchen-Speaker"]
    assert cli.main(["known", "--clear"], app=screens.app) == 0
    assert len(KnownDevices.load(tmp_path / "known.json")) == 0


def test_known_when_empty(screens, monkeypatch, tmp_path):
    monkeypatch.setenv("HEARTHSCAN_STATE_DIR", str(tmp_path))
    assert cli.main(["known", "--lang", "en"], app=screens.app) == 0
    assert "No devices remembered yet" in screens.out
