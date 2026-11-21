import ntpath
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from hearthscan import netinfo, system
from hearthscan.netinfo import Interface, NetworkInfo, Route, adapter_kind, local_network

DATA = Path(__file__).parent / "data"

ETH = Interface("eth0", "eth0", ip_address("192.168.1.50"), ip_network("192.168.1.0/24"))
WG = Interface("wg0", "wg0", ip_address("10.66.0.2"), ip_network("10.66.0.0/24"), "virtual")


def read(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def not_in_a_sandbox(monkeypatch):
    monkeypatch.setattr(system, "sandbox", lambda: None)


def fake_system(monkeypatch, ifaces, routes):
    monkeypatch.setattr(netinfo, "interfaces", lambda: ifaces)
    monkeypatch.setattr(netinfo, "default_routes", lambda: routes)


def test_route_print_english():
    assert netinfo.parse_route_print(read("route_print_en.txt")) == [
        Route("192.168.0.1", "192.168.0.23", 35),
        Route("192.168.0.1", "192.168.0.57", 50),
    ]


def test_route_print_translated_headers_and_crlf():
    text = read("route_print_tr.txt").replace("\n", "\r\n")
    assert netinfo.parse_route_print(text) == [Route("192.168.1.1", "192.168.1.34", 25)]


def test_proc_net_route():
    assert netinfo.parse_proc_net_route(read("proc_net_route.txt")) == [
        Route("10.0.0.1", "eth0", 100),
        Route("192.168.1.1", "wlp2s0", 600),
    ]


def test_ip_route_fallback():
    text = (
        "default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.50 metric 600\n"
        "default via 10.0.0.1 dev eth0 proto static\n"
    )
    assert netinfo.parse_ip_route(text) == [
        Route("10.0.0.1", "eth0", 0),
        Route("192.168.1.1", "wlp2s0", 600),
    ]


def test_netstat_macos():
    assert netinfo.parse_netstat_rn(read("netstat_rn_macos.txt")) == [
        Route("192.168.1.1", "en0", 0)
    ]


def test_netstat_with_refs_and_use_columns():
    text = "default            192.168.0.1        UGSc           41        0     en1\n"
    assert netinfo.parse_netstat_rn(text) == [Route("192.168.0.1", "en1", 0)]


@pytest.mark.parametrize(
    "description, kind",
    [
        ("Intel(R) Wi-Fi 6E AX211 160MHz Wi-Fi", "physical"),
        ("Intel(R) Ethernet Controller I225-V Ethernet", "physical"),
        ("Killer E2600 Gigabit Ethernet Controller Local Area Connection", "physical"),
        ("Microsoft Hyper-V Network Adapter Ethernet", "physical"),
        ("Hyper-V Virtual Ethernet Adapter vEthernet (External)", "vswitch"),
        ("WireGuard Tunnel home", "virtual"),
        ("TAP-Windows Adapter V9 Ethernet 2", "virtual"),
        ("Cisco AnyConnect Secure Mobility Client Virtual Miniport Adapter", "virtual"),
        ("Bluetooth Device (Personal Area Network)", "virtual"),
    ],
)
def test_windows_adapter_kinds(description, kind):
    assert adapter_kind(description) == kind


@pytest.mark.parametrize(
    "name, kind",
    [
        ("eth0", "physical"),
        ("wlp2s0", "physical"),
        ("enx00e04c680001", "physical"),
        ("br0", "physical"),
        ("bridge0", "physical"),
        ("docker0", "virtual"),
        ("br-3f9c1d2e7a10", "virtual"),
        ("tailscale0", "virtual"),
        ("wg0", "virtual"),
    ],
)
def test_linux_adapter_kinds(monkeypatch, name, kind):
    monkeypatch.setattr(netinfo, "IS_MACOS", False)
    assert adapter_kind(name, name) == kind


@pytest.mark.parametrize(
    "name, kind", [("en0", "physical"), ("utun3", "virtual"), ("bridge100", "virtual")]
)
def test_macos_adapter_kinds(monkeypatch, name, kind):
    monkeypatch.setattr(netinfo, "IS_MACOS", True)
    assert adapter_kind(name, name) == kind


def test_physical_adapter_wins_over_vpn_default_route(monkeypatch):
    routes = [Route("10.66.0.1", "wg0", 0), Route("192.168.1.1", "eth0", 600)]
    fake_system(monkeypatch, [WG, ETH], routes)
    assert local_network() == NetworkInfo(ETH, "192.168.1.1")


def test_windows_routes_match_by_address(monkeypatch):
    wifi = Interface(
        "{1B4E28BA-2FA1-11D2-883F-0016D3CCA427}",
        "Wi-Fi",
        ip_address("192.168.0.57"),
        ip_network("192.168.0.0/24"),
    )
    fake_system(monkeypatch, [wifi], [Route("192.168.0.1", "192.168.0.57")])
    assert local_network() == NetworkInfo(wifi, "192.168.0.1")


def test_hyper_v_external_switch_carrying_the_default_route(monkeypatch):
    switch = Interface(
        "{6F9619FF-8B86-D011-B42D-00C04FC964FF}",
        "vEthernet (External)",
        ip_address("192.168.1.20"),
        ip_network("192.168.1.0/24"),
        "vswitch",
    )
    fake_system(monkeypatch, [switch], [Route("192.168.1.1", "192.168.1.20", 15)])
    assert local_network() == NetworkInfo(switch, "192.168.1.1")


def test_internal_switch_is_not_picked_without_a_route(monkeypatch):
    internal = Interface(
        "x", "vEthernet (WSL)", ip_address("172.29.0.1"), ip_network("172.29.0.0/20"), "vswitch"
    )
    fake_system(monkeypatch, [internal, ETH], [])
    assert local_network() == NetworkInfo(ETH, None)


def test_second_address_on_the_same_interface(monkeypatch):
    alias = Interface("eth0", "eth0", ip_address("192.168.100.2"), ip_network("192.168.100.0/24"))
    fake_system(monkeypatch, [alias, ETH], [Route("192.168.1.1", "eth0", 100)])
    assert local_network() == NetworkInfo(ETH, "192.168.1.1")


def test_no_default_route_falls_back_to_physical_interface(monkeypatch):
    fake_system(monkeypatch, [WG, ETH], [])
    assert local_network() == NetworkInfo(ETH, None)


def test_offline(monkeypatch):
    fake_system(monkeypatch, [], [])
    assert local_network() is None


def test_sandbox_is_passed_along(monkeypatch):
    monkeypatch.setattr(system, "sandbox", lambda: "wsl")
    fake_system(monkeypatch, [ETH], [Route("192.168.1.1", "eth0")])
    assert local_network().sandbox == "wsl"


def test_big_networks_are_narrowed_to_a_slash_24():
    big = Interface("eth0", "eth0", ip_address("10.1.2.3"), ip_network("10.0.0.0/8"))
    assert NetworkInfo(big, "10.0.0.1").scan_network() == ip_network("10.1.2.0/24")
    assert NetworkInfo(ETH, "192.168.1.1").scan_network() == ETH.network


def test_windows_runs_route_from_system32(monkeypatch):
    calls = []

    def fake_run(args, timeout=10.0):
        calls.append(args)
        return read("route_print_en.txt")

    monkeypatch.setattr(netinfo, "IS_WINDOWS", True)
    monkeypatch.setattr(netinfo, "run", fake_run)
    assert netinfo.default_routes()[0] == Route("192.168.0.1", "192.168.0.23", 35)
    route_exe = system.windows_tool("route.exe")
    assert calls == [[route_exe, "print", "-4"]]
    assert ntpath.isabs(route_exe)


def test_real_system_lookups_do_not_crash():
    netinfo.interfaces()
    netinfo.default_routes()
    netinfo.local_network()
