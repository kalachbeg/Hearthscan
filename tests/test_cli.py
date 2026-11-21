import asyncio
import io
import sys
from ipaddress import ip_address, ip_network

import pytest

from hearthscan import __main__ as cli
from hearthscan import discovery
from hearthscan.models import Device, NetbiosInfo
from hearthscan.netinfo import Interface, NetworkInfo
from hearthscan.ports import PortResult, PortState
from hearthscan.runner import run

HOME = NetworkInfo(
    Interface("eth0", "Ethernet", ip_address("192.168.1.50"), ip_network("192.168.1.0/24")),
    "192.168.1.1",
)


def test_net(monkeypatch, capsys):
    monkeypatch.setattr(cli, "local_network", lambda: HOME)
    assert cli.main(["net"]) == 0
    assert "192.168.1.1" in capsys.readouterr().out


def test_net_when_offline(monkeypatch):
    monkeypatch.setattr(cli, "local_network", lambda: None)
    assert cli.main(["net"]) == 1


def test_ports(monkeypatch, capsys):
    async def fake_scan(hosts, ports, timeout, on_open):
        result = PortResult(hosts[0], 22, PortState.OPEN, 0.001)
        on_open(result)
        return [result]

    monkeypatch.setattr(cli, "scan", fake_scan)
    assert cli.main(["ports", "192.168.1.1", "-p", "22"]) == 0
    assert "22/tcp  open  ssh" in capsys.readouterr().out


@pytest.mark.parametrize(
    "args", [["ports", "8.8.8.8"], ["ports", "192.168.1.1", "-p", "ssh"], ["ports", "10.1"]]
)
def test_ports_with_bad_input(args):
    assert cli.main(args) == 2


@pytest.mark.parametrize("timeout", ["0", "-2", "nan", "inf", "soon"])
def test_timeout_must_be_a_positive_number(timeout):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["ports", "192.168.1.1", "-t", timeout])
    assert stopped.value.code == 2


def test_ctrl_c(monkeypatch):
    def interrupted(coro):
        coro.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run", interrupted)
    assert cli.main(["ports", "192.168.1.1"]) == 130


def test_runner_turns_cancellation_into_keyboard_interrupt():
    async def cancel_myself():
        asyncio.current_task().cancel()
        await asyncio.sleep(1)

    with pytest.raises(KeyboardInterrupt):
        run(cancel_myself())


def test_runner_returns_the_result():
    async def answer():
        return 42

    assert run(answer()) == 42


def fake_discovery(monkeypatch, devices, notes=()):
    async def discover(info, *, on_note=None, **kw):
        for source, message in notes:
            on_note(source, message)
        return devices

    monkeypatch.setattr(cli, "local_network", lambda: HOME)
    monkeypatch.setattr(discovery, "discover", discover)


def test_devices_marks_the_ones_nothing_confirmed(monkeypatch, capsys):
    fake_discovery(
        monkeypatch,
        [
            Device("192.168.1.1", is_gateway=True, confirmed=True),
            Device("192.168.1.30", mac="da:a1:19:00:00:30", seen_by={"arp"}),
            Device("192.168.1.50", is_self=True, confirmed=True),
        ],
        notes=[("firewall", "no device answered mDNS or SSDP. " + "A firewall may " * 10)],
    )
    assert cli.main(["devices"]) == 0
    out, err = capsys.readouterr()
    lines = {line.split()[0]: line for line in out.splitlines() if line.startswith("192.")}
    assert lines["192.168.1.1"].rstrip().endswith("gateway")
    assert lines["192.168.1.30"].rstrip().endswith("seen recently")
    assert lines["192.168.1.50"].rstrip().endswith("you")
    assert "note: no device answered mDNS or SSDP." in err
    assert all(len(line) <= 78 for line in err.splitlines())


def test_devices_output_survives_a_narrow_code_page(monkeypatch):
    # Windows gives a redirected stdout the ANSI code page with strict errors.
    out_bytes, err_bytes = io.BytesIO(), io.BytesIO()
    out = io.TextIOWrapper(out_bytes, encoding="cp1252")
    err = io.TextIOWrapper(err_bytes, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    fake_discovery(
        monkeypatch,
        [
            Device(
                "192.168.1.20",
                vendor="深圳 Example",  # CJK, as in some OUI vendor names
                netbios=NetbiosInfo(name="AY₧E-PC"),  # cp857 name read as cp437
                confirmed=True,
            )
        ],
        notes=[("upnp", "upnp did not run (\U0001f525)")],
    )
    assert cli.main(["devices"]) == 0
    out.flush()
    err.flush()
    assert "AY?E-PC" in out_bytes.getvalue().decode("cp1252")
    assert "?? Example" in out_bytes.getvalue().decode("cp1252")
    assert "did not run (?)" in err_bytes.getvalue().decode("cp1252")
