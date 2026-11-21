import asyncio
from ipaddress import ip_address, ip_network

import pytest

from hearthscan import __main__ as cli
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
