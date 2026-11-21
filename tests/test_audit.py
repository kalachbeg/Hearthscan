import asyncio
import re
from ipaddress import ip_address, ip_network

import pytest

from hearthscan import __version__, audit, discovery, ports, probes, rules, runner, scoring
from hearthscan.discovery import arp, classify
from hearthscan.models import Device, Finding, MdnsInfo, Service
from hearthscan.netinfo import Interface, NetworkInfo
from hearthscan.ports import PortResult, PortState

ETH = Interface("eth0", "Wi-Fi", ip_address("192.168.1.50"), ip_network("192.168.1.0/24"))
INFO = NetworkInfo(ETH, "192.168.1.1")
PORTS = [23, 80, 443, 445, 631, 9100]
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00")
FINDING = Finding("telnet-open", "high", "192.168.1.1", port=23, params={"port": "23"})


def mac(last_octet):
    return f"a4:83:e7:00:00:{last_octet:02x}"


def entry(last_octet, state):
    return arp.Neighbor(f"192.168.1.{last_octet}", mac(last_octet), "eth0", state)


def found_by_discovery():
    """What the fake discovery returns, out of order on purpose."""
    return [
        Device(
            "192.168.1.50",
            dns_name="workstation",
            seen_by={"local"},
            confirmed=True,
            is_self=True,
            kind="computer",
            evidence=["this computer"],
        ),
        Device("192.168.1.1", mac=mac(1), seen_by={"arp", "ssdp"}, confirmed=True, is_gateway=True),
        Device(
            "192.168.1.100",
            mac=mac(100),
            mdns=MdnsInfo(hostname="office.local"),
            seen_by={"arp", "mdns"},
            confirmed=True,
        ),
        # Bare neighbor table entries. .20 answers with a reset, .30 and .40 stay
        # silent, and only .30 is still in the table afterwards.
        Device("192.168.1.20", mac=mac(20), seen_by={"arp"}),
        Device("192.168.1.30", mac=mac(30), seen_by={"arp"}),
        Device("192.168.1.40", mac=mac(40), seen_by={"arp"}),
    ]


@pytest.fixture
def net(monkeypatch):
    """Discovery, the port scan, the probes, the rules and scoring, all faked.

    Tests change what answers through net["open"], net["closed"] and net["table"].
    """
    calls = {
        "open": {
            ("192.168.1.1", 23),
            ("192.168.1.1", 80),
            ("192.168.1.100", 631),
            ("192.168.1.100", 9100),
            ("192.168.1.50", 445),
        },
        "closed": {("192.168.1.1", 443), ("192.168.1.20", 80)},
        "table": [entry(1, "reachable"), entry(20, "stale"), entry(30, "stale")],
        "scan": [],
        "reads": 0,
        "probes": [],
        "rules": [],
        "scores": [],
    }

    async def discover(info, *, on_note=None, **kw):
        calls["discover"] = info
        on_note("mdns", "mdns did not run (no multicast)")
        return found_by_discovery()

    async def scan(hosts, port_list, *, timeout, on_progress=None, **kw):
        hosts, port_list = list(hosts), list(port_list)
        calls["scan"].append((hosts, port_list, timeout))
        jobs = [(host, port) for host in hosts for port in port_list]
        results = []
        for done, job in enumerate(jobs, 1):
            state = PortState.FILTERED
            if job in calls["open"]:
                state = PortState.OPEN
            elif job in calls["closed"]:
                state = PortState.CLOSED
            results.append(PortResult(*job, state))
            if on_progress:
                on_progress(done, len(jobs))
        return results

    def neighbors():
        calls["reads"] += 1
        return calls["table"]

    async def probe_all(targets, *, timeout=2.0, concurrency=32, on_done=None):
        targets = list(targets)
        calls["probes"].append((targets, timeout))
        found = {}
        for ip, port in targets:
            found[ip, port] = Service(port, name=f"probed-{port}", product="Acme 1.0", auth="none")
            if on_done:
                on_done((ip, port), found[ip, port])
        return found

    def evaluate(devices, *, gateway=None):
        devices = list(devices)
        calls["rules"].append((devices, gateway))
        return [FINDING]

    def score(findings):
        calls["scores"].append(list(findings))
        return 85

    monkeypatch.setattr(discovery, "discover", discover)
    monkeypatch.setattr(ports, "scan", scan)
    monkeypatch.setattr(arp, "neighbors", neighbors)
    monkeypatch.setattr(probes, "probe_all", probe_all)
    monkeypatch.setattr(rules, "evaluate", evaluate)
    monkeypatch.setattr(scoring, "score", score)
    return calls


def run_audit(info=INFO, **kw):
    stages, notes = [], []
    result = asyncio.run(
        audit.audit(
            info,
            on_progress=lambda *stage: stages.append(stage),
            on_note=lambda *note: notes.append(note),
            **{"ports": PORTS, **kw},
        )
    )
    return result, stages, notes


def stage_names(stages):
    names = []
    for name, _, _ in stages:
        if not names or names[-1] != name:
            names.append(name)
    return names


def steps(stages, wanted):
    return [(done, total) for name, done, total in stages if name == wanted]


def scanned_hosts(net):
    return [host for hosts, _, _ in net["scan"] for host in hosts]


def test_audit_end_to_end(net):
    result, stages, notes = run_audit()
    by_ip = {d.ip: d for d in result.devices}

    assert stage_names(stages) == ["discover", "ports", "probes", "checks", "done"]
    assert stages[0] == ("discover", 0, 0)
    assert stages[-2:] == [("checks", 0, 0), ("done", 0, 0)]
    assert steps(stages, "ports") == [(n, 36) for n in range(37)]
    assert steps(stages, "probes") == [(n, 5) for n in range(6)]

    assert net["discover"] is INFO
    assert scanned_hosts(net) == [d.ip for d in found_by_discovery()]
    assert net["scan"][0][1:] == (PORTS, 1.0)

    # Sorted by address, and .40 is gone: silent, and no longer in the table.
    assert [d.ip for d in result.devices] == [
        "192.168.1.1",
        "192.168.1.20",
        "192.168.1.30",
        "192.168.1.50",
        "192.168.1.100",
    ]
    assert net["reads"] == 1

    # A reset is an answer too.
    assert by_ip["192.168.1.20"].confirmed
    assert by_ip["192.168.1.20"].seen_by == {"arp", "tcp"}
    assert by_ip["192.168.1.20"].services == []
    # Still listed, so kept, but nothing vouches for it.
    assert not by_ip["192.168.1.30"].confirmed
    assert by_ip["192.168.1.30"].seen_by == {"arp"}
    assert by_ip["192.168.1.1"].seen_by == {"arp", "ssdp", "tcp"}

    router = by_ip["192.168.1.1"]
    assert [(s.port, s.name, s.product) for s in router.services] == [
        (23, "probed-23", "Acme 1.0"),
        (80, "probed-80", "Acme 1.0"),
    ]
    targets, probe_timeout = net["probes"][0]
    assert sorted(targets) == sorted(net["open"])
    assert probe_timeout == audit.PROBE_TIMEOUT

    # Classified again now that the ports are known. This machine stays as is.
    printer = by_ip["192.168.1.100"]
    assert printer.kind == "printer" and "port 9100 open" in printer.evidence
    assert router.kind == "router"
    me = by_ip["192.168.1.50"]
    assert me.kind == "computer" and me.evidence == ["this computer"]
    assert [s.port for s in me.services] == [445]
    assert "tcp" in me.seen_by

    checked, gateway = net["rules"][0]
    assert checked == result.devices and gateway == "192.168.1.1"
    assert checked[-1].kind == "printer"
    assert net["scores"] == [[FINDING]]
    assert result.findings == [FINDING]
    assert result.score == 85

    assert result.version == __version__
    assert STAMP.fullmatch(result.started) and STAMP.fullmatch(result.finished)
    assert result.started <= result.finished
    assert result.interface == "Wi-Fi"
    assert result.address == "192.168.1.50"
    assert result.network == "192.168.1.0/24"
    assert result.gateway == "192.168.1.1"
    assert result.ports == PORTS
    assert result.notes == notes == [("mdns", "mdns did not run (no multicast)")]


def test_without_probes_the_services_stay_plain(net):
    result, stages, _ = run_audit(probe=False)
    assert net["probes"] == []
    assert stage_names(stages) == ["discover", "ports", "checks", "done"]
    assert result.device("192.168.1.1").services == [
        Service(23, name="telnet"),
        Service(80, name="http"),
    ]
    assert result.device("192.168.1.100").services == [
        Service(631, name="ipp"),
        Service(9100, name="jetdirect"),
    ]
    assert result.device("192.168.1.100").kind == "printer"


def test_services_are_sorted_and_unknown_ports_get_no_name(net):
    net["open"] |= {("192.168.1.50", 47123), ("192.168.1.50", 22)}
    result, _, _ = run_audit(probe=False, ports=[47123, *PORTS, 22])
    assert result.device("192.168.1.50").services == [
        Service(22, name="ssh"),
        Service(445, name="smb"),
        Service(47123),
    ]


def test_a_probe_failure_does_not_sink_the_audit(net, monkeypatch):
    async def broken(targets, **kw):
        raise RuntimeError("probe blew up")

    monkeypatch.setattr(probes, "probe_all", broken)
    result, stages, notes = run_audit()
    assert result.device("192.168.1.1").services == [
        Service(23, name="telnet"),
        Service(80, name="http"),
    ]
    assert ("probes", "service probes failed (RuntimeError: probe blew up)") in notes
    assert result.notes == notes
    assert result.score == 85 and stages[-1] == ("done", 0, 0)


def test_only_matching_probe_results_replace_services(net, monkeypatch):
    async def odd(targets, **kw):
        return {
            ("192.168.1.1", 23): Service(23, name="telnet", banner="login:"),
            ("192.168.1.1", 80): "not a service",
            ("192.168.1.100", 631): Service(632, name="ipp"),
            ("192.168.1.99", 22): Service(22, name="ssh"),
        }

    monkeypatch.setattr(probes, "probe_all", odd)
    result, _, _ = run_audit()
    assert result.device("192.168.1.1").services == [
        Service(23, name="telnet", banner="login:"),
        Service(80, name="http"),
    ]
    assert result.device("192.168.1.100").services == [
        Service(631, name="ipp"),
        Service(9100, name="jetdirect"),
    ]
    assert result.device("192.168.1.99") is None


def test_probe_progress_counts_calls_whatever_they_carry(net, monkeypatch):
    async def counting(targets, *, on_done=None, **kw):
        targets = list(targets)
        for done in range(1, len(targets) + 1):
            on_done(done, len(targets))
        on_done(len(targets), len(targets))  # one too many is clamped
        return {}

    monkeypatch.setattr(probes, "probe_all", counting)
    _, stages, _ = run_audit()
    assert steps(stages, "probes") == [(0, 5), (1, 5), (2, 5), (3, 5), (4, 5), (5, 5), (5, 5)]


def test_no_open_ports_means_no_probes(net):
    net["open"] = set()
    result, stages, _ = run_audit()
    assert net["probes"] == []
    assert steps(stages, "probes") == [(0, 0)]
    assert all(d.services == [] for d in result.devices)


def test_classify_runs_again_on_everything_but_this_machine(net, monkeypatch):
    seen = []
    monkeypatch.setattr(classify, "classify", lambda d: seen.append((d.ip, list(d.services))))
    run_audit()
    assert sorted(ip for ip, _ in seen) == [
        "192.168.1.1",
        "192.168.1.100",
        "192.168.1.20",
        "192.168.1.30",
    ]
    services = dict(seen)["192.168.1.100"]
    assert [s.product for s in services] == ["Acme 1.0", "Acme 1.0"]


def test_a_bare_entry_that_turned_reachable_is_kept_and_confirmed(net):
    net["table"] = [entry(30, "reachable"), entry(40, "stale")]
    result, _, _ = run_audit()
    assert result.device("192.168.1.30").confirmed
    assert result.device("192.168.1.30").seen_by == {"arp"}
    assert not result.device("192.168.1.40").confirmed


def test_an_unreadable_table_keeps_every_device(net):
    net["table"] = []
    result, _, _ = run_audit()
    assert {"192.168.1.30", "192.168.1.40"} <= {d.ip for d in result.devices}


def test_no_table_read_when_every_device_answered(net):
    net["closed"] |= {("192.168.1.30", 80), ("192.168.1.40", 80)}
    result, _, _ = run_audit()
    assert net["reads"] == 0
    assert all(d.confirmed for d in result.devices)


def test_an_empty_port_list_scans_nothing(net):
    result, stages, _ = run_audit(ports=[])
    assert net["scan"] == []
    assert steps(stages, "ports") == [(0, 0)]
    assert result.ports == []
    assert "192.168.1.40" not in {d.ip for d in result.devices}


def test_duplicate_ports_are_scanned_once(net):
    result, _, _ = run_audit(ports=[80, 23, 80, 23])
    assert net["scan"][0][1] == [80, 23]
    assert result.ports == [80, 23]


def test_long_port_lists_are_scanned_a_few_hosts_at_a_time(net, monkeypatch):
    monkeypatch.setattr(ports, "MAX_PAIRS", 12)
    result, stages, _ = run_audit()
    assert [hosts for hosts, _, _ in net["scan"]] == [
        ["192.168.1.50", "192.168.1.1"],
        ["192.168.1.100", "192.168.1.20"],
        ["192.168.1.30", "192.168.1.40"],
    ]
    assert steps(stages, "ports") == [(n, 36) for n in range(37)]
    assert result.device("192.168.1.1").services[0].port == 23
    assert result.device("192.168.1.20").confirmed


def test_too_many_open_ports_are_cut(net, monkeypatch):
    monkeypatch.setattr(audit, "MAX_SERVICES", 1)
    result, _, notes = run_audit(probe=False)
    assert result.device("192.168.1.1").services == [Service(23, name="telnet")]
    assert ("ports", "192.168.1.1 accepts connections on 2 ports; kept the first 1") in notes


def test_the_probe_timeout_follows_a_longer_connect_timeout(net):
    run_audit(timeout=3.5)
    assert net["scan"][0][2] == 3.5
    assert net["probes"][0][1] == 3.5


def test_the_result_names_the_network_that_was_swept(net):
    wide = Interface("eth0", "eth0", ip_address("10.0.5.20"), ip_network("10.0.0.0/16"))
    result, _, _ = run_audit(info=NetworkInfo(wide, "10.0.0.1"))
    assert result.network == "10.0.5.0/24"
    assert result.address == "10.0.5.20"


@pytest.mark.parametrize(
    "kw",
    [
        {"timeout": 0},
        {"timeout": -1},
        {"timeout": float("nan")},
        {"timeout": float("inf")},
        {"timeout": True},
        {"timeout": "1"},
        {"ports": [0]},
        {"ports": [65536]},
        {"ports": [True]},
        {"ports": "80"},
        {"ports": [80.0]},
    ],
)
def test_bad_arguments_fail_before_anything_runs(net, kw):
    with pytest.raises(ValueError):
        run_audit(**kw)
    assert "discover" not in net


@pytest.mark.parametrize(
    "module, name",
    [(discovery, "discover"), (ports, "scan"), (probes, "probe_all")],
)
def test_cancelling_leaves_nothing_running(net, monkeypatch, module, name):
    reached = []

    async def forever(*args, **kw):
        reached.append(name)
        await asyncio.sleep(3600)

    monkeypatch.setattr(module, name, forever)

    async def main():
        task = asyncio.ensure_future(audit.audit(INFO, ports=PORTS))
        for _ in range(500):
            if reached:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []
    assert reached == [name]


def test_ctrl_c_through_the_runner(net, monkeypatch):
    async def interrupted(*args, **kw):
        # What the runner's SIGINT handler does: cancel the main task.
        asyncio.current_task().cancel()
        await asyncio.sleep(3600)

    monkeypatch.setattr(probes, "probe_all", interrupted)
    with pytest.raises(KeyboardInterrupt):
        runner.run(audit.audit(INFO, ports=PORTS))


def test_the_runner_hands_back_the_result(net):
    result = runner.run(audit.audit(INFO, ports=PORTS))
    assert result.score == 85 and len(result.devices) == 5


def test_recheck_drops_gone_entries_and_keeps_order(net):
    net["table"] = [entry(1, "reachable"), entry(30, "reachable")]
    devices = [
        Device("192.168.1.1", seen_by={"arp", "ssdp"}, confirmed=True),
        Device("192.168.1.30", seen_by={"arp"}),
        Device("192.168.1.10", seen_by={"netbios"}, confirmed=True),
        Device("192.168.1.40", seen_by={"arp"}),
    ]
    kept = asyncio.run(discovery.recheck(devices, INFO))
    assert [d.ip for d in kept] == ["192.168.1.1", "192.168.1.30", "192.168.1.10"]
    assert kept[1] is devices[1] and kept[1].confirmed
    assert net["reads"] == 1


def test_recheck_reads_nothing_when_all_are_confirmed(net):
    devices = [Device("192.168.1.30", seen_by={"arp"}, confirmed=True)]
    assert asyncio.run(discovery.recheck(devices, INFO)) == devices
    assert net["reads"] == 0
