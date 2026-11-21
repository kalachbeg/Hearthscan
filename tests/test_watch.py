import asyncio
import json
import math
from ipaddress import ip_address, ip_network

import pytest

from hearthscan import audit, discovery, runner, watch
from hearthscan.models import Device, Finding, ScanResult
from hearthscan.netinfo import Interface, NetworkInfo
from hearthscan.store import KnownDevices

ETH = Interface("eth0", "Wi-Fi", ip_address("192.168.1.50"), ip_network("192.168.1.0/24"))
INFO = NetworkInfo(ETH, "192.168.1.1")


def mac(last_octet):
    return f"a4:83:e7:00:00:{last_octet:02x}"


def here(last_octet, **kw):
    """A device that answered."""
    kw.setdefault("mac", mac(last_octet))
    return Device(f"192.168.1.{last_octet}", seen_by={"arp", "mdns"}, confirmed=True, **kw)


def entry(last_octet):
    """A device known from nothing but a neighbor table entry."""
    return Device(f"192.168.1.{last_octet}", mac=mac(last_octet), seen_by={"arp"})


def me():
    return Device("192.168.1.50", is_self=True, seen_by={"local"}, confirmed=True)


@pytest.fixture
def state(monkeypatch, tmp_path):
    folder = tmp_path / "state"
    monkeypatch.setenv("HEARTHSCAN_STATE_DIR", str(folder))
    return folder


@pytest.fixture
def lan(monkeypatch, state):
    """Discovery faked. Each call takes the next item of lan["rounds"]:
    a list of devices to return, or an exception to raise."""
    plan = {"rounds": [], "calls": 0, "notes": []}

    async def discover(info, *, on_note=None, **kw):
        assert info is INFO
        step = plan["rounds"][plan["calls"]]
        plan["calls"] += 1
        for source, message in plan["notes"]:
            on_note(source, message)
        if isinstance(step, BaseException):
            raise step
        return list(step)

    async def no_audit(*args, **kw):
        raise AssertionError("audit should not run")

    monkeypatch.setattr(discovery, "discover", discover)
    monkeypatch.setattr(audit, "audit", no_audit)
    return plan


def run(store, steps, plan, **kw):
    plan["rounds"], plan["calls"] = list(steps), 0
    seen = {"rounds": [], "waits": [], "notes": []}
    options = {"every": 0, "rounds": len(steps), **kw}
    asyncio.run(
        watch.watch(
            INFO,
            store,
            on_round=seen["rounds"].append,
            on_wait=seen["waits"].append,
            on_note=lambda *note: seen["notes"].append(note),
            **options,
        )
    )
    return seen


def told(round_):
    """The changes of a round as (kind, address) pairs."""
    return [(c.kind, c.device.ip if c.device else None) for c in round_.changes]


def saved_keys(state):
    data = json.loads((state / "known.json").read_text(encoding="utf-8"))
    return [item["key"] for item in data["devices"]]


def test_the_first_run_learns_everything(lan, state):
    store = KnownDevices.load()
    seen = run(store, [[here(1), entry(30), me()]], lan)
    (first,) = seen["rounds"]
    assert first.number == 1
    assert first.result is None
    assert [d.ip for d in first.devices] == ["192.168.1.1", "192.168.1.30", "192.168.1.50"]
    assert told(first) == [("new", "192.168.1.1"), ("new", "192.168.1.30"), ("new", "192.168.1.50")]
    assert [c.known.key for c in first.changes] == [mac(1), mac(30), "self"]
    assert first.started <= first.finished
    assert saved_keys(state) == [mac(1), mac(30), "self"]


def test_a_known_network_starts_quietly(lan, state):
    run(KnownDevices.load(), [[here(1), here(20), me()]], lan)
    # The next run reads the list back and only new devices stand out, even
    # though .20 is missing and .30 was not there the first time.
    seen = run(KnownDevices.load(), [[here(1), here(30), me()]], lan)
    assert told(seen["rounds"][0]) == [("new", "192.168.1.30")]


def test_new_back_and_gone(lan, state):
    store = KnownDevices.load()
    seen = run(
        store,
        [
            [here(1), here(20), me()],
            [here(1), me()],
            [here(1), here(20), here(30), me()],
            [here(1), here(20), here(30), me()],
        ],
        lan,
    )
    assert [told(r) for r in seen["rounds"]] == [
        [("new", "192.168.1.1"), ("new", "192.168.1.20"), ("new", "192.168.1.50")],
        [("gone", "192.168.1.20")],
        [("back", "192.168.1.20"), ("new", "192.168.1.30")],
        [],
    ]
    gone = seen["rounds"][1].changes[0]
    assert gone.known.key == mac(20) and gone.finding is None
    assert [r.number for r in seen["rounds"]] == [1, 2, 3, 4]
    assert saved_keys(state) == [mac(1), mac(20), "self", mac(30)]


def test_a_known_device_that_turns_up_later_is_back(lan):
    store = KnownDevices()
    store.update([here(20)], "2026-03-01T10:00:00+00:00")
    seen = run(store, [[here(1)], [here(1), here(20)]], lan)
    assert told(seen["rounds"][1]) == [("back", "192.168.1.20")]


def test_bare_table_entries_do_not_flap(lan):
    store = KnownDevices()
    store.update([here(20), here(30), here(40)], "2026-03-01T10:00:00+00:00")
    seen = run(
        store,
        [
            # .20 answers at first and then only lingers in the table.
            # .30 is never more than an entry that comes and goes.
            # .40 lingers before it answers, so it was here all along.
            [here(20), entry(30), entry(40)],
            [entry(20), entry(40)],
            [here(20), entry(30), here(40)],
            [entry(20), entry(40)],
            [entry(20), entry(30), here(40)],
        ],
        lan,
    )
    assert [told(r) for r in seen["rounds"]] == [[], [], [], [], []]


def test_gone_once_the_entry_is_gone_too(lan):
    store = KnownDevices()
    store.update([here(20)], "2026-03-01T10:00:00+00:00")
    seen = run(store, [[here(20)], [entry(20)], [], [entry(20)], [here(20)]], lan)
    assert [told(r) for r in seen["rounds"]] == [
        [],
        [],
        [("gone", "192.168.1.20")],
        # Told it left, so an entry alone does not bring it back...
        [],
        # ...but an answer does.
        [("back", "192.168.1.20")],
    ]


def test_a_missing_entry_then_an_answer_is_back(lan):
    store = KnownDevices()
    store.update([here(20)], "2026-03-01T10:00:00+00:00")
    seen = run(store, [[entry(20)], [], [entry(20)], [here(20)]], lan)
    assert [told(r) for r in seen["rounds"]] == [[], [], [], [("back", "192.168.1.20")]]


def test_a_newcomer_seen_only_in_the_table(lan):
    seen = run(KnownDevices(), [[me()], [me(), entry(40)], [me(), here(40)], [me()]], lan)
    assert [told(r) for r in seen["rounds"]] == [
        [("new", "192.168.1.50")],
        [("new", "192.168.1.40")],
        [],
        [("gone", "192.168.1.40")],
    ]


def test_a_new_address_is_not_a_new_device(lan):
    moved = here(20)
    moved.ip = "192.168.1.21"
    seen = run(KnownDevices(), [[here(20)], [moved]], lan)
    assert told(seen["rounds"][1]) == []


def test_rounds_and_waits(lan):
    seen = run(KnownDevices(), [[me()]] * 3, lan, every=0.25)
    assert len(seen["rounds"]) == 3
    # Once before each wait, and no wait after the last round.
    assert len(seen["waits"]) == 2
    assert all(0 < left <= 0.25 for left in seen["waits"])


def test_no_wait_when_a_round_takes_longer_than_every(lan):
    seen = run(KnownDevices(), [[me()]] * 2, lan, every=0)
    assert len(seen["rounds"]) == 2
    assert seen["waits"] == []


def test_a_failed_round_becomes_a_note(lan, state):
    store = KnownDevices()
    seen = run(
        store,
        [[here(1), here(20)], OSError("Network is unreachable"), [here(1)]],
        lan,
    )
    assert seen["notes"] == [("watch", "round 2 failed (Network is unreachable)")]
    assert [r.number for r in seen["rounds"]] == [1, 3]
    # Compared with the last round that worked.
    assert told(seen["rounds"][1]) == [("gone", "192.168.1.20")]
    assert lan["calls"] == 3


def test_other_errors_stop_the_watch(lan, state):
    lan["rounds"] = [[here(1)], RuntimeError("bug")]
    rounds = []

    async def main():
        await watch.watch(INFO, KnownDevices(), every=0, rounds=3, on_round=rounds.append)

    with pytest.raises(RuntimeError, match="bug"):
        asyncio.run(main())
    assert len(rounds) == 1
    assert saved_keys(state) == [mac(1)]


def test_discovery_notes_are_passed_on_once(lan):
    lan["notes"] = [("mdns", "mdns did not run (no multicast)")]
    seen = run(KnownDevices(), [[me()]] * 3, lan)
    assert seen["notes"] == [("mdns", "mdns did not run (no multicast)")]


def test_a_failed_save_becomes_a_note(lan, state, monkeypatch):
    store = KnownDevices()
    real_save = store.save
    attempts = []

    def save():
        attempts.append(1)
        if len(attempts) == 1:
            raise PermissionError("in use")
        real_save()

    monkeypatch.setattr(store, "save", save)
    seen = run(store, [[here(1)], [here(1), here(20)]], lan)
    assert seen["notes"] == [("store", "could not save the list of known devices (in use)")]
    assert len(seen["rounds"]) == 2
    assert saved_keys(state) == [mac(1), mac(20)]


@pytest.mark.parametrize(
    "kw",
    [
        {"every": 29.9},
        {"every": 0},
        {"every": -1, "rounds": 2},
        {"every": math.nan, "rounds": 2},
        {"every": math.inf},
        {"every": "300"},
        {"every": True, "rounds": 2},
        {"rounds": 0},
        {"rounds": -3},
        {"rounds": 2.0},
        {"rounds": True},
    ],
)
def test_bad_arguments_fail_before_anything_runs(lan, kw):
    async def main():
        await watch.watch(INFO, KnownDevices(), on_round=lambda r: None, **kw)

    with pytest.raises(ValueError):
        asyncio.run(main())
    assert lan["calls"] == 0


# Full scans


def result(devices, findings):
    return ScanResult(
        version="2.0.0",
        started="2026-03-01T10:00:00+00:00",
        finished="2026-03-01T10:00:30+00:00",
        interface="Wi-Fi",
        address="192.168.1.50",
        network="192.168.1.0/24",
        gateway="192.168.1.1",
        devices=devices,
        findings=findings,
    )


def telnet(ip):
    return Finding("telnet-open", "high", ip, port=23, params={"port": "23"})


def forward(external):
    params = {"external_port": str(external), "internal_port": "443", "protocol": "TCP"}
    return Finding("port-forward", "low", "192.168.1.20", port=443, params=params)


@pytest.fixture
def audits(monkeypatch, lan):
    """The audit faked. Each call returns the next item of audits["results"]."""
    plan = {"results": [], "calls": 0}

    async def fake_audit(info, *, on_note=None, **kw):
        assert info is INFO
        found = plan["results"][plan["calls"]]
        plan["calls"] += 1
        return found

    monkeypatch.setattr(audit, "audit", fake_audit)
    return plan


def test_full_scans_report_new_findings(lan, audits):
    moved = here(20)
    moved.ip = "192.168.1.21"
    audits["results"] = [
        result([here(1), here(20)], [telnet("192.168.1.1")]),
        result([here(1), here(20)], [telnet("192.168.1.1"), telnet("192.168.1.20")]),
        # .20 moved to another address; its finding is still the same one.
        result([here(1), moved], [telnet("192.168.1.1"), telnet("192.168.1.21")]),
        result([here(1), here(20)], [telnet("192.168.1.20"), forward(8443)]),
        result([here(1), here(20)], [telnet("192.168.1.20"), forward(8443), forward(9443)]),
    ]
    seen = run(KnownDevices(), [None] * 5, lan, full=True)
    rounds = seen["rounds"]
    assert lan["calls"] == 0 and audits["calls"] == 5
    assert rounds[0].result is audits["results"][0]
    assert rounds[0].devices == audits["results"][0].devices

    def findings(round_):
        return [
            (c.finding.rule, c.device.ip, c.finding.params.get("external_port"))
            for c in round_.changes
            if c.kind == "finding"
        ]

    # Nothing to compare with in the first round.
    assert told(rounds[0]) == [("new", "192.168.1.1"), ("new", "192.168.1.20")]
    assert findings(rounds[1]) == [("telnet-open", "192.168.1.20", None)]
    assert rounds[1].changes[0].known.key == mac(20)
    assert told(rounds[2]) == []
    assert findings(rounds[3]) == [("port-forward", "192.168.1.20", "8443")]
    # Two forwards to one port are two findings.
    assert findings(rounds[4]) == [("port-forward", "192.168.1.20", "9443")]


# Stopping


def test_cancelling_during_the_wait(lan, state):
    lan["rounds"] = [[here(1), me()]]
    waiting = []

    async def main():
        store = KnownDevices()
        task = asyncio.ensure_future(
            watch.watch(
                INFO,
                store,
                every=3600,
                on_round=lambda r: None,
                on_wait=waiting.append,
            )
        )
        for _ in range(500):
            if waiting:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []
    assert len(waiting) == 1 and 3500 < waiting[0] <= 3600
    assert saved_keys(state) == [mac(1), "self"]


def test_cancelling_during_a_round(lan, state, monkeypatch):
    lan["rounds"] = [[here(1)]]
    reached = []
    real_discover = discovery.discover

    async def slow(info, **kw):
        if lan["calls"] == 0:
            return await real_discover(info, **kw)
        reached.append(1)
        await asyncio.sleep(3600)

    monkeypatch.setattr(discovery, "discover", slow)

    async def main():
        task = asyncio.ensure_future(
            watch.watch(INFO, KnownDevices(), every=0, rounds=5, on_round=lambda r: None)
        )
        for _ in range(500):
            if reached:
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    assert asyncio.run(main()) == []
    assert reached == [1]
    assert saved_keys(state) == [mac(1)]


def test_ctrl_c_through_the_runner(lan, state):
    lan["rounds"] = [[here(1), here(20)]]

    def interrupted(left):
        # What the runner's SIGINT handler does: cancel the main task.
        asyncio.current_task().cancel()

    with pytest.raises(KeyboardInterrupt):
        runner.run(
            watch.watch(
                INFO, KnownDevices(), every=3600, on_round=lambda r: None, on_wait=interrupted
            )
        )
    assert saved_keys(state) == [mac(1), mac(20)]
