import json
import os
from pathlib import Path

import pytest

from hearthscan import store, system
from hearthscan.models import Device
from hearthscan.store import Known, KnownDevices, device_key

T1 = "2026-03-01T10:00:00+00:00"
T2 = "2026-03-01T10:05:00+00:00"
T3 = "2026-03-02T08:00:00+00:00"


@pytest.fixture(autouse=True)
def state(monkeypatch, tmp_path):
    folder = tmp_path / "state"
    monkeypatch.setenv("HEARTHSCAN_STATE_DIR", str(folder))
    return folder


def mac(last_octet):
    return f"a4:83:e7:00:00:{last_octet:02x}"


def device(last_octet, **kw):
    kw.setdefault("mac", mac(last_octet))
    kw.setdefault("confirmed", True)
    return Device(f"192.168.1.{last_octet}", **kw)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def saved(records):
    return {"tool": "hearthscan", "type": "known-devices", "version": 1, "devices": records}


def record(key, **kw):
    return {"key": key, "first_seen": T1, "last_seen": T1, **kw}


# Where the file lives


@pytest.fixture
def home(monkeypatch, tmp_path):
    folder = tmp_path / "home"
    monkeypatch.delenv("HEARTHSCAN_STATE_DIR")
    monkeypatch.setattr(Path, "home", lambda: folder)
    return folder


def on(monkeypatch, name):
    monkeypatch.setattr(system, "IS_WINDOWS", name == "windows")
    monkeypatch.setattr(system, "IS_MACOS", name == "macos")


def test_the_override_wins(monkeypatch, state):
    on(monkeypatch, "windows")
    assert store.state_dir() == state
    assert store.default_path() == state / "known.json"


def test_windows_uses_local_app_data(home, monkeypatch, tmp_path):
    on(monkeypatch, "windows")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert store.state_dir() == tmp_path / "Local" / "Hearthscan"
    monkeypatch.delenv("LOCALAPPDATA")
    assert store.state_dir() == home / "AppData" / "Local" / "Hearthscan"


def test_macos_uses_application_support(home, monkeypatch):
    on(monkeypatch, "macos")
    assert store.state_dir() == home / "Library" / "Application Support" / "Hearthscan"


def test_linux_follows_xdg(home, monkeypatch, tmp_path):
    on(monkeypatch, "linux")
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert store.state_dir() == tmp_path / "xdg" / "hearthscan"
    # A relative path is to be ignored.
    monkeypatch.setenv("XDG_STATE_HOME", os.path.join("relative", "state"))
    assert store.state_dir() == home / ".local" / "state" / "hearthscan"
    monkeypatch.delenv("XDG_STATE_HOME")
    assert store.state_dir() == home / ".local" / "state" / "hearthscan"


def test_the_folder_appears_on_the_first_save(state):
    known = KnownDevices.load()
    assert len(known) == 0 and known.broken is None
    assert not state.exists()
    known.update([device(1)], T1)
    known.save()
    assert (state / "known.json").is_file()


# Keys


def test_device_keys():
    assert device_key(device(1, mac="A4-83-E7-00-00-01")) == "a4:83:e7:00:00:01"
    assert device_key(device(1, mac=None)) == "ip:192.168.1.1"
    assert device_key(device(1, mac="not a mac")) == "ip:192.168.1.1"
    # This machine comes without a MAC and may change its address.
    assert device_key(Device("192.168.1.50", is_self=True)) == "self"


# Updating


def test_update_returns_only_devices_never_seen_before():
    known = KnownDevices()
    first = known.update([device(1), device(20)], T1)
    assert [r.key for r in first] == [mac(1), mac(20)]
    assert all(r.first_seen == r.last_seen == T1 for r in first)

    again = known.update([device(1), device(20), device(30)], T2)
    assert [r.key for r in again] == [mac(30)]
    assert [r.key for r in known.records] == [mac(1), mac(20), mac(30)]
    assert known.get(mac(1)).first_seen == T1
    assert known.get(mac(1)).last_seen == T2


def test_update_refreshes_but_keeps_what_a_scan_missed():
    known = KnownDevices()
    named = device(20, dns_name="printer.lan", vendor="Acme", kind="printer")
    known.update([named], T1)
    moved = device(20, vendor=None, kind="unknown")
    moved.ip = "192.168.1.21"
    assert known.update([moved], T2) == []
    found = known.get(mac(20))
    assert (found.last_ip, found.name, found.vendor, found.kind) == (
        "192.168.1.21",
        "printer",
        "Acme",
        "printer",
    )
    renamed = device(20, dns_name="office-printer.lan", kind="nas")
    known.update([renamed], T3)
    assert (found.name, found.kind, found.last_seen) == ("office-printer", "nas", T3)


def test_a_bare_table_entry_is_recorded_but_not_seen_again():
    known = KnownDevices()
    assert [r.key for r in known.update([device(30, confirmed=False)], T1)] == [mac(30)]
    known.update([device(30, confirmed=False)], T3)
    assert known.get(mac(30)).last_seen == T1


def test_one_record_per_device_in_a_scan():
    known = KnownDevices()
    twice = [device(1), device(1, mac=mac(1).upper())]
    twice[1].ip = "192.168.1.2"
    assert len(known.update(twice, T1)) == 1
    assert known.get(mac(1)).last_ip == "192.168.1.1"


def test_random_macs_are_marked():
    known = KnownDevices()
    known.update([device(1), device(2, mac="da:a1:19:00:00:02")], T1)
    assert not known.get(mac(1)).random_mac
    assert known.get("da:a1:19:00:00:02").random_mac


def test_text_fields_are_cleaned_and_capped():
    known = KnownDevices()
    noisy = device(1, dns_name="\x1b[31mred\x1b[0m " + "x" * 1000, vendor="Acme\nCorp\x00")
    (found,) = known.update([noisy], T1)
    assert len(found.name) == store.MAX_TEXT
    assert found.name.startswith("[31mred [0m xxx")
    assert "\x1b" not in found.name
    assert found.vendor == "Acme Corp"


def test_update_rejects_a_bad_time():
    with pytest.raises(ValueError):
        KnownDevices().update([device(1)], "yesterday")


# Trusting and forgetting


def test_trust_forget_and_clear():
    known = KnownDevices()
    known.update([device(1), device(20)], T1)
    assert known.trust("A4-83-E7-00-00-01")
    assert known.get(mac(1)).trusted
    assert not known.trust("ip:192.168.1.99")
    assert known.trust(mac(1), trusted=False)
    assert not known.get(mac(1)).trusted

    assert known.forget(mac(20))
    assert not known.forget(mac(20))
    assert mac(20) not in known and mac(1) in known
    assert [r.key for r in known.update([device(20)], T2)] == [mac(20)]

    known.clear()
    assert known.records == []


def test_find_by_mac_key_or_last_address():
    known = KnownDevices()
    known.update([device(1), device(20, mac=None)], T1)
    old = device(30)
    known.update([old], T1)
    newer = device(31)
    newer.ip = "192.168.1.30"
    known.update([newer], T2)
    assert known.find("A4:83:E7:00:00:01").key == mac(1)
    assert known.find("ip:192.168.1.20").key == "ip:192.168.1.20"
    assert known.find("192.168.1.20").key == "ip:192.168.1.20"
    # Two records had that address; the one seen last has it now.
    assert known.find("192.168.1.30").key == mac(31)
    assert known.find("192.168.1.99") is None


# Saving and loading


def test_save_and_load_round_trip(state):
    known = KnownDevices.load()
    known.update(
        [device(1, dns_name="router.lan", kind="router"), device(2, mac="da:a1:19:00:00:02")], T1
    )
    known.trust(mac(1))
    known.save()

    data = json.loads((state / "known.json").read_text(encoding="utf-8"))
    assert (data["tool"], data["type"], data["version"]) == ("hearthscan", "known-devices", 1)
    assert data["devices"][0] == {
        "key": mac(1),
        "first_seen": T1,
        "last_seen": T1,
        "last_ip": "192.168.1.1",
        "name": "router",
        "vendor": None,
        "kind": "router",
        "trusted": True,
        "random_mac": False,
    }

    again = KnownDevices.load()
    assert again.records == known.records
    assert again.broken is None


def test_load_reads_older_and_newer_fields(state):
    write(
        state / "known.json",
        saved(
            [
                record("A4-83-E7-00-00-01", colour="blue"),
                record("ip:192.168.1.7", last_ip="192.168.1.7", name="n" * 500),
            ]
        ),
    )
    known = KnownDevices.load()
    first, second = known.records
    assert first == Known(mac(1), T1, T1)
    assert len(second.name) == store.MAX_TEXT
    assert known.broken is None


def test_saving_is_atomic(state, monkeypatch):
    known = KnownDevices.load()
    known.update([device(1)], T1)
    known.save()
    before = (state / "known.json").read_bytes()

    def fail(src, dst):
        raise PermissionError("in use")

    known.update([device(20)], T2)
    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(PermissionError):
        known.save()
    assert (state / "known.json").read_bytes() == before
    assert sorted(p.name for p in state.iterdir()) == ["known.json"]


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"{not json",
        b"\xff\xfe\x00garbage",
        b"[" * 100_000,
        json.dumps([]).encode(),
        json.dumps({"schema": 1, "tool": "hearthscan", "devices": []}).encode(),
        json.dumps({"tool": "other", "type": "known-devices", "version": 1}).encode(),
        json.dumps({**saved([]), "version": 2}).encode(),
        json.dumps({**saved([]), "version": True}).encode(),
        json.dumps(saved({})).encode(),
        json.dumps(saved(["a4:83:e7:00:00:01"])).encode(),
        json.dumps(saved([{"first_seen": T1, "last_seen": T1}])).encode(),
        json.dumps(saved([record("bad\nkey")])).encode(),
        json.dumps(saved([record(mac(1), last_seen="soon")])).encode(),
        json.dumps(saved([record(mac(1), trusted="yes")])).encode(),
        json.dumps(saved([record(mac(1), name=7)])).encode(),
    ],
)
def test_a_broken_file_is_kept_aside(state, content):
    state.mkdir()
    (state / "known.json").write_bytes(content)
    known = KnownDevices.load()
    assert known.records == []
    assert known.broken == state / "known.json.broken"
    assert known.broken.read_bytes() == content
    assert not (state / "known.json").exists()

    known.update([device(1)], T1)
    known.save()
    assert [r.key for r in KnownDevices.load().records] == [mac(1)]


def test_an_oversized_file_is_kept_aside(state, monkeypatch):
    write(state / "known.json", saved([record(mac(n)) for n in range(1, 50)]))
    monkeypatch.setattr(store, "MAX_FILE", 1000)
    known = KnownDevices.load()
    assert known.records == [] and known.broken is not None


def test_a_file_that_cannot_be_read_raises(state):
    (state / "known.json").mkdir(parents=True)
    with pytest.raises(OSError):
        KnownDevices.load()


# Caps


def test_the_oldest_records_go_first(monkeypatch):
    monkeypatch.setattr(store, "MAX_RECORDS", 3)
    known = KnownDevices()
    known.update([device(1), device(2), device(3)], T1)
    known.update([device(1)], T2)
    known.trust(mac(2))
    # .2 and .3 were seen last the longest ago, but .2 is trusted.
    fresh = known.update([device(4)], T3)
    assert [r.key for r in fresh] == [mac(4)]
    assert sorted(r.key for r in known.records) == [mac(1), mac(2), mac(4)]


def test_a_long_file_is_cut_to_the_cap(state, monkeypatch):
    times = [f"2026-03-{day:02d}T10:00:00+00:00" for day in range(1, 6)]
    write(
        state / "known.json",
        saved([record(mac(n), last_seen=times[n - 1]) for n in (3, 1, 5, 2, 4)]),
    )
    monkeypatch.setattr(store, "MAX_RECORDS", 2)
    known = KnownDevices.load()
    assert [r.key for r in known.records] == [mac(5), mac(4)]
    assert known.broken is None
