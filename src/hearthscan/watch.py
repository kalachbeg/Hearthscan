"""Scan again and again and tell what changed since the round before.

Each round compares what it found with the list of devices seen before and
with the previous round. A device known only from a neighbor table entry the
OS has not confirmed tells nothing about whether it is still here, so it never
counts as gone or back on its own.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import audit, discovery, rules
from .models import Device, Finding, ScanResult
from .netinfo import NetworkInfo
from .store import Known, KnownDevices, device_key

# Shorter gaps would have the sweeps of one round still echoing in the next.
MIN_EVERY = 30.0

# Notes from discovery repeat every round. Each is passed on once, and past
# this many different ones the rest are passed on every time.
MAX_NOTES = 256

CHANGE_KINDS = ("new", "back", "gone", "finding")


@dataclass(slots=True)
class Change:
    kind: str  # one of CHANGE_KINDS
    device: Device | None = None  # for "gone", as the last round saw it
    finding: Finding | None = None  # only for "finding"
    known: Known | None = None  # the device's record in the list of devices seen before


@dataclass(slots=True)
class Round:
    number: int  # counts from 1, failed rounds included
    started: str  # ISO 8601, UTC
    finished: str
    devices: list[Device] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    result: ScanResult | None = None  # only with full scans


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _check(every: float, rounds: int | None) -> None:
    if rounds is not None and (
        isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1
    ):
        raise ValueError(f"rounds must be a whole number, 1 or more, not {rounds!r}")
    if (
        isinstance(every, bool)
        or not isinstance(every, (int, float))
        or not math.isfinite(every)
        or every < 0
    ):
        raise ValueError(f"every must be a number of seconds, not {every!r}")
    if rounds is None and every < MIN_EVERY:
        raise ValueError(f"every must be at least {MIN_EVERY:g} seconds, not {every!r}")


class _Presence:
    """Which devices are here, as far as the rounds so far can tell.

    A device is here once a round confirms it, and stays here until a round
    does not list it at all. One listed without confirmation in the first
    round, or first seen that way, is neither here nor gone until a round
    settles it, and settling it reports nothing.
    """

    def __init__(self) -> None:
        self.here: set[str] = set()
        self.unsure: set[str] = set()
        self.last: dict[str, Device] = {}
        self.first = True

    def compare(
        self, devices: list[Device], fresh: dict[str, Known], store: KnownDevices
    ) -> list[Change]:
        listed: dict[str, Device] = {}
        for device in devices:
            listed.setdefault(device_key(device), device)
        changes: list[Change] = []
        for key, device in listed.items():
            if key in self.here:
                continue
            if key in fresh:
                changes.append(Change("new", device, known=fresh[key]))
                if device.confirmed:
                    self.here.add(key)
                else:
                    self.unsure.add(key)
            elif device.confirmed:
                if not self.first and key not in self.unsure:
                    changes.append(Change("back", device, known=store.get(key)))
                self.unsure.discard(key)
                self.here.add(key)
            elif self.first:
                self.unsure.add(key)
        for key, device in self.last.items():
            if key in listed:
                continue
            if key in self.here:
                self.here.discard(key)
                changes.append(Change("gone", device, known=store.get(key)))
            self.unsure.discard(key)
        self.last = listed
        self.first = False
        return changes


def _finding_id(finding: Finding, key: str) -> tuple:
    """What tells findings apart from one round to the next.

    The device key stands in for the address, which DHCP may change.
    """
    try:
        per_port = rules.rule(finding.rule).per_port
    except KeyError:
        per_port = False
    params = () if per_port else tuple(sorted(finding.params.items()))
    return (finding.rule, key, finding.port, params)


def _findings(result: ScanResult) -> dict[tuple, Finding]:
    keys = {device.ip: device_key(device) for device in result.devices}
    found: dict[tuple, Finding] = {}
    for finding in result.findings:
        key = keys.get(finding.ip, f"ip:{finding.ip}")
        found.setdefault(_finding_id(finding, key), finding)
    return found


async def watch(
    info: NetworkInfo,
    store: KnownDevices,
    *,
    every: float = 300.0,
    full: bool = False,
    rounds: int | None = None,
    on_round: Callable[[Round], None],
    on_wait: Callable[[float], None] | None = None,
    on_note: Callable[[str, str], None] | None = None,
) -> None:
    """Find the devices on the network every `every` seconds and report what changed.

    Each round runs discovery, or the whole audit with `full`, records the
    devices in `store`, saves it and calls `on_round`. Rounds start `every`
    seconds apart; before waiting for the next, `on_wait(seconds_left)` is
    called. With `rounds`, the watch stops after that many. Without it,
    `every` has to be at least MIN_EVERY.

    The first round reports the devices `store` has never seen as "new" and
    nothing else. From the second on, a device the store knows is "back" when
    the round before did not have it, and one confirmed earlier is "gone"
    when a round does not list it at all. With `full`, findings the round
    before did not have are reported too, also from the second round on.

    `on_note(source, message)` hears about rounds that failed with an
    OSError (source "watch") and saves that failed (source "store"); the
    watch carries on with the next round. Notes from discovery and the audit
    are passed on the first time they come up.
    """
    _check(every, rounds)
    loop = asyncio.get_running_loop()
    presence = _Presence()
    found_before: set[tuple] | None = None
    passed: set[tuple[str, str]] = set()
    unsaved = False

    def note(source: str, message: str) -> None:
        if on_note:
            on_note(source, message)

    def relay(source: str, message: str) -> None:
        if (source, message) in passed:
            return
        if len(passed) < MAX_NOTES:
            passed.add((source, message))
        note(source, message)

    def save() -> None:
        nonlocal unsaved
        try:
            store.save()
        except OSError as exc:
            note("store", f"could not save the list of known devices ({exc})")
        else:
            unsaved = False

    number = 0
    try:
        while True:
            number += 1
            begun = loop.time()
            started = _now()
            result: ScanResult | None = None
            try:
                if full:
                    result = await audit.audit(info, on_note=relay)
                    devices = result.devices
                else:
                    devices = await discovery.discover(info, on_note=relay)
            except OSError as exc:
                note("watch", f"round {number} failed ({exc})")
            else:
                fresh = {record.key: record for record in store.update(devices)}
                unsaved = True
                changes = presence.compare(devices, fresh, store)
                if result is not None:
                    found_now = _findings(result)
                    if found_before is not None:
                        changes += [
                            Change("finding", result.device(f.ip), f, store.get(fid[1]))
                            for fid, f in found_now.items()
                            if fid not in found_before
                        ]
                    found_before = set(found_now)
                save()
                on_round(Round(number, started, _now(), devices, changes, result))
            if rounds is not None and number >= rounds:
                return
            left = every - (loop.time() - begun)
            if left > 0:
                if on_wait:
                    on_wait(left)
                await asyncio.sleep(left)
    finally:
        # Only when the last save failed; otherwise the file is up to date.
        if unsaved:
            with contextlib.suppress(OSError):
                store.save()
