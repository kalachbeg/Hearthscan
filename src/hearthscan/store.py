"""Remember the devices seen on earlier scans, so a newcomer stands out.

The list lives in known.json in state_dir(). Each device is keyed by its MAC,
or by its address when no MAC is known. The file carries a version number;
readers ignore fields they do not know, so adding one keeps the number.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import unicodedata
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import system
from .models import Device, normalize_mac

VERSION = 1
TOOL = "hearthscan"
TYPE = "known-devices"
FILENAME = "known.json"

# A home network has a few dozen devices. Phones that make up a new MAC now
# and then add a record each time, so the oldest ones go past this many.
MAX_RECORDS = 4096
MAX_TEXT = 128  # characters kept of a name, vendor or kind
MAX_KEY = 128
# Far more than MAX_RECORDS records take. A bigger file is not ours.
MAX_FILE = 8 * 1024 * 1024

# Discovery knows this machine without its MAC, and its address changes
# whenever DHCP hands out another one.
SELF_KEY = "self"


def state_dir() -> Path:
    """Where Hearthscan keeps what it remembers between runs. Not created here.

    HEARTHSCAN_STATE_DIR overrides the platform default.
    """
    override = os.environ.get("HEARTHSCAN_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if system.IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
        return base / "Hearthscan"
    if system.IS_MACOS:
        return Path.home() / "Library" / "Application Support" / "Hearthscan"
    xdg = os.environ.get("XDG_STATE_HOME")
    # The XDG spec says to ignore a relative path.
    if xdg and os.path.isabs(xdg):
        return Path(xdg) / "hearthscan"
    return Path.home() / ".local" / "state" / "hearthscan"


def default_path() -> Path:
    """The file KnownDevices uses unless given another."""
    return state_dir() / FILENAME


@dataclass(slots=True)
class Known:
    key: str  # the MAC, "ip:<address>" without one, or SELF_KEY for this machine
    first_seen: str  # ISO 8601, UTC
    last_seen: str
    last_ip: str | None = None
    name: str | None = None
    vendor: str | None = None
    kind: str = "unknown"
    trusted: bool = False
    # A made-up MAC. The same phone may come back with another one.
    random_mac: bool = False


def device_key(device: Device) -> str:
    """What identifies a device across scans: its MAC, or its address without one."""
    if device.is_self:
        return SELF_KEY
    mac = normalize_mac(device.mac)
    return mac if mac else f"ip:{device.ip}"


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _moment(text: str) -> datetime:
    """Parse an ISO 8601 time. A time without an offset is taken as UTC."""
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _clean(text: str | None, limit: int = MAX_TEXT) -> str | None:
    """Text safe to show: control, format and unassigned characters become spaces."""
    if not text:
        return None
    text = "".join(" " if unicodedata.category(ch)[0] == "C" else ch for ch in text[: limit * 4])
    return " ".join(text.split())[:limit].rstrip() or None


class KnownDevices:
    """The devices seen before. Changes stay in memory until save()."""

    def __init__(self, path: Path | None = None, records: Iterable[Known] = ()) -> None:
        self.path = Path(path) if path is not None else default_path()
        self._records: dict[str, Known] = {}
        for record in records:
            self._records.setdefault(record.key, record)
        self._trim()
        # Where load() moved an unreadable file, so the caller can say so.
        self.broken: Path | None = None

    @classmethod
    def load(cls, path: Path | None = None) -> KnownDevices:
        """Read the list. A missing file is an empty list.

        A file that is not a list of known devices, or not one this version
        can read, is renamed to known.json.broken and the list starts empty.
        Raises OSError when the file is there but cannot be read or moved.
        """
        store = cls(path)
        try:
            with open(store.path, "rb") as file:
                raw = file.read(MAX_FILE + 1)
        except FileNotFoundError:
            return store
        try:
            records = _parse(raw)
        except ValueError:
            aside = store.path.with_name(store.path.name + ".broken")
            os.replace(store.path, aside)
            store.broken = aside
            return store
        return cls(store.path, records)

    def save(self) -> None:
        """Write the list. A crash halfway leaves the old file as it was."""
        folder = self.path.parent
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        data: dict[str, Any] = {
            "tool": TOOL,
            "type": TYPE,
            "version": VERSION,
            "devices": [asdict(record) for record in self._records.values()],
        }
        text = json.dumps(data, indent=2) + "\n"
        fd, temp = tempfile.mkstemp(prefix=".known-", suffix=".tmp", dir=folder)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as file:
                file.write(text)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(temp)
            raise

    @property
    def records(self) -> list[Known]:
        """Every record, in the order they were first seen."""
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and _normal_key(key) in self._records

    def get(self, key: str) -> Known | None:
        """The record for a key. A MAC may be written any way normalize_mac accepts."""
        return self._records.get(_normal_key(key))

    def find(self, text: str) -> Known | None:
        """The record for a key, a MAC or the address a device had when last seen."""
        found = self.get(text)
        if found is not None:
            return found
        text = text.strip()
        at = [r for r in self._records.values() if r.last_ip == text]
        return max(at, key=lambda r: _moment(r.last_seen), default=None)

    def update(self, devices: Iterable[Device], when: str | None = None) -> list[Known]:
        """Record what a scan found and return the records of devices never seen before.

        The others get their last address, name, vendor and kind refreshed,
        keeping what was known when the scan found nothing better. Only a
        confirmed device counts as seen again: a bare neighbor table entry can
        outlive its device by hours.
        """
        when = when or _now()
        _moment(when)  # a ValueError now beats a file nobody can sort later
        fresh: list[Known] = []
        done: set[str] = set()
        for device in devices:
            key = device_key(device)
            if key in done:
                continue
            done.add(key)
            name = _clean(device.name)
            vendor = _clean(device.vendor)
            kind = _clean(device.kind) or "unknown"
            record = self._records.get(key)
            if record is None:
                record = Known(
                    key=key,
                    first_seen=when,
                    last_seen=when,
                    last_ip=_clean(device.ip, 64),
                    name=name,
                    vendor=vendor,
                    kind=kind,
                    random_mac=device.random_mac,
                )
                self._records[key] = record
                fresh.append(record)
                continue
            if device.confirmed:
                record.last_seen = when
            record.last_ip = _clean(device.ip, 64) or record.last_ip
            record.name = name or record.name
            record.vendor = vendor or record.vendor
            if kind != "unknown":
                record.kind = kind
        self._trim()
        return [record for record in fresh if record.key in self._records]

    def trust(self, key: str, trusted: bool = True) -> bool:
        """Mark a device as one you know. False when there is no such record."""
        record = self.get(key)
        if record is None:
            return False
        record.trusted = trusted
        return True

    def forget(self, key: str) -> bool:
        """Drop a record, so the device counts as new next time. False when there is none."""
        return self._records.pop(_normal_key(key), None) is not None

    def clear(self) -> None:
        self._records.clear()

    def _trim(self) -> None:
        """Keep MAX_RECORDS at most, dropping untrusted ones before trusted, oldest first."""
        extra = len(self._records) - MAX_RECORDS
        if extra <= 0:
            return
        order = sorted(self._records.values(), key=lambda r: (r.trusted, _moment(r.last_seen)))
        for record in order[:extra]:
            del self._records[record.key]


def _normal_key(key: str) -> str:
    key = key.strip()
    return normalize_mac(key) or key


def _parse(raw: bytes) -> list[Known]:
    """The records in a saved file. Raises ValueError for anything else."""
    if len(raw) > MAX_FILE:
        raise ValueError("too large")
    try:
        data = json.loads(raw)
    except RecursionError:
        raise ValueError("nested too deeply") from None
    if not isinstance(data, dict) or data.get("tool") != TOOL or data.get("type") != TYPE:
        raise ValueError("not a list of known devices")
    version = data.get("version")
    if isinstance(version, bool) or version != VERSION:
        raise ValueError(f"version {version!r}")
    items = data.get("devices")
    if not isinstance(items, list):
        raise ValueError("devices should be a list")
    return [_record(item) for item in items]


def _text(item: dict[str, Any], name: str, limit: int = MAX_TEXT) -> str | None:
    value = item.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} should be a string")
    return _clean(value, limit)


def _flag(item: dict[str, Any], name: str) -> bool:
    value = item.get(name, False)
    if not isinstance(value, bool):
        raise ValueError(f"{name} should be true or false")
    return value


def _time(item: dict[str, Any], name: str) -> str:
    value = item.get(name)
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError(f"{name} should be a time")
    _moment(value)
    return value


def _record(item: object) -> Known:
    if not isinstance(item, dict):
        raise ValueError("a record should be an object")
    key = item.get("key")
    if not isinstance(key, str) or not key or len(key) > MAX_KEY or _clean(key, MAX_KEY) != key:
        raise ValueError("bad key")
    return Known(
        key=_normal_key(key),
        first_seen=_time(item, "first_seen"),
        last_seen=_time(item, "last_seen"),
        last_ip=_text(item, "last_ip", 64),
        name=_text(item, "name"),
        vendor=_text(item, "vendor"),
        kind=_text(item, "kind") or "unknown",
        trusted=_flag(item, "trusted"),
        random_mac=_flag(item, "random_mac"),
    )
