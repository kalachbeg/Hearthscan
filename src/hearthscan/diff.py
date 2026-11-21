"""What changed between two scans of the same network."""

from __future__ import annotations

import dataclasses
import ipaddress
from collections import Counter
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import serialize
from .models import Device, Finding, ScanResult, normalize_mac

# Rules that can report several findings on one port, one for each forward.
_FORWARD_RULES = frozenset({"port-forward", "port-forward-risky"})


@dataclass(slots=True)
class Diff:
    new_devices: list[Device] = field(default_factory=list)
    gone_devices: list[Device] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    fixed_findings: list[Finding] = field(default_factory=list)
    score_before: int = 100
    score_after: int = 100

    @property
    def unchanged(self) -> bool:
        """True when both scans saw the same devices, findings and score."""
        return not (
            self.new_devices
            or self.gone_devices
            or self.new_findings
            or self.fixed_findings
            or self.score_before != self.score_after
        )


def compare(old: ScanResult, new: ScanResult) -> Diff:
    """The devices and findings that came and went between `old` and `new`.

    Two devices are the same when their MACs match, or, when one of them has
    no MAC, when their addresses match. Two findings are the same when their
    rule, device and port are, so a device that moved to another address
    keeps its findings.
    """
    pairs = _pair_devices(old.devices, new.devices)  # new index -> old index
    paired_old = set(pairs.values())
    old_ids = _identities(old.devices, {i: i for i in paired_old}, "old")
    new_ids = _identities(new.devices, pairs, "new")
    old_keys = [_finding_key(f, old_ids) for f in old.findings]
    new_keys = [_finding_key(f, new_ids) for f in new.findings]
    return Diff(
        new_devices=[d for i, d in enumerate(new.devices) if i not in pairs],
        gone_devices=[d for i, d in enumerate(old.devices) if i not in paired_old],
        new_findings=_unmatched(new.findings, new_keys, old_keys),
        fixed_findings=_unmatched(old.findings, old_keys, new_keys),
        score_before=old.score,
        score_after=new.score,
    )


def to_dict(diff: Diff) -> dict[str, Any]:
    """Plain data for json.dump. Devices and findings look as they do in a saved result."""
    return {
        "score_before": diff.score_before,
        "score_after": diff.score_after,
        "new_devices": serialize.devices_to_list(diff.new_devices),
        "gone_devices": serialize.devices_to_list(diff.gone_devices),
        "new_findings": [dataclasses.asdict(f) for f in diff.new_findings],
        "fixed_findings": [dataclasses.asdict(f) for f in diff.fixed_findings],
    }


def _ip(text: str) -> str:
    """One spelling per address, so "fe80::01" and "fe80::1" compare equal."""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _mac(device: Device) -> str | None:
    return normalize_mac(device.mac)


def _mac_and_ip(device: Device) -> tuple[str, str] | None:
    mac = _mac(device)
    return (mac, _ip(device.ip)) if mac else None


def _pair_devices(old: Sequence[Device], new: Sequence[Device]) -> dict[int, int]:
    """Index in `new` -> index in `old` for every device both scans saw."""
    pairs: dict[int, int] = {}
    free = set(range(len(old)))

    def pair_by(
        key: Callable[[Device], Hashable | None],
        allowed: Callable[[Device, Device], bool] = lambda a, b: True,
    ) -> None:
        waiting: dict[Hashable, list[int]] = {}
        for index in sorted(free):
            value = key(old[index])
            if value is not None:
                waiting.setdefault(value, []).append(index)
        for index, device in enumerate(new):
            value = key(device)
            if index in pairs or value is None:
                continue
            for candidate in waiting.get(value, []):
                if candidate in free and allowed(old[candidate], device):
                    pairs[index] = candidate
                    free.discard(candidate)
                    break

    # MAC and address together first, so a MAC behind several addresses pairs up right.
    pair_by(_mac_and_ip)
    pair_by(_mac)
    # Two different MACs on one address are two devices: the address was handed on.
    pair_by(lambda d: _ip(d.ip), lambda a, b: not (_mac(a) and _mac(b)))
    return pairs


def _identities(devices: Sequence[Device], paired: dict[int, int], side: str) -> dict[str, tuple]:
    """Address -> what stands for that device in both scans.

    `paired` maps a device's index to its pair number. A device without a pair
    stands for itself on its own side only.
    """
    identities: dict[str, tuple] = {}
    for index, device in enumerate(devices):
        identity = ("pair", paired[index]) if index in paired else (side, index)
        # The first device with an address wins, as in ScanResult.device().
        identities.setdefault(_ip(device.ip), identity)
    return identities


def _finding_key(finding: Finding, identities: dict[str, tuple]) -> tuple:
    ip = _ip(finding.ip)
    key: tuple = (finding.rule, identities.get(ip, ("address", ip)), finding.port)
    if finding.rule in _FORWARD_RULES:
        key += (finding.params.get("external_port"), finding.params.get("protocol"))
    return key


def _unmatched(findings: list[Finding], keys: list[tuple], other: list[tuple]) -> list[Finding]:
    """The findings the other scan has no match for, in their own order."""
    left = Counter(other)
    unmatched = []
    for finding, key in zip(findings, keys, strict=True):
        if left[key]:
            left[key] -= 1
        else:
            unmatched.append(finding)
    return unmatched
