"""Name the maker of a network card from the first bits of its MAC address.

The table comes from the public IEEE registries; scripts/build_oui.py rebuilds it.
"""

from __future__ import annotations

import functools
import gzip
import zlib
from importlib import resources
from typing import TYPE_CHECKING

from ..models import is_random_mac, is_unicast_mac, normalize_mac

if TYPE_CHECKING:
    from importlib.resources.abc import Traversable

# Hex digits of an MA-S (36-bit), MA-M (28-bit) and MA-L (24-bit) prefix, most
# specific first: a large block can be split up and sold off in smaller pieces.
PREFIX_DIGITS = (9, 7, 6)
MAX_VENDOR = 64
# The shipped table is about 1.2 MB unpacked. Anything far beyond that is not ours.
MAX_TABLE = 16 * 1024 * 1024

_HEX = frozenset("0123456789ABCDEF")


def _data_file() -> Traversable:
    return resources.files("hearthscan") / "data" / "oui.tsv.gz"


def _parse(text: str) -> dict[str, str]:
    table: dict[str, str] = {}
    # Apple alone owns over a thousand blocks; keep one copy of each name.
    names: dict[str, str] = {}
    for line in text.split("\n"):
        prefix, tab, vendor = line.partition("\t")
        prefix = prefix.strip().upper()
        vendor = vendor.strip()[:MAX_VENDOR]
        if tab and vendor and len(prefix) in PREFIX_DIGITS and _HEX.issuperset(prefix):
            table[prefix] = names.setdefault(vendor, vendor)
    return table


@functools.cache
def _table() -> dict[str, str]:
    try:
        with _data_file().open("rb") as raw, gzip.GzipFile(fileobj=raw) as unpacked:
            data = unpacked.read(MAX_TABLE + 1)
    except (OSError, EOFError, zlib.error):
        return {}
    text = data[:MAX_TABLE].decode("utf-8", errors="replace")
    if len(data) > MAX_TABLE:
        text = text.rpartition("\n")[0]  # the last line was cut short
    return _parse(text)


def available() -> bool:
    """True when the vendor table could be loaded."""
    return bool(_table())


def lookup(mac: str | None) -> str | None:
    """The short name of the vendor that owns the block `mac` comes from.

    Returns None for anything that is not a MAC address, for randomized
    (locally administered) and multicast addresses, and for unassigned blocks.
    """
    mac = normalize_mac(mac)
    if mac is None or is_random_mac(mac) or not is_unicast_mac(mac):
        return None
    digits = mac.replace(":", "").upper()
    table = _table()
    for size in PREFIX_DIGITS:
        vendor = table.get(digits[:size])
        if vendor is not None:
            return vendor
    return None
