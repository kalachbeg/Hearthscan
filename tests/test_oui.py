import gzip
import importlib.util
import io
import sys
import urllib.error
from collections import Counter
from pathlib import Path

import pytest

from hearthscan.discovery import oui

ROOT = Path(__file__).resolve().parents[1]


def load_build_script():
    spec = importlib.util.spec_from_file_location("build_oui", ROOT / "scripts" / "build_oui.py")
    module = importlib.util.module_from_spec(spec)
    # dataclasses look the module up in sys.modules while the class is created
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


build_oui = load_build_script()

FAKE_TABLE = {
    "A4B1C2": "Acme",
    "A4B1C23": "Blockhouse",
    "A4B1C2345": "Smallfry",
    "0C1D2E": "Hearthware",
    # Never returned: the first byte marks these as randomized or multicast.
    "A6B1C2": "Randomized",
    "A5B1C2": "Multicast",
}

CSV_HEADER = "Registry,Assignment,Organization Name,Organization Address\n"


@pytest.fixture
def table_file(tmp_path, monkeypatch):
    """Point the lookup at a data file in tmp_path and forget whatever was loaded."""
    path = tmp_path / "oui.tsv.gz"
    monkeypatch.setattr(oui, "_data_file", lambda: path)
    oui._table.cache_clear()
    yield path
    oui._table.cache_clear()


@pytest.fixture
def fake_table(table_file):
    table_file.write_bytes(build_oui.render(FAKE_TABLE))
    return table_file


@pytest.mark.parametrize(
    "mac, vendor",
    [
        ("a4:b1:c2:34:5f:01", "Smallfry"),
        ("a4:b1:c2:3f:00:01", "Blockhouse"),
        ("a4:b1:c2:99:00:01", "Acme"),
        ("A4-B1-C2-34-5F-01", "Smallfry"),
        ("a4b1.c299.0001", "Acme"),
        ("0c:1d:2e:00:00:07", "Hearthware"),
        ("a4:b1:c3:00:00:01", None),
    ],
)
def test_most_specific_prefix_wins(fake_table, mac, vendor):
    assert oui.lookup(mac) == vendor


@pytest.mark.parametrize(
    "mac",
    [
        "a6:b1:c2:00:00:01",  # locally administered
        "a5:b1:c2:00:00:01",  # multicast
        "01:00:5e:00:00:fb",
        "ff:ff:ff:ff:ff:ff",
    ],
)
def test_random_and_multicast_addresses_have_no_vendor(fake_table, mac):
    assert oui.lookup(mac) is None


@pytest.mark.parametrize(
    "mac",
    [None, "", "Living-Room", "a4:b1:c2", "a4:b1:c2:99:00:zz", "a4:b1:c2:99:00:01:02", "0" * 12],
)
def test_malformed_input(fake_table, mac):
    assert oui.lookup(mac) is None


def test_missing_data_file(table_file):
    assert not table_file.exists()
    assert oui.lookup("a4:b1:c2:99:00:01") is None
    assert not oui.available()


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not gzip at all",
        gzip.compress(b"A4B1C2\tAcme\n")[:-6],  # truncated
        gzip.compress(b"A4B1C2\tAcme\n")[:10] + b"\xff" * 20,  # corrupt stream
    ],
)
def test_broken_data_file(table_file, data):
    table_file.write_bytes(data)
    assert oui.lookup("a4:b1:c2:99:00:01") is None


def test_bad_lines_are_skipped(table_file):
    lines = [
        "A4B1C2\tAcme",
        "no tab here",
        "XYZXYZ\tBad Hex",
        "A4B1\tToo Short",
        "A4B1C2345678\tToo Long",
        "0C1D2E\t",
        "0c1d2f\tLowercase Prefix",
        "0C1D30\t" + "x" * 500,
        "0C1D31\tCarriage Return\r",
        "0C1D32\tBroken \udcff UTF-8",
    ]
    text = "\n".join(lines).encode("utf-8", errors="surrogateescape")
    table_file.write_bytes(gzip.compress(text))
    assert oui.lookup("a4:b1:c2:00:00:01") == "Acme"
    assert oui.lookup("0c:1d:2e:00:00:01") is None
    assert oui.lookup("0c:1d:2f:00:00:01") == "Lowercase Prefix"
    assert oui.lookup("0c:1d:30:00:00:01") == "x" * oui.MAX_VENDOR
    assert oui.lookup("0c:1d:31:00:00:01") == "Carriage Return"
    assert oui.lookup("0c:1d:32:00:00:01") == "Broken \N{REPLACEMENT CHARACTER} UTF-8"


def test_oversized_table_is_cut_at_a_line(table_file, monkeypatch):
    # The limit falls inside "Second". A cut line must not come back as "Seco".
    monkeypatch.setattr(oui, "MAX_TABLE", 24)
    table_file.write_bytes(gzip.compress(b"0C1D2E\tFirst\n0C1D2F\tSecond\n0C1D30\tThird\n"))
    assert oui.lookup("0c:1d:2e:00:00:01") == "First"
    assert oui.lookup("0c:1d:2f:00:00:01") is None
    assert oui.lookup("0c:1d:30:00:00:01") is None


def test_table_loads_once(fake_table, monkeypatch):
    calls = []
    monkeypatch.setattr(oui, "_data_file", lambda: calls.append(1) or fake_table)
    for _ in range(3):
        assert oui.lookup("a4:b1:c2:99:00:01") == "Acme"
    assert len(calls) == 1


@pytest.fixture
def shipped_table():
    oui._table.cache_clear()
    yield
    oui._table.cache_clear()


@pytest.mark.parametrize(
    "mac, vendor",
    [
        ("00:03:93:12:34:56", "Apple"),
        ("00:00:0c:12:34:56", "Cisco"),
        ("00:1a:11:12:34:56", "Google"),
        ("24:0a:c4:12:34:56", "Espressif"),
        ("00:04:0e:12:34:56", "AVM"),
        ("b8:27:eb:12:34:56", "Raspberry Pi"),
        ("f0:40:af:91:23:45", "Raspberry Pi"),  # MA-M block inside an IEEE MA-L
        ("8c:1f:64:34:a1:23", "Raspberry Pi"),  # MA-S block
        ("8c:1f:64:34:b1:23", "Infrared Inspection Systems"),
        ("f4:64:12:12:34:56", "Sony Interactive"),
        ("00:22:a6:12:34:56", "Sony Interactive"),
        ("ac:80:0a:12:34:56", "Sony"),
        ("00:17:88:12:34:56", "Signify"),
        ("c4:29:96:12:34:56", "Signify"),
        ("e8:c1:d7:12:34:56", "Philips"),
        ("84:28:59:12:34:56", "Amazon"),
    ],
)
def test_shipped_table(shipped_table, mac, vendor):
    assert oui.available()
    assert oui.lookup(mac) == vendor


@pytest.mark.parametrize(
    "organization, name",
    [
        ("Apple, Inc.", "Apple"),
        ("HUAWEI TECHNOLOGIES CO.,LTD", "Huawei"),
        ("TP-LINK TECHNOLOGIES CO.,LTD.", "TP-Link"),
        ("Espressif Inc.", "Espressif"),
        ("Hangzhou Hikvision Digital Technology Co.,Ltd.", "Hikvision"),
        ("Raspberry Pi Trading Ltd", "Raspberry Pi"),
        ("Raspberry Pi (Trading) Ltd", "Raspberry Pi"),
        ("Sonos, Inc.", "Sonos"),
        ("AVM Audiovisuelles Marketing und Computersysteme GmbH", "AVM"),
        ("Samsung Electronics Co.,Ltd", "Samsung"),
        ("Intel Corporate", "Intel"),
        ("Liteon Technology Corporation", "Liteon"),
        ("NETGEAR", "Netgear"),
        ("Motorola Mobility LLC, a Lenovo Company", "Motorola"),
        # PlayStations and Hue lights keep a name of their own, apart from Sony and Philips.
        ("Sony Interactive Entertainment Inc.", "Sony Interactive"),
        ("Sony Computer Entertainment America", "Sony Interactive"),
        ("Sony Corporation", "Sony"),
        ("Signify B.V.", "Signify"),
        ("Philips Lighting BV", "Signify"),
        ("Philips Electronics Nederland BV", "Philips"),
        ("Amazon Technologies Inc.", "Amazon"),
    ],
)
def test_short_name_known_vendors(organization, name):
    assert build_oui.short_name(organization) == name


@pytest.mark.parametrize(
    "organization, name",
    [
        ("ACME WIDGET TECHNOLOGY CO., LTD.", "Acme Widget"),
        ("Shenzhen Brightfoo Electronic Technology Co.,Ltd", "Brightfoo"),
        ("SHEN ZHEN BRIGHTFOO TECHNOLOGY CO.,LTD", "Brightfoo"),
        ("Brightfoo (Hangzhou) Co., Ltd.", "Brightfoo"),
        ("Brightfoo?Hangzhou) Medical Technology Co.,Ltd", "Brightfoo Medical"),
        ("Gizmotron Systems GmbH & Co. KG", "Gizmotron Systems"),
        ("Gizmotron GmbH Fernwartungssysteme", "Gizmotron"),
        ("Quuxtel Sp. z o.o.", "Quuxtel"),
        ("Quuxtel spol. s r.o.", "Quuxtel"),
        ("Zorbix Elektronik San. ve Tic. A.\N{LATIN CAPITAL LETTER S WITH CEDILLA}.", "Zorbix"),
        ("Vexa Comunicaciones S.A. de C.V.", "Vexa Comunicaciones"),
        ("Hoopla Labs Inc. dba Quux Home", "Quux Home"),
        ("Hoopla Labs, LLC (dba Quux)", "Quux"),
        ("Hoopla Labs, INC.DBA Quux", "Quux"),
        ("Plinth Holdings Limited Liability Company", "Plinth"),
        (
            "Widget\N{NO-BREAK SPACE}Works\N{IDEOGRAPHIC SPACE}Co.\N{FULLWIDTH COMMA}Ltd.",
            "Widget Works",
        ),
        ("ZORBIX AND SONS LTD", "Zorbix and Sons"),
        ("ABC TECHNOLOGIES INC", "ABC"),
        ("C.E. ELECTRONICS, INC", "C.E."),
        ("BRIGHTFOO.INC", "Brightfoo"),
        ('JSC "Quuxtel"', "Quuxtel"),
        ("Gizmo Ltd.Dongguan branch", "Gizmo"),
        ("Gizmo Communication Equipment Co,Ltd.ShenZhen", "Gizmo Communication Equipment"),
        ("Gizmo AG, Sector Industry, Motion Control", "Gizmo"),
        ("Gizmo \N{EN DASH} Smart Home, Inc.", "Gizmo - Smart Home"),
    ],
)
def test_short_name_strips_forms_and_filler(organization, name):
    assert build_oui.short_name(organization) == name


@pytest.mark.parametrize(
    "organization, name",
    [
        # Nothing distinctive would be left, so the filler stays.
        ("Digital Technology Co., Ltd.", "Digital Technology"),
        ("Shenzhen Technology Co., Ltd.", "Shenzhen Technology"),
        ("Friends of America LLC", "Friends of America"),
        ("Hitachi High Technologies Inc.", "Hitachi High Technologies"),
        ("Electronics Corporation of Nowhere Limited", "Electronics Corporation of Nowhere"),
        # Company words inside a name are part of the name.
        ("Corporation Street Labs", "Corporation Street Labs"),
        ("DBA Gizmos Inc.", "DBA Gizmos"),
        ("Texas Instruments", "Texas Instruments"),
        ("Silicon Laboratories", "Silicon Laboratories"),
    ],
)
def test_short_name_keeps_what_makes_the_name(organization, name):
    assert build_oui.short_name(organization) == name


@pytest.mark.parametrize(
    "organization", ["IEEE Registration Authority", "Private", "PRIVATE", "", "   ", ",."]
)
def test_short_name_drops_non_vendors(organization):
    assert build_oui.short_name(organization) is None


def test_short_name_caps_length():
    name = build_oui.short_name("Quux " * 40 + "Ltd")
    assert len(name) <= build_oui.MAX_NAME
    assert name.endswith("Quux")


def test_recase():
    assert build_oui.recase("ACME WIDGETS AND GADGETS") == "Acme Widgets and Gadgets"
    assert build_oui.recase("TP-LINK") == "TP-Link"
    assert build_oui.recase("NXP BV") == "NXP BV"
    assert build_oui.recase("Mixed Case STAYS") == "Mixed Case STAYS"


def test_fold():
    assert build_oui.fold("A.\N{LATIN CAPITAL LETTER S WITH CEDILLA}.") == "as"
    assert build_oui.fold("GmbH&Co.KG") == "gmbh&cokg"
    assert build_oui.fold("(Pty)") == "pty"


def registry_csv(*rows):
    return CSV_HEADER + "".join(f"{r},{a},{n},Somewhere 1\n" for r, a, n in rows)


def test_parse_registry_skips_bad_rows():
    text = registry_csv(
        ("MA-L", "0C1D2E", "Hearthware Inc."),
        ("MA-L", "0c1d2f", "Lowercase Ltd"),
        ("MA-L", "XYZ123", "Bad Hex"),
        ("MA-L", "0C1D2", "Too Short"),
        ("MA-L", "A6B1C2", "Local Bit"),
        ("MA-L", "A5B1C2", "Multicast Bit"),
        ("MA-L", "0C1D30", "Private"),
    )
    text += "MA-L\n"  # a short row
    stats = Counter()
    registry = build_oui.REGISTRIES[0]
    rows = list(build_oui.parse_registry(text, registry, stats))
    assert rows == [
        ("0C1D2E", "Hearthware Inc."),
        ("0C1D2F", "Lowercase Ltd"),
        ("0C1D30", "Private"),
    ]
    assert stats == {"bad assignment": 3, "multicast or local": 2}


def test_parse_registry_rejects_a_new_format():
    with pytest.raises(ValueError, match="columns"):
        list(build_oui.parse_registry("Prefix,Vendor\n0C1D2E,Acme\n", build_oui.REGISTRIES[0], {}))


def test_build_drops_non_vendors_and_keeps_the_first_duplicate():
    stats = Counter()
    entries = build_oui.build(
        [
            ("0C1D2E", "Hearthware Inc."),
            ("0C1D2E", "Someone Else Ltd"),
            ("0C1D2F", "Private"),
            ("0C1D30", "IEEE Registration Authority"),
            ("0C1D3E5", "Smallfry GmbH"),
        ],
        stats,
    )
    assert entries == {"0C1D2E": "Hearthware", "0C1D3E5": "Smallfry"}
    assert stats == {"duplicate": 1, "no vendor": 2}


def test_render_is_sorted_and_reproducible():
    entries = {"0C1D2F": "Second", "0C1D2E5": "Smallfry", "0C1D2E": "First"}
    data = build_oui.render(entries)
    assert data == build_oui.render(dict(reversed(entries.items())))
    assert data[4:8] == b"\x00\x00\x00\x00"  # gzip mtime
    text = gzip.decompress(data).decode("utf-8")
    assert text == "0C1D2E\tFirst\n0C1D2E5\tSmallfry\n0C1D2F\tSecond\n"


def write_sources(directory, with_iab=True):
    directory.mkdir()
    (directory / "oui.csv").write_text(
        registry_csv(("MA-L", "0C1D2E", "Hearthware Inc."), ("MA-L", "0C1D2F", "Private"))
    )
    (directory / "mam.csv").write_text(registry_csv(("MA-M", "0C1D3E5", "Blockhouse Ltd")))
    (directory / "oui36.csv").write_text(registry_csv(("MA-S", "0C1D3F123", "Smallfry Oy")))
    if with_iab:
        (directory / "iab.csv").write_text(registry_csv(("IAB", "0C1D40ABC", "Oldtimer Corp")))


def test_main_builds_from_saved_files(tmp_path, capsys):
    write_sources(tmp_path / "src", with_iab=False)
    output = tmp_path / "out" / "oui.tsv.gz"
    args = ["--source", str(tmp_path / "src"), "--output", str(output)]
    assert build_oui.main(args) == 0
    text = gzip.decompress(output.read_bytes()).decode("utf-8")
    assert text == "0C1D2E\tHearthware\n0C1D3E5\tBlockhouse\n0C1D3F123\tSmallfry\n"
    printed = capsys.readouterr().out
    assert "IAB: iab.csv not found, skipped" in printed
    assert "wrote 3 prefixes (1 24-bit, 1 28-bit, 1 36-bit)" in printed


def test_main_fails_without_a_required_file(tmp_path, capsys):
    write_sources(tmp_path / "src")
    (tmp_path / "src" / "mam.csv").unlink()
    output = tmp_path / "oui.tsv.gz"
    assert build_oui.main(["--source", str(tmp_path / "src"), "--output", str(output)]) == 1
    assert not output.exists()
    assert "MA-M" in capsys.readouterr().err


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def http_error(url, code):
    return urllib.error.HTTPError(url, code, "nope", {}, None)


def test_fetch_tries_another_user_agent_when_refused(monkeypatch):
    agents = []

    def fake_urlopen(request, timeout):
        agents.append(request.get_header("User-agent"))
        if len(agents) == 1:
            raise http_error(request.full_url, 403)
        return FakeResponse(b"Registry,Assignment\n")

    monkeypatch.setattr(build_oui.urllib.request, "urlopen", fake_urlopen)
    assert build_oui.fetch("https://example.test/oui.csv") == b"Registry,Assignment\n"
    assert agents == list(build_oui.USER_AGENTS)


def test_fetch_does_not_retry_other_errors(monkeypatch):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request)
        raise http_error(request.full_url, 404)

    monkeypatch.setattr(build_oui.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        build_oui.fetch("https://example.test/iab.csv")
    assert len(calls) == 1


def test_fetch_refuses_huge_downloads(monkeypatch):
    monkeypatch.setattr(build_oui, "MAX_DOWNLOAD", 10)
    monkeypatch.setattr(
        build_oui.urllib.request, "urlopen", lambda request, timeout: FakeResponse(b"x" * 11)
    )
    with pytest.raises(ValueError, match="larger"):
        build_oui.fetch("https://example.test/oui.csv")
