import ctypes
import json
import locale
import re
import types
from pathlib import Path

import pytest

from hearthscan import i18n, models, system

I18N_DIR = Path(i18n.__file__).parent
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
DASHES = tuple(chr(code) for code in (0x2012, 0x2013, 0x2014, 0x2015))
ENV_VARS = ("HEARTHSCAN_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")
BANDS = ("good", "fair", "poor", "bad")

# Rule id -> the params a finding of that rule carries.
CATALOG = {
    "telnet-open": {"port"},
    "ftp-open": {"port", "product"},
    "vnc-no-auth": {"port"},
    "vnc-open": {"port"},
    "rdp-open": {"port"},
    "adb-open": {"port", "product"},
    "adb-exposed": {"port"},
    "redis-no-auth": {"port"},
    "docker-api-open": {"port", "product"},
    "memcached-open": {"port"},
    "elasticsearch-no-auth": {"port", "product"},
    "database-open": {"port", "service"},
    "mqtt-anonymous": {"port"},
    "rtsp-no-auth": {"port"},
    "smb1-enabled": {"port"},
    "socks-no-auth": {"port"},
    "dvr-port-open": {"port"},
    "winbox-open": {"port"},
    "pptp-open": {"port"},
    "webmin-open": {"port"},
    "nfs-open": {"port"},
    "rsync-open": {"port", "modules"},
    "login-over-http": {"port"},
    "old-tls": {"port", "version"},
    "upnp-igd": set(),
    "tr069-open": {"port"},
    "jetdirect-open": {"port"},
    "smb-open": {"port"},
    "ssh-open": {"port", "product"},
    "unknown-device": set(),
}


def load(code):
    def no_duplicates(pairs):
        keys = [key for key, _ in pairs]
        assert len(keys) == len(set(keys)), f"duplicate keys in {code}.json"
        return dict(pairs)

    text = (I18N_DIR / f"{code}.json").read_text(encoding="utf-8")
    return json.loads(text, object_pairs_hook=no_duplicates)


def placeholders(text):
    return set(PLACEHOLDER.findall(text))


@pytest.fixture(autouse=True)
def keep_language():
    previous = i18n.language()
    yield
    i18n.set_language(previous)


@pytest.fixture
def no_system_language(monkeypatch):
    """Nothing in the environment or the system names a language."""
    for var in ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(locale, "getlocale", lambda *args: (None, None))
    monkeypatch.setattr(system, "IS_WINDOWS", False)
    monkeypatch.setattr(system, "IS_MACOS", False)


def fake_windll(langid, calls=None):
    def get_language():
        return langid

    kernel32 = types.SimpleNamespace(GetUserDefaultUILanguage=get_language)

    def windll(name):
        if calls is not None:
            calls.append(name)
        return kernel32

    return windll


# The files


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_files_are_flat_objects_of_strings(code):
    texts = load(code)
    assert texts
    for key, text in texts.items():
        assert isinstance(key, str)
        assert isinstance(text, str), key
        assert text.strip() == text and text, key
        assert "  " not in text, key


def test_every_language_has_the_same_keys():
    english = load("en")
    for code in i18n.LANGUAGES:
        assert set(load(code)) == set(english), code


def test_every_language_has_the_same_placeholders():
    english = load("en")
    for code in i18n.LANGUAGES:
        for key, text in load(code).items():
            assert placeholders(text) == placeholders(english[key]), (code, key)


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_every_rule_has_a_title_a_reason_and_a_fix(code):
    texts = load(code)
    for rule, params in CATALOG.items():
        for part in ("title", "why", "fix"):
            key = f"rule.{rule}.{part}"
            assert key in texts, key
            assert placeholders(texts[key]) <= params, key


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_no_rule_texts_beyond_the_catalog(code):
    rules = {key.split(".")[1] for key in load(code) if key.startswith("rule.")}
    assert rules == set(CATALOG)


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_kinds_severities_and_bands(code):
    texts = load(code)
    for kind in models.KINDS:
        assert f"kind.{kind}" in texts
    for severity in models.SEVERITIES:
        assert f"severity.{severity}" in texts
    for band in BANDS:
        assert f"band.{band}.title" in texts
        assert f"band.{band}.summary" in texts


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_sentences_end_and_titles_do_not(code):
    for key, text in load(code).items():
        if key.startswith("ui."):
            continue  # screen texts: labels and whole messages mixed
        if key.endswith((".why", ".fix", ".summary")):
            assert text.endswith("."), key
        else:
            assert not text.endswith("."), key


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_braces_only_in_placeholders(code):
    for key, text in load(code).items():
        rest = PLACEHOLDER.sub("", text)
        assert "{" not in rest and "}" not in rest, key


@pytest.mark.parametrize("name", ["en.json", "tr.json", "__init__.py"])
def test_no_long_dashes(name):
    text = (I18N_DIR / name).read_text(encoding="utf-8")
    for dash in DASHES:
        assert dash not in text, (name, hex(ord(dash)))


def test_turkish_uses_ascii_apostrophes():
    text = (I18N_DIR / "tr.json").read_text(encoding="utf-8")
    assert chr(0x2018) not in text and chr(0x2019) not in text
    assert "Telnet'i" in text


def test_turkish_never_puts_a_suffix_on_a_placeholder():
    # "{port}'a" reads right for some numbers and wrong for others.
    for key, text in load("tr").items():
        assert not re.search(r"\}['\w]", text), key


# Looking texts up


def test_english_by_default_and_turkish_on_request():
    i18n.set_language("en")
    assert i18n.t("severity.high") == "High"
    assert i18n.t("kind.smart-home") == "Smart home device"
    assert i18n.set_language("tr") == "tr"
    assert i18n.language() == "tr"
    assert i18n.t("severity.high") == "Yüksek"
    assert i18n.t("kind.nas") == "NAS (ağ diski)"


def test_fills_placeholders():
    i18n.set_language("en")
    assert "(port 23)" in i18n.t("rule.telnet-open.fix", port=23)
    assert "PostgreSQL" in i18n.t("rule.database-open.why", service="PostgreSQL", port="5432")
    i18n.set_language("tr")
    turkish = load("tr")
    fixed = turkish["rule.telnet-open.fix"].replace("{port}", "23")
    assert i18n.t("rule.telnet-open.fix", port=23) == fixed
    reason = turkish["rule.old-tls.why"].replace("{version}", "TLSv1.1")
    assert i18n.t("rule.old-tls.why", version="TLSv1.1", port="443") == reason


def test_unused_params_are_ignored():
    i18n.set_language("en")
    assert i18n.t("severity.low", port=1, product="x") == "Low"


FAKE_TEXTS = {
    "en": {
        "greeting": "Hello {name}",
        "pair": "{a} and {b}",
        "only.english": "English only",
        "odd": "50% {not a placeholder} {",
        "self": "{key}",
    },
    "tr": {"greeting": "Merhaba {name}"},
}


@pytest.fixture
def fake_texts(monkeypatch):
    monkeypatch.setattr(i18n, "_texts", lambda code: FAKE_TEXTS.get(code, {}))


def test_falls_back_to_english_then_to_the_key(fake_texts):
    i18n.set_language("tr")
    assert i18n.t("greeting", name="Ada") == "Merhaba Ada"
    assert i18n.t("only.english") == "English only"
    assert i18n.t("no.such.key") == "no.such.key"
    assert i18n.t("no.such.{key}", key="x") == "no.such.{key}"


def test_missing_params_stay_as_placeholders(fake_texts):
    i18n.set_language("en")
    assert i18n.t("greeting") == "Hello {name}"
    assert i18n.t("pair", a="one") == "one and {b}"


def test_braces_in_values_are_not_expanded(fake_texts):
    i18n.set_language("en")
    assert i18n.t("greeting", name="{name}") == "Hello {name}"
    assert i18n.t("greeting", name="{0} {} {__class__}") == "Hello {0} {} {__class__}"
    assert i18n.t("pair", a="{b}", b="two") == "{b} and two"
    assert i18n.t("odd", x="y") == "50% {not a placeholder} {"


def test_values_become_strings(fake_texts):
    i18n.set_language("en")
    assert i18n.t("greeting", name=23) == "Hello 23"
    assert i18n.t("greeting", name=None) == "Hello None"


def test_a_placeholder_may_be_called_key(fake_texts):
    i18n.set_language("en")
    assert i18n.t("self", key="value") == "value"


def test_has(fake_texts):
    i18n.set_language("tr")
    assert i18n.has("greeting")
    assert i18n.has("only.english")
    assert not i18n.has("no.such.key")


def test_has_with_the_real_files():
    assert i18n.has("rule.telnet-open.title")
    assert not i18n.has("rule.no-such-rule.title")


# Choosing the language


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("tr", "tr"),
        ("TR", "tr"),
        ("tr_TR.UTF-8", "tr"),
        ("tr-TR", "tr"),
        ("Turkish", "tr"),
        ("en", "en"),
        ("en_GB", "en"),
        ("de", "en"),
        ("xx-YY", "en"),
        ("", "en"),
        ("C", "en"),
        ("../../etc/passwd", "en"),
    ],
)
def test_set_language(code, expected):
    assert i18n.set_language(code) == expected
    assert i18n.language() == expected


def test_set_language_none_detects(monkeypatch):
    monkeypatch.setattr(i18n, "detect", lambda: "tr")
    assert i18n.set_language(None) == "tr"
    monkeypatch.setattr(i18n, "detect", lambda: "en")
    assert i18n.set_language(None) == "en"


def test_detect_defaults_to_english(no_system_language):
    assert i18n.detect() == "en"


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"LANG": "tr_TR.UTF-8"}, "tr"),
        ({"LANG": "en_US.UTF-8"}, "en"),
        ({"LANG": "de_DE.UTF-8"}, "en"),
        ({"LC_ALL": "tr_TR"}, "tr"),
        ({"LC_MESSAGES": "tr_TR.UTF-8@euro"}, "tr"),
        ({"LANGUAGE": "tr"}, "tr"),
        ({"LANGUAGE": "tr:en"}, "tr"),
        ({"LANGUAGE": "de:tr:en"}, "tr"),
        ({"LANGUAGE": "de:en:tr"}, "en"),
        ({"HEARTHSCAN_LANG": "tr"}, "tr"),
        ({"HEARTHSCAN_LANG": "en", "LANG": "tr_TR.UTF-8"}, "en"),
        ({"HEARTHSCAN_LANG": "", "LANG": "tr_TR.UTF-8"}, "tr"),
        ({"LC_ALL": "en_US.UTF-8", "LANG": "tr_TR.UTF-8"}, "en"),
        # C and POSIX name no language, so the next variable decides.
        ({"LC_ALL": "C.UTF-8", "LANG": "tr_TR.UTF-8"}, "tr"),
        ({"LANG": "POSIX", "LANGUAGE": "tr"}, "tr"),
        ({"LANG": "C"}, "en"),
        # LANGUAGE picks the message language before LC_* and LANG, as in gettext.
        ({"LANG": "en_US.UTF-8", "LANGUAGE": "tr:en"}, "tr"),
        ({"LANG": "tr_TR.UTF-8", "LANGUAGE": "en_US:en"}, "en"),
    ],
)
def test_detect_from_environment(no_system_language, monkeypatch, env, expected):
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    assert i18n.detect() == expected


def test_environment_beats_the_system(no_system_language, monkeypatch):
    monkeypatch.setenv("LANG", "en_US.UTF-8")
    monkeypatch.setattr(locale, "getlocale", lambda *args: ("tr_TR", "UTF-8"))
    monkeypatch.setattr(system, "IS_WINDOWS", True)
    monkeypatch.setattr(ctypes, "WinDLL", fake_windll(0x041F), raising=False)
    assert i18n.detect() == "en"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (("tr_TR", "UTF-8"), "tr"),
        (("Turkish_Turkey", "1254"), "tr"),
        (("Turkish_Türkiye", "1254"), "tr"),
        (("en_US", "UTF-8"), "en"),
        (("Danish_Denmark", "1252"), "en"),
        ((None, None), "en"),
    ],
)
def test_detect_from_locale(no_system_language, monkeypatch, name, expected):
    monkeypatch.setattr(locale, "getlocale", lambda *args: name)
    assert i18n.detect() == expected


def test_detect_survives_a_broken_locale(no_system_language, monkeypatch):
    def broken(*args):
        raise ValueError("unknown locale: xx")

    monkeypatch.setattr(locale, "getlocale", broken)
    assert i18n.detect() == "en"


@pytest.mark.parametrize(
    ("langid", "expected"),
    [(0x041F, "tr"), (0x0409, "en"), (0x0406, "en"), (0x0407, "en")],
)
def test_detect_from_windows_display_language(no_system_language, monkeypatch, langid, expected):
    calls = []
    monkeypatch.setattr(system, "IS_WINDOWS", True)
    monkeypatch.setattr(ctypes, "WinDLL", fake_windll(langid, calls), raising=False)
    assert i18n.detect() == expected
    assert calls == ["kernel32"]


def test_windows_display_language_wins_over_a_foreign_region(no_system_language, monkeypatch):
    # A Turkish Windows with Danish number and date formats.
    monkeypatch.setattr(locale, "getlocale", lambda *args: ("Danish_Denmark", "1252"))
    monkeypatch.setattr(system, "IS_WINDOWS", True)
    monkeypatch.setattr(ctypes, "WinDLL", fake_windll(0x041F), raising=False)
    assert i18n.detect() == "tr"


def test_english_windows_with_turkish_formats_stays_english(no_system_language, monkeypatch):
    monkeypatch.setattr(locale, "getlocale", lambda *args: ("Turkish_Türkiye", "1254"))
    monkeypatch.setattr(system, "IS_WINDOWS", True)
    monkeypatch.setattr(ctypes, "WinDLL", fake_windll(0x0409), raising=False)
    assert i18n.detect() == "en"


def test_detect_survives_a_missing_windows_api(no_system_language, monkeypatch):
    def missing(name):
        raise OSError("no such library")

    monkeypatch.setattr(system, "IS_WINDOWS", True)
    monkeypatch.setattr(ctypes, "WinDLL", missing, raising=False)
    assert i18n.detect() == "en"
    monkeypatch.setattr(ctypes, "WinDLL", lambda name: types.SimpleNamespace(), raising=False)
    assert i18n.detect() == "en"


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ('(\n    "tr-TR",\n    "en-US"\n)\n', "tr"),
        ("(\n    tr,\n    en\n)\n", "tr"),
        ('(\n    "en-TR",\n    "tr-TR"\n)\n', "en"),
        ("(\n    en\n)\n", "en"),
        ("", "en"),
        ("()", "en"),
        ("\x00" * 10000, "en"),
    ],
)
def test_detect_from_macos_languages(no_system_language, monkeypatch, output, expected):
    calls = []

    def run(args, timeout=10.0):
        calls.append(args)
        return output

    monkeypatch.setattr(system, "IS_MACOS", True)
    monkeypatch.setattr(system, "run", run)
    assert i18n.detect() == expected
    assert calls == [["/usr/bin/defaults", "read", "-g", "AppleLanguages"]]


def test_no_system_commands_off_macos(no_system_language, monkeypatch):
    def run(args, timeout=10.0):
        raise AssertionError("should not run anything")

    monkeypatch.setattr(system, "run", run)
    assert i18n.detect() == "en"


# Loading


def test_parse_keeps_only_strings():
    raw = json.dumps({"a": "A", "b": 1, "c": None, "d": ["x"], "e": {"f": "g"}}).encode()
    assert i18n._parse(raw) == {"a": "A"}


@pytest.mark.parametrize(
    "raw",
    [b"", b"not json", b"[1, 2]", b'"text"', b"\xff\xfe{}", b"[" * 100000],
)
def test_parse_rejects_what_is_not_a_text_table(raw):
    assert i18n._parse(raw) == {}


def test_parse_rejects_oversized_files():
    raw = json.dumps({"a": "x" * i18n.MAX_FILE}).encode()
    assert i18n._parse(raw) == {}


def test_missing_language_file_is_empty():
    assert i18n._texts("zz") == {}
