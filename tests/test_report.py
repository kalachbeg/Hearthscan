import re
from datetime import datetime, timezone
from html.parser import HTMLParser

import pytest

from hearthscan import i18n
from hearthscan.i18n import t
from hearthscan.models import Device, Finding, PortMapping, RouterInfo, ScanResult, Service
from hearthscan.report import format_time, html_report

STARTED = "2026-01-02T03:04:05+00:00"
BIDI = "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

TELNET = Finding("telnet-open", "high", "192.168.1.1", 23, {"port": "23"}, "banner: login:")
UPNP = Finding("upnp-igd", "medium", "192.168.1.1", None, {}, "WANIPConnection:1")
SSH = Finding("ssh-open", "info", "192.168.1.1", 22, {"port": "22", "product": ""})
UNKNOWN = Finding("unknown-device", "info", "192.168.1.77")
FORWARD = Finding(
    "port-forward",
    "low",
    "192.168.1.50",
    3389,
    {"external_port": "50000", "internal_port": "3389", "protocol": "TCP", "description": "RDP"},
    "TCP 50000 to 192.168.1.50:3389 (RDP)",
)


def devices():
    return [
        Device(
            "192.168.1.1",
            mac="a4:83:e7:00:00:01",
            vendor="Acme",
            model="Acme HR-100",
            dns_name="router.lan",
            kind="router",
            services=[Service(80, name="http"), Service(23, name="telnet")],
            confirmed=True,
            is_gateway=True,
        ),
        Device("192.168.1.50", dns_name="Office-PC", kind="computer", confirmed=True, is_self=True),
        Device("192.168.1.77", mac="da:a1:19:00:00:30"),
    ]


def result(*findings, router=None, devices=devices, notes=(), score=85):
    return ScanResult(
        version="2.0.0",
        started=STARTED,
        finished="2026-01-02T03:04:47+00:00",
        interface="Ethernet",
        address="192.168.1.50",
        network="192.168.1.0/24",
        gateway="192.168.1.1",
        devices=devices(),
        findings=list(findings),
        score=score,
        ports=[22, 23, 80],
        notes=list(notes),
        router=router,
    )


def router_info(*mappings, complete=True):
    return RouterInfo(
        external_ip="10.20.30.40",
        connection="IP_Routed",
        status="Connected",
        uptime=3 * 86400 + 5 * 3600 + 59 * 60,
        mappings=list(mappings),
        mappings_complete=complete,
    )


class Page(HTMLParser):
    """Every tag, attribute and piece of text in a page, entities already decoded."""

    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []
        self.style = []
        self._in_style = False
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        self._in_style = tag == "style"

    def handle_endtag(self, tag):
        self._in_style = False

    def handle_data(self, data):
        (self.style if self._in_style else self.text).append(data)

    @property
    def words(self):
        return " ".join(" ".join(self.text).split())


ALLOWED_TAGS = {
    "html", "head", "meta", "title", "style", "body", "main", "header", "section", "article",
    "footer", "h1", "h2", "h3", "p", "span", "div", "dl", "dt", "dd", "code", "ul", "li",
    "table", "thead", "tbody", "tr", "th", "td",
}  # fmt: skip
ALLOWED_ATTRIBUTES = {
    "lang", "charset", "name", "content", "http-equiv", "class", "style", "aria-hidden",
    "scope", "data-label",
}  # fmt: skip


def assert_only_our_markup(page):
    for tag, attrs in page.tags:
        assert tag in ALLOWED_TAGS, tag
        assert set(attrs) <= ALLOWED_ATTRIBUTES, (tag, attrs)
        if "style" in attrs:
            assert re.fullmatch(r"width: \d{1,3}%", attrs["style"]), attrs
    assert sum(tag == "style" for tag, _ in page.tags) == 1


@pytest.fixture(autouse=True)
def english():
    previous = i18n.language()
    i18n.set_language("en")
    yield
    i18n.set_language(previous)


# The page


def test_a_complete_page():
    out = html_report(result(TELNET))
    assert out.startswith("<!DOCTYPE html>\n")
    assert out.rstrip().endswith("</html>")
    page = Page(out)
    tags = dict(page.tags)
    assert tags["html"] == {"lang": "en"}
    assert ("meta", {"charset": "utf-8"}) in page.tags
    assert ("meta", {"name": "viewport", "content": "width=device-width, initial-scale=1"}) in (
        page.tags
    )
    title = re.search(r"<title>(.*)</title>", out).group(1)
    assert "192.168.1.0/24" in title and format_time(STARTED) in title
    assert_only_our_markup(page)


def test_styles_cover_dark_mode_phones_and_print():
    out = html_report(result())
    assert "prefers-color-scheme: dark" in out
    assert "@media print" in out
    assert "@media (max-width:" in out
    assert "system-ui" in out


def test_nothing_is_loaded_from_anywhere():
    out = html_report(result(TELNET, UPNP, SSH, router=router_info(), notes=[("x", "y")]))
    lowered = out.lower()
    for needle in ("http:", "https:", "//", "url(", "@import", "@font-face", "<script", "<link"):
        assert needle not in lowered, needle
    for needle in ("src=", "href=", "srcset", "<img", "<iframe", "<object", "<svg", "<form"):
        assert needle not in lowered, needle
    metas = [attrs for tag, attrs in Page(out).tags if tag == "meta"]
    csp = next(m["content"] for m in metas if m.get("http-equiv") == "Content-Security-Policy")
    assert "default-src 'none'" in csp
    assert "script-src" not in csp


def test_the_header_mirrors_the_terminal():
    words = Page(html_report(result(TELNET, UPNP, SSH, score=70))).words
    assert "Network score 70 / 100" in words
    assert t("band.fair.title") in words and t("band.fair.summary") in words
    assert t("ui.score.urgent") in words
    assert "192.168.1.0/24 · devices: 3 · high: 1, medium: 1 · took 42 s" in words


def test_no_urgent_line_without_critical_or_high_findings():
    words = Page(html_report(result(UPNP, SSH))).words
    assert t("ui.score.urgent") not in words
    clean = Page(html_report(result(SSH, score=100))).words
    assert t("ui.summary.clean") in clean
    assert t("band.good.title") in clean


def test_findings_as_cards():
    out = html_report(result(TELNET, UPNP))
    page = Page(out)
    assert ("article", {"class": "finding sev-high"}) in page.tags
    assert ("span", {"class": "badge sev-high"}) in page.tags
    assert ("span", {"class": "badge sev-medium"}) in page.tags
    words = page.words
    assert "High Telnet is switched on router, Router (192.168.1.1), port 23" in words
    assert t("rule.telnet-open.why") in words
    assert t("rule.telnet-open.fix", port=23) in words
    assert "Why it matters" in words and "What to do" in words
    assert "<code>banner: login:</code>" in out
    assert out.index("Telnet is switched on") < out.index(t("rule.upnp-igd.title"))
    assert t("ui.findings.none") not in words


def test_good_to_know_is_a_short_list():
    out = html_report(result(SSH, UNKNOWN))
    page = Page(out)
    words = page.words
    assert t("ui.findings.fyi") in words
    assert t("rule.ssh-open.title") in words
    assert t("rule.ssh-open.why") not in words  # titles only
    assert t("rule.unknown-device.fix") in words  # except how to find an unknown device
    assert "Unknown device (192.168.1.77)" in words
    assert not any(tag == "article" for tag, _ in page.tags)
    assert t("ui.findings.none") in words


def test_the_router():
    rdp = PortMapping("TCP", 50000, "192.168.1.50", 3389, "Remote desktop")
    game = PortMapping("UDP", 27015, "192.168.1.88", 27016, "Game server", enabled=False)
    out = html_report(result(FORWARD, router=router_info(rdp, game)))
    page = Page(out)
    words = page.words
    assert "Your router" in words
    assert "Internet address 10.20.30.40" in words
    assert "Connection type IP_Routed" in words and "Status Connected" in words
    assert "Running for 3 d 5 h" in words
    assert "50000 TCP Office-PC (192.168.1.50), port 3389 Remote desktop" in words
    assert "27015 UDP 192.168.1.88:27016 Game server switched off" in words
    assert ("tr", {"class": "off"}) in page.tags
    assert t("ui.router.none") not in words
    assert out.index("Your router") < out.index("Devices on your network")
    assert out.index("What we found") < out.index("Your router")


def test_a_router_without_forwards():
    words = Page(html_report(result(router=RouterInfo(status="Connected")))).words
    assert t("ui.router.none") in words
    assert "Internet address" not in words and "Running for" not in words
    assert t("ui.router.incomplete") not in words


def test_a_cut_short_forward_list_is_not_called_empty():
    words = Page(html_report(result(router=router_info(complete=False)))).words
    assert t("ui.router.none") not in words
    assert t("ui.router.incomplete") in words


def test_the_devices():
    out = html_report(result())
    page = Page(out)
    words = page.words
    assert "Devices on your network" in words
    assert "192.168.1.1 router Router Acme HR-100 23 telnet 80 http router" in words
    assert "192.168.1.50 Office-PC Computer this computer" in words
    assert "192.168.1.77 Unknown device did not answer" in words
    labels = {attrs.get("data-label") for tag, attrs in page.tags if tag == "td"}
    # Empty cells go without a label, so a phone does not show the label alone.
    assert labels == {"Address", "Name", "Type", "Maker and model", "Open ports", "Tags", None}
    assert "<td></td>" in out


def test_notes_and_footer():
    out = html_report(result(notes=[("mdns", "mDNS did not answer")]))
    words = Page(out).words
    assert "Notes mDNS did not answer" in words
    footer = words[words.index("Hearthscan 2.0.0") :]
    assert f"Scan started {format_time(STARTED)}" in footer
    assert t("report.privacy") in footer


def test_an_empty_result():
    empty = result(devices=list)
    empty.gateway = None
    words = Page(html_report(empty)).words
    assert t("ui.findings.none") in words
    assert t("report.devices.none") in words
    assert "Your router" not in words
    assert "Notes" not in words
    assert "devices: 0" in words


def test_turkish():
    i18n.set_language("tr")
    out = html_report(result(TELNET, SSH, router=router_info()))
    page = Page(out)
    assert dict(page.tags)["html"] == {"lang": "tr"}
    words = page.words
    assert "Ağ puanı" in words and "Neden önemli" in words  # noqa: RUF001
    assert "Ne yapmalı" in words and "Modeminiz" in words  # noqa: RUF001
    assert "Ağınızdaki cihazlar" in words  # noqa: RUF001
    assert "Hearthscan raporu: 192.168.1.0/24" in out
    assert "3 gün 5 saat" in words
    assert t("report.privacy") in words
    assert re.search(r"\d\d\.\d\d\.2026 \d\d:\d\d", words)


def test_the_score_bar_stays_in_range():
    page = Page(html_report(result(score=250)))
    widths = [attrs["style"] for tag, attrs in page.tags if "style" in attrs]
    assert widths == ["width: 100%"]


# Text from the network


HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'; background: url(http://192.168.1.9/x.png); '",
    "]]><!--",
    "<style>body{display:none}</style>",
    "A\u202eexe.txt",
    "\u2066isolated\u2069",
    "nul\x00and\x1besc\x7f\x9bend",
    "lone \ud800 surrogate",
    "&amp; &lt;",
]


def hostile_result():
    scan = result(router=router_info())
    for index, text in enumerate(HOSTILE):
        scan.devices.append(
            Device(
                f"192.168.1.{100 + index}",
                vendor=text,
                model=text,
                dns_name=text,
                kind=text,
                services=[Service(8000 + index, name=text)],
                confirmed=True,
            )
        )
        scan.findings.append(
            Finding(
                "port-forward",
                "high",
                f"192.168.1.{100 + index}",
                8000 + index,
                {"external_port": text, "internal_port": text, "protocol": text},
                text,
            )
        )
        scan.router.mappings.append(PortMapping(text, 1, f"192.168.1.{100 + index}", 2, text))
        scan.notes.append(("x", text))
    scan.findings.append(Finding(HOSTILE[0], HOSTILE[1], "192.168.1.100", 1, {}, HOSTILE[1]))
    scan.router.status = scan.router.connection = HOSTILE[1]
    scan.network = scan.interface = scan.version = HOSTILE[0]
    return scan


@pytest.mark.parametrize("code", i18n.LANGUAGES)
def test_hostile_text_never_becomes_markup(code):
    i18n.set_language(code)
    out = html_report(hostile_result())
    page = Page(out)
    assert_only_our_markup(page)
    lowered = out.lower()
    assert "<script" not in lowered and "<img" not in lowered and "<!--" not in lowered
    assert "]]>" not in out
    style = "".join(page.style)
    assert "url(" not in style and "display:none" not in style
    words = page.words
    assert "<script>alert(1)</script>" in words  # shown as text instead
    assert '"><img src=x onerror=alert(1)>' in words
    assert "&amp; &lt;" in words


def test_quotes_cannot_leave_an_attribute():
    scan = result(Finding("telnet-open", 'high" onclick="x', "192.168.1.1", 23, {"port": "23"}))
    page = Page(html_report(scan))
    assert_only_our_markup(page)
    assert ("article", {"class": "finding sev-info"}) in page.tags


def test_no_direction_or_control_characters_survive():
    out = html_report(hostile_result())
    for char in BIDI:
        assert char not in out, hex(ord(char))
    for code in [*range(0x20), *range(0x7F, 0xA0)]:
        if chr(code) != "\n":
            assert chr(code) not in out, hex(code)
    assert "\ud800" not in out
    out.encode("utf-8")  # writable as UTF-8
    words = Page(out).words
    assert "Aexe.txt" in words and "isolated" in words
    assert "nul and esc end" in words
    assert "lone \ufffd surrogate" in words


# Times


def test_format_time_is_local():
    expected = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc).astimezone()
    assert format_time(STARTED) == expected.strftime("%Y-%m-%d %H:%M")
    assert format_time("2026-01-02T03:04:05Z") == format_time(STARTED)
    i18n.set_language("tr")
    assert format_time(STARTED) == expected.strftime("%d.%m.%Y %H:%M")


@pytest.mark.parametrize("text", ["yesterday", "", "2026-13-45", "<b>"])
def test_format_time_keeps_what_it_cannot_read(text):
    assert format_time(text) == text


@pytest.mark.parametrize("text", ["0001-01-01T00:00:00+00:00", "9999-12-31T23:59:59+00:00"])
def test_format_time_at_the_ends_of_the_calendar(text):
    # Past the end of the calendar in local time: shown as saved instead.
    assert format_time(text)[:4] == text[:4]


def test_an_unreadable_time_still_makes_a_page():
    scan = result()
    scan.started = scan.finished = "not a time"
    words = Page(html_report(scan)).words
    assert "Scan started not a time" in words
    assert "took" not in words
