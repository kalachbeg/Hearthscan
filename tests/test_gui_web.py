"""The page of the desktop window, read as files.

The server sends it with a strict content security policy: no inline scripts
or styles, nothing from other hosts. Names and banners from the network must
reach the page as text, never as markup.
"""

import json
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

import hearthscan

PACKAGE = Path(hearthscan.__file__).parent
WEB = PACKAGE / "gui" / "web"
FILES = ("index.html", "app.js", "styles.css")
DASHES = tuple(chr(code) for code in (0x2012, 0x2013, 0x2014, 0x2015))
# Invisible marks that change the order text is shown in; code should spell them as escapes.
DIRECTION_MARKS = tuple(
    chr(code) for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
)
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# t('key') and t('key', { name: value, ... }) with a literal key.
TEXT_CALL = re.compile(r"""\bt\(\s*'([^']+)'\s*(\)|,\s*\{([^{}]*)\})""", re.S)
PARAM_NAME = re.compile(r"(\w+)\s*:")
TEXT_ATTRIBUTES = ("data-t", "data-t-placeholder", "data-t-label")

# Ways to turn a string into markup or code.
FORBIDDEN_JS = {
    "innerHTML": r"\binnerHTML\b",
    "outerHTML": r"\bouterHTML\b",
    "insertAdjacentHTML": r"\binsertAdjacentHTML\b",
    "document.write": r"\bdocument\s*\.\s*write(ln)?\b",
    "eval": r"\beval\s*\(",
    "new Function": r"\bnew\s+Function\b",
    "string timer": r"\bset(Timeout|Interval)\s*\(\s*['\"`]",
    "createContextualFragment": r"\bcreateContextualFragment\b",
    "DOMParser": r"\bDOMParser\b",
    "srcdoc": r"\bsrcdoc\b",
    "style attribute": r"setAttribute\(\s*['\"]style['\"]",
    "cssText": r"\bcssText\b",
}


def read(name):
    return (WEB / name).read_text(encoding="utf-8")


def texts(code):
    return json.loads((PACKAGE / "i18n" / f"{code}.json").read_text(encoding="utf-8"))


def js_array(name):
    """The string items of `const NAME = [...]` in app.js."""
    match = re.search(rf"const {name} = \[([^\]]*)\]", read("app.js"))
    assert match, name
    return re.findall(r"'([^']+)'", match.group(1))


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.inline = []
        self._open = None

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag in ("script", "style"):
            self._open = tag

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_endtag(self, tag):
        if tag == self._open:
            self._open = None

    def handle_data(self, data):
        if self._open and data.strip():
            self.inline.append((self._open, data))


@pytest.fixture(scope="module")
def page():
    parser = Page()
    parser.feed(read("index.html"))
    parser.close()
    return parser


@pytest.mark.parametrize("name", FILES)
def test_files_are_utf8_without_long_dashes(name):
    raw = (WEB / name).read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8")
    for dash in DASHES:
        assert dash not in text, (name, hex(ord(dash)))


@pytest.mark.parametrize("name", FILES)
def test_no_hidden_text_direction_marks(name):
    text = read(name)
    for mark in DIRECTION_MARKS:
        assert mark not in text, (name, hex(ord(mark)))


@pytest.mark.parametrize("name", FILES)
def test_no_web_addresses(name):
    text = read(name).lower()
    assert "http://" not in text
    assert "https://" not in text


def test_styles_load_nothing():
    css = read("styles.css")
    assert "@import" not in css
    for target in re.findall(r"url\(\s*['\"]?([^'\")]*)", css):
        assert target.startswith("data:"), target


def test_page_has_no_inline_code_or_styles(page):
    assert page.inline == []
    for tag, attrs in page.tags:
        assert tag != "style"
        for name in attrs:
            assert not name.startswith("on"), (tag, name)
            assert name != "style", tag


def test_page_loads_only_its_own_script_and_stylesheet(page):
    scripts = [attrs for tag, attrs in page.tags if tag == "script"]
    assert [attrs.get("src") for attrs in scripts] == ["app.js"]
    links = [attrs for tag, attrs in page.tags if tag == "link"]
    assert [(attrs.get("rel"), attrs.get("href")) for attrs in links] == [
        ("stylesheet", "styles.css")
    ]
    for tag, attrs in page.tags:
        assert tag not in ("img", "iframe", "object", "embed", "form", "base")
        for name in ("src", "href", "action", "srcset", "xlink:href"):
            value = attrs.get(name)
            if value is not None and tag not in ("script", "link"):
                raise AssertionError(f"<{tag} {name}={value!r}>")


def test_page_declares_its_encoding_and_viewport(page):
    metas = [attrs for tag, attrs in page.tags if tag == "meta"]
    assert {"charset": "utf-8"} in metas
    assert any(attrs.get("name") == "viewport" for attrs in metas)


@pytest.mark.parametrize("what", sorted(FORBIDDEN_JS))
def test_app_never_turns_strings_into_markup_or_code(what):
    assert not re.search(FORBIDDEN_JS[what], read("app.js")), what


def test_every_text_the_app_asks_for_exists():
    english, turkish = texts("en"), texts("tr")
    calls = TEXT_CALL.findall(read("app.js"))
    assert len(calls) > 40  # the pattern still matches how app.js asks for texts
    for key, _, _ in calls:
        assert key in english, key
        assert key in turkish, key


def test_the_app_fills_every_placeholder():
    english = texts("en")
    for key, closing, params in TEXT_CALL.findall(read("app.js")):
        given = set(PARAM_NAME.findall(params)) if closing != ")" else set()
        assert set(PLACEHOLDER.findall(english[key])) == given, key


def test_every_text_the_page_names_exists(page):
    english, turkish = texts("en"), texts("tr")
    keys = [attrs[name] for _, attrs in page.tags for name in TEXT_ATTRIBUTES if name in attrs]
    assert len(keys) > 20
    for key in keys:
        assert key in english, key
        assert key in turkish, key


def test_texts_the_app_builds_from_parts_exist():
    english = texts("en")
    for stage in js_array("STAGES"):
        assert f"ui.stage.{stage}" in english
    for severity in js_array("SEVERITIES"):
        assert f"severity.{severity}" in english
    for severity in js_array("COUNTED"):
        assert f"ui.count.{severity}" in english
    table = re.search(r"const BANDS = (\[.*?\]);", read("app.js"))
    assert table
    bands = re.findall(r"'(\w+)'\]", table.group(1))
    assert bands == ["good", "fair", "poor", "bad"]
    for band in bands:
        assert f"band.{band}.title" in english
        assert f"band.{band}.summary" in english
    for sandbox in ("wsl", "container"):
        assert f"ui.sandbox.{sandbox}" in english


def test_every_element_the_app_looks_up_exists(page):
    ids = {attrs["id"] for _, attrs in page.tags if "id" in attrs}
    wanted = set(re.findall(r"\$\('([\w-]+)'\)", read("app.js")))
    wanted |= {f"view-{view}" for view in js_array("VIEWS")}
    assert wanted
    assert wanted <= ids, sorted(wanted - ids)
