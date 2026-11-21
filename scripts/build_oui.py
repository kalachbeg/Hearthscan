"""Build src/hearthscan/data/oui.tsv.gz from the public IEEE MAC address registries.

The data comes from the MA-L, MA-M, MA-S and IAB lists at standards-oui.ieee.org.
Rebuild it with `uv run python scripts/build_oui.py`, or pass `--source DIR` to read
CSV files saved earlier (oui.csv, mam.csv, oui36.csv, iab.csv) instead of downloading.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "src" / "hearthscan" / "data" / "oui.tsv.gz"


@dataclass(slots=True)
class Registry:
    name: str
    url: str
    digits: int  # hex digits in an assignment
    required: bool = True


REGISTRIES = (
    Registry("MA-L", "https://standards-oui.ieee.org/oui/oui.csv", 6),
    Registry("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", 7),
    Registry("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", 9),
    # Closed to new assignments since 2014. The list may go away one day.
    Registry("IAB", "https://standards-oui.ieee.org/iab/iab.csv", 9, required=False),
)

USER_AGENTS = (
    "hearthscan-build-oui",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
)
REFUSED = {403, 406, 418, 429}
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_NAME = 64
COLUMNS = ("Registry", "Assignment", "Organization Name")

# Registry entries that name no vendor. "IEEE Registration Authority" owns the
# MA-L blocks that are split into MA-M and MA-S assignments.
NOT_A_VENDOR = {"", "private", "ieee registration authority"}


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


# Spellings of the vendors that turn up on home networks, matched at the start
# of the organization name (case does not matter). The first match wins.
ALIASES: tuple[tuple[str, str], ...] = (
    (r"apple\b", "Apple"),
    (r"samsung\b", "Samsung"),
    (r"huawei\b", "Huawei"),
    (r"honor device\b", "Honor"),
    (r"(?:beijing )?xiaomi\b", "Xiaomi"),
    (r"tp-link\b", "TP-Link"),
    (r"amazon\b", "Amazon"),
    (r"google\b", "Google"),
    (r"nest labs\b", "Nest"),
    (r"ring llc\b", "Ring"),
    (r"meta platforms\b", "Meta"),
    (r"espressif\b", "Espressif"),
    (r"sonos\b", "Sonos"),
    (r"(?:hangzhou |prama )?hikvision\b", "Hikvision"),
    (r"(?:zhejiang )?dahua technology", "Dahua"),
    (r"(?:hangzhou )?ezviz\b", "Ezviz"),
    (r"reolink\b", "Reolink"),
    (r"wyze\b", "Wyze"),
    (r"synology\b", "Synology"),
    (r"qnap\b", "QNAP"),
    (r"netgear\b", "Netgear"),
    (r"asustek\b|asus\b", "ASUS"),
    (r"avm\b(?! electronics)|fritz! technology\b", "AVM"),
    (r"ubiquiti\b", "Ubiquiti"),
    (r"raspberry pi\b", "Raspberry Pi"),
    (r"intel corporat", "Intel"),
    (r"realtek\b", "Realtek"),
    (r"murata manufacturing\b", "Murata"),
    (r"lite-?on\b", "Liteon"),
    (r"azurewave\b", "AzureWave"),
    (r"hewlett[- ]packard enterprise\b", "HPE"),
    (r"hewlett[- ]packard\b|hp inc\b", "HP"),
    (r"canon\b", "Canon"),
    (r"brother industries\b", "Brother"),
    (r"(?:seiko )?epson\b", "Epson"),
    (r"roku\b", "Roku"),
    (r"nintendo\b", "Nintendo"),
    # PlayStation blocks. Device classification tells consoles from Sony TVs by this name.
    (r"sony interactive\b|sony computer entertainment\b", "Sony Interactive"),
    (r"sony\b", "Sony"),
    (r"lg electr?onics\b|lg electornics\b", "LG"),
    # Hue lights. Philips itself makes TVs, appliances and medical gear.
    (r"signify\b|philips lighting\b", "Signify"),
    (r"philips\b", "Philips"),
    (r"tuya\b", "Tuya"),
    (r"shelly\b|allterco\b", "Shelly"),
    (r"arcadyan\b", "Arcadyan"),
    (r"sagemcom\b", "Sagemcom"),
    (r"(?:shanghai )?zte\b", "ZTE"),
    (r"technicolor\b", "Technicolor"),
    (r"zyxel\b", "Zyxel"),
    (r"d-link\b", "D-Link"),
    (r"microsoft\b", "Microsoft"),
    (r"dell\b", "Dell"),
    (r"lenovo\b", "Lenovo"),
    (r"motorola mobility\b|motorola \(wuhan\)", "Motorola"),
    (r"bose\b", "Bose"),
    (r"cisco meraki\b", "Meraki"),
    (r"(?:cisco-|the )?linksys\b", "Linksys"),
    (r"cisco\b", "Cisco"),
    (r"(?:guangdong )?oppo\b", "OPPO"),
    (r"vivo mobile\b", "vivo"),
    (r"realme\b", "realme"),
    (r"oneplus\b", "OnePlus"),
    (r"hon hai precision\b", "Foxconn"),
    (r"(?:shenzhen )?skyworth\b", "Skyworth"),
    (r"(?:qingdao )?hisense\b", "Hisense"),
    (r"tcl\b", "TCL"),
    (r"(?:shen ?zhen )?tenda\b", "Tenda"),
    (r"giga-byte\b", "Gigabyte"),
    (r"micro-star\b", "MSI"),
    (r"nxp\b", "NXP"),
    (r"3com\b", "3Com"),
    (r"commscope\b", "CommScope"),
    (r"airties\b", "AirTies"),
    (r"arcelik\b", "Arcelik"),
    (r"vestel\b", "Vestel"),
)
_ALIASES = tuple((re.compile(pattern, re.IGNORECASE), name) for pattern, name in ALIASES)

# Company forms, compared after folding: lowercase, no accents, nothing but
# letters, digits, "&" and "/". "Co.,Ltd." splits at the comma into "co" and "ltd".
LEGAL_FORMS = _words(
    """
    ltd lt ltda lda ldta limited limitada liability private inc incorporated incorporation corp
    corporation co coltd coinc company comapny cokg kg kgaa gmbh mbh gesmbh gmbhcokg gmbh&cokg
    ag ohg ug gbr ev ek sa sas sasu sarl sau sl slu srl srlu sro spa bv bvba nv llc llp lp plc
    pllc ulc pbc ab oy oyj as asa a/s aps kk kft zrt nyrt jsc ojsc pjsc cjsc ooo doo dd uab sia
    ou sti ltdsti sirketi san sanayi tic ticaret pte pteltd pvt pvtltd pty ptyltd bhd sdn sdnbhd
    tbk cv sapi s/a spzoo spolka zoo spk spj se epp fzc fze fzco
    """
)
# Words that say what a company does or where it sits rather than who it is.
# They go only from the end of a name, and only while something distinctive is left.
NOISE_WORDS = _words(
    """
    technologies technology technolgoy technoligy technoly tech electronics electronic
    elektronik elettronica electronique eletronica electronica elektronika international intl
    int holdings holding group manufacturing mfg industrial ind trading corporate worldwide
    enterprises comercio industria
    usa america americas europe japan korea china taiwan india asia pacific deutschland germany
    france uk singapore hk canada australia nederland netherlands holland italia italy iberica
    nordic danmark denmark sverige sweden norge norway finland suomi belgium schweiz switzerland
    austria polska poland espana spain brasil brazil mexico malaysia thailand philippines
    vietnam indonesia israel turkey ireland
    """
)
# Short words that join parts of a company form: "GmbH & Co. KG", "San. ve Tic.",
# "S.A. de C.V.". Punctuation on its own folds to "".
CONNECTORS = frozenset({"", "&", "and", "und", "ve", "y", "e", "et", "de"})
# A name never ends on one of these ("Bank of America" keeps its last word,
# "Hitachi High Technologies" too).
DANGLING = _words(
    """
    of for the de da do di du der des del la le von van a an by in i at on high hi advanced
    applied integrated north south east west latin central
    """
)
CHINESE_PLACES = _words(
    """
    beijing shanghai shenzhen sz guangzhou guangdong hangzhou zhejiang jiangsu suzhou xiamen
    fujian fuzhou dongguan foshan zhuhai zhongshan huizhou sichuan chengdu chongqing wuhan hubei
    hunan changsha nanjing ningbo qingdao shandong jinan tianjin hefei anhui henan zhengzhou
    hebei xian shaanxi shanxi liaoning dalian shenyang jiangxi nanchang kunshan wuxi changzhou
    taicang jiaxing wenzhou yantai weihai weifang guangxi yunnan kunming hainan jilin harbin
    heilongjiang guizhou quanzhou shaoxing huzhou jinhua taizhou yangzhou nantong xuzhou
    jiangmen shantou luoyang nanning lanzhou shijiazhuang zhangzhou putian zibo langfang
    baoding hongkong
    """
)
# Words too vague to be a vendor name on their own.
GENERIC = (
    CHINESE_PLACES
    | NOISE_WORDS
    | DANGLING
    | _words(
        """
        digital smart intelligent intelligence general global universal united national new
        first best super micro data info information power electric electrical network networks
        communication communications telecom telecommunication telecommunications wireless
        mobile system systems solution solutions computer computers software precision optical
        audio video media vision security automation control controls instruments device
        devices product products equipment engineering design energy medical research science
        service services development innovation innovations lab labs laboratory laboratories
        enterprise industries industry western eastern northern southern home auto link net
        cloud iot ai display semiconductor lighting sensor sensors star sun sky
        """
    )
)
# Leading words that are not part of the name: "The", Russian company forms.
LEADING_WORDS = frozenset({"the", "ooo", "ao", "zao", "oao", "jsc", "ojsc", "cjsc", "pjsc"})
# Forms that end the name even when more words follow ("Foo GmbH Bar Systems").
STRONG_FORMS = _words(
    "gmbh mbh ag ltd ltda inc llc corp corporation oy oyj srl spa kft sro coltd pteltd pvtltd "
    "gmbhcokg gmbh&cokg"
)
# Three-letter words that are words, not acronyms, when a name is in capitals.
SHORT_WORDS = _words(
    "the and for new one top sky sun big air art pro max net web box eco bio key red sea car "
    "cam lab oil gas toy joy fox bee ace age all way win our man sub"
)
LOWER_WORDS = _words("and of for the und de da do di du des del la le von van y e et ve")
_KEEP_SHORT = SHORT_WORDS | LOWER_WORDS

_TOKEN = re.compile(r"[^\s,;]+")
_LETTERS = re.compile(r"[^\W\d_]+")
_PARENS = re.compile(r"(?<=\S)\s*\([^)]*\)?")
_DBA = re.compile(r"[\s(.,](?:dba|d/b/a)\s+([^)]+)", re.IGNORECASE)
_CLAUSE = re.compile(r",\s+an?\s+.*$", re.IGNORECASE)
_BRANCH = re.compile(r"[\s.,]+(?:[^\W\d_]+\s+)?branch$", re.IGNORECASE)
# "BUFFALO.INC", "Co.,Ltd.Shenzhen": a company form glued to the next word.
_GLUED = re.compile(
    r"(?<=[^\W\d_]{2})\.(?=(?:inc|ltd|co|corp|llc)\b)|(?<=\bltd)\.(?=[^\W\d_])", re.IGNORECASE
)
_INITIALS = re.compile(r"(?:^|\s)(?:[^\W\d_]\.)+[^\W\d_]$")
# Polish and Czech forms written with spaces, joined so they fold to one word.
_SPACED_FORMS = (
    (re.compile(r"\bsp\.?\s*z\s*o\.?\s*o\b\.?", re.IGNORECASE), "Sp.z.o.o."),
    (re.compile(r"\bz\s+o\.\s*o\b\.?", re.IGNORECASE), "z.o.o."),
    (re.compile(r"\bsp\.\s*([kj])\b\.?", re.IGNORECASE), r"Sp.\1."),
    (re.compile(r"\bspol\.?\s*s\s*r\.?\s*o\b\.?", re.IGNORECASE), "s.r.o."),
)
_DASHES = str.maketrans(
    dict.fromkeys(
        "\N{HYPHEN}\N{NON-BREAKING HYPHEN}\N{FIGURE DASH}\N{EN DASH}\N{EM DASH}\N{MINUS SIGN}",
        "-",
    )
)
_QUOTES = (
    "\"'"
    "\N{LEFT-POINTING DOUBLE ANGLE QUOTATION MARK}\N{RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK}"
    "\N{LEFT DOUBLE QUOTATION MARK}\N{RIGHT DOUBLE QUOTATION MARK}"
)
_TRIM = " ,.;:-&/"
_DOTTED_I = "\N{LATIN CAPITAL LETTER I WITH DOT ABOVE}"
_DOTLESS_I = "\N{LATIN SMALL LETTER DOTLESS I}"


def fold(word: str) -> str:
    """Lowercase ASCII form of a word for comparisons: "A.S." and "a.s" both give "as"."""
    text = unicodedata.normalize("NFKD", word.replace(_DOTTED_I, "I").replace(_DOTLESS_I, "i"))
    text = "".join(c for c in text if not unicodedata.combining(c)).lower()
    return re.sub(r"[^a-z0-9&/]", "", text)


def clean(text: str) -> str:
    """Even out the odd spaces, full-width punctuation and dashes the registry uses."""
    text = unicodedata.normalize("NFKC", text).translate(_DASHES)
    # A "?" stands for a character lost on the way into the registry.
    text = "".join(" " if c == "?" else c for c in text if unicodedata.category(c) != "Cf")
    return " ".join(text.split())


def _alias(name: str) -> str | None:
    for pattern, alias in _ALIASES:
        if pattern.match(name):
            return alias
    return None


def _drop_parens(name: str) -> str:
    inside = " ".join(re.findall(r"\(([^)]*)\)?", name))
    outside = _PARENS.sub(" ", name)
    if "(" not in outside:
        # The registry sometimes lost the opening bracket: "Foo?Shenzhen) Medical".
        outside = re.sub(r"\S*\)", " ", outside)
    outside = " ".join(outside.split())
    if not re.search("[A-Za-z]", outside) and re.search("[A-Za-z]", inside):
        # "<Chinese name> (<the same in Latin letters>)"
        return inside.strip()
    return outside or name


def _distinctive(words: list[str]) -> bool:
    return any(fold(w) not in GENERIC for w in words)


def _words_of(tokens: list[re.Match[str]]) -> list[str]:
    return [t.group() for t in tokens]


def _cut_after_form(name: str) -> str:
    tokens = list(_TOKEN.finditer(name))
    for i, token in enumerate(tokens[1:], 1):
        if fold(token.group()) in STRONG_FORMS and _distinctive(_words_of(tokens[:i])):
            return name[: token.end()]
    return name


def _strip_forms(name: str) -> str:
    """Drop company forms and filler words from the end of a name."""
    for pattern, joined in _SPACED_FORMS:
        name = pattern.sub(joined, name)
    tokens = list(_TOKEN.finditer(name))
    end = len(tokens)
    while end > 1:
        key = fold(tokens[end - 1].group())
        filler = key in NOISE_WORDS or key in CHINESE_PLACES
        if key not in LEGAL_FORMS and not (filler and _distinctive(_words_of(tokens[: end - 1]))):
            break
        cut = end - 1
        while cut > 1 and fold(tokens[cut - 1].group()) in CONNECTORS:
            cut -= 1
        if fold(tokens[cut - 1].group()) in DANGLING:
            break
        end = cut
    if end == len(tokens):
        return name
    return name[: tokens[end - 1].end()].rstrip(_TRIM)


def _strip_leading(name: str) -> str:
    words = name.split()
    if len(words) > 1 and fold(words[0]) in LEADING_WORDS:
        words = words[1:]
    for size in (2, 1):
        if len(words) > size and fold("".join(words[:size])) in CHINESE_PLACES:
            rest = words[size:]
            if _distinctive(rest) and fold(rest[0]) not in DANGLING:
                words = rest
                break
    return " ".join(words)


def _recase_word(match: re.Match[str]) -> str:
    word = match.group()
    text, start, end = match.string, match.start(), match.end()
    whole = (start == 0 or text[start - 1] == " ") and (end == len(text) or text[end] == " ")
    if whole and start > 0 and word.lower() in LOWER_WORDS:
        return word.lower()
    if len(word) <= 3 and word.lower() not in _KEEP_SHORT:
        return word
    if not re.search("[AEIOUY]", word) and word.isascii():
        return word
    return word.replace(_DOTTED_I, "I").capitalize()


def recase(name: str) -> str:
    """Make a name written in capitals readable. Short acronyms stay as they are."""
    if any(c.islower() for c in name) or not any(c.isupper() for c in name):
        return name
    return _LETTERS.sub(_recase_word, name)


def short_name(organization: str) -> str | None:
    """The vendor name to show for a registry organization name.

    Returns None for entries that name no vendor ("Private", blank, the IEEE
    itself). Company forms and trailing filler words are dropped, names in
    capitals are recased and well known vendors get one spelling each.
    """
    name = clean(organization)
    if name.lower().strip(_TRIM) in NOT_A_VENDOR:
        return None
    dba = _DBA.search(name)
    if dba and dba.group(1).strip():
        name = dba.group(1).strip()  # the brand people know
    alias = _alias(name)
    if alias:
        return alias
    name = _BRANCH.sub("", name)
    name = _CLAUSE.sub("", name)
    name = _GLUED.sub(". ", name)
    name = _drop_parens(name)
    name = _cut_after_form(name)
    name = _strip_forms(name.strip(_TRIM))
    name = _strip_leading(name).strip(_TRIM + _QUOTES)
    if not name:
        name = clean(organization)
    name = recase(name)
    if _INITIALS.search(name):
        name += "."  # "A.D.C." lost its last dot to the trimming above
    if len(name) > MAX_NAME:
        name = name[:MAX_NAME].rsplit(" ", 1)[0].rstrip(_TRIM)
    return name


def _download(url: str, agent: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": agent})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError(f"{url} is larger than {MAX_DOWNLOAD} bytes")
    return data


def fetch(url: str) -> bytes:
    """Download a registry file. Tries a browser-like User-Agent if the plain one is refused."""
    for agent in USER_AGENTS[:-1]:
        try:
            return _download(url, agent)
        except urllib.error.HTTPError as exc:
            if exc.code not in REFUSED:
                raise
    return _download(url, USER_AGENTS[-1])


def parse_registry(text: str, registry: Registry, stats: Counter[str]) -> Iterator[tuple[str, str]]:
    """Yield (prefix, organization name) for each usable row of a registry CSV."""
    reader = csv.DictReader(io.StringIO(text))
    missing = [c for c in COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        raise ValueError(f"{registry.name}: columns {missing} are missing; did the format change?")
    for row in reader:
        prefix = (row["Assignment"] or "").strip().upper()
        if len(prefix) != registry.digits or not re.fullmatch("[0-9A-F]+", prefix):
            stats["bad assignment"] += 1
            continue
        # Multicast and locally administered blocks never show up in a lookup.
        if int(prefix[:2], 16) & 0x03:
            stats["multicast or local"] += 1
            continue
        yield prefix, row["Organization Name"] or ""


def build(rows: Iterable[tuple[str, str]], stats: Counter[str]) -> dict[str, str]:
    """Shorten the names and drop entries without a vendor. The first entry for a prefix wins."""
    entries: dict[str, str] = {}
    names: dict[str, str | None] = {}
    for prefix, organization in rows:
        if organization not in names:
            names[organization] = short_name(organization)
        vendor = names[organization]
        if vendor is None:
            stats["no vendor"] += 1
        elif prefix in entries:
            stats["duplicate"] += 1
        else:
            entries[prefix] = vendor
    return entries


def render(entries: dict[str, str]) -> bytes:
    """Gzipped "PREFIX<TAB>Vendor" lines.

    No timestamp or file name goes into the gzip header, so the same entries give
    the same bytes. (A Python built on zlib-ng packs a little differently.)
    """
    text = "".join(f"{prefix}\t{entries[prefix]}\n" for prefix in sorted(entries))
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as gz:
        gz.write(text.encode("utf-8"))
    return buffer.getvalue()


def _read(registry: Registry, source: Path | None) -> str | None:
    if source is not None:
        path = source / registry.url.rsplit("/", 1)[1]
        if not path.exists() and not registry.required:
            print(f"{registry.name}: {path.name} not found, skipped")
            return None
        data = path.read_bytes()
    else:
        try:
            data = fetch(registry.url)
        except urllib.error.HTTPError as exc:
            if registry.required or exc.code not in (404, 410):
                raise
            print(f"{registry.name}: no longer published ({exc.code}), skipped")
            return None
    return data.decode("utf-8-sig", errors="replace")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", type=Path, help="read the CSV files from this directory")
    parser.add_argument("--output", type=Path, default=OUTPUT, help="where to write the table")
    args = parser.parse_args(argv)

    stats: Counter[str] = Counter()
    rows: list[tuple[str, str]] = []
    for registry in REGISTRIES:
        try:
            text = _read(registry, args.source)
            found = [] if text is None else list(parse_registry(text, registry, stats))
        except (OSError, ValueError, csv.Error) as exc:
            print(f"{registry.name}: {exc}", file=sys.stderr)
            return 1
        if text is not None:
            print(f"{registry.name}: {len(found)} assignments")
        rows.extend(found)

    entries = build(rows, stats)
    if not entries:
        print("nothing to write", file=sys.stderr)
        return 1
    data = render(entries)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    partial = args.output.with_name(args.output.name + ".part")
    partial.write_bytes(data)
    os.replace(partial, args.output)

    for reason, count in sorted(stats.items()):
        print(f"skipped ({reason}): {count}")
    lengths = Counter(len(prefix) for prefix in entries)
    print(
        f"wrote {len(entries)} prefixes ({lengths[6]} 24-bit, {lengths[7]} 28-bit, "
        f"{lengths[9]} 36-bit), {len(set(entries.values()))} vendors, {len(data)} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
