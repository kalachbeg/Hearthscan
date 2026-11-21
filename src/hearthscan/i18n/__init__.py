"""Texts in the languages Hearthscan speaks.

Each language is a flat JSON object next to this file, {"key": "text"}, with
{name} placeholders. English is complete; other languages fall back to it.
"""

from __future__ import annotations

import ctypes
import functools
import json
import locale
import os
import re
from importlib import resources

from .. import system

LANGUAGES = ("en", "tr")

# The language files are a few dozen kilobytes. Anything far beyond that is not ours.
MAX_FILE = 1024 * 1024

# Explicit choices, in the order gettext reads them. Each may hold a list such as "tr:en".
_ENV_VARS = ("HEARTHSCAN_LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")

# Windows locale names spell the language out ("Turkish_Turkey.1254").
_ALIASES = {"turkish": "tr", "tur": "tr", "english": "en", "eng": "en"}
_NO_LANGUAGE = frozenset({"c", "posix"})
_LANG_TURKISH = 0x1F

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

_current = "en"


def _language_code(tag: str) -> str | None:
    """Language of a locale tag: "tr_TR.UTF-8", "tr-TR" and "Turkish_Turkey" give "tr".

    None for "C", "POSIX" and anything else that names no language.
    """
    name = re.split(r"[_.@-]", tag.strip(), maxsplit=1)[0].lower()
    name = _ALIASES.get(name, name)
    if name in _NO_LANGUAGE or not re.fullmatch(r"[a-z]{2,3}", name):
        return None
    return name


def _from_list(value: str) -> str | None:
    """The first language of "de:tr:en" that we have, else the first one named."""
    named = None
    for entry in value.split(":"):
        code = _language_code(entry)
        if code in LANGUAGES:
            return code
        named = named or code
    return named


def _locale_is_turkish() -> bool:
    try:
        name = locale.getlocale()[0]
    except (ValueError, TypeError):
        return False
    return _language_code(name or "") == "tr"


def _windows_language() -> str | None:
    """The Windows display language as "tr" or "en", None when it cannot be read."""
    if not system.IS_WINDOWS:
        return None
    try:
        get_language = ctypes.WinDLL("kernel32").GetUserDefaultUILanguage
        get_language.argtypes = ()
        get_language.restype = ctypes.c_ushort
        langid = int(get_language())
    except (OSError, AttributeError, TypeError, ValueError):
        return None
    return "tr" if langid & 0x3FF == _LANG_TURKISH else "en"


def _macos_is_turkish() -> bool:
    if not system.IS_MACOS:
        return False
    output = system.run(["/usr/bin/defaults", "read", "-g", "AppleLanguages"], timeout=3.0)
    # (\n    "tr-TR",\n    "en-US"\n)
    first = output[:4096].strip().strip("()").split(",")[0]
    return _language_code(first.strip().strip('"')) == "tr"


def detect() -> str:
    """Return "tr" when the user's language is Turkish, else "en". Never raises.

    The environment variables are an explicit choice and decide either way.
    On Windows the display language decides next, either way: the locale there
    is the region format, and plenty of people in Turkey run English Windows
    with Turkish formats. Elsewhere the locale and the macOS language list
    only count when they say Turkish.
    """
    for var in _ENV_VARS:
        code = _from_list(os.environ.get(var, ""))
        if code:
            return "tr" if code == "tr" else "en"
    windows = _windows_language()
    if windows is not None:
        return windows
    for is_turkish in (_locale_is_turkish, _macos_is_turkish):
        if is_turkish():
            return "tr"
    return "en"


def set_language(code: str | None) -> str:
    """Switch to `code`, or to the user's language for None. Returns the language in use."""
    global _current
    if code is None:
        _current = detect()
    else:
        found = _language_code(code)
        _current = found if found in LANGUAGES else "en"
    return _current


def language() -> str:
    """The language in use. English until set_language() is called."""
    return _current


def _parse(raw: bytes) -> dict[str, str]:
    if len(raw) > MAX_FILE:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}


@functools.cache
def _texts(code: str) -> dict[str, str]:
    try:
        with (resources.files(__name__) / f"{code}.json").open("rb") as file:
            raw = file.read(MAX_FILE + 1)
    except OSError:
        return {}
    return _parse(raw)


def _fill(text: str, params: dict[str, object]) -> str:
    # One pass over the text, so braces inside the values are never read as placeholders.
    def value(match: re.Match[str]) -> str:
        name = match.group(1)
        return str(params[name]) if name in params else match.group(0)

    return _PLACEHOLDER.sub(value, text) if params else text


def t(key: str, /, **params: object) -> str:
    """The text for `key` with its {placeholders} filled in.

    Falls back to English and then to the key itself. A placeholder without a
    value is left as it is.
    """
    text = _texts(_current).get(key)
    if text is None:
        text = _texts("en").get(key)
    if text is None:
        return key
    return _fill(text, params)


def table(code: str) -> dict[str, str]:
    """Every English key with its text in language `code`, English where it has none."""
    english = _texts("en")
    chosen = _texts(code) if code in LANGUAGES else {}
    return {key: chosen.get(key, text) for key, text in english.items()}


def has(key: str) -> bool:
    """True when `key` has a text in the current language or in English."""
    return key in _texts(_current) or key in _texts("en")
