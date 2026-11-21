# PyInstaller spec for the single-file hearthscan binary.
#
# Build it from the repository root:
#
#   uv sync --locked --extra window
#   uv run --with pyinstaller==6.22.3 pyinstaller packaging/hearthscan.spec
#
# The binary lands in dist/ (hearthscan.exe on Windows). When pywebview is
# installed (the window extra) it goes into the binary and `hearthscan gui`
# opens a window of its own. The Linux builds leave it out, so there the gui
# command opens the web browser instead.

import importlib.util
import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
INIT = (ROOT / "src" / "hearthscan" / "__init__.py").read_text(encoding="utf-8")
VERSION = re.search(r"""^__version__ = ["']([^"']+)["']""", INIT, re.M).group(1)

# Most commands import their modules only when they run, and the language
# files, the vendor table and the window's web page are read through
# importlib.resources, so the whole package goes in.
hiddenimports = collect_submodules("hearthscan")
datas = collect_data_files("hearthscan")
binaries = []


def importable(name):
    return importlib.util.find_spec(name) is not None


def wanted(module):
    # The hook folders shipped by pywebview and pythonnet are for this build,
    # not for the program, and the Android backend cannot even be imported.
    return "pyinstaller" not in module and not module.startswith("webview.platforms.android")


# pywebview chooses its backend at run time, so it is collected whole, with
# the pieces that backend drives: .NET through pythonnet on Windows and Cocoa
# through PyObjC on macOS.
if importable("webview"):
    if sys.platform == "win32":
        pieces = ["webview", "clr_loader", "pythonnet"]
        hiddenimports.append("clr")
    elif sys.platform == "darwin":
        pieces = ["webview", "objc", "Foundation", "AppKit", "WebKit", "UniformTypeIdentifiers"]
        hiddenimports.append("PyObjCTools.AppHelper")
    else:
        pieces = ["webview"]
    for name in pieces:
        if not importable(name):
            continue
        # The DLLs under webview/lib are only of use on Windows.
        skip = ["lib"] if name == "webview" and sys.platform != "win32" else None
        found = collect_all(
            name, include_py_files=False, filter_submodules=wanted, exclude_datas=skip
        )
        datas += found[0]
        binaries += found[1]
        hiddenimports += found[2]


def windows_version():
    """The version resource Explorer shows under Properties > Details."""
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    release = [int(part) for part in re.match(r"\d+(?:\.\d+)*", VERSION).group(0).split(".")]
    numbers = tuple([*release, 0, 0, 0, 0][:4])
    texts = [
        StringStruct("FileDescription", "Hearthscan"),
        StringStruct("FileVersion", VERSION),
        StringStruct("InternalName", "hearthscan"),
        StringStruct("LegalCopyright", "MIT License"),
        StringStruct("OriginalFilename", "hearthscan.exe"),
        StringStruct("ProductName", "Hearthscan"),
        StringStruct("ProductVersion", VERSION),
    ]
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=numbers, prodvers=numbers),
        kids=[
            StringFileInfo([StringTable("040904B0", texts)]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )


a = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="hearthscan",
    console=True,
    upx=False,
    # Symbol tables only help a debugger. They are stripped on Linux alone:
    # Windows has no strip tool and on macOS the libraries carry signatures.
    strip=sys.platform.startswith("linux"),
    icon="NONE",
    version=windows_version() if sys.platform == "win32" else None,
)
