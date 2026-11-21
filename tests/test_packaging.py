"""The release files have to agree with each other.

The workflow builds the assets the launchers download, the launchers check
the SHA-256 of what they download before running it and leave nothing behind
outside their temporary folder, and the PyInstaller spec takes the package
data along. These are checks on the text of the files, so they run anywhere.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "hearthscan"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
RUN_SH = ROOT / "launch" / "run.sh"
RUN_PS1 = ROOT / "launch" / "run.ps1"
SPEC = ROOT / "packaging" / "hearthscan.spec"
ENTRY = ROOT / "packaging" / "entry.py"

# What every GitHub release carries besides SHA256SUMS. The README promises these names.
ASSETS = {
    "hearthscan-windows-x64.exe",
    "hearthscan-macos-arm64",
    "hearthscan-macos-x64",
    "hearthscan-linux-x64",
    "hearthscan-linux-arm64",
}

REPO = "https://github.com/kalachbeg/Hearthscan"
RAW = "https://raw.githubusercontent.com/kalachbeg/Hearthscan/main/launch"
FROM_SOURCE = f"uvx --from git+{REPO} hearthscan"

# Modules the commands import only when they run.
LAZY_MODULES = ("audit", "discovery", "gui", "store", "watch", "report", "diff", "router")
DATA_FILES = (
    "i18n/en.json",
    "i18n/tr.json",
    "data/oui.tsv.gz",
    "gui/web/index.html",
    "gui/web/app.js",
    "gui/web/styles.css",
)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code_lines(text: str) -> str:
    """The text without its comment lines."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def matrix() -> dict[str, dict[str, str]]:
    """The build matrix of the workflow: asset name to its os and extras."""
    rows = re.findall(
        r"^\s*- os: (\S+)\n\s+asset: (\S+)\n\s+extras: (.*)$", read(WORKFLOW), re.MULTILINE
    )
    return {asset: {"os": os, "extras": extras.strip().strip('"')} for os, asset, extras in rows}


# The workflow


def test_workflow_builds_every_asset():
    built = matrix()
    assert set(built) == ASSETS
    names = re.findall(r"^\s*asset: (\S+)$", read(WORKFLOW), re.MULTILINE)
    assert len(names) == len(set(names))


def test_workflow_runners_and_extras():
    built = matrix()
    assert built["hearthscan-linux-arm64"]["os"] == "ubuntu-24.04-arm"
    assert built["hearthscan-windows-x64.exe"]["os"].startswith("windows-")
    assert built["hearthscan-macos-x64"]["os"].endswith("-intel")
    for asset, row in built.items():
        # The window extra goes into the Windows and macOS builds only.
        window = row["extras"] == "--extra window"
        assert window == ("-linux-" not in asset), asset


def test_workflow_triggers_and_permissions():
    text = read(WORKFLOW)
    assert re.search(r'^  push:\n    tags: \["v\*"\]$', text, re.MULTILINE)
    assert re.search(r"^  workflow_dispatch:", text, re.MULTILINE)
    assert re.search(r"^permissions:\n  contents: read$", text, re.MULTILINE)
    jobs = jobs_of(text)
    assert "contents: write" in jobs["release"]
    assert "contents: write" not in jobs["build"] + jobs["pypi"]
    # Only a pushed tag publishes anything; a manual run only builds.
    for name in ("release", "pypi"):
        assert "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" in jobs[name]
    assert "vars.PUBLISH_PYPI == 'true'" in jobs["pypi"]
    assert "environment: pypi" in jobs["pypi"]
    assert "id-token: write" in jobs["pypi"]
    assert "pypa/gh-action-pypi-publish@" in jobs["pypi"]
    assert "password:" not in jobs["pypi"]


def jobs_of(text: str) -> dict[str, str]:
    parts = re.split(r"^  ([a-z][a-z0-9_-]*):\n", text.split("\njobs:\n", 1)[1], flags=re.M)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def test_workflow_release_job():
    release = jobs_of(read(WORKFLOW))["release"]
    assert "pattern: hearthscan-*" in release
    assert "merge-multiple: true" in release
    # sha256sum on Linux writes "<hash>  <name>", the format both launchers read.
    assert "sha256sum hearthscan-* > SHA256SUMS" in release
    assert "src/hearthscan/__init__.py" in release
    assert '"v$version" != "$GITHUB_REF_NAME"' in release
    assert '"## [" version "]"' in release
    assert "CHANGELOG.md" in release
    assert 'gh release create "$GITHUB_REF_NAME" assets/*' in release


def test_workflow_smoke_tests_every_binary():
    build = jobs_of(read(WORKFLOW))["build"]
    for command in ("--version", "--help", "scan --help", "net --json"):
        assert f'"$bin" {command}' in build


def test_workflow_pins():
    text = read(WORKFLOW)
    for action in re.findall(r"uses: (\S+)", text):
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@v\d+(\.\d+){0,2}", action), action
    # setup-uv publishes full version tags only.
    assert re.findall(r"astral-sh/setup-uv@(\S+)", text)
    for tag in re.findall(r"astral-sh/setup-uv@(\S+)", text):
        assert re.fullmatch(r"v\d+\.\d+\.\d+", tag)
    command = r"--with pyinstaller==(\d+\.\d+\.\d+) pyinstaller packaging/hearthscan\.spec"
    pinned = re.findall(command, text)
    assert pinned
    # The build command written at the top of the spec uses the same release.
    assert set(re.findall(command, read(SPEC))) == set(pinned)
    assert "uv sync --locked" in text


# The launchers


def sh_assets() -> set[str]:
    """Every asset name run.sh can ask for."""
    text = code_lines(read(RUN_SH))
    assert 'asset="hearthscan-$os-$arch"' in text
    systems = set(re.findall(r"\bos=(\w+)", text))
    machines = set(re.findall(r"\barch=(\w+)", text))
    return {f"hearthscan-{os}-{arch}" for os in systems for arch in machines}


def ps1_assets() -> set[str]:
    return set(re.findall(r"\$asset = '([^']+)'", read(RUN_PS1)))


def test_launchers_ask_for_the_built_assets():
    assert sh_assets() == {asset for asset in ASSETS if not asset.endswith(".exe")}
    # Windows on ARM runs the x64 build as well.
    assert ps1_assets() == {"hearthscan-windows-x64.exe"}
    assert sh_assets() | ps1_assets() == set(matrix())


@pytest.mark.parametrize("path", [RUN_SH, RUN_PS1], ids=["run.sh", "run.ps1"])
def test_launcher_download_addresses(path):
    text = read(path)
    assert re.search(rf"""^\s*\$?(REPO|repo) ?= ?["']{REPO}["']$""", text, re.MULTILINE)
    text = text.replace("$REPO", REPO).replace("$repo", REPO)
    assert f'"{REPO}/releases/latest/download"' in text
    assert f'"{REPO}/releases/download/v$version"' in text
    assert "/SHA256SUMS" in text
    assert "HEARTHSCAN_VERSION" in text
    assert "HEARTHSCAN_DOWNLOAD_BASE" in text
    # What to do when there is no release yet.
    assert f'"{FROM_SOURCE}"' in text


def test_launchers_document_the_one_liners():
    sh, ps1 = read(RUN_SH), read(RUN_PS1)
    assert f"curl -fsSL {RAW}/run.sh | sh\n" in sh
    assert f"curl -fsSL {RAW}/run.sh | sh -s -- scan --lang tr\n" in sh
    assert f"irm {RAW}/run.ps1 | iex\n" in ps1
    assert f"& ([scriptblock]::Create((irm {RAW}/run.ps1))) scan --lang tr\n" in ps1


@pytest.mark.parametrize("path", [RUN_SH, RUN_PS1], ids=["run.sh", "run.ps1"])
def test_launchers_are_plain_ascii(path):
    # Windows PowerShell reads a script without a byte order mark in the ANSI
    # code page, and sh breaks on carriage returns.
    raw = path.read_bytes()
    assert raw.isascii()
    if path.suffix == ".sh":
        assert b"\r" not in raw


def test_run_sh_is_posix_sh():
    text = read(RUN_SH)
    assert text.startswith("#!/bin/sh\n")
    code = code_lines(text)
    bashisms = {
        "[[ test": r"\[\[",
        "function keyword": r"^\s*function\s+\w+",
        "array": r"\w+=\(|\$\{\w+\[",
        "source": r"^\s*source\s",
        "here string": r"<<<",
        "process substitution": r"[<>]\(",
        "&> redirect": r"&>",
        "$'...' quoting": r"\$'",
        "== in a test": r"\[\s[^\]\n]*\s==\s",
        "pipefail": r"pipefail",
        "case change": r"\$\{\w+(,,|\^\^)",
        "substring": r"\$\{\w+:\d",
    }
    for name, pattern in bashisms.items():
        assert not re.search(pattern, code, re.MULTILINE), name


def test_run_sh_checks_the_checksum_before_running():
    code = code_lines(read(RUN_SH))
    missing = code.index('if [ -z "$expected" ]; then')
    compare = code.index('if [ "$actual" != "$expected" ]; then')
    assert code[missing:].split("\n", 2)[1].strip().startswith(("say", "fail"))
    assert code[compare:].split("\n", 2)[1].strip().startswith("fail")
    runs = [match.start() for match in re.finditer(r'"\$tmp/\$asset" "\$@"', code)]
    assert runs
    assert all(missing < compare < run for run in runs)
    assert code.index("chmod +x") > compare


def test_run_ps1_checks_the_checksum_before_running():
    code = code_lines(read(RUN_PS1))
    assert "Get-FileHash -LiteralPath $exe -Algorithm SHA256" in code
    assert re.search(r"if \(-not \$expected\) \{[^}]*return \$null", code)
    assert re.search(r"if \(\$actual -cne \$expected\) \{[^}]*return \$null", code)
    assert code.index("$actual -cne $expected") < code.index("return $exe")
    # The program only ever runs as what Get-Hearthscan returned, after the check.
    assert code.count("& $exe @args") == 1
    assert re.search(r"\$exe = Get-Hearthscan \$tmp\s+if \(\$exe\) \{", code)
    assert code.index("$exe = Get-Hearthscan $tmp") < code.index("& $exe @args")


def test_run_sh_stays_in_its_temp_folder():
    code = code_lines(read(RUN_SH))
    assert re.search(r'tmp=\$\(mktemp -d "[^"]+"\)', code)
    # Downloads only land in the temporary folder.
    for target in re.findall(r"^\s*fetch \S+ (\S+)$", code, re.MULTILINE):
        assert target.startswith('"$tmp/'), target
    assert '-o "$2"' in code
    assert '-O "$2"' in code
    # Output only ever goes to the terminal or to /dev/null.
    for target in re.findall(r"(?<![<>&\d])\d?>>?\s*([^&\s][^\s;|)]*)", code):
        assert target == "/dev/null", target
    assert not re.search(r"\b(mkdir|cp|mv|tee|touch|ln|dd|install)\s", code)
    assert re.findall(r"\brm\s.*", code) == ['rm -rf "$tmp"']
    changed = re.findall(r"\bchmod \S+ (\S+)", code)
    assert changed
    assert all(path.startswith('"$tmp/') for path in changed)
    # GNU wget would keep ~/.wget-hsts otherwise.
    assert "--no-hsts" in code


def test_run_ps1_stays_in_its_temp_folder():
    code = code_lines(read(RUN_PS1))
    assert "Join-Path ([IO.Path]::GetTempPath())" in code
    assert code.count("-OutFile") == 1
    for target in re.findall(r"Save-Download \S+ (\$\w+)", code):
        assert target in ("$sums", "$exe")
    assert "$sums = Join-Path $Folder 'SHA256SUMS'" in code
    assert "$exe = Join-Path $Folder $asset" in code
    assert "$exe = Get-Hearthscan $tmp" in code
    writers = (
        "Set-Content",
        "Add-Content",
        "Out-File",
        "New-Item",
        "Copy-Item",
        "Move-Item",
        "Set-ItemProperty",
        "Set-ExecutionPolicy",
        "SetEnvironmentVariable",
        "[IO.File]::Write",
        "Start-Transcript",
    )
    for writer in writers:
        assert writer not in code, writer
    assert not re.search(r"\s>>?\s", code)
    # What the script changes for the program's sake, it puts back.
    for setting in ("$env:TEMP = $savedTemp", "$env:TMP = $savedTmp"):
        assert setting in code
    assert "[Net.ServicePointManager]::SecurityProtocol = $savedProtocols" in code


def test_launchers_clean_up_on_every_exit():
    sh = code_lines(read(RUN_SH))
    for trap in ("trap cleanup EXIT", "trap 'exit 130' INT", "trap 'exit 143' TERM"):
        assert trap in sh
    assert sh.index("trap cleanup EXIT") < sh.index("tmp=$(mktemp -d")
    ps1 = code_lines(read(RUN_PS1))
    finally_block = ps1.split("} finally {", 1)[1]
    assert "Remove-TempFolder $tmp" in finally_block.split("\n    }", 1)[0]
    assert "$global:LASTEXITCODE = $exitCode" in ps1


def test_run_ps1_keeps_the_execution_policy_and_session():
    text = read(RUN_PS1)
    assert "ExecutionPolicy" not in code_lines(text)
    # Everything runs inside one script block, so nothing leaks into the session.
    body = [line for line in code_lines(text).splitlines() if line.strip()]
    assert body[0] == "& {"
    assert body[-1] == "} @args"
    assert "Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing" in text
    assert "[Net.SecurityProtocolType]::Tls12" in text


# The PyInstaller spec


def test_spec_collects_the_package():
    spec = read(SPEC)
    assert 'collect_submodules("hearthscan")' in spec
    assert 'datas = collect_data_files("hearthscan")' in spec
    for module in LAZY_MODULES:
        assert (PACKAGE / f"{module}.py").is_file() or (PACKAGE / module / "__init__.py").is_file()
    for name in DATA_FILES:
        assert (PACKAGE / name).is_file(), name


def test_spec_builds_one_console_file():
    spec = read(SPEC)
    assert "COLLECT(" not in spec
    assert re.search(r"EXE\(\s*pyz,\s*a\.scripts,\s*a\.binaries,\s*a\.datas,", spec)
    assert 'name="hearthscan"' in spec
    assert "console=True" in spec
    assert "upx=False" in spec
    assert 'str(ROOT / "packaging" / "entry.py")' in spec


def test_spec_takes_pywebview_along_when_installed():
    spec = read(SPEC)
    assert 'if importable("webview"):' in spec
    assert '"webview", "clr_loader", "pythonnet"' in spec
    assert re.search(r"collect_all\(\s*name,", spec)


def test_entry_script():
    lines = [line for line in read(ENTRY).splitlines() if line and not line.startswith("#")]
    assert lines == ["from hearthscan.cli import main", "raise SystemExit(main())"]


def test_ps1_does_not_stop_on_the_programs_stderr():
    # Progress and notes go to stderr; Windows PowerShell 5.1 would turn them
    # into terminating errors under ErrorActionPreference 'Stop'.
    text = read(RUN_PS1)
    start = text.index("& $exe @args")
    before = text[:start]
    assert before.rstrip().endswith("$ErrorActionPreference = 'Continue'")
