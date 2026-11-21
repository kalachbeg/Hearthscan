"""The command line: a small menu when started bare, or straight to a command."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import math
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path

from rich import box
from rich.console import Console, RenderableType
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    Task,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from . import __version__, diff, i18n, render, scoring, serialize
from .i18n import t
from .models import SEVERITIES, Device, Finding, RouterInfo, ScanResult
from .netinfo import NetworkInfo, local_network
from .ports import HOME_PORTS, SERVICE_NAMES, PortResult, PortState, parse_ports, scan
from .report import format_time, html_report
from .runner import run
from .scope import ScopeError, expand
from .system import IS_WINDOWS

EXIT_OK = 0
EXIT_NO_NETWORK = 1
EXIT_USAGE = 2
EXIT_FINDINGS = 3  # --fail-on matched something
EXIT_STOPPED = 130

MAX_TIMEOUT = 60.0

# Saved results are a few hundred kilobytes. Anything far beyond that is not one.
MAX_RESULT_FILE = 64 * 1024 * 1024

HTML_SUFFIXES = (".html", ".htm")

_EXIT_CODES = """exit status:
  0    done
  1    no local network found
  2    bad arguments, or a file could not be read or saved
  3    --fail-on found something that serious
  130  stopped with Ctrl+C"""


class _Abort(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or not 0 < value <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"must be between 0 and {MAX_TIMEOUT:.0f} seconds")
    return value


def _minutes(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or not 0.5 <= value <= 24 * 60:
        raise argparse.ArgumentTypeError("must be between 0.5 and 1440 minutes")
    return value


def _port_spec(text: str) -> list[int]:
    try:
        return parse_ports(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


class _Count(ProgressColumn):
    """ "12/40" where there is a count, nothing where there is none."""

    def render(self, task: Task) -> Text:
        if task.total is None:
            return Text("")
        return Text(f"{int(task.completed)}/{int(task.total)}", style="progress.download")


class _Stages:
    """Shows audit progress as a spinner per stage and a bar where there is a count."""

    def __init__(self, progress: Progress) -> None:
        self.progress = progress
        self.task: TaskID | None = None
        self.stage = ""

    def __call__(self, stage: str, done: int, total: int) -> None:
        if stage != self.stage:
            self.stage = stage
            if self.task is not None:
                self.progress.remove_task(self.task)
                self.task = None
            if stage == "done":
                return
            self.task = self.progress.add_task(t(f"ui.stage.{stage}"), total=total or None)
        if self.task is not None:
            self.progress.update(self.task, completed=done, total=total or None)


def _spinner() -> str:
    # The old Windows console host has no braille glyphs; Windows Terminal does.
    if IS_WINDOWS and not (os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM")):
        return "line"
    return "dots"


def _writable(path: Path) -> str | None:
    """Why `path` cannot take the result, or None when it looks fine."""
    if not str(path).strip():
        return "empty path"
    if path.is_dir():
        return "it is a folder"
    if not path.parent.is_dir():
        return f"folder {path.parent} does not exist"
    return None


def _same_file(a: Path, b: Path) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def _where(finding: Finding, result: ScanResult) -> str:
    where = render.device_label(result.device(finding.ip), finding.ip)
    if finding.port:
        where = t("ui.finding.where", device=where, port=finding.port)
    return where


def diff_view(changes: diff.Diff, old: ScanResult, new: ScanResult) -> list[RenderableType]:
    """What `hearthscan diff` shows: the score, then the findings and devices that came and went."""
    period = t("diff.period", before=format_time(old.started), after=format_time(new.started))
    parts: list[RenderableType] = [Text(t("diff.title"), style="bold"), Text(period, style="dim")]

    before, after = changes.score_before, changes.score_after
    band_style = render.BAND_STYLES[scoring.band(after)]
    score = Text(t("ui.score.title") + "  ", style="bold")
    if before == after:
        score.append(str(after), style=f"bold {band_style}")
        score.append(f" / 100  ({t('diff.score_same')})", style="dim")
    else:
        score.append(f"{before} → ")
        score.append(str(after), style=f"bold {band_style}")
        score.append(f"  ({after - before:+d})", style="green" if after > before else "red")
    parts += [Text(), score, Text()]

    findings = [
        ("diff.new_findings", changes.new_findings, new),
        ("diff.fixed_findings", changes.fixed_findings, old),
    ]
    devices = [
        ("diff.new_devices", changes.new_devices),
        ("diff.gone_devices", changes.gone_devices),
    ]
    if not any(found for _, found, _ in findings) and not any(listed for _, listed in devices):
        parts.append(Text(t("diff.none"), style="green"))
        return parts
    for key, found, result in findings:
        if not found:
            continue
        parts.append(Text(t(key, count=len(found)), style="bold"))
        for finding in found:
            line = Text.assemble("  ", render.severity_badge(finding.severity), "  ")
            line.append(t(f"rule.{finding.rule}.title"))
            line.append(f"  {_where(finding, result)}", style="dim")
            parts.append(line)
        parts.append(Text())
    for key, listed in devices:
        if not listed:
            continue
        parts.append(Text(t(key, count=len(listed)), style="bold"))
        for device in listed:
            line = Text("  • " + render.device_label(device, device.ip))
            if made_by := render.maker(device):
                line.append(f"  {made_by}", style="dim")
            parts.append(line)
        parts.append(Text())
    return parts


_CHANGE_STYLES = {"new": "bold yellow", "back": "green", "gone": "dim", "finding": "bold red"}


def _change_line(change) -> Text:
    label = t(f"watch.change.{change.kind}")
    line = Text.assemble("  ", (f" {label} ", _CHANGE_STYLES.get(change.kind, "")), "  ")
    if change.finding is not None:
        finding = change.finding
        line.append(t(f"rule.{finding.rule}.title"), style="bold")
        where = render.device_label(change.device, finding.ip)
        if finding.port:
            where = t("ui.finding.where", device=where, port=finding.port)
        line.append(f"  {where}", style="dim")
        return line
    device = change.device
    if device is not None:
        line.append(render.device_label(device, device.ip))
        made = render.maker(device)
        if made:
            line.append(f"  {made}", style="dim")
    elif change.known is not None:
        line.append(change.known.name or change.known.last_ip or change.known.key)
    return line


def _known_table(records, width: int | None = None) -> Table:
    wide = width is None or width >= 110
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    table.add_column(t("ui.col.name"), min_width=12, max_width=30)
    table.add_column(t("known.col.last_ip"), no_wrap=True)
    if wide:
        table.add_column(t("ui.col.maker"), min_width=8, max_width=24)
    table.add_column(t("ui.col.kind"), min_width=12)
    if wide:
        table.add_column(t("known.col.first_seen"), no_wrap=True)
    table.add_column(t("known.col.last_seen"), no_wrap=True)
    table.add_column(t("known.col.trusted"), justify="center", no_wrap=True)
    # Devices nobody has vouched for come first: those are the ones to look at.
    for record in sorted(records, key=lambda r: (r.trusted, r.last_seen)):
        style = "" if record.trusted else "yellow"
        row = [
            Text(record.name or "", style=style),
            Text(record.last_ip or ""),
        ]
        if wide:
            row.append(Text(record.vendor or ""))
        row.append(Text(t(f"kind.{record.kind}") if record.kind else ""))
        if wide:
            row.append(Text(format_time(record.first_seen)))
        row += [Text(format_time(record.last_seen)), Text("\u2713" if record.trusted else "")]
        table.add_row(*row)
    return table


class App:
    def __init__(self, out: Console | None = None, err: Console | None = None) -> None:
        self.out = out or Console(highlight=False)
        self.err = err or Console(stderr=True, highlight=False)

    def note(self, source: str, message: str) -> None:
        self.err.print(Text(f"{t('ui.note')}: {message}", style="yellow"))

    def error(self, message: str) -> None:
        self.err.print(Text(f"{t('ui.error')}: {message}", style="red"))

    def network(self) -> NetworkInfo:
        info = local_network()
        if info is None:
            self.err.print(Text(t("ui.no_network"), style="red"))
            raise _Abort(EXIT_NO_NETWORK)
        if info.sandbox:
            self.note("sandbox", t(f"ui.sandbox.{info.sandbox}"))
        return info

    def _progress(self) -> Progress:
        return Progress(
            SpinnerColumn(_spinner()),
            TextColumn("{task.description}"),
            BarColumn(),
            _Count(),
            TimeElapsedColumn(),
            console=self.err,
            transient=True,
        )

    def _run(self, job):
        try:
            return run(job)
        except KeyboardInterrupt:
            self.err.print(Text(t("ui.stopped"), style="yellow"))
            raise _Abort(EXIT_STOPPED) from None

    def _load(self, path: Path) -> ScanResult:
        """A result saved with `scan -o` or `scan --json`. Stops with status 2 on anything else."""
        if path.is_dir():
            self.error(t("report.error.read", path=str(path), reason="it is a folder"))
            raise _Abort(EXIT_USAGE)
        try:
            with path.open("rb") as file:
                raw = file.read(MAX_RESULT_FILE + 1)
        except OSError as exc:
            self.error(t("report.error.read", path=str(path), reason=exc.strerror or exc))
            raise _Abort(EXIT_USAGE) from None
        try:
            if len(raw) > MAX_RESULT_FILE:
                raise ValueError("the file is far too large")
            # Some Windows editors put a byte order mark in front.
            return serialize.loads(raw.decode("utf-8-sig"))
        except UnicodeDecodeError:
            reason = "not UTF-8 text"
        except ValueError as exc:
            reason = str(exc)
        self.error(t("report.error.not_result", path=str(path), reason=reason))
        raise _Abort(EXIT_USAGE)

    def _save(self, path: Path, text: str) -> bool:
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            self.error(t("ui.save_failed", path=str(path), reason=exc.strerror or exc))
            return False
        return True

    # Commands

    def show_network(self, *, as_json: bool = False) -> int:
        info = self.network()
        if as_json:
            data = {
                "interface": info.interface.label,
                "address": str(info.address),
                "network": str(info.network),
                "scan_network": str(info.scan_network()),
                "gateway": info.gateway,
                "sandbox": info.sandbox,
            }
            print(json.dumps(data, indent=2))
            return EXIT_OK
        self.out.print(render.network_details(info))
        return EXIT_OK

    def list_devices(self, *, as_json: bool = False) -> int:
        from .discovery import discover

        info = self.network()
        with self._progress() as progress:
            progress.add_task(t("ui.stage.discover"), total=None)
            devices = self._run(discover(info, on_note=self.note))
        if as_json:
            print(json.dumps({"devices": serialize.devices_to_list(devices)}, indent=2))
            return EXIT_OK
        self.out.print(Text(t("ui.devices.title"), style="bold"))
        self.out.print(render.devices_table(devices, with_ports=False, width=self.out.width))
        self.out.print(Text(t("ui.summary.devices", count=len(devices)), style="dim"))
        return EXIT_OK

    def show_router(self, *, as_json: bool = False) -> int:
        from . import discovery, router

        info = self.network()

        async def ask(stages: _Stages) -> tuple[list[Device], RouterInfo | None]:
            stages("discover", 0, 0)
            devices = await discovery.discover(info, on_note=self.note)
            gateway = next((d for d in devices if d.is_gateway), None)
            if gateway is None or router.wan_service(gateway) is None:
                return devices, None
            stages("router", 0, 0)
            return devices, await router.query(gateway)

        with self._progress() as progress:
            devices, found = self._run(ask(_Stages(progress)))
        if as_json:
            data = None if found is None else dataclasses.asdict(found)
            print(json.dumps({"router": data}, indent=2))
            return EXIT_OK
        if found is None:
            self.out.print(Text(t("ui.router.no_upnp")))
            return EXIT_OK
        self.out.print(Text(t("ui.router.title"), style="bold"))
        for part in render.router_view(found, devices, self.out.width):
            self.out.print(part)
        return EXIT_OK

    def full_scan(
        self,
        *,
        ports: Sequence[int] = HOME_PORTS,
        timeout: float = 1.0,
        probe: bool = True,
        as_json: bool = False,
        output: Path | None = None,
        fail_on: str | None = None,
    ) -> int:
        from .audit import audit

        # A typo in -o should cost a second, not a whole scan.
        if output is not None and (problem := _writable(output)):
            self.error(t("ui.save_failed", path=str(output), reason=problem))
            return EXIT_USAGE

        info = self.network()
        started = time.monotonic()
        with self._progress() as progress:
            result: ScanResult = self._run(
                audit(
                    info,
                    ports=ports,
                    timeout=timeout,
                    probe=probe,
                    on_progress=_Stages(progress),
                    on_note=self.note,
                )
            )
        elapsed = time.monotonic() - started
        if as_json:
            print(serialize.dumps(result))
        else:
            view = render.result_view(
                result, elapsed, probed=probe, notes=False, width=self.out.width
            )
            for part in view:
                self.out.print(part)

        code = EXIT_OK
        if fail_on is not None:
            limit = SEVERITIES.index(fail_on)
            if any(SEVERITIES.index(f.severity) <= limit for f in result.findings):
                code = EXIT_FINDINGS
        if output is not None:
            if output.suffix.lower() in HTML_SUFFIXES:
                text = html_report(result)
            else:
                text = serialize.dumps(result)
            if not self._save(output, text):
                return EXIT_USAGE
            # soft_wrap: a long path stays on one line, so it can be copied.
            self.err.print(Text(t("ui.saved", path=str(output)), style="dim"), soft_wrap=True)
        return code

    def save_report(self, source: Path, output: Path | None = None) -> int:
        """Turn a saved result into an HTML report, by default next to it."""
        result = self._load(source)
        target = source.with_suffix(".html") if output is None else output
        problem = _writable(target)
        if problem is None and _same_file(target, source):
            problem = "it is the result being read"
        if problem:
            self.error(t("ui.save_failed", path=str(target), reason=problem))
            return EXIT_USAGE
        if not self._save(target, html_report(result)):
            return EXIT_USAGE
        self.out.print(Text(t("report.saved", path=str(target))), soft_wrap=True)
        return EXIT_OK

    def compare_scans(self, old_path: Path, new_path: Path, *, as_json: bool = False) -> int:
        """Show what changed between two saved results."""
        old, new = self._load(old_path), self._load(new_path)
        if old.network != new.network:
            self.note("diff", t("diff.other_network", before=old.network, after=new.network))
        changes = diff.compare(old, new)
        if as_json:
            print(json.dumps(diff.to_dict(changes), indent=2))
            return EXIT_OK
        for part in diff_view(changes, old, new):
            self.out.print(part)
        return EXIT_OK

    def watch_network(self, *, every: float = 300.0, full: bool = False) -> int:
        from . import store as known_store
        from . import watch as watcher

        info = self.network()
        try:
            known = known_store.KnownDevices.load()
        except OSError as exc:
            path = str(known_store.default_path())
            self.error(t("watch.store_failed", path=path, reason=exc.strerror or exc))
            return EXIT_USAGE
        if known.broken is not None:
            self.note("store", t("watch.store_broken", path=str(known.broken)))
        learning = len(known) == 0
        minutes = f"{every / 60:g}"
        self.out.print(Text(t("watch.start", network=str(info.scan_network()), minutes=minutes)))
        self.out.print(Text(t("watch.stop_hint"), style="dim"))
        if learning:
            self.out.print(Text(t("watch.learning"), style="dim"))

        def show(found: watcher.Round) -> None:
            nonlocal learning
            stamp = format_time(found.finished)
            header = Text.assemble(
                (stamp, "bold"), "  ", t("watch.round", count=len(found.devices))
            )
            self.out.print(header)
            if learning:
                learning = False
                new = sum(1 for change in found.changes if change.kind == "new")
                self.out.print(Text("  " + t("watch.learned", count=new), style="green"))
                return
            if not found.changes:
                self.out.print(Text("  " + t("watch.quiet"), style="dim"))
                return
            for change in found.changes:
                self.out.print(_change_line(change))
            if any(change.kind == "new" for change in found.changes):
                self.out.bell()

        def wait(seconds: float) -> None:
            seconds = max(seconds, 0)
            if seconds < 90:
                text = t("watch.next_seconds", seconds=f"{seconds:.0f}")
            else:
                text = t("watch.next", minutes=f"{seconds / 60:.0f}")
            self.out.print(Text("  " + text, style="dim"))

        try:
            run(
                watcher.watch(
                    info,
                    known,
                    every=every,
                    full=full,
                    on_round=show,
                    on_wait=wait,
                    on_note=self.note,
                )
            )
        except KeyboardInterrupt:
            self.err.print(Text(t("ui.stopped"), style="yellow"))
            return EXIT_STOPPED
        return EXIT_OK

    def known_devices(
        self,
        *,
        trust: str | None = None,
        untrust: str | None = None,
        forget: str | None = None,
        clear: bool = False,
        as_json: bool = False,
    ) -> int:
        from . import store as known_store

        try:
            known = known_store.KnownDevices.load()
        except OSError as exc:
            path = str(known_store.default_path())
            self.error(t("watch.store_failed", path=path, reason=exc.strerror or exc))
            return EXIT_USAGE
        if known.broken is not None:
            self.note("store", t("watch.store_broken", path=str(known.broken)))

        changes = [(trust, "trust"), (untrust, "untrust"), (forget, "forget")]
        for what, action in changes:
            if what is None:
                continue
            record = known.find(what)
            if record is None:
                self.error(t("known.not_found", what=what))
                return EXIT_USAGE
            if action == "trust":
                known.trust(record.key)
                message = "known.trusted"
            elif action == "untrust":
                known.trust(record.key, trusted=False)
                message = "known.untrusted"
            else:
                known.forget(record.key)
                message = "known.forgotten"
            known.save()
            self.out.print(Text(t(message, what=record.name or record.last_ip or record.key)))
            return EXIT_OK
        if clear:
            known.clear()
            known.save()
            self.out.print(Text(t("known.cleared")))
            return EXIT_OK

        if as_json:
            data = {"known": [dataclasses.asdict(record) for record in known.records]}
            print(json.dumps(data, indent=2))
            return EXIT_OK
        if not len(known):
            self.out.print(Text(t("known.none")))
            return EXIT_OK
        self.out.print(Text(t("known.title"), style="bold"))
        self.out.print(_known_table(known.records, width=self.out.width))
        self.out.print(Text(t("known.path", path=str(known_store.default_path())), style="dim"))
        return EXIT_OK

    def scan_ports(self, targets: str, ports: Sequence[int] | None, timeout: float) -> int:
        def show(result: PortResult) -> None:
            name = SERVICE_NAMES.get(result.port, "")
            line = f"{result.host:<16} {result.port:>5}/tcp  {t('ui.ports.open')}  {name}"
            self.out.print(Text(line))

        try:
            hosts = expand(targets)
        except ScopeError:
            self.error(t("ui.error.not_private", target=targets))
            return EXIT_USAGE
        except ValueError as exc:
            self.error(t("ui.error.bad_target", target=targets, reason=str(exc)))
            return EXIT_USAGE
        wanted = list(ports or HOME_PORTS)
        try:
            results = self._run(scan(hosts, wanted, timeout=timeout, on_open=show))
        except ValueError as exc:
            self.error(str(exc))
            return EXIT_USAGE
        states = Counter(r.state for r in results)
        summary = t(
            "ui.ports.summary",
            hosts=len(hosts),
            ports=len(wanted),
            open=states[PortState.OPEN],
            closed=states[PortState.CLOSED],
            filtered=states[PortState.FILTERED],
        )
        self.out.print(Text(summary, style="dim"))
        return EXIT_OK

    # Menu

    def menu(self, help_text: Callable[[], str]) -> int:
        if not (sys.stdin.isatty() and self.out.is_terminal):
            # Run from a script, or with the output going to a file: there is
            # nobody to answer a prompt, so explain the commands instead.
            target = self.out if self.out.is_terminal else self.err
            target.print(Text(help_text()))
            return EXIT_OK
        actions: dict[str, tuple[str, Callable[[], int]]] = {
            "1": ("ui.menu.scan", self.full_scan),
            "2": ("ui.menu.devices", self.list_devices),
            "3": ("ui.menu.network", self.show_network),
            "4": ("ui.menu.router", self.show_router),
            "5": ("ui.menu.watch", self.watch_network),
        }
        try:
            info = local_network()
            while True:
                self.out.print(render.banner(info))
                for key, (label, _) in actions.items():
                    self.out.print(Text.assemble(f"  {key}  ", (t(label), "")), style="bold")
                self.out.print(Text(f"  q  {t('ui.menu.quit')}"))
                choice = _Choice.ask(
                    t("ui.menu.prompt"), choices=[*actions, "q"], default="1", console=self.out
                )
                if choice == "q":
                    return EXIT_OK
                # No network or Ctrl+C during a scan: back to the menu either way.
                with contextlib.suppress(_Abort):
                    actions[choice][1]()
                self.out.input(Text(t("ui.menu.again"), style="dim"))
                info = local_network()
        except (KeyboardInterrupt, EOFError):
            self.out.print()
            return EXIT_OK


class _Choice(Prompt):
    @property
    def illegal_choice_message(self) -> str:  # type: ignore[override]
        return f"[prompt.invalid.choice]{t('ui.menu.invalid')}"


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--lang",
        choices=i18n.LANGUAGES,
        default=argparse.SUPPRESS,
        help="language of the output (default: the system language)",
    )
    parser = argparse.ArgumentParser(
        prog="hearthscan",
        description="Find out what is on your home network and what it exposes.",
        epilog="Run it without a command for a small menu.\n\n" + _EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="command")

    scan_cmd = commands.add_parser(
        "scan",
        parents=[common],
        help="check the whole network and explain the risks",
        description="Find the devices on your network, check what they expose, and explain "
        "each risk with what to do about it.",
        epilog=_EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan_cmd.add_argument(
        "-p",
        "--ports",
        type=_port_spec,
        help="ports to check instead of the usual home ports, e.g. 22,80,8000-8100",
    )
    scan_cmd.add_argument(
        "-t",
        "--timeout",
        type=_seconds,
        default=1.0,
        help=f"seconds to wait for each port, up to {MAX_TIMEOUT:.0f} (default: 1)",
    )
    scan_cmd.add_argument(
        "--no-probe",
        action="store_true",
        help="only list open ports; skips the password checks, so some risks are missed",
    )
    scan_cmd.add_argument("--json", action="store_true", help="print the result as JSON")
    scan_cmd.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="also save the result: an HTML report when FILE ends in .html, JSON otherwise",
    )
    scan_cmd.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit with status 3 when anything this serious or worse turns up",
    )

    devices_cmd = commands.add_parser(
        "devices",
        parents=[common],
        help="list the devices on your network",
        description="List the devices on your network, without checking their ports.",
    )
    devices_cmd.add_argument("--json", action="store_true", help="print the list as JSON")

    net_cmd = commands.add_parser(
        "net",
        parents=[common],
        help="show the local network",
        description="Show the connection, address, network and router Hearthscan would use.",
    )
    net_cmd.add_argument("--json", action="store_true", help="print it as JSON")

    router_cmd = commands.add_parser(
        "router",
        parents=[common],
        help="show what the router says about itself and the ports it opened to the internet",
        description="Ask the router over UPnP for its internet address, its connection and "
        "the ports it forwards from the internet. Nothing on the router is changed.",
    )
    router_cmd.add_argument("--json", action="store_true", help="print it as JSON")

    report_cmd = commands.add_parser(
        "report",
        parents=[common],
        help="turn a saved result into an HTML report",
        description="Turn a result saved with `hearthscan scan -o FILE.json` into an HTML "
        "report. The page opens in any browser and loads nothing from the internet.",
        epilog=_EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    report_cmd.add_argument("result", type=Path, metavar="RESULT", help="a saved JSON result")
    report_cmd.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="where to write the report (default: next to RESULT, ending in .html)",
    )

    diff_cmd = commands.add_parser(
        "diff",
        parents=[common],
        help="show what changed between two saved results",
        description="Compare two results saved with `hearthscan scan -o FILE.json` and show "
        "the devices and findings that came and went, and how the score moved.",
        epilog=_EXIT_CODES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    diff_cmd.add_argument("old", type=Path, metavar="OLD", help="the earlier result")
    diff_cmd.add_argument("new", type=Path, metavar="NEW", help="the later result")
    diff_cmd.add_argument("--json", action="store_true", help="print the changes as JSON")

    watch_cmd = commands.add_parser(
        "watch",
        parents=[common],
        help="keep an eye on the network and report devices that turn up",
        description="Look at the network every few minutes and say when a device turns up "
        "that was never seen before, comes back, or leaves. The devices seen so far are "
        "remembered in a small file in your user folder (see `hearthscan known`).",
    )
    watch_cmd.add_argument(
        "--every",
        type=_minutes,
        default=5.0,
        metavar="MINUTES",
        help="minutes between checks, at least 0.5 (default: 5)",
    )
    watch_cmd.add_argument(
        "--full",
        action="store_true",
        help="run a full check each time and also report new risks (slower)",
    )

    known_cmd = commands.add_parser(
        "known",
        parents=[common],
        help="list the devices Hearthscan remembers from watching",
        description="List the devices watch mode has seen. Mark the ones you recognise as "
        "trusted, so the rest stand out.",
    )
    known_actions = known_cmd.add_mutually_exclusive_group()
    known_actions.add_argument(
        "--trust", metavar="DEVICE", help="mark a device as trusted (MAC or address)"
    )
    known_actions.add_argument("--untrust", metavar="DEVICE", help="remove the trusted mark")
    known_actions.add_argument("--forget", metavar="DEVICE", help="forget a device")
    known_actions.add_argument("--clear", action="store_true", help="forget every device")
    known_actions.add_argument("--json", action="store_true", help="print the list as JSON")

    ports_cmd = commands.add_parser(
        "ports",
        parents=[common],
        help="check TCP ports on chosen hosts in your network",
        description="Check TCP ports on hosts you choose. Only private addresses are allowed.",
    )
    ports_cmd.add_argument("targets", help="address, range or CIDR, e.g. 192.168.1.0/24")
    ports_cmd.add_argument(
        "-p",
        "--ports",
        type=_port_spec,
        help="ports to check instead of the usual home ports, e.g. 22,80,8000-8100",
    )
    ports_cmd.add_argument(
        "-t",
        "--timeout",
        type=_seconds,
        default=1.0,
        help=f"seconds to wait for each port, up to {MAX_TIMEOUT:.0f} (default: 1)",
    )
    return parser


def _plain_streams() -> None:
    # Names come from the network. A redirected stdout on Windows uses the ANSI
    # code page with strict errors, so one odd name would throw away the scan,
    # and Turkish letters would turn into question marks. Files and pipes get
    # UTF-8; a console keeps its encoding but stops raising.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        isatty = getattr(stream, "isatty", None)
        if isatty is not None and not isatty():
            reconfigure(encoding="utf-8", errors="replace")
        else:
            reconfigure(errors="replace")


def main(argv: Sequence[str] | None = None, app: App | None = None) -> int:
    _plain_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    i18n.set_language(getattr(args, "lang", None))
    app = app or App()
    try:
        if args.command == "scan":
            return app.full_scan(
                ports=args.ports or HOME_PORTS,
                timeout=args.timeout,
                probe=not args.no_probe,
                as_json=args.json,
                output=args.output,
                fail_on=args.fail_on,
            )
        if args.command == "devices":
            return app.list_devices(as_json=args.json)
        if args.command == "net":
            return app.show_network(as_json=args.json)
        if args.command == "router":
            return app.show_router(as_json=args.json)
        if args.command == "ports":
            return app.scan_ports(args.targets, args.ports, args.timeout)
        if args.command == "report":
            return app.save_report(args.result, args.output)
        if args.command == "diff":
            return app.compare_scans(args.old, args.new, as_json=args.json)
        if args.command == "watch":
            return app.watch_network(every=args.every * 60, full=args.full)
        if args.command == "known":
            return app.known_devices(
                trust=args.trust,
                untrust=args.untrust,
                forget=args.forget,
                clear=args.clear,
                as_json=args.json,
            )
        return app.menu(parser.format_help)
    except _Abort as stop:
        return stop.code
    except KeyboardInterrupt:
        app.err.print(Text(t("ui.stopped"), style="yellow"))
        return EXIT_STOPPED
