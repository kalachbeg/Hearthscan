"""The command line: a small menu when started bare, or straight to a command."""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Sequence
from pathlib import Path

from rich.console import Console
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
from rich.text import Text

from . import __version__, i18n, render, serialize
from .i18n import t
from .models import SEVERITIES, ScanResult
from .netinfo import NetworkInfo, local_network
from .ports import HOME_PORTS, SERVICE_NAMES, PortResult, PortState, parse_ports, scan
from .runner import run
from .scope import ScopeError, expand
from .system import IS_WINDOWS

EXIT_OK = 0
EXIT_NO_NETWORK = 1
EXIT_USAGE = 2
EXIT_FINDINGS = 3  # --fail-on matched something
EXIT_STOPPED = 130

MAX_TIMEOUT = 60.0

_EXIT_CODES = """exit status:
  0    done
  1    no local network found
  2    bad arguments, or the result could not be saved
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
            try:
                output.write_text(serialize.dumps(result), encoding="utf-8")
            except OSError as exc:
                self.error(t("ui.save_failed", path=str(output), reason=exc.strerror or exc))
                return EXIT_USAGE
            self.err.print(Text(t("ui.saved", path=str(output)), style="dim"))
        return code

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
    scan_cmd.add_argument("-o", "--output", type=Path, help="also save the result as JSON")
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
        if args.command == "ports":
            return app.scan_ports(args.targets, args.ports, args.timeout)
        return app.menu(parser.format_help)
    except _Abort as stop:
        return stop.code
    except KeyboardInterrupt:
        app.err.print(Text(t("ui.stopped"), style="yellow"))
        return EXIT_STOPPED
