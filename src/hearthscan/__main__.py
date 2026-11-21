"""Bare-bones command line until the real one lands."""

from __future__ import annotations

import argparse
import math
import sys
import textwrap
from collections import Counter

from . import __version__
from .netinfo import local_network
from .ports import HOME_PORTS, SERVICE_NAMES, PortResult, PortState, parse_ports, scan
from .runner import run
from .scope import expand

_SANDBOX_NOTES = {
    "wsl": (
        "note: this looks like WSL. In its default NAT mode WSL sits on a virtual\n"
        "      network, not your home LAN. Run Hearthscan on Windows itself, or\n"
        "      switch WSL to mirrored networking."
    ),
    "container": "note: running in a container; this is probably the container network.",
}


def _seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be a positive number of seconds")
    return value


def _show_network() -> int:
    info = local_network()
    if info is None:
        print("No local network found. Are you connected?", file=sys.stderr)
        return 1
    print(f"interface  {info.interface.label}")
    print(f"address    {info.address}")
    print(f"network    {info.network}")
    print(f"gateway    {info.gateway or '-'}")
    if info.scan_network() != info.network:
        print(f"scanning   {info.scan_network()} (the network is bigger than a /22)")
    if info.sandbox:
        print(_SANDBOX_NOTES[info.sandbox], file=sys.stderr)
    return 0


def _scan_ports(targets: str, port_spec: str | None, timeout: float) -> int:
    def show(result: PortResult) -> None:
        name = SERVICE_NAMES.get(result.port, "")
        print(f"{result.host:<16} {result.port:>5}/tcp  open  {name}")

    try:
        hosts = expand(targets)
        ports = parse_ports(port_spec) if port_spec else list(HOME_PORTS)
        results = run(scan(hosts, ports, timeout=timeout, on_open=show))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return 130
    states = Counter(r.state for r in results)
    print(
        f"\n{len(hosts)} host(s), {len(ports)} port(s): {states[PortState.OPEN]} open, "
        f"{states[PortState.CLOSED]} closed, {states[PortState.FILTERED]} filtered"
    )
    return 0


def _list_devices() -> int:
    from .discovery import discover

    info = local_network()
    if info is None:
        print("No local network found. Are you connected?", file=sys.stderr)
        return 1
    if info.sandbox:
        print(_SANDBOX_NOTES[info.sandbox], file=sys.stderr)

    def note(source: str, message: str) -> None:
        print(
            textwrap.fill(message, 78, initial_indent="note: ", subsequent_indent="      "),
            file=sys.stderr,
        )

    print(f"looking around {info.scan_network()} ...", file=sys.stderr)
    try:
        devices = run(discover(info, on_note=note))
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return 130
    for d in devices:
        flags = (
            ("gateway", d.is_gateway),
            ("you", d.is_self),
            ("seen recently", not d.confirmed),
        )
        tags = " ".join(tag for tag, on in flags if on)
        print(
            f"{d.ip:<15} {d.mac or '-':<17} {(d.vendor or '-')[:18]:<18} "
            f"{d.kind:<10} {(d.name or '-')[:28]:<28} {(d.model or '')[:24]:<24} {tags}"
        )
    print(f"\n{len(devices)} device(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Names come from the network. On Windows a redirected stdout uses the ANSI
    # code page with strict errors, and one odd name would throw away the scan.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
    parser = argparse.ArgumentParser(prog="hearthscan", description="Home network checkup.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("net", help="show the local network and gateway")
    commands.add_parser("devices", help="list the devices on your network")
    ports_cmd = commands.add_parser("ports", help="check TCP ports on hosts in your network")
    ports_cmd.add_argument("targets", help="address, range or CIDR, e.g. 192.168.1.0/24")
    ports_cmd.add_argument("-p", "--ports", help="e.g. 22,80,8000-8100 (default: common ones)")
    ports_cmd.add_argument(
        "-t", "--timeout", type=_seconds, default=1.0, help="seconds per port (default: 1)"
    )
    args = parser.parse_args(argv)
    if args.command == "ports":
        return _scan_ports(args.targets, args.ports, args.timeout)
    if args.command == "devices":
        return _list_devices()
    return _show_network()


if __name__ == "__main__":
    sys.exit(main())
