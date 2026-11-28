"""Turn results into something pleasant to read in a terminal.

Names, models and vendors come from devices on the network. They always go in
as Text objects, never as plain strings, so a name like "[/]" or "[link=...]"
is shown as it is instead of being read as rich markup.
"""

from __future__ import annotations

from collections.abc import Iterable

from rich import box
from rich.console import Group, RenderableType
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__, scoring
from .i18n import t
from .models import SEVERITIES, Device, Finding, PortMapping, RouterInfo, ScanResult
from .netinfo import NetworkInfo

SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
    "info": "dim",
}
BAND_STYLES = {"good": "green", "fair": "yellow", "poor": "dark_orange", "bad": "red"}
# Below this many columns the maker column goes, so names and ports keep room.
NARROW = 90


def device_label(device: Device | None, ip: str) -> str:
    if device is None:
        return ip
    kind = t(f"kind.{device.kind}")
    if not device.name:
        return f"{kind} ({ip})"
    if device.is_gateway:
        # "home (192.168.1.1)" says nothing; "home, Router (...)" does.
        return f"{device.name}, {kind} ({ip})"
    return f"{device.name} ({ip})"


def maker(device: Device) -> str:
    vendor, model = device.vendor or "", device.model or ""
    if vendor and model.lower().startswith(vendor.lower()):
        return model
    return " ".join(part for part in (vendor, model) if part)


def banner(info: NetworkInfo | None) -> Panel:
    lines = [Text.assemble(("Hearthscan ", "bold"), (__version__, "dim"))]
    if info is None:
        lines.append(Text(t("ui.no_network"), style="yellow"))
    else:
        lines.append(
            Text(t("ui.banner.network", network=info.scan_network(), via=info.interface.label))
        )
    return Panel(Group(*lines), box=box.ROUNDED, expand=False, padding=(0, 2))


def network_details(info: NetworkInfo) -> Table:
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="dim")
    grid.add_column()
    rows = [
        ("ui.network.interface", info.interface.label),
        ("ui.network.address", str(info.address)),
        ("ui.network.network", str(info.network)),
        ("ui.network.gateway", info.gateway or "-"),
    ]
    if info.scan_network() != info.network:
        rows.append(("ui.network.scanning", t("ui.network.narrowed", network=info.scan_network())))
    for key, value in rows:
        grid.add_row(Text(t(key)), Text(value))
    return grid


def devices_table(
    devices: Iterable[Device], *, with_ports: bool = True, width: int | None = None
) -> Table:
    show_maker = width is None or width >= NARROW
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    table.add_column(t("ui.col.address"), no_wrap=True)
    table.add_column(t("ui.col.name"), min_width=12, max_width=30)
    table.add_column(t("ui.col.kind"), min_width=8)
    if show_maker:
        table.add_column(t("ui.col.maker"), min_width=10, max_width=34)
    if with_ports:
        # Wide enough for a five digit port, so a number never breaks in two.
        table.add_column(t("ui.col.ports"), min_width=5, max_width=24)
    for device in devices:
        tags = [
            tag
            for tag, on in (
                (t("ui.tag.gateway"), device.is_gateway),
                (t("ui.tag.self"), device.is_self),
                (t("ui.tag.recent"), not device.confirmed),
            )
            if on
        ]
        name = Text(device.name or "")
        if tags:
            name.append(("\n" if device.name else "") + ", ".join(tags), style="dim")
        row: list[Text] = [Text(device.ip), name, Text(t(f"kind.{device.kind}"))]
        if show_maker:
            row.append(Text(maker(device)))
        if with_ports:
            ports = sorted(device.services, key=lambda s: s.port)
            row.append(Text(" ".join(str(s.port) for s in ports)))
        table.add_row(*row)
    return table


def severity_badge(severity: str) -> Text:
    # No upper(): it turns the Turkish "Kritik" into "KRITIK" with a dotless I.
    return Text(f" {t('severity.' + severity)} ", style=SEVERITY_STYLES.get(severity, ""))


def score_panel(result: ScanResult, elapsed: float | None = None, *, probed: bool = True) -> Panel:
    band = scoring.band(result.score)
    style = BAND_STYLES[band]
    headline = Text.assemble(
        (t("ui.score.title") + "  ", "bold"),
        (str(result.score), f"bold {style}"),
        (" / 100   ", "dim"),
        (t(f"band.{band}.title"), f"bold {style}"),
    )
    counts = scoring.counts(result.findings)
    found = [
        t(f"ui.count.{severity}", count=counts[severity])
        for severity in SEVERITIES
        if counts[severity] and severity != "info"
    ]
    facts = [result.network, t("ui.summary.devices", count=len(result.devices))]
    facts.append(", ".join(found) if found else t("ui.summary.clean"))
    if elapsed is not None:
        facts.append(t("ui.summary.took", seconds=f"{elapsed:.0f}"))
    lines: list[RenderableType] = [headline, Text(t(f"band.{band}.summary"))]
    if counts["critical"] or counts["high"]:
        lines.append(Text(t("ui.score.urgent"), style="bold red"))
    if not probed:
        lines.append(Text(t("ui.score.unprobed"), style="yellow"))
    lines.append(Text("  ·  ".join(facts), style="dim"))
    return Panel(Group(*lines), box=box.ROUNDED, border_style=style, expand=False, padding=(1, 2))


def _where(finding: Finding, device: Device | None) -> str:
    where = device_label(device, finding.ip)
    if finding.port:
        where = t("ui.finding.where", device=where, port=finding.port)
    return where


def finding_block(finding: Finding, device: Device | None) -> RenderableType:
    rows: list[RenderableType] = [
        Text.assemble(
            severity_badge(finding.severity), "  ", (t(f"rule.{finding.rule}.title"), "bold")
        ),
        Text(_where(finding, device), style="dim"),
        Text.assemble(
            (t("ui.finding.why") + ": ", "bold"),
            t(f"rule.{finding.rule}.why", **finding.params),
        ),
        Text.assemble(
            (t("ui.finding.fix") + ": ", "bold"),
            t(f"rule.{finding.rule}.fix", **finding.params),
        ),
    ]
    return Padding(Group(*rows), (0, 0, 1, 2))


def _uptime(seconds: int) -> str:
    days, rest = divmod(seconds, 86400)
    return t("ui.router.uptime_value", days=days, hours=rest // 3600)


def _forwards_to(mapping: PortMapping, devices: dict[str, Device]) -> str:
    device = devices.get(mapping.internal_client)
    if device is None:
        return f"{mapping.internal_client}:{mapping.internal_port}"
    return t(
        "ui.finding.where",
        device=device_label(device, mapping.internal_client),
        port=mapping.internal_port,
    )


def mappings_table(
    mappings: Iterable[PortMapping], devices: Iterable[Device], *, width: int | None = None
) -> Table:
    """The port forwards a router lists. Switched off ones are dimmed."""
    by_ip = {device.ip: device for device in devices}
    wide = width is None or width >= NARROW
    table = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    table.add_column(t("ui.col.external"), no_wrap=True)
    if wide:
        table.add_column(t("ui.col.protocol"), no_wrap=True)
    table.add_column(t("ui.col.forwards_to"), min_width=12)
    table.add_column(t("ui.col.description"), min_width=8, max_width=40)
    for mapping in mappings:
        port = str(mapping.external_port)
        row: list[Text] = [Text(port if wide else f"{port}/{mapping.protocol}")]
        if wide:
            row.append(Text(mapping.protocol))
        row += [Text(_forwards_to(mapping, by_ip)), Text(mapping.description)]
        table.add_row(*row, style=None if mapping.enabled else "dim")
    return table


def router_view(
    info: RouterInfo, devices: Iterable[Device], width: int | None = None
) -> list[RenderableType]:
    """What the router said about its internet side, then the ports it forwards."""
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="dim")
    grid.add_column()
    rows = [
        ("ui.router.external_ip", info.external_ip),
        ("ui.router.connection", info.connection),
        ("ui.router.status", info.status),
        ("ui.router.uptime", _uptime(info.uptime) if info.uptime is not None else None),
    ]
    for key, value in rows:
        if value:
            grid.add_row(Text(t(key)), Text(value))

    parts: list[RenderableType] = []
    if grid.row_count:
        parts += [grid, Text()]
    parts.append(Text(t("ui.router.mappings"), style="bold"))
    if info.mappings:
        parts.append(mappings_table(info.mappings, devices, width=width))
    elif info.mappings_complete:
        # Not when the list broke off: the forwards past that point are unknown.
        parts.append(Padding(Text(t("ui.router.none"), style="green"), (0, 0, 0, 2)))
    if not info.mappings_complete:
        incomplete = t("ui.router.incomplete", count=len(info.mappings))
        parts.append(Text(incomplete, style="yellow"))
    return parts


def result_view(
    result: ScanResult,
    elapsed: float | None = None,
    *,
    probed: bool = True,
    notes: bool = True,
    width: int | None = None,
) -> list[RenderableType]:
    """Everything `hearthscan scan` shows, top to bottom: score, risks, router, devices.

    `notes=False` leaves out result.notes, for when they were already shown
    while the scan ran.
    """
    parts: list[RenderableType] = [score_panel(result, elapsed, probed=probed), Text()]

    serious = [f for f in result.findings if f.severity != "info"]
    fyi = [f for f in result.findings if f.severity == "info"]
    parts += [Text(t("ui.findings.title"), style="bold"), Text()]
    if serious:
        parts += [finding_block(f, result.device(f.ip)) for f in serious]
    else:
        parts.append(Padding(Text(t("ui.findings.none"), style="green"), (0, 0, 1, 2)))
    if fyi:
        parts.append(Text(t("ui.findings.fyi"), style="bold"))
        for finding in fyi:
            device = result.device(finding.ip)
            parts.append(
                Text.assemble(
                    "  • ",
                    t(f"rule.{finding.rule}.title"),
                    (f"  {_where(finding, device)}", "dim"),
                )
            )
            if finding.rule == "unknown-device":
                fix = t(f"rule.{finding.rule}.fix", **finding.params)
                parts.append(Padding(Text(fix, style="dim"), (0, 0, 0, 4)))
        parts.append(Text())

    if result.router is not None:
        parts += [Text(t("ui.router.title"), style="bold"), Text()]
        parts += router_view(result.router, result.devices, width)
        parts.append(Text())

    parts += [Text(t("ui.devices.title"), style="bold"), devices_table(result.devices, width=width)]
    if notes and result.notes:
        parts.append(Text())
        parts += [Text(f"{t('ui.note')}: {message}", style="dim") for _, message in result.notes]
    return parts
