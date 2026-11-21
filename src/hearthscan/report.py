"""A scan result as one HTML page that opens anywhere and loads nothing.

Names, banners and descriptions come from devices on the network and the
router. Everything put into the page goes through _e(), which escapes it and
drops control and text direction characters, so no name can add markup or
turn the text around it backwards.
"""

from __future__ import annotations

import contextlib
import html
from datetime import datetime

from . import __version__, scoring
from .i18n import language, t
from .models import SEVERITIES, Device, Finding, PortMapping, RouterInfo, ScanResult
from .render import device_label, maker

# Control characters become spaces, lone surrogates (possible in JSON) the
# replacement character, and directional marks, embeddings, overrides and
# isolates go.
_UNSAFE: dict[int, str | None] = {
    **dict.fromkeys([*range(0x20), *range(0x7F, 0xA0)], " "),
    **dict.fromkeys(range(0xD800, 0xE000), "�"),
    **dict.fromkeys([0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)]),
}

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #f6f5f2;
  --surface: #ffffff;
  --text: #1f2023;
  --muted: #5b5e64;
  --line: #dcd9d2;
  --tint: #f0eee9;
  --good: #2e7d32;
  --fair: #8a6100;
  --poor: #c2410c;
  --bad: #c62828;
  --critical-fg: #ffffff;
  --critical-bg: #c62828;
  --high-fg: #b3261e;
  --high-bg: #fdecea;
  --medium-fg: #7a5200;
  --medium-bg: #fff1c7;
  --low-fg: #006577;
  --low-bg: #ddf3f6;
  --info-fg: #5b5e64;
  --info-bg: #ecebe7;
}
@media screen and (prefers-color-scheme: dark) {
  :root {
    --bg: #141517;
    --surface: #1d1f22;
    --text: #e8e6e1;
    --muted: #a4a7ac;
    --line: #34373c;
    --tint: #26292d;
    --good: #81c784;
    --fair: #f2c94c;
    --poor: #ffa36c;
    --bad: #ff8a80;
    --critical-fg: #ffffff;
    --critical-bg: #d32f2f;
    --high-fg: #ff8a80;
    --high-bg: #3d1f1f;
    --medium-fg: #f2c94c;
    --medium-bg: #3a3117;
    --low-fg: #7fd6e3;
    --low-bg: #15353b;
    --info-fg: #a4a7ac;
    --info-bg: #2a2c30;
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial,
    "Noto Sans", sans-serif;
}
main { max-width: 56rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
h1, h2, h3 { line-height: 1.25; }
h2 { font-size: 1.3rem; margin: 2.5rem 0 1rem; }
h3 { font-size: 1.05rem; margin: 1.75rem 0 .6rem; }
code, .port {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
}
.band-good { --band: var(--good); }
.band-fair { --band: var(--fair); }
.band-poor { --band: var(--poor); }
.band-bad { --band: var(--bad); }
.sev-critical { --sev-fg: var(--critical-fg); --sev-bg: var(--critical-bg); }
.sev-high { --sev-fg: var(--high-fg); --sev-bg: var(--high-bg); }
.sev-medium { --sev-fg: var(--medium-fg); --sev-bg: var(--medium-bg); }
.sev-low { --sev-fg: var(--low-fg); --sev-bg: var(--low-bg); }
.sev-info { --sev-fg: var(--info-fg); --sev-bg: var(--info-bg); }
.finding.sev-critical { --edge: var(--critical-bg); }
.finding.sev-high { --edge: var(--high-fg); }
.finding.sev-medium { --edge: var(--medium-fg); }
.finding.sev-low { --edge: var(--low-fg); }
.finding.sev-info { --edge: var(--line); }
.score, .finding, .list, .table {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 10px;
}
.score { border-top: 6px solid var(--band); padding: 1.25rem 1.5rem; }
.brand { margin: 0; font-size: .85rem; font-weight: 600; color: var(--muted); }
.score h1 {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: .25rem .6rem;
  margin: .4rem 0 .75rem;
  font-size: 1.15rem;
}
.score .number { font-size: 3rem; line-height: 1; color: var(--band); }
.score .out-of { font-weight: 400; color: var(--muted); }
.meter { height: 8px; border-radius: 4px; background: var(--tint); overflow: hidden; }
.meter span { display: block; height: 100%; background: var(--band); }
.band { margin: 1rem 0 .2rem; font-size: 1.1rem; font-weight: 700; color: var(--band); }
.score p { margin: .4rem 0; }
.urgent { font-weight: 600; color: var(--bad); }
.score .facts { margin-bottom: 0; font-size: .9rem; color: var(--muted); }
.finding { border-left: 5px solid var(--edge); padding: 1rem 1.25rem; margin: 0 0 1rem; }
.finding header { display: flex; flex-wrap: wrap; align-items: center; gap: .4rem .6rem; }
.finding h3 { margin: 0; }
.badge {
  display: inline-block;
  padding: .1rem .6rem;
  border-radius: 999px;
  font-size: .8rem;
  font-weight: 700;
  white-space: nowrap;
  color: var(--sev-fg);
  background: var(--sev-bg);
}
.where { margin: .35rem 0 0; font-size: .9rem; color: var(--muted); overflow-wrap: anywhere; }
.explain { margin: .5rem 0 0; }
.explain dt { margin-top: .7rem; font-weight: 600; }
.explain dd { margin: .15rem 0 0; }
.explain .detail { font-size: .85rem; font-weight: 400; color: var(--muted); }
.explain code {
  display: block;
  padding: .45rem .6rem;
  border-radius: 6px;
  font-size: .8rem;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  color: var(--muted);
  background: var(--tint);
}
.ok { font-weight: 600; color: var(--good); }
.warn { color: var(--fair); }
.list { list-style: none; margin: 0; padding: 0; }
.list li { padding: .65rem 1rem; border-top: 1px solid var(--line); }
.list li:first-child { border-top: 0; }
.list .hint { margin: .3rem 0 0; font-size: .9rem; color: var(--muted); }
.notes ul { color: var(--muted); }
.facts-grid {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: .35rem 1.5rem;
  margin: 0 0 1.25rem;
}
.facts-grid dt { color: var(--muted); }
.facts-grid dd { margin: 0; overflow-wrap: anywhere; }
.table { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: .92rem; }
th, td {
  padding: .55rem .8rem;
  border-top: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}
thead th { border-top: 0; font-weight: 600; white-space: nowrap; background: var(--tint); }
/* break-word, not anywhere: words stay whole and a long one makes the table scroll. */
td { overflow-wrap: break-word; }
td.address { white-space: nowrap; }
tr.off td { color: var(--muted); }
.port, .tag {
  display: inline-block;
  margin: 0 .25rem .25rem 0;
  font-size: .8rem;
  white-space: nowrap;
}
.port { padding: 0 .35rem; border-radius: 4px; background: var(--tint); }
.port span { color: var(--muted); }
.tag { padding: 0 .5rem; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); }
footer {
  margin-top: 3rem;
  padding-top: 1rem;
  border-top: 1px solid var(--line);
  font-size: .85rem;
  color: var(--muted);
}
footer p { margin: .3rem 0; }
@media (max-width: 40rem) {
  main { padding: 1rem .75rem 2rem; }
  .score, .finding { padding: 1rem; }
  .score .number { font-size: 2.5rem; }
  .facts-grid { grid-template-columns: 1fr; gap: 0; }
  .facts-grid dd { margin-bottom: .6rem; }
  .table { overflow: visible; }
  .stack thead {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
  .stack tr { display: block; padding: .5rem .9rem; border-top: 1px solid var(--line); }
  .stack tbody tr:first-child { border-top: 0; }
  .stack td {
    display: grid;
    grid-template-columns: minmax(6rem, 35%) 1fr;
    gap: .75rem;
    padding: .2rem 0;
    border: 0;
  }
  .stack td::before { content: attr(data-label); color: var(--muted); }
  .stack td > div { min-width: 0; overflow-wrap: anywhere; }
  .stack td:empty { display: none; }
}
@media print {
  :root { color-scheme: light; }
  body { font-size: 11pt; background: #ffffff; }
  main { max-width: none; padding: 0; }
  .score, .finding, .list, .table { border-color: #b5b2ab; }
  .badge { border: 1px solid currentColor; }
  .meter, .meter span, .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .table { overflow: visible; }
  .finding, .list li, tr, .score { break-inside: avoid; }
  h2, h3 { break-after: avoid; }
}
"""

# Nothing may load: not even a stray tag in a name could fetch anything.
_POLICY = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def html_report(result: ScanResult) -> str:
    """The result as a complete HTML document in the current language."""
    started = format_time(result.started)
    title = t("report.title", network=result.network, time=started)
    sections = [
        _header(result),
        _findings(result),
        _router(result.router, result.devices) if result.router is not None else "",
        _devices(result.devices),
        _notes(result.notes),
    ]
    made = f"Hearthscan {result.version or __version__}"
    footer = [
        f"<p>{_e(made)} · {_e(t('report.started', time=started))}</p>",
        f"<p>{_e(t('report.privacy'))}</p>",
    ]
    return "\n".join(
        [
            "<!DOCTYPE html>",
            f'<html lang="{_e(language())}">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f'<meta http-equiv="Content-Security-Policy" content="{_POLICY}">',
            '<meta name="color-scheme" content="light dark">',
            f"<title>{_e(title)}</title>",
            f"<style>{_STYLE}</style>",
            "</head>",
            "<body>",
            "<main>",
            *filter(None, sections),
            "<footer>",
            *footer,
            "</footer>",
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


def format_time(iso: str) -> str:
    """An ISO 8601 time as a local date and time, or the text unchanged if it is not one."""
    moment = _parse_time(iso)
    if moment is None:
        return iso
    if moment.tzinfo is not None:
        # Times near year 1 or 9999 may not convert; they are shown as saved.
        with contextlib.suppress(ValueError, OverflowError, OSError):
            moment = moment.astimezone()
    return t(
        "report.datetime",
        year=f"{moment.year:04d}",
        month=f"{moment.month:02d}",
        day=f"{moment.day:02d}",
        hour=f"{moment.hour:02d}",
        minute=f"{moment.minute:02d}",
    )


def _parse_time(iso: str) -> datetime | None:
    try:
        # Python 3.10 does not read the "Z" suffix yet.
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def _e(value: object) -> str:
    """Text made safe to put anywhere in the page, attribute values included."""
    return html.escape(str(value).translate(_UNSAFE), quote=True)


def _duration(started: str, finished: str) -> float | None:
    start, end = _parse_time(started), _parse_time(finished)
    if start is None or end is None:
        return None
    try:
        seconds = (end - start).total_seconds()
    except TypeError:  # one with a time zone and one without
        return None
    return seconds if seconds >= 0 else None


def _severity(finding: Finding) -> str:
    """The severity as a class name. Anything unknown is shown like info."""
    return finding.severity if finding.severity in SEVERITIES else "info"


def _where(finding: Finding, device: Device | None) -> str:
    where = device_label(device, finding.ip)
    if finding.port:
        where = t("ui.finding.where", device=where, port=finding.port)
    return where


def _header(result: ScanResult) -> str:
    score = max(0, min(100, int(result.score)))
    band = scoring.band(score)
    counts = scoring.counts(result.findings)
    found = [
        t(f"ui.count.{severity}", count=counts[severity])
        for severity in SEVERITIES
        if counts[severity] and severity != "info"
    ]
    facts = [result.network, t("ui.summary.devices", count=len(result.devices))]
    facts.append(", ".join(found) if found else t("ui.summary.clean"))
    took = _duration(result.started, result.finished)
    if took is not None:
        facts.append(t("ui.summary.took", seconds=f"{took:.0f}"))
    lines = [
        f'<header class="score band-{band}">',
        '<p class="brand">Hearthscan</p>',
        f'<h1>{_e(t("ui.score.title"))} <span class="number">{score}</span>'
        '<span class="out-of">/ 100</span></h1>',
        f'<div class="meter" aria-hidden="true"><span style="width: {score}%"></span></div>',
        f'<p class="band">{_e(t(f"band.{band}.title"))}</p>',
        f"<p>{_e(t(f'band.{band}.summary'))}</p>",
    ]
    if counts["critical"] or counts["high"]:
        lines.append(f'<p class="urgent">{_e(t("ui.score.urgent"))}</p>')
    lines += [f'<p class="facts">{" · ".join(_e(fact) for fact in facts)}</p>', "</header>"]
    return "\n".join(lines)


def _card(finding: Finding, device: Device | None) -> str:
    severity = _severity(finding)
    lines = [
        f'<article class="finding sev-{severity}">',
        "<header>",
        f'<span class="badge sev-{severity}">{_e(t(f"severity.{finding.severity}"))}</span>',
        f"<h3>{_e(t(f'rule.{finding.rule}.title'))}</h3>",
        "</header>",
        f'<p class="where">{_e(_where(finding, device))}</p>',
        '<dl class="explain">',
        f"<dt>{_e(t('ui.finding.why'))}</dt>",
        f"<dd>{_e(t(f'rule.{finding.rule}.why', **finding.params))}</dd>",
        f"<dt>{_e(t('ui.finding.fix'))}</dt>",
        f"<dd>{_e(t(f'rule.{finding.rule}.fix', **finding.params))}</dd>",
    ]
    if finding.evidence:
        lines += [
            f'<dt class="detail">{_e(t("report.evidence"))}</dt>',
            f"<dd><code>{_e(finding.evidence)}</code></dd>",
        ]
    lines += ["</dl>", "</article>"]
    return "\n".join(lines)


def _findings(result: ScanResult) -> str:
    serious = [f for f in result.findings if f.severity != "info"]
    fyi = [f for f in result.findings if f.severity == "info"]
    lines = ["<section>", f"<h2>{_e(t('ui.findings.title'))}</h2>"]
    if serious:
        lines += [_card(f, result.device(f.ip)) for f in serious]
    else:
        lines.append(f'<p class="ok">{_e(t("ui.findings.none"))}</p>')
    if fyi:
        lines += [f"<h3>{_e(t('ui.findings.fyi'))}</h3>", '<ul class="list">']
        for finding in fyi:
            where = _where(finding, result.device(finding.ip))
            item = f'<li>{_e(t(f"rule.{finding.rule}.title"))}<p class="where">{_e(where)}</p>'
            if finding.rule == "unknown-device":
                item += f'<p class="hint">{_e(t(f"rule.{finding.rule}.fix", **finding.params))}</p>'
            lines.append(item + "</li>")
        lines.append("</ul>")
    lines.append("</section>")
    return "\n".join(lines)


def _table(headers: list[str], rows: list[tuple[list[str], str]]) -> str:
    """A table that turns into labelled blocks on a phone. Cells come in escaped."""
    labels = [_e(t(key)) for key in headers]
    lines = ['<div class="table">', '<table class="stack">', "<thead><tr>"]
    lines += [f'<th scope="col">{label}</th>' for label in labels]
    lines += ["</tr></thead>", "<tbody>"]
    for cells, row_class in rows:
        tds = []
        for index, (label, cell) in enumerate(zip(labels, cells, strict=True)):
            if not cell:
                tds.append("<td></td>")  # hidden on a phone
                continue
            # The first column holds an address or a port number, which should not wrap.
            css = ' class="address"' if index == 0 else ""
            # On a phone a cell is a grid of label and value. The div keeps several
            # port or tag chips together as one value.
            tds.append(f'<td{css} data-label="{label}"><div>{cell}</div></td>')
        opening = f'<tr class="{row_class}">' if row_class else "<tr>"
        lines.append(opening + "".join(tds) + "</tr>")
    lines += ["</tbody>", "</table>", "</div>"]
    return "\n".join(lines)


def _uptime(seconds: int) -> str:
    days, rest = divmod(seconds, 86400)
    return t("ui.router.uptime_value", days=days, hours=rest // 3600)


def _forwards_to(mapping: PortMapping, devices: dict[str, Device]) -> str:
    device = devices.get(mapping.internal_client)
    if device is None:
        return f"{mapping.internal_client}:{mapping.internal_port}"
    label = device_label(device, mapping.internal_client)
    return t("ui.finding.where", device=label, port=mapping.internal_port)


def _router(info: RouterInfo, devices: list[Device]) -> str:
    facts = [
        ("ui.router.external_ip", info.external_ip),
        ("ui.router.connection", info.connection),
        ("ui.router.status", info.status),
        ("ui.router.uptime", _uptime(info.uptime) if info.uptime is not None else None),
    ]
    lines = ["<section>", f"<h2>{_e(t('ui.router.title'))}</h2>"]
    shown = [(key, value) for key, value in facts if value]
    if shown:
        lines.append('<dl class="facts-grid">')
        lines += [f"<dt>{_e(t(key))}</dt><dd>{_e(value)}</dd>" for key, value in shown]
        lines.append("</dl>")
    lines.append(f"<h3>{_e(t('ui.router.mappings'))}</h3>")
    if info.mappings:
        # Reversed, so the first device with an address wins, as in ScanResult.device().
        by_ip = {device.ip: device for device in reversed(devices)}
        off = f' <span class="tag">{_e(t("report.forward.off"))}</span>'
        rows = [
            (
                [
                    _e(m.external_port),
                    _e(m.protocol),
                    _e(_forwards_to(m, by_ip)),
                    _e(m.description) + ("" if m.enabled else off),
                ],
                "" if m.enabled else "off",
            )
            for m in info.mappings
        ]
        headers = ["ui.col.external", "ui.col.protocol", "ui.col.forwards_to", "ui.col.description"]
        lines.append(_table(headers, rows))
    elif info.mappings_complete:
        lines.append(f'<p class="ok">{_e(t("ui.router.none"))}</p>')
    if not info.mappings_complete:
        incomplete = t("ui.router.incomplete", count=len(info.mappings))
        lines.append(f'<p class="warn">{_e(incomplete)}</p>')
    lines.append("</section>")
    return "\n".join(lines)


def _devices(devices: list[Device]) -> str:
    lines = ["<section>", f"<h2>{_e(t('ui.devices.title'))}</h2>"]
    if not devices:
        lines += [f"<p>{_e(t('report.devices.none'))}</p>", "</section>"]
        return "\n".join(lines)
    rows = []
    for device in devices:
        ports = "".join(
            f'<span class="port">{_e(service.port)}'
            + (f" <span>{_e(service.name)}</span>" if service.name else "")
            + "</span>"
            for service in sorted(device.services, key=lambda s: s.port)
        )
        tags = "".join(
            f'<span class="tag">{_e(t(key))}</span>'
            for key, on in (
                ("ui.tag.gateway", device.is_gateway),
                ("ui.tag.self", device.is_self),
                ("ui.tag.recent", not device.confirmed),
            )
            if on
        )
        cells = [
            _e(device.ip),
            _e(device.name or ""),
            _e(t(f"kind.{device.kind}")),
            _e(maker(device)),
            ports,
            tags,
        ]
        rows.append((cells, ""))
    headers = [
        "ui.col.address",
        "ui.col.name",
        "ui.col.kind",
        "ui.col.maker",
        "ui.col.ports",
        "report.col.tags",
    ]
    lines += [_table(headers, rows), "</section>"]
    return "\n".join(lines)


def _notes(notes: list[tuple[str, str]]) -> str:
    if not notes:
        return ""
    lines = ['<section class="notes">', f"<h2>{_e(t('report.notes'))}</h2>", "<ul>"]
    lines += [f"<li>{_e(message)}</li>" for _, message in notes]
    lines += ["</ul>", "</section>"]
    return "\n".join(lines)
