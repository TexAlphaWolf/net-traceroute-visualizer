"""Reports: text, Markdown, JSON and one self-contained HTML page (no script, no external file)."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape

from .analysis import Analysis, Epoch, Event, HopStat, addr_key, hop_stats, median

ISO = "%Y-%m-%dT%H:%M:%SZ"
SHORT = "%Y-%m-%d %H:%M"


class Anonymizer:
    """Replaces addresses and target names with short stable labels, so a report can be published.

    The label comes from an HMAC with a key: the same address gets the same label in one report (the route can still be
    followed), and nobody can go back from a label to the address. Without ``key`` a random one is used, so two reports
    cannot be matched with each other."""

    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or secrets.token_bytes(16)

    def _label(self, kind: str, value: str) -> str:
        return f"{kind}-{hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()[:6]}"

    def addr(self, value: str) -> str:
        return value if value == "*" else self._label("node", value)

    def target(self, value: str) -> str:
        return self._label("target", value)


Alias = Callable[[str], str]


def _aliases(anon: Anonymizer | None) -> tuple[Alias, Alias, Alias]:
    """(address, target, label of a hop such as "a|b" or "*")"""
    if anon is None:
        return (lambda x: x), (lambda x: x), (lambda x: x)
    return anon.addr, anon.target, lambda lab: "|".join(anon.addr(x) for x in lab.split("|"))


@dataclass(frozen=True)
class Summary:
    target: str
    runs: int
    last: datetime
    reached: bool
    hops: int
    rtt_ms: float | None
    routes: int
    last_change: datetime | None
    events: int


def summarize(an: Analysis) -> Summary:
    changes = [e for e in an.events if e.kind == "route_change"]
    last = an.last
    recent = [v for v in (t.end_to_end() for t in an.traces[-5:]) if v is not None]
    return Summary(
        target=an.target,
        runs=len(an.traces),
        last=last.ts,
        reached=last.reached,
        hops=len(last.addr_sets()),
        rtt_ms=round(median(recent), 1) if recent else None,
        routes=len(an.epochs),
        last_change=changes[-1].ts if changes else None,
        events=sum(1 for e in an.events if e.kind != "alternate"),
    )


def fmt_time(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime(SHORT) + "Z"


def fmt_ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f} ms"


def _hop_changes(before: tuple[str, ...], after: tuple[str, ...], alias: Alias) -> str:
    diffs = []
    for i in range(max(len(before), len(after))):
        b = before[i] if i < len(before) else "(none)"
        a = after[i] if i < len(after) else "(none)"
        if b != a:
            diffs.append(f"hop {i + 1}: {alias(b) if b != '(none)' else b} -> {alias(a) if a != '(none)' else a}")
    shown = diffs[:2]
    if len(diffs) > 2:
        more = len(diffs) - 2
        shown.append(f"{more} more hop{' differs' if more == 1 else 's differ'}")
    return "; ".join(shown)


def describe(event: Event, *, alias: Alias = lambda x: x) -> str:
    """One line in plain words."""
    if event.kind == "route_change":
        how = {
            "reroute": "Route changed",
            "longer": "Route got longer",
            "shorter": "Route got shorter",
            "balanced": "Traffic is now also balanced over another path",
            "unbalanced": "A balanced path left the route",
        }.get(event.subkind, "Route changed")
        change = _hop_changes(event.before, event.after, alias) or "an address outside the usual route answered"
        delta = f" End-to-end {event.delta_ms:+.1f} ms." if event.delta_ms is not None else ""
        return f"{how}: {change}.{delta}"
    if event.kind == "alternate":
        return f"Another equal-cost router answers at hop {event.ttl}: {alias(event.addr or '?')}."
    if event.kind == "latency_shift":
        hop = f", starting at hop {event.ttl}" if event.ttl else ""
        return f"End-to-end time moved {event.delta_ms:+.1f} ms to {fmt_ms(event.value_ms)}{hop}."
    if event.kind == "unreachable":
        where = f" Last hop that answered: {event.ttl}" + (f" ({alias(event.addr)})." if event.addr else ".")
        return "The destination stopped answering." + (where if event.ttl else "")
    if event.kind == "recovered":
        return "The destination answers again."
    return event.kind


# --- text and markdown -----------------------------------------------------------------------------------------------


def text_report(analyses: list[Analysis], *, anon: Anonymizer | None = None) -> str:
    _, name, lab = _aliases(anon)
    lines: list[str] = []
    for an in analyses:
        s = summarize(an)
        state = "reachable" if s.reached else "NOT reachable"
        lines.append(
            f"{name(an.target)}: {state}, {s.hops} hops, {fmt_ms(s.rtt_ms)}, {s.runs} runs, {s.routes} route(s)"
        )
        for e in an.events:
            if e.kind != "alternate":
                lines.append(f"  {fmt_time(e.ts)}  {describe(e, alias=lab)}")
    return "\n".join(lines) + "\n"


def markdown(analyses: list[Analysis], *, anon: Anonymizer | None = None) -> str:
    alias, name, lab = _aliases(anon)
    out = [
        "# Path report",
        "",
        "| Target | State | Hops | End-to-end | Runs | Routes | Last route change |",
        "|---|---|---|---|---|---|---|",
    ]
    sums = [summarize(a) for a in analyses]
    for s in sums:
        change = fmt_time(s.last_change) if s.last_change else "-"
        out.append(
            f"| {name(s.target)} | {'reachable' if s.reached else '**not reachable**'} | {s.hops} | {fmt_ms(s.rtt_ms)} "
            f"| {s.runs} | {s.routes} | {change} |"
        )
    for an in analyses:
        out += ["", f"## {name(an.target)}", ""]
        events = [e for e in an.events if e.kind != "alternate"]
        if not events:
            out.append("No route change, latency shift or outage in the period.")
        for e in events:
            out.append(f"- `{fmt_time(e.ts)}` {describe(e, alias=lab)}")
        out += ["", "| Hop | Address | Median | 95th | Lost |", "|---|---|---|---|---|"]
        for h in hop_stats(an):
            addrs = ", ".join(alias(a) for a in h.addrs) or "*"
            note = " (slow to answer)" if h.slow_icmp else ""
            out.append(
                f"| {h.ttl} | {addrs}{note} | {fmt_ms(h.median_ms)} | {fmt_ms(h.p95_ms)} | {h.loss * 100:.0f}% |"
            )
    return "\n".join(out) + "\n"


def to_json(analyses: list[Analysis], *, anon: Anonymizer | None = None) -> str:
    alias, name, lab = _aliases(anon)
    doc = []
    for an in analyses:
        s = summarize(an)
        doc.append(
            {
                "target": name(an.target),
                "reachable": s.reached,
                "runs": s.runs,
                "last": s.last.strftime(ISO),
                "end_to_end_ms": s.rtt_ms,
                "routes": s.routes,
                "route": [[alias(a) for a in hop] for hop in an.route()],
                "hops": [
                    {
                        "ttl": h.ttl,
                        "addresses": [alias(a) for a in h.addrs],
                        "median_ms": h.median_ms,
                        "p95_ms": h.p95_ms,
                        "loss": h.loss,
                        "slow_to_answer": h.slow_icmp,
                    }
                    for h in hop_stats(an)
                ],
                "events": [
                    {
                        "kind": e.kind,
                        "subkind": e.subkind,
                        "start": e.ts.strftime(ISO),
                        "detected": e.detected.strftime(ISO),
                        "hop": e.ttl,
                        "before": [lab(x) for x in e.before],
                        "after": [lab(x) for x in e.after],
                        "delta_ms": e.delta_ms,
                        "address": alias(e.addr) if e.addr else None,
                        "text": describe(e, alias=lab),
                    }
                    for e in an.events
                ],
            }
        )
    return json.dumps(doc, indent=2) + "\n"


# --- HTML ------------------------------------------------------------------------------------------------------------

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#667085;--line:#d9dee7;--accent:#2563eb;--warn:#b45309;--bad:#c0262d;
--ok:#15803d;--ghost:#98a2b3;--node:#eef3ff;--nodeb:#9db7f5}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f141b;--card:#171e28;--fg:#e5e9f0;--muted:#9aa5b5;
--line:#2c3644;--accent:#6ea0ff;--warn:#f0a43a;--bad:#ff6b72;--ok:#4ade80;--ghost:#6b778a;--node:#1d2a44;--nodeb:#3d5a9a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",
Roboto,sans-serif}main{max-width:980px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:18px;margin:0}h3{font-size:13px;text-transform:uppercase;letter-spacing:.06em;
color:var(--muted);margin:20px 0 8px}.sub{color:var(--muted);margin:0 0 20px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:13px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:16px 0}
.card header{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:baseline;justify-content:space-between}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:minmax(0,1fr);gap:0 24px}@media (min-width:860px){.grid{grid-template-columns:1fr 1fr}}
svg{max-width:100%;height:auto;display:block}ul.ev{list-style:none;margin:0;padding:0}ul.ev li{padding:6px 0;
border-bottom:1px solid var(--line);font-size:14px}ul.ev time{color:var(--muted);font-size:12px;display:block}
.tag{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-right:6px}
"""


def _truncate(text: str, width_chars: int) -> str:
    return text if len(text) <= width_chars else text[: max(1, width_chars - 1)] + "…"


def _edges(epoch: Epoch, last: int = 120) -> dict[tuple[tuple[int, str], tuple[int, str]], float]:
    """How often two answers at consecutive hops belong to the same run (silent hops are the node ``*``)."""
    out: dict[tuple[tuple[int, str], tuple[int, str]], float] = {}
    for tr in epoch.traces[-last:]:
        sets = tr.addr_sets()
        for idx in range(len(sets) - 1):
            src = sorted(sets[idx]) or ["*"]
            dst = sorted(sets[idx + 1]) or ["*"]
            for a in src:
                for b in dst:
                    key = ((idx, a), (idx + 1, b))
                    out[key] = out.get(key, 0.0) + 1.0 / (len(src) * len(dst))
    return out


def _sort_key(addr: str) -> tuple[int, int]:
    return (0, 0) if addr == "*" else addr_key(addr)


def ladder_svg(an: Analysis, alias: Alias, name: Alias = lambda x: x) -> str:
    """The route hop by hop: one row per hop, one box per router, lines between the boxes that follow each other in a
    run. The route before the last change is drawn in grey, dashed."""
    cur = an.current
    prev = an.epochs[-2] if len(an.epochs) > 1 else None
    rows_cur = [list(h) or ["*"] for h in an.route(cur)]
    while rows_cur and rows_cur[-1] == ["*"]:
        rows_cur.pop()
    rows_prev = [list(h) or ["*"] for h in an.route(prev)] if prev else []
    while rows_prev and rows_prev[-1] == ["*"]:
        rows_prev.pop()
    n = max(len(rows_cur), len(rows_prev))
    rows: list[list[tuple[str, bool]]] = []  # (address, is_current)
    for i in range(n):
        now = sorted(rows_cur[i] if i < len(rows_cur) else [], key=_sort_key)
        old = sorted((a for a in (rows_prev[i] if i < len(rows_prev) else []) if a not in now), key=_sort_key)
        rows.append([(a, True) for a in now] + [(a, False) for a in old])
    width, row_h, left = 720, 52, 44
    widest = max((len(r) for r in rows), default=1)
    box_w = min(176, (width - left - 8 - (widest - 1) * 10) / widest)
    box_h = 30
    pos: dict[tuple[int, str, bool], tuple[float, float]] = {}
    for i, row in enumerate(rows):
        total = len(row) * box_w + (len(row) - 1) * 10
        x0 = left + (width - left - total) / 2
        for k, (addr, is_cur) in enumerate(row):
            pos[(i, addr, is_cur)] = (x0 + k * (box_w + 10), 18 + i * row_h)
    stats = {s.ttl: s for s in hop_stats(an)}
    parts: list[str] = []
    for source, is_cur in ((prev, False), (cur, True)):
        if source is None:
            continue
        edges = _edges(source)
        top = max(edges.values(), default=1.0)
        for ((i, a), (j, b)), weight in sorted(edges.items()):
            p1 = pos.get((i, a, is_cur)) or pos.get((i, a, not is_cur))
            p2 = pos.get((j, b, is_cur)) or pos.get((j, b, not is_cur))
            if p1 is None or p2 is None:
                continue
            x1, y1 = p1[0] + box_w / 2, p1[1] + box_h
            x2, y2 = p2[0] + box_w / 2, p2[1]
            w = 1 + 3 * weight / top
            style = "stroke:var(--accent)" if is_cur else "stroke:var(--ghost);stroke-dasharray:4 4"
            parts.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" style="{style}" '
                f'stroke-width="{w:.1f}" opacity="{0.9 if is_cur else 0.6}"/>'
            )
    for i, row in enumerate(rows):
        parts.append(
            f'<text x="{left - 12}" y="{18 + i * row_h + 20}" text-anchor="end" class="mono" fill="var(--muted)">{i + 1}</text>'
        )
        for addr, is_cur in row:
            x, y = pos[(i, addr, is_cur)]
            silent = addr == "*"
            shown = "no answer" if silent else alias(addr)
            fill = "var(--card)" if (silent or not is_cur) else "var(--node)"
            stroke = "var(--ghost)" if (silent or not is_cur) else "var(--nodeb)"
            dash = ' stroke-dasharray="4 3"' if (silent or not is_cur) else ""
            st = stats.get(i + 1)
            slow = " (slow to answer)" if (is_cur and st and st.slow_icmp) else ""
            ms = f" - {st.median_ms:.1f} ms" if (is_cur and st and st.median_ms is not None and not silent) else ""
            parts.append(
                f"<g><title>{escape(shown + ms + slow)}</title>"
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{box_w:.1f}" height="{box_h}" rx="6" fill="{fill}" stroke="{stroke}"{dash}/>'
                f'<text x="{x + box_w / 2:.1f}" y="{y + 13:.1f}" text-anchor="middle" class="mono" fill="var(--fg)" opacity="{1 if is_cur else 0.6}">'
                f"{escape(_truncate(shown, int(box_w / 7.4)))}</text>"
                + (
                    f'<text x="{x + box_w / 2:.1f}" y="{y + 25:.1f}" text-anchor="middle" font-size="11" fill="{"var(--warn)" if slow else "var(--muted)"}">'
                    f"{escape(ms[3:] + (' · slow reply' if slow else ''))}</text>"
                    if ms
                    else ""
                )
                + "</g>"
            )
    height = 18 + n * row_h
    legend = ""
    if prev is not None and any(not c for r in rows for _, c in r):
        legend = f'<text x="{left}" y="{height + 6}" font-size="11" fill="var(--muted)">Dashed grey: the route before the last change</text>'
        height += 14
    return (
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Route to {escape(name(an.target))}, hop by hop" '
        f'font-family="system-ui,sans-serif" font-size="12">' + "".join(parts) + legend + "</svg>"
    )


def sparkline_svg(an: Analysis, name: Alias = lambda x: x) -> str:
    """End-to-end time over the whole history, with a line at every route change and a band for every outage."""
    pts = [(t.ts, t.end_to_end()) for t in an.traces]
    vals = [v for _, v in pts if v is not None]
    if len(vals) < 2:
        return '<p class="muted">Not enough runs for a chart yet.</p>'
    t0, t1 = an.traces[0].ts, an.traces[-1].ts
    span = max((t1 - t0).total_seconds(), 1.0)
    ordered = sorted(vals)
    top = ordered[min(len(ordered) - 1, int(0.99 * len(ordered)))] * 1.1
    low = max(0.0, ordered[0] * 0.8)
    w, h, pad = 460, 120, 24

    def px(ts: datetime) -> float:
        return pad + (w - pad - 8) * (ts - t0).total_seconds() / span

    def py(v: float) -> float:
        return h - 18 - (h - 30) * (min(v, top) - low) / max(top - low, 1e-9)

    bands = []
    down: datetime | None = None
    for e in an.events:
        if e.kind == "unreachable":
            down = e.ts
        elif e.kind == "recovered" and down is not None:
            bands.append((down, e.ts))
            down = None
    if down is not None:
        bands.append((down, t1))
    parts = [
        f'<rect x="{px(a):.1f}" y="6" width="{max(px(b) - px(a), 2):.1f}" height="{h - 24}" fill="var(--bad)" opacity="0.18"/>'
        for a, b in bands
    ]
    path = []
    pen = "M"
    for ts, v in pts:
        if v is None:
            pen = "M"
            continue
        path.append(f"{pen}{px(ts):.1f},{py(v):.1f}")
        pen = "L"
    parts.append(f'<path d="{" ".join(path)}" fill="none" stroke="var(--accent)" stroke-width="1.4"/>')
    for e in an.events:
        if e.kind in ("route_change", "latency_shift"):
            colour = "var(--ok)" if e.kind == "route_change" else "var(--warn)"
            parts.append(
                f'<line x1="{px(e.ts):.1f}" y1="6" x2="{px(e.ts):.1f}" y2="{h - 18}" stroke="{colour}" stroke-width="1.5" stroke-dasharray="3 3"/>'
            )
    parts.append(
        f'<text x="{pad - 4}" y="14" text-anchor="end" font-size="10" fill="var(--muted)">{top / 1.1:.0f}</text>'
    )
    parts.append(
        f'<text x="{pad - 4}" y="{h - 18}" text-anchor="end" font-size="10" fill="var(--muted)">{low:.0f}</text>'
    )
    parts.append(f'<text x="{pad}" y="{h - 4}" font-size="10" fill="var(--muted)">{escape(fmt_time(t0))}</text>')
    parts.append(
        f'<text x="{w - 8}" y="{h - 4}" text-anchor="end" font-size="10" fill="var(--muted)">{escape(fmt_time(t1))}</text>'
    )
    legend = (
        '<p class="muted" style="font-size:12px;margin:2px 0 0"><span class="ok">- - -</span> route change &nbsp; '
        '<span class="warn">- - -</span> latency shift &nbsp; <span class="bad">▮</span> destination not answering '
        "&nbsp; (milliseconds)</p>"
    )
    return (
        f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="End-to-end time to {escape(name(an.target))}">'
        + "".join(parts)
        + "</svg>"
        + legend
    )


def _hop_table(stats: list[HopStat], alias: Alias) -> str:
    rows = []
    for h in stats:
        addrs = ", ".join(alias(a) for a in h.addrs) or "no answer"
        flag = (
            ' <span class="warn" title="This hop answers slower than hops after it: a busy router, not a slow path">slow reply</span>'
            if h.slow_icmp
            else ""
        )
        rows.append(
            f'<tr><td class="n">{h.ttl}</td><td class="mono">{escape(addrs)}{flag}</td><td class="n">{fmt_ms(h.median_ms)}</td>'
            f'<td class="n">{fmt_ms(h.p95_ms)}</td><td class="n">{h.loss * 100:.0f}%</td></tr>'
        )
    return (
        '<table><thead><tr><th class="n">Hop</th><th>Address</th><th class="n">Median</th><th class="n">95th</th>'
        '<th class="n">Lost</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table>"
    )


_TAGS = {
    "route_change": ("Route", "ok"),
    "alternate": ("Balanced", "muted"),
    "latency_shift": ("Latency", "warn"),
    "unreachable": ("Down", "bad"),
    "recovered": ("Up", "ok"),
}


def _events_list(events: list[Event], lab: Alias) -> str:
    shown = [e for e in events if e.kind != "alternate"]
    if not shown:
        return '<p class="muted">No route change, latency shift or outage in this period.</p>'
    items = []
    for e in reversed(shown):
        tag, cls = _TAGS[e.kind]
        items.append(
            f'<li><time datetime="{e.ts.strftime(ISO)}">{escape(fmt_time(e.ts))}</time>'
            f'<span class="tag {cls}">{tag}</span>{escape(describe(e, alias=lab))}</li>'
        )
    return '<ul class="ev">' + "".join(items) + "</ul>"


def html_page(
    analyses: list[Analysis],
    *,
    title: str = "Path report",
    since: datetime | None = None,
    anon: Anonymizer | None = None,
    now: datetime | None = None,
) -> str:
    alias, name, lab = _aliases(anon)
    sums = [summarize(a) for a in analyses]
    stamp = (now or datetime.now(UTC)).strftime(SHORT) + " UTC"
    head_rows = []
    for i, s in enumerate(sums):
        state = '<span class="pill ok">reachable</span>' if s.reached else '<span class="pill bad">not reachable</span>'
        head_rows.append(
            f'<tr><td><a href="#t-{i}" style="color:inherit">{escape(name(s.target))}</a></td><td>{state}</td>'
            f'<td class="n">{s.hops}</td><td class="n">{fmt_ms(s.rtt_ms)}</td><td class="n">{s.runs}</td>'
            f'<td class="n">{s.routes}</td><td>{escape(fmt_time(s.last_change)) if s.last_change else "-"}</td></tr>'
        )
    cards = []
    for i, (an, s) in enumerate(zip(analyses, sums, strict=True)):
        state = '<span class="pill ok">reachable</span>' if s.reached else '<span class="pill bad">not reachable</span>'
        shown = an.events if since is None else [e for e in an.events if e.ts >= since]
        cards.append(
            f'<section class="card" id="t-{i}"><header><h2>{escape(name(s.target))}</h2>'
            f'<span>{state} <span class="muted">· {s.hops} hops · {fmt_ms(s.rtt_ms)} · {s.runs} runs · '
            f"{s.routes} route{'s' if s.routes != 1 else ''}</span></span></header>"
            '<div class="grid"><div><h3>Route now</h3>' + ladder_svg(an, alias, name) + "</div>"
            "<div><h3>End-to-end time</h3>"
            + sparkline_svg(an, name)
            + "<h3>What changed</h3>"
            + _events_list(shown, lab)
            + "</div></div>"
            "<h3>Hops</h3>" + _hop_table(hop_stats(an), alias) + "</section>"
        )
    period = f" since {escape(fmt_time(since))}" if since else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        f"<title>{escape(title)}</title><style>{CSS}</style></head><body><main>"
        f'<h1>{escape(title)}</h1><p class="sub">Generated {escape(stamp)}{period}. {len(analyses)} target(s).</p>'
        '<div class="card"><table><thead><tr><th>Target</th><th>State</th><th class="n">Hops</th><th class="n">End-to-end</th>'
        '<th class="n">Runs</th><th class="n">Routes</th><th>Last route change</th></tr></thead><tbody>'
        + "".join(head_rows)
        + "</tbody></table></div>"
        + "".join(cards)
        + "</main></body></html>"
    )
