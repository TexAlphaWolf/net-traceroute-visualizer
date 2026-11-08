"""Command line: trace, watch, parse, changes, show, report, status."""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import __version__, render
from .analysis import Analysis, Params, analyze, hop_stats
from .model import Trace, check_target, utcnow
from .parse import ParseError, parse
from .probe import METHODS, TraceError, run_trace
from .store import Store

_DURATION = re.compile(r"^(\d{1,6})([smhd])$")


class UsageError(Exception):
    """A mistake in the command line: reported in one line, exit code 2."""


def parse_duration(text: str) -> timedelta:
    m = _DURATION.match(text)
    if not m:
        raise UsageError(f"not a duration (use 30s, 15m, 12h or 7d): {text[:20]!r}")
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    return timedelta(seconds=int(m.group(1)) * unit)


def _targets(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        try:
            t = check_target(v)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        if t not in out:
            out.append(t)
    return out


def _analyses(store: Store, targets: list[str], confirm: int) -> list[Analysis]:
    params = Params(confirm=confirm)
    names = targets or store.targets()
    out: list[Analysis] = []
    for name in names:
        traces, skipped = store.read(name)
        if skipped:
            print(f"{name}: skipped {skipped} damaged line(s) in the history", file=sys.stderr)
        if traces:
            out.append(analyze(name, traces, params))
        elif targets:
            raise UsageError(f"no history for {name} in {store.root}")
    if not out:
        raise UsageError(f"nothing recorded yet in {store.root}: run 'pathmap trace TARGET' first")
    return out


def _summary_line(trace: Trace) -> str:
    rtt = trace.end_to_end()
    state = "reached" if trace.reached else "NOT reached"
    return f"{len(trace.addr_sets())} hops, {state}" + (f", {rtt:.1f} ms" if rtt is not None else "")


def _trace_all(targets: list[str], args: argparse.Namespace, store: Store) -> int:
    def one(target: str) -> tuple[str, Trace | str]:
        try:
            return target, run_trace(
                target, max_hops=args.max_hops, queries=args.queries, wait=args.wait, method=args.method
            )
        except TraceError as exc:
            return target, str(exc)

    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, len(targets)))) as pool:
        results = list(pool.map(one, targets))
    failed = 0
    for target, result in results:
        if isinstance(result, str):
            failed += 1
            print(f"{target}: ERROR {result}")
        else:
            store.append(result)
            print(f"{target}: {_summary_line(result)}")
    return 1 if failed else 0


def cmd_trace(args: argparse.Namespace) -> int:
    return _trace_all(_targets(args.targets), args, Store(Path(args.data)))


def cmd_watch(args: argparse.Namespace) -> int:
    targets = _targets(args.targets)
    store = Store(Path(args.data))
    interval = parse_duration(args.interval).total_seconds()
    if interval < 10:
        raise UsageError("the interval must be at least 10s")
    done = 0
    problems = 0
    try:
        while args.rounds == 0 or done < args.rounds:
            started = time.monotonic()
            problems += _trace_all(targets, args, store)
            done += 1
            if args.rounds and done >= args.rounds:
                break
            time.sleep(max(0.0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print("stopped", file=sys.stderr)
    return 1 if problems else 0


def cmd_parse(args: argparse.Namespace) -> int:
    text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8", errors="replace")
    target = _targets([args.target])[0]
    try:
        ts = datetime.fromisoformat(args.time) if args.time else utcnow()
    except ValueError:
        raise UsageError("--time must look like 2026-10-01T12:30:00Z") from None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    try:
        trace = parse(text, target, ts)
    except ParseError as exc:
        print(f"cannot read it: {exc}", file=sys.stderr)
        return 1
    print(f"{target}: {_summary_line(trace)}")
    if args.store:
        Store(Path(args.data)).append(trace)
        print(f"added to {args.data}")
    return 0


def cmd_changes(args: argparse.Namespace) -> int:
    store = Store(Path(args.data))
    since = parse_duration(args.since) if args.since else None
    analyses = _analyses(store, _targets(args.targets), args.confirm)
    cutoff = utcnow() - since if since else None
    shown = 0
    for an in analyses:
        events = [e for e in an.events if e.kind != "alternate" and (cutoff is None or e.ts >= cutoff)]
        for e in events:
            print(f"{an.target}  {render.fmt_time(e.ts)}  {render.describe(e)}")
        shown += len(events)
    if not shown:
        print("no change in the period")
    return 1 if (args.fail_on_change and shown) else 0


def cmd_show(args: argparse.Namespace) -> int:
    (target,) = _targets([args.target])
    an = _analyses(Store(Path(args.data)), [target], args.confirm)[0]
    last = an.last
    print(
        f"{target}: {_summary_line(last)}; last run {render.fmt_time(last.ts)}; {len(an.epochs)} route(s) in the history"
    )
    print(f"{'hop':>3}  {'address':<40} {'median':>9} {'95th':>9} {'lost':>5}")
    for h in hop_stats(an):
        addrs = ", ".join(h.addrs) or "no answer"
        note = "  slow to answer" if h.slow_icmp else ""
        print(
            f"{h.ttl:>3}  {addrs:<40} {render.fmt_ms(h.median_ms):>9} {render.fmt_ms(h.p95_ms):>9} {h.loss * 100:>4.0f}%{note}"
        )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = Store(Path(args.data))
    since = parse_duration(args.since) if args.since else None
    analyses = _analyses(store, _targets(args.targets), args.confirm)
    anon = None
    if args.anonymize:
        try:
            key = bytes.fromhex(args.anon_key) if args.anon_key else None
        except ValueError:
            raise UsageError("--anon-key must be hexadecimal") from None
        anon = render.Anonymizer(key)
    cutoff = utcnow() - since if since else None
    if args.format == "html":
        body = render.html_page(analyses, since=cutoff, anon=anon)
    elif args.format == "md":
        body = render.markdown(analyses, anon=anon)
    elif args.format == "json":
        body = render.to_json(analyses, anon=anon)
    else:
        body = render.text_report(analyses, anon=anon)
    if args.out:
        Path(args.out).write_text(body, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(body)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    store = Store(Path(args.data))
    stale = parse_duration(args.stale)
    analyses = _analyses(store, _targets(args.targets), args.confirm)
    now = utcnow()
    bad = 0
    for an in analyses:
        s = render.summarize(an)
        notes = []
        if not s.reached:
            notes.append("NOT reached")
        if now - s.last > stale:
            notes.append(f"STALE (last run {render.fmt_time(s.last)})")
        bad += bool(notes)
        print(
            f"{s.target}: {render.fmt_ms(s.rtt_ms)}, {s.hops} hops, {s.routes} route(s)"
            + (f"  <-- {', '.join(notes)}" if notes else "")
        )
    return 1 if bad else 0


def _add_trace_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("targets", nargs="+", help="IP addresses or host names")
    p.add_argument("--max-hops", type=int, default=30)
    p.add_argument("--queries", type=int, default=3, help="probes per hop (Linux and macOS; Windows always sends 3)")
    p.add_argument("--wait", type=float, default=2.0, help="seconds to wait for each probe")
    p.add_argument("--method", choices=METHODS, default="udp", help="udp (default), icmp or tcp (Linux)")
    p.add_argument("--workers", type=int, default=4, help="targets traced at the same time")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pathmap", description="Repeated traceroutes, route history and a change report.")
    ap.add_argument("--version", action="version", version=f"pathmap {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser, *, many: bool = True) -> None:
        p.add_argument("--data", default="pathmap-data", help="directory of the history (default: pathmap-data)")
        p.add_argument(
            "--confirm", type=int, default=3, help="runs in a row that must disagree to call it a route change"
        )
        if many:
            p.add_argument("targets", nargs="*", help="limit to these targets (default: all)")

    p = sub.add_parser("trace", help="trace the targets once and store the result")
    _add_trace_options(p)
    p.add_argument("--data", default="pathmap-data")
    p.set_defaults(fn=cmd_trace)

    p = sub.add_parser("watch", help="trace the targets again and again")
    _add_trace_options(p)
    p.add_argument("--data", default="pathmap-data")
    p.add_argument("--interval", default="5m", help="time between rounds, e.g. 30s, 5m, 1h (default 5m)")
    p.add_argument("--rounds", type=int, default=0, help="stop after this many rounds (default: never)")
    p.set_defaults(fn=cmd_watch)

    p = sub.add_parser("parse", help="read a saved traceroute or tracert output")
    p.add_argument("file", help="file with the output, or - for standard input")
    p.add_argument("--target", required=True, help="what was traced (an address or a name)")
    p.add_argument("--time", help="when it was run, e.g. 2026-10-01T12:30:00Z (default: now)")
    p.add_argument("--store", action="store_true", help="add it to the history")
    p.add_argument("--data", default="pathmap-data")
    p.set_defaults(fn=cmd_parse)

    p = sub.add_parser("changes", help="list route changes, latency shifts and outages")
    common(p)
    p.add_argument("--since", help="only the last 7d, 12h ...")
    p.add_argument("--fail-on-change", action="store_true", help="exit 1 if there is anything to list")
    p.set_defaults(fn=cmd_changes)

    p = sub.add_parser("show", help="the current route to one target, hop by hop")
    common(p, many=False)
    p.add_argument("target")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("report", help="write a report")
    common(p)
    p.add_argument("--format", choices=("html", "md", "json", "text"), default="html")
    p.add_argument("--out", help="file to write (default: standard output)")
    p.add_argument("--since", help="list only the events of the last 7d, 12h ...")
    p.add_argument(
        "--anonymize", action="store_true", help="replace addresses and names with labels (to publish a report)"
    )
    p.add_argument("--anon-key", help="hexadecimal key: the same labels in every report (default: random)")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("status", help="one line per target; exit 1 if one is down or not traced lately")
    common(p)
    p.add_argument("--stale", default="1d", help="no run for this long is a problem (default 1d)")
    p.set_defaults(fn=cmd_status)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args))
    except UsageError as exc:
        print(f"pathmap: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"pathmap: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"pathmap: {exc.strerror or 'file error'}: {exc.filename}", file=sys.stderr)
        return 2
