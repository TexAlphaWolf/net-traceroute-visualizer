"""Measure pathmap against a simulated network whose changes are known, and against the real traceroute of this machine.

    python tools/evaluate.py                  # full run (about a minute), prints a summary
    python tools/evaluate.py --quick          # smaller sets, used in CI
    python tools/evaluate.py --out docs/report.json

Sections: parse (text of three kinds of traceroute -> Trace), pipeline (route changes, load balancing, latency and
outages found against the injected truth, with two naive baselines), sweep (the effect of the ``confirm`` setting), cost
(time and disk), real (the traceroute program of this machine on the loopback).

Seeds: the defaults of pathmap were set while looking at seeds 1 to 5; this script uses other seeds (100 and up), which
were not looked at before the numbers were produced.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

import netsim  # noqa: E402
from pathmap import render  # noqa: E402
from pathmap.analysis import Params, analyze, hop_stats, median  # noqa: E402
from pathmap.model import Trace, utcnow  # noqa: E402
from pathmap.parse import parse  # noqa: E402
from pathmap.probe import run_trace  # noqa: E402
from pathmap.store import Store  # noqa: E402

SEED = 1000
ROUTE_KINDS = ("reroute", "longer", "shorter")


def rnd(ts) -> int:
    return round((ts - netsim.T0) / netsim.STEP)


def make_set(seed0: int, count: int, rounds: int, *, events: bool, decoy_every: int = 4):
    out = []
    for i in range(count):
        rng = random.Random(seed0 + i)
        sc = netsim.make_scenario(rng, i, rounds, events=events, decoy=(i % decoy_every == 0))
        out.append((sc, sc.run(rng)))
    return out


# --- parse -----------------------------------------------------------------------------------------------------------


def section_parse(quick: bool) -> dict[str, object]:
    n = 300 if quick else 3000
    rng = random.Random(SEED)
    counts = Counter()
    t_all = 0.0
    for i in range(n):
        sc = netsim.make_scenario(rng, i % 200, 3, events=False, decoy=(i % 3 == 0))
        trace = sc.path.trace(rng, netsim.T0, loss=0.05)
        for fmt, text in (
            ("unix", netsim.render_unix(trace)),
            ("unix_names", netsim.render_unix(trace, names=True)),
            ("windows", netsim.render_windows(trace)),
        ):
            t0 = time.perf_counter()
            got = parse(text, trace.target, trace.ts)
            t_all += time.perf_counter() - t0
            counts[f"{fmt}_total"] += 1
            if fmt.startswith("unix"):
                same = got == trace
            else:
                same = len(got.hops) == len(trace.hops) and got.reached == trace.reached
                for a, b in zip(got.hops, trace.hops, strict=True):
                    last = next((p.addr for p in reversed(b.probes) if p.addr), None)
                    want = [
                        None if p.addr is None else (1.0 if (p.rtt or 0) < 1 else float(round(p.rtt or 0)))
                        for p in b.probes
                    ]
                    have = [None if p.addr is None else p.rtt for p in a.probes]
                    same = same and a.addrs == (frozenset([last]) if last else frozenset()) and have == want
            counts[f"{fmt}_same"] += int(same)
    return {
        "traces": n,
        **{k: counts[k] for k in sorted(counts)},
        "parse_ms_each": round(t_all / (3 * n) * 1000, 4),
    }


# --- pipeline --------------------------------------------------------------------------------------------------------


def naive_alerts(traces: list[Trace]) -> tuple[list[int], list[int]]:
    """Positions where comparing a run with the previous one says "changed": (a) the first answering address of every
    hop, stars included, as in a plain diff of two outputs; (b) the sets of addresses, stars ignored."""
    a_list, b_list = [], []

    def sig_a(t: Trace):
        return tuple(next((p.addr for p in h.probes if p.addr), "*") for h in t.hops)

    for i in range(1, len(traces)):
        if sig_a(traces[i]) != sig_a(traces[i - 1]):
            a_list.append(i)
        x, y = traces[i].addr_sets(), traces[i - 1].addr_sets()
        differ = len(x) != len(y) or any(p and q and p != q for p, q in zip(x, y, strict=False))
        if differ:
            b_list.append(i)
    return a_list, b_list


def naive_culprit(traces: list[Trace], start: int) -> int | None:
    """The hop with the biggest jump over the previous hop in the median times after ``start`` (how people read it)."""
    meds: dict[int, float] = {}
    per: dict[int, list[float]] = {}
    for t in traces[start : start + 20]:
        for i, h in enumerate(t.hops):
            if h.rtts:
                per.setdefault(i, []).append(median(h.rtts))
    for i, v in per.items():
        meds[i] = median(v)
    best, prev, culprit = -1e9, 0.0, None
    for i in sorted(meds):
        if meds[i] - prev > best:
            best, culprit = meds[i] - prev, i + 1
        prev = meds[i]
    return culprit


def take(events: list, pred):
    """Remove from ``events`` and return the first one that satisfies ``pred`` (None if there is none)."""
    for e in events:
        if pred(e):
            events.remove(e)
            return e
    return None


def score(items, params: Params, leftovers: list | None = None) -> dict[str, object]:
    c = Counter()
    delays: dict[str, list[int]] = {}
    delta_err: list[float] = []
    naive_total = Counter()
    for sc, traces in items:
        an = analyze(sc.path.target, traces, params)
        events = list(an.events)

        a_alerts, b_alerts = naive_alerts(traces)
        naive_total["a"] += len(a_alerts)
        naive_total["b"] += len(b_alerts)
        for t in sc.truth:
            c[f"truth_{t.kind}"] += 1
            if t.kind in ROUTE_KINDS:
                e = take(events, lambda e, t=t: e.kind == "route_change" and abs(rnd(e.ts) - t.round) <= 2)
                if e:
                    c["found_route"] += 1
                    c[f"found_{t.kind}"] += 1
                    c["subkind_ok"] += int(e.subkind == t.kind)
                    c["ttl_ok"] += int(e.ttl == t.ttl)
                    c["ttl_within_1"] += int(e.ttl is not None and t.ttl is not None and abs(e.ttl - t.ttl) <= 1)
                    delays.setdefault("route", []).append(rnd(e.detected) - t.round)
                if any(t.round - 1 <= i <= t.round + 2 for i in b_alerts):
                    c["naive_b_found_route"] += 1
            elif t.kind == "grow":
                e = take(
                    events,
                    lambda e, t=t: (
                        e.kind == "route_change" and e.ttl == t.ttl and t.round - 2 <= rnd(e.ts) <= t.round + 12
                    ),
                )
                if e:
                    c["found_grow_as_change"] += 1
                    c["found_grow"] += 1
                    c["grow_ttl_ok"] += 1
                    delays.setdefault("grow", []).append(rnd(e.detected) - t.round)
                else:
                    e = take(events, lambda e, t=t: e.kind == "alternate" and e.addr == t.addr)
                    if e:
                        c["found_grow_as_alternate"] += 1
                        c["found_grow"] += 1
                        delays.setdefault("grow", []).append(rnd(e.detected) - t.round)
            elif t.kind == "shrink":
                e = take(
                    events,
                    lambda e, t=t: (
                        e.kind == "route_change"
                        and e.subkind == "unbalanced"
                        and e.ttl == t.ttl
                        and t.round - 12 <= rnd(e.ts) <= t.round + 3
                    ),
                )
                if e:
                    c["found_shrink"] += 1
                    delays.setdefault("shrink", []).append(rnd(e.detected) - t.round)
            elif t.kind == "latency":
                e = take(events, lambda e, t=t: e.kind == "latency_shift" and abs(rnd(e.ts) - t.round) <= 3)
                size = "small" if t.extra_ms < 25 else "medium" if t.extra_ms < 50 else "large"
                c[f"truth_latency_{size}"] += 1
                if e:
                    c[f"found_latency_{size}"] += 1
                    c["found_latency"] += 1
                    c["latency_ttl_ok"] += int(e.ttl == t.ttl)
                    delays.setdefault("latency", []).append(rnd(e.detected) - t.round)
                    delta_err.append(abs((e.delta_ms or 0) - t.extra_ms) / t.extra_ms)
                c["latency_naive_ttl_ok"] += int(naive_culprit(traces, t.round + 8) == t.ttl)
            elif t.kind == "outage":
                e = take(events, lambda e, t=t: e.kind == "unreachable" and abs(rnd(e.ts) - t.round) <= 2)
                if e:
                    c["found_outage"] += 1
                    c["outage_ttl_ok"] += int(e.ttl == t.ttl)
                    delays.setdefault("outage", []).append(rnd(e.detected) - t.round)
                r = take(events, lambda e, t=t: e.kind == "recovered" and abs(rnd(e.ts) - (t.round + t.length)) <= 2)
                c["found_recovery"] += int(r is not None)
        for e in events:
            if leftovers is not None:
                leftovers.append((sc, e))
            if e.kind == "alternate":
                c["alternate_without_truth"] += 1
            else:
                c[f"false_{e.kind}"] += 1
        c["runs"] += len(traces)
        c["targets"] += 1
        hs = hop_stats(an)
        slow_addrs = {r.addr for st in sc.path.stages for r in st.routers if r.slow > 0}
        visible_decoy = set()  # slow routers that are clearly slower than some hop after them (20 ms or more)
        for idx, st in enumerate(sc.path.stages):
            for r in st.routers:
                if r.slow > 0:
                    mine = sc.path.cumulative(idx) + r.offset + r.slow
                    later = [sc.path.cumulative(j) + 0.3 for j in range(idx + 1, len(sc.path.stages))]
                    if later and mine - min(later) >= 20.0:
                        visible_decoy.add(r.addr)
        for s_ in hs:
            is_slow = any(a in slow_addrs for a in s_.addrs)
            c["hops"] += 1
            c["decoy_hops"] += int(is_slow)
            c["decoy_visible"] += int(any(a in visible_decoy for a in s_.addrs))
            c["decoy_visible_flagged"] += int(any(a in visible_decoy for a in s_.addrs) and s_.slow_icmp)
            c["normal_flagged"] += int((not is_slow) and s_.slow_icmp)
    out: dict[str, object] = dict(c)
    out["naive_a_alerts"] = naive_total["a"]
    out["naive_b_alerts"] = naive_total["b"]
    out["delay_runs_median"] = {k: statistics.median(v) for k, v in delays.items()}
    out["delay_runs_max"] = {k: max(v) for k, v in delays.items()}
    out["latency_delta_error_median"] = round(statistics.median(delta_err), 3) if delta_err else None
    return out


def section_pipeline(quick: bool) -> dict[str, object]:
    count, rounds, quiet_count = (12, 300, 8) if quick else (40, 400, 20)
    ev_items = make_set(SEED, count, rounds, events=True)
    qt_items = make_set(SEED + 1000, quiet_count, rounds, events=False)
    with_events = score(ev_items, Params())
    quiet = score(qt_items, Params())
    a_q, b_q = 0, 0
    for _, traces in qt_items:
        a, b = naive_alerts(traces)
        a_q += len(a)
        b_q += len(b)
    truth_route = sum(with_events.get(f"truth_{k}", 0) for k in (*ROUTE_KINDS, "grow", "shrink"))  # type: ignore[misc]
    return {
        "targets_with_events": count,
        "targets_quiet": quiet_count,
        "rounds_per_target": rounds,
        "interval_minutes": int(netsim.STEP.total_seconds() // 60),
        "with_events": with_events,
        "quiet": quiet,
        "quiet_naive_a_alerts": a_q,
        "quiet_naive_b_alerts": b_q,
        "quiet_comparisons": quiet["runs"] - quiet["targets"],  # type: ignore[operator]
        "truth_route_events": truth_route,
    }


# --- sweep -----------------------------------------------------------------------------------------------------------


def section_sweep(quick: bool) -> dict[str, object]:
    count, rounds, quiet_count = (8, 300, 6) if quick else (24, 400, 12)
    ev_items = make_set(SEED + 2000, count, rounds, events=True)
    qt_items = make_set(SEED + 3000, quiet_count, rounds, events=False)
    rows = []
    for confirm in (1, 2, 3, 4, 5):
        p = Params(confirm=confirm)
        ev = score(ev_items, p)
        q = score(qt_items, p)
        found = sum(ev.get(k, 0) for k in ("found_reroute", "found_longer", "found_shorter"))  # type: ignore[misc]
        truth = sum(ev.get(k, 0) for k in ("truth_reroute", "truth_longer", "truth_shorter"))  # type: ignore[misc]
        false = ev.get("false_route_change", 0) + q.get("false_route_change", 0)  # type: ignore[operator]
        blips = ev.get("truth_blip", 0)
        rows.append(
            {
                "confirm": confirm,
                "found": found,
                "truth": truth,
                "false_route_changes": false,
                "blips": blips,
                "delay_runs_median": ev["delay_runs_median"].get("route"),  # type: ignore[union-attr]
            }
        )
    return {"rows": rows}


# --- cost ------------------------------------------------------------------------------------------------------------


def section_cost(quick: bool) -> dict[str, object]:
    targets, rounds = (20, 300) if quick else (100, 1000)
    rng = random.Random(SEED + 4000)
    sets = []
    for i in range(targets):
        sc = netsim.make_scenario(rng, i, rounds, events=True)
        sets.append((sc.path.target, sc.run(rng)))
    t0 = time.perf_counter()
    analyses = [analyze(name, traces) for name, traces in sets]
    t_analyze = time.perf_counter() - t0
    t0 = time.perf_counter()
    html = render.html_page(analyses)
    t_html = time.perf_counter() - t0
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp))
        t0 = time.perf_counter()
        for _, traces in sets:
            for t in traces:
                store.append(t)
        t_write = time.perf_counter() - t0
        size = store.size_bytes()
        t0 = time.perf_counter()
        for name, _ in sets:
            store.read(name)
        t_read = time.perf_counter() - t0
    runs = targets * rounds
    per_run = size / runs
    return {
        "targets": targets,
        "rounds": rounds,
        "runs": runs,
        "analyze_s": round(t_analyze, 3),
        "analyze_ms_per_target": round(t_analyze / targets * 1000, 2),
        "html_s": round(t_html, 3),
        "html_kib": round(len(html.encode()) / 1024, 1),
        "write_s": round(t_write, 3),
        "read_s": round(t_read, 3),
        "bytes_per_run": round(per_run, 1),
        "kib_per_target_year_5min": round(per_run * 288 * 365 / 1024, 0),
    }


# --- real ------------------------------------------------------------------------------------------------------------


def section_real(quick: bool) -> dict[str, object]:
    exe = "tracert" if platform.system() == "Windows" else "traceroute"
    if shutil.which(exe) is None:
        return {"available": False, "program": exe}
    times, last = [], None
    for _ in range(3 if quick else 10):
        t0 = time.perf_counter()
        try:
            last = run_trace("127.0.0.1", max_hops=5, queries=3, wait=1.0)
        except Exception as exc:
            return {"available": True, "program": exe, "error": str(exc)[:100]}
        times.append(time.perf_counter() - t0)
    assert last is not None
    ver = (
        subprocess.run([exe, "--version"], capture_output=True, text=True, check=False) if exe == "traceroute" else None
    )
    return {
        "available": True,
        "program": exe,
        "version": (ver.stdout or ver.stderr).strip().splitlines()[0][:60]
        if ver and (ver.stdout or ver.stderr)
        else "",
        "runs": len(times),
        "hops": len(last.hops),
        "reached": last.reached,
        "run_ms_median": round(statistics.median(times) * 1000, 1),
        "rtt_ms": last.end_to_end(),
        "when": utcnow().strftime("%Y-%m-%d"),
    }


SECTIONS = {
    "parse": section_parse,
    "pipeline": section_pipeline,
    "sweep": section_sweep,
    "cost": section_cost,
    "real": section_real,
}


def summary(rep: dict[str, object]) -> list[str]:
    lines: list[str] = []
    if "parse" in rep:
        p = rep["parse"]
        lines.append(
            f"parsed identically: unix {p['unix_same']} of {p['unix_total']}, with names "  # type: ignore[index]
            f"{p['unix_names_same']} of {p['unix_names_total']}, windows {p['windows_same']} of {p['windows_total']}"  # type: ignore[index]
        )
    if "pipeline" in rep:
        pl = rep["pipeline"]
        e, q = pl["with_events"], pl["quiet"]  # type: ignore[index]
        route_found = sum(e.get(f"found_{k}", 0) for k in (*ROUTE_KINDS, "grow", "shrink"))
        lines.append(f"route changes found: {route_found} of {pl['truth_route_events']}")  # type: ignore[index]
        lines.append(
            f"false alarms: {e.get('false_route_change', 0) + q.get('false_route_change', 0)} route, "
            f"{e.get('false_latency_shift', 0) + q.get('false_latency_shift', 0)} latency"
        )
        lines.append(
            f"false alarms in quiet runs: {sum(q.get(k, 0) for k in ('false_route_change', 'false_latency_shift', 'false_unreachable', 'false_recovered'))} of {q['runs']}"
        )
        lines.append(
            f"naive alerts in quiet runs: {pl['quiet_naive_a_alerts']} and {pl['quiet_naive_b_alerts']} of {pl['quiet_comparisons']}"
        )  # type: ignore[index]
        lines.append(
            f"latency shifts found: {e.get('found_latency', 0)} of {e.get('truth_latency', 0)}, hop right {e.get('latency_ttl_ok', 0)}"
        )
        lines.append(f"outages found: {e.get('found_outage', 0)} of {e.get('truth_outage', 0)}")
    if "real" in rep:
        r = rep["real"]
        lines.append(
            f"real traceroute: {r if not r.get('available') else str(r.get('hops')) + ' hop, reached ' + str(r.get('reached'))}"
        )  # type: ignore[attr-defined]
    return lines


def check(rep: dict[str, object]) -> list[str]:
    """What must hold for the numbers to be believed; the CI job fails on any of these."""
    bad: list[str] = []
    if "parse" in rep:
        p = rep["parse"]
        for fmt in ("unix", "unix_names", "windows"):
            if p[f"{fmt}_same"] != p[f"{fmt}_total"]:  # type: ignore[index]
                bad.append(f"parse: {fmt} read back differently")
    if "pipeline" in rep:
        pl = rep["pipeline"]
        e, q = pl["with_events"], pl["quiet"]  # type: ignore[index]
        found = sum(e.get(f"found_{k}", 0) for k in (*ROUTE_KINDS, "grow", "shrink"))
        if found < 0.95 * pl["truth_route_events"]:  # type: ignore[index]
            bad.append(f"pipeline: only {found} of {pl['truth_route_events']} route changes found")  # type: ignore[index]
        false = sum(
            x.get(k, 0)
            for x in (e, q)
            for k in ("false_route_change", "false_latency_shift", "false_unreachable", "false_recovered")
        )
        if false > 1:
            bad.append(f"pipeline: {false} false alarms")
        if e.get("found_outage", 0) != e.get("truth_outage", 0):
            bad.append("pipeline: an outage was missed")
        if e.get("normal_flagged", 0) or q.get("normal_flagged", 0):
            bad.append("pipeline: a normal hop was called slow")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", default=",".join(SECTIONS))
    ap.add_argument("--out", type=Path)
    ap.add_argument("--check", action="store_true", help="exit 1 if the numbers break the expectations")
    args = ap.parse_args()
    rep: dict[str, object] = {
        "environment": {
            "python": platform.python_version(),
            "system": f"{platform.system()} {platform.machine()}",
            "quick": args.quick,
            "seed": SEED,
        }
    }
    for name in args.only.split(","):
        t0 = time.perf_counter()
        rep[name] = SECTIONS[name](args.quick)
        print(f"[{name}] {time.perf_counter() - t0:.1f} s", file=sys.stderr)
    for line in summary(rep):
        print(line)
    if args.out:
        args.out.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    if args.check:
        problems = check(rep)
        for line in problems:
            print(f"CHECK FAILED: {line}", file=sys.stderr)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
