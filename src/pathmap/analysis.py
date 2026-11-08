"""From a list of traces to route changes, latency shifts and outages.

A route is not one list of addresses. A router that does not answer shows ``*`` in some runs and its address in
others; a load balancer (ECMP) sends probes of the same run through different routers; one run can differ from the
rest for a moment and come back. Comparing a run with the previous one reports all of that as "the route changed".

What is done here instead:

* An **epoch** is a period with one route. It knows every address seen at each hop (*known*).
* A run **conforms** to the epoch when every address it shows is known at that hop. A silent hop matches anything.
* A run that does not conform is held back. If ``confirm`` runs in a row do not conform, the route changed: a new epoch
  starts at the first of them. If a conforming run comes first, it was a blip.
* An address that appears in ``alt_runs`` separate blips is a load-balancing alternate: it is added to *known* and
  reported once as an ``alternate``, not as a route change.
* A known address that stops appearing while its hop keeps answering through other addresses, long enough that
  chance is very unlikely (the evidence is computed from how often the address used to show up), means a member left a
  load-balancing group: a route change of kind ``unbalanced``.
* Latency is judged on the end-to-end time, with medians. The hop where it started is the first one after which all
  the following hops moved by about the same amount; a single slow hop in the middle is a router that answers slowly,
  not a slow path.
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .model import Trace

INHERIT_ANSWERS = 150.0  # answers per hop that a new epoch keeps from the one before it


@dataclass(frozen=True)
class Params:
    confirm: int = 3  # runs in a row that must disagree before a route change is reported
    warmup: int = 8  # runs at the start of an epoch used only to learn which addresses belong to it (24 answers show a
    # member that takes a third of the traffic with a 99.98% chance)
    alt_runs: int = 3  # separate blips an address needs to be accepted as a load-balancing alternate
    share: float = 0.1  # an address belongs to the route of an epoch if it made this share of the answers at its hop
    vanish_runs: int = 6  # runs an address must be missing before we look at whether that is a coincidence
    vanish_evidence: float = (
        13.8  # -ln(p): the chance of the absence under unchanged load balancing must be below e^-13.8
    )
    lat_window: int = 5  # runs in the "now" window of the latency test
    lat_base: int = 20  # runs of the reference window
    lat_min_ms: float = 8.0  # smallest shift worth reporting
    lat_rel: float = 0.1  # ... or this share of the usual time, if larger
    lat_noise_k: float = 4.0  # ... or this many robust standard deviations of the reference window, if larger
    outage_confirm: int = 3  # runs in a row without an answer from the destination

    def __post_init__(self) -> None:
        if min(self.confirm, self.warmup, self.alt_runs, self.outage_confirm, self.vanish_runs) < 1:
            raise ValueError("confirm, warmup, alt_runs, outage_confirm and vanish_runs must be at least 1")
        if not 0 < self.share <= 1:
            raise ValueError("share must be in (0, 1]")
        if self.lat_window < 3 or self.lat_base < 5:
            raise ValueError("lat_window must be at least 3 and lat_base at least 5")


@dataclass(frozen=True)
class Event:
    """Something worth telling a person.

    kind: route_change | alternate | latency_shift | unreachable | recovered
    subkind (route_change): reroute | longer | shorter | balanced | unbalanced
    ts: when it started; detected: the time of the run that confirmed it
    ttl: first hop that differs (route_change), hop where the extra time starts (latency_shift), last hop that answered
    (unreachable), hop of the new address (alternate)
    """

    kind: str
    target: str
    ts: datetime
    detected: datetime
    ttl: int | None = None
    subkind: str = ""
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()
    delta_ms: float | None = None
    value_ms: float | None = None
    addr: str | None = None


@dataclass
class Epoch:
    """A period with one route. ``traces`` are the runs that belong to it, in time order."""

    start: datetime
    traces: list[Trace] = field(default_factory=list)
    end: datetime | None = None
    known: dict[int, set[str]] = field(default_factory=dict)
    counts: dict[int, dict[str, float]] = field(default_factory=dict)  # answers per hop index and address
    answered: dict[int, float] = field(default_factory=dict)  # answers per hop index
    last_seen: dict[tuple[int, str], int] = field(default_factory=dict)  # position in ``traces``
    alt_seen: Counter[tuple[int, str]] = field(default_factory=Counter)
    prior: dict[int, set[str]] = field(default_factory=dict)  # what the epoch before knew: a way back, not news
    stale: dict[tuple[int, str], list[int]] = field(default_factory=dict)  # [next run to count, answers counted]
    ignore: set[tuple[int, str]] = field(default_factory=set)  # too rare to tell whether they vanished

    @classmethod
    def from_traces(cls, traces: list[Trace]) -> Epoch:
        epoch = cls(traces[0].ts)
        for trace in traces:
            epoch.push(trace)
        return epoch

    @classmethod
    def after(cls, old: Epoch, runs: list[Trace], changed: set[int] | None = None) -> Epoch:
        """The epoch that follows ``old``, started by ``runs``. Hops that were not replaced keep what ``old`` learned
        about them (the members of a load-balancing group that the few first runs of the new epoch have not shown yet);
        the hops that were replaced start from the runs alone."""
        new = cls(runs[0].ts)
        new.prior = {idx: set(addrs) for idx, addrs in old.known.items()}
        hops = changed if changed is not None else old.replaced_hops(runs)
        sets = [run.addr_sets() for run in runs]
        extent = max(len(row) for row in sets)  # hops beyond the end of the new route are gone
        for idx, addrs in old.known.items():
            answered_now = any(idx < len(row) and row[idx] for row in sets)  # silent in every run: probably gone
            if idx not in hops and idx < extent and answered_now:
                scale = min(1.0, INHERIT_ANSWERS / old.answered[idx])  # keep the shares, forget most of the history
                new.known[idx] = set(addrs)
                new.counts[idx] = {a: n * scale for a, n in old.counts[idx].items()}
                new.answered[idx] = old.answered[idx] * scale
                for addr in addrs:
                    new.last_seen[(idx, addr)] = -1  # not seen since the new epoch began
        for run in runs:
            new.push(run)
        return new

    def only_new(self, sets: tuple[frozenset[str], ...]) -> bool:
        """True if every address this epoch does not know yet at its hop is also unknown to the epoch before it. During
        the first runs of an epoch such an address is a load-balancing member not seen yet; an address of the epoch
        before is the route going back, which must be able to count as a change."""
        return all(
            a in self.known.get(idx, set()) or a not in self.prior.get(idx, set())
            for idx, s in enumerate(sets)
            for a in s
        )

    def forget(self, idx: int, addr: str) -> None:
        """Drop an address that was inherited and has not shown up since the epoch began."""
        self.known.get(idx, set()).discard(addr)
        gone = self.counts.get(idx, {}).pop(addr, 0.0)
        self.answered[idx] = self.answered.get(idx, 0.0) - gone
        for table in (self.last_seen, self.stale):
            table.pop((idx, addr), None)
        self.ignore.discard((idx, addr))

    def replaced_hops(self, runs: list[Trace]) -> set[int]:
        """Hops where the runs show new addresses and none of the known ones: the hop was replaced. A hop where the
        old and the new addresses answer together was extended (a router joined a group), and keeps what is known."""
        sets = [run.addr_sets() for run in runs]
        out = set()
        for idx in self.new_hops(runs):
            known = self.known.get(idx, set())
            if not any(idx < len(row) and row[idx] & known for row in sets):
                out.add(idx)
        return out

    def new_hops(self, runs: list[Trace]) -> set[int]:
        """Hop indexes where some run shows an address this epoch has not seen at that hop."""
        return {idx for run in runs for idx, s in enumerate(run.addr_sets()) if not s <= self.known.get(idx, set())}

    def push(self, trace: Trace) -> None:
        pos = len(self.traces)
        self.traces.append(trace)
        for idx, addrs in enumerate(trace.addr_sets()):
            if not addrs:
                continue
            self.known.setdefault(idx, set()).update(addrs)
            counter = self.counts.setdefault(idx, {})
            for probe in trace.hops[idx].probes:
                if probe.addr is not None:
                    counter[probe.addr] = counter.get(probe.addr, 0.0) + 1.0
                    self.answered[idx] = self.answered.get(idx, 0.0) + 1.0
            for addr in addrs:
                self.last_seen[(idx, addr)] = pos
                self.stale.pop((idx, addr), None)
                self.ignore.discard((idx, addr))

    def conforms(self, sets: tuple[frozenset[str], ...]) -> bool:
        return all(not s or s <= self.known.get(idx, set()) for idx, s in enumerate(sets))

    def path(self, share: float) -> tuple[tuple[str, ...], ...]:
        """The route of the epoch: for each hop, the addresses that made at least ``share`` of the answers."""
        if not self.known:
            return ()
        hops: list[tuple[str, ...]] = []
        for idx in range(max(self.known) + 1):
            counter = self.counts.get(idx)
            if not counter:
                hops.append(())
                continue
            need = share * self.answered[idx]
            hops.append(tuple(a for a, n in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])) if n >= need))
        return tuple(hops)

    def vanished(self, p: Params) -> tuple[int, int, str] | None:
        """Position in ``traces`` of the first run of an absence that cannot be chance, the hop index and the address;
        or None.

        An address that made a share ``f`` of the answers at its hop (before it went missing) is missing from the last
        runs while the hop keeps answering through other addresses. If the hop gave ``n`` answers in that time, the
        chance of such an absence with unchanged load balancing is about ``(1 - f) ** n``; it must be below
        ``exp(-vanish_evidence)``."""
        total = len(self.traces)
        for key, last in self.last_seen.items():
            if total - 1 - last < p.vanish_runs or key in self.ignore:
                continue
            idx, addr = key
            state = self.stale.setdefault(key, [last + 1, 0])
            while state[0] < total:  # count the answers of the hop since the address was last seen, incrementally
                run = self.traces[state[0]]
                if idx < len(run.hops):
                    state[1] += sum(1 for probe in run.hops[idx].probes if probe.addr)
                state[0] += 1
            before = self.answered[idx] - state[1]
            f = self.counts[idx][addr] / before if before > 0 else 1.0
            if f < 0.1 or f >= 1.0:
                self.ignore.add(key)
            elif state[1] * -math.log1p(-f) >= p.vanish_evidence:
                return last + 1, idx, addr
        return None


@dataclass
class HopStat:
    ttl: int
    addrs: tuple[str, ...]
    median_ms: float | None
    p95_ms: float | None
    loss: float
    slow_icmp: bool = False


@dataclass
class Analysis:
    target: str
    traces: list[Trace]
    epochs: list[Epoch]
    events: list[Event]
    params: Params

    @property
    def current(self) -> Epoch:
        return self.epochs[-1]

    @property
    def last(self) -> Trace:
        return self.traces[-1]

    def route(self, epoch: Epoch | None = None) -> tuple[tuple[str, ...], ...]:
        return (epoch or self.current).path(self.params.share)


def median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    pos = q * (len(ordered) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (pos - lo)


def addr_key(addr: str) -> tuple[int, int]:
    ip = ipaddress.ip_address(addr)
    return ip.version, int(ip)


def hop_label(addrs: tuple[str, ...]) -> str:
    """ "a|b" for the addresses of a hop in address order (so the same set always reads the same), "*" for none."""
    return "|".join(sorted(addrs, key=addr_key)) if addrs else "*"


def _trim(path: tuple[tuple[str, ...], ...]) -> tuple[tuple[str, ...], ...]:
    hops = list(path)
    while hops and not hops[-1]:
        hops.pop()
    return tuple(hops)


def _e2e(traces: list[Trace]) -> list[float]:
    return [v for v in (t.end_to_end() for t in traces) if v is not None]


def _hop_medians(traces: list[Trace]) -> dict[int, float]:
    per: dict[int, list[float]] = {}
    for tr in traces:
        for idx, hop in enumerate(tr.hops):
            r = hop.rtts
            if r:
                per.setdefault(idx, []).append(median(r))
    return {idx: median(v) for idx, v in per.items() if len(v) >= 3}


def _latency_shifts(target: str, traces: list[Trace], p: Params) -> list[Event]:
    """Level shifts of the end-to-end time inside one epoch (``traces`` are the runs of that epoch)."""
    series = [(i, v) for i, v in enumerate(t.end_to_end() for t in traces) if v is not None]
    window, base_n = p.lat_window, p.lat_base
    values = [v for _, v in series]
    events: list[Event] = []
    start = 0
    for j in range(len(series)):
        if j - start + 1 < base_n + window:
            continue
        recent = values[j - window + 1 : j + 1]
        base = values[j - window - base_n + 1 : j - window + 1]
        centre = median(base)
        sigma = 1.4826 * median([abs(x - centre) for x in base])
        thr = max(p.lat_min_ms, p.lat_rel * centre, p.lat_noise_k * sigma)
        shift = median(recent) - centre
        if abs(shift) < thr:
            continue
        sign = 1.0 if shift > 0 else -1.0
        moved = [(x - centre) * sign >= thr / 2 for x in recent]
        if sum(moved) < window - 1:
            continue
        onset = j - window + 1 + moved.index(True)
        o_trace, o_ts = series[onset][0], traces[series[onset][0]].ts
        events.append(
            Event(
                kind="latency_shift",
                target=target,
                ts=o_ts,
                detected=traces[series[j][0]].ts,
                ttl=_culprit(traces, o_trace, series[j][0], shift, base_n),
                delta_ms=round(shift, 3),
                value_ms=round(median(recent), 3),
            )
        )
        start = onset
    return events


def _culprit(traces: list[Trace], onset: int, now: int, shift: float, base_n: int) -> int | None:
    """The first hop (1-based) after which all the hops that answer moved by about the end-to-end shift."""
    before = _hop_medians(traces[max(0, onset - base_n) : onset])
    after = _hop_medians(traces[onset : now + 1])
    deltas = {idx: after[idx] - before[idx] for idx in after if idx in before}
    if not deltas:
        return None
    need = 0.6 * abs(shift)
    sign = 1.0 if shift > 0 else -1.0
    culprit = min(deltas)
    for idx in sorted(deltas, reverse=True):
        if deltas[idx] * sign < need:
            break
        culprit = idx
    return culprit + 1


def _subkind(before: tuple[tuple[str, ...], ...], after: tuple[tuple[str, ...], ...]) -> str:
    if len(after) != len(before):
        return "longer" if len(after) > len(before) else "shorter"
    pairs = [(set(b), set(a)) for b, a in zip(before, after, strict=True) if b and a]
    if pairs and all(b <= a for b, a in pairs) and any(b < a for b, a in pairs):
        return "balanced"  # same route, one more equal-cost way through it
    if pairs and all(a <= b for b, a in pairs) and any(a < b for b, a in pairs):
        return "unbalanced"  # same route, one equal-cost way less
    return "reroute"


def _route_change(
    target: str, old: Epoch, new: Epoch, after: tuple[tuple[str, ...], ...], detected: datetime, ttl: int, p: Params
) -> Event:
    before = _trim(old.path(p.share))
    e_before, e_after = _e2e(old.traces), _e2e(new.traces)
    return Event(
        kind="route_change",
        target=target,
        ts=new.start,
        detected=detected,
        ttl=ttl,
        subkind=_subkind(before, after),
        before=tuple(hop_label(h) for h in before),
        after=tuple(hop_label(h) for h in after),
        delta_ms=round(median(e_after) - median(e_before), 3) if e_before and e_after else None,
    )


def _after_path(old: Epoch, runs: list[Trace], changed: set[int], p: Params) -> tuple[tuple[str, ...], ...]:
    """The route as the confirming runs show it: the hops that changed from the runs, the others as they were. (The
    share of a new address in the whole new epoch is still too small to count after only a few runs.)"""
    seen = _trim(Epoch.from_traces(runs).path(p.share))
    before = old.path(p.share)
    return tuple(seen[i] if i in changed else (before[i] if i < len(before) else ()) for i in range(len(seen)))


def analyze(target: str, traces: list[Trace], params: Params | None = None) -> Analysis:
    """Walk the runs of one target in time order and build epochs and events. ``traces`` must not be empty."""
    p = params or Params()
    if not traces:
        raise ValueError("nothing to analyze")
    events: list[Event] = []
    epoch = Epoch.from_traces(traces[:1])
    epochs: list[Epoch] = [epoch]
    pending: list[Trace] = []
    blip_addrs: set[tuple[int, str]] = set()
    for trace in traces[1:]:
        sets = trace.addr_sets()
        if len(epoch.traces) < p.warmup and not pending and epoch.only_new(sets):
            epoch.push(trace)
            continue
        if epoch.conforms(sets):
            if pending:
                _close_blip(target, epoch, blip_addrs, pending, trace, p, events)
                pending, blip_addrs = [], set()
            epoch.push(trace)
            gone = epoch.vanished(p)
            if gone is not None and gone[0] == 0:
                epoch.forget(gone[1], gone[2])  # kept from the epoch before and never seen again: no new change
            elif gone is not None:
                pos, idx, _ = gone
                old = Epoch.from_traces(epoch.traces[:pos])
                old.end = epoch.traces[pos].ts
                new = Epoch.after(old, epoch.traces[pos:], {idx})
                after = _trim(new.path(p.share))
                events.append(_route_change(target, old, new, after, trace.ts, idx + 1, p))
                epochs[-1] = old
                epochs.append(new)
                epoch = new
            continue
        pending.append(trace)
        blip_addrs |= {(idx, a) for idx, s in enumerate(sets) for a in s if a not in epoch.known.get(idx, set())}
        if len(pending) >= p.confirm:
            epoch.end = pending[0].ts
            changed = epoch.new_hops(pending)
            new = Epoch.after(epoch, pending)
            events.append(
                _route_change(
                    target, epoch, new, _after_path(epoch, pending, changed, p), trace.ts, min(changed) + 1, p
                )
            )
            epochs.append(new)
            epoch, pending, blip_addrs = new, [], set()
    for ep in epochs:
        events.extend(_latency_shifts(target, ep.traces, p))
    events.extend(_outages(target, traces, p))
    events.sort(key=lambda e: (e.ts, e.kind))
    return Analysis(target, traces, epochs, events, p)


def _close_blip(
    target: str,
    epoch: Epoch,
    blip_addrs: set[tuple[int, str]],
    pending: list[Trace],
    trace: Trace,
    p: Params,
    events: list[Event],
) -> None:
    """A run that disagreed was followed by one that agrees: those were blips. An address that keeps coming back in
    separate blips is a load-balancing alternate."""
    for idx, addr in sorted(blip_addrs):
        epoch.alt_seen[(idx, addr)] += 1
        if epoch.alt_seen[(idx, addr)] >= p.alt_runs:
            epoch.known.setdefault(idx, set()).add(addr)
            events.append(
                Event(
                    kind="alternate",
                    target=target,
                    ts=pending[0].ts,
                    detected=trace.ts,
                    ttl=idx + 1,
                    addr=addr,
                )
            )


def _outages(target: str, traces: list[Trace], p: Params) -> list[Event]:
    events: list[Event] = []
    seen_reached = False
    down = False
    run: list[Trace] = []
    for tr in traces:
        if tr.reached:
            if down:
                events.append(Event(kind="recovered", target=target, ts=tr.ts, detected=tr.ts))
            seen_reached, down, run = True, False, []
        elif seen_reached and not down:
            run.append(tr)
            if len(run) >= p.outage_confirm:
                down = True
                sets = tr.addr_sets()
                last = sets[-1] if sets else frozenset()
                events.append(
                    Event(
                        kind="unreachable",
                        target=target,
                        ts=run[0].ts,
                        detected=tr.ts,
                        ttl=len(sets) or None,
                        addr=sorted(last)[0] if last else None,
                    )
                )
    return events


def hop_stats(analysis: Analysis, epoch: Epoch | None = None) -> list[HopStat]:
    """Per-hop numbers for one epoch (the current one by default), and which hops answer slowly on their own."""
    ep = epoch or analysis.current
    path = _trim(ep.path(analysis.params.share))
    stats: list[HopStat] = []
    for idx, addrs in enumerate(path):
        rtts: list[float] = []
        lost = total = 0
        for tr in ep.traces:
            if idx < len(tr.hops):
                hop = tr.hops[idx]
                rtts.extend(hop.rtts)
                lost += hop.lost
                total += len(hop.probes)
        stats.append(
            HopStat(
                ttl=idx + 1,
                addrs=addrs,
                median_ms=round(median(rtts), 3) if rtts else None,
                p95_ms=round(percentile(rtts, 0.95), 3) if rtts else None,
                loss=round(lost / total, 4) if total else 0.0,
            )
        )
    for i, stat in enumerate(stats):
        later = [s.median_ms for s in stats[i + 1 :] if s.median_ms is not None]
        if stat.median_ms is not None and later:
            gap = stat.median_ms - min(later)
            stat.slow_icmp = gap > max(10.0, 0.2 * stat.median_ms)
    return stats
