"""A simulated network with a known truth, to test and to measure pathmap.

A path is a list of stages; a stage has one router, or several when the traffic is balanced (ECMP). Every probe of every
run picks one router of the stage at random, as a per-packet balancer does. Routers can be silent (a firewall that never
answers) or slow to answer (a busy control plane). The simulator changes the network at chosen runs and records what it
changed: that record is the truth the tools are measured against. Nothing here uses pathmap's analysis code.
"""

from __future__ import annotations

import copy
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from pathmap.model import Hop, Probe, Trace

T0 = datetime(2026, 10, 1, 0, 0, tzinfo=UTC)
STEP = timedelta(minutes=15)


@dataclass
class Router:
    addr: str
    offset: float = 0.0  # ms, small constant extra time of this router
    slow: float = 0.0  # ms added to the answers of this router only (slow ICMP, not slow traffic)
    silent: bool = False  # never answers


@dataclass
class Stage:
    routers: list[Router]
    link_ms: float  # one-way delay of the link that leads to this stage


@dataclass
class Truth:
    round: int
    kind: str  # reroute | longer | shorter | grow | shrink | blip | latency | outage
    ttl: int | None = None  # first visible hop that differs, or hop where the extra time starts
    addr: str | None = None  # address that appeared (grow) or left (shrink)
    extra_ms: float = 0.0  # round-trip time added (latency)
    length: int = 0  # runs the event lasts (blip, outage)


@dataclass
class SimPath:
    target: str
    dest: str
    stages: list[Stage]
    down_from: int | None = None  # stages with index >= this never answer (outage)
    counter: int = 0
    net: int = 0

    def new_addr(self) -> str:
        self.counter += 1
        return f"10.{self.net}.{self.counter // 250}.{self.counter % 250 + 1}"

    def cumulative(self, idx: int) -> float:
        return 2.0 * sum(s.link_ms for s in self.stages[: idx + 1])

    def trace(
        self, rng: random.Random, ts: datetime, queries: int = 3, loss: float = 0.02, max_hops: int = 30
    ) -> Trace:
        hops: list[Hop] = []
        reached = False
        for idx, stage in enumerate(self.stages):
            probes: list[Probe] = []
            for _ in range(queries):
                router = rng.choice(stage.routers)
                dead = router.silent or (self.down_from is not None and idx >= self.down_from)
                if dead or rng.random() < loss:
                    probes.append(Probe())
                    continue
                base = self.cumulative(idx) + router.offset + router.slow
                rtt = base + abs(rng.gauss(0.0, 0.03 * base + 0.25))
                if rng.random() < 0.015:
                    rtt += rng.uniform(30, 150)  # a spike: queueing somewhere
                probes.append(Probe(router.addr, round(rtt, 3)))
            hops.append(Hop(idx + 1, tuple(probes)))
            if idx == len(self.stages) - 1 and any(p.addr == self.dest for p in probes):
                reached = True
        if not reached:
            # a run toward a host that does not answer ends in stars up to the hop limit; a few are enough here
            for _ in range(min(2, max_hops - len(hops))):
                hops.append(Hop(len(hops) + 1, tuple(Probe() for _ in range(queries))))
        return Trace(self.target, ts, tuple(hops), self.dest, reached)


def build_path(rng: random.Random, index: int, *, firewall: bool = True, decoy: bool = False) -> SimPath:
    """A path of 7 to 13 hops; about a third of the hops are balanced over 2 or 3 routers."""
    dest = f"198.51.100.{index % 250 + 1}"
    path = SimPath(target=f"site{index}.example.net", dest=dest, stages=[], net=index % 250)
    count = rng.randint(7, 13)
    for s in range(count - 1):
        width = 1 if (s == 0 or rng.random() > 0.3) else rng.randint(2, 3)
        routers = [Router(path.new_addr(), offset=rng.uniform(0, 0.6)) for _ in range(width)]
        path.stages.append(Stage(routers, link_ms=rng.uniform(0.4, 9.0)))
    path.stages.append(Stage([Router(dest, offset=rng.uniform(0, 0.6))], link_ms=rng.uniform(1.0, 15.0)))
    singles = [i for i in range(2, count - 2) if len(path.stages[i].routers) == 1]
    if firewall and singles and rng.random() < 0.5:
        path.stages[rng.choice(singles)].routers[0].silent = True
    if decoy:
        choices = [
            i for i in range(1, count - 2) if len(path.stages[i].routers) == 1 and not path.stages[i].routers[0].silent
        ]
        if choices:
            path.stages[rng.choice(choices)].routers[0].slow = rng.uniform(60, 110)
    return path


def visible(path: SimPath) -> list[set[str]]:
    """What a perfect observer sees at each hop: the addresses of the routers that answer."""
    return [{r.addr for r in st.routers if not r.silent} for st in path.stages]


def first_visible_difference(before: list[set[str]], after: list[set[str]]) -> int | None:
    """1-based hop of the first visible difference between two routes (a hop with no visible address says nothing)."""
    shorter = min(len(before), len(after))
    for i in range(shorter):
        if before[i] and after[i] and before[i] != after[i]:
            return i + 1
    return shorter + 1 if len(before) != len(after) else None


def _is_plain(path: SimPath, i: int) -> bool:
    return not any(r.silent for r in path.stages[i].routers)


@dataclass
class Scenario:
    path: SimPath
    rounds: int
    truth: list[Truth] = field(default_factory=list)
    actions: dict[int, list[Callable[[SimPath], None]]] = field(default_factory=dict)

    def at(self, r: int, fn: Callable[[SimPath], None]) -> None:
        self.actions.setdefault(r, []).append(fn)

    def run(self, rng: random.Random, queries: int = 3, loss: float = 0.02) -> list[Trace]:
        out: list[Trace] = []
        for r in range(self.rounds):
            for fn in self.actions.get(r, []):
                fn(self.path)
            out.append(self.path.trace(rng, T0 + r * STEP, queries=queries, loss=loss))
        return out


KINDS = ("reroute", "longer", "shorter", "grow", "shrink", "blip", "latency", "outage")
WEIGHTS = (3, 1, 1, 2, 2, 3, 3, 1.5)


def make_scenario(
    rng: random.Random,
    index: int,
    rounds: int,
    *,
    events: bool = True,
    decoy: bool = False,
    kinds: tuple[str, ...] = KINDS,
) -> Scenario:
    path = build_path(rng, index, decoy=decoy)
    sc = Scenario(path, rounds)
    if not events:
        return sc
    # work on a shadow copy to choose events consistently with the changes made before them
    shadow = copy.deepcopy(path)
    r = rng.randint(18, 30)
    weights = [w for k, w in zip(KINDS, WEIGHTS, strict=True) if k in kinds]
    while r < rounds - 30:
        kind = rng.choices([k for k in KINDS if k in kinds], weights)[0]
        if _schedule(rng, sc, shadow, kind, r):
            r += rng.randint(45, 70)
        else:
            r += 5
    return sc


def _schedule(rng: random.Random, sc: Scenario, shadow: SimPath, kind: str, r: int) -> bool:
    n = len(shadow.stages)
    # events that touch the route are applied to both the shadow (to plan) and the real path (at run r)
    before = visible(shadow)

    def apply(fn: Callable[[SimPath], None]) -> None:
        fn(shadow)
        sc.at(r, fn)

    if kind == "reroute":
        choices = [i for i in range(1, n - 2) if _is_plain(shadow, i)]
        if not choices:
            return False
        a = rng.choice(choices)
        span = rng.randint(1, min(2, n - 2 - a))
        fresh = [
            ([shadow.new_addr() for _ in range(rng.randint(1, 2))], rng.uniform(0.4, 9.0), rng.uniform(0, 0.6))
            for _ in range(span)
        ]

        def do(p: SimPath, a: int = a, fresh: list[tuple[list[str], float, float]] = fresh) -> None:
            for k, (addrs, link, off) in enumerate(fresh):
                p.stages[a + k] = Stage([Router(x, off) for x in addrs], link)

        apply(do)
        sc.truth.append(Truth(r, "reroute", first_visible_difference(before, visible(shadow))))
        return True
    if kind == "longer":
        a = rng.randint(1, n - 2)
        link = rng.uniform(0.5, 6.0)
        new = shadow.new_addr()

        def do_long(p: SimPath, a: int = a, link: float = link, new: str = new) -> None:
            p.stages.insert(a, Stage([Router(new, 0.2)], link))

        apply(do_long)
        sc.truth.append(Truth(r, "longer", first_visible_difference(before, visible(shadow))))
        return True
    if kind == "shorter":
        choices = [i for i in range(1, n - 2) if _is_plain(shadow, i) and n > 7]
        if not choices:
            return False
        a = rng.choice(choices)

        def do_short(p: SimPath, a: int = a) -> None:
            del p.stages[a]

        apply(do_short)
        sc.truth.append(Truth(r, "shorter", first_visible_difference(before, visible(shadow))))
        return True
    if kind == "grow":
        choices = [i for i in range(1, n - 1) if _is_plain(shadow, i) and len(shadow.stages[i].routers) < 4]
        if not choices:
            return False
        a = rng.choice(choices)
        new = shadow.new_addr()

        def do_grow(p: SimPath, a: int = a, new: str = new) -> None:
            p.stages[a].routers.append(Router(new, 0.2))

        apply(do_grow)
        sc.truth.append(Truth(r, "grow", a + 1, addr=new))
        return True
    if kind == "shrink":
        choices = [i for i in range(1, n - 1) if _is_plain(shadow, i) and len(shadow.stages[i].routers) >= 2]
        if not choices:
            return False
        a = rng.choice(choices)
        gone = rng.choice(shadow.stages[a].routers).addr

        def do_shrink(p: SimPath, a: int = a, gone: str = gone) -> None:
            p.stages[a].routers = [x for x in p.stages[a].routers if x.addr != gone]

        apply(do_shrink)
        sc.truth.append(Truth(r, "shrink", a + 1, addr=gone))
        return True
    if kind == "blip":
        choices = [i for i in range(1, n - 2) if _is_plain(shadow, i)]
        if not choices:
            return False
        a = rng.choice(choices)
        length = rng.randint(1, 2)
        saved: dict[str, Stage] = {}
        new = shadow.new_addr()

        def start(p: SimPath, a: int = a, new: str = new) -> None:
            saved["stage"] = p.stages[a]
            p.stages[a] = Stage([Router(new, 0.2)], saved["stage"].link_ms)

        def stop(p: SimPath, a: int = a) -> None:
            p.stages[a] = saved["stage"]

        sc.at(r, start)
        sc.at(r + length, stop)
        sc.truth.append(Truth(r, "blip", a + 1, length=length))
        return True
    if kind == "latency":
        a = rng.randint(1, n - 1)
        extra = rng.uniform(12, 80)  # round-trip ms

        def do_lat(p: SimPath, a: int = a, extra: float = extra) -> None:
            p.stages[a].link_ms += extra / 2

        apply(do_lat)
        first = next((i for i in range(a, n) if _is_plain(shadow, i)), n - 1)  # a silent hop cannot show the rise
        sc.truth.append(Truth(r, "latency", first + 1, extra_ms=extra))
        return True
    if kind == "outage":
        length = rng.randint(4, 12)
        k = rng.randint(1, n - 1)

        def down(p: SimPath, k: int = k) -> None:
            p.down_from = k

        def up(p: SimPath) -> None:
            p.down_from = None

        sc.at(r, down)
        sc.at(r + length, up)
        last = max((i for i in range(k) if _is_plain(shadow, i)), default=0)  # last hop that can still answer
        sc.truth.append(Truth(r, "outage", last + 1, length=length))
        return True
    raise ValueError(kind)


# --- the text each program would print, for the parser tests ------------------------------------------------------


def render_unix(trace: Trace, max_hops: int = 30, names: bool = False) -> str:
    """The text of Linux or macOS traceroute; with ``names`` the host names are printed too ("name (address)")."""
    dest = trace.dest or "0.0.0.0"
    label = (lambda a: f"r-{a.replace('.', '-')}.isp.example ({a})") if names else (lambda a: a)
    lines = [f"traceroute to {dest} ({dest}), {max_hops} hops max, 60 byte packets"]
    for hop in trace.hops:
        parts: list[str] = []
        last: str | None = None
        for p in hop.probes:
            if p.addr is None:
                parts.append("*")
                continue
            if p.addr != last:
                parts.append(label(p.addr))
                last = p.addr
            parts.append(f"{p.rtt:.3f} ms" + (f" {p.note}" if p.note else ""))
        lines.append(f"{hop.ttl:2d}  " + "  ".join(parts))
    return "\n".join(lines) + "\n"


def render_windows(trace: Trace, max_hops: int = 30) -> str:
    dest = trace.dest or "0.0.0.0"
    lines = ["", f"Tracing route to {dest} over a maximum of {max_hops} hops", ""]
    for hop in trace.hops:
        cells: list[str] = []
        addr: str | None = None
        for p in hop.probes:
            if p.addr is None:
                cells.append("   *    ")
            else:
                addr = p.addr
                ms = "<1 ms" if (p.rtt or 0) < 1 else f"{round(p.rtt or 0)} ms"
                cells.append(f"{ms:>7} ")
        lines.append(f"{hop.ttl:3d}  " + " ".join(cells) + f" {addr if addr else 'Request timed out.'}")
    lines += ["", "Trace complete.", ""]
    return "\n".join(lines)
