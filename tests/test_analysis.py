from datetime import UTC, datetime, timedelta

import pytest

from pathmap.analysis import Params, analyze, hop_label, hop_stats, median, percentile
from pathmap.model import Hop, Probe, Trace

T0 = datetime(2026, 10, 1, tzinfo=UTC)
DEST = "10.0.0.99"
ROUTE = [["10.0.0.1"], ["10.0.0.2"], ["10.0.0.3"], [DEST]]
BASE = [10.0, 20.0, 30.0, 40.0]


def mk(i, route=ROUTE, rtts=BASE, reached=True, extra=None):
    """Run number i. ``route``: addresses per hop (empty list = silent); the probes of a hop take them in turn."""
    hops = []
    for h, addrs in enumerate(route):
        probes = []
        for q in range(3):
            if not addrs:
                probes.append(Probe())
            else:
                probes.append(Probe(addrs[(i + q) % len(addrs)], rtts[h] + 0.1 * q + (extra or {}).get(h, 0.0)))
        hops.append(Hop(h + 1, tuple(probes)))
    return Trace("t.example", T0 + timedelta(minutes=15 * i), tuple(hops), DEST, reached)


def series(parts):
    out = []
    for count, kw in parts:
        for _ in range(count):
            out.append(mk(len(out), **kw))
    return out


def events(an, kind=None):
    return [e for e in an.events if kind is None or e.kind == kind]


def test_a_stable_route_has_one_epoch_and_no_events():
    an = analyze("t.example", series([(60, {})]))
    assert len(an.epochs) == 1 and an.events == []
    assert an.route() == (("10.0.0.1",), ("10.0.0.2",), ("10.0.0.3",), (DEST,))


def test_a_silent_hop_matches_anything():
    flaky = [["10.0.0.1"], ["10.0.0.2"], [], [DEST]]
    traces = []
    for i in range(60):
        traces.append(mk(i, route=flaky if i % 3 == 0 else ROUTE))
    assert analyze("t.example", traces).events == []


def test_load_balancing_is_not_a_change():
    ecmp = [["10.0.0.1"], ["10.0.0.2", "10.0.0.20"], ["10.0.0.3"], [DEST]]
    one_a = [["10.0.0.1"], ["10.0.0.2"], ["10.0.0.3"], [DEST]]
    one_b = [["10.0.0.1"], ["10.0.0.20"], ["10.0.0.3"], [DEST]]
    traces = [mk(i, route=ecmp) for i in range(10)]
    for i in range(10, 80):
        traces.append(mk(i, route=[ecmp, one_a, one_b][i % 3]))
    an = analyze("t.example", traces)
    assert an.events == [] and len(an.epochs) == 1


def test_a_short_blip_is_not_a_route_change_but_a_longer_one_is():
    other = [["10.0.0.1"], ["10.0.0.77"], ["10.0.0.3"], [DEST]]
    assert analyze("t.example", series([(20, {}), (2, {"route": other}), (20, {})])).events == []
    an = analyze("t.example", series([(20, {}), (3, {"route": other}), (20, {})]))
    e, back = events(an, "route_change")  # it went, and it came back
    assert e.subkind == "reroute" and e.ttl == 2
    assert e.ts == T0 + timedelta(minutes=15 * 20) and e.detected == T0 + timedelta(minutes=15 * 22)
    assert e.before[1] == "10.0.0.2" and e.after[1] == "10.0.0.77"
    assert back.ts == T0 + timedelta(minutes=15 * 23) and back.before[1] == "10.0.0.77" and back.after[1] == "10.0.0.2"
    # the new route goes on for 20 more runs: it stays one epoch
    an = analyze("t.example", series([(20, {}), (40, {"route": other})]))
    assert len(an.epochs) == 2 and an.route()[1] == ("10.0.0.77",)


def test_longer_and_shorter():
    longer = [["10.0.0.1"], ["10.0.0.2"], ["10.0.0.50"], ["10.0.0.3"], [DEST]]
    an = analyze("t.example", series([(20, {"rtts": BASE}), (30, {"route": longer, "rtts": [*BASE, 50.0]})]))
    (e,) = events(an, "route_change")
    assert e.subkind == "longer" and e.ttl == 3
    back = analyze("t.example", series([(20, {"route": longer, "rtts": [*BASE, 50.0]}), (30, {})]))
    (e,) = events(back, "route_change")
    assert e.subkind == "shorter" and e.ttl == 3


def test_a_router_joining_a_group_is_balanced_and_leaving_is_unbalanced():
    both = [["10.0.0.1"], ["10.0.0.2", "10.0.0.20"], ["10.0.0.3"], [DEST]]
    an = analyze("t.example", series([(20, {}), (40, {"route": both})]))
    (e,) = events(an, "route_change")
    assert e.subkind == "balanced" and e.ttl == 2
    left = analyze("t.example", series([(20, {"route": both}), (60, {})]))
    (e,) = events(left, "route_change")
    assert e.subkind == "unbalanced" and e.ttl == 2
    assert left.route()[1] == ("10.0.0.2",) and len(left.epochs) == 2


def test_an_address_seen_in_separate_blips_becomes_an_alternate():
    other = [["10.0.0.1"], ["10.0.0.77"], ["10.0.0.3"], [DEST]]
    parts = [(12, {})]
    for _ in range(3):
        parts += [(1, {"route": other}), (6, {})]
    an = analyze("t.example", series(parts))
    (alt,) = events(an, "alternate")
    assert alt.ttl == 2 and alt.addr == "10.0.0.77"
    assert events(an, "route_change") == []
    # from now on the alternate conforms
    an = analyze("t.example", series([*parts, (5, {"route": other}), (5, {})]))
    assert events(an, "route_change") == []


def test_a_member_that_never_shows_in_the_new_epoch_is_forgotten_quietly():
    both = [["10.0.0.1"], ["10.0.0.2", "10.0.0.20"], ["10.0.0.3"], [DEST]]
    moved = [["10.0.0.1"], ["10.0.0.2"], ["10.0.0.55"], [DEST]]
    an = analyze("t.example", series([(20, {"route": both}), (25, {"route": moved})]))
    assert [e.kind for e in an.events] == ["route_change"]
    assert an.route()[1] == ("10.0.0.2",)


def test_outage_and_recovery():
    down = [["10.0.0.1"], ["10.0.0.2"], [], []]
    traces = series([(10, {}), (2, {"route": down, "reached": False}), (10, {})])
    assert analyze("t.example", traces).events == []  # two runs are not an outage
    an = analyze("t.example", series([(10, {}), (6, {"route": down, "reached": False}), (10, {})]))
    kinds = [e.kind for e in an.events]
    assert kinds == ["unreachable", "recovered"]
    first = an.events[0]
    assert first.ts == T0 + timedelta(minutes=150) and first.ttl == 2 and first.addr == "10.0.0.2"
    assert an.events[1].ts == T0 + timedelta(minutes=15 * 16)
    never = analyze("t.example", series([(20, {"route": down, "reached": False})]))
    assert never.events == []  # a host that never answered is not "down"


def test_latency_shift_and_the_hop_where_it_starts():
    shifted = [10.0, 20.0, 90.0, 100.0]
    an = analyze("t.example", series([(45, {}), (30, {"rtts": shifted})]))
    (e,) = events(an, "latency_shift")
    assert e.ttl == 3 and e.delta_ms == pytest.approx(60.0, abs=2) and e.ts == T0 + timedelta(minutes=15 * 45)
    assert e.detected - e.ts <= timedelta(minutes=15 * 4)
    # a drop is a shift too
    an = analyze("t.example", series([(45, {"rtts": shifted}), (30, {})]))
    assert events(an, "latency_shift")[0].delta_ms < 0
    # small noise is not
    noisy = [mk(i, rtts=[10.0, 20.0, 30.0, 40.0 + (i % 5)]) for i in range(80)]
    assert analyze("t.example", noisy).events == []


def test_one_slow_hop_is_not_a_slow_path():
    traces = [mk(i, extra={1: 80.0}) for i in range(60)]  # hop 2 answers 80 ms late, the rest is normal
    an = analyze("t.example", traces)
    assert an.events == []
    flags = {s.ttl: s.slow_icmp for s in hop_stats(an)}
    assert flags == {1: False, 2: True, 3: False, 4: False}


def test_hop_stats():
    an = analyze("t.example", [mk(i) for i in range(10)])
    stats = hop_stats(an)
    assert [s.ttl for s in stats] == [1, 2, 3, 4]
    assert stats[0].median_ms == pytest.approx(10.1, abs=0.01) and stats[0].loss == 0.0
    assert stats[0].p95_ms >= stats[0].median_ms
    silent = analyze("t.example", [mk(i, route=[["10.0.0.1"], [], ["10.0.0.3"], [DEST]]) for i in range(10)])
    s2 = hop_stats(silent)[1]
    assert s2.addrs == () and s2.median_ms is None and s2.loss == 1.0


def test_labels_are_in_address_order():
    assert hop_label(("10.0.0.9", "10.0.0.10")) == "10.0.0.9|10.0.0.10"
    assert hop_label(()) == "*"


def test_helpers():
    assert median([3.0, 1.0, 2.0]) == 2.0 and median([1.0, 2.0, 3.0, 4.0]) == 2.5
    assert percentile([1.0, 2.0, 3.0, 4.0, 5.0], 0.5) == 3.0 and percentile([1.0], 0.95) == 1.0
    assert percentile([0.0, 10.0], 0.95) == pytest.approx(9.5)


@pytest.mark.parametrize(
    "kw",
    [
        {"confirm": 0},
        {"warmup": 0},
        {"vanish_runs": 0},
        {"share": 0},
        {"share": 1.5},
        {"lat_window": 2},
        {"lat_base": 4},
    ],
)
def test_params_are_checked(kw):
    with pytest.raises(ValueError):
        Params(**kw)


def test_nothing_to_analyze():
    with pytest.raises(ValueError):
        analyze("t.example", [])


def test_confirm_can_be_changed():
    other = [["10.0.0.1"], ["10.0.0.77"], ["10.0.0.3"], [DEST]]
    traces = series([(20, {}), (1, {"route": other}), (20, {})])
    assert len(events(analyze("t.example", traces, Params(confirm=1)), "route_change")) == 2  # there and back
    assert analyze("t.example", traces, Params(confirm=2)).events == []
