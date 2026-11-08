"""The simulator itself, and a small version of the evaluation (tools/evaluate.py runs the full one)."""

import random

import pytest

import netsim
from pathmap.analysis import analyze


def rounds_of(ts):
    return round((ts - netsim.T0) / netsim.STEP)


def test_the_simulator_is_deterministic():
    a = netsim.make_scenario(random.Random(7), 3, 120)
    b = netsim.make_scenario(random.Random(7), 3, 120)
    assert [(t.round, t.kind, t.ttl) for t in a.truth] == [(t.round, t.kind, t.ttl) for t in b.truth]
    ra, rb = random.Random(1), random.Random(1)
    assert a.run(ra) == b.run(rb)


def test_a_path_has_the_requested_shape():
    rng = random.Random(2)
    path = netsim.build_path(rng, 5, decoy=True)
    assert 7 <= len(path.stages) <= 13 and path.stages[0].routers[0].silent is False
    assert any(r.slow > 0 for st in path.stages for r in st.routers)
    t = path.trace(rng, netsim.T0)
    assert t.reached and t.dest == path.dest and len(t.hops) == len(path.stages)


def test_an_outage_ends_in_stars():
    rng = random.Random(3)
    path = netsim.build_path(rng, 1, firewall=False)
    path.down_from = 3
    t = path.trace(rng, netsim.T0, loss=0.0)
    assert not t.reached and len(t.addr_sets()) == 3 and len(t.hops) == len(path.stages) + 2


@pytest.mark.parametrize("kind", ["reroute", "longer", "shorter", "grow", "shrink", "blip", "latency", "outage"])
def test_every_kind_of_event_can_be_scheduled(kind):
    for seed in range(30):
        sc = netsim.make_scenario(random.Random(seed), 1, 200, kinds=(kind,))
        if sc.truth:
            assert {t.kind for t in sc.truth} == {kind}
            return
    pytest.fail(f"no {kind} event in 30 scenarios")


def test_a_small_evaluation():
    found = total = false = 0
    for i in range(10):
        rng = random.Random(500 + i)
        sc = netsim.make_scenario(rng, i, 300, kinds=("reroute", "longer", "shorter", "blip", "latency", "outage"))
        an = analyze(sc.path.target, sc.run(rng))
        route = [t for t in sc.truth if t.kind in ("reroute", "longer", "shorter")]
        total += len(route)
        changes = [e for e in an.events if e.kind == "route_change"]
        found += sum(any(abs(rounds_of(e.ts) - t.round) <= 2 for e in changes) for t in route)
        false += sum(not any(abs(rounds_of(e.ts) - t.round) <= 2 for t in route) for e in changes)
    assert total >= 10 and found == total and false == 0


def test_quiet_networks_stay_quiet():
    for i in range(6):
        rng = random.Random(900 + i)
        sc = netsim.make_scenario(rng, i, 300, events=False, decoy=(i % 2 == 0))
        an = analyze(sc.path.target, sc.run(rng))
        assert [e for e in an.events if e.kind != "alternate"] == []
