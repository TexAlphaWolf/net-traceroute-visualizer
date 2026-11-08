from datetime import UTC, datetime

import pytest

from pathmap.model import Hop, Probe, Trace, check_address, check_target

T = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def trace(*rows, reached=True, dest="10.0.0.9"):
    hops = tuple(Hop(i, tuple(Probe(a, r) if a else Probe() for a, r in row)) for i, row in enumerate(rows, 1))
    return Trace("t.example", T, hops, dest, reached)


@pytest.mark.parametrize("good", ["8.8.8.8", "2001:db8::1", "example.com", "A.B-c.example", "localhost", "::1"])
def test_good_targets(good):
    assert check_target(good) == (good.lower() if not good[0].isdigit() and ":" not in good else check_target(good))


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "-oProxy",
        "a b",
        "a;b",
        "a/b",
        "../x",
        "x" * 254,
        "a..b",
        "-a.example",
        "a_b.example",
        "fe80::1%eth0",
        "a\nb",
        "$(id)",
    ],
)
def test_bad_targets(bad):
    with pytest.raises(ValueError):
        check_target(bad)


def test_target_is_canonical():
    assert check_target("EXAMPLE.com") == "example.com"
    assert check_target("2001:0db8:0:0:0:0:0:1") == "2001:db8::1"
    with pytest.raises(ValueError):
        check_target(5)  # type: ignore[arg-type]


def test_address_check():
    assert check_address("10.0.0.1") == "10.0.0.1"
    with pytest.raises(ValueError):
        check_address("not-an-ip")


@pytest.mark.parametrize(
    "make",
    [
        lambda: Probe("10.0.0.1", -1.0),
        lambda: Probe("10.0.0.1", float("nan")),
        lambda: Probe(None, 1.0),
        lambda: Probe("10.0.0.1", 1.0, "bad note"),
        lambda: Hop(0, (Probe(),)),
        lambda: Hop(1, ()),
        lambda: Trace("t", T, ()),
        lambda: Trace("t", datetime(2026, 1, 1), (Hop(1, (Probe(),)),)),
        lambda: Trace("t", T, (Hop(2, (Probe(),)),)),
    ],
)
def test_validation(make):
    with pytest.raises(ValueError):
        make()


def test_hop_properties():
    hop = Hop(1, (Probe("10.0.0.1", 1.0), Probe(), Probe("10.0.0.2", 3.0)))
    assert hop.addrs == {"10.0.0.1", "10.0.0.2"}
    assert hop.rtts == [1.0, 3.0]
    assert hop.lost == 1


def test_addr_sets_drop_the_silent_tail_only():
    t = trace([("10.0.0.1", 1.0)], [(None, None)], [("10.0.0.3", 3.0)], [(None, None)], [(None, None)], reached=False)
    assert [sorted(s) for s in t.addr_sets()] == [["10.0.0.1"], [], ["10.0.0.3"]]


def test_end_to_end():
    t = trace([("10.0.0.1", 1.0)], [("10.0.0.9", 4.0), ("10.0.0.9", 2.0), ("10.0.0.9", 9.0)])
    assert t.end_to_end() == 4.0
    even = trace([("10.0.0.9", 2.0), ("10.0.0.9", 4.0)])
    assert even.end_to_end() == 3.0
    assert trace([("10.0.0.1", 1.0)], reached=False).end_to_end() is None
    assert trace([(None, None)], reached=True).end_to_end() is None


def test_json_round_trip():
    t = Trace(
        "t.example",
        T,
        (Hop(1, (Probe("10.0.0.1", 1.234, "!H"), Probe())), Hop(2, (Probe("10.0.0.9", 2.5),))),
        "10.0.0.9",
        True,
    )
    assert Trace.from_dict(t.to_dict()) == t


@pytest.mark.parametrize(
    "raw",
    [
        [],
        {},
        {"t": "yesterday", "d": "a", "a": None, "r": 0, "h": [[[None, None]]]},
        {"t": "2026-10-01T12:00:00.000000Z", "d": "a b", "a": None, "r": 0, "h": [[[None, None]]]},
        {"t": "2026-10-01T12:00:00.000000Z", "d": "a", "a": "x", "r": 0, "h": [[[None, None]]]},
        {"t": "2026-10-01T12:00:00.000000Z", "d": "a", "a": None, "r": 0, "h": "no"},
        {"t": "2026-10-01T12:00:00.000000Z", "d": "a", "a": None, "r": 0, "h": [5]},
        {"t": "2026-10-01T12:00:00.000000Z", "d": "a", "a": None, "r": 0, "h": [[[]]]},
        {"t": "2026-10-01T12:00:00.000000Z", "d": "a", "a": None, "r": 0, "h": [[["10.0.0.1", "slow"]]]},
    ],
)
def test_from_dict_rejects(raw):
    with pytest.raises(ValueError):
        Trace.from_dict(raw)
