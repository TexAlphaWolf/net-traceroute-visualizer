import random
from datetime import UTC, datetime
from pathlib import Path

import pytest

import netsim
from pathmap.parse import ParseError, detect_format, parse

T = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
SAMPLES = Path(__file__).parent / "samples"


def sample(name: str, target: str):
    return parse((SAMPLES / name).read_text(), target, T)


def test_linux():
    t = sample("linux.txt", "8.8.8.8")
    assert len(t.hops) == 5 and t.dest == "8.8.8.8" and t.reached
    assert [sorted(h.addrs) for h in t.hops] == [
        ["192.168.1.1"],
        ["10.20.0.1"],
        [],
        ["72.14.1.1", "72.14.1.2"],
        ["8.8.8.8"],
    ]
    assert t.hops[0].rtts == [0.432, 0.401, 0.389]
    assert t.hops[2].lost == 3
    # "72.14.1.1  12.3 ms 72.14.1.2  13.4 ms  12.9 ms": the third answer belongs to the second address
    assert [(p.addr, p.rtt) for p in t.hops[3].probes] == [
        ("72.14.1.1", 12.3),
        ("72.14.1.2", 13.4),
        ("72.14.1.2", 12.9),
    ]


def test_names_are_ignored_but_addresses_kept():
    t = sample("linux_names.txt", "dns.google")
    assert t.dest == "8.8.8.8" and t.reached
    assert t.hops[0].addrs == {"192.168.1.1"}
    assert [(p.addr, p.rtt) for p in t.hops[2].probes] == [(None, None), ("72.14.1.1", 12.3), ("72.14.1.1", 12.9)]


def test_annotations_and_extra_information():
    t = sample("linux_flags.txt", "203.0.113.9")
    assert t.hops[1].addrs == {"10.0.0.1"}  # [AS64500] skipped
    assert t.hops[2].rtts == [7.0, 7.1, 7.2]  # [MPLS: ...] skipped
    assert [p.note for p in t.hops[3].probes] == ["!H", "!H", "!H"]
    assert not t.reached


def test_macos():
    t = sample("macos.txt", "example.com")
    assert t.dest == "93.184.216.34" and t.reached and len(t.hops) == 3


def test_windows_english_with_names():
    t = sample("windows_en.txt", "dns.google")
    assert detect_format((SAMPLES / "windows_en.txt").read_text()) == "windows"
    assert t.dest == "8.8.8.8" and t.reached
    assert t.hops[0].addrs == {"192.168.1.1"} and t.hops[0].rtts == [1.0, 1.0, 1.0]  # "<1 ms"
    assert t.hops[2].lost == 3 and t.hops[2].addrs == frozenset()
    assert t.hops[4].addrs == {"8.8.8.8"}


def test_windows_in_another_language():
    t = sample("windows_it.txt", "8.8.8.8")
    assert len(t.hops) == 3 and t.reached and t.hops[1].lost == 3


def test_windows_destination_unreachable_report():
    t = sample("windows_unreachable.txt", "10.9.9.9")
    assert t.hops[2].addrs == {"10.0.0.1"} and t.hops[2].probes[0].note == "!H"
    assert not t.reached


def test_ipv6():
    t = sample("ipv6.txt", "2001:db8::53")
    assert t.dest == "2001:db8::53" and t.reached and len(t.hops) == 3


def test_a_host_that_never_answers_ends_in_stars():
    t = sample("empty_stars.txt", "203.0.113.50")
    assert not t.reached and len(t.hops) == 4 and len(t.addr_sets()) == 1


def test_destination_comes_from_the_target_when_there_is_no_header():
    t = parse(" 1  10.0.0.1  1.0 ms\n 2  10.0.0.9  2.0 ms\n", "10.0.0.9", T)
    assert t.dest == "10.0.0.9" and t.reached


def test_no_destination_is_not_reached():
    t = parse(" 1  10.0.0.1  1.0 ms\n", "some.name", T)
    assert t.dest is None and not t.reached


def test_decimal_comma_and_crlf():
    t = parse(
        "traceroute to 10.0.0.9 (10.0.0.9), 30 hops max\r\n 1  10.0.0.9  1,5 ms  1,6 ms  1,7 ms\r\n", "10.0.0.9", T
    )
    assert t.hops[0].rtts == [1.5, 1.6, 1.7]


@pytest.mark.parametrize(
    "text",
    [
        "",
        "hello world\n",
        "traceroute: unknown host\n",
        "traceroute to x (10.0.0.1)\n 1  10.0.0.1  1.0 ms\n 3  10.0.0.3  1.0 ms\n",  # jump from 1 to 3
        " 1  1.0 ms\n",  # a time without an address
        " 1  10.0.0.1  ms ms\n 2  ???  1 ms\n",
        " 1  !H\n",  # an annotation before any probe
        " 1  notanaddress  1.0 ms\n",
        " 1  10.0.0.1 ms\n",
    ],
)
def test_garbage_is_refused(text):
    with pytest.raises(ParseError):
        parse(text, "10.0.0.1", T)


def test_windows_line_that_is_not_a_hop_is_skipped():
    text = "Tracing route to 10.0.0.9 over a maximum of 30 hops\n  1    <1 ms    <1 ms    <1 ms  10.0.0.9\n  2  nothing useful here\n"
    t = parse(text, "10.0.0.9", T, fmt="windows")
    assert len(t.hops) == 1


def test_unknown_format_is_refused():
    with pytest.raises(ParseError):
        parse("x", "10.0.0.1", T, fmt="solaris")


def test_detect_format_defaults_to_unix_for_stars_only():
    assert detect_format(" 1  * * *\n") == "unix"
    assert detect_format("nothing") == "unix"


@pytest.mark.parametrize("seed", range(5))
def test_what_the_simulator_prints_is_read_back(seed):
    rng = random.Random(seed)
    for i in range(40):
        sc = netsim.make_scenario(rng, i, 3, events=False, decoy=bool(i % 2))
        trace = sc.path.trace(rng, T, loss=0.08)
        assert parse(netsim.render_unix(trace), trace.target, T) == trace
        assert parse(netsim.render_unix(trace, names=True), trace.target, T) == trace
        win = parse(netsim.render_windows(trace), trace.target, T)
        assert len(win.hops) == len(trace.hops) and win.reached == trace.reached
        for got, want in zip(win.hops, trace.hops, strict=True):
            last = next((p.addr for p in reversed(want.probes) if p.addr), None)
            assert got.addrs == (frozenset([last]) if last else frozenset())
