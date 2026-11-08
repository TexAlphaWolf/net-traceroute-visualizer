import json
import random
from datetime import UTC, datetime, timedelta

import netsim
from pathmap import render
from pathmap.analysis import analyze
from pathmap.model import Hop, Probe, Trace
from test_analysis import DEST, series

OTHER = [["10.0.0.1"], ["10.0.0.77"], ["10.0.0.3"], [DEST]]
DOWN = [["10.0.0.1"], ["10.0.0.2"], [], []]


def busy():
    parts = [(20, {}), (30, {"route": OTHER}), (6, {"route": DOWN, "reached": False}), (30, {"route": OTHER})]
    return analyze("t.example", series(parts))


def test_every_kind_of_event_has_a_sentence():
    an = busy()
    text = [render.describe(e) for e in an.events]
    assert any(t.startswith("Route changed: hop 2: 10.0.0.2 -> 10.0.0.77") for t in text)
    assert any("destination stopped answering" in t and "(10.0.0.2)" in t for t in text)
    assert any("answers again" in t for t in text)
    shifted = analyze("t.example", series([(45, {}), (30, {"rtts": [10.0, 20.0, 90.0, 100.0]})]))
    assert any("moved +" in render.describe(e) and "starting at hop 3" in render.describe(e) for e in shifted.events)


def test_sentences_for_the_other_route_kinds():
    both = [["10.0.0.1"], ["10.0.0.2", "10.0.0.20"], ["10.0.0.3"], [DEST]]
    longer = [["10.0.0.1"], ["10.0.0.2"], ["10.0.0.50"], ["10.0.0.3"], [DEST]]
    out = render.describe(analyze("t", series([(20, {}), (40, {"route": both})])).events[0])
    assert out.startswith("Traffic is now also balanced")
    out = render.describe(analyze("t", series([(20, {"route": both}), (60, {})])).events[0])
    assert out.startswith("A balanced path left the route")
    out = render.describe(
        analyze("t", series([(20, {}), (30, {"route": longer, "rtts": [10.0, 20.0, 30.0, 40.0, 50.0]})])).events[0]
    )
    assert out.startswith("Route got longer") and "1 more hop differs" in out
    many = [[f"10.9.0.{i}"] for i in range(1, 7)] + [[DEST]]
    out = render.describe(
        analyze("t", series([(20, {}), (30, {"route": many, "rtts": [10.0 * i for i in range(1, 8)]})])).events[0]
    )
    assert "more hops differ" in out


def test_alternate_sentence():
    parts = [(12, {})]
    for _ in range(3):
        parts += [(1, {"route": OTHER}), (6, {})]
    (alt,) = [e for e in analyze("t", series(parts)).events if e.kind == "alternate"]
    assert render.describe(alt) == "Another equal-cost router answers at hop 2: 10.0.0.77."


def test_text_markdown_json():
    an = busy()
    text = render.text_report([an])
    assert text.startswith("t.example: reachable, 4 hops") and "Route changed" in text
    md = render.markdown([an])
    assert md.startswith("# Path report") and "| t.example | reachable |" in md and "| 2 | 10.0.0.77 |" in md
    doc = json.loads(render.to_json([an]))
    assert doc[0]["target"] == "t.example" and doc[0]["route"][1] == ["10.0.0.77"]
    assert {e["kind"] for e in doc[0]["events"]} >= {"route_change", "unreachable", "recovered"}
    quiet = analyze("t.example", series([(30, {})]))
    assert "No route change" in render.markdown([quiet])
    down = analyze("t.example", series([(10, {}), (6, {"route": DOWN, "reached": False})]))
    assert "**not reachable**" in render.markdown([down]) and "NOT reachable" in render.text_report([down])


def test_html_is_one_page_without_script_and_with_the_expected_parts():
    page = render.html_page([busy()], now=datetime(2026, 10, 9, tzinfo=UTC))
    assert page.startswith("<!doctype html>")
    assert "<script" not in page.lower() and "http://" not in page and "https://" not in page
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "Generated 2026-10-09 00:00 UTC" in page
    for part in (
        "Route now",
        "End-to-end time",
        "What changed",
        "<svg",
        "10.0.0.77",
        "Dashed grey",
        "destination not answering",
    ):
        assert part in page
    assert page.count("<section") == 1


def test_html_escapes_what_comes_from_outside():
    nasty = Trace(
        'x"><script>alert(1)</script>',
        datetime(2026, 10, 1, tzinfo=UTC),
        (Hop(1, (Probe("10.0.0.1", 1.0),)),),
        "10.0.0.1",
        True,
    )
    traces = [Trace(nasty.target, nasty.ts + timedelta(minutes=i), nasty.hops, nasty.dest, True) for i in range(12)]
    page = render.html_page([analyze(nasty.target, traces)])
    assert "<script>alert" not in page and "&lt;script&gt;" in page


def test_sparkline_needs_data_and_shows_an_outage_band():
    short = analyze("t.example", series([(1, {})]))
    assert "Not enough runs" in render.sparkline_svg(short)
    still_down = analyze("t.example", series([(10, {}), (8, {"route": DOWN, "reached": False})]))
    svg = render.sparkline_svg(still_down)
    assert "var(--bad)" in svg and "<path" in svg


def test_anonymizer_hides_addresses_and_names_but_keeps_the_route_followable():
    an = busy()
    anon = render.Anonymizer(b"k" * 16)
    for out in (
        render.html_page([an], anon=anon),
        render.markdown([an], anon=anon),
        render.text_report([an], anon=anon),
        render.to_json([an], anon=anon),
    ):
        assert "10.0.0." not in out and "t.example" not in out and "node-" in out
    assert anon.addr("10.0.0.1") == render.Anonymizer(b"k" * 16).addr("10.0.0.1")
    assert anon.addr("10.0.0.1") != render.Anonymizer(b"x" * 16).addr("10.0.0.1")
    assert render.Anonymizer().addr("10.0.0.1") != render.Anonymizer().addr("10.0.0.1")  # random key by default
    assert anon.addr("*") == "*"


def test_a_simulated_network_renders_without_errors():
    rng = random.Random(3)
    analyses = []
    for i in range(4):
        sc = netsim.make_scenario(rng, i, 250, decoy=(i == 0))
        analyses.append(analyze(sc.path.target, sc.run(rng)))
    page = render.html_page(analyses, since=netsim.T0 + timedelta(days=1))
    assert page.count("<section") == 4 and "since 2026-10-02" in page
    assert render.summarize(analyses[0]).runs == 250
