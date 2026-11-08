"""The numbers quoted in the docs must be the ones in docs/report.json, and the documented commands must exist."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from pathmap.cli import build_parser

ROOT = Path(__file__).resolve().parent.parent
REPORT = json.loads((ROOT / "docs" / "report.json").read_text(encoding="utf-8"))
README = (ROOT / "README.md").read_text(encoding="utf-8")
EVAL = (ROOT / "docs" / "evaluation.md").read_text(encoding="utf-8")
P = REPORT["pipeline"]
W = P["with_events"]
Q = P["quiet"]
FOUND = W["found_route"] + W["found_grow"] + W["found_shrink"]


def test_report_is_a_full_run() -> None:
    assert REPORT["environment"]["quick"] is False
    assert (W["targets"], Q["targets"], P["rounds_per_target"]) == (40, 20, 400)
    assert REPORT["environment"]["seed"] >= 1000


def test_the_claims_are_true_in_the_report() -> None:
    parse = REPORT["parse"]
    assert parse["unix_same"] == parse["unix_total"] == parse["unix_names_same"] == parse["windows_same"]
    assert P["truth_route_events"] == FOUND
    assert W["subkind_ok"] == W["found_route"] and W["ttl_within_1"] == W["found_route"]
    assert W["found_latency_large"] == W["truth_latency_large"]
    assert W["latency_ttl_ok"] == W["found_latency"] > W["latency_naive_ttl_ok"]
    assert (W["found_outage"], W["found_recovery"]) == (W["truth_outage"],) * 2
    assert W["normal_flagged"] == 0 and Q["normal_flagged"] == 0
    assert Q["naive_a_alerts"] > 1000 and Q["naive_b_alerts"] > 1000
    rows = {r["confirm"]: r for r in REPORT["sweep"]["rows"]}
    assert rows[3]["false_route_changes"] == 0 and rows[1]["false_route_changes"] > 0


def test_numbers_in_the_readme() -> None:
    assert f"**{P['quiet_naive_a_alerts']} of {P['quiet_comparisons']}**" in README
    assert f"({P['quiet_naive_b_alerts']} when" in README
    assert "**0**" in README and f"**{FOUND} of {P['truth_route_events']}**" in README
    assert f"0 false alarms in {Q['runs']} runs" in README
    assert f"in {W['ttl_ok']} of {W['found_route']} and within one hop in all {W['found_route']}" in README
    assert f"a median of {W['delay_runs_median']['route']:g} runs" in README
    assert f"**{W['found_latency']} of {W['truth_latency']}**" in README
    assert f"hop named correctly {W['latency_ttl_ok']} of {W['found_latency']}" in README
    assert f"{W['latency_naive_ttl_ok']} of {W['truth_latency']}" in README
    assert f"**{W['found_outage']} of {W['truth_outage']}**" in README
    c = REPORT["cost"]
    assert f"{c['targets']} destinations with {c['rounds']} runs each are analysed in {c['analyze_s']:.1f} s" in README
    assert f"about {round(c['bytes_per_run'], -1):.0f} bytes per run" in README
    assert f"**{REPORT['parse']['unix_total']} of {REPORT['parse']['unix_total']}**" in README


def test_numbers_in_the_evaluation() -> None:
    assert f"| route changes found | {FOUND} of {P['truth_route_events']} |" in EVAL
    for label, key in (("reroute", "reroute"), ("longer path", "longer"), ("shorter path", "shorter")):
        assert f"{W['truth_' + key]} | {W['found_' + key]} |" in EVAL, label
    assert f"| all | {W['truth_latency']} | {W['found_latency']} |" in EVAL
    for r in REPORT["sweep"]["rows"]:
        line = (
            f"| {r['confirm']} | {r['found']} of {r['truth']} | {r['false_route_changes']} | {r['delay_runs_median']} |"
        )
        assert line in EVAL
    assert f"{REPORT['cost']['analyze_s']:g} s" in EVAL


def test_the_evaluation_document_is_generated_from_the_report(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "report.json").write_text((ROOT / "docs" / "report.json").read_text(encoding="utf-8"))
    subprocess.run([sys.executable, str(ROOT / "tools" / "make_evaluation_doc.py")], cwd=tmp_path, check=True)
    assert (tmp_path / "docs" / "evaluation.md").read_text(encoding="utf-8") == EVAL


def test_every_command_in_the_readme_exists_and_the_other_way_round() -> None:
    commands = set(build_parser()._subparsers._group_actions[0].choices)  # type: ignore[union-attr,attr-defined]
    documented = set(re.findall(r"^\| `([a-z-]+)[ `]", README, re.MULTILINE))
    assert documented == commands


def test_the_sample_in_the_examples_is_readable() -> None:
    from datetime import UTC, datetime

    from pathmap.parse import parse

    text = (ROOT / "examples" / "traceroute-linux.txt").read_text(encoding="utf-8")
    trace = parse(text, "8.8.8.8", datetime(2026, 1, 1, tzinfo=UTC))
    assert trace.reached and len(trace.addr_sets()) == 5
