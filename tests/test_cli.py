import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pathmap import cli
from pathmap.model import Hop, Probe, Trace, utcnow
from pathmap.probe import TraceError

SAMPLES = Path(__file__).parent / "samples"


def fake_trace(addr="10.0.0.9", reached=True, when=None, middle="10.0.0.5"):
    def run(target, **kw):
        if target == "bad.example":
            raise TraceError("traceroute failed: no such host")
        hops = (Hop(1, (Probe(middle, 2.0),) * 3), Hop(2, (Probe(addr, 5.0),) * 3))
        return Trace(target, when or utcnow(), hops, addr, reached)

    return run


def run_cli(*argv, capsys):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_trace_stores_and_prints(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_trace", fake_trace())
    code, out, _ = run_cli("trace", "10.0.0.9", "--data", str(tmp_path), capsys=capsys)
    assert code == 0 and "10.0.0.9: 2 hops, reached, 5.0 ms" in out
    code, out, _ = run_cli("show", "10.0.0.9", "--data", str(tmp_path), capsys=capsys)
    assert code == 0 and "10.0.0.5" in out and "1 route(s)" in out


def test_trace_reports_failures_with_exit_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_trace", fake_trace())
    code, out, _ = run_cli("trace", "10.0.0.9", "bad.example", "--data", str(tmp_path), capsys=capsys)
    assert code == 1 and "bad.example: ERROR traceroute failed: no such host" in out and "10.0.0.9: 2 hops" in out


def test_trace_refuses_a_bad_target(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:  # argparse itself takes it for an option
        cli.main(["trace", "-oProxyCommand=x", "--data", str(tmp_path)])
    assert exc.value.code == 2
    code, _, err = run_cli("trace", "--data", str(tmp_path), "--", "-oProxyCommand=x", capsys=capsys)  # and if forced
    assert code == 2 and "not a valid" in err
    code, _, err = run_cli("trace", "a;b", "--data", str(tmp_path), capsys=capsys)
    assert code == 2 and "not a valid" in err


def test_watch_runs_the_rounds_and_sleeps_between(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_trace", fake_trace())
    naps = []
    monkeypatch.setattr(cli.time, "sleep", naps.append)
    code, out, _ = run_cli(
        "watch", "10.0.0.9", "--rounds", "3", "--interval", "30s", "--data", str(tmp_path), capsys=capsys
    )
    assert code == 0 and out.count("10.0.0.9: 2 hops") == 3 and len(naps) == 2 and all(0 < n <= 30 for n in naps)
    traces, _ = cli.Store(tmp_path).read("10.0.0.9")
    assert len(traces) == 3


def test_watch_rejects_a_tiny_interval_and_stops_on_ctrl_c(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_trace", fake_trace())
    code, _, err = run_cli("watch", "10.0.0.9", "--interval", "5s", "--data", str(tmp_path), capsys=capsys)
    assert code == 2 and "at least 10s" in err

    def interrupt(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.time, "sleep", interrupt)
    code, _, err = run_cli("watch", "10.0.0.9", "--interval", "10s", "--data", str(tmp_path), capsys=capsys)
    assert code == 0 and "stopped" in err


def test_parse_reads_a_saved_output(tmp_path, capsys):
    code, out, _ = run_cli("parse", str(SAMPLES / "linux.txt"), "--target", "8.8.8.8", "--store", "--data", str(tmp_path),
                           "--time", "2026-10-01T12:30:00Z", capsys=capsys)  # fmt: skip
    assert code == 0 and "5 hops, reached" in out
    (t,), _ = cli.Store(tmp_path).read("8.8.8.8")
    assert t.ts == datetime(2026, 10, 1, 12, 30, tzinfo=UTC)


def test_parse_errors(tmp_path, capsys):
    bad = tmp_path / "bad.txt"
    bad.write_text("hello")
    code, _, err = run_cli("parse", str(bad), "--target", "8.8.8.8", capsys=capsys)
    assert code == 1 and "cannot read it" in err
    code, _, err = run_cli(
        "parse", str(SAMPLES / "linux.txt"), "--target", "8.8.8.8", "--time", "yesterday", capsys=capsys
    )
    assert code == 2 and "--time" in err
    code, _, err = run_cli("parse", str(tmp_path / "missing.txt"), "--target", "8.8.8.8", capsys=capsys)
    assert code == 2 and "missing.txt" in err


def test_parse_from_stdin(tmp_path, monkeypatch, capsys):
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO((SAMPLES / "windows_en.txt").read_text()))
    code, out, _ = run_cli("parse", "-", "--target", "dns.google", "--time", "2026-10-01T12:30:00", capsys=capsys)
    assert code == 0 and "reached" in out


def fill(tmp_path, switch_after=30, total=60, down_last=0):
    store = cli.Store(tmp_path)
    now = utcnow()
    for i in range(total):
        when = now - timedelta(minutes=15 * (total - i))
        middle = "10.0.0.5" if i < switch_after else "10.0.0.6"
        reached = i < total - down_last
        hops = (Hop(1, (Probe(middle, 2.0),) * 3), Hop(2, (Probe("10.0.0.9", 5.0) if reached else Probe(),) * 3))
        store.append(Trace("10.0.0.9", when, hops, "10.0.0.9", reached))


def test_changes_status_and_report(tmp_path, capsys):
    fill(tmp_path)
    code, out, _ = run_cli("changes", "--data", str(tmp_path), capsys=capsys)
    assert code == 0 and "Route changed: hop 1:" in out
    code, _, _ = run_cli("changes", "--data", str(tmp_path), "--fail-on-change", capsys=capsys)
    assert code == 1
    code, out, _ = run_cli("changes", "--data", str(tmp_path), "--since", "1h", "--fail-on-change", capsys=capsys)
    assert code == 0 and "no change in the period" in out
    code, out, _ = run_cli("status", "--data", str(tmp_path), capsys=capsys)
    assert code == 0 and "10.0.0.9" in out and "STALE" not in out
    code, out, _ = run_cli("status", "--data", str(tmp_path), "--stale", "1m", capsys=capsys)
    assert code == 1 and "STALE" in out


def test_status_flags_a_destination_that_stopped_answering(tmp_path, capsys):
    fill(tmp_path, down_last=5)
    code, out, _ = run_cli("status", "--data", str(tmp_path), capsys=capsys)
    assert code == 1 and "NOT reached" in out


@pytest.mark.parametrize("fmt", ["html", "md", "json", "text"])
def test_report_formats(tmp_path, capsys, fmt):
    fill(tmp_path)
    out_file = tmp_path / f"r.{fmt}"
    code, out, _ = run_cli("report", "--data", str(tmp_path), "--format", fmt, "--out", str(out_file), capsys=capsys)
    assert code == 0 and "wrote" in out and out_file.stat().st_size > 100
    code, out, _ = run_cli("report", "--data", str(tmp_path), "--format", fmt, "--since", "30d", capsys=capsys)
    assert code == 0 and "10.0.0.9" in out
    if fmt == "json":
        assert json.loads(out)[0]["target"] == "10.0.0.9"


def test_report_anonymized(tmp_path, capsys):
    fill(tmp_path)
    code, out, _ = run_cli(
        "report", "--data", str(tmp_path), "--anonymize", "--anon-key", "00ff", "--format", "text", capsys=capsys
    )
    assert code == 0 and "10.0.0" not in out and "target-" in out
    code, _, err = run_cli("report", "--data", str(tmp_path), "--anonymize", "--anon-key", "zz", capsys=capsys)
    assert code == 2 and "hexadecimal" in err


def test_nothing_recorded_and_unknown_target(tmp_path, capsys):
    code, _, err = run_cli("report", "--data", str(tmp_path / "none"), capsys=capsys)
    assert code == 2 and "nothing recorded" in err
    fill(tmp_path)
    code, _, err = run_cli("show", "10.1.1.1", "--data", str(tmp_path), capsys=capsys)
    assert code == 2 and "no history for 10.1.1.1" in err


def test_damaged_history_lines_are_reported(tmp_path, capsys):
    fill(tmp_path)
    path = cli.Store(tmp_path).path_for("10.0.0.9")
    with path.open("ab") as fh:
        fh.write(b"garbage\n")
    __, _, err = run_cli("status", "--data", str(tmp_path), capsys=capsys)
    assert "skipped 1 damaged line" in err


@pytest.mark.parametrize("text", ["5", "5x", "m5", "", "-3d", "99999999d"])
def test_bad_durations(text):
    with pytest.raises(cli.UsageError):
        cli.parse_duration(text)


def test_durations():
    assert cli.parse_duration("90s") == timedelta(seconds=90)
    assert cli.parse_duration("2h") == timedelta(hours=2) and cli.parse_duration("7d") == timedelta(days=7)


def test_version_and_help(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0 and "pathmap 1.0.0" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main([])
