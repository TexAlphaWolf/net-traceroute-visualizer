from datetime import UTC, datetime, timedelta

import pytest

from pathmap.model import Hop, Probe, Trace
from pathmap.store import Store

T = datetime(2026, 10, 1, tzinfo=UTC)


def tr(target, minutes, addr="10.0.0.9"):
    return Trace(target, T + timedelta(minutes=minutes), (Hop(1, (Probe(addr, 1.0),)),), addr, True)


def test_append_and_read(tmp_path):
    s = Store(tmp_path)
    s.append(tr("a.example", 5))
    s.append(tr("a.example", 0))
    traces, skipped = s.read("a.example")
    assert [t.ts for t in traces] == [T, T + timedelta(minutes=5)]  # sorted by time, whatever the file order
    assert skipped == 0
    assert s.read("nothing.example") == ([], 0)


def test_damaged_lines_are_skipped_and_counted(tmp_path):
    s = Store(tmp_path)
    s.append(tr("a.example", 0))
    with s.path_for("a.example").open("ab") as fh:
        fh.write(
            b"{not json\n\n\xff\xfe\n[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[\n"
        )
        fh.write(b'{"t":"2026-10-01T00:00:00.000000Z","d":"a.example"')  # a crash in the middle of a record
    s.append(tr("a.example", 10))
    traces, skipped = s.read("a.example")
    assert len(traces) == 2 and skipped == 4


def test_targets_and_file_names(tmp_path):
    s = Store(tmp_path)
    for name in ("b.example", "10.0.0.1", "2001:db8::1", "con"):
        s.append(tr(name, 0))
    assert sorted(s.targets()) == sorted(["b.example", "10.0.0.1", "2001:db8::1", "con"])
    assert s.path_for("2001:db8::1").name == "trace-2001=db8==1.jsonl"
    assert s.path_for("con").name == "trace-con.jsonl"  # not a reserved device name on Windows
    assert s.size_bytes() > 0
    assert Store(tmp_path / "empty").targets() == [] and Store(tmp_path / "empty").size_bytes() == 0


def test_stray_files_are_not_targets(tmp_path):
    s = Store(tmp_path)
    s.append(tr("a.example", 0))
    (s.dir / "trace-bad name.jsonl").write_text("")
    (s.dir / "notes.txt").write_text("")
    assert s.targets() == ["a.example"]


def test_a_target_cannot_escape_the_directory(tmp_path):
    s = Store(tmp_path)
    for bad in ("../x", "a/b", "..\\x"):
        with pytest.raises(ValueError):
            s.path_for(bad)
