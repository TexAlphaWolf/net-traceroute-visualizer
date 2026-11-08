import shutil
import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from pathmap.probe import TraceError, build_command, run_trace

NOW = datetime(2026, 10, 1, tzinfo=UTC)
OUT = b"traceroute to 10.0.0.9 (10.0.0.9), 30 hops max\n 1  10.0.0.9  1.0 ms  1.1 ms  1.2 ms\n"


def fake(stdout=OUT, stderr=b"", exc=None, seen=None):
    def run(argv, **kw):
        if seen is not None:
            seen.append((argv, kw))
        if exc:
            raise exc
        return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)

    return run


def test_linux_command():
    assert build_command("Linux", "Example.com", queries=2, wait=1.5, max_hops=20) == [
        "traceroute", "-n", "-q", "2", "-w", "1.5", "-m", "20", "example.com",
    ]  # fmt: skip
    assert build_command("Linux", "10.0.0.1", method="icmp")[-2:] == ["-I", "10.0.0.1"]
    assert build_command("Linux", "10.0.0.1", method="tcp")[-2:] == ["-T", "10.0.0.1"]


def test_macos_and_windows_commands():
    assert build_command("Darwin", "10.0.0.1")[0] == "traceroute"
    assert build_command("Darwin", "2001:db8::1")[0] == "traceroute6"
    assert build_command("Windows", "10.0.0.1", wait=1.5, max_hops=12) == [
        "tracert",
        "-d",
        "-h",
        "12",
        "-w",
        "1500",
        "10.0.0.1",
    ]
    with pytest.raises(ValueError):
        build_command("Darwin", "10.0.0.1", method="tcp")
    with pytest.raises(ValueError):
        build_command("Windows", "10.0.0.1", method="icmp")


@pytest.mark.parametrize(
    "kw",
    [
        {"method": "carrier-pigeon"},
        {"max_hops": 0},
        {"max_hops": 65},
        {"queries": 0},
        {"queries": 11},
        {"wait": 0.1},
        {"wait": 31},
    ],
)
def test_command_limits(kw):
    with pytest.raises(ValueError):
        build_command("Linux", "10.0.0.1", **kw)


@pytest.mark.parametrize("target", ["-oProxyCommand=x", "a;b", "a b", ""])
def test_a_target_can_never_become_an_option_or_a_command(target):
    with pytest.raises(ValueError):
        build_command("Linux", target)


def test_run_trace_parses_and_uses_an_argument_list():
    seen = []
    t = run_trace("10.0.0.9", system="Linux", run=fake(seen=seen), which=lambda _: "/usr/bin/x", clock=lambda: NOW)
    assert t.reached and t.ts == NOW and t.hops[0].rtts == [1.0, 1.1, 1.2]
    argv, kw = seen[0]
    assert isinstance(argv, list) and "shell" not in kw
    assert kw["env"]["LC_ALL"] == "C" and kw["timeout"] == 30 * 3 * 2.0 + 15


def test_missing_program():
    with pytest.raises(TraceError, match="not found"):
        run_trace("10.0.0.9", system="Linux", which=lambda _: None)
    with pytest.raises(TraceError, match="Windows"):
        run_trace("10.0.0.9", system="Windows", which=lambda _: None)


def test_timeout_and_os_error():
    with pytest.raises(TraceError, match="did not finish"):
        run_trace(
            "10.0.0.9", system="Linux", which=lambda _: "x", run=fake(exc=subprocess.TimeoutExpired("t", 1)), timeout=1
        )
    with pytest.raises(TraceError, match="cannot run"):
        run_trace(
            "10.0.0.9", system="Linux", which=lambda _: "x", run=fake(exc=PermissionError(13, "Permission denied"))
        )


def test_unreadable_output_uses_the_first_line_of_stderr():
    with pytest.raises(TraceError, match="Name or service not known"):
        run_trace(
            "x.invalid",
            system="Linux",
            which=lambda _: "x",
            run=fake(stdout=b"", stderr=b"x.invalid: Name or service not known\n"),
        )
    with pytest.raises(TraceError, match="no hop lines"):
        run_trace("10.0.0.9", system="Linux", which=lambda _: "x", run=fake(stdout=b"", stderr=b""))


def test_windows_output_is_decoded():
    out = "\r\nTraccia instradamento verso 10.0.0.9\r\n  1    <1 ms    <1 ms    <1 ms  10.0.0.9\r\n".encode("cp850")
    t = run_trace("10.0.0.9", system="Windows", which=lambda _: "x", run=fake(stdout=out))
    assert t.reached


@pytest.mark.skipif(shutil.which("traceroute") is None, reason="no traceroute program on this machine")
def test_real_traceroute_on_the_loopback():
    t = run_trace("127.0.0.1", max_hops=3, queries=2, wait=1.0)
    assert t.reached and t.dest == "127.0.0.1" and len(t.hops) == 1
    assert t.hops[0].addrs == {"127.0.0.1"}
