"""Run the traceroute program of the system and turn its output into a Trace."""

from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import subprocess
from collections.abc import Callable
from datetime import datetime
from typing import Any

from .model import Trace, check_target, utcnow
from .parse import ParseError, parse

METHODS = ("udp", "icmp", "tcp")


class TraceError(RuntimeError):
    """The traceroute program could not be run or printed nothing usable. The message is short and safe to show."""


def build_command(
    system: str, target: str, *, max_hops: int = 30, queries: int = 3, wait: float = 2.0, method: str = "udp"
) -> list[str]:
    """The argument list (never a shell string) for one run. ``target`` must already be validated."""
    if method not in METHODS:
        raise ValueError(f"method must be one of {', '.join(METHODS)}")
    if not 1 <= max_hops <= 64:
        raise ValueError("max_hops must be between 1 and 64")
    if not 1 <= queries <= 10:
        raise ValueError("queries must be between 1 and 10")
    if not 0.2 <= wait <= 30:
        raise ValueError("wait must be between 0.2 and 30 seconds")
    target = check_target(target)
    if system == "Windows":
        if method != "udp":
            raise ValueError("tracert always uses ICMP echo: leave --method at its default on Windows")
        # tracert always sends 3 probes per hop
        return ["tracert", "-d", "-h", str(max_hops), "-w", str(int(wait * 1000)), target]
    is_v6 = ":" in target and ipaddress.ip_address(target).version == 6
    program = "traceroute6" if (system == "Darwin" and is_v6) else "traceroute"
    argv = [program, "-n", "-q", str(queries), "-w", f"{wait:g}", "-m", str(max_hops)]
    if method == "icmp":
        argv.append("-I")
    elif method == "tcp":
        if system != "Linux":
            raise ValueError("--method tcp is only available with the Linux traceroute")
        argv.append("-T")
    argv.append(target)
    return argv


def _decode(raw: bytes, system: str) -> str:
    if system == "Windows":
        try:
            return raw.decode("oem", errors="replace")
        except LookupError:
            return raw.decode("cp437", errors="replace")
    return raw.decode("utf-8", errors="replace")


def run_trace(
    target: str,
    *,
    max_hops: int = 30,
    queries: int = 3,
    wait: float = 2.0,
    method: str = "udp",
    timeout: float | None = None,
    system: str | None = None,
    run: Callable[..., Any] = subprocess.run,
    which: Callable[[str], str | None] = shutil.which,
    clock: Callable[[], datetime] = utcnow,
) -> Trace:
    """Run one traceroute toward ``target`` and return it. Raises TraceError with a short message on failure."""
    system = system or platform.system()
    target = check_target(target)
    argv = build_command(system, target, max_hops=max_hops, queries=queries, wait=wait, method=method)
    if which(argv[0]) is None:
        hint = "install the 'traceroute' package" if system != "Windows" else "tracert should be part of Windows"
        raise TraceError(f"'{argv[0]}' was not found on this system ({hint})")
    limit = timeout if timeout is not None else max_hops * queries * wait + 15
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    started = clock()
    try:
        done = run(argv, capture_output=True, timeout=limit, check=False, env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise TraceError(f"{argv[0]} did not finish within {limit:g} seconds") from None
    except OSError as exc:
        raise TraceError(f"cannot run {argv[0]}: {exc.strerror or 'error'}") from None
    text = _decode(done.stdout, system)
    try:
        return parse(text, target, started)
    except ParseError:
        detail = _decode(done.stderr, system).strip().splitlines()
        message = detail[0][:80] if detail else "no hop lines in the output"
        raise TraceError(f"{argv[0]} failed: {message}") from None
