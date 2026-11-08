"""Read the text printed by ``traceroute`` (Linux, macOS) and ``tracert`` (Windows) into a Trace.

The parser never relies on words ("Request timed out", "Trace complete"): Windows prints them in the language of the
system. It looks at the *shape* of a line: a hop number, then round-trip times, stars and addresses.
"""

from __future__ import annotations

import re
from datetime import datetime

from .model import Hop, Probe, Trace, check_address

_HOP_LINE = re.compile(r"^\s*(\d{1,3})\s+(\S.*?)\s*$")
_UNIX_HEADER = re.compile(r"^\s*traceroute6?\s+to\s", re.IGNORECASE)
_NUMBER = re.compile(r"^<?\d+(?:[.,]\d+)?$")
_ANNOTATION = re.compile(r"^!\S{1,7}$")


class ParseError(ValueError):
    """The text is not a traceroute listing we understand."""


def _ip(token: str) -> str | None:
    try:
        return check_address(token.strip("[]()"))
    except ValueError:
        return None


def _number(token: str) -> float:
    return float(token.lstrip("<").replace(",", "."))


def _header_destination(lines: list[str]) -> str | None:
    """The address of the destination, from the lines before the first hop (the header)."""
    for line in lines:
        if _HOP_LINE.match(line):
            break
        for match in re.finditer(r"[(\[]([^)\]]+)[)\]]", line):
            found = _ip(match.group(1))
            if found:
                return found
        for token in line.replace(",", " ").split():
            found = _ip(token.rstrip(":"))
            if found:
                return found
    return None


def detect_format(text: str) -> str:
    """Return ``"unix"`` or ``"windows"``."""
    lines = text.splitlines()
    if any(_UNIX_HEADER.match(line) for line in lines):
        return "unix"
    for line in lines:
        m = _HOP_LINE.match(line)
        if not m:
            continue
        tokens = m.group(2).split()
        if tokens[0] == "*":
            continue
        if _NUMBER.match(tokens[0]) and len(tokens) > 1 and tokens[1] == "ms":
            return "windows"
        return "unix"
    return "unix"


def _parse_unix_hop(ttl: int, body: str) -> Hop:
    tokens = body.split()
    probes: list[Probe] = []
    current: str | None = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "*":
            probes.append(Probe())
        elif _NUMBER.match(tok) and i + 1 < len(tokens) and tokens[i + 1] == "ms":
            if current is None:
                raise ParseError(f"hop {ttl}: a round-trip time without an address")
            probes.append(Probe(current, _number(tok)))
            i += 1
        elif tok == "ms":
            pass
        elif _ANNOTATION.match(tok):
            if not probes:
                raise ParseError(f"hop {ttl}: an annotation before any probe")
            last = probes[-1]
            probes[-1] = Probe(last.addr, last.rtt, tok)
        elif tok.startswith("["):
            # [AS1234], [MPLS: Label ...], [*]: extra information we do not use
            while i < len(tokens) and not tokens[i].endswith("]"):
                i += 1
        else:
            addr = _ip(tok)
            if addr is None and i + 1 < len(tokens) and tokens[i + 1].startswith("("):
                addr = _ip(tokens[i + 1])
                i += 1
            if addr is None:
                raise ParseError(f"hop {ttl}: cannot read {tok[:30]!r}")
            current = addr
            if i + 1 < len(tokens) and tokens[i + 1] == "ms":
                raise ParseError(f"hop {ttl}: unexpected 'ms'")
        i += 1
    if not probes:
        raise ParseError(f"hop {ttl}: no probes")
    return Hop(ttl, tuple(probes))


def _parse_windows_hop(ttl: int, body: str) -> Hop | None:
    tokens = body.split()
    cells: list[float | None] = []
    pos = 0
    while len(cells) < 3 and pos < len(tokens):
        tok = tokens[pos]
        if tok == "*":
            cells.append(None)
            pos += 1
        elif _NUMBER.match(tok) and pos + 1 < len(tokens) and tokens[pos + 1] == "ms":
            cells.append(_number(tok))
            pos += 2
        else:
            break
    addr = None
    for tok in tokens[pos:]:
        addr = _ip(tok)
        if addr:
            break
    if not cells:
        if addr is None:
            return None  # not a hop line at all
        # "10.0.0.5 reports: Destination host unreachable."
        return Hop(ttl, (Probe(addr, None, "!H"),))
    probes = []
    for cell in cells:
        if cell is None:
            probes.append(Probe())
        elif addr is None:
            raise ParseError(f"hop {ttl}: a round-trip time without an address")
        else:
            probes.append(Probe(addr, cell))
    return Hop(ttl, tuple(probes))


def parse(text: str, target: str, ts: datetime, fmt: str | None = None) -> Trace:
    """Parse the output of one traceroute run.

    ``target`` is what was asked for (an IP address or a name); the address of the destination comes from the header
    of the listing, or from ``target`` when that already is an address. ``reached`` is true when a probe was answered
    by that address.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    kind = fmt or detect_format(text)
    if kind not in ("unix", "windows"):
        raise ParseError(f"unknown format {kind!r}")
    hops: list[Hop] = []
    for line in lines:
        m = _HOP_LINE.match(line)
        if m is None:
            continue
        ttl = int(m.group(1))
        body = m.group(2)
        hop = _parse_unix_hop(ttl, body) if kind == "unix" else _parse_windows_hop(ttl, body)
        if hop is None:
            continue
        if ttl != len(hops) + 1:
            raise ParseError(f"hop numbers jump from {len(hops)} to {ttl}")
        hops.append(hop)
    if not hops:
        raise ParseError("no hop lines found: is this the output of traceroute or tracert?")
    dest = _header_destination(lines) or _ip(target)
    reached = dest is not None and any(dest in hop.addrs for hop in hops)
    return Trace(target, ts, tuple(hops), dest, reached)
