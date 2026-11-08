"""Probes, hops and traces: the data model, its validation and its JSON form."""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache

MAX_HOPS = 255
MAX_PROBES = 16
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_NOTE = re.compile(r"^![A-Za-z0-9<>]{1,6}$")


def check_target(value: str) -> str:
    """Return the canonical form of a target (an IP address or a host name) or raise ValueError.

    The value ends up in the argument list of ``traceroute`` and in a file name, so only plain host names and IP
    addresses are accepted: no leading ``-``, no spaces, no path characters, no IPv6 zone.
    """
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("a target must be an IP address or a host name of at most 253 characters")
    if "%" not in value:  # ipaddress accepts an IPv6 zone ("fe80::1%eth0"); a zone is local to a machine, not a target
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    if _HOSTNAME.match(value) is None:
        raise ValueError(f"not a valid IP address or host name: {value[:60]!r}")
    return value.lower()


@lru_cache(maxsize=65536)
def check_address(value: str) -> str:
    """Return the canonical form of an IP address found in tool output, or raise ValueError."""
    if "%" in value:
        raise ValueError("an address with a zone is not accepted")
    return str(ipaddress.ip_address(value))


@dataclass(frozen=True)
class Probe:
    """One probe packet: who answered (None for no answer), how long it took in ms, and an optional flag such as !H."""

    addr: str | None = None
    rtt: float | None = None
    note: str = ""

    def __post_init__(self) -> None:
        if self.rtt is not None and not (math.isfinite(self.rtt) and 0 <= self.rtt < 1e6):
            raise ValueError(f"round-trip time out of range: {self.rtt!r}")
        if self.rtt is not None and self.addr is None:
            raise ValueError("a probe with a round-trip time needs an address")
        if self.note and _NOTE.match(self.note) is None:
            raise ValueError(f"bad probe note: {self.note[:20]!r}")


@dataclass(frozen=True)
class Hop:
    """All the probes sent with one TTL."""

    ttl: int
    probes: tuple[Probe, ...]

    def __post_init__(self) -> None:
        if not 1 <= self.ttl <= MAX_HOPS:
            raise ValueError(f"TTL out of range: {self.ttl}")
        if not 1 <= len(self.probes) <= MAX_PROBES:
            raise ValueError(f"a hop needs between 1 and {MAX_PROBES} probes")

    @property
    def addrs(self) -> frozenset[str]:
        return frozenset(p.addr for p in self.probes if p.addr is not None)

    @property
    def rtts(self) -> list[float]:
        return [p.rtt for p in self.probes if p.rtt is not None]

    @property
    def lost(self) -> int:
        return sum(1 for p in self.probes if p.addr is None)


@dataclass(frozen=True)
class Trace:
    """One traceroute run: the hops, when it ran, and whether the destination answered."""

    target: str
    ts: datetime
    hops: tuple[Hop, ...]
    dest: str | None = None
    reached: bool = False

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValueError("a trace needs a time zone aware timestamp")
        if not self.hops:
            raise ValueError("a trace needs at least one hop")
        for i, hop in enumerate(self.hops, start=1):
            if hop.ttl != i:
                raise ValueError("hops must be numbered 1, 2, 3 ... without gaps")

    def addr_sets(self) -> tuple[frozenset[str], ...]:
        """The addresses seen at each TTL, without the silent hops at the end (a run toward a host that never answers
        ends in a row of ``* * *``: that is not part of the path)."""
        sets = [hop.addrs for hop in self.hops]
        while sets and not sets[-1]:
            sets.pop()
        return tuple(sets)

    def last_hop_rtts(self) -> list[float]:
        """The round-trip times of the last hop that answered."""
        for hop in reversed(self.hops):
            if hop.addrs:
                return hop.rtts
        return []

    def end_to_end(self) -> float | None:
        """Median round-trip time to the destination, or None when it did not answer."""
        if not self.reached:
            return None
        rtts = self.last_hop_rtts()
        if not rtts:
            return None
        ordered = sorted(rtts)
        mid = len(ordered) // 2
        return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2

    def to_dict(self) -> dict[str, object]:
        hops: list[list[list[object]]] = []
        for hop in self.hops:
            row: list[list[object]] = []
            for p in hop.probes:
                cell: list[object] = [p.addr, p.rtt]
                if p.note:
                    cell.append(p.note)
                row.append(cell)
            hops.append(row)
        return {
            "t": self.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "d": self.target,
            "a": self.dest,
            "r": 1 if self.reached else 0,
            "h": hops,
        }

    @classmethod
    def from_dict(cls, raw: object) -> Trace:
        """Strict inverse of to_dict; raises ValueError on anything unexpected."""
        if not isinstance(raw, dict):
            raise ValueError("a record must be an object")
        try:
            ts = datetime.strptime(str(raw["t"]), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
            target = check_target(str(raw["d"]))
            dest = raw["a"]
            dest_text = None if dest is None else check_address(str(dest))
            reached = raw["r"] in (1, True)
            rows = raw["h"]
            if not isinstance(rows, list):
                raise ValueError("hops must be a list")
            hops: list[Hop] = []
            for i, row in enumerate(rows, start=1):
                probes: list[Probe] = []
                for cell in row:
                    addr = cell[0]
                    rtt = cell[1]
                    note = cell[2] if len(cell) > 2 else ""
                    probes.append(
                        Probe(
                            None if addr is None else check_address(str(addr)),
                            None if rtt is None else float(rtt),
                            str(note),
                        )
                    )
                hops.append(Hop(i, tuple(probes)))
        except (KeyError, TypeError, IndexError) as exc:
            raise ValueError(f"malformed record: {exc!r}") from None
        return cls(target, ts, tuple(hops), dest_text, reached)


def utcnow() -> datetime:
    return datetime.now(UTC)
