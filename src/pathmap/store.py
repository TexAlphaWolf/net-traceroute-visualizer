"""The history: one JSON-lines file per target, appended to, never rewritten."""

from __future__ import annotations

import json
from pathlib import Path

from .model import Trace, check_target

PREFIX = "trace-"
SUFFIX = ".jsonl"


class Store:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.dir = root / "traces"

    def path_for(self, target: str) -> Path:
        """File of a target. ``:`` of IPv6 becomes ``=`` (a host name cannot contain it), and the prefix keeps names
        such as ``con`` away from the reserved device names of Windows."""
        safe = check_target(target).replace(":", "=")
        return self.dir / f"{PREFIX}{safe}{SUFFIX}"

    def append(self, trace: Trace) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        line = json.dumps(trace.to_dict(), separators=(",", ":")) + "\n"
        path = self.path_for(trace.target)
        # A crash can leave a truncated last line without its newline: end it first, or the new record would be glued
        # to the fragment and lost with it. read() skips the fragment.
        if path.exists() and path.stat().st_size:
            with path.open("rb") as fh:
                fh.seek(-1, 2)
                if fh.read(1) != b"\n":
                    line = "\n" + line
        with path.open("ab") as fh:  # one write call per record
            fh.write(line.encode("utf-8"))

    def read(self, target: str) -> tuple[list[Trace], int]:
        """All the traces of a target in time order, and how many damaged lines were skipped."""
        path = self.path_for(target)
        if not path.exists():
            return [], 0
        traces: list[Trace] = []
        skipped = 0
        with path.open("rb") as fh:
            for raw in fh:
                if not raw.strip():
                    continue
                try:
                    traces.append(Trace.from_dict(json.loads(raw)))
                except (ValueError, RecursionError):
                    skipped += 1
        traces.sort(key=lambda t: t.ts)
        return traces, skipped

    def targets(self) -> list[str]:
        if not self.dir.is_dir():
            return []
        found = []
        for p in sorted(self.dir.glob(f"{PREFIX}*{SUFFIX}")):
            name = p.name[len(PREFIX) : -len(SUFFIX)].replace("=", ":")
            try:
                found.append(check_target(name))
            except ValueError:
                continue
        return found

    def size_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.dir.glob(f"{PREFIX}*{SUFFIX}")) if self.dir.is_dir() else 0
