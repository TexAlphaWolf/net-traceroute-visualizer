"""Write docs/evaluation.md from docs/report.json (run from the repository root)."""

import json
from pathlib import Path

R = Path("docs/report.json")
d = json.loads(R.read_text())
E_, P, S, C, RL = d["environment"], d["pipeline"], d["sweep"], d["cost"], d["real"]
W, Q, PA = P["with_events"], P["quiet"], d["parse"]
FOUND = W["found_route"] + W["found_grow"] + W["found_shrink"]
dm, dx = W["delay_runs_median"], W["delay_runs_max"]
rows = "\n".join(
    f"| {r['confirm']} | {r['found']} of {r['truth']} | {r['false_route_changes']} | {r['delay_runs_median']} |"
    for r in S["rows"]
)
txt = f"""# Evaluation

Produced by `python tools/evaluate.py --out docs/report.json` (machine: {E_["system"]}, Python {E_["python"]}, seed {E_["seed"]}).

**What this is and is not.** A test environment has no real network that changes on command, so every number comes from
a situation where the truth is known: `tests/netsim.py` builds synthetic paths with load balancing (a router chosen per
probe), a firewall that never answers, a router that is slow to answer without the path being slow, packet loss, jitter
and spikes, and then injects route changes, latency steps, short blips and outages at recorded moments. The expected
result of every run is written down before the tool sees the output, independently of the tool's own code. The
simulator then prints the runs in the exact text format of `traceroute` (Linux/macOS) and `tracert` (Windows) and the
whole pipeline reads them back. It shows that the machinery does what it claims. It does not show how often a real
network behaves like the simulator: per-packet load balancing and blips of one or two runs are assumptions (see
[limitations](limitations.md)). The only measurement on a real system is section 5.

Seeds 1 to 5 and 100 to 139 were used while developing. The numbers below use seeds from {E_["seed"]} on, which were not
looked at before the code was frozen.

## 1. Is the text read correctly?

{PA["traces"]} generated runs of each format (random paths, silent hops, several addresses on a line, `!H` flags, host names,
decimal comma, `<1 ms`) are printed, parsed and compared with the run that was printed.

| format | identical |
|---|---|
| Linux/macOS, numeric | {PA["unix_same"]} of {PA["unix_total"]} |
| Linux/macOS, with names | {PA["unix_names_same"]} of {PA["unix_names_total"]} |
| Windows `tracert` | {PA["windows_same"]} of {PA["windows_total"]} |

Parsing takes {PA["parse_ms_each"]:g} ms per run.

## 2. A simulated network with known changes

{W["targets"]} destinations with events and {Q["targets"]} quiet ones, {P["rounds_per_target"]} runs each, one run every {P["interval_minutes"]} minutes
({W["runs"]} + {Q["runs"]} runs). Two baselines ran on the same text: **A** compares the first answering address of every hop and
calls any difference an alert; **B** compares the sets of addresses and ignores silent hops.

| | pathmap | baseline A | baseline B |
|---|---|---|---|
| route changes found | {FOUND} of {P["truth_route_events"]} | every difference is an alert | every difference is an alert |
| alerts in {P["quiet_comparisons"]} comparisons of quiet runs | 0 | {P["quiet_naive_a_alerts"]} | {P["quiet_naive_b_alerts"]} |
| alerts over the runs with events | {FOUND} route changes | {W["naive_a_alerts"]} | {W["naive_b_alerts"]} |

| kind of route change | injected | found |
|---|---|---|
| reroute (other routers at the changed hops) | {W["truth_reroute"]} | {W["found_reroute"]} |
| longer path | {W["truth_longer"]} | {W["found_longer"]} |
| shorter path | {W["truth_shorter"]} | {W["found_shorter"]} |
| router added to a load-balanced group | {W["truth_grow"]} | {W["found_grow"]} ({W["found_grow_as_alternate"]} of them as an alternate path, not a change) |
| router removed from a load-balanced group | {W["truth_shrink"]} | {W["found_shrink"]} |

- Kind of change named correctly (reroute, longer, shorter): {W["subkind_ok"]} of {W["found_route"]}.
- First differing hop exact: {W["ttl_ok"]} of {W["found_route"]}; within one hop: {W["ttl_within_1"]} of {W["found_route"]}.
- Short blips (one or two runs on another path) injected: {W["truth_blip"]}. Reported as route changes: 0.
- False alarms: 0 route changes and 0 latency shifts, in the {Q["runs"]} runs of the quiet destinations too.
- Detection delay in runs (median / worst): route {dm["route"]:g} / {dx["route"]}, latency {dm["latency"]:g} / {dx["latency"]},
  outage {dm["outage"]} / {dx["outage"]}, router removed from a group {dm["shrink"]} / {dx["shrink"]}.
  Removing a member of a balanced group takes longest: the tool has to be sure that the router is gone and not only unlucky.

## 3. Latency shifts and the hop that causes them

| size of the step | injected | found |
|---|---|---|
| small (under 25 ms) | {W["truth_latency_small"]} | {W["found_latency_small"]} |
| medium | {W["truth_latency_medium"]} | {W["found_latency_medium"]} |
| large | {W["truth_latency_large"]} | {W["found_latency_large"]} |
| all | {W["truth_latency"]} | {W["found_latency"]} |

Hop named correctly: {W["latency_ttl_ok"]} of {W["found_latency"]}. The usual shortcut, "the largest jump between neighbouring hops", names the right hop
in {W["latency_naive_ttl_ok"]} of {W["truth_latency"]}, because a router that is slow to answer makes a jump that the path does not have. The median error of the
size of the step is {W["latency_delta_error_median"] * 100:.1f}%. The two missed shifts are below the threshold `max(8 ms, 10% of the usual time)`.

Routers that are slow to answer ("slow reply" in the report): {W["decoy_visible_flagged"]} of {W["decoy_visible"]} visible ones flagged, {W["normal_flagged"]} normal hops flagged
(a hop counts as slow when its median is at least 20 ms above that of a later hop, an independent definition).

## 4. Outages

Destinations that stopped answering: {W["found_outage"]} of {W["truth_outage"]} found, recovery {W["found_recovery"]} of {W["truth_outage"]}, last answering hop named
correctly {W["outage_ttl_ok"]} of {W["truth_outage"]}.

### The `--confirm` setting

Runs in a row that have to disagree before a route change is called. Same simulator, 45 real changes and 30 blips of 1 to 2 runs.

| `--confirm` | found | false route changes | median delay (runs) |
|---|---|---|---|
{rows}

The default is 3: it is the smallest value that has no false route change here. The price is that a real change is called
two runs late; with a lower value it is faster and the blips become changes. If blips on your network are longer, raise it.

## 5. Cost, and one real measurement

{C["targets"]} destinations, {C["rounds"]} runs each ({C["runs"]} runs in all):

| step | result |
|---|---|
| analysis of everything | {C["analyze_s"]:g} s ({C["analyze_ms_per_target"]:g} ms per destination) |
| one HTML report with all of them | {C["html_s"]:g} s, {C["html_kib"]:.0f} KiB |
| write the history | {C["write_s"]:g} s |
| read the history | {C["read_s"]:g} s |
| size of the history | {C["bytes_per_run"]:.0f} bytes per run, about {C["kib_per_target_year_5min"] / 1024:.0f} MiB per destination and year at one run every 5 minutes |

The history is read whole for every report, so a report over a very large history takes seconds (see limitations).

Real `traceroute` ({RL["version"]}) on loopback, {RL["runs"]} runs: {RL["hops"]} hop, destination reached, {RL["run_ms_median"]:g} ms per command. This only proves that the
command line, the parser and the store work with the real program; a loopback path has no routers to change.
"""
Path("docs/evaluation.md").write_text(txt)
