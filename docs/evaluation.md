# Evaluation

Produced by `python tools/evaluate.py --out docs/report.json` (machine: Linux x86_64, Python 3.13.16, seed 1000).

**What this is and is not.** A test environment has no real network that changes on command, so every number comes from
a situation where the truth is known: `tests/netsim.py` builds synthetic paths with load balancing (a router chosen per
probe), a firewall that never answers, a router that is slow to answer without the path being slow, packet loss, jitter
and spikes, and then injects route changes, latency steps, short blips and outages at recorded moments. The expected
result of every run is written down before the tool sees the output, independently of the tool's own code. The
simulator then prints the runs in the exact text format of `traceroute` (Linux/macOS) and `tracert` (Windows) and the
whole pipeline reads them back. It shows that the machinery does what it claims. It does not show how often a real
network behaves like the simulator: per-packet load balancing and blips of one or two runs are assumptions (see
[limitations](limitations.md)). The only measurement on a real system is section 5.

Seeds 1 to 5 and 100 to 139 were used while developing. The numbers below use seeds from 1000 on, which were not
looked at before the code was frozen.

## 1. Is the text read correctly?

3000 generated runs of each format (random paths, silent hops, several addresses on a line, `!H` flags, host names,
decimal comma, `<1 ms`) are printed, parsed and compared with the run that was printed.

| format | identical |
|---|---|
| Linux/macOS, numeric | 3000 of 3000 |
| Linux/macOS, with names | 3000 of 3000 |
| Windows `tracert` | 3000 of 3000 |

Parsing takes 0.1097 ms per run.

## 2. A simulated network with known changes

40 destinations with events and 20 quiet ones, 400 runs each, one run every 15 minutes
(16000 + 8000 runs). Two baselines ran on the same text: **A** compares the first answering address of every hop and
calls any difference an alert; **B** compares the sets of addresses and ignores silent hops.

| | pathmap | baseline A | baseline B |
|---|---|---|---|
| route changes found | 141 of 141 | every difference is an alert | every difference is an alert |
| alerts in 7980 comparisons of quiet runs | 0 | 6135 | 6403 |
| alerts over the runs with events | 141 route changes | 12861 | 12773 |

| kind of route change | injected | found |
|---|---|---|
| reroute (other routers at the changed hops) | 53 | 53 |
| longer path | 12 | 12 |
| shorter path | 17 | 17 |
| router added to a load-balanced group | 28 | 28 (2 of them as an alternate path, not a change) |
| router removed from a load-balanced group | 31 | 31 |

- Kind of change named correctly (reroute, longer, shorter): 82 of 82.
- First differing hop exact: 80 of 82; within one hop: 82 of 82.
- Short blips (one or two runs on another path) injected: 49. Reported as route changes: 0.
- False alarms: 0 route changes and 0 latency shifts, in the 8000 runs of the quiet destinations too.
- Detection delay in runs (median / worst): route 2 / 2, latency 3 / 6,
  outage 2 / 2, router removed from a group 7 / 14.
  Removing a member of a balanced group takes longest: the tool has to be sure that the router is gone and not only unlucky.

## 3. Latency shifts and the hop that causes them

| size of the step | injected | found |
|---|---|---|
| small (under 25 ms) | 13 | 11 |
| medium | 18 | 18 |
| large | 23 | 23 |
| all | 54 | 52 |

Hop named correctly: 52 of 52. The usual shortcut, "the largest jump between neighbouring hops", names the right hop
in 37 of 54, because a router that is slow to answer makes a jump that the path does not have. The median error of the
size of the step is 1.4%. The two missed shifts are below the threshold `max(8 ms, 10% of the usual time)`.

Routers that are slow to answer ("slow reply" in the report): 5 of 5 visible ones flagged, 0 normal hops flagged
(a hop counts as slow when its median is at least 20 ms above that of a later hop, an independent definition).

## 4. Outages

Destinations that stopped answering: 21 of 21 found, recovery 21 of 21, last answering hop named
correctly 21 of 21.

### The `--confirm` setting

Runs in a row that have to disagree before a route change is called. Same simulator, 45 real changes and 30 blips of 1 to 2 runs.

| `--confirm` | found | false route changes | median delay (runs) |
|---|---|---|---|
| 1 | 45 of 45 | 61 | 0 |
| 2 | 45 of 45 | 31 | 1 |
| 3 | 45 of 45 | 0 | 2 |
| 4 | 45 of 45 | 0 | 3 |
| 5 | 45 of 45 | 0 | 4 |

The default is 3: it is the smallest value that has no false route change here. The price is that a real change is called
two runs late; with a lower value it is faster and the blips become changes. If blips on your network are longer, raise it.

## 5. Cost, and one real measurement

100 destinations, 1000 runs each (100000 runs in all):

| step | result |
|---|---|
| analysis of everything | 2.948 s (29.48 ms per destination) |
| one HTML report with all of them | 0.689 s, 2922 KiB |
| write the history | 5.724 s |
| read the history | 7.926 s |
| size of the history | 750 bytes per run, about 75 MiB per destination and year at one run every 5 minutes |

The history is read whole for every report, so a report over a very large history takes seconds (see limitations).

Real `traceroute` (Modern traceroute for Linux, version 2.1.5) on loopback, 10 runs: 1 hop, destination reached, 1.7 ms per command. This only proves that the
command line, the parser and the store work with the real program; a loopback path has no routers to change.
