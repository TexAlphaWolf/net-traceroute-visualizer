# Security

## Model

pathmap is a command line program with **no network service of its own**. It starts the system `traceroute` or `tracert`
(sending probes to the targets you name) and reads and writes files in one directory (`--data`). The Docker image runs
as an unprivileged user.

- The program is started with an **argument list**, never through a shell. A target is only accepted as an IP address
  or a plain host name: no leading `-`, no spaces, no path characters, no IPv6 zone, at most 253 characters. A name is
  also used in a file name, and the reserved Windows names are avoided.
- Output of the program and every line of the history are **validated** (addresses parsed with `ipaddress`, times,
  numbers in a range); a damaged line is skipped and counted.
- Time and size limits: every run has a timeout.
- The HTML report has **no script** and a `default-src 'none'` policy, no external file, and everything that comes from
  a trace is escaped.
- `--anonymize` replaces addresses and names with keyed labels (HMAC); without `--anon-key` the key is random, so the
  labels cannot be matched between reports.

What it does not protect:

- The history shows the routers between you and the targets, and the times of the traces. Treat the data directory
  as you would a network diagram.
- A report is not anonymous unless you ask for it. Even then, the shape of a path and its latency can identify a network.
- `traceroute` sends packets: use it only on targets you are allowed to probe, and at an interval that is polite (the minimum of `watch` is 10 s).

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab), not in a public issue.
