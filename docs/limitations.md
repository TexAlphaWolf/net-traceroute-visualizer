# Limitations

- **The evaluation uses a simulator.** Per-packet load balancing and blips of one or two runs are assumptions. Real
  networks with per-flow balancing look the same to `traceroute` only when the probe's flow is the same; pathmap does not
  control the flow (no Paris-traceroute mode) and `mtr` output is not read.
- **Blips longer than `confirm - 1` runs are route changes.** That is the definition. Raise `--confirm` if your paths flip for longer.
- **A hop removed just before a silent hop** makes the first differing hop ambiguous (off by one).
- **Removing a router from a balanced group** is noticed after a median of 7 runs (worst 14), because the tool has to rule out bad luck.
- **Small latency shifts are missed**: anything below `max(8 ms, 10% of the usual time)`.
- **The history is read whole.** A report over a very large history takes seconds (about 8 s for 100 000 runs); keep
  one directory per project or rotate it (a file per target, so old files can simply be moved away).
- **What a router shows is not the path of your traffic.** `traceroute` shows the path of its own probes; a hop that is slow to answer
  can be flagged as "slow reply" but the tool cannot know how that router forwards traffic.
- Only the loopback was measured with the real program; the Linux, macOS and Windows formats are covered by samples and the generator.
- IPv6 works through `traceroute -6`/`traceroute6`/`tracert`, but the evaluation is only IPv4.
