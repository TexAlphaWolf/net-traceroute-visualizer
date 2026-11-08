# Changelog

## 1.0.0

First release.

- Repeated traces with the system `traceroute` / `tracert`; parser for Linux, macOS and Windows output (English and Italian).
- History in JSON lines, one file per target; damaged and truncated lines are survived.
- Route changes (reroute, longer, shorter, load-balanced group changes), blips, latency shifts with the hop that causes them, outages.
- Reports as text, Markdown, JSON or one HTML page with a hop map and a timeline; `--anonymize` for publishing.
- `status` and `changes --fail-on-change` for monitoring and cron.
