"""Render docs/demo.png: the HTML report of a week on a SYNTHETIC network (no real network is needed to show the page).

pip install -e ".[dev]" && playwright install chromium
python tools/screenshot.py
"""

from __future__ import annotations

import random
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

from playwright.sync_api import sync_playwright  # noqa: E402

import netsim  # noqa: E402
from netsim import Router, Scenario, SimPath, Stage  # noqa: E402
from pathmap.analysis import analyze  # noqa: E402
from pathmap.render import html_page  # noqa: E402

OUT = ROOT / "docs" / "demo.png"
ROUNDS = 6 * 96  # six days, one run every 15 minutes


def stage(addr: str | list[str], link: float, *, silent: bool = False, slow: float = 0.0) -> Stage:
    addrs = [addr] if isinstance(addr, str) else addr
    return Stage([Router(a, offset=0.2, silent=silent, slow=slow) for a in addrs], link)


def main_path() -> Scenario:
    path = SimPath(
        target="www.example.net",
        dest="203.0.113.10",
        stages=[
            stage("192.168.1.1", 0.4),
            stage("10.20.0.1", 4.0),
            stage("10.20.1.1", 3.0),
            stage(["10.30.0.1", "10.30.0.2"], 6.0),  # balanced over two routers
            stage("10.30.1.1", 5.0),
            stage("10.40.0.1", 4.0, silent=True),  # a firewall that never answers
            stage("10.40.1.1", 3.0, slow=95.0),  # answers slowly, forwards normally
            stage("10.50.0.1", 6.0),
            stage("203.0.113.10", 4.0),
        ],
        net=7,
    )
    sc = Scenario(path, ROUNDS)

    def reroute(p: SimPath) -> None:
        p.stages[3] = stage("10.31.0.1", 9.0)  # day 2: traffic moves to another transit

    def slower(p: SimPath) -> None:
        p.stages[7].link_ms += 22.0  # day 4: a link gets 44 ms slower (round trip)

    def down(p: SimPath) -> None:
        p.down_from = 8

    def up(p: SimPath) -> None:
        p.down_from = None

    sc.at(130, reroute)
    sc.at(300, slower)
    sc.at(430, down)
    sc.at(438, up)
    return sc


def quiet_path() -> Scenario:
    rng = random.Random(4)
    sc = netsim.make_scenario(rng, 2, ROUNDS, events=False)
    sc.path.target = "api.example.org"
    return sc


def main() -> None:
    rng = random.Random(21)
    analyses = []
    for sc in (main_path(), quiet_path()):
        analyses.append(analyze(sc.path.target, sc.run(rng)))
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "report.html"
        page.write_text(html_page(analyses, now=datetime(2026, 10, 7, 9, 0, tzinfo=UTC)), encoding="utf-8")
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            shot = browser.new_page(viewport={"width": 1000, "height": 2600}, device_scale_factor=2)
            shot.goto(page.as_uri())
            box = shot.locator("section").first.bounding_box()
            assert box is not None
            shot.screenshot(
                path=str(OUT), clip={"x": 0, "y": 0, "width": 1000, "height": box["y"] + box["height"] + 16}
            )
            browser.close()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
