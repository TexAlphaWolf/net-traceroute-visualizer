# Contributing

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest -n auto --cov
```

The detection is tested against a simulator with known truth (`tests/netsim.py`); a change to `analysis.py` should be
followed by `python tools/evaluate.py --check`, which fails on a false alarm or a missed change. Do not tune on the seeds the
report uses (1000 and above): use the development seeds, then look at the report once.

Claims in the docs are checked against `docs/report.json` by `tests/test_docs.py`. Re-run
`python tools/evaluate.py --out docs/report.json` and update the text of the docs when the numbers change.
`docs/evaluation.md` is written from `report.json` by `python tools/make_evaluation_doc.py`.
