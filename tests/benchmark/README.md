# cedarpy benchmark suite

`pytest-benchmark` suite for cedarpy. Two distinct workflows live here:

1. **Single-run benchmarks** — the `make benchmark*` targets (run / save / compare-against-baseline). See `Makefile`.
2. **Historical record** — multi-run release-mode capture across a list of historical commits, aggregated into a committed perf history (this README is mostly about this).

## Files

- `test_benchmark_authorize.py` — the benchmarks themselves.
- `capture_history.sh` — captures release-mode runs at each historical commit; writes native pytest-benchmark JSONs.
- `aggregate.py` — reads native JSONs, writes per-commit summary JSONs and `HISTORY.md`.
- `results/Darwin-CPython-3.11-64bit/` — native pytest-benchmark JSONs (one per pytest invocation, autoincremented).
- `results/history/<state>.json` — per-commit summary (median/max/min/stdev across N runs per benchmark).
- `results/HISTORY.md` — rendered table view of `results/history/*.json`, one section per benchmark.
- `results/baseline.json` — used by `make benchmark-compare` (single-run comparison gate).

## Capturing the historical record

Prereqs (per project `CLAUDE.md`):
- `venv-dev/` exists. Run `make venv-dev` if not.
- Working tree is clean.

```sh
make benchmark-history
```

This runs `capture_history.sh` (default ~30–40 min — scales as `states × runs × (build + run time)`), then `aggregate.py` (both phases). Outputs land in `results/history/` and `results/HISTORY.md`.

The script switches branches via `git checkout` for each state and restores the starting branch on exit (success or failure).

### Adding a new historical state

1. Edit the `STATES` array in `capture_history.sh`. Format: `"<save_prefix>:<git-ref>"`. Use sanitized tag names (`v4_8_2`) for tagged releases or `<descriptor>_<short-sha>` (e.g., `pr72_abc1234`) for untagged commits.
2. Re-run `make benchmark-history`. The aggregator discovers states from filenames and adds the new row.
3. Commit the new files under `results/Darwin-CPython-3.11-64bit/`, `results/history/`, and the regenerated `results/HISTORY.md`.

### Re-rendering the markdown only

```sh
python tests/benchmark/aggregate.py --phase b
```

Useful after manual edits to per-commit JSONs (e.g., correcting a label).

## Run-count and modes

- N runs per state: defaults to 5; override with `BENCHMARK_RUNS=N make benchmark-history`.
- Build mode is **release** (`maturin develop --release`). The committed historical record exists explicitly to be release-mode, since debug-mode variance is too high for cross-commit comparison (#69 motivation).
