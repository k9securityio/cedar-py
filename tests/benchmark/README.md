# cedarpy benchmark suite

`pytest-benchmark` suite for cedarpy. Three workflows live here:

1. **Ad-hoc benchmarks** — `make benchmark` / `make benchmark-save` for single-run exploration. See `Makefile`.
2. **Regression gate** — `make benchmark-compare` runs N=5 release-mode benchmarks at HEAD and gates on median Δ vs `results/baseline.json` (see "The regression gate" below).
3. **Historical record** — multi-run release-mode capture across a list of historical commits, aggregated into a committed perf history (most of this README).

## Files

- `test_benchmark_authorize.py` — the benchmarks themselves.
- `run_current.sh` — runs N=5 release-mode benchmarks at HEAD; writes ephemeral per-run JSONs into `results/current/` (gitignored).
- `capture_history.sh` — captures release-mode runs at each historical commit; writes native pytest-benchmark JSONs.
- `aggregate.py` — three modes:
  - default (`--phase ab`): reads native JSONs, writes per-commit summary JSONs and `HISTORY.md`.
  - `--build-baseline-from <state>`: synthesizes a median-of-N baseline JSON from a committed historical state.
  - `--compare-current [DIR]`: compares per-benchmark median across N current runs against `baseline.json` and exits non-zero on regression.
- `results/Darwin-CPython-3.11-64bit/` — native pytest-benchmark JSONs (one per pytest invocation, autoincremented).
- `results/current/` — ephemeral per-run JSONs from `run_current.sh` (gitignored, wiped each invocation).
- `results/history/<state>.json` — per-commit summary (median/max/min/stdev across N runs per benchmark).
- `results/HISTORY.md` — rendered table view of `results/history/*.json`, one section per benchmark.
- `results/baseline.json` — symlink to the active baseline (typically `baseline-v4_8_0-median.json`); used by `make benchmark-compare`.

## The regression gate

```sh
make benchmark-compare
```

Runs `bash run_current.sh` (one release-mode rebuild + N pytest invocations writing to `results/current/run<N>.json`), then `python tests/benchmark/aggregate.py --compare-current` (loads the N runs, computes per-benchmark median μs, compares against `baseline.json`'s `stats.median` per benchmark, and gates on **median Δ > 5%**). A summary table prints on both pass and fail, so drift is visible even when the gate passes.

- **N defaults to 5.** Override per-invocation: `BENCHMARK_RUNS=2 make benchmark-compare` (fast smoke test) or `BENCHMARK_RUNS=10 make benchmark-compare` (tighter median).
- **The gate is median-only.** The previous `mean:15%` threshold was dropped as noisy by design — a single tail outlier could trip a passing run. The N=5 median is the stable signal.
- **Faster-than-baseline never fails.** Only positive Δ exceeding the threshold is a regression.
- The runner does NOT require a clean working tree; the gate runs on whatever HEAD has. Build mode is always release (`maturin develop --release`).

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

- N runs per state: defaults to 5; override with `BENCHMARK_RUNS=N make benchmark-history`. We tested N=7 in a backfill experiment: medians shifted by <1.3 percentage points (already converged at N=5) and max actually became *noisier* (more samples → more chances of capturing rare tail outliers, which then dominate the max statistic). N=5 is the right default for the median signal we gate on; a useful tail estimate (e.g., p90) would need N≥20–30 plus a percentile-aware aggregator — out of scope for the historical record.
- Build mode is **release** (`maturin develop --release`). The committed historical record exists explicitly to be release-mode, since debug-mode variance is too high for cross-commit comparison (#69 motivation).
