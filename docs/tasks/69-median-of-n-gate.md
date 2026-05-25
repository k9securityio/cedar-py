# Task 69 - Benchmark process improvements: median-of-N gate for `make benchmark-compare`

GitHub issue: https://github.com/k9securityio/cedar-py/issues/69

## Objective

Implement **goal 3** of #69 — the only remaining goal. Goals 1 (release-mode `make benchmark*` targets) and 2 (release-mode median baseline) landed in PR #72; the historical-record bonus landed in PR #71 and was extended in PR #73.

Replace the current single-current-run-vs-baseline-median gate with an **N=5 release-mode multi-run gate** that compares the **median Δ across N current runs at HEAD** against `tests/benchmark/results/baseline.json`. This removes the false-regression risk from tail-variance on any single run — the same root cause that made the #68 bisect unreadable until we built the N=5 aggregation in the first place.

Reuse `tests/benchmark/aggregate.py`'s per-benchmark stats logic. The new pieces are a HEAD-only runner (no git-checkout dance like `capture_history.sh` does) and a comparator that computes median across N current runs and gates on median Δ.

## High-level implementation steps

1. Add a HEAD-only N-run runner under `tests/benchmark/` that does `maturin develop --release` once, then runs `pytest tests/benchmark` N times and writes per-run JSONs to a temp / results-scoped location.
2. Extend `tests/benchmark/aggregate.py` (or add a sibling comparator) to load the N current-run JSONs, compute per-benchmark median, and compare against `baseline.json`'s per-stats-field median. Exit non-zero if any benchmark's median Δ exceeds the threshold.
3. Rewire `make benchmark-compare` to invoke the runner + comparator instead of the current single-pytest-run `--benchmark-compare-fail` path.
4. Honor `BENCHMARK_RUNS=N` override (default N=5).
5. Print a concise summary table on both pass and fail (per-benchmark median Δ vs baseline), so a passing run still surfaces drift.
6. Update `tests/benchmark/README.md` to document the new flow, the default N, and the override.

## Questions

1. **Threshold.** Current gate uses `pytest-benchmark`'s `--benchmark-compare-fail=median:5%,mean:15%`. Goal 3 explicitly says "apply thresholds to the **median** of the N runs, not a single-run mean." Drop the `mean` threshold entirely (per #69's out-of-scope note that the mean check is noisy by design and "should probably be dropped once goal 3 lands")? Or keep `mean` as an informational column but only fail on `median`?

Decision: Drop the `mean` threshold evaluation.

2. **Where the per-run JSONs live.** Two options:
   - **Ephemeral**: write to a `tmp/` / `.benchmarks-current/` dir under `tests/benchmark/results/`, gitignored, cleaned up between runs. Keeps the committed results tree small.
   - **Persistent**: write to `tests/benchmark/results/Darwin-…/` like the existing pytest-benchmark autosave path, leaving them for post-hoc investigation. Matches what's already happening (the five `0033_…0037_v4_8_2-runN.json` files in `git status` look like leftovers from a manual N=5 run).

   Tilt: ephemeral, since `make benchmark-history` already owns the "captured for the record" use case. The pytest-benchmark autosaves are useful for ad-hoc work but shouldn't be the gate's storage.

Decision: Use the `ephemeral` approach. `make benchmark-history` will capture results "for the record".

3. **Run-count default.** #69 specifies N=5. The PR #71 N=7 backfill found medians shifted by <1.3 pp at N=7 vs N=5, so N=5 is the right default. Confirm `BENCHMARK_RUNS` env override is the right knob (vs. a Makefile variable or CLI flag on the runner).

Decision: use N=5 runs.

4. **Reuse vs. fork of `aggregate.py`.** `aggregate.py` currently consumes the `states-manifest.json` produced by `capture_history.sh` (multiple states × multiple runs per state). The HEAD-only gate is a degenerate case (one "state" = HEAD, N runs). Add a `--current-runs <glob>` mode to `aggregate.py` that skips the states-manifest plumbing, or fork a smaller `compare_current.py`? Tilt: extend `aggregate.py` so the stats logic stays in one place.

Decision: Extend `aggregate.py` so the stats logic stays in one place. 

5. **CI exposure.** PR #72's progress comment on #69 flagged that `make benchmark-compare` is expected to fail on `test_complex_policy` at the time it was written — but PR #75 (Path B for #74) has since landed, which should have restored v4.8.0 perf on the default path. Worth re-running `make benchmark-compare` at current `main` (pre-this-work) to confirm the gate currently passes, so any failures introduced by the new N=5 logic are clearly attributable. Also: is `make benchmark-compare` actually invoked from any GitHub Actions workflow today, or is it maintainer-local only? If it runs in CI, the N=5 cost (5× `pytest tests/benchmark` ≈ several minutes per CI run) needs sign-off.

v4.8.0 perf was restored on the default path (`main`).

GitHub Actions do _not_ run benchmarks because the execution environment is too noisy / inconsistent.

`make benchmark-compare` is only run by maintainers locally on their hardware prior to release. 

Decision: You do not need to execute any 'official' runs to update benchmark history. But we will run `make benchmark-compare` on `main` to confirm the gate works and is (still) passing.

6. **Stale autosave files.** The five `0033_…0037_v4_8_2-run*.json` files showing in `git status` look like artifacts from a prior manual N=5 attempt. Delete as part of this task, or leave for separate housekeeping?

Decision: Delete them.

## Detailed implementation steps

TODO: fill in after the questions above are resolved.
