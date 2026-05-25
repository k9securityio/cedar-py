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

File:line references are against `main` at the tip of branch `feat/issue-69-median-of-n-gate`.

### Preflight

1. **Confirm the current gate passes on `main`.** From a clean `venv-dev`, run `make benchmark-compare` on `main` (single-pytest-run vs `baseline.json`). Expectation per the #74/Path B resolution: passes. Record the per-benchmark median Δ output; it's the reference for sanity-checking the new N=5 gate's output in step 13.

2. **Delete the stale autosave files.** `git rm` (or plain `rm` — they're untracked per `git status`) the five `tests/benchmark/results/Darwin-CPython-3.11-64bit/0033_…0037_v4_8_2-run*.json` files. They're leftovers from a manual N=5 attempt and are not part of the committed historical record (which uses the `v4_8_2:v4.8.2:v4.8.2` state in `capture_history.sh` and its own captured runs).

### Runner — `tests/benchmark/run_current.sh` (new)

3. **Add a HEAD-only N-run runner.** New file `tests/benchmark/run_current.sh`. Modeled on the inner loop of `capture_history.sh:87–108` but without the `git checkout` dance, the states-manifest plumbing, or the `restore_branch` trap. Responsibilities:
   - Verify `venv-dev/` exists; `source venv-dev/bin/activate`.
   - **Do not** require a clean working tree (the historical-record runner does; the gate runs on whatever HEAD has).
   - Read `RUNS="${BENCHMARK_RUNS:-5}"`.
   - Compute an ephemeral output dir under the project: `OUT_DIR="$REPO_ROOT/tests/benchmark/results/current"`. Wipe it at the start of each invocation (`rm -rf "$OUT_DIR" && mkdir -p "$OUT_DIR"`) so re-runs don't accidentally aggregate across stale files.
   - `maturin develop --release` once (release-mode is the contract — `benchmark-compare` is release-mode-only after PR #72).
   - Loop `n in 1..RUNS`, invoking `pytest tests/benchmark --benchmark-only --benchmark-json="$OUT_DIR/run$n.json" -q`. Use `--benchmark-json` (single explicit path) rather than `--benchmark-save` + `--benchmark-storage` so the runner owns the filenames directly and doesn't write into `Darwin-CPython-3.11-64bit/` (which is the historical record's home).
   - On any pytest non-zero exit, exit non-zero immediately (set `-e` is enough).
   - Print one tail-3 summary per run, matching `capture_history.sh`'s ergonomics.
   - `chmod +x`.

4. **Gitignore the ephemeral output dir.** Append `tests/benchmark/results/current/` to `.gitignore` (alongside the existing `tests/benchmark/results/out` entry on line 80). This keeps `git status` clean after `make benchmark-compare`.

### Comparator — extend `tests/benchmark/aggregate.py`

5. **Add a `--compare-current <dir>` mode.** New CLI flag on `aggregate.py:408–414`, mutually exclusive with `--phase` and `--build-baseline-from`. Argument is the runner's output dir (defaulting to `tests/benchmark/results/current/`). Calls a new `compare_current_to_baseline(current_dir, baseline_path, threshold_pct)` function and exits with that function's return code.

6. **Implement `compare_current_to_baseline`.** New top-level function in `aggregate.py`. Steps:
   - Load every `run*.json` under `current_dir`. If fewer than 1 file is present, exit non-zero with a clear error pointing the user at `run_current.sh`. (No lower bound > 1 — let the user run with `BENCHMARK_RUNS=1` if they want a fast-feedback debug loop; the gate just becomes single-run-vs-median in that case.)
   - Build `current_means_us: dict[name -> list[float]]` by reading `b["stats"]["mean"]` per benchmark across runs (same convention as `per_benchmark_stats` at `aggregate.py:166–188` — convert to μs by `* 1_000_000`).
   - Compute `current_median_us = statistics.median(means_us)` per benchmark.
   - Load `tests/benchmark/results/baseline.json` and extract `baseline_median_us = b["stats"]["median"] * 1_000_000` per benchmark. Use the `"median"` stats field (the synthesized baseline's per-stats-field median across the v4.8.0 historical runs — see `build_baseline_from_state` at `aggregate.py:339–405`). Fall back gracefully (warn + skip) if a benchmark in `current_dir` isn't in the baseline or vice versa.
   - Per benchmark, compute `delta_pct = (current_median_us - baseline_median_us) / baseline_median_us * 100`.
   - Apply the threshold: **fail any benchmark where `delta_pct > THRESHOLD_PCT`** (default 5.0, matching the existing `--benchmark-compare-fail=median:5%`). Faster-than-baseline (negative Δ) never fails. Allow override via `--threshold-pct` CLI arg, but don't expose it through the Makefile in this PR (out of scope per #69's "regression-check threshold tuning is out of scope").
   - Print a concise summary table to stdout in **all** cases (pass and fail):
     ```
     Benchmark                                          Baseline (μs)   Median (μs)   Δ median   Status
     test_complex_policy                                273.3           272.4         -0.3%      PASS
     test_medium_policy                                 ...
     ```
     One row per benchmark, sorted alphabetically. Use `fmt_us` / `fmt_pct` helpers (`aggregate.py:244–255`) for consistency with `HISTORY.md` formatting. Mark failing rows with `FAIL` so the maintainer can scan output quickly.
   - Print a footer line indicating N (the run count) and the threshold used.
   - Return non-zero if any benchmark FAIL'd; zero otherwise.

7. **No `mean` threshold evaluation.** Per the resolved question, the comparator gates only on **median Δ**. Don't compute or print a `mean Δ` column — the goal is to remove the noisy mean check entirely, not preserve it as visual noise.

8. **Don't fork — extend.** Per the resolved question, all new logic lives in `aggregate.py`. The existing functions (`per_benchmark_stats`, `build_baseline_from_state`, `phase_a`, `phase_b`) stay untouched.

### Makefile — `make benchmark-compare`

9. **Rewire the target.** Replace `Makefile:68–84`. New shape:
   ```make
   .PHONY: benchmark-compare
   benchmark-compare:
   	@echo Running benchmarks and comparing N runs against baseline
   	@if [ ! -f $(BENCHMARK_RESULTS_DIR)/baseline.json ]; then \
   		echo "Error: $(BENCHMARK_RESULTS_DIR)/baseline.json not found. Sym-link it to a baseline-<state>-median.json first."; \
   		exit 1; \
   	fi
   	set -e ;\
   	bash tests/benchmark/run_current.sh ;\
   	python3 tests/benchmark/aggregate.py --compare-current $(BENCHMARK_RESULTS_DIR)/current
   ```
   - `BENCHMARK_RUNS=N make benchmark-compare` works transparently via the env-var passthrough in `run_current.sh`.
   - Drop the comment block at `Makefile:70–72` (stddev/max noise note) — irrelevant under the new gate.
   - Keep `maturin develop --release` inside `run_current.sh` so the build step stays adjacent to the runs (and is shared with any future `run_current.sh` invocations from outside `make`).

10. **`make benchmark` and `benchmark-save` are unchanged.** Those are exploration targets; they stay single-run.

### Docs

11. **Update `tests/benchmark/README.md`.** Two updates to the "Single-run benchmarks" framing:
    - Rename that workflow heading to acknowledge the gate is now multi-run (`benchmark-compare` is no longer single-run).
    - Add a short subsection describing the new gate: N=5 release-mode runs at HEAD, median-Δ vs `baseline.json`, threshold 5%, override via `BENCHMARK_RUNS=N`. Point to `run_current.sh` and the `--compare-current` flag for ad-hoc invocation.

12. **Update `CLAUDE.md`'s "Local dev workflow" benchmarks bullet.** Currently describes `make benchmark-compare` as a "single-run regression check." Reword to "N=5 release-mode runs at HEAD with median-Δ gating against `baseline.json`; override the run count via `BENCHMARK_RUNS=N`."

### Validation

13. **Smoke-test the new gate on `main`.** From a clean working tree at the tip of `feat/issue-69-median-of-n-gate`:
    - `BENCHMARK_RUNS=2 make benchmark-compare` first — confirms the wiring end-to-end in ~2 min before paying the full N=5 cost.
    - `make benchmark-compare` (default N=5). Expectation: PASS on all benchmarks, per the Path B (PR #75) restoration of v4.8.0 perf on the default code path. Compare per-benchmark median Δ against step 1's output as a sanity check — they should be within run-to-run noise.
    - If any benchmark FAILs, investigate before merging: either Path B's perf hasn't fully held since PR #75 (real signal, file a follow-up), or the threshold is too tight for this hardware (unlikely — the 5% median threshold is what the existing gate already used).

14. **Negative test the gate.** Manually plant a known-bad current run JSON in `tests/benchmark/results/current/` (e.g., by hand-editing one of the N=5 outputs to inflate `test_complex_policy`'s `stats.mean` by 20%) and re-run only the comparator (`python3 tests/benchmark/aggregate.py --compare-current tests/benchmark/results/current`). Confirm the gate exits non-zero and the row is marked FAIL. Discard the planted file.

15. **Unit-test the comparator.** Add `tests/unit/test_aggregate_compare.py` (or extend an existing aggregate test if one exists — there isn't one as of this branch). Cover:
    - Median Δ within threshold → returns 0, prints PASS.
    - Median Δ above threshold → returns non-zero, prints FAIL for the offending benchmark.
    - Faster-than-baseline (negative Δ) → never FAILs, prints negative Δ.
    - Benchmark present in current but absent in baseline → warn + skip, don't crash.
    - N=1 input → still produces a comparison (median of one sample = that sample).
    Use small fabricated `run*.json` and `baseline.json` fixtures rather than real benchmark output.

### Close-out

16. **CHANGELOG.** Add an entry under `[Unreleased]` describing the gate change: "`make benchmark-compare` now runs N=5 release-mode benchmarks at HEAD and gates on median Δ vs `baseline.json` (was: single pytest-benchmark run with `--benchmark-compare-fail=median:5%,mean:15%`). The `mean` threshold has been dropped; only median Δ is gated. Override the run count with `BENCHMARK_RUNS=N`."

17. **PR description.** Reference #69 and call out: (a) Goal 3 is now done, closing the issue when this PR merges; (b) the `mean` threshold drop, per #69's out-of-scope note; (c) the ephemeral results directory and the `.gitignore` addition; (d) the deleted stale autosave files. `Resolves #69`.

18. **After merge.** Confirm #69 auto-closes. Optional follow-up housekeeping (out of scope here, captured for the record): delete the closed `feat/issue-69-state-pr70` and `fix/optional-resolve-policy-ids` branches on origin, per the side note in `74-id-annotation-support.md`.
