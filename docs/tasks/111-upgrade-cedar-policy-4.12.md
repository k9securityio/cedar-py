# Task 111 - Upgrade cedar-policy engine to 4.12.0

GitHub issue: https://github.com/k9securityio/cedar-py/issues/111

## Objective

Complete the upgrade of the embedded Cedar engine from 4.8.2 to
[cedar-policy 4.12.0](https://github.com/cedar-policy/cedar/releases/tag/v4.12.0)
and release it as **cedarpy v4.12.0** (cedarpy's major.minor tracks the engine's).

PR #106 (@h0rv) supplies the `Cargo.lock` bump and is the base of this branch.
The review phase is already complete (see #111): no breaking changes reach
cedarpy (all confined to experimental features we don't enable — we enable only
`partial-eval`), lockfile churn is verified and `cargo audit` reports no new
advisories, and unit tests pass against the 4.12 engine. This task covers the
remaining verification and release-preparation work.

## High-level implementation steps

1. **Benchmark** — run `make benchmark-compare` on a quiet machine (median-Δ
   gate vs `tests/benchmark/results/baseline.json`). An engine bump is exactly
   the change the gate exists for; read any failure diagnostically per the
   load-sensitivity guidance in `CLAUDE.md`.
2. **Integration corpus refresh** — bump the `third_party/cedar-integration-tests`
   submodule from `release/4.8.x` to `release/4.12.x` (tag `v4.12.0` exists
   upstream) and re-run `make integration-tests` plus the corpus suite; the
   contributor's passing runs used the 4.8 corpus.
3. **Manifest floor** — bump the `cedar-policy*` requirements in `Cargo.toml`
   from `4.8.2` to `4.12.0` so builds cannot resolve an older engine than what
   we tested.
4. **Docs** — update the two `4.8.2` references in `CLAUDE.md` (partial-eval
   feature line; the `Schema::clone()` gotcha — re-verify its `api.rs:1851`
   line reference against 4.12.0 source), and add a `CHANGELOG.md` entry under
   `[Unreleased]` crediting @h0rv (#106).
5. **Release prep** — per `docs/release-process.md`: bump the cedarpy version
   in `Cargo.toml` (line 5) to 4.12.0, let `Cargo.lock` refresh on build, and
   update the README compatibility table row (cedar v4.12.0 / cedarpy v4.12.0 /
   main).

## Questions

### Q1. How should PR #106 land relative to this branch?

Context: This branch (`gh-111-upgrade-cedar-policy-4.12`) is based on the PR
#106 head, which contains only the `Cargo.lock` bump by @h0rv.

Question: Should PR #106 merge on its own first (then rebase this branch on
`main`), or should this branch's PR supersede #106, carrying the contributor's
commit?

Options:
  1. Merge #106 as-is once the 4.12-corpus integration run passes, then rebase
     this branch on `main` and land the remaining work in a follow-up PR.
  2. Close #106 and land everything from this branch in one PR, preserving
     @h0rv's commit for attribution.

Recommendation: Option 1 — keeps the contributor's attribution clean on their
own merged PR and keeps each PR small and auditable, matching the repo's
preference for minimal lockfile diffs.

Decision: Retarget PR #106 to merge into `gh-111-upgrade-cedar-policy-4.12`
so all 4.12-support changes and testing land together in a single PR to
`main`. A number of changes are expected to support cedar-policy 4.12 and
they should be reviewed together. @h0rv's commit arrives via the #106 merge,
preserving attribution.

### Q2. Should the benchmark baseline be refreshed after the 4.12 gate passes?

Context: `CLAUDE.md` says not to refresh `tests/benchmark/results/baseline.json`
for routine dep updates — only for performance-relevant code changes. An engine
minor-version jump spanning four releases (with an upstream validator-memory
improvement in 4.12.0) is arguably performance-relevant.

Question: If `make benchmark-compare` passes against the 4.8.2 baseline, should
the baseline be refreshed to 4.12.0 medians so future comparisons measure
against the shipped engine?

Options:
  1. Refresh the baseline at release time (quiet-machine N=5 capture) and note
     it in the release PR.
  2. Keep the 4.8.2 baseline until the next performance-relevant cedarpy code
     change.

Recommendation: Option 1 — the engine is the dominant term in every benchmark,
so drift vs a 4.8.2 baseline would accumulate into exactly the kind of ambient
+2–4% noise `CLAUDE.md` warns about.

Decision: Recommendation accepted, Option 1.

### Q3. How should the cedar-integration-tests submodule be re-pinned?

Context: `.gitmodules` tracks `branch = release/4.8.x` and the submodule is
pinned at the `v4.8.0` tag commit. Upstream has `release/4.12.x`, whose head is
currently identical to tag `v4.12.0`.

Question: Update the `.gitmodules` branch to `release/4.12.x` and pin the
submodule at the `v4.12.0` tag commit, mirroring the current arrangement?

Options:
  1. `branch = release/4.12.x` in `.gitmodules`, submodule pinned at `v4.12.0`.
  2. Pin the tag commit only, leaving the branch reference unchanged.

Recommendation: Option 1 — same shape as today, and the branch reference
documents which corpus line the pin came from.

Decision: Recommendation accepted, Option 1.

### Q4. Should the stale `third_party/cedar` submodule be bumped too?

Context: `third_party/cedar` is pinned at a pre-v3.0.0-era commit. It is used
by `tests/unit/test_validate.py` (loads `cedar-policy-cli/sample-data/`) and as
the local source tree for `api.rs` line references in docs (e.g. the
`Schema::clone()` gotcha in `CLAUDE.md` cites `api.rs:1851`).

Question: Bump `third_party/cedar` to the `v4.12.0` tag as part of this task,
or leave it for separate housekeeping?

Options:
  1. Bump to `v4.12.0` in this task; re-verify the `test_validate.py` parity
     tests against the newer sample-data and refresh doc line references.
  2. Leave it out of scope; the task only needs the corpus submodule moved.

Recommendation: Option 1 — the docs step already requires re-verifying
`api.rs` references against 4.12.0 source, which is easiest with the submodule
at the matching tag; sample-data churn risk is covered by the existing parity
tests.

Decision: Recommendation accepted, Option 1.

### Q5. Should new 4.12-corpus test suites be wired into the integration tests?

Context: `tests/integration/test_cedar_integration_tests.py` hard-codes each
suite (`example_use_cases` 1a…5b, `ip`, `multi`, …) via
`@parameterized.expand`, so bumping the submodule will not automatically pick
up suites added between the 4.8 and 4.12 corpora. The corpus tarball tests, by
contrast, enumerate automatically.

Question: After the submodule bump, should the 4.12 corpus's `tests/` tree be
audited for new kinds/suites and any additions wired in, or is re-running the
existing suite list sufficient for this task?

Options:
  1. Audit and wire in any new suites as part of this task.
  2. Re-run the existing list only; file a follow-up issue if the audit shows
     new suites.

Recommendation: Option 1 if the diff is small (likely — suite additions
upstream are infrequent); fall back to Option 2 if a new suite needs
non-trivial harness work.

Decision: Recommendation accepted, Option 1.

## Detailed implementation steps

File:line references are against `main` at the base of branch
`gh-111-upgrade-cedar-policy-4.12`.

### Phase A — Land the engine bump on the task branch

1. ✅ Merge PR #106 into this branch with a **merge commit** (`gh pr merge 106
   --merge`), not a squash — a squash would rewrite @h0rv's commit SHA. The PR
   base is already retargeted to this branch. Then `git pull` locally.
   (Merged as `78beae58`; local doc commits rebased on top for linear history.)
2. ✅ Rebuild the native extension: `maturin develop --release`.
3. ✅ **Verify:** `pytest tests/unit` — 218 passed, 2 subtests passed.

### Phase B — Submodule bumps and integration verification

1. ✅ Bump `third_party/cedar-integration-tests`: set `branch = release/4.12.x`
   in `.gitmodules` (line 7), check out tag `v4.12.0` (commit `6b4c3dcb…`) in
   the submodule, and stage both. (Q3: Option 1.)
2. ✅ Bump `third_party/cedar` from its pre-v3.0.0 pin to tag `v4.12.0` and stage
   the pin. (Q4: Option 1.)
3. ✅ Re-run `pytest tests/unit` — sample-data files were renamed upstream
   (`policies_N[_bad].txt` → `.cedar`, `schema.json` → `schema.cedarschema.json`);
   updated the references in `tests/unit/test_validate.py`. 218 passed —
   file contents unchanged semantically, no expectation changes needed.
4. ✅ Audit the corpus diff for new suites (Q5: Option 1): v4.8.0 → v4.12.0
   adds exactly two suites, `example_use_cases/2a_json_policy` (JSON policy
   format) and `example_use_cases/2a_json_schema` (JSON schema format). Wired
   both in; the loader now converts `policyFormat: "json"` suites via
   `cedarpy.policies_from_json_str`. `4c` is still absent from the 4.12
   corpus, so it stays disabled.
5. ✅ **Verify:** integration tests 78 passed (74 + 4 from the new suites);
   corpus tests 60,800 passed against the 4.12 corpus (was 59,696 on 4.8).

### Phase C — Manifest floor and docs

1. ✅ `Cargo.toml:17-19`: bump `cedar-policy` (keeping
   `features = ["partial-eval"]`), `cedar-policy-cli`, and
   `cedar-policy-formatter` from `4.8.2` to `4.12.0`. `cargo build` confirmed
   `Cargo.lock` unchanged.
2. ✅ `CLAUDE.md`: updated the two `4.8.2` references. Verified in v4.12.0
   source that `Schema` still directly wraps `ValidatorSchema` (not
   Arc-wrapped); line reference refreshed to `api.rs:1908`.
3. ✅ `CHANGELOG.md` under `[Unreleased]`: engine bump 4.8.2 → 4.12.0 (Cedar
   language 4.4 → 4.5), no cedarpy API changes, crediting @h0rv (#106).
4. ✅ **Verify:** grep clean except the README compatibility row, which
   correctly describes the released cedarpy 4.8.7 and changes at release time
   (Phase E). Full `pytest`: 218 passed.
5. ✅ (Post-plan addition.) Removed the never-used `cedar-policy-cli`
   dependency — declared since the initial scaffold, zero references in
   `src/lib.rs`. Pure lockfile shrink: 34 transitive crates dropped (clap,
   miette support stack, rustix, …), 0 added. Also removes the `=X.Y.Z`
   exact-pin coupling the cli crate imposed on `cedar-policy` resolution.
   Verified: unit 218 / integration 78 / corpus 60,800 all pass.

### Phase D — Benchmark on a quiet machine

1. ✅ Run `make benchmark-compare` (N=5, release mode) against the existing
   4.8.2 baseline. Initial run FAILED uniformly (+3.2%…+8.9%, all 26
   benchmarks). Diagnosed with an A/B control: an identical N=5 capture at
   the pre-#106 (4.8.2) state on the same machine ALSO failed (+0.6%…+7.7%),
   proving most of the shift was ambient drift vs the January-era baseline,
   not an engine regression. Root cause of the residual positive bias: a
   latent comparator bug — `_load_current_runs` loaded per-run `stats.mean`
   but the baseline stores `stats.median`; mean > median for right-skewed
   timings, so every Δ was biased positive by a few points. Fixed the gate to
   compare medians to medians (with `tests/unit/test_benchmark_compare.py`
   fixtures updated). Median-to-median, 4.12 vs the old baseline is
   **mean +2.9%, max +4.1% (`test_entities_as_json_string`) — every
   benchmark under the 5% threshold**: no regression.
2. ✅ Refreshed the baseline (Q2: Option 1): captured N=5 4.12 runs as
   `results/Darwin-CPython-3.11-64bit/0038–0042_gh111_d76174b-run*.json`, built
   `baseline-gh111_d76174b-median.json` via `aggregate.py --build-baseline-from gh111_d76174b`, and repointed the `baseline.json` symlink (the intended refresh
   mechanism) from `baseline-v4_8_0-median.json` to it.
3. ✅ **Verify:** `benchmark-compare` PASSES against the refreshed baseline;
   full unit suite 218 passed.

### Phase E — PR to main, then release cedarpy v4.12.0

0. ✅ Pre-flight: local `main` held an unpushed docs commit (`3b796e05`,
   provenance-verification correction + release-branch retention policy,
   2026-07-10). Resolved: the maintainer intended it for the retention
   branch — it is now published as the tip of `release/4.8.x` (created from
   local `main`, pushed 2026-08-28). Note `origin/main` still lacks it, so
   the release-process doc corrections are not on `main`; cherry-pick or
   push if wanted there.
1. Push this branch and open the PR to `main`: summary of engine changes
   (4.9–4.12 changelog review), dependency/audit verification, test results
   (unit / integration / corpus at the 4.12 corpus), and benchmark outcome.
   Note for the reviewer that release-job actions are PR-skipped and first
   exercised on the real release.
2. **Verify:** CI green across all platforms (cold Rust compiles; macOS
   x86_64 is the ~15 min long pole). Merge the PR (merge commit, repo
   convention).
3. Decide/create the 4.8-line retention branch: before `main` moves on, push
   a `release/4.8.x` branch at the v4.8.7 release commit and update its README
   compatibility-table row to point at it (pattern: the v4.7.2/v4.1.0 rows).
4. Release per `docs/release-process.md`: `release/4.12.0` branch off updated
   `main`; bump `Cargo.toml` version (line 5) to `4.12.0`; `cargo build` to
   refresh `Cargo.lock`; README compatibility row (cedar v4.12.0 / cedarpy
   v4.12.0 / main); promote CHANGELOG `[Unreleased]` → `[4.12.0] - <date>`
   with fresh empty `[Unreleased]` and footer links. PR, CI green, merge —
   leave the `release/4.12.0` branch in place (retention policy).
5. Tag `v4.12.0` on updated `main`, push the tag, approve the `pypi-release`
   deployment.
6. **Verify:** all wheels + sdist on PyPI at 4.12.0; SLSA provenance via
   `gh attestation verify` against a downloaded distribution (attestations
   live on GitHub, not PyPI — one combined v4 attestation covers the set);
   publish the GitHub Release with the CHANGELOG section as notes.
