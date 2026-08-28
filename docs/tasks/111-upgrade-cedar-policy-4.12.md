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

Decision: TBD

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

Decision: TBD

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

Decision: TBD

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

Decision: TBD

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

Decision: TBD

## Detailed implementation steps

TODO: Make a detailed list of implementation steps to complete this task and
replace this todo with those steps.
