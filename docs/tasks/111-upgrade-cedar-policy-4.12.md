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

1. **PR #106 disposition.** This branch is based on the PR #106 head. Merge
   #106 first and rebase this branch on `main`, or fold everything into one PR
   that supersedes #106 (preserving @h0rv's commit)? Tilt: merge #106 on its
   own once the 4.12-corpus integration run passes, keeping the contributor's
   attribution clean, then land the rest from this branch.
2. **Benchmark baseline.** `CLAUDE.md` says not to refresh the baseline for
   routine dep updates, only for performance-relevant code changes. An engine
   major-bump arguably is performance-relevant. If the 4.12 medians pass the
   gate, keep the 4.8.2 baseline as-is, or refresh it so future comparisons
   measure against the shipped engine? Tilt: refresh at release time and note
   it in the release PR.
3. **Submodule branch vs tag.** `.gitmodules` tracks `branch = release/4.8.x`.
   Move the branch reference to `release/4.12.x`, pinning the submodule at the
   `v4.12.0` tag commit as we pinned `v4.8.0` before?

## Detailed implementation steps

TODO: Make a detailed list of implementation steps to complete this task and
replace this todo with those steps.
