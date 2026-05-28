# CLAUDE.md

Project-specific guidance for Claude Code sessions working in `cedar-py`.

## What this project is

`cedarpy` is a Python package that wraps the Rust [cedar-policy](https://github.com/cedar-policy/cedar) engine via [PyO3](https://pyo3.rs/) + [maturin](https://www.maturin.rs/). The canonical version lives in `Cargo.toml`; `pyproject.toml` uses `dynamic = ["version"]` and maturin reads from `Cargo.toml` at build time.

## Local dev workflow

- **Virtualenv:** `venv-dev/` is the active dev venv (not `venv/`). `source venv-dev/bin/activate` before running `pytest`, `pip-compile`, `maturin develop`, etc.
- **Rebuild native extension after Rust changes:** `maturin develop --release`
- **Unit tests:** `pytest` (discovers `tests/unit/`)
- **Integration tests:** `make integration-tests` — pulls the `third_party/cedar-integration-tests` git submodule
- **Benchmarks:**
  - `make benchmark-compare` runs N=5 release-mode benchmarks at HEAD and gates on **median Δ** vs `tests/benchmark/results/baseline.json` (per-benchmark `stats.median`). Override the run count with `BENCHMARK_RUNS=N`. The previous `mean:15%` threshold was dropped — median-only gating per #69 goal 3. Per-run JSONs land in `tests/benchmark/results/current/` (gitignored, wiped each invocation). Do NOT refresh the baseline for routine dep updates — only for performance-relevant code changes.
  - `make benchmark-history` for release-mode multi-run capture across the historical commits listed in `tests/benchmark/capture_history.sh`. Outputs land in `tests/benchmark/results/history/<state>.json` (per-commit summary stats) and `tests/benchmark/results/HISTORY.md` (rendered cross-state table). The script does a `git checkout` per state and restores the starting branch on exit.
  - See `tests/benchmark/README.md` for the workflow, default run count (N=5) and why we landed there, the `STATES` format (`<save_prefix>:<git_ref>:<description>`, all required), and the `states-manifest.json` plumbing between the runner and aggregator.

## Dependency management

### Python

- `make fresh-requirements` regenerates `requirements*.txt` via `pip-compile`, but **without** `--upgrade`. pip-compile is sticky: it reuses the versions already in the lockfile wherever constraints still permit. To actually move a version, pass `--upgrade-package <name>` or `--upgrade`.
- Runtime `requirements.txt` is empty — cedarpy has no runtime Python deps. Only `requirements.dev.txt` matters.

### Rust

- Cedar's transitive deps often surface in Dependabot alerts (`time`, `keccak`, etc). Resolve with `cargo update -p <crate>`; no manifest change required.
- `Cargo.toml` has no active version overrides. The previously-pinned `rustix` workaround (for a 2024 CVE) was removed and `rustix` is now fully transitive.
- **Pinning a specific transitive version:** prefer `cargo update --precise <ver> -p <crate>` over a `=X.Y.Z` manifest pin. Belt-and-suspenders (caret in `Cargo.toml` + precise in `Cargo.lock`) keeps the lock authoritative without freezing the manifest.
- **Outside-contributor PRs and `Cargo.lock`:** be deliberate about transitive churn. If a contributor's PR adds/removes many lockfile entries beyond what the change requires, restore `Cargo.lock` from `main` (`git checkout main -- Cargo.lock`) and re-apply only the intended pins on top. We've done this once (PR #82) — small lockfile diffs are easier to audit and review.

### Dependabot policy (`.github/dependabot.yml`)

- **Version-update PRs are disabled** (`open-pull-requests-limit: 0` per ecosystem). Dependabot only opens PRs for security advisories.
- **Cooldown** (7 days minor/patch, 14 days major) is retained in the config so it's in force if version updates are ever re-enabled.
- Security updates are managed separately in repo Settings → Code security, and are unaffected by this config.

## Release process

Documented in `docs/release-process.md`. Highlights:

- Tag-driven: pushing a `v*` tag to `main` triggers the `release` job in `.github/workflows/CI.yml`.
- **Publishing uses PyPI Trusted Publishing (OIDC)** — there is no `PYPI_API_TOKEN` secret and one must not be re-introduced. The `pypi-release` GitHub environment gates deployment with a manual reviewer approval and restricts to tags matching `v*`.
- Version bump touches three files: `Cargo.toml` (line 5), `Cargo.lock` (auto on `cargo build`), and the cedarpy-release cell in the README compatibility table.
- `maturin upload --skip-existing` makes the release job idempotent; re-running against an already-published version is safe.

## Conventions

- **Branch naming:** conventional-commits style (`feat/`, `fix/`, `chore/`, `docs/`, `release/<version>`). **Do not** prefix branches with internal Jira keys (e.g. `CLOUD-####`) — this is an open-source repo.
- **Commit messages and PR descriptions:** same rule — keep internal Jira keys out. Internal tracking is one-way (the Jira issue links out to GitHub PRs, not the other way).
- **Cedar engine ↔ cedarpy mapping:** README has a table. Update the cedarpy column on every release.

## Cedar API gotchas

- **Annotations are inert in Cedar evaluation.** Per the [Cedar docs](https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-annotations), "an annotation has no impact on policy evaluation" and "`@id` is not special in the Cedar language." The Cedar CLI applies `@id` as a labeling convention by renaming `PolicyId`s at load time; the `cedar-policy` Rust library does not. cedar-py is a library, not a CLI consumer — to surface `@id` in `diagnostics.reasons` or `ValidationError.policy_id`, post-process at response-serialization time. Do **not** rebuild the `PolicySet` to apply `@id` (that's `O(|PolicySet|)` cost per call for a labeling concern; see #66/#68/#74 history).
- **Resolving `@id` cheaply.** `PolicySet::annotation(pid, "id")` parses `"id"` as a Cedar `Id` on every lookup — surprisingly expensive on batch workloads. Prefer `policy_set.policy(pid).and_then(|p| p.annotations().find(|(k, _)| *k == "id"))` which uses raw `&str` keys (see `resolve_display_id` in `src/lib.rs`).
- **Partial eval skips schema context type-checking when `action` is unknown.** Cedar's `Context::from_json_str` takes an optional `(schema, action)` tuple to type-check the context against the action-specific shape. With `is_authorized_partial`, if `action` is unknown there's no action UID to look up, so schema-based context validation is silently skipped (correct partial-eval semantics — the action-specific shape is by definition unknown until action is bound). Callers must re-run `is_authorized` once unknowns are bound to get full schema validation. The `is_authorized_partial` docstring and PR #82 CHANGELOG entry both warn about this; do not "fix" by refusing to evaluate when schema is set + action is missing (that defeats the use case).
- **Partial eval requires the `partial-eval` Cargo feature.** `cedar-policy = { version = "4.8.2", features = ["partial-eval"] }` in `Cargo.toml`. The feature is non-default upstream and gates `is_authorized_partial`, `PartialResponse`, `definitely_satisfied()/errored()`, `may_be_determining()/must_be_determining()`, `nontrivial_residuals()`, `unknown_entities()`, and `concretize()`.

## Follow-on work to be aware of

- **GitHub Actions consolidation (GH issue #62):** 6 actions in `CI.yml` are on outdated major versions (e.g. `actions/upload-artifact@v4` when v7 is current). Planned approach: one consolidated PR pinning all actions to commit SHAs with tag comments. Defer until there's time to review the cross-major changelogs, and do not bundle with a release.
- **Benchmark process improvements (GH issue #69):** Goals 2 and 3 have landed (PR #71 for the historical record + tooling; PR #84 for the median-of-N gate in `make benchmark-compare`). **Goal 1 remains open** — switching `make benchmark` / `benchmark-save` to release mode (currently debug). `benchmark-compare` is already release-mode as of PR #84.
  - **Empirical finding from PR #71's data:** medians are robust at N=5 (N=7 backfill shifted Δ by <1.3 pp on every benchmark we checked); max grows monotonically with N as more samples capture rare tail outliers and shouldn't be used for cross-state gating. The Δ max column in `HISTORY.md` is informational only.
- **`windows-sys 0.48` transitive cleanup (GH issue #85):** `Cargo.lock` carries 9 stale `windows-sys 0.48` / `windows-targets 0.48` / `windows_*_gnu/msvc/gnullvm 0.48.5` entries pulled in via `walkdir → winapi-util → windows-sys 0.48`, which reach the tree through `lalrpop` as a build-dependency of `cedar-policy-core`. Build-dep only, Windows-only, never flows into the wheel. Not urgent; clean up when convenient.
