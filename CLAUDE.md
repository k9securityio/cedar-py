# CLAUDE.md

Project-specific guidance for Claude Code sessions working in `cedar-py`.

## What this project is

`cedarpy` is a Python package that wraps the Rust [cedar-policy](https://github.com/cedar-policy/cedar) engine via [PyO3](https://pyo3.rs/) + [maturin](https://www.maturin.rs/). The canonical version lives in `Cargo.toml`; `pyproject.toml` uses `dynamic = ["version"]` and maturin reads from `Cargo.toml` at build time.

## Local dev workflow

- **Virtualenv:** `venv-dev/` is the active dev venv (not `venv/`). `source venv-dev/bin/activate` before running `pytest`, `pip-compile`, `maturin develop`, etc.
- **Rebuild native extension after Rust changes:** `maturin develop --release`
- **Unit tests:** `pytest` (discovers `tests/unit/`)
- **Integration tests:** `make integration-tests` — pulls the `third_party/cedar-integration-tests` git submodule
- **Benchmarks:** `make benchmark-compare`. Do NOT refresh `tests/benchmark/results/baseline.json` for routine dep updates — only when performance-relevant code changes.
  - **Build mode is debug.** `make benchmark-compare` runs `maturin develop` (debug). The committed `baseline.json` was also recorded in debug mode. Do NOT change one without the other — debug-mode runs are ~8× slower than release-mode runs, so a release-mode run trivially "passes" against the debug baseline. Tracked in #69.
  - **Single-run benchmarks are very noisy.** Run-to-run mean swings of 30–50 percentage points on tail outliers are normal — the same code can fail one run and pass the next. For any meaningful regression analysis, run N≥5 times and take **medians**, not single-run means. The `out/v4.8.2-bisect/` directory has a working aggregator (`aggregate.py`) and runner (`run.sh`) that demonstrate the pattern. #69 tracks productizing this.
  - The release process (`docs/release-process.md`) requires `make benchmark-compare` before opening a release PR. If a single run reports a regression, run it 4 more times and check the medians before declaring a real issue.

## Dependency management

### Python

- `make fresh-requirements` regenerates `requirements*.txt` via `pip-compile`, but **without** `--upgrade`. pip-compile is sticky: it reuses the versions already in the lockfile wherever constraints still permit. To actually move a version, pass `--upgrade-package <name>` or `--upgrade`.
- Runtime `requirements.txt` is empty — cedarpy has no runtime Python deps. Only `requirements.dev.txt` matters.

### Rust

- Cedar's transitive deps often surface in Dependabot alerts (`time`, `keccak`, etc). Resolve with `cargo update -p <crate>`; no manifest change required.
- `Cargo.toml` has no active version overrides. The previously-pinned `rustix` workaround (for a 2024 CVE) was removed and `rustix` is now fully transitive.

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
- **Editing contributor PRs as maintainer:** when "Allow edits from maintainers" is checked on a fork-based PR, push directly for trivial changes (typos, error-message wording, release-note tweaks), and use a review comment for substantive logic edits. Always leave a PR comment summarizing what you pushed and why — name the SHA so the contributor can locate the change without hunting.

## Cedar API gotchas worth knowing

- **`Policy::clone()` is not cheap.** `cedar_policy::ast::Policy` has an `Arc<Template>` internally, but the public `Policy` type also carries a separate `LosslessPolicy` representation that gets cloned alongside the AST. Plus, `PolicySet::add()` does its own validation + indexing per insert. So rebuilding a `PolicySet` (e.g. to rename policies) costs in proportion to `|policies|` — measurable at ~15% on complex-policy workloads in release mode (much more in debug). Don't put per-call `PolicySet` rebuilds on the hot path. (#68 was this exact mistake; the fix made `@id` rename opt-in via the `resolve_policy_ids_from_annotations` parameter.)
- **`@id` annotations are not parser directives** — they're metadata. `PolicySet::from_str` assigns auto-ids (`policy0`, `policy1`, ...) regardless of `@id` content. Honoring `@id` requires either rebuilding the `PolicySet` (current implementation, opt-in) or translating ids at result-construction time (alternative drafted but not adopted).

## Follow-on work to be aware of

- **GitHub Actions consolidation (GH issue #62):** 6 actions in `CI.yml` are on outdated major versions (e.g. `actions/upload-artifact@v4` when v7 is current). Planned approach: one consolidated PR pinning all actions to commit SHAs with tag comments. Defer until there's time to review the cross-major changelogs, and do not bundle with a release.
- **Benchmark process improvements (GH issue #69):** four items: add a benchmark variant exercising `resolve_policy_ids_from_annotations=True`; switch `make benchmark` targets to release builds; refresh `baseline.json` to a release-mode recording at the post-#68 tip; productize the multi-run aggregation pattern (currently in `out/v4.8.2-bisect/`). Items 2+3 must move together. Important pre-release-tooling work — until #69 lands, treat single-run regression alarms with skepticism and re-run N=5+ for medians.

## Out-of-tree working artifacts

The `out/` directory at the repo root holds local-only working artifacts (analysis docs, captured tool output, draft PR/issue text, benchmark JSONs from ad-hoc bisects). Currently NOT in `.gitignore`. Treat its contents as scratch space — useful for the maintainer running an investigation, not for the public repo. Don't commit `out/` files unless explicitly intended.
