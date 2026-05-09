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
  - `make benchmark-compare` for single-run regression check vs `tests/benchmark/results/baseline.json`. Do NOT refresh the baseline for routine dep updates — only for performance-relevant code changes.
  - `make benchmark-history` for release-mode multi-run capture across the historical commits listed in `tests/benchmark/capture_history.sh`. Outputs land in `tests/benchmark/results/history/<state>.json` (per-commit summary stats) and `tests/benchmark/results/HISTORY.md` (rendered cross-state table). The script does a `git checkout` per state and restores the starting branch on exit.
  - See `tests/benchmark/README.md` for the workflow, default run count (N=5) and why we landed there, the `STATES` format (`<save_prefix>:<git_ref>:<description>`, all required), and the `states-manifest.json` plumbing between the runner and aggregator.

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

## Follow-on work to be aware of

- **GitHub Actions consolidation (GH issue #62):** 6 actions in `CI.yml` are on outdated major versions (e.g. `actions/upload-artifact@v4` when v7 is current). Planned approach: one consolidated PR pinning all actions to commit SHAs with tag comments. Defer until there's time to review the cross-major changelogs, and do not bundle with a release.
- **Benchmark process improvements (GH issue #69):** three goals.
  - **Goal 2** (committed historical record + tooling for it) lands via PR #71 on `feat/issue-69-benchmark-history`: `make benchmark-history`, `tests/benchmark/capture_history.sh`, `tests/benchmark/aggregate.py`, `tests/benchmark/results/HISTORY.md`, and the per-commit summaries under `tests/benchmark/results/history/`.
  - **Goals 1 and 3 are still open.** Goal 1 switches `make benchmark` / `benchmark-save` / `benchmark-compare` to release mode (currently debug). Goal 3 rewires `make benchmark-compare` to do N=5 release-mode runs at HEAD and gate on **median Δ** vs a refreshed `baseline.json` — `pytest-benchmark` 5.x has no native cross-invocation aggregation, so the gating logic has to live in our aggregator.
  - **Sequencing:** goal 1 (release-mode targets) and the matching `baseline.json` refresh must move together — a release-mode run vs the current debug-mode baseline trivially "passes". The new baseline should be captured post-#68-fix on main; until that fix lands, `baseline.json` would record the regression as "normal".
  - **Empirical finding from PR #71's data:** medians are robust at N=5 (N=7 backfill shifted Δ by <1.3 pp on every benchmark we checked); max grows monotonically with N as more samples capture rare tail outliers and shouldn't be used for cross-state gating. The Δ max column in `HISTORY.md` is informational only.
