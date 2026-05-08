# Changelog

All notable changes to `cedarpy` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`cedarpy`'s version number tracks the upstream Cedar Policy engine major and minor version, with cedarpy-specific patch numbers. See the README for the Cedar engine ↔ `cedarpy` release mapping.

## [Unreleased]

### Added

- `@id("...")` annotations on a policy or template now override the auto-generated `policy0`/`policy1`/... id, so `AuthzResult.diagnostics.reasons` and `ValidationError.policy_id` carry the human-readable id the user wrote in their policies ([#66](https://github.com/k9securityio/cedar-py/pull/66))

### Changed

- **Behavior change.** `is_authorized` / `is_authorized_batch` now return `Decision.NoDecision` with a diagnostic when given an invalid schema, instead of silently discarding the schema and returning a real `Allow` / `Deny`. The same path applies in `validate_policies` ([#65](https://github.com/k9securityio/cedar-py/pull/65))
- **Behavior change.** Two policies with the same `@id` annotation now surface as `Decision.NoDecision` (in `is_authorized`) or `validation_passed=False` (in `validate_policies`) with a `"duplicate policy id"` diagnostic. Prior to [#66](https://github.com/k9securityio/cedar-py/pull/66), `@id` annotations were ignored entirely, so duplicates were inert ([#66](https://github.com/k9securityio/cedar-py/pull/66))

## [4.8.1] - 2026-04-22

Dependency update release. No functional or API changes — Cedar Policy engine version is unchanged (still v4.8.2).

### Security

- Bump `pytest` 7.4.0 → 9.0.3 — [CVE-2025-71176](https://nvd.nist.gov/vuln/detail/CVE-2025-71176) ([#41](https://github.com/k9securityio/cedar-py/pull/41))
- Bump `wheel` 0.40.0 → 0.47.0 — [CVE-2026-24049](https://nvd.nist.gov/vuln/detail/CVE-2026-24049) ([#41](https://github.com/k9securityio/cedar-py/pull/41))
- Bump `time` 0.3.37 → 0.3.47 — [CVE-2026-25727](https://nvd.nist.gov/vuln/detail/CVE-2026-25727) ([#42](https://github.com/k9securityio/cedar-py/pull/42))
- Bump `keccak` 0.1.5 → 0.1.6 — [GHSA-3288-p39f-rqpv](https://github.com/advisories/GHSA-3288-p39f-rqpv) ([#42](https://github.com/k9securityio/cedar-py/pull/42))

### Changed

- Removed the stale `rustix = "~0.37.25"` pin; `rustix` is now governed by the transitive dep graph ([#43](https://github.com/k9securityio/cedar-py/pull/43))

### Build & supply chain

- Switched PyPI publishing from a long-lived API token to **PyPI Trusted Publishing** (OIDC), with a protected `pypi-release` deployment environment requiring maintainer approval. All wheels and the sdist for this release ship with SLSA build-provenance attestations ([#59](https://github.com/k9securityio/cedar-py/pull/59))
- Added a Dependabot cooldown policy (7 days for minor/patch bumps, 14 for majors) to reduce exposure to newly-published compromised releases ([#44](https://github.com/k9securityio/cedar-py/pull/44), [#45](https://github.com/k9securityio/cedar-py/pull/45))
- Disabled Dependabot version-update PRs; security-update PRs remain active ([#60](https://github.com/k9securityio/cedar-py/pull/60))

## [4.8.0] - 2025-12-17

### Changed

- **Potentially breaking.** Updated the Cedar Policy engine to v4.8.2. `format_policies()` output has changed: the Cedar 4.8 formatter emits dot notation instead of bracket notation ([#38](https://github.com/k9securityio/cedar-py/pull/38) — thanks [@Iamrodos](https://github.com/Iamrodos))

### Added

- Performance regression test suite built on `pytest-benchmark` ([#39](https://github.com/k9securityio/cedar-py/pull/39))

[Unreleased]: https://github.com/k9securityio/cedar-py/compare/v4.8.1...HEAD
[4.8.1]: https://github.com/k9securityio/cedar-py/compare/v4.8.0...v4.8.1
[4.8.0]: https://github.com/k9securityio/cedar-py/compare/v4.7.2...v4.8.0
