# Changelog

All notable changes to `cedarpy` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

`cedarpy`'s version number tracks the upstream Cedar Policy engine major and minor version, with cedarpy-specific patch numbers. See the README for the Cedar engine ↔ `cedarpy` release mapping.

## [Unreleased]

### Added

- A reusable, pre-parsed `Entities` handle, mirroring the `PolicySet` handle. Parse a stable entity graph once with `Entities.from_json_str(entities_json, schema=None)` and pass the handle to `is_authorized`, `is_authorized_batch`, or `is_authorized_partial` anywhere an entities string/list is accepted — skipping the per-call JSON deserialization and transitive-closure computation. For the common "stable base plus a small per-request delta" pattern, `entities.add_from_json_str(delta_json, schema=None)` clones the base and parses only the delta, returning a **new** handle (the base is immutable and reused). The merge is a disjoint union: a delta uid that duplicates a non-identical base uid raises `ValueError`, as does malformed JSON or a schema violation. The `entities` parameter widens from `str | list` to `str | list | Entities`; existing string/list callers are unchanged, so this is a pure, opt-in addition. The handle supports `len()` (entity count) and `str()` (rendered entities JSON), and on a successful evaluation the result `metrics` gain an `entities_pre_parsed` flag (`1` for the handle path, `0` otherwise). Mirrors the cedar-java / cedar-policy-rb handle APIs ([#83](https://github.com/k9securityio/cedar-py/issues/83)). Thanks [@Iamrodos](https://github.com/Iamrodos)!

## [4.8.5] - 2026-06-21

### Added

- `is_authorized` / `is_authorized_batch` now accept a structured `{"type": ..., "id": ...}` dict for `principal`, `action`, and `resource`, in addition to the existing Cedar surface-syntax string (`'User::"alice"'`). The dict form routes through `EntityUid::from_json` (mirroring cedar-java's `JsonEUID`) and accepts entity ids containing characters the surface parser rejects as "needs to be normalized" (e.g. embedded newlines). Pure addition — string-form callers are unchanged. Also adds a `make corpus-tests` target that runs the upstream fuzzer-generated corpus (7,462 files / 59,696 request cases); kept separate from `make integration-tests` because it takes several minutes ([#87](https://github.com/k9securityio/cedar-py/pull/87). Thanks [@geekphilosophy](https://github.com/geekphilosophy))!
- A reusable, pre-parsed `PolicySet` handle. Parse policies once with `PolicySet.from_str(...)` (or `PolicySet.from_json_str(...)` for the Cedar JSON/EST format) and pass the handle to `is_authorized`, `is_authorized_batch`, or `is_authorized_partial` anywhere a policies string is accepted — skipping the re-parse on every call, which is the dominant per-call cost for static policy sets. The `policies` parameter widens from `str` to `str | PolicySet`; passing policies as a string is unchanged, so this is a pure, opt-in addition. The handle is immutable, releases its memory when the last Python reference is dropped, supports `len()` (policy count) and `str()` (rendered Cedar text), and raises `ValueError` at construction on unparseable policies. On a successful evaluation the result `metrics` gain a `policies_pre_parsed` flag (`1` for the handle path, `0` for the string path). Mirrors the cedar-java / cedar-policy-rb handle APIs. Scoped to policies; reusable `Entities` / `Schema` handles are a possible follow-up ([#83](https://github.com/k9securityio/cedar-py/issues/83)). Thanks [@Iamrodos](https://github.com/Iamrodos)!

### Changed

- **Behavior change.** `is_authorized` / `is_authorized_batch` now raise a `KeyError` when a request is missing `principal`, `action`, or `resource`, instead of triggering a Rust panic. The missing field name is named in the exception ([#87](https://github.com/k9securityio/cedar-py/pull/87))
- **Behavior change.** Diagnostic errors during `is_authorized` / `is_authorized_batch` (policy-parse, per-request, and result-serialization errors) are no longer written to stdout unless `verbose=True`, matching the rest of the authorization path. The errors are still returned in the result's `diagnostics` ([#83](https://github.com/k9securityio/cedar-py/issues/83))

## [4.8.4] - 2026-05-29

### Added

- Adds `is_authorized_partial(request, policies, entities, schema=None)` for Cedar's partial-evaluation authorizer. Request fields that are `None` or absent are treated as unknowns. The authorizer returns `Decision.Allow` or `Decision.Deny` when the unknowns can't change the outcome, and `Decision.NoDecision` plus residual policies (as Cedar JSON) otherwise; callers re-evaluate the residuals once the unknowns are bound. `PartialAuthzResult` uses the same `decision` / `correlation_id` / `diagnostics` / `metrics` structure as `AuthzResult`, with `may_be_determining`, `must_be_determining`, `nontrivial_residuals`, and `unknown_entities` added to diagnostics. Unlike `is_authorized`, an absent or `None` `context` is treated as unknown rather than empty. Pass `context={}` for an explicitly empty context. **Note: A partial-eval result is not a final authorization decision.** Re-run `is_authorized` once unknowns are bound; schema type-checking (including action-typed context shapes) is skipped while fields remain unknown. Enables the `partial-eval` Cargo feature on `cedar-policy` ([#28](https://github.com/k9securityio/cedar-py/issues/28)) — Thanks [@swenger](https://github.com/swenger)!

### Changed

- `make benchmark-compare` now runs N=5 release-mode benchmarks at HEAD and gates on median Δ vs `tests/benchmark/results/baseline.json`, replacing the prior single pytest-benchmark run with `--benchmark-compare-fail=median:5%,mean:15%`. The `mean` threshold has been dropped — a single tail outlier could trip a passing run, and the N=5 median is the stable signal. Per-run JSONs land in `tests/benchmark/results/current/` (gitignored). Override the run count via `BENCHMARK_RUNS=N` ([#69](https://github.com/k9securityio/cedar-py/issues/69))

## [4.8.3] - 2026-05-13

### Changed

- **Behavior change (partial revert of 4.8.2).** `AuthzResult.diagnostics.reasons` and `ValidationError.policy_id` once again surface the parser-generated `PolicyId` (e.g., `policy0`), restoring the 4.8.1 contract that was relied on for multi-tenant disambiguation. The `@id("...")` annotation value is now exposed in a parallel map keyed by the parser id: `Diagnostics.id_annotations_by_reason` and `ValidationResult.id_annotations_by_policy_id`. Entries are present whenever the policy declares an `@id` annotation, with the literal annotation value as the map value — so `@id("foo")` contributes `"foo"`, and `@id("")` / bare `@id` (which the Cedar docs define as equivalent to `@id("")`) contributes `""`. Policies with no `@id` annotation are omitted from the map. This keeps the 4.8.2 ergonomics gain (recover the `@id` label without rebuilding the policy set) while preventing identity collapse when two policies share the same `@id` ([#77](https://github.com/k9securityio/cedar-py/issues/77))

## [4.8.2] - 2026-05-12

### Added

- **Behavior change.** `@id("...")` annotations on a policy now surface as the human-readable id in `AuthzResult.diagnostics.reasons` and `ValidationError.policy_id`, instead of the auto-generated `policy0`/`policy1`/... id. Annotations are inert in Cedar evaluation per the [Cedar docs](https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-annotations); this is a labeling step on the response surface, not a rename of the underlying `PolicyId`. An `@id` with an empty value — either `@id("")` or value-less `@id` (which per the Cedar docs is equivalent to `@id("")`) — falls back to the parser-generated id, since an empty display id is unhelpful for logs and lookups ([#29](https://github.com/k9securityio/cedar-py/issues/29), [#74](https://github.com/k9securityio/cedar-py/issues/74), [#75](https://github.com/k9securityio/cedar-py/pull/75))

### Changed

- **Behavior change.** `is_authorized` / `is_authorized_batch` now return `Decision.NoDecision` with a diagnostic when given an invalid schema, instead of silently discarding the schema and returning a real `Allow` / `Deny`. The same path applies in `validate_policies` ([#65](https://github.com/k9securityio/cedar-py/pull/65))

### Fixed

- `make release` now builds and tests a release-mode wheel. The target previously ran `maturin build` (which defaults to the dev/debug profile) and then ran pytest against whatever cedarpy was currently installed in the venv — neither half tested the wheel that would ship. PyPI artifacts were unaffected (CI already passed `--release`); this fixes locally-built wheels.

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

[Unreleased]: https://github.com/k9securityio/cedar-py/compare/v4.8.5...HEAD
[4.8.5]: https://github.com/k9securityio/cedar-py/compare/v4.8.4...v4.8.5
[4.8.4]: https://github.com/k9securityio/cedar-py/compare/v4.8.3...v4.8.4
[4.8.3]: https://github.com/k9securityio/cedar-py/compare/v4.8.2...v4.8.3
[4.8.2]: https://github.com/k9securityio/cedar-py/compare/v4.8.1...v4.8.2
[4.8.1]: https://github.com/k9securityio/cedar-py/compare/v4.8.0...v4.8.1
[4.8.0]: https://github.com/k9securityio/cedar-py/compare/v4.7.2...v4.8.0
