# Task 74 - Define and implement support for `@id` annotations

GitHub issue: https://github.com/k9securityio/cedar-py/issues/74

## Objective

Provide the developer/operator ergonomics motivated by #66 — human-readable ids in `AuthzResult.diagnostics.reasons` and in `ValidationError.policy_id` when the author writes `@id("...")` — without:

- restricting what users can do with the underlying Cedar engine, and
- imposing per-call `PolicySet` rebuild cost on workloads that don't use `@id`.

Switch from **Path A** (rebuild the `PolicySet` so renamed ids appear natively in Cedar's `Diagnostics` / validation errors) to **Path B** (leave parser-generated `PolicyId`s untouched through evaluation; resolve `@id` only when serializing responses). Path B is correct per Cedar's documented semantics — annotations have no impact on policy evaluation, and `@id` is a CLI labeling convention, not part of the language — and cheap: O(matched policies) per response instead of O(|PolicySet|) per call.

## High-level implementation steps

1. **Pipe the parsed `PolicySet` into response construction.** `AuthzResponse::new` currently takes only Cedar's `Response`. It needs access to the `PolicySet` so it can look up `@id` annotations per matched policy via `PolicySet::annotation(pid, "id")` (third_party/cedar/cedar-policy/src/api.rs:1260). `execute_authorization_request` in `src/lib.rs:317` already has the `PolicySet` reference — pass it through.

2. **Resolve `@id` at serialization time in `DiagnosticsSer.reason`.** For each `PolicyId` in `response.diagnostics().reason()`, emit `policy_set.annotation(pid, "id").unwrap_or(pid.as_ref()).to_string()`. The wire shape stays `HashSet<String>` so Python's `AuthzResult.diagnostics.reasons` behavior is unchanged from #66, but no `PolicyId` renaming happens.

3. **Do the same for `validate_policies`.** After `validator.validate(...)`, walk `validation_result.validation_errors()` and replace each `policy_id` with the `@id` annotation (if present) before building `ValidationErrorSer`. The validation runs against the un-renamed `PolicySet`; only the serialized error surface is affected.

4. **Remove Path A from the hot path.** Drop the `rename_from_id_annotation` call from `is_authorized_batch` and `validate_policies` in `src/lib.rs`. Whether to delete the helper itself depends on whether anything else might still want it (likely not — leave for the cleanup pass).

5. **Decide the fate of `resolve_policy_ids_from_annotations`.** The opt-in parameter introduced in #70 exists to gate the cost of Path A. Once Path B replaces it, the parameter is essentially free always-on. Default Path B on, then either:
   - remove the parameter entirely (small API break vs. unreleased PR #70 only — #66 shipped in `[Unreleased]`), or
   - keep it as a no-op for one release for soft compat.

6. **Behavior decision: duplicate `@id` values.** Path A surfaces duplicate `@id`s as `NoDecision` + diagnostic (since two policies can't share a `PolicyId` after rename). Path B doesn't need that constraint — two distinct policies with the same `@id` both evaluate normally, and `reasons` will list the display name twice (deduped by the `HashSet`). Settle on the preferred semantics and align tests.

7. **Tests.**
   - Existing `@id` tests in `tests/unit/test_authorize.py:505–597` should pass (probably with `resolve_policy_ids_from_annotations` removed from the calls if the param is dropped).
   - `test_id_annotation_duplicate_returns_no_decision` needs revisiting per step 6.
   - Add coverage for `validate_policies` returning the `@id` value in `ValidationError.policy_id`.
   - Add coverage confirming evaluation outcome is independent of `@id` (e.g., two policies with conflicting `@id`s still produce correct `Allow`/`Deny`).

8. **Benchmark Path B.** Re-run `make benchmark-history` capturing one new state at the tip of this branch and compare against the existing v4.8.0 / main / PR #70 medians in `tests/benchmark/results/HISTORY.md`. Expectation: Path B sits within v4.8.0 noise floor on all benchmarks, with or without `@id` usage. If confirmed, supersede #70 and close that PR.

9. **Docs / CHANGELOG.** Update `CHANGELOG.md` (currently `[Unreleased]` carries the #66 + #70 entries — fold them into a single "Path B" entry). Update `CLAUDE.md`'s cedar API gotchas to reflect "annotations are inert; resolve at response time, not via rename".

10. **Close out related work.** When this lands: close #68 (root cause fixed), supersede #70 (close without merge), update #66's status in CHANGELOG.

## Questions

1. **Response shape — replace or surface both?** Should `reasons` continue to carry only the display-resolved id (drop-in replacement for current Path A behavior), or should we add a parallel field (e.g., `reasons_raw` / `policy_ids`) so tooling can see both the parser-generated id and the `@id` annotation? Smallest API surface vs. preserving ground truth for callers that want it.

Up through cedar-py 4.8.1, the authz_result.diagnostics.reasons has always been a list of the parser-generated policy ids. I don't think those policy ids are useful to users unless they also assume the policy ids are assigned in the same order in which they submitted their policies. Given the opacity of the current policy id generation process, I think it is reasonable to _replace_ the generated policy id, e.g. `policy0` with a policy's `@id` annotation if it exists and is populated with a string, e.g. `allow_view_photo`. 

Of course, it's possible or even probable that someone depends on the current behavior because it is externally visible (Hyrum's Law).   

2. **Duplicate `@id` semantics.** Treat as an error (current Path A behavior) or allow (Path B's natural behavior, with duplicated entries deduped by `HashSet`)? Tilt: allow, since Cedar itself permits it and the existing failure mode is a Path A artifact, not a user-protection feature.

`cedar-py` shoudl allow duplicate `@id`s because:
a. Cedar explicitly says that annotations are not used as part of policy evaluation. So enforcing non-duplicate `@id` annotations is not a 'Cedar' behavior, it would be a cedar-py specific behavior. And that may cause problems if an application's Cedar policies need to be used with `cedar-py` and other Cedar Policy binding implementations, including directly with the `cedar-policy` Rust library.   
b. Up through cedar-py 4.8.1, the cedar-py has allowed duplicate `@id`s (because it also ignored them).

 

3. **`resolve_policy_ids_from_annotations` parameter — remove or keep as deprecated no-op?** Removing is cleaner; the only users affected are anyone on `main` between #66 and this fix, since #66/#70 haven't shipped to PyPI.

Remove `resolve_policy_ids_from_annotations`.

4. **Annotation key — `id` only, or general?** The current Path A code only honors `@id`. Should we expose a more general API (e.g., let callers configure which annotation key drives display names), or keep `@id` hardcoded to match cedar-policy-cli convention? Tilt: keep `@id` hardcoded; expand if/when a real use case appears.

Support `id` only.

5. **Templates.** cedarpy doesn't yet expose a templates API (#29). Apply the same `@id`-on-templates resolution preemptively (symmetric with cedar-policy-cli) or wait until templates land?

Support `@id` on templates.

## Detailed implementation steps

TODO: Fill in once the questions above are answered and high-level steps are approved.
