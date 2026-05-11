# Task 74 - Define and implement support for `@id` annotations

GitHub issue: https://github.com/k9securityio/cedar-py/issues/74

## Objective

Provide the developer/operator ergonomics motivated by #66 — human-readable ids in `AuthzResult.diagnostics.reasons` and in `ValidationError.policy_id` when the author writes `@id("...")` — without:

- restricting what users can do with the underlying Cedar engine, and
- imposing per-call `PolicySet` rebuild cost on workloads that don't use `@id`.

Switch from **Path A** (rebuild the `PolicySet` so renamed ids appear natively in Cedar's `Diagnostics` / validation errors) to **Path B** (leave parser-generated `PolicyId`s untouched through evaluation; resolve `@id` only when serializing responses). Path B is correct per Cedar's documented semantics — annotations have no impact on policy evaluation, and `@id` is a CLI labeling convention, not part of the language — and cheap: O(matched policies) per response instead of O(|PolicySet|) per call.

## High-level implementation steps

1. ✅ **Pipe the parsed `PolicySet` into response construction.** `AuthzResponse::new` currently takes only Cedar's `Response`. It needs access to the `PolicySet` so it can look up `@id` annotations per matched policy via `PolicySet::annotation(pid, "id")` (third_party/cedar/cedar-policy/src/api.rs:1260). `execute_authorization_request` in `src/lib.rs:317` already has the `PolicySet` reference — pass it through.

2. ✅ **Resolve `@id` at serialization time in `DiagnosticsSer.reason`.** Hoisted into a `resolve_display_id(policy_set, pid)` helper to deduplicate with the validation path and avoid the `Cedar::Id` parse cost of `PolicySet::annotation` — see notes on step 15. For each `PolicyId` in `response.diagnostics().reason()`, emit `policy_set.annotation(pid, "id").unwrap_or(pid.as_ref()).to_string()`. The wire shape stays `HashSet<String>` so Python's `AuthzResult.diagnostics.reasons` behavior is unchanged from #66, but no `PolicyId` renaming happens.

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

> All file:line references are against the current `feat/id-annotations-via-post-process` branch (`7b44b6d` + the new branch's work). PR #70 is **not** in this branch — the `resolve_policy_ids_from_annotations` parameter does not appear here, so steps below are written against the Path A baseline (always-on rename) from #66.

### Rust — `src/lib.rs`

1. **Switch `DiagnosticsSer.reason` from `HashSet<PolicyId>` to `HashSet<String>`** (`src/lib.rs:243–251`). JSON wire shape is unchanged (`PolicyId` already serializes as a bare string), but the new type lets us substitute display strings.

2. **Add a `policy_set: &PolicySet` parameter to `AuthzResponse::new`** (`src/lib.rs:298–314`). Inside, build `reason` by mapping each `&PolicyId` from `response.diagnostics().reason()` to:

   ```rust
   policy_set
       .annotation(pid, "id")
       .map(str::to_string)
       .unwrap_or_else(|| pid.to_string())
   ```

   Un-annotated policies retain their parser-generated id (`policy0`, `policy1`, …) — same observable behavior as v4.8.0 and earlier.

3. ✅ **Thread `policy_set` through `execute_authorization_request`** (`src/lib.rs:316–354`). The reference is already in scope (`policy_set: &PolicySet` parameter at line 319); just forward it to the `AuthzResponse::new` call at line 345.

4. ✅ **Remove the Path A rename in `is_authorized_batch`** (`src/lib.rs:124–141`). Replace the nested match with the direct parse result:

   ```rust
   let policy_set = match PolicySet::from_str(&policies) {
       Ok(pset) => pset,
       Err(parse_errors) => {
           let err_message = format!("policy parse errors:\n{:#}", parse_errors.to_string());
           println!("{:#}", err_message);
           errs.push(Error::msg(err_message));
           PolicySet::new()
       }
   };
   ```

5. ✅ **Remove the Path A rename in `validate_policies`** (`src/lib.rs:478–504`). Same shape as step 4. The validator runs against the un-renamed `PolicySet`.

6. ✅ **Resolve `@id` for validation errors** — via the shared `resolve_display_id` helper. (`src/lib.rs:555–566`). After `validator.validate(...)`, map each `ValidationError` like so:

   ```rust
   errors: validation_result
       .validation_errors()
       .map(|e| {
           let raw_id = e.policy_id();
           let display_id = policy_set
               .annotation(raw_id, "id")
               .map(str::to_string)
               .unwrap_or_else(|| raw_id.to_string());
           ValidationErrorSer { policy_id: display_id, error: e.to_string() }
       })
       .collect(),
   ```

7. ✅ **Delete `rename_from_id_annotation`** (`src/lib.rs:428–473`) outright. Nothing else calls it after steps 4 and 5.

8. ✅ **Build & smoke-test:** `maturin develop --release` from inside `venv-dev`. Run `pytest tests/unit -q` and confirm only the duplicate-`@id` test fails (it's about to be rewritten in step 11).

### Python tests — `tests/unit/test_authorize.py`

9. ✅ **Keep `test_id_annotation_renames_policy_id_in_reasons`** (`tests/unit/test_authorize.py:505–527`) as-is — behavior is unchanged from the user's perspective.

10. ✅ **Keep `test_id_annotation_mixed_with_unannotated_policies`** (`tests/unit/test_authorize.py:529–567`) as-is — un-annotated policies still surface as `policy0`/`policy1`/… per parser order.

11. ✅ **Rewrite `test_id_annotation_duplicate_returns_no_decision`** — landed as `test_id_annotation_duplicates_are_allowed`. The companion `test_validate_with_duplicate_policy_id_annotations` in `test_validate.py` was likewise rewritten to assert that validation now passes for duplicate `@id`s. (`tests/unit/test_authorize.py:569–597`) to assert the new Path B semantics:

    - Rename to `test_id_annotation_duplicate_is_allowed` (or similar).
    - Assert `decision == Allow` for a request that matches both duplicates.
    - Assert `diagnostics.reasons == ["dup"]` (one entry, deduped by the response's `HashSet`).
    - Assert `diagnostics.errors == []`.
    - Doc-comment the rationale: matches Cedar engine semantics (annotations are inert) and v4.8.1 behavior (duplicates were silently accepted because the parser-generated ids never collided).

12. ✅ **Add a new test asserting evaluation independence from `@id`.** Landed as `test_id_annotation_does_not_affect_evaluation` — covers alice/bob (each route to their own policy) and carol (no match → `Deny`). Two `permit`s with the same `@id("X")` but different `principal ==` clauses — verify each request still routes to the correct policy and returns the expected `Allow`/`Deny`. This is the regression test guarding against any future drift back toward "annotations affect evaluation".

13. ✅ **Add a new test for `validate_policies` annotation resolution.** Existing `test_id_annotation_renames_policy_id_in_validation_errors` covers case (a); new `test_validation_error_reports_parser_id_when_no_id_annotation` covers case (b).

14. ✅ **Audit the unit test suite against the Cedar annotations documentation.**

    Docs claims fetched from https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-annotations on 2026-05-10:
    1. Annotations are "arbitrary key-value pairs" with "no impact on policy evaluation."
    2. Syntax: `@annotationname("annotation value")`.
    3. **Values are optional**: omitting the value implicitly equals `""`, so `@annotationname` ≡ `@annotationname("")`.
    4. Multiple annotations allowed per policy.
    5. Annotations must appear at the top of the policy, before the effect.
    6. "`@id` is not special in the Cedar language, it behaves like any other annotation."
    7. "The Cedar CLI uses the `@id` annotation to set policy IDs, but other interfaces, such as the Cedar APIs, have other ways to set policy IDs."
    8. Example shown: `@advice("My advice")` `@id("My ID")` `@shadow_mode` stacked on one policy.

    Findings & convergence actions taken:

    - **Misalignment (now resolved)**: pre-existing `test_id_annotation_duplicate_returns_no_decision` (authorize) and `test_validate_with_duplicate_policy_id_annotations` (validate) asserted that duplicate `@id`s force `NoDecision` / `validation_passed=False`. This was a Path-A-specific behavior that contradicts docs claim 1 (annotations don't affect evaluation) and claim 6 (`@id` isn't special). Convergence: rewrote both as part of step 11 to assert duplicates are accepted.
    - **Gap (now closed)**: docs claim 1 wasn't directly exercised. Convergence: added `test_id_annotation_does_not_affect_evaluation` (step 12) — two policies with shared `@id` and different `principal ==` clauses, three principals, asserts each request lands on the right policy regardless of the shared annotation value.
    - **Gap (now closed)**: docs claim 4 (multiple annotations per policy) wasn't exercised. Convergence: added `test_id_annotation_coexists_with_other_annotations` — uses the docs' example trio `@advice("be careful")` + `@id("alice_view")` + `@shadow_mode` and asserts `@id` resolution still works in the presence of unrelated annotations.
    - **Gap (now closed)**: docs claim 3 (value-less annotation ≡ empty-string value) wasn't exercised, and the behavior is non-obvious — cedar-py's `resolve_display_id` returns the empty string rather than falling back to the parser id, since the user explicitly wrote `@id` (per the docs equivalence). Convergence: added `test_id_annotation_value_less_syntax` to lock the behavior in and document the choice.

    Deferred (out of scope for `@id` resolution):

    - **Gap**: cedar-py has no general API for surfacing non-`@id` annotations to callers. The docs say annotations are "available for use by services and applications that read and process Cedar policies" — but no `cedarpy` API exposes them. Convergence proposal: open a follow-up issue for a `policy_annotations(policies: str) -> List[Dict[str, str]]` (or similar) API once a real use case appears. Would expand the diff significantly and isn't required for `@id`.
    - **Gap**: docs claim 5 (annotations must precede the effect) is enforced by the Cedar parser; cedar-py would surface a parse error and we don't need to test parser internals.
    - **Gap**: annotations on templates. cedar-py doesn't expose a templates API yet (#29). When templates land, the same `resolve_display_id` path will need a template-aware lookup. Tracked under #29.

### Benchmarks

15. ✅ **Verify with `make benchmark-compare`.** All medians within v4.8.0 noise (≤3%) after the `resolve_display_id` optimization:

    | Benchmark | Baseline median | Path B median | Δ median |
    |---|---|---|---|
    | `test_complex_policy` | 273.3 | 272.4–276.2 | -0.4% to +1.1% |
    | `test_batch_simple_policy` | 384.5 | 387.2–388.3 | +0.7% to +1.0% |
    | `test_sandbox_b_batch_multiple_users` | 683.1 | 684.4–686.6 | +0.2% to +0.5% |
    | `test_batch_complex_policy` | 1234.2 | 1240.5–1253.2 | +0.5% to +1.5% |

    Single-run mean-based failures (e.g. `test_medium_entity_set` mean +30% driven by a 15ms max outlier) are expected per #69 goal 3 and the CLAUDE.md note on `mean` noise — the median signal is the gating one.

    A first attempt that called `PolicySet::annotation(pid, "id")` per matched policy showed a reproducible +9% median regression on `test_batch_simple_policy` because cedar parses the `"id"` key as a Cedar `Id` on every call. Switching to `policy.annotations().find(|(k, _)| *k == "id")` (which works on raw `&str` keys) eliminated the regression.

16. ❌ **Optional — capture a 7th historical state.** Deferring to a follow-up commit so the implementation diff stays focused. The `make benchmark-compare` results above are sufficient evidence for review; PR #70's state (#73) already provides the bracketing data point.

### Docs

17. ✅ **Update `CHANGELOG.md`.** Rewrote the `[Unreleased]` `@id` entry as a labeling-only feature and dropped the duplicate-`@id` NoDecision line (no longer the behavior). References #29 and #74.

18. ✅ **Update `CLAUDE.md`.** Added a "Cedar API gotchas" section with two entries: annotations are inert in evaluation (with the post-process recipe), and the `PolicySet::annotation` Cedar-`Id`-parse trap with the cheaper `policy.annotations().find()` alternative.

### Cleanup / close-out

19. 🚧 **Open the PR** with body referencing #74 (closes), #68 (closes — root cause fixed), and #70 (will be superseded; close without merge once this PR merges). Include the benchmark-compare output as evidence. Pending user direction to commit and push.

20. 🚧 **After merge:** close #68, close #70 with a comment pointing at the merged PR, comment on #66 noting the Path B replacement is the production approach. Delete the `feat/id-annotations-via-post-process` branch locally and on origin once the PR closes.
