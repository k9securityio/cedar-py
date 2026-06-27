# Task 62 - Consolidate GitHub Actions updates and pin to commit SHAs

GitHub issue: https://github.com/k9securityio/cedar-py/issues/62

## Objective

**Harden the CI and release process against supply-chain and related attacks**, using
`.github/workflows/CI.yml` as the surface. The headline change is closing the GitHub
Actions version debt (accumulated while Dependabot version-updates were dormant) and
pinning every action to an immutable commit SHA, but the task applies the broader set of
GitHub Actions security practices from these references:

- https://www.wiz.io/blog/github-actions-security-guide
- https://corgea.com/learn/github-actions-security-checklist

Do this in a single reviewed PR that:

- bumps all 7 distinct actions (19 `uses:` occurrences) to current cooldown-eligible versions,
- replaces every tag ref with a commit SHA pinned to that tag (`uses: actions/checkout@<sha>  # v7.0.0`),
  so a compromised upstream tag cannot silently ship new code into our build/release,
- sets `persist-credentials: false` on all `checkout` steps (we publish via OIDC and never
  git-push from CI, so the persisted `.git/config` credential is pure leak surface), and
- adds a **zizmor** workflow-lint job so unpinned actions / injection / dangerous-trigger
  regressions fail future PRs.

Per-action breaking-change review must be done and recorded in the PR body before the refs
are bumped. CI matrix (linux x86/aarch64, windows, macos x86/aarch64, sdist) plus the new
lint job must be green on the PR, and the release/OIDC-publish path must not regress.

Repo/org settings that can't be expressed in the workflow file (CODEOWNERS, disabling
Actions PR auto-approve, org action-allowlist + SHA-pin enforcement, Dependabot SHA
maintenance) are documented for a follow-up decision in `out/62-out-of-band-hardening.md`
(gitignored), not in this PR.

### Security posture assessment (researched 2026-06-27)

Already aligned with the references — **leave as-is**: workflow-level `permissions: contents: read`
with the release job scoping its own `id-token`/`contents:write`/`attestations`; safe triggers
(`pull_request`, not `pull_request_target`; no `workflow_run`/`issue_comment`); OIDC Trusted
Publishing with **zero `secrets.*`** in the workflow; `pypi-release` environment approval gate;
no untrusted `${{ github.event.* }}` shell interpolation; explicit artifact paths.
Deny-by-default `permissions: {}` was considered and **declined** — marginal over the existing
workflow-level `contents: read`.

Gaps addressed by this task: (1) tag-pinned not SHA-pinned actions; (2) `checkout` persists a
git credential; (3) no workflow linting. Gaps deferred out-of-band: CODEOWNERS, repo/org policy
settings, cooldown enforcement (manual discipline today — see CLAUDE.md "Version-selection policy").

## Version policy

Prefer the **latest** version of each action, subject to a **7-day cooldown** —
only adopt a release published at least 7 days ago (matching the Dependabot cooldown
in `.github/dependabot.yml`). As of the 2026-06-27 research the cutoff is
**published on or before 2026-06-20**. Two latest releases fall inside the cooldown
and we step back one release: `setup-python` v6.3.0 (2026-06-24) → **v6.2.0**, and
`attest-build-provenance` v4.1.1 (2026-06-26) → **v4.1.0**. Re-check dates at
implementation time and bump to whatever is then eligible.

## Current state (researched 2026-06-27)

| Action | In CI.yml | Latest | **Target (cooldown-eligible)** | Notes |
|---|---|---|---|---|
| `actions/checkout` | v4 | v7.0.0 | **v7.0.0** (2026-06-18, 9d) | Used on every job; `submodules: 'true'`. Latest v7 per user; supersedes the issue's stale v6 target. |
| `actions/setup-python` | v5 | v6.3.0 | **v6.2.0** (v6.3.0 too new) | Verify Python 3.13 still resolves on all runners. |
| `actions/upload-artifact` | v4 | v7.0.1 | **v7.0.1** | Must stay format-compatible with `download-artifact`. |
| `actions/download-artifact` | v4 | v8.0.1 | **v8.0.1** | Release job only; consumes `wheels-*` artifacts. |
| `actions/attest-build-provenance` | v1 | v4.1.1 | **v4.1.0** (v4.1.1 too new) | Provenance signing; verify `subject-path: 'wheels-*/*'` semantics. |
| `PyO3/maturin-action` | v1 | v1.51.0 | **v1.51.0** (no v2) | **Critical** — drives build + OIDC publish. Stay on v1. |
| `uraimo/run-on-arch-action` | v2 | v3.1.0 | **v3.1.0** | aarch64 tests only; highest-variance third-party. Verify the v2→v3 major on the emulated step. |

`uses:` occurrences in `CI.yml` (19 total): checkout ×4 (L31, L102, L143, L174),
setup-python ×3 (L34, L105, L146), maturin-action ×5 (L38, L110, L150, L176, L211),
upload-artifact ×4 (L45, L116, L156, L181), run-on-arch-action ×1 (L70),
download-artifact ×1 (L204), attest-build-provenance ×1 (L206).
The release-job actions — `download-artifact` (L204), `attest-build-provenance` (L206),
and the `maturin upload` (L211) — only run in the `release` job, which is skipped on PRs.

## High-level implementation steps

1. **Research per-action breaking changes** and record findings in the PR body
   (this is the gating research task from the issue checklist):
   - `upload-artifact` v4→v7: retention defaults, name-collision handling, min runner version.
   - `download-artifact` v4→v8: confirm `upload-artifact@v7` output is consumable by `@v8`.
   - `attest-build-provenance` v1→v4: glob resolution of `subject-path: 'wheels-*/*'`,
     attestation-per-file vs single, any newly-required inputs.
   - `checkout` v4→v7: confirm `submodules: 'true'` behavior unchanged (likely Node runtime bump only).
   - `setup-python` v5→v6 (v6.2.0): Python 3.13 resolution on ubuntu-22.04, windows-latest, macos-14, macos-15-intel.
   - `maturin-action`: confirm no v2; pick latest v1.x (v1.51.0).
   - `run-on-arch-action` v2→v3 (v3.1.0): review the major bump on the aarch64 emulation step.

2. **Resolve each chosen tag to its commit SHA** (`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`),
   handling lightweight vs annotated tags (dereference to the commit, not the tag object).

3. **Edit `CI.yml`** — (a) replace all 19 `uses:` refs with `@<sha>  # <tag>`; (b) add
   `persist-credentials: false` to the 4 `checkout` steps; (c) replace the stale maturin
   autogen header with a hand-maintained/SHA-pinned warning; (d) add a `lint-workflows`
   job running zizmor over `.github/workflows/`.

4. **Validate on the PR** — every build path + the new lint job run on `pull_request`; all
   matrix rows and the zizmor lint must pass.

5. **Release-path validation** — no throwaway tag (per Q1); the upgraded release-job actions
   are first exercised on the next real release. `maturin upload --skip-existing` keeps it idempotent.

6. **Document & close** — PR body carries the per-action changelog findings + the hardening
   summary; out-of-band repo/org recommendations live in `out/62-out-of-band-hardening.md`
   (gitignored). Update `CLAUDE.md`'s "Follow-on work" note (#62) once merged.

## Out of scope (this PR)

- Deny-by-default `permissions: {}` — declined; existing workflow-level `contents: read` suffices.
- Re-enabling Dependabot version-update PRs (keep `open-pull-requests-limit: 0`; security-only policy stays).
- Out-of-band repo/org settings (CODEOWNERS, PR auto-approve, org allowlist + SHA-pin
  enforcement) — captured in `out/62-out-of-band-hardening.md` for a separate decision.
- Rust/Python dependency bumps.

## Acceptance criteria

- [ ] All `uses:` refs in `CI.yml` pinned to commit SHAs with tag comments (zero bare `@vN` refs).
- [ ] All `checkout` steps set `persist-credentials: false`.
- [ ] A `lint-workflows` (zizmor) job is present and **green** on the PR.
- [ ] CI build matrix green on the PR.
- [ ] PR body documents per-action changelog review findings + the hardening summary.
- [ ] Out-of-band repo/org recommendations recorded in `out/62-out-of-band-hardening.md`.
- [ ] Release path validated on the next real release (no throwaway tag).

## Questions

1. **How do we validate the `release` job, which PR CI skips?** The job is gated
   `if: startsWith(github.ref, 'refs/tags/') || workflow_dispatch`, so a normal PR
   build never runs it — `download-artifact` v4→v8, `attest-build-provenance` v1→v4,
   and the maturin OIDC upload (the highest-risk bumps) go unexercised on the PR.

   **Resolved: no bogus releases.** Do not push a throwaway tag and do not use a
   `workflow_dispatch` dry run. Upgrade the release-job actions in this PR, merge on
   green PR CI (build matrix), and let them get their first real exercise on the next
   real release the user already needs to cut. `maturin upload --skip-existing` keeps
   that idempotent; if `attest-build-provenance@v4` or `download-artifact@v8`
   misbehaves it fails the release job *before* the publish step, so we fix-forward
   and re-run. Rollback if the release path regresses: revert this PR.

2. **`uraimo/run-on-arch-action` v2 → v3 major bump (third-party, aarch64 only).**
   Adopt the new major or hold on latest v2.x?

   **Resolved: adopt v3.1.0.** It's the prefer-latest choice, and unlike the
   release-job actions it runs on the linux **aarch64 matrix row on every PR**, so a
   v2→v3 breakage surfaces before merge. Review the v2→v3 changelog and record findings
   in the PR body.

3. **The maturin autogen header.** `CI.yml` opens with
   `# This file is autogenerated by maturin ... To update, run: maturin generate-ci`.
   The file is already heavily hand-edited and SHA-pinning diverges it further — a
   `maturin generate-ci` regenerate would clobber the SHA pins. Leave the header or fix it?

   **Resolved: update the header to warn.** Replace the stale "autogenerated" note with
   one stating the file is hand-maintained, actions are pinned to commit SHAs (per the
   `# vX.Y.Z` tag comments), and `maturin generate-ci` must not be used to regenerate it.

## Phase A research findings (2026-06-27)

Per-action changelog review (sources in the eventual PR body). All bumps are **SAFE** for
cedar-py's usage; CI is fully GitHub-hosted so the Node-24 / runner ≥ v2.327.1 floor that
several majors introduce is already satisfied (it only bites self-hosted runners).

| Action | Target | Verdict | Notes |
|---|---|---|---|
| `actions/checkout` | v7.0.0 | SAFE | v7's only behavior change blocks fork-PR checkout for `pull_request_target`/`workflow_run` — we use neither. `submodules:'true'` unchanged. |
| `actions/setup-python` | v6.x | SAFE | `architecture` + `python-version` inputs unchanged; 3.13 resolves on all runners; no required inputs. We don't set `cache`, so v6 cache-key changes are moot. |
| `actions/upload-artifact` | v7.0.1 | SAFE | Default `archive:true` still zips → keeps download compat. Distinct `name:`s, no collisions. |
| `actions/download-artifact` | v8.0.1 | SAFE | No-input "download all" still creates one `wheels-*/` dir per artifact (glob intact). v8 errors on hash-mismatch (non-event for valid artifacts) and skips unzip only for non-zipped content (ours is zipped). |
| `actions/attest-build-provenance` | v4.x | SAFE (1 change) | **v2+ emits a single combined attestation over `wheels-*/*` instead of one-per-wheel.** Accepted — it's the current recommended pattern. Permissions (`id-token`/`attestations: write`) unchanged. |
| `PyO3/maturin-action` | v1.51.0 | SAFE | No v2 exists. `--find-interpreter`/`sccache`/`manylinux:auto`/`command:sdist`/`command:upload` (OIDC) unchanged through v1.51.0. |
| `uraimo/run-on-arch-action` | v3.1.0 | SAFE | `arch`/`distro:ubuntu22.04`/`githubToken`/`install`/`run` all unchanged; v3 is a QEMU 9.2.2 upgrade that *improves* aarch64 emulation reliability. |

**Non-version hardening confirmations:**
- `persist-credentials: false` is safe on every checkout — nothing in CI git-pushes/commits, and
  the submodule is public so its clone needs no token. (checkout v6+ also moved any persisted
  cred to `$RUNNER_TEMP`, but with `false` none is persisted at all.)
- No untrusted `${{ github.event.* }}` shell interpolation exists to fix (audit found only an `if:` expression).

**zizmor decision (resolved):** run via **`pipx run zizmor==1.25.2`** in a `run:` step (pipx is
preinstalled on `ubuntu-latest`), with only `actions/checkout` as a SHA-pinned action — smallest
third-party surface, hard pass/fail via exit code. The official `zizmorcore/zizmor-action` (SARIF
integration) was considered and declined for surface reasons. Job needs `permissions: contents: read`
plus `env: GH_TOKEN: ${{ github.token }}` for online audits (or `--offline` for zero-network).
- **Version cooldown:** `zizmor==1.25.2` (published 2026-05-16) is eligible; `1.26.x` (2026-06-21)
  is too new under the on/before-2026-06-20 cutoff — re-check at implementation and take the newest eligible.
- **Expected zizmor result:** a fully SHA-pinned workflow with `persist-credentials:false`,
  `pull_request` triggers, least-privilege `permissions`, and OIDC produces **no findings** in the
  default `regular` persona. zizmor's `unpinned-uses` (all actions, since v1.20.0) and `artipacked`
  (checkout without `persist-credentials:false`) are exactly what would fail *before* Phase C — which
  is why the lint job is added in the same edit that SHA-pins everything and adds `persist-credentials:false`.

## Detailed implementation steps

Branch `chore/consolidate-pin-github-actions` is already cut and carries the task doc +
CLAUDE.md cooldown policy. The code change is confined to `.github/workflows/CI.yml`; the
out-of-band recommendations live in the gitignored `out/62-out-of-band-hardening.md` (already drafted).

### Phase A — Per-action changelog research

Deliverable: a findings note per action (drafted into the eventual PR body), confirming
the target version and flagging any breaking change or newly-required input.

1. For each action, read the release notes spanning current→target major(s) and record:
   - `actions/checkout` v4→v7: confirm `submodules: 'true'` still clones the
     `third_party/cedar-integration-tests` submodule the same way; expect a Node-runtime bump only.
   - `actions/setup-python` v5→v6: confirm `python-version: 3.13` (and the Windows
     `architecture:` input) still resolve on ubuntu-22.04, windows-latest, macos-14, macos-15-intel.
   - `actions/upload-artifact` v4→v7: retention defaults, artifact-name collision behavior,
     minimum runner version. Note the `wheels-*` naming the release job globs on.
   - `actions/download-artifact` v4→v8: confirm artifacts from `upload-artifact@v7` are
     consumable by `@v8` (the no-arg "download all" form used at L204), and that the
     unpack layout (`wheels-*/` directories) is unchanged — `attest` and `maturin upload` glob `wheels-*/*`.
   - `actions/attest-build-provenance` v1→v4: confirm `subject-path: 'wheels-*/*'` glob
     semantics (per-file vs single attestation) and check for any newly-required inputs.
   - `PyO3/maturin-action` v1.x: confirm no v2 exists; review v1 changelog to the chosen
     v1.51.0 for changes to `--find-interpreter`, `sccache`, `manylinux: auto`, `command: sdist`, `command: upload`.
   - `uraimo/run-on-arch-action` v2→v3: review the major bump for input/behavior changes
     to `arch`/`distro`/`githubToken`/`install`/`run`.

2. **zizmor lint approach (RESOLVED — see Phase A findings):** run `pipx run zizmor==<eligible>`
   in a `run:` step (no zizmor action; only `actions/checkout` is SHA-pinned in that job).
   Re-confirm the cooldown-eligible zizmor version at implementation (1.25.2 as of research;
   1.26.x once it clears 7 days).

3. **Confirm the two non-version hardening changes are safe for our usage:**
   - `persist-credentials: false` on `checkout`: we never `git push`/commit from CI and publish
     via OIDC, so no step needs the persisted credential. Confirm submodule checkout of the
     **public** `third_party/cedar-integration-tests` still works without it (it should — public
     remote needs no token).
   - Re-confirm there's no untrusted `${{ github.event.* }}` shell interpolation to fix (audit
     on 2026-06-27 found none; the only `github.*` use is an `if:` expression).

4. **Verify Phase A:** every action (incl. zizmor) has a recorded finding with an explicit
   "no breaking change for our usage" or a documented mitigation. No target left as "TBD".

### Phase B — Re-check cooldown and resolve tags → commit SHAs

Deliverable: a frozen mapping `action → tag → 40-char commit SHA` for all 8 actions
(7 existing + zizmor).

5. Re-run the cooldown check (today's date − 7 days; 14 for a major). For each action get
   the latest eligible release: `gh api repos/<owner>/<repo>/releases/latest --jq '[.tag_name,.published_at]|@tsv'`,
   stepping back a release if the latest is inside cooldown. Expect v6.3.0/v4.1.1 to have
   aged into eligibility by implementation time — take them if so (prefer-latest policy).
6. Resolve each chosen tag to the **commit** SHA, dereferencing annotated tags:
   `gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq '.object.type,.object.sha'` — if
   `.object.type == "tag"`, follow with `gh api repos/<owner>/<repo>/git/tags/<sha> --jq '.object.sha'`
   to get the underlying commit. Pin to the **commit** SHA, not the tag-object SHA.
7. Record the mapping in a scratch table for use in Phase C and the PR body.
8. **Verify Phase B:** each resolved SHA is 40 hex chars and `gh api repos/<o>/<r>/commits/<sha> --jq .sha`
   returns it (confirms it's a real commit on that repo). Cross-check the SHA against the
   tag on the action's GitHub releases/tags page.

### Phase C — Edit CI.yml

Deliverable: `CI.yml` with all `uses:` refs SHA-pinned, hardened `checkout` steps, a new
zizmor lint job, and a corrected header.

9. Replace the maturin autogen header (top of file) with the hand-maintained / SHA-pinned
   warning (per Question 3 resolution): state the file is hand-maintained, actions are
   pinned to commit SHAs per the `# vX.Y.Z` comments, and `maturin generate-ci` must not
   regenerate it.
10. Rewrite all 19 existing `uses:` lines to `uses: <action>@<sha>  # <tag>` form using the
    Phase B mapping. Keep two spaces before the `#` comment. Touch only the ref; leave each
    step's `with:`/`if:`/`name:` untouched. Apply any required-input changes from Phase A here.
11. Add `persist-credentials: false` to all 4 `checkout` steps' `with:` blocks (alongside the
    existing `submodules: 'true'` where present; the sdist checkout at L174 has no `with:` —
    add one).
12. Add a `lint-workflows` job (runs on `pull_request`/`push`, `permissions: contents: read`):
    SHA-pinned `checkout` (`persist-credentials: false`) then a `run:` step
    `pipx run zizmor==<eligible> .github/workflows/` with `env: GH_TOKEN: ${{ github.token }}`.
    This enforces SHA-pinning on every future PR — confirm zizmor passes against the just-edited
    file (triage any findings; only suppress via `zizmor.yml` with justification if a finding is a
    genuine false positive for our setup).
13. **Verify Phase C (local):**
    - `grep -nE 'uses:' .github/workflows/CI.yml` shows every line ending in a 40-hex SHA + `# v…`
      comment; **zero** bare `@vN` tag refs remain (now 20 `uses:` lines: 19 + the lint job's checkout).
    - `grep -c 'persist-credentials: false'` returns 5 (4 build/release checkouts + lint job checkout).
    - Syntax: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/CI.yml'))"`.
    - actionlint (not installed locally) via Docker:
      `docker run --rm -v "$PWD":/repo --workdir /repo rhysd/actionlint:latest -color` — must be clean.
    - zizmor locally if available (`uvx zizmor .github/workflows/` or the Docker image) — clean.
    - `git diff` review: only the header, `uses:` refs, `persist-credentials:` additions, and the
      new lint job changed.

### Phase D — PR and CI-matrix validation

Deliverable: a green PR exercising every build path + the lint job. (Open/push only when the user says to.)

14. Commit the `CI.yml` change (single focused commit) and, on the user's go-ahead, push and
    open the PR. PR body = the Phase A findings + the Phase B SHA↔tag mapping + a short hardening
    summary (SHA pins, `persist-credentials: false`, zizmor), per acceptance criteria.
15. **Verify Phase D:** all PR CI matrix rows green — linux x86_64 + **aarch64** (the aarch64
    row validates `run-on-arch-action@v3` end-to-end), windows x64, macos aarch64 + x86_64, sdist
    — **and** the new `lint-workflows` (zizmor) job green. This validates checkout (+persist-creds),
    setup-python, maturin-action (build/sdist), upload-artifact, run-on-arch, and zizmor.
    Note explicitly in the PR that `download-artifact@v8`, `attest-build-provenance@v4`, and
    `maturin upload` are **not** exercised here (release job is PR-skipped) — see Phase F.

### Phase E — Merge

16. Merge on green CI (squash per repo norm). No release smoke test (Question 1 resolution).

### Phase F — Release-path validation (on the next real release)

Deliverable: confirmation the upgraded release-job actions work, gathered from a real release
the user already needs to cut — no throwaway tags.

17. When the next `v*` release tag is pushed, watch the `release` job: `download-artifact@v8`
    unpacks `wheels-*/`, `attest-build-provenance@v4` attests `wheels-*/*`, `maturin upload
    --skip-existing` publishes via OIDC.
18. **Verify Phase F:** release job green; wheels on PyPI; provenance attestation generated.
    **Rollback:** if the release job fails on the upgraded actions, the publish step (which
    runs after attestation) won't have published a bad artifact; revert this PR's `CI.yml`
    change, re-tag/re-run (`--skip-existing` is idempotent), and fix-forward.

### Phase G — Close-out

19. Update `CLAUDE.md`'s "Follow-on work" note for #62 (mark SHA-pinning + hardening landed).
    Close GH #62 with a comment linking the PR. Note the new state: `CI.yml` actions are
    SHA-pinned and zizmor-gated, so Dependabot (if version-updates are re-enabled later) will
    propose SHA+comment bumps under the cooldown. Surface `out/62-out-of-band-hardening.md` to
    the user for the repo/org-settings follow-up decision.
