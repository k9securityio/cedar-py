# Release Process

Releasing a new `cedarpy` version is a tag-driven process. Pushing a `v*` tag to `main` triggers the `release` job in
`.github/workflows/CI.yml`, which builds wheels on every platform, generates SLSA build-provenance attestations, and
publishes to PyPI via [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC — no long-lived tokens).

## Prerequisites (one-time)

- PyPI trusted publisher configured for `cedarpy` at https://pypi.org/manage/project/cedarpy/settings/publishing/ with:
    - Owner `k9securityio`, repository `cedar-py`, workflow `CI.yml`, environment `pypi-release`
- GitHub environment `pypi-release` configured in repo Settings → Environments with:
    - Deployment tags restricted to pattern `v*`
    - Required reviewer (maintainer) — provides a manual approval gate on every release
    - Prevent self-review: off (single-maintainer setup)

## Release steps

### 1. Open a release PR

```bash
git checkout main && git pull
git checkout -b release/X.Y.Z
```

Update three files:

- `Cargo.toml` — bump the `version` field (line 5)
- `README.md` — update the `cedarpy release` cell in the compatibility table
- `Cargo.lock` — regenerate by running `cargo build`

Commit with a message whose body is the draft release notes:

```bash
git commit -am "release: bump version to X.Y.Z

<summary of changes since last release>"
```

Open the PR, wait for CI green across all platforms, and merge.

### 2. Tag and push

From updated `main`:

```bash
git checkout main && git pull
git tag -a vX.Y.Z -m "cedarpy vX.Y.Z"
git push origin vX.Y.Z
```

The tag push triggers a full CI run plus the `release` job.

### 3. Approve the deployment

The `release` job pauses at the `pypi-release` environment waiting for reviewer approval.

1. Open the CI run on the tag in the Actions tab
2. Click **Review deployments** → select `pypi-release` → **Approve and deploy**

The job then:

1. Downloads all wheel + sdist artifacts from the build-matrix jobs
2. Generates SLSA provenance attestations via `actions/attest-build-provenance`
3. Runs `maturin upload --skip-existing` — authenticates via OIDC and publishes to PyPI

`--skip-existing` makes the job idempotent, so a re-run against an already-published version is a no-op.

### 4. Verify

Confirm at https://pypi.org/project/cedarpy/X.Y.Z/ that:

- All expected wheels (linux x86_64/aarch64, macos x86_64/aarch64, windows x64) and the sdist are present
- Provenance attestations appear on each distribution

### 5. Publish the GitHub Release

```bash
gh release create vX.Y.Z --title "cedarpy vX.Y.Z" --notes-file <path-to-notes>
```

Release notes should cover:

- Security fixes (with CVE / advisory IDs)
- Cedar Policy engine version change, if any
- Build / supply-chain changes
- `Full Changelog: <previous-tag>...vX.Y.Z` link

## Rollback

If a release is discovered to be broken after PyPI publish:

1. PyPI files cannot be replaced — cut a new patch version with the fix
2. Optionally yank the broken version on PyPI (`pip install cedarpy==X.Y.Z` still works for anyone who pinned it, but
   new installs won't pick it)
3. Delete the GitHub Release if it was published; the tag can remain

There is no way to un-publish a wheel from PyPI.
