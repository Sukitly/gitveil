# Releasing Gitveil

GitHub Releases is Gitveil's only authoritative distribution source. Releases contain complete native archives for Linux and macOS, a version-pinned installer, a checksum manifest, and GitHub artifact attestations. Gitveil is not published to crates.io, and no release artifact may omit the private SOPS or age-keygen sidecar.

## Release contract

A stable release contains exactly these six assets:

```text
gitveil-v<version>-darwin-aarch64.tar.gz
gitveil-v<version>-darwin-x86_64.tar.gz
gitveil-v<version>-linux-aarch64.tar.gz
gitveil-v<version>-linux-x86_64.tar.gz
gitveil-installer.sh
SHA256SUMS
```

Every native archive contains `bin/`, `libexec/`, and `share/licenses/` as one installation unit. `gitveil-installer.sh` embeds the four archive digests and a fixed `vMAJOR.MINOR.PATCH` download path. It never resolves a moving branch or downloads an executable that is not covered by its embedded checksum table.

Published releases are immutable. Their tag and assets cannot be replaced or deleted. A release that needs a code or packaging correction must use a new patch version.

Repository settings enforce the publication boundary:

- the `Protect release tags` ruleset prevents updates and deletion for `refs/tags/v*`;
- the `release` environment accepts only `v*` tags and requires maintainer approval before the publish job receives write permission; and
- GitHub release immutability locks the tag and all assets at publication.

A version tag push builds, attests, and drafts the release without human involvement: draft creation and asset upload are not behind the approval gate. Drafts are invisible to users and carry no immutability, so their assets remain mutable until publication. The `release` environment therefore gates publication only, and the publish job re-derives the facts the approval relies on inside the gate: it downloads every draft asset, checks `SHA256SUMS`, and verifies each artifact attestation before anything goes live.

## One-time setup

Automatic tagging uses a dedicated credential because tags pushed with the default `GITHUB_TOKEN` do not trigger the tag-driven release workflow:

1. Create a fine-grained personal access token scoped to this repository only, with `Contents: Read and write` and no other permission, and a bounded expiration.
2. Store it as the `RELEASE_TOKEN` repository Actions secret.
3. When it expires, generate a replacement and overwrite the secret; nothing else changes.

## Standard release

A release is one command and two clicks:

```bash
scripts/prepare-release.py patch   # or minor / major
```

The script verifies a clean, up-to-date `main`, computes the next version, updates `Cargo.toml`, `Cargo.lock`, and the pinned installer links in `README.md`, and opens a pull request from a `release/v<version>` branch. Because the pull request touches `Cargo.toml`, the release workflow also builds all four native target archives as a pre-release rehearsal.

1. **Merge the release pull request** after the required `Core`, `Linux`, and `macOS` checks and the rehearsal pass. On merge, `create-release-tag.yml` validates that the branch name matches the Cargo version, tags the merge commit `v<version>`, and deletes the release branch. The tag push starts the release workflow.
2. **Approve the `release` environment** in the workflow run once the build, assembly, and attestation jobs finish. Approval is the publication decision: the publish job re-verifies the six-asset contract against the draft and then publishes it. There is no separate manual publish step.

The tag-triggered release workflow:

1. verifies that the tag is exact SemVer, matches `Cargo.toml`, and points to `origin/main`;
2. runs the native host suite on Linux x86_64, Linux aarch64, macOS Intel, and macOS aarch64;
3. builds the Gitveil binary and fetches only the current runner's checksum-pinned official sidecars;
4. constructs and smoke-tests the complete native archive on each runner;
5. transfers all four archives with per-archive checksums;
6. generates the version-pinned installer and aggregate `SHA256SUMS` manifest;
7. attests all six final assets;
8. creates a draft release with generated release notes;
9. waits for approval of the `release` environment; and
10. downloads the draft assets, verifies the six-asset contract, `SHA256SUMS`, and every artifact attestation, and publishes the release.

The workflow refuses to touch a release that is already published.

## Inspecting before approval

The draft and its generated notes are visible on the Releases page before the environment is approved. For an independent check on a trusted machine, download the draft assets and verify them:

```bash
rm -rf release-review
mkdir release-review
gh release download v<version> --repo Sukitly/gitveil --dir release-review
(cd release-review && shasum -a 256 --check SHA256SUMS)
for asset in release-review/*; do
  gh attestation verify "$asset" --repo Sukitly/gitveil
done
```

Release notes remain editable after publication; assets and the tag do not.

## Failed releases

- Retry a failed workflow job when the failure is transient and no artifact input changed.
- Never move or reuse a release tag after artifacts have been published.
- If source, dependencies, packaging, checksums, or installer behavior must change, fix them through a pull request and publish a new patch version.
- If `create-release-tag.yml` fails because `RELEASE_TOKEN` expired, refresh the secret and re-run the job; the tag step is idempotent.
- Manual fallback: the automated path is equivalent to tagging by hand. From an up-to-date `main` checkout of the release commit, `git tag -a v<version> -m "Gitveil v<version>" && git push origin v<version>` starts the same tag-triggered workflow.
- For a security release, coordinate through GitHub Private Vulnerability Reporting and publish the associated security advisory when disclosure is appropriate.
