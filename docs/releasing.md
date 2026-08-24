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
- the `release` environment accepts only `v*` tags and requires maintainer approval before the draft job receives write permission; and
- GitHub release immutability locks the tag and all assets when the draft is published.

## Prepare the version

1. Update the package version in `Cargo.toml` through a pull request. Update `Cargo.lock` and user documentation when necessary.
2. Merge only after the required `Core`, `Linux`, and `macOS` checks pass. Release-related pull requests also build all four native target archives through `.github/workflows/release.yml`.
3. Confirm that the release commit is on `origin/main`, the working tree is clean, and the version has not already been released.

The tag must exactly match the Cargo package version. Prerelease suffixes and moving branch references are rejected.

## Create the draft release

From an up-to-date `main` checkout, create and push an annotated tag:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.1.0 -m "Gitveil v0.1.0"
git push origin v0.1.0
```

The tag-triggered release workflow:

1. verifies that the tag is exact SemVer, matches `Cargo.toml`, and points to `origin/main`;
2. runs the native host suite on Linux x86_64, Linux aarch64, macOS Intel, and macOS aarch64;
3. builds the Gitveil binary and fetches only the current runner's checksum-pinned official sidecars;
4. constructs and smoke-tests the complete native archive on each runner;
5. transfers all four archives with per-archive checksums;
6. generates the version-pinned installer and aggregate `SHA256SUMS` manifest;
7. attests all six final assets;
8. waits for approval of the `release` environment; and
9. creates or updates a draft GitHub Release with generated release notes.

The workflow refuses to replace assets on a published release.

## Verify and publish

After the workflow succeeds, inspect the draft release before publishing it:

```bash
rm -rf release-review
mkdir release-review
gh release download v0.1.0 --repo Sukitly/gitveil --dir release-review
(cd release-review && sha256sum --check SHA256SUMS)
for asset in release-review/*; do
  gh attestation verify "$asset" --repo Sukitly/gitveil
done
```

On macOS, use `shasum -a 256 --check SHA256SUMS` when `sha256sum` is unavailable. Confirm that the draft contains exactly the six declared assets, all attestations verify, generated notes describe the intended changes, and every release workflow job has no unresolved annotation.

Publish the draft through the GitHub Releases interface. Publication makes the release and its assets immutable and updates the `releases/latest` installer URL.

## Failed releases

- Retry a failed workflow job when the failure is transient and no artifact input changed.
- Never move or reuse a release tag after artifacts have been published.
- If source, dependencies, packaging, checksums, or installer behavior must change, fix them through a pull request and publish a new patch version.
- For a security release, coordinate through GitHub Private Vulnerability Reporting and publish the associated security advisory when disclosure is appropriate.
