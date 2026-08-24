#!/usr/bin/env python3
"""Create the version-bump pull request that starts a release.

Usage: scripts/prepare-release.py {patch|minor|major}

The script verifies the local checkout is a clean, up-to-date main, computes
the next version, updates Cargo.toml, Cargo.lock, and the pinned installer
links in README.md, and opens a pull request from a release/v<version>
branch. After that pull request merges, create-release-tag.yml tags the
merge commit, and the tag-triggered release workflow builds, attests, and
publishes the release once the release environment is approved.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_PATTERN = re.compile(r'^version = "(\d+)\.(\d+)\.(\d+)"$', re.MULTILINE)
PINNED_DOWNLOAD_PATTERN = re.compile(r"releases/download/v\d+\.\d+\.\d+/")


def fail(message: str) -> "sys.NoReturn":
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def run(*command: str, capture: bool = False) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=capture,
    )
    if result.returncode != 0:
        detail = (result.stderr or "").strip() if capture else ""
        suffix = f": {detail}" if detail else ""
        fail(f"`{' '.join(command)}` failed{suffix}")
    return (result.stdout or "").strip() if capture else ""


def ref_exists(ref: str) -> bool:
    local = subprocess.run(
        ["git", "rev-parse", "--quiet", "--verify", ref],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if local.returncode == 0:
        return True
    remote = run("git", "ls-remote", "origin", ref, capture=True)
    return bool(remote)


def current_version() -> tuple[int, int, int]:
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(manifest)
    if match is None:
        fail("Cargo.toml carries no exact SemVer package version")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def next_version(level: str) -> tuple[str, str]:
    major, minor, patch = current_version()
    current = f"{major}.{minor}.{patch}"
    if level == "major":
        return current, f"{major + 1}.0.0"
    if level == "minor":
        return current, f"{major}.{minor + 1}.0"
    return current, f"{major}.{minor}.{patch + 1}"


def ensure_ready() -> None:
    branch = run("git", "branch", "--show-current", capture=True)
    if branch != "main":
        fail(f"run from main; the current branch is {branch}")
    if run("git", "status", "--porcelain", capture=True):
        fail("the working tree has uncommitted changes")
    run("git", "fetch", "origin", "main")
    local = run("git", "rev-parse", "HEAD", capture=True)
    remote = run("git", "rev-parse", "origin/main", capture=True)
    if local != remote:
        fail("local main is not up to date with origin/main; run `git pull --ff-only`")


def rewrite_files(current: str, version: str) -> None:
    manifest_path = ROOT / "Cargo.toml"
    manifest = manifest_path.read_text(encoding="utf-8")
    updated = manifest.replace(
        f'version = "{current}"', f'version = "{version}"', 1
    )
    if updated == manifest:
        fail(f"Cargo.toml does not carry version {current}")
    manifest_path.write_text(updated, encoding="utf-8")

    run("cargo", "update", "--quiet", "--package", "gitveil")

    readme_path = ROOT / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    rewritten = PINNED_DOWNLOAD_PATTERN.sub(
        f"releases/download/v{version}/", readme
    )
    if rewritten == readme:
        fail("README.md carries no pinned installer download links to update")
    readme_path.write_text(rewritten, encoding="utf-8")


def pull_request_body(current: str, version: str) -> str:
    return f"""## Summary

Prepares the v{version} release per `docs/releasing.md`:

- `Cargo.toml` / `Cargo.lock`: version {current} -> {version}.
- README: pinned installer download links now reference `v{version}` (valid once the release is published).

Because this pull request touches `Cargo.toml`, the release workflow also builds all four native target archives as a pre-release rehearsal.

## After merge

Merging this pull request tags the merge commit automatically and starts the tag-triggered release workflow. Approving the `release` environment in Actions publishes the verified release; no further manual step exists after the approval.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("level", choices=["patch", "minor", "major"])
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive confirmation",
    )
    arguments = parser.parse_args()

    ensure_ready()
    current, version = next_version(arguments.level)
    branch = f"release/v{version}"
    print(f"current version: {current}")
    print(f"next version:    {version}")

    if ref_exists(f"refs/heads/{branch}"):
        fail(f"branch {branch} already exists")
    if ref_exists(f"refs/tags/v{version}"):
        fail(f"tag v{version} already exists")

    if not arguments.yes:
        answer = input(f"create the release pull request for v{version}? [y/N] ")
        if answer.strip().lower() != "y":
            print("release preparation cancelled")
            return

    rewrite_files(current, version)
    run("git", "switch", "-c", branch)
    run("git", "add", "Cargo.toml", "Cargo.lock", "README.md")
    run("git", "commit", "-m", f"Bump version to {version}")
    run("git", "push", "-u", "origin", branch)
    url = run(
        "gh",
        "pr",
        "create",
        "--title",
        f"Bump version to {version}",
        "--body",
        pull_request_body(current, version),
        capture=True,
    )
    run("git", "switch", "main")
    print(f"release pull request: {url}")
    print("next: merge the pull request; the tag and release run are automatic.")
    print("then: approve the release environment in Actions to publish.")


if __name__ == "__main__":
    main()
