#!/usr/bin/env python3
"""Create the version-bump pull request that starts a release.

Usage: scripts/prepare-release.py {patch|minor|major}

The script verifies the local checkout is a clean, up-to-date main and that
every input it needs is present, then updates Cargo.toml, Cargo.lock, and
the pinned installer links in README.md and opens a pull request from a
release/v<version> branch. All content and tool checks run before the first
write; a failure during the write phase rolls the three files back. After
the pull request merges, create-release-tag.yml tags the merge commit, and
the tag-triggered release workflow builds, attests, and publishes the
release once the release environment is approved.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from _lib.release_version import (
    ReleaseVersionError,
    bumped_version,
    package_version,
    rewrite_pinned_downloads,
    set_package_version,
)

ROOT = Path(__file__).resolve().parent.parent
RELEASE_FILES = ("Cargo.toml", "Cargo.lock", "README.md")


class CommandError(Exception):
    """An external command failed; the message names it and its stderr."""


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
        raise CommandError(f"`{' '.join(command)}` failed{suffix}")
    return (result.stdout or "").strip() if capture else ""


def restore(*command: str) -> None:
    """Best-effort rollback step; a rollback must never mask the failure."""
    subprocess.run(command, cwd=ROOT, check=False, capture_output=True)


def ref_exists(ref: str) -> bool:
    local = subprocess.run(
        ["git", "rev-parse", "--quiet", "--verify", ref],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if local.returncode == 0:
        return True
    return bool(run("git", "ls-remote", "origin", ref, capture=True))


def ensure_clean_main() -> None:
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


def preflight(level: str) -> tuple[str, str, str, str]:
    """Runs every check and content computation before the first write."""
    ensure_clean_main()

    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    try:
        current = package_version(manifest)
        version = bumped_version(current, level)
        bumped_manifest = set_package_version(manifest, version)
        rewritten_readme = rewrite_pinned_downloads(readme, version)
    except ReleaseVersionError as error:
        fail(str(error))

    branch = f"release/v{version}"
    if ref_exists(f"refs/heads/{branch}"):
        fail(f"branch {branch} already exists")
    if ref_exists(f"refs/tags/v{version}"):
        fail(f"tag v{version} already exists")

    try:
        run("cargo", "--version", capture=True)
    except CommandError:
        fail("cargo is not available on PATH")
    try:
        run("gh", "auth", "status", capture=True)
    except CommandError:
        fail("`gh auth status` failed; authenticate with `gh auth login` first")

    return current, version, bumped_manifest, rewritten_readme


def write_release_files(bumped_manifest: str, rewritten_readme: str) -> None:
    """Applies the three-file bump; any failure restores all of them."""
    try:
        (ROOT / "Cargo.toml").write_text(bumped_manifest, encoding="utf-8")
        run("cargo", "update", "--quiet", "--package", "gitveil", capture=True)
        (ROOT / "README.md").write_text(rewritten_readme, encoding="utf-8")
    except (CommandError, OSError) as error:
        restore("git", "checkout", "--", *RELEASE_FILES)
        fail(f"{error}; Cargo.toml, Cargo.lock, and README.md were rolled back")


def publish_branch(branch: str, version: str) -> None:
    try:
        run("git", "switch", "-c", branch)
        run("git", "add", *RELEASE_FILES)
        run("git", "commit", "-m", f"Bump version to {version}")
    except CommandError as error:
        restore("git", "checkout", "--", *RELEASE_FILES)
        restore("git", "switch", "main")
        restore("git", "branch", "-D", branch)
        fail(f"{error}; the working tree and branches were rolled back")
    try:
        run("git", "push", "-u", "origin", branch)
    except CommandError as error:
        restore("git", "switch", "main")
        restore("git", "branch", "-D", branch)
        fail(f"{error}; nothing was pushed and the local branch was removed")


def pull_request_body(current: str, version: str) -> str:
    return f"""## Summary

Prepares the v{version} release per `docs/releasing.md`:

- `Cargo.toml` / `Cargo.lock`: version {current} -> {version}.
- README: pinned installer download links now reference `v{version}` (valid once the release is published).

Because this pull request touches `Cargo.toml`, the release workflow also builds all four native target archives as a pre-release rehearsal.

## After merge

Merging this pull request tags the merge commit automatically and starts the tag-triggered release workflow. Approving the `release` environment in Actions publishes the verified release; no further manual step exists after the approval.
"""


def create_pull_request(branch: str, current: str, version: str) -> str:
    try:
        return run(
            "gh",
            "pr",
            "create",
            "--title",
            f"Bump version to {version}",
            "--body",
            pull_request_body(current, version),
            capture=True,
        )
    except CommandError as error:
        restore("git", "switch", "main")
        fail(
            f"{error}; the branch {branch} is already pushed. "
            f"Retry with `gh pr create --head {branch}`, or abandon the "
            f"release with `git push origin --delete {branch}` and "
            f"`git branch -D {branch}`"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("level", choices=["patch", "minor", "major"])
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive confirmation",
    )
    arguments = parser.parse_args()

    try:
        current, version, bumped_manifest, rewritten_readme = preflight(arguments.level)
    except CommandError as error:
        fail(str(error))
    branch = f"release/v{version}"
    print(f"current version: {current}")
    print(f"next version:    {version}")

    if not arguments.yes:
        answer = input(f"create the release pull request for v{version}? [y/N] ")
        if answer.strip().lower() != "y":
            print("release preparation cancelled")
            return

    write_release_files(bumped_manifest, rewritten_readme)
    publish_branch(branch, version)
    url = create_pull_request(branch, current, version)
    try:
        run("git", "switch", "main")
    except CommandError as error:
        fail(f"{error}; the pull request exists: {url}")
    print(f"release pull request: {url}")
    print("next: merge the pull request; the tag and release run are automatic.")
    print("then: approve the release environment in Actions to publish.")


if __name__ == "__main__":
    main()
