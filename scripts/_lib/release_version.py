"""Pure version arithmetic and document rewriting for release preparation.

The package version is defined as the `version` key inside the `[package]`
section of Cargo.toml. Reads and writes are anchored to that section so this
module agrees with the structured readers in the release workflows
(`tomllib` in create-release-tag.yml, `cargo metadata` in release.yml) even
when other sections carry their own `version` lines.
"""

from __future__ import annotations

import re

_PACKAGE_HEADER_PATTERN = re.compile(r"^\[package\][ \t]*$", re.MULTILINE)
_SECTION_HEADER_PATTERN = re.compile(r"^\[", re.MULTILINE)
_VERSION_LINE_PATTERN = re.compile(r'^version = "(\d+)\.(\d+)\.(\d+)"$', re.MULTILINE)
_PINNED_DOWNLOAD_PATTERN = re.compile(r"releases/download/v\d+\.\d+\.\d+/")


class ReleaseVersionError(ValueError):
    """A manifest or document does not carry the expected release shape."""


def _package_section_span(manifest: str) -> tuple[int, int]:
    header = _PACKAGE_HEADER_PATTERN.search(manifest)
    if header is None:
        raise ReleaseVersionError("Cargo.toml carries no [package] section")
    start = header.end()
    following = _SECTION_HEADER_PATTERN.search(manifest, start)
    end = len(manifest) if following is None else following.start()
    return start, end


def package_version(manifest: str) -> str:
    """Returns the exact SemVer version of the `[package]` section."""
    start, end = _package_section_span(manifest)
    match = _VERSION_LINE_PATTERN.search(manifest, start, end)
    if match is None:
        raise ReleaseVersionError(
            "the [package] section carries no exact SemVer version"
        )
    return ".".join(match.groups())


def bumped_version(current: str, level: str) -> str:
    """Returns `current` bumped by one `major`, `minor`, or `patch` step."""
    major, minor, patch = (int(part) for part in current.split("."))
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    if level == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ReleaseVersionError(f"unknown bump level {level!r}")


def set_package_version(manifest: str, version: str) -> str:
    """Rewrites the `[package]` version; other sections stay untouched."""
    start, end = _package_section_span(manifest)
    section, count = _VERSION_LINE_PATTERN.subn(
        f'version = "{version}"', manifest[start:end], count=1
    )
    if count != 1:
        raise ReleaseVersionError(
            "the [package] section carries no exact SemVer version"
        )
    return manifest[:start] + section + manifest[end:]


def rewrite_pinned_downloads(document: str, version: str) -> str:
    """Repoints `releases/download/vX.Y.Z/` links; `releases/latest` stays."""
    rewritten, count = _PINNED_DOWNLOAD_PATTERN.subn(
        f"releases/download/v{version}/", document
    )
    if count == 0:
        raise ReleaseVersionError(
            "the document carries no pinned release download links"
        )
    return rewritten
