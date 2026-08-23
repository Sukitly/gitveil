#!/usr/bin/env python3
"""Pinned official SOPS artifacts shared by tests, Docker, and release packaging."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import platform
import stat
import urllib.request

# The sidecar shipped to users and required at runtime.
VERSION = "3.13.3"
# The SOPS build that wrote ciphertext already living in user repositories. The
# compatibility suite edits baseline-written envelopes with VERSION to prove the
# byte-for-byte leaf stability contract survives a sidecar upgrade. Advance this
# only once no supported repository can still hold older ciphertext.
COMPATIBILITY_BASELINE_VERSION = "3.13.2"


def release_base_url(version: str) -> str:
    return f"https://github.com/getsops/sops/releases/download/v{version}"


def source_url(version: str) -> str:
    return f"https://github.com/getsops/sops/tree/v{version}"


SOURCE_URL = source_url(VERSION)


@dataclass(frozen=True)
class Artifact:
    version: str
    system: str
    machine: str
    filename: str
    sha256: str

    @property
    def url(self) -> str:
        return f"{release_base_url(self.version)}/{self.filename}"


_ARTIFACTS = {
    ("3.13.3", "linux", "x86_64"): Artifact(
        "3.13.3",
        "linux",
        "x86_64",
        "sops-v3.13.3.linux.amd64",
        "e5bec3346a873ae91d871550f3e698c1aad962aff462a080e40f25fde17fef6b",
    ),
    ("3.13.3", "linux", "aarch64"): Artifact(
        "3.13.3",
        "linux",
        "aarch64",
        "sops-v3.13.3.linux.arm64",
        "53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77",
    ),
    ("3.13.3", "darwin", "x86_64"): Artifact(
        "3.13.3",
        "darwin",
        "x86_64",
        "sops-v3.13.3.darwin.amd64",
        "42162d5cef10b74fcf80a045a70e658d7ce6e63d6ea1be6f347e44015714468d",
    ),
    ("3.13.3", "darwin", "aarch64"): Artifact(
        "3.13.3",
        "darwin",
        "aarch64",
        "sops-v3.13.3.darwin.arm64",
        "b97c0d434aab577dc40310e8d22ff9e45eef4c80638ab978daae9b4681c59286",
    ),
    ("3.13.2", "linux", "x86_64"): Artifact(
        "3.13.2",
        "linux",
        "x86_64",
        "sops-v3.13.2.linux.amd64",
        "154dfe4cd70554bdd82b98e4cd4acf191d43d01ead6f00a73477aa44c4ac42ef",
    ),
    ("3.13.2", "linux", "aarch64"): Artifact(
        "3.13.2",
        "linux",
        "aarch64",
        "sops-v3.13.2.linux.arm64",
        "78abf2e15c86250a1553ae6f53aba96be6b2a8126f160b1534959add3467ad76",
    ),
    ("3.13.2", "darwin", "x86_64"): Artifact(
        "3.13.2",
        "darwin",
        "x86_64",
        "sops-v3.13.2.darwin.amd64",
        "5a66836229ff4a73779b19644b6db28fd574a6b995c15fc333469b2f93ee2acd",
    ),
    ("3.13.2", "darwin", "aarch64"): Artifact(
        "3.13.2",
        "darwin",
        "aarch64",
        "sops-v3.13.2.darwin.arm64",
        "412c475b52f167f1facd75d564422ffd1fa5302aaa7a404bdf4e30087e04b5a8",
    ),
}


def normalize_platform(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    normalized_system = (system or platform.system()).lower()
    normalized_machine = (machine or platform.machine()).lower()
    normalized_machine = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "arm64": "aarch64",
    }.get(normalized_machine, normalized_machine)
    return normalized_system, normalized_machine


def artifact_for(
    system: str | None = None,
    machine: str | None = None,
    version: str = VERSION,
) -> Artifact:
    normalized_system, normalized_machine = normalize_platform(system, machine)
    try:
        return _ARTIFACTS[(version, normalized_system, normalized_machine)]
    except KeyError as error:
        raise ValueError(
            f"unsupported SOPS artifact: {version} on {normalized_system}/{normalized_machine}"
        ) from error


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify(path: Path, artifact: Artifact) -> None:
    actual = digest(path)
    if actual != artifact.sha256:
        raise ValueError(
            f"SOPS checksum mismatch for {artifact.filename}: "
            f"expected {artifact.sha256}, got {actual}"
        )


def fetch_verified(destination: Path, artifact: Artifact) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        verify(destination, artifact)
        return destination

    temporary = destination.with_name(f"{destination.name}.download")
    temporary.unlink(missing_ok=True)
    try:
        with urllib.request.urlopen(artifact.url, timeout=60) as response, temporary.open("xb") as output:
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                output.write(chunk)
        verify(temporary, artifact)
        temporary.chmod(temporary.stat().st_mode | stat.S_IXUSR)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--print-version",
        action="store_true",
        help="print the selected SOPS version instead of its artifact metadata",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="select the compatibility baseline instead of the pinned sidecar",
    )
    parser.add_argument("--system")
    parser.add_argument("--machine")
    arguments = parser.parse_args()
    selected_version = COMPATIBILITY_BASELINE_VERSION if arguments.baseline else VERSION
    if arguments.print_version:
        print(selected_version)
    else:
        selected = artifact_for(arguments.system, arguments.machine, selected_version)
        print(f"{selected.filename}\t{selected.sha256}")
