#!/usr/bin/env python3
"""Checksum-pinned official age artifacts used by the quickstart test contract."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path
import platform
import shutil
import stat
import tarfile
import urllib.request

VERSION = "1.3.1"


def release_base_url(version: str) -> str:
    return f"https://github.com/FiloSottile/age/releases/download/v{version}"


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


# SHA-256 values are pinned from the official v1.3.1 GitHub release asset metadata.
_ARTIFACTS = {
    ("darwin", "x86_64"): Artifact(
        VERSION,
        "darwin",
        "x86_64",
        "age-v1.3.1-darwin-amd64.tar.gz",
        "2b233301ad21ab7b1eabd9ae1198a164005fa4928fcdd745d47c39f8593209d7",
    ),
    ("darwin", "aarch64"): Artifact(
        VERSION,
        "darwin",
        "aarch64",
        "age-v1.3.1-darwin-arm64.tar.gz",
        "01120ea2cbf0463d4c6bd767f99f3271bbed1cdc8a9aa718a76ba1fe4f01998b",
    ),
    ("linux", "x86_64"): Artifact(
        VERSION,
        "linux",
        "x86_64",
        "age-v1.3.1-linux-amd64.tar.gz",
        "bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377",
    ),
    ("linux", "aarch64"): Artifact(
        VERSION,
        "linux",
        "aarch64",
        "age-v1.3.1-linux-arm64.tar.gz",
        "c6878a324421b69e3e20b00ba17c04bc5c6dab0030cfe55bf8f68fa8d9e9093a",
    ),
}


def normalize_platform(
    system: str | None = None, machine: str | None = None
) -> tuple[str, str]:
    normalized_system = (system or platform.system()).lower()
    normalized_machine = (machine or platform.machine()).lower()
    normalized_machine = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "arm64": "aarch64",
    }.get(normalized_machine, normalized_machine)
    return normalized_system, normalized_machine


def artifact_for(system: str | None = None, machine: str | None = None) -> Artifact:
    normalized_system, normalized_machine = normalize_platform(system, machine)
    try:
        return _ARTIFACTS[(normalized_system, normalized_machine)]
    except KeyError as error:
        raise ValueError(
            f"unsupported age artifact: {VERSION} on "
            f"{normalized_system}/{normalized_machine}"
        ) from error


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_archive(path: Path, artifact: Artifact) -> None:
    actual = digest(path)
    if actual != artifact.sha256:
        raise ValueError(
            f"age checksum mismatch for {artifact.filename}: "
            f"expected {artifact.sha256}, got {actual}"
        )


def fetch_archive(destination: Path, artifact: Artifact) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        verify_archive(destination, artifact)
        return destination

    temporary = destination.with_name(f"{destination.name}.download")
    temporary.unlink(missing_ok=True)
    try:
        with urllib.request.urlopen(artifact.url, timeout=60) as response, temporary.open(
            "xb"
        ) as output:
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                output.write(chunk)
        verify_archive(temporary, artifact)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def extract_verified_age_keygen(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as package:
        try:
            member = package.getmember("age/age-keygen")
        except KeyError as error:
            raise ValueError("official age archive does not contain age/age-keygen") from error
        if not member.isfile():
            raise ValueError("official age archive age/age-keygen is not a file")
        source = package.extractfile(member)
        if source is None:
            raise ValueError("official age archive age/age-keygen cannot be read")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f"{destination.name}.extract")
        temporary.unlink(missing_ok=True)
        try:
            with source, temporary.open("xb") as output:
                shutil.copyfileobj(source, output)
            temporary.chmod(temporary.stat().st_mode | stat.S_IXUSR)
            temporary.replace(destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    return destination


def fetch_verified(destination: Path, artifact: Artifact) -> Path:
    archive = fetch_archive(destination.parent / artifact.filename, artifact)
    with tarfile.open(archive, "r:gz") as package:
        source = package.extractfile("age/age-keygen")
        if source is None:
            raise ValueError("official age archive age/age-keygen cannot be read")
        expected_binary_digest = hashlib.sha256(source.read()).hexdigest()
    if destination.is_file() and digest(destination) == expected_binary_digest:
        destination.chmod(destination.stat().st_mode | stat.S_IXUSR)
        return destination
    extracted = extract_verified_age_keygen(archive, destination)
    if digest(extracted) != expected_binary_digest:
        extracted.unlink(missing_ok=True)
        raise ValueError("extracted age-keygen does not match the verified archive")
    return extracted


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-version", action="store_true")
    parser.add_argument("--system")
    parser.add_argument("--machine")
    arguments = parser.parse_args()
    if arguments.print_version:
        print(VERSION)
    else:
        selected = artifact_for(arguments.system, arguments.machine)
        print(f"{selected.filename}\t{selected.sha256}")
