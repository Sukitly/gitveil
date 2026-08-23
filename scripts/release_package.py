#!/usr/bin/env python3
"""Shared native release archive construction for Gitveil packaging and installation."""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from age_artifacts import VERSION as AGE_VERSION
from age_artifacts import artifact_for as age_artifact_for
from age_artifacts import fetch_archive as fetch_age_archive
from age_artifacts import fetch_verified as fetch_age_keygen
from age_artifacts import verify_archive as verify_age_archive
from age_artifacts import verify_binary as verify_age_keygen
from sops_artifacts import VERSION as SOPS_VERSION
from sops_artifacts import artifact_for, fetch_verified, verify


def package_version(root: Path) -> str:
    manifest = (root / "Cargo.toml").resolve()
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(manifest),
        ],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    metadata = json.loads(result.stdout)
    for package in metadata["packages"]:
        if Path(package["manifest_path"]).resolve() == manifest:
            return str(package["version"])
    raise RuntimeError("Cargo metadata does not contain the Gitveil package")


def archive_root_name(root: Path) -> str:
    artifact = artifact_for()
    return f"gitveil-v{package_version(root)}-{artifact.system}-{artifact.machine}"


def add_deterministic(tar: tarfile.TarFile, path: Path, arcname: str) -> None:
    info = tar.gettarinfo(str(path), arcname)
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    if info.isfile():
        with path.open("rb") as source:
            tar.addfile(info, source)
    else:
        tar.addfile(info)


def write_archive(staging_root: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive.with_name(f"{archive.name}.tmp")
    temporary.unlink(missing_ok=True)
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as output:
                paths = [staging_root, *sorted(staging_root.rglob("*"))]
                for path in paths:
                    add_deterministic(
                        output,
                        path,
                        str(path.relative_to(staging_root.parent)),
                    )
    temporary.replace(archive)


def expected_archive_members(archive_root: str) -> set[str]:
    return {
        f"{archive_root}",
        f"{archive_root}/bin",
        f"{archive_root}/bin/gitveil",
        f"{archive_root}/libexec",
        f"{archive_root}/libexec/gitveil",
        f"{archive_root}/libexec/gitveil/sops",
        f"{archive_root}/libexec/gitveil/age-keygen",
        f"{archive_root}/share",
        f"{archive_root}/share/licenses",
        f"{archive_root}/share/licenses/gitveil",
        f"{archive_root}/share/licenses/gitveil/LICENSE",
        f"{archive_root}/share/licenses/gitveil/SOPS-MPL-2.0.txt",
        f"{archive_root}/share/licenses/gitveil/SOPS-NOTICE.txt",
        f"{archive_root}/share/licenses/gitveil/AGE-BSD-3-Clause.txt",
        f"{archive_root}/share/licenses/gitveil/AGE-NOTICE.txt",
    }


def validate_archive(archive: Path, archive_root: str) -> None:
    expected = expected_archive_members(archive_root)
    with tarfile.open(archive, "r:gz") as package:
        member_list = package.getmembers()
    members = {member.name: member for member in member_list}
    if len(member_list) != len(members):
        raise RuntimeError("release archive contains duplicate member names")
    if set(members) != expected:
        missing = sorted(expected - set(members))
        extra = sorted(set(members) - expected)
        raise RuntimeError(f"invalid release archive layout; missing={missing}, extra={extra}")

    files = {
        f"{archive_root}/bin/gitveil",
        f"{archive_root}/libexec/gitveil/sops",
        f"{archive_root}/libexec/gitveil/age-keygen",
        f"{archive_root}/share/licenses/gitveil/LICENSE",
        f"{archive_root}/share/licenses/gitveil/SOPS-MPL-2.0.txt",
        f"{archive_root}/share/licenses/gitveil/SOPS-NOTICE.txt",
        f"{archive_root}/share/licenses/gitveil/AGE-BSD-3-Clause.txt",
        f"{archive_root}/share/licenses/gitveil/AGE-NOTICE.txt",
    }
    for name, member in members.items():
        if name in files and not member.isfile():
            raise RuntimeError(f"release member is not a file: {name}")
        if name not in files and not member.isdir():
            raise RuntimeError(f"release member is not a directory: {name}")
    for executable in [
        f"{archive_root}/bin/gitveil",
        f"{archive_root}/libexec/gitveil/sops",
        f"{archive_root}/libexec/gitveil/age-keygen",
    ]:
        if members[executable].mode & 0o111 == 0:
            raise RuntimeError(f"release executable is not executable: {executable}")


def build_archive(
    root: Path,
    output_dir: Path,
    binary: Path,
    sops_binary: Path | None,
    age_keygen_binary: Path | None,
) -> Path:
    artifact = artifact_for()
    if not binary.is_file():
        raise RuntimeError(f"Gitveil release binary is missing: {binary}")
    if sops_binary is None:
        sops_binary = fetch_verified(
            root / "target" / "release-tools" / f"sops-{SOPS_VERSION}" / "sops",
            artifact,
        )
    else:
        verify(sops_binary, artifact)

    age_artifact = age_artifact_for()
    age_tools = root / "target" / "release-tools" / f"age-{AGE_VERSION}"
    if age_keygen_binary is None:
        age_keygen_binary = fetch_age_keygen(age_tools / "age-keygen", age_artifact)
    else:
        test_archive = (
            root
            / "target"
            / "test-tools"
            / f"age-{AGE_VERSION}"
            / age_artifact.filename
        )
        if test_archive.is_file():
            verify_age_archive(test_archive, age_artifact)
            age_archive = test_archive
        else:
            age_archive = fetch_age_archive(
                age_tools / age_artifact.filename, age_artifact
            )
        verify_age_keygen(age_keygen_binary, age_archive)

    archive_root = archive_root_name(root)
    with tempfile.TemporaryDirectory(prefix="gitveil-package-") as temporary:
        staging_root = Path(temporary) / archive_root
        destinations = {
            binary: staging_root / "bin" / "gitveil",
            sops_binary: staging_root / "libexec" / "gitveil" / "sops",
            age_keygen_binary: staging_root / "libexec" / "gitveil" / "age-keygen",
            root / "LICENSE": staging_root / "share" / "licenses" / "gitveil" / "LICENSE",
            root / "licenses" / "SOPS-MPL-2.0.txt": staging_root
            / "share"
            / "licenses"
            / "gitveil"
            / "SOPS-MPL-2.0.txt",
            root / "licenses" / "SOPS-NOTICE.txt": staging_root
            / "share"
            / "licenses"
            / "gitveil"
            / "SOPS-NOTICE.txt",
            root / "licenses" / "AGE-BSD-3-Clause.txt": staging_root
            / "share"
            / "licenses"
            / "gitveil"
            / "AGE-BSD-3-Clause.txt",
            root / "licenses" / "AGE-NOTICE.txt": staging_root
            / "share"
            / "licenses"
            / "gitveil"
            / "AGE-NOTICE.txt",
        }
        for source, destination in destinations.items():
            if not source.is_file():
                raise RuntimeError(f"release input is missing: {source}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        os.chmod(staging_root / "bin" / "gitveil", 0o755)
        os.chmod(staging_root / "libexec" / "gitveil" / "sops", 0o755)
        os.chmod(staging_root / "libexec" / "gitveil" / "age-keygen", 0o755)
        archive = output_dir / f"{archive_root}.tar.gz"
        write_archive(staging_root, archive)
    validate_archive(archive, archive_root)
    return archive
