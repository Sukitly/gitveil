#!/usr/bin/env python3
"""Build and install a complete Gitveil release into a user-local prefix."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile

from release_package import archive_root_name, build_archive, package_version, validate_archive

_INSTALL_MEMBERS = (
    ("share/licenses/gitveil/LICENSE", 0o644),
    ("share/licenses/gitveil/SOPS-MPL-2.0.txt", 0o644),
    ("share/licenses/gitveil/SOPS-NOTICE.txt", 0o644),
    ("share/licenses/gitveil/AGE-BSD-3-Clause.txt", 0o644),
    ("share/licenses/gitveil/AGE-NOTICE.txt", 0o644),
    ("libexec/gitveil/sops", 0o755),
    ("libexec/gitveil/age-keygen", 0o755),
    ("bin/gitveil", 0o755),
)


def default_prefix() -> Path:
    cargo_home = os.environ.get("CARGO_HOME")
    return Path(cargo_home).expanduser() if cargo_home else Path.home() / ".cargo"


def extract_payload(archive: Path, archive_root: str, staging: Path) -> Path:
    validate_archive(archive, archive_root)
    payload = staging / "payload"
    with tarfile.open(archive, "r:gz") as package:
        for relative, mode in _INSTALL_MEMBERS:
            member_name = f"{archive_root}/{relative}"
            member = package.getmember(member_name)
            source = package.extractfile(member)
            if source is None:
                raise RuntimeError(f"release member cannot be read: {member_name}")
            destination = payload / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, destination.open("xb") as output:
                shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
            destination.chmod(mode)
    return payload


def verify_payload(payload: Path) -> None:
    commands = [
        [str(payload / "libexec/gitveil/sops"), "--disable-version-check", "--version"],
        [str(payload / "libexec/gitveil/age-keygen"), "--version"],
        [str(payload / "bin/gitveil"), "--version"],
    ]
    for command in commands:
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("installed executable validation could not run") from error
        if result.returncode != 0:
            raise RuntimeError("installed executable validation failed")


def is_directory_without_following_symlinks(path: Path) -> bool:
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except FileNotFoundError:
        return False


def path_exists(path: Path) -> bool:
    return os.path.lexists(path)


def commit_payload(payload: Path, prefix: Path, staging: Path) -> None:
    destinations = [(payload / relative, prefix / relative) for relative, _ in _INSTALL_MEMBERS]
    for _, destination in destinations:
        if is_directory_without_following_symlinks(destination):
            raise RuntimeError(f"install destination is a directory: {destination}")

    backups = staging / "backups"
    backups.mkdir()
    committed: list[tuple[Path, Path | None]] = []
    complete = False
    try:
        for index, (source, destination) in enumerate(destinations):
            destination.parent.mkdir(parents=True, exist_ok=True)
            backup = backups / str(index) if path_exists(destination) else None
            if backup is not None:
                os.replace(destination, backup)
            installed = False
            try:
                os.replace(source, destination)
                installed = True
            finally:
                if not installed and backup is not None:
                    os.replace(backup, destination)
            committed.append((destination, backup))
        complete = True
    finally:
        if not complete:
            for destination, backup in reversed(committed):
                if path_exists(destination):
                    destination.unlink()
                if backup is not None and path_exists(backup):
                    os.replace(backup, destination)


def install_archive(archive: Path, archive_root: str, prefix: Path) -> None:
    prefix.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".gitveil-install-", dir=prefix) as temporary:
        staging = Path(temporary)
        payload = extract_payload(archive, archive_root, staging)
        verify_payload(payload)
        commit_payload(payload, prefix, staging)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and install Gitveil with its pinned private sidecars."
    )
    parser.add_argument(
        "--prefix",
        type=Path,
        help="installation prefix (default: $CARGO_HOME or ~/.cargo)",
    )
    parser.add_argument("--binary", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--sops-bin", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--age-keygen-bin", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--skip-build", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if not args.skip_build:
        subprocess.run(["cargo", "build", "--release", "--locked"], cwd=root, check=True)
    binary = (args.binary or root / "target" / "release" / "gitveil").resolve()
    sops_binary = args.sops_bin.resolve() if args.sops_bin else None
    age_keygen_binary = (
        args.age_keygen_bin.resolve() if args.age_keygen_bin else None
    )
    prefix = (args.prefix or default_prefix()).expanduser().resolve()
    archive_root = archive_root_name(root)

    with tempfile.TemporaryDirectory(prefix="gitveil-local-package-") as temporary:
        archive = build_archive(
            root, Path(temporary), binary, sops_binary, age_keygen_binary
        )
        install_archive(archive, archive_root, prefix)

    print(f"Installed Gitveil {package_version(root)} to {prefix}")
    bin_directory = prefix / "bin"
    path_entries = {
        Path(entry).expanduser().resolve()
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry
    }
    if bin_directory not in path_entries:
        print(f"Add {bin_directory} to PATH.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
