"""Assemble version-pinned native release installer assets."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import shutil

from .release_archive import RELEASE_FILES, expected_archive_members

TARGETS = (
    ("darwin", "aarch64"),
    ("darwin", "x86_64"),
    ("linux", "aarch64"),
    ("linux", "x86_64"),
)
INSTALLER_NAME = "gitveil-installer.sh"
CHECKSUM_MANIFEST_NAME = "SHA256SUMS"
_VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def archive_name(version: str, system: str, machine: str) -> str:
    return f"gitveil-v{version}-{system}-{machine}.tar.gz"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_version(version: str) -> None:
    if _VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("release version must be an exact MAJOR.MINOR.PATCH value")


def expected_archives(version: str, archive_directory: Path) -> dict[str, Path]:
    validate_version(version)
    archives = {
        archive_name(version, system, machine): archive_directory
        / archive_name(version, system, machine)
        for system, machine in TARGETS
    }
    missing = [name for name, path in archives.items() if not path.is_file()]
    if missing:
        raise ValueError(f"release archives are missing: {', '.join(sorted(missing))}")
    return archives


def copy_atomic(source: Path, destination: Path, mode: int) -> None:
    if source.resolve() == destination.resolve():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f"{destination.name}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(mode)
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def write_atomic(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        with temporary.open("xb") as output:
            output.write(content)
            output.flush()
        temporary.chmod(mode)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def render_installer(version: str, checksums: dict[str, str]) -> str:
    cases = []
    for system, machine in TARGETS:
        name = archive_name(version, system, machine)
        uname_system = "Darwin" if system == "darwin" else "Linux"
        cases.append(
            f'''    "{uname_system}/{machine}")
        archive='{name}'
        expected_sha256='{checksums[name]}'
        ;;'''
        )
    target_cases = "\n".join(cases)
    expected_members = "\n".join(sorted(expected_archive_members("$archive_root")))
    rollback_files = "\n".join(
        f"        rollback_file {index} {relative}"
        for index, (relative, _) in reversed(list(enumerate(RELEASE_FILES, start=1)))
    )
    verify_files = "\n".join(
        f"verify_file {relative} {mode:04o}" for relative, mode in RELEASE_FILES
    )
    preflight_files = "\n".join(
        f"preflight_file {relative}" for relative, _ in RELEASE_FILES
    )
    commit_files = "\n".join(
        f"commit_file {index} {relative}"
        for index, (relative, _) in enumerate(RELEASE_FILES, start=1)
    )
    return f'''#!/bin/sh
set -eu

VERSION='{version}'
REPOSITORY='Sukitly/gitveil'

fail() {{
    printf 'gitveil installer: %s\\n' "$1" >&2
    exit 1
}}

usage() {{
    cat <<'USAGE'
Install Gitveil and its private SOPS and age-keygen sidecars.

Usage: gitveil-installer.sh [--prefix PATH]

Options:
  --prefix PATH  Installation prefix (default: $HOME/.local)
  -h, --help     Show this help
USAGE
}}

prefix=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            [ "$#" -ge 2 ] || fail "--prefix requires a path"
            prefix=$2
            [ -n "$prefix" ] || fail "installation prefix cannot be empty"
            shift 2
            ;;
        --prefix=*)
            prefix=${{1#--prefix=}}
            [ -n "$prefix" ] || fail "installation prefix cannot be empty"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

if [ -z "$prefix" ]; then
    [ -n "${{HOME-}}" ] || fail "HOME is required when --prefix is not provided"
    prefix=$HOME/.local
fi
case "$prefix" in
    /*) ;;
    *) fail "installation prefix must be an absolute path" ;;
esac

for required_command in curl tar mktemp sort cmp awk sed uname mkdir rm mv chmod; do
    command -v "$required_command" >/dev/null 2>&1 \
        || fail "required command is unavailable: $required_command"
done

system=$(uname -s)
machine=$(uname -m)
case "$machine" in
    arm64) machine=aarch64 ;;
    amd64|x64) machine=x86_64 ;;
esac
case "$system/$machine" in
{target_cases}
    *) fail "unsupported platform: $system/$machine" ;;
esac

archive_root=${{archive%.tar.gz}}
download_url="https://github.com/$REPOSITORY/releases/download/v{version}/$archive"
umask 077
mkdir -p "$prefix"
work=$(mktemp -d "$prefix/.gitveil-install.XXXXXX") \
    || fail "could not create installation staging directory"
mkdir -p "$work/backups" "$work/backed-up" "$work/committed"
complete=0

rollback_file() {{
    index=$1
    relative=$2
    destination=$prefix/$relative
    if [ -f "$work/backed-up/$index" ]; then
        rm -f "$destination"
        mv "$work/backups/$index" "$destination" || :
    elif [ -f "$work/committed/$index" ]; then
        rm -f "$destination"
    fi
}}

cleanup() {{
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$complete" -ne 1 ]; then
{rollback_files}
    fi
    rm -rf "$work"
    exit "$status"
}}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

archive_path=$work/$archive
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --output "$archive_path" "$download_url"

if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256=$(sha256sum "$archive_path" | awk '{{print $1}}')
elif command -v shasum >/dev/null 2>&1; then
    actual_sha256=$(shasum -a 256 "$archive_path" | awk '{{print $1}}')
else
    fail "neither sha256sum nor shasum is available"
fi
[ "$actual_sha256" = "$expected_sha256" ] \
    || fail "archive checksum verification failed"

cat > "$work/expected-members" <<EOF
{expected_members}
EOF
LC_ALL=C sort "$work/expected-members" -o "$work/expected-members"
tar -tzf "$archive_path" | sed 's:/$::' | LC_ALL=C sort > "$work/archive-members"
cmp -s "$work/expected-members" "$work/archive-members" \
    || fail "release archive contains an unexpected member layout"
tar -tvzf "$archive_path" > "$work/archive-member-types"
awk '
    substr($0, 1, 1) != "d" && substr($0, 1, 1) != "-" {{ exit 1 }}
' "$work/archive-member-types" \
    || fail "release archive contains a non-file or non-directory member"

mkdir "$work/extracted"
tar -xzf "$archive_path" -C "$work/extracted"
payload=$work/payload
mv "$work/extracted/$archive_root" "$payload"

verify_file() {{
    relative=$1
    mode=$2
    path=$payload/$relative
    [ -f "$path" ] && [ ! -L "$path" ] \
        || fail "release payload member is not a regular file: $relative"
    chmod "$mode" "$path"
}}
{verify_files}

"$payload/bin/gitveil" --version >/dev/null 2>&1 \
    || fail "Gitveil executable validation failed"
"$payload/libexec/gitveil/sops" --disable-version-check --version >/dev/null 2>&1 \
    || fail "SOPS sidecar validation failed"
"$payload/libexec/gitveil/age-keygen" --version >/dev/null 2>&1 \
    || fail "age-keygen sidecar validation failed"

preflight_file() {{
    relative=$1
    destination=$prefix/$relative
    if [ -d "$destination" ] && [ ! -L "$destination" ]; then
        fail "install destination is a directory: $destination"
    fi
}}
{preflight_files}

commit_file() {{
    index=$1
    relative=$2
    source=$payload/$relative
    destination=$prefix/$relative
    destination_parent=${{destination%/*}}
    mkdir -p "$destination_parent"
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        mv "$destination" "$work/backups/$index"
        : > "$work/backed-up/$index"
    fi
    if ! mv "$source" "$destination"; then
        return 1
    fi
    : > "$work/committed/$index"
}}
{commit_files}
complete=1

printf 'Installed Gitveil %s to %s\\n' "$VERSION" "$prefix"
case ":${{PATH-}}:" in
    *":$prefix/bin:"*) ;;
    *) printf 'Add %s/bin to PATH.\\n' "$prefix" ;;
esac
'''


def assemble_release_assets(
    version: str, archive_directory: Path, output_directory: Path
) -> tuple[Path, Path]:
    archives = expected_archives(version, archive_directory)
    checksums = {name: digest(path) for name, path in archives.items()}
    for name, source in archives.items():
        copy_atomic(source, output_directory / name, 0o644)
    installer = output_directory / INSTALLER_NAME
    write_atomic(installer, render_installer(version, checksums).encode("utf-8"), 0o755)

    manifest_entries = {
        **checksums,
        INSTALLER_NAME: digest(installer),
    }
    manifest = "".join(
        f"{checksum}  {name}\n"
        for name, checksum in sorted(manifest_entries.items())
    )
    checksum_manifest = output_directory / CHECKSUM_MANIFEST_NAME
    write_atomic(checksum_manifest, manifest.encode("utf-8"), 0o644)
    return installer, checksum_manifest
