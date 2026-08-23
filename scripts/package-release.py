#!/usr/bin/env python3
"""Build a native Gitveil release archive with its pinned private sidecars."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from release_package import build_archive
from sops_artifacts import digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--sops-bin", type=Path)
    parser.add_argument("--age-keygen-bin", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if not args.skip_build:
        subprocess.run(["cargo", "build", "--release", "--locked"], cwd=root, check=True)
    binary = (args.binary or root / "target" / "release" / "gitveil").resolve()
    sops_binary = args.sops_bin.resolve() if args.sops_bin else None
    age_keygen_binary = (
        args.age_keygen_bin.resolve() if args.age_keygen_bin else None
    )
    output_dir = args.output_dir if args.output_dir.is_absolute() else root / args.output_dir
    archive = build_archive(
        root, output_dir, binary, sops_binary, age_keygen_binary
    )
    checksum = digest(archive)
    checksum_file = archive.with_suffix(f"{archive.suffix}.sha256")
    checksum_file.write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")
    print(archive)
    print(checksum_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
