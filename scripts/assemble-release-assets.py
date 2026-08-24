#!/usr/bin/env python3
"""Assemble the version-pinned installer and checksum manifest for a release."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from _lib.release_installer import assemble_release_assets


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--archive-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    try:
        installer, checksum_manifest = assemble_release_assets(
            args.version,
            args.archive_dir.resolve(),
            args.output_dir.resolve(),
        )
    except (OSError, ValueError) as error:
        print(f"could not assemble release assets: {error}", file=sys.stderr)
        return 1
    print(installer)
    print(checksum_manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
