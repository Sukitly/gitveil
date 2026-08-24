#!/usr/bin/env python3
"""Fetch the checksum-pinned age-keygen binary used by integration tests."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from age_artifacts import VERSION, artifact_for, fetch_verified


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-archive", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    destination = root / "target" / "test-tools" / f"age-{VERSION}" / "age-keygen"
    artifact = artifact_for()
    try:
        binary = fetch_verified(destination, artifact)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    except Exception as error:
        print(f"could not fetch the age-keygen test binary: {error}", file=sys.stderr)
        return 1
    print(binary.parent / artifact.filename if args.print_archive else binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
