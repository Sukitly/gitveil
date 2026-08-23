#!/usr/bin/env python3
"""Fetch the checksum-pinned age-keygen binary used by integration tests."""

from __future__ import annotations

from pathlib import Path
import sys

from age_artifacts import VERSION, artifact_for, fetch_verified


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    destination = root / "target" / "test-tools" / f"age-{VERSION}" / "age-keygen"
    try:
        binary = fetch_verified(destination, artifact_for())
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    except Exception as error:
        print(f"could not fetch the age-keygen test binary: {error}", file=sys.stderr)
        return 1
    print(binary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
