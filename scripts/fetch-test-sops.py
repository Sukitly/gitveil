#!/usr/bin/env python3
"""Fetch the SOPS binaries the test suite needs without changing system tools.

Two builds are fetched: the pinned sidecar, and the compatibility baseline whose
ciphertext the suite replays to prove leaf stability survives a sidecar upgrade.
Only the pinned binary's path is printed, because that is the one callers pass to
release packaging; the baseline is located by the tests themselves.
"""

from __future__ import annotations

from pathlib import Path
import sys

from _lib.sops_artifacts import (
    COMPATIBILITY_BASELINE_VERSION,
    VERSION,
    artifact_for,
    fetch_verified,
)


def fetch(root: Path, version: str) -> Path:
    artifact = artifact_for(version=version)
    destination = root / "target" / "test-tools" / f"sops-{version}" / "sops"
    return fetch_verified(destination, artifact)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        pinned = fetch(root, VERSION)
        fetch(root, COMPATIBILITY_BASELINE_VERSION)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    except Exception as error:
        print(f"could not fetch the SOPS test binaries: {error}", file=sys.stderr)
        return 1
    print(pinned)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
