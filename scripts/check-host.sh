#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

case "$(uname -s)" in
    Darwin|Linux) ;;
    *)
        echo "Gitveil local checks support macOS and Linux only" >&2
        exit 2
        ;;
esac

if ! cargo nextest --version >/dev/null 2>&1; then
    echo "cargo-nextest is required: cargo install cargo-nextest --locked" >&2
    exit 2
fi

SOPS_TEST_BIN=$(python3 scripts/fetch-test-sops.py)
AGE_KEYGEN_TEST_BIN=$(python3 scripts/fetch-test-age.py)
cargo fmt --all -- --check
python3 scripts/check-architecture.py
python3 scripts/check-docs.py
cargo clippy --all-targets --all-features --locked -- -D warnings
AGE_KEYGEN_BIN="$AGE_KEYGEN_TEST_BIN" cargo nextest run --all-features --locked
cargo deny check
cargo build --release --locked
python3 scripts/package-release.py \
    --skip-build \
    --binary target/release/gitveil \
    --sops-bin "$SOPS_TEST_BIN" \
    --output-dir target/package-test
git diff --check
