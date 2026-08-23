#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RUST_TOOLCHAIN=$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$ROOT/rust-toolchain.toml")
if [ -z "$RUST_TOOLCHAIN" ]; then
    echo "Unable to read the pinned toolchain from rust-toolchain.toml" >&2
    exit 2
fi
SOPS_VERSION=$(python3 "$ROOT/scripts/sops_artifacts.py" --print-version)
SOPS_BASELINE_VERSION=$(python3 "$ROOT/scripts/sops_artifacts.py" --print-version --baseline)
AGE_VERSION=$(python3 "$ROOT/scripts/age_artifacts.py" --print-version)
IMAGE_KEY=$(cat "$ROOT/docker/test.Dockerfile" "$ROOT/scripts/sops_artifacts.py" "$ROOT/scripts/age_artifacts.py" "$ROOT/rust-toolchain.toml" | cksum | awk '{ print $1 "-" $2 }')
IMAGE=${GITVEIL_LINUX_TEST_IMAGE:-gitveil-test:rust-$RUST_TOOLCHAIN-sops-$SOPS_VERSION-age-$AGE_VERSION-$IMAGE_KEY}
SOPS_METADATA=$(python3 "$ROOT/scripts/sops_artifacts.py" --system linux --machine "$(uname -m)")
SOPS_ARTIFACT=$(printf '%s\n' "$SOPS_METADATA" | cut -f1)
SOPS_SHA256=$(printf '%s\n' "$SOPS_METADATA" | cut -f2)
SOPS_BASELINE_METADATA=$(python3 "$ROOT/scripts/sops_artifacts.py" --baseline --system linux --machine "$(uname -m)")
SOPS_BASELINE_ARTIFACT=$(printf '%s\n' "$SOPS_BASELINE_METADATA" | cut -f1)
SOPS_BASELINE_SHA256=$(printf '%s\n' "$SOPS_BASELINE_METADATA" | cut -f2)
AGE_METADATA=$(python3 "$ROOT/scripts/age_artifacts.py" --system linux --machine "$(uname -m)")
AGE_ARTIFACT=$(printf '%s\n' "$AGE_METADATA" | cut -f1)
AGE_SHA256=$(printf '%s\n' "$AGE_METADATA" | cut -f2)

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required for local Linux tests" >&2
    exit 2
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    printf 'Building the local Linux test image; the first run downloads the Rust %s base image.\n' "$RUST_TOOLCHAIN"
    docker build \
        --file "$ROOT/docker/test.Dockerfile" \
        --build-arg "RUST_TOOLCHAIN=$RUST_TOOLCHAIN" \
        --build-arg "SOPS_VERSION=$SOPS_VERSION" \
        --build-arg "SOPS_ARTIFACT=$SOPS_ARTIFACT" \
        --build-arg "SOPS_SHA256=$SOPS_SHA256" \
        --build-arg "SOPS_BASELINE_VERSION=$SOPS_BASELINE_VERSION" \
        --build-arg "SOPS_BASELINE_ARTIFACT=$SOPS_BASELINE_ARTIFACT" \
        --build-arg "SOPS_BASELINE_SHA256=$SOPS_BASELINE_SHA256" \
        --build-arg "AGE_VERSION=$AGE_VERSION" \
        --build-arg "AGE_ARTIFACT=$AGE_ARTIFACT" \
        --build-arg "AGE_SHA256=$AGE_SHA256" \
        --tag "$IMAGE" \
        "$ROOT/docker"
else
    printf 'Using cached local Linux test image %s\n' "$IMAGE"
fi

docker run --rm \
    --mount "type=bind,source=$ROOT,target=/source,readonly" \
    --mount "type=volume,source=gitveil-cargo-registry,target=/usr/local/cargo/registry" \
    "$IMAGE" \
    sh -eu -c '
        mkdir -p /work
        tar --exclude=.git --exclude=target -C /source -cf - . | tar -C /work -xf -
        cd /work
        python3 scripts/check-architecture.py
        python3 scripts/check-docs.py
        cargo clippy --all-targets --all-features --locked -- -D warnings
        cargo nextest run --all-features --locked
        cargo build --release --locked
        python3 scripts/package-release.py \
            --skip-build \
            --binary target/release/gitveil \
            --sops-bin /usr/local/bin/sops \
            --age-keygen-bin /usr/local/bin/age-keygen \
            --age-keygen-archive /usr/local/share/gitveil-test/age.tar.gz \
            --output-dir target/package-test
    '
