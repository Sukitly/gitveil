FROM rust:1.98-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7

# RUST_TOOLCHAIN is derived from rust-toolchain.toml by scripts/check-linux.sh so
# the pinned toolchain has a single source of truth. The base image tag only has
# to satisfy the same major.minor; rustup fetches the exact patch release.
ARG RUST_TOOLCHAIN
ARG SOPS_VERSION=3.13.3
ARG SOPS_ARTIFACT
ARG SOPS_SHA256
# The compatibility baseline is a test-only dependency: the suite replays
# ciphertext written by this build through the pinned sidecar.
ARG SOPS_BASELINE_VERSION=3.13.2
ARG SOPS_BASELINE_ARTIFACT
ARG SOPS_BASELINE_SHA256
# age-keygen is the pinned identity sidecar used by integration and packaging tests.
ARG AGE_VERSION=1.3.1
ARG AGE_ARTIFACT
ARG AGE_SHA256
ARG NEXTEST_VERSION=0.9.140
ENV SOPS_BIN=/usr/local/bin/sops \
    SOPS_BASELINE_BIN=/usr/local/bin/sops-baseline \
    SOPS_DISABLE_VERSION_CHECK=1 \
    AGE_KEYGEN_BIN=/usr/local/bin/age-keygen \
    AGE_KEYGEN_ARCHIVE=/usr/local/share/gitveil-test/age.tar.gz

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl git python3 \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    test -n "${RUST_TOOLCHAIN}"; \
    rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --component clippy --component rustfmt; \
    rustup default "${RUST_TOOLCHAIN}"; \
    rustc --version

RUN set -eu; \
    test -n "${SOPS_ARTIFACT}"; \
    test -n "${SOPS_SHA256}"; \
    curl --fail --location --silent --show-error \
        "https://github.com/getsops/sops/releases/download/v${SOPS_VERSION}/${SOPS_ARTIFACT}" \
        --output /usr/local/bin/sops; \
    echo "${SOPS_SHA256}  /usr/local/bin/sops" | sha256sum --check --strict; \
    chmod 0755 /usr/local/bin/sops; \
    sops --disable-version-check --version

RUN set -eu; \
    test -n "${SOPS_BASELINE_ARTIFACT}"; \
    test -n "${SOPS_BASELINE_SHA256}"; \
    curl --fail --location --silent --show-error \
        "https://github.com/getsops/sops/releases/download/v${SOPS_BASELINE_VERSION}/${SOPS_BASELINE_ARTIFACT}" \
        --output /usr/local/bin/sops-baseline; \
    echo "${SOPS_BASELINE_SHA256}  /usr/local/bin/sops-baseline" | sha256sum --check --strict; \
    chmod 0755 /usr/local/bin/sops-baseline; \
    /usr/local/bin/sops-baseline --disable-version-check --version

RUN set -eu; \
    test -n "${AGE_ARTIFACT}"; \
    test -n "${AGE_SHA256}"; \
    curl --fail --location --silent --show-error \
        "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/${AGE_ARTIFACT}" \
        --output /tmp/age.tar.gz; \
    echo "${AGE_SHA256}  /tmp/age.tar.gz" | sha256sum --check --strict; \
    tar -xzf /tmp/age.tar.gz -C /tmp age/age-keygen; \
    install -m 0755 /tmp/age/age-keygen /usr/local/bin/age-keygen; \
    mkdir -p /usr/local/share/gitveil-test; \
    install -m 0644 /tmp/age.tar.gz /usr/local/share/gitveil-test/age.tar.gz; \
    rm -rf /tmp/age /tmp/age.tar.gz; \
    age-keygen --version

RUN set -eu; \
    case "$(uname -m)" in \
        x86_64) \
            artifact="linux"; \
            checksum="4ee9aaa0d0171a985a5d0eb735b87355894c1c455972e9674fb9fdbd1387c9a3" \
            ;; \
        aarch64|arm64) \
            artifact="linux-arm"; \
            checksum="8b3f4d4560b6b0f83774fecc6be07e47716dbad0eb0bb6c3890f478f4affe4b6" \
            ;; \
        *) \
            echo "unsupported Docker architecture: $(uname -m)" >&2; \
            exit 1 \
            ;; \
    esac; \
    curl --fail --location --silent --show-error \
        "https://get.nexte.st/${NEXTEST_VERSION}/${artifact}" \
        --output /tmp/nextest.tar.gz; \
    echo "${checksum}  /tmp/nextest.tar.gz" | sha256sum --check --strict; \
    tar -xzf /tmp/nextest.tar.gz -C /usr/local/cargo/bin; \
    rm /tmp/nextest.tar.gz; \
    cargo nextest --version

WORKDIR /work
