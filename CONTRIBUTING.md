# Contributing to Gitveil

Gitveil handles secret-bearing files and Git history, so changes must preserve its security boundaries as well as its user-visible behavior.

## Development environment

Required tools:

- macOS or Linux
- Git 2.20+
- Rust 1.98.0, selected automatically by `rust-toolchain.toml`
- Python 3.9+
- `cargo-nextest` 0.9.140
- `cargo-deny`
- Docker for the Linux quality gate

Install the Cargo tools if they are not already available:

```bash
cargo install cargo-nextest --locked --version 0.9.140
cargo install cargo-deny --locked
```

The test and packaging scripts download checksum-pinned SOPS and age artifacts into `target/` on first use. They do not modify system installations.

## Making changes

Create a branch from the latest `main`. Keep commits focused and use English for commit messages, pull request titles, descriptions, code comments, tests, and documentation.

When changing core behavior, add or update the relevant test first and confirm that it fails for the expected reason before implementing the change. Pure decisions belong in pure modules; filesystem, process, Git, SOPS, environment, clock, and random effects stay at explicit boundaries.

Preserve these invariants:

- Secret values, private identities, and decrypted comments must not enter argv, logs, errors, reports, baselines, tracked fixtures, or Git metadata.
- Unknown subprocess output is redacted by default.
- Workspace paths are validated before descriptor-relative filesystem access; symlink and submodule escapes are rejected.
- Git subprocesses are read-only. Gitveil does not modify the index, configuration, hooks, attributes, or Git state outside `.git/gitveil/`.
- SOPS and age-keygen subprocess arguments never contain secret values or private identity material.
- Production code does not use `unwrap` or `expect` for external input, filesystem, Git, SOPS, process, or protocol results.
- Do not use `unsafe` unless a platform security API has no safe wrapper; document the local invariant and add a platform test.
- Identity generation uses the pinned official age-keygen sidecar, stages private material in owner-only storage, and never replaces an existing identity path.
- Tests generate private identities and plaintext canaries at runtime instead of storing them in tracked fixtures.
- Unchanged ciphertext and encrypted leaves are asserted byte-for-byte where stability is part of the contract.

## Tests

Run the host gate for the current platform:

```bash
./scripts/check-host.sh
```

Run the native Linux suite in Docker:

```bash
./scripts/check-linux.sh
```

On macOS, run both through the unified gate before requesting review:

```bash
./scripts/check-all.sh
```

The gates cover formatting, architecture boundaries, public documentation links, Clippy, unit and integration tests, dependency policy, release builds, and native archive validation. Integration tests use real Git and checksum-pinned SOPS and age-keygen executables. Initial cold runs download dependencies and build artifacts and may take substantially longer than warm runs.

GitHub Actions runs `scripts/check-host.sh` natively on Linux and macOS for every pull request and push to `main`. CI uses no repository secrets and does not publish artifacts or releases.

## Pull requests

A pull request should:

- Explain the behavior or invariant being changed.
- Include tests for each changed postcondition and relevant failure path.
- Update user documentation when installation, commands, output, configuration, security boundaries, or release layout changes.
- Contain no private identity, plaintext secret, local absolute path, generated build output, or unrelated formatting churn.
- Pass the applicable host and Linux quality gates.

By intentionally submitting a contribution for inclusion in Gitveil, you agree to license that contribution under the MIT License without additional terms or conditions.
