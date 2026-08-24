# Contributing to Gitveil

Gitveil handles secret-bearing files and Git history, so changes must preserve its security boundaries as well as its user-visible behavior.

## Development environment

Required tools for source development:

- macOS or Linux
- Git 2.20+
- Rust 1.98.0, selected automatically by `rust-toolchain.toml`
- Python 3.9+

GitHub Actions installs the pinned `cargo-nextest` and `cargo-deny` versions used by the complete merge gates. Artifact helpers download checksum-pinned SOPS and age builds for the current platform into `target/`; they do not modify system installations.

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

Use targeted commands for local Red/Green feedback. Fetch only the current platform's pinned sidecars when the selected test needs them:

```bash
./scripts/fetch-test-sops.py
AGE_KEYGEN_BIN="$(./scripts/fetch-test-age-keygen.py)" \
  cargo test --test integration_identity
cargo test open::plan::tests::both_sides_changed_reports_a_conflict_and_keeps_local
```

Complete validation runs only in GitHub Actions. `.config/nextest.toml` defines two complementary suites:

| Check | Runner | Scope |
|---|---|---|
| `Core` | Ubuntu | Platform-independent unit and `contract_*` tests, formatting, architecture, documentation, Clippy, and dependency policy |
| `Linux` | Ubuntu | Native CLI, Git, SOPS, identity, filesystem, runtime, release build, and package validation |
| `macOS` | macOS | The same native host suite on macOS |

Every pull request and push to `main` runs all three checks on GitHub-hosted runners. The merge-gate workflow uses no repository secrets and never publishes releases. Release-related pull requests additionally exercise the four-target native archive workflow without requesting attestation or publication permissions. Exact version tags run the trusted attestation and draft-release jobs described in [`docs/releasing.md`](docs/releasing.md). Do not add aggregate local gate scripts or a Docker replica of the hosted Linux runner.

## Pull requests

A pull request should:

- Explain the behavior or invariant being changed.
- Include tests for each changed postcondition and relevant failure path.
- Update user documentation when installation, commands, output, configuration, security boundaries, or release layout changes.
- Contain no private identity, plaintext secret, local absolute path, generated build output, or unrelated formatting churn.
- Pass the required `Core`, `Linux`, and `macOS` GitHub Actions checks.

By intentionally submitting a contribution for inclusion in Gitveil, you agree to license that contribution under the MIT License without additional terms or conditions.
