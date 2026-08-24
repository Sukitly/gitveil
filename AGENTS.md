# Contributor Instructions for Coding Agents

These instructions apply to the entire repository. Explicit user instructions for the current task take precedence.

## Start with the public contract

Before changing code, read the documents relevant to the task:

- [README.md](README.md) for product behavior, installation, and security boundaries.
- [CONTRIBUTING.md](CONTRIBUTING.md) for the development environment, tests, and pull request expectations.
- [SECURITY.md](SECURITY.md) for vulnerability reporting.
- [docs/getting-started.md](docs/getting-started.md) for the user-facing setup path.

Inspect the existing implementation and tests before proposing changes. Do not infer behavior from module names alone.

## Repository constraints

- Gitveil is one Rust 2024 package with a library and a thin binary.
- Supported production hosts are macOS and Linux.
- The Rust version is pinned in `rust-toolchain.toml`.
- Compatible SOPS and age-keygen builds and artifact checksums are declared in `scripts/sops_artifacts.py` and `scripts/age_artifacts.py`.
- `Cargo.toml` intentionally has `publish = false`; do not publish the crate or create releases unless explicitly requested.
- Keep all tracked text, code comments, tests, commit messages, and pull request content in English.
- Do not add private keys, plaintext secrets, local absolute paths, generated build output, unpublished planning material, or tool transcripts.
- Do not install software or modify system configuration on behalf of a maintainer unless explicitly requested. Report missing prerequisites instead.

## Architecture

Keep pure policy and transformation code separate from external effects.

- Pure domain modules and feature-local `plan` modules must not access the filesystem, processes, Git, SOPS, environment, network, clock, threads, or randomness.
- `scripts/check-architecture.py` is the executable declaration of modules that belong to the functional core. Add new pure modules to that declaration rather than bypassing the check.
- `src/source/` owns typed and lossless source parsing and rendering.
- `src/semantic/` owns pure semantic diff and merge behavior.
- `src/git/`, `src/sops/`, `src/age.rs`, and `src/runtime/` contain external adapters.
- Top-level feature modules such as `identity`, `configure`, `seal`, `open`, `status`, `verify`, and `resolve` orchestrate pure decisions and explicit effects.
- `src/main.rs` remains a thin CLI entry point; reusable behavior belongs in the library.

Choose the correct abstraction rather than the smallest diff. Do not duplicate policy in an orchestrator when it belongs in a pure model or plan.

## Security invariants

Treat these as product contracts:

- Secret values, private identities, data keys, and decrypted comments must not enter argv, Git metadata, logs, errors, reports, baselines, or tracked fixtures.
- Secret-bearing values must not gain `Debug` or `Display` implementations that can reveal their contents.
- Unknown Git or SOPS stderr is redacted by default. Preserve typed error categories instead of forwarding arbitrary subprocess output.
- SOPS and age-keygen subprocess arguments never contain secret values or private identity material.
- Git subprocesses use read-only plumbing. Gitveil never modifies the index, Git configuration, hooks, attributes, or Git state outside `.git/gitveil/`.
- Workspace paths are validated before descriptor-relative filesystem access. Symlink and submodule escapes must fail closed.
- Owner-only permissions are required for plaintext, generated identities, identity staging, runtime directories, temporary files, local IPC, and installed private sidecars where applicable.
- Production code must not use `unwrap` or `expect` for external input, filesystem, Git, SOPS, process, or protocol results.
- Do not add `unsafe` code. If a platform security API has no safe wrapper, obtain maintainer approval, document the local invariant, and add platform coverage first.
- Do not weaken a security assertion to accommodate nondeterministic fixture behavior. Isolate the external source of nondeterminism instead.

## Change workflow

1. Confirm the working tree state and preserve unrelated changes.
2. Describe the intended files, behavior, tests, and documentation impact before implementing a nontrivial change.
3. Work on a purpose-specific branch; never commit directly to `main`.
4. For core behavior, write or update the behavioral test at the appropriate level first and confirm that it fails for the expected reason.
5. Implement the complete user-facing path without placeholders, mock production backends, transition paths, broad catch-all errors, or disabled checks.
6. Refactor with the tests as a safety net.
7. Update affected public documentation in the same change.
8. Run the applicable quality gates once the complete change is assembled.

Do not discard an uncommitted working tree with `git checkout -- .`, `git restore .`, or equivalent destructive commands. Use a separate worktree when an old revision must be inspected.

## Testing

Match the test level to the contract:

- Keep pure decision tests colocated with their modules.
- Use contract tests for public domain behavior.
- Use real ephemeral repositories and real pinned SOPS and age-keygen executables for Git, SOPS, identity, filesystem, process, and runtime integration behavior.
- Inject failures only at external boundaries that cannot be triggered reliably; do not mock the semantic core.
- Generate unique age identities and plaintext canaries at test time. Never add a private identity or plaintext secret fixture.
- Assert unchanged ciphertext and encrypted leaves byte-for-byte where stability is part of the contract.
- Failure tests must assert both redacted output and absence of unintended side effects.
- Isolate `HOME`, global and system Git configuration, identity environment variables, and fixture state.
- Every child process needs a deadline and must be killed and reaped after a timeout.

Use targeted tests during development. Complete validation runs only in GitHub Actions:

- `Core` runs platform-independent library unit tests, pure `contract_*` binaries, formatting, architecture and documentation checks, Clippy, and dependency policy once on Ubuntu.
- `Linux` and `macOS` each run the complementary native host suite, release build, and package validation on a GitHub-hosted runner.
- `.config/nextest.toml` is the executable test classification. New `tests/*.rs` binaries default to the host suite unless deliberately named `contract_*`; colocated unit tests must remain pure unless their adapter module is explicitly assigned to the host profile.

Do not recreate aggregate local quality-gate scripts or Docker replicas of GitHub-hosted runners. Local commands are for targeted Red/Green feedback; the pull request checks are the complete merge gates.

Do not change test expectations merely to make a gate pass. Fix the implementation, fixture isolation, or contract.

## Documentation and dependency changes

- Update `README.md` when commands, configuration, installation, security boundaries, or release layout change.
- Update `docs/getting-started.md` when the first-use path changes.
- Update `CONTRIBUTING.md` when contributor tooling or quality gates change.
- Keep relative links in public Markdown valid; `scripts/check-docs.py` enforces them.
- Keep dependency changes intentional and locked. Explain why a new runtime dependency belongs at its architectural boundary.
- Preserve third-party license files and notices in release archives.

## Pull requests

Use English branch names, commits, pull request titles, and descriptions. Keep each pull request focused on one coherent change. The `main` ruleset requires:

- a pull request,
- linear history through squash merging,
- resolved review conversations,
- successful `Core`, `Linux`, and `macOS` checks,
- a branch tested against the latest `main`.

Before handing off a change, inspect the final diff, run `git diff --check`, confirm that no generated or secret-bearing files are tracked, and report the exact checks run and any checks that could not be run.
