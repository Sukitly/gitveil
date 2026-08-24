# Gitveil

[![CI](https://github.com/Sukitly/gitveil/actions/workflows/ci.yml/badge.svg)](https://github.com/Sukitly/gitveil/actions/workflows/ci.yml)

Gitveil provides file-level encryption for dotenv, JSON, YAML, and TOML secret files. Plaintext files are excluded through `.gitignore`; each adjacent `<name>.gitveil` file is an ordinary tracked file containing a standard SOPS YAML envelope. Gitveil does not install Git filters, hooks, or drivers, and it does not write Git configuration or the index.

## Requirements

- macOS or Linux
- Git 2.20+ for `verify` and `resolve`
- A matching age identity on machines that need plaintext access

Gitveil does not require a system SOPS or age executable. Release archives include checksum-verified official SOPS 3.13.3 and age-keygen 1.3.1 sidecars under `libexec/gitveil/`; Gitveil does not search for either tool on the system `PATH`.

## Installation

Install from a source checkout for the current user:

```bash
./scripts/install-local.py
```

The default prefix is `${CARGO_HOME:-$HOME/.cargo}`. To select another prefix:

```bash
./scripts/install-local.py --prefix ~/.local
```

The installer performs a locked release build, fetches and verifies official SOPS 3.13.3 and age-keygen 1.3.1 artifacts, validates the complete release archive, and transactionally installs the binary, private sidecars, and license files. Do not use `cargo install --path .`: Cargo installs only the binary and omits the private sidecars.

The user-facing installation unit is a native release archive. Maintainers build one on each target platform with:

```bash
python3 scripts/package-release.py
```

The archive is written to `dist/gitveil-v<version>-<os>-<arch>.tar.gz` with this layout:

```text
bin/gitveil
libexec/gitveil/sops
libexec/gitveil/age-keygen
share/licenses/gitveil/LICENSE
share/licenses/gitveil/SOPS-MPL-2.0.txt
share/licenses/gitveil/SOPS-NOTICE.txt
share/licenses/gitveil/AGE-BSD-3-Clause.txt
share/licenses/gitveil/AGE-NOTICE.txt
```

Install all three top-level directories under the same prefix and place `<prefix>/bin` on `PATH`. Gitveil never downloads executables at runtime.

Source development and tests may explicitly override the private sidecars with `SOPS_BIN` and `AGE_KEYGEN_BIN`; each override must still have its pinned version. These variables are not part of the user installation contract.

## Initial setup

Generate a private identity explicitly after installation. The command selects `SOPS_AGE_KEY_FILE` when set, then the standard SOPS identity file for the current platform, creates every missing identity directory at mode `0700`, writes the identity at mode `0600`, and never replaces an existing path:

```bash
gitveil identity generate
recipient="$(gitveil identity recipients)"
```

If a native age identity file already exists at the selected location, skip `generate` and use `gitveil identity recipients` to derive its public value. Both commands select one file using an explicit command option, then `SOPS_AGE_KEY_FILE`, then the platform default key file. `recipients` does not inspect `SOPS_AGE_KEY`, execute `SOPS_AGE_KEY_CMD`, or enumerate every identity source that SOPS may load. To use a custom location, select it consistently for generation and subsequent commands:

```bash
export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/keys.txt"
gitveil identity generate
recipient="$(gitveil identity recipients)"
```

After the identity has been atomically published, a directory-sync failure is reported as a warning rather than a generation failure: the command still prints the published path and recipient and exits successfully, but durability across an immediate system crash was not confirmed. Preserve the identity file; `gitveil identity recipients --identity <path>` can print its recipient again.

`init` and `add` must run at a Git repository root containing a `.git` file or directory. `init` accepts only public `age1...` recipients, never private identities:

```bash
gitveil init --policy team --recipient "$recipient"
```

From a source checkout, run the isolated end-to-end example to exercise Gitveil-managed identity generation, `init`, `add`, `seal`, commit, clone, `open`, `status`, and `verify` with real command output:

```bash
./examples/quickstart.sh
# Keep the successful workspace for inspection. It contains a demo identity
# and plaintext, so delete the entire workspace when finished.
./examples/quickstart.sh --keep-workspace
```

`examples/` is not included in native release archives. Archive users can follow the equivalent commands in this README.

Register a path and establish the verified `.gitignore` boundary before creating plaintext, avoiding an unprotected window:

```bash
gitveil add packages/service/.env.dev --format dotenv --profile dev
install -m 600 /dev/null packages/service/.env.dev
$EDITOR packages/service/.env.dev
gitveil verify
gitveil seal packages/service/.env.dev
gitveil status packages/service/.env.dev
```

Existing plaintext that is not tracked by Git can be registered directly. Gitveil validates its source format, preserves its bytes, and tightens its mode to `0600`. The seal next action printed by `add` includes only plaintext files that already exist; create a predeclared missing path before sealing it:

```bash
gitveil add .env --format dotenv
```

Tracked or staged plaintext is rejected because `.gitignore` cannot protect an index entry. Run `git rm --cached -- PATH` explicitly, rotate any secret that may have leaked, and use `gitveil verify` to inspect history. Gitveil never modifies the index or stages files automatically.

The repository-root `.gitveilrc.json` is the sole authority for managed paths, formats, profiles, and recipient policies. `init` creates one policy and an empty file list; `add` appends entries using typed canonical JSON. The default profile is `default`. Multiple recipients in one policy provide OR authorization, and different files may reference different policies. Gitveil ignores repository `.sops.yaml` files.

`add` maintains one managed block at the end of `.gitignore`. It creates an exact plaintext ignore and ciphertext re-include for every managed pair, then asks Git to verify their effective visibility:

```gitignore
# BEGIN gitveil managed files
/packages/service/.env.dev
!/packages/service/.env.dev.gitveil
# END gitveil managed files
```

If an ignored parent directory prevents Git from re-including only the ciphertext, `add` fails without widening repository visibility. One error reports all affected paths and each effective rule as `source:line:pattern`. Concurrent configuration changes do not overwrite external manifest or `.gitignore` writes; Gitveil may retain an extra fail-safe ignore and require a retry. Commit `.gitveilrc.json`, `.gitignore`, and ciphertext companions. Never commit plaintext or an age private identity.

Gitveil does not currently provide a managed-entry removal command. Manually removing a manifest entry may leave a fail-safe extra ignore; a later `add` rebuilds the block. First-class removal and projection reconciliation remain future work.

## Identity management

Gitveil generates native age identities only when `gitveil identity generate` is explicitly invoked. It does not overwrite, synchronize, distribute, back up, or automatically rotate them. Keep identity files at mode `0600`, back them up securely outside the repository, and have each team member generate an independent identity. Exchange only public recipients, never private keys. The repository stores only public `age1...` recipients. `status` and `verify` remain available without an identity. To add a member, add the member's public recipient to the manifest policy and run `gitveil seal` to rewrap access.

To remove a member, first rotate the actual secret values in plaintext, remove the member's recipient from the manifest policy, and run `gitveil seal`. When Gitveil detects a recipient removal, it encrypts the entire file under a fresh data key and reports `sealed; data key rotated`; neither the new values nor the new key are decryptable by the removed identity. Addition-only changes keep the existing data key and preserve encrypted leaf bytes.

## Daily usage

```bash
# Plaintext to adjacent ciphertext: create, incrementally edit, or align recipients
gitveil seal
gitveil seal --profile dev

# Ciphertext to plaintext: merge by key against the local baseline
gitveil open
gitveil open --profile dev

# Inspect data/layout drift, recipient drift, and conflicts without a private key
gitveil status
gitveil status --profile prod

# Read-only scan for plaintext leaks and invalid ciphertext in Git history
gitveil verify
gitveil verify --range origin/main..HEAD

# Semantically merge ciphertext conflicts from Git index stages 1, 2, and 3
gitveil resolve
```

`seal` preserves encrypted bytes for unchanged keys and preserves the entire ciphertext byte-for-byte when plaintext semantics, layout, and recipients are unchanged. After a recipient-policy change, `status` reports recipient drift. Addition-only changes use SOPS `updatekeys` to rewrap the same data key without re-encrypting data or layout leaves. Any removal creates a fresh data key and re-encrypts the entire file so removed identities cannot decrypt later versions.

`open` does not overwrite an entire existing plaintext file. Ciphertext-only changes synchronize automatically, plaintext-only changes remain local, and concurrent changes to the same key keep the local value and report a conflict. The baseline at `.git/gitveil/state/` contains only salted digests; when it is missing, Gitveil uses a conservative merge mode.

`open`, `seal`, and `status` accept `--profile <name>`. A profile can be combined with explicit paths, but every path must belong to that profile or the command fails before any file operation. Unknown profiles also fail, preventing misspellings from producing an empty success. Files outside the selected profile remain unchanged.

## Merge conflicts

Git treats `*.gitveil` as ordinary files. After a textual conflict, run:

```bash
gitveil resolve
```

Changes to different keys merge automatically. A same-key conflict writes plaintext conflict markers. Resolve the plaintext, then run:

```bash
gitveil seal
git add <path>.gitveil
git commit
```

Gitveil reads index stages but never runs `git add`.

## Security boundaries

- Secret values, private identities, and decrypted comments never enter argv, Git configuration, errors, reports, baselines, or tracked metadata.
- Source keys, hierarchy, scalar types, recipients, and approximate ciphertext lengths are public metadata.
- Gitveil enforces SOPS `encrypted_regex: .*`; every source scalar and layout/comment value is encrypted.
- Each ciphertext file uses one data key. Removing a recipient causes `seal` and `resolve` to rotate that key, preventing the removed identity from decrypting later versions. Access to historical versions cannot be revoked; forward exclusion also requires rotating the actual secret values.
- Paths undergo workspace-relative validation and descriptor-relative confinement; symlink and submodule escapes are rejected.
- SOPS and age-keygen subprocesses have deadlines. Unknown sidecar stderr is redacted and converted into fixed, typed diagnostics rather than being forwarded verbatim.
- Temporary files and IPC endpoints live in owner-only runtime directories.
- Gitveil writes no Git-internal state outside `.git/gitveil/` and never modifies the index, configuration, hooks, or attributes. Only root-level `init` and `add` write repository configuration; `add` owns and verifies the managed `.gitignore` block.

## Development

```bash
./scripts/check-host.sh
./scripts/check-linux.sh
./scripts/check-all.sh
```

The unified local quality gate covers the macOS host, Docker Linux, real SOPS compatibility, release archive structure, and native release builds. GitHub Actions runs the native host gate on Linux and macOS for every pull request and push to `main`.

## License

Gitveil source code is available under the [MIT License](LICENSE). The official SOPS executable bundled in native release archives is distributed under the [Mozilla Public License 2.0](licenses/SOPS-MPL-2.0.txt); its version and source location are recorded in the [SOPS notice](licenses/SOPS-NOTICE.txt). The bundled official age-keygen executable is distributed under the [BSD 3-Clause License](licenses/AGE-BSD-3-Clause.txt); its version and source location are recorded in the [age notice](licenses/AGE-NOTICE.txt).
