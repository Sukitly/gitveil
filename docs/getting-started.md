# Getting started

This guide starts by generating an age identity outside Gitveil, then exercises `init`, `add`, `seal`, commit, clone, `open`, `status`, and `verify` in a temporary Git repository. Gitveil does not generate, store, or synchronize private identities.

## Prerequisites

- Install the complete Gitveil distribution as described in the [`README.md`](../README.md); do not use only `cargo install --path .`.
- Install Git 2.20+.
- Install [age](https://github.com/FiloSottile/age#installation), including `age-keygen`.

```bash
# macOS
brew install age

# Debian / Ubuntu
sudo apt install age

# Fedora
sudo dnf install age

# Arch Linux
sudo pacman -S age
```

If none of these package managers applies, install the binary for your platform from an official age release and verify its checksum. `age-keygen` is needed only to generate an identity and derive its public recipient; normal Gitveil operation does not depend on a system age executable.

## Prepare an identity once

The following commands create a long-lived local identity. Run them only when the destination does not already exist; never overwrite an existing identity:

```bash
umask 077
identity_file="$HOME/.config/sops/age/keys.txt"
mkdir -p "$(dirname "$identity_file")"
age-keygen -o "$identity_file"
chmod 600 "$identity_file"

export SOPS_AGE_KEY_FILE="$identity_file"
recipient="$(age-keygen -y "$SOPS_AGE_KEY_FILE")"
```

`recipient` is a public, committable `age1...` string. `SOPS_AGE_KEY_FILE` contains only the path to the identity file. The private identity itself must never enter a repository, command argument, log, or chat system.

For regular use, set the `SOPS_AGE_KEY_FILE` path in your shell configuration. Keep the identity file at mode `0600` and back it up securely outside the repository. Plaintext cannot be recovered after every matching identity is lost.

A team should not share one private identity. Each member generates an independent identity and sends only the public recipient. Add multiple recipients to the same policy during initialization:

```bash
gitveil init \
  --policy team \
  --recipient age1alice... \
  --recipient age1bob...
```

Recipients in one policy provide OR authorization: any matching identity can decrypt. Removing or rotating a current recipient cannot revoke access to ciphertext already present in Git history.

## Complete repository flow

This walkthrough uses a demo value. Do not put a real credential in shell history. `init` and `add` must run at the Git repository root.

```bash
quickstart_root="$(mktemp -d)"
mkdir "$quickstart_root/source"
cd "$quickstart_root/source"

git init -q
git symbolic-ref HEAD refs/heads/main
git config user.name "Gitveil Quickstart"
git config user.email "gitveil-quickstart@example.invalid"

gitveil init --policy team --recipient "$recipient"

# Register the missing path and verify ignore protection before creating plaintext.
gitveil add .env --format dotenv
umask 077
printf 'API_TOKEN=replace-with-a-demo-value\n' >.env

gitveil seal .env
git check-ignore -v .env
git status --short
```

`git check-ignore -v` should show the exact `.env` rule from Gitveil's managed block. `git status --short` should show only `.gitveilrc.json`, `.gitignore`, and `.env.gitveil`, not `.env`. Commit only public configuration and ciphertext:

```bash
git add .gitveilrc.json .gitignore .env.gitveil
git commit -m "Add encrypted environment"

gitveil status .env
gitveil verify && printf '%s\n' 'History verification passed.'
```

`status` should report `.env: clean`. On clean history, `verify` itself emits no output; the following success message demonstrates that its exit status was zero. Simulate another machine that has the same identity:

```bash
cd "$quickstart_root"
git clone source clone
cd clone

if [ -e .env ]; then
  printf '%s\n' 'Unexpected plaintext in clone' >&2
  exit 1
else
  printf '%s\n' 'Plaintext is absent before open.'
fi

gitveil open .env
cmp ../source/.env .env && printf '%s\n' 'Plaintext bytes match.'
ls -l .env
gitveil status .env
gitveil verify && printf '%s\n' 'History verification passed.'
```

After `cmp` succeeds, it prints the confirmation message. `ls -l .env` should begin with `-rw-------`, proving mode `0600`. After verification, leave the temporary directory and delete `quickstart_root`; do not delete the long-lived identity file.

## Executable quickstart

A source checkout includes an isolated, repeatable script that performs the same flow and prints real command output:

```bash
./examples/quickstart.sh
```

The script uses an external `age-keygen` to create a temporary demo identity, isolates HOME and Git configuration, verifies recovery in the clone, and then removes the identity, plaintext, and both temporary repositories. It does not read or modify a long-lived identity and does not print the recipient, private identity, or demo plaintext. To inspect the generated source and clone repositories, explicitly keep a successful workspace:

```bash
./examples/quickstart.sh --keep-workspace
```

A retained workspace contains an ephemeral private identity and demo plaintext. Use it only for local inspection, then delete the entire path printed by the script. The quickstart script is not included in release archives, which contain only the binary, private sidecar, and license files; archive users can follow the commands in this guide instead.

## Add Gitveil to an existing repository

- Prefer running `gitveil add` on a missing path so ignore protection exists before the secret is created.
- Existing untracked plaintext can be added directly; Gitveil validates the format, preserves the bytes, and tightens the mode to `0600`.
- Tracked or staged plaintext requires an explicit `git rm --cached -- PATH`. Rotate any credential that may have leaked, then run `gitveil verify` to inspect history.
- Commit `.gitveilrc.json`, `.gitignore`, and `*.gitveil`; never commit plaintext or a private identity.
- `gitveil status` and `gitveil verify` remain available without an identity.

See the [`README.md`](../README.md) for the complete command surface and security boundaries.
