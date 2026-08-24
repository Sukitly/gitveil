# Getting started

This guide starts by explicitly generating an age identity through Gitveil, then exercises `init`, `add`, `seal`, commit, clone, `open`, `status`, and `verify` in a temporary Git repository. Gitveil does not generate an identity during installation or without an explicit command.

## Prerequisites

- Install the complete Gitveil distribution as described in the [`README.md`](../README.md); do not use only `cargo install --path .`.
- Install Git 2.20+.

The complete distribution includes private, checksum-verified SOPS and age-keygen sidecars. Neither executable needs to be installed on the system `PATH`.

## Prepare an identity once

The following commands create a long-lived local identity at the standard SOPS location for the current platform and derive its public recipient:

```bash
gitveil identity generate
recipient="$(gitveil identity recipients)"
```

Generation creates every missing identity directory at mode `0700`, writes the identity at mode `0600`, and refuses to replace any existing path. Installation itself never creates an identity.

To select a custom location, set it before both commands and keep that setting for commands that need plaintext access:

```bash
export SOPS_AGE_KEY_FILE="$HOME/.config/sops/age/keys.txt"
gitveil identity generate
recipient="$(gitveil identity recipients)"
```

`recipient` is a public, committable `age1...` string. Both identity commands select one file using an explicit command option, then `SOPS_AGE_KEY_FILE`, then the platform default key file. `gitveil identity recipients` does not inspect `SOPS_AGE_KEY`, execute `SOPS_AGE_KEY_CMD`, or enumerate every identity source that SOPS may load.

`SOPS_AGE_KEY_FILE` contains only the path to the identity file. The private identity itself must never enter a repository, command argument, log, or chat system. Back it up securely outside the repository; plaintext cannot be recovered after every matching identity is lost. Gitveil redacts unknown sidecar stderr and reports fixed, classified diagnostics instead.

If generation warns that directory durability could not be confirmed, the identity has already been published and the command still prints its public recipient. Preserve the identity file rather than rerunning generation; use `gitveil identity recipients --identity <path>` if the recipient must be printed again.

A team should not share one private identity. Each member generates an independent identity and sends only the public recipient. Add multiple recipients to the same policy during initialization:

```bash
gitveil init \
  --policy team \
  --recipient age1alice... \
  --recipient age1bob...
```

Recipients in one policy provide OR authorization: any matching identity can decrypt. After initialization, membership changes only through the explicit authorization commands: `gitveil recipient add age1...` grants access and rewraps every affected ciphertext, and `gitveil recipient remove age1...` revokes access and rotates each file's data key. Each command converges only the recipients it names; editing `.gitveilrc.json` by hand grants nothing, and the remaining difference blocks `seal` until a recipient command names it. Removing or rotating a current recipient cannot revoke access to ciphertext already present in Git history.

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

The script uses `gitveil identity generate` with the pinned private age-keygen sidecar to create a temporary demo identity, isolates HOME and Git configuration, verifies recovery in the clone, and then removes the identity, plaintext, and both temporary repositories. It does not read or modify a long-lived identity and does not print the recipient, private identity, or demo plaintext. To inspect the generated source and clone repositories, explicitly keep a successful workspace:

```bash
./examples/quickstart.sh --keep-workspace
```

A retained workspace contains an ephemeral private identity and demo plaintext. Use it only for local inspection, then delete the entire path printed by the script. The quickstart script is not included in release archives, which contain the Gitveil binary, both private sidecars, and license files; archive users can follow the commands in this guide instead.

## Add Gitveil to an existing repository

- Prefer running `gitveil add` on a missing path so ignore protection exists before the secret is created.
- Existing untracked plaintext can be added directly; Gitveil validates the format, preserves the bytes, and tightens the mode to `0600`.
- Tracked or staged plaintext requires an explicit `git rm --cached -- PATH`. Rotate any credential that may have leaked, then run `gitveil verify` to inspect history.
- Commit `.gitveilrc.json`, `.gitignore`, and `*.gitveil`; never commit plaintext or a private identity.
- `gitveil status` and `gitveil verify` remain available without an identity.

See the [`README.md`](../README.md) for the complete command surface and security boundaries.
