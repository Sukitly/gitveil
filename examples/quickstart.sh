#!/bin/sh
set -eu

GITVEIL_BIN=${GITVEIL_BIN:-gitveil}
PLAINTEXT_CANARY=gitveil-quickstart-secret-canary
KEEP_WORKSPACE=0
COMPLETED=0

fail() {
    printf '%s\n' "Gitveil quickstart failed: $1" >&2
    exit 1
}

usage() {
    printf '%s\n' "Usage: $0 [--keep-workspace]" >&2
    exit 2
}

case "$#" in
    0) ;;
    1)
        [ "$1" = "--keep-workspace" ] || usage
        KEEP_WORKSPACE=1
        ;;
    *) usage ;;
esac

for dependency in git age-keygen mktemp cmp stat uname; do
    command -v "$dependency" >/dev/null 2>&1 || fail "$dependency is required"
done
command -v "$GITVEIL_BIN" >/dev/null 2>&1 || fail "gitveil is required"

WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/gitveil-quickstart.XXXXXX") || fail "temporary workspace creation failed"
chmod 700 "$WORK_ROOT"
cleanup() {
    if [ "$COMPLETED" -eq 1 ] && [ "$KEEP_WORKSPACE" -eq 1 ]; then
        printf '%s\n' "Workspace retained at $WORK_ROOT"
        printf '%s\n' "It contains an ephemeral identity and demo plaintext; remove it after inspection."
    else
        rm -rf "$WORK_ROOT"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

HOME_DIR=$WORK_ROOT/home
SOURCE_REPOSITORY=$WORK_ROOT/source
CLONED_REPOSITORY=$WORK_ROOT/clone
IDENTITY_FILE=$WORK_ROOT/identity.txt
AGE_KEYGEN_STDERR=$WORK_ROOT/age-keygen.stderr
GIT_LS_FILES_STDERR=$WORK_ROOT/git-ls-files.stderr
mkdir -p "$HOME_DIR/xdg" "$SOURCE_REPOSITORY"
: >"$HOME_DIR/gitconfig"

export HOME=$HOME_DIR
export XDG_CONFIG_HOME=$HOME_DIR/xdg
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=$HOME_DIR/gitconfig
unset SOPS_AGE_KEY SOPS_AGE_KEY_FILE SOPS_AGE_KEY_CMD

step() {
    printf '\n==> %s\n' "$1"
}

ignore_state() {
    if git check-ignore -q -- "$1"; then
        return 0
    else
        status=$?
    fi
    if [ "$status" -eq 1 ]; then
        return 1
    fi
    fail "git check-ignore failed"
}

require_ignored() {
    if ignore_state "$1"; then
        return
    fi
    fail "expected path is not ignored"
}

require_visible() {
    if ignore_state "$1"; then
        fail "expected path is unexpectedly ignored"
    fi
}

tracked_state() {
    if git ls-files --error-unmatch -- "$1" >/dev/null 2>"$GIT_LS_FILES_STDERR"; then
        rm -f "$GIT_LS_FILES_STDERR"
        return 0
    else
        status=$?
    fi
    if [ "$status" -eq 1 ]; then
        rm -f "$GIT_LS_FILES_STDERR"
        return 1
    fi
    cat "$GIT_LS_FILES_STDERR" >&2
    rm -f "$GIT_LS_FILES_STDERR"
    fail "git ls-files failed"
}

require_tracked() {
    if tracked_state "$1"; then
        return
    fi
    fail "expected path is not tracked"
}

require_untracked() {
    if tracked_state "$1"; then
        fail "plaintext entered the Git index"
    fi
}

compare_plaintext() {
    if cmp "$1" "$2"; then
        return
    else
        status=$?
    fi
    if [ "$status" -eq 1 ]; then
        fail "opened plaintext does not match the source"
    fi
    fail "plaintext comparison failed"
}

step "Generating an ephemeral age identity"
if age-keygen -o "$IDENTITY_FILE" >/dev/null 2>"$AGE_KEYGEN_STDERR"; then
    rm -f "$AGE_KEYGEN_STDERR"
else
    status=$?
    cat "$AGE_KEYGEN_STDERR" >&2
    exit "$status"
fi
chmod 600 "$IDENTITY_FILE"
if RECIPIENT=$(age-keygen -y "$IDENTITY_FILE" 2>"$AGE_KEYGEN_STDERR"); then
    rm -f "$AGE_KEYGEN_STDERR"
else
    status=$?
    cat "$AGE_KEYGEN_STDERR" >&2
    exit "$status"
fi
[ -n "$RECIPIENT" ] || fail "public recipient derivation returned no recipient"
export SOPS_AGE_KEY_FILE=$IDENTITY_FILE

step "Initializing the source repository"
cd "$SOURCE_REPOSITORY"
git init -q || fail "git init failed"
git symbolic-ref HEAD refs/heads/main || fail "git symbolic-ref failed"
git config user.name "Gitveil Quickstart" || fail "git config failed"
git config user.email "gitveil-quickstart@example.invalid" || fail "git config failed"
"$GITVEIL_BIN" init --policy team --recipient "$RECIPIENT" || fail "gitveil init failed"

step "Registering the plaintext path before creating it"
"$GITVEIL_BIN" add .env --format dotenv || fail "gitveil add failed"
umask 077
printf 'API_TOKEN=%s\n' "$PLAINTEXT_CANARY" >.env

step "Sealing and committing ciphertext"
"$GITVEIL_BIN" seal .env || fail "gitveil seal failed"
require_ignored .env
require_visible .env.gitveil
git check-ignore -v -- .env
git add .gitveilrc.json .gitignore .env.gitveil || fail "git add failed"
require_untracked .env
git commit -m "Add encrypted quickstart secret" || fail "git commit failed"

step "Cloning and reopening the managed plaintext"
git clone -q "$SOURCE_REPOSITORY" "$CLONED_REPOSITORY" || fail "git clone failed"
cd "$CLONED_REPOSITORY"
[ ! -e .env ] || fail "plaintext was present in the clone"
require_tracked .env.gitveil
require_ignored .env
"$GITVEIL_BIN" open .env || fail "gitveil open failed"
compare_plaintext "$SOURCE_REPOSITORY/.env" .env
printf '%s\n' "Plaintext bytes match the source."

case "$(uname -s)" in
    Darwin)
        MODE=$(stat -f '%Lp' .env)
        ;;
    Linux)
        MODE=$(stat -c '%a' .env)
        ;;
    *)
        fail "unsupported platform"
        ;;
esac
[ "$MODE" = "600" ] || fail "opened plaintext is not mode 0600"
printf '%s\n' "Opened plaintext mode is 0600."

step "Checking repository state and history"
"$GITVEIL_BIN" status .env || fail "gitveil status failed"
"$GITVEIL_BIN" verify || fail "gitveil verify failed"
printf '%s\n' "History verification passed."

COMPLETED=1
printf '\n%s\n' "Gitveil quickstart completed successfully."
