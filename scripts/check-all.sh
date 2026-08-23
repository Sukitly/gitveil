#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ "$(uname -s)" != "Darwin" ]; then
    echo "The combined macOS/Linux quality gate must run on a macOS host" >&2
    exit 2
fi

"$ROOT/scripts/check-host.sh"
"$ROOT/scripts/check-linux.sh"
