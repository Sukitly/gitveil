#!/usr/bin/env python3
"""Reject external-effect dependencies from declared functional-core modules."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PURE_FILES = [
    "src/config.rs",
    "src/path.rs",
    "src/profile.rs",
    "src/recipient.rs",
    "src/envelope.rs",
    "src/source/document.rs",
    "src/source/dotenv.rs",
    "src/source/json.rs",
    "src/source/mod.rs",
    "src/source/strict.rs",
    "src/source/toml.rs",
    "src/source/yaml.rs",
    "src/semantic/diff.rs",
    "src/semantic/merge.rs",
    "src/semantic/mod.rs",
    "src/manifest.rs",
    "src/configure/plan.rs",
    "src/baseline/record.rs",
    "src/seal/plan.rs",
    "src/open/plan.rs",
    "src/resolve/plan.rs",
    "src/verify/policy.rs",
    "src/sops/classify.rs",
]
FORBIDDEN = {
    r"\bcrate::git\b": "Git adapter",
    r"\bcrate::sops\b": "SOPS adapter",
    r"\bcrate::runtime\b": "runtime adapter",
    r"\bcrate::\s*\{[^}]*\bgit\b": "Git adapter",
    r"\bcrate::\s*\{[^}]*\bsops\b": "SOPS adapter",
    r"\bcrate::\s*\{[^}]*\bruntime\b": "runtime adapter",
    r"\bstd::fs\b": "filesystem",
    r"\bstd::process\b": "process",
    r"\bstd::env\b": "environment",
    r"\bstd::net\b": "network",
    r"\bstd::time\b": "clock",
    r"\bstd::thread\b": "thread",
    r"\bstd::\s*\{[^}]*\b(?:fs|process|env|net|time|thread)\b": "external state",
    r"\brand::": "random source",
    r"\brustix\b": "platform syscall",
    r"\btempfile\b": "filesystem",
    r"\binterprocess\b": "local IPC",
    r"\bwait_timeout\b": "process",
}

errors: list[str] = []
for relative in PURE_FILES:
    path = ROOT / relative
    if not path.is_file():
        errors.append(f"declared pure module is missing: {relative}")
        continue
    content = path.read_text(encoding="utf-8")
    for pattern, boundary in FORBIDDEN.items():
        for match in re.finditer(pattern, content, flags=re.DOTALL):
            line = content.count("\n", 0, match.start()) + 1
            errors.append(f"{relative}:{line} depends on forbidden {boundary} boundary")

if errors:
    print(f"Functional-core dependency check failed with {len(errors)} issue(s):", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    sys.exit(1)

print(f"Functional-core dependency check passed for {len(PURE_FILES)} modules.")
