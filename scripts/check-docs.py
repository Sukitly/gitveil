#!/usr/bin/env python3
"""Validate relative links in Gitveil's public Markdown documentation."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
errors: list[str] = []


def strip_html_comments(content: str) -> str:
    """Remove HTML comment blocks from Markdown before extracting links."""
    return re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)


def extract_relative_links(content: str) -> list[str]:
    """Extract relative Markdown links, excluding URLs, email links, and anchors."""
    links = []
    for match in re.finditer(r"\[[^\]]*\]\(([^)]+)\)", strip_html_comments(content)):
        link = match.group(1)
        if link.startswith(("http://", "https://", "mailto:", "#")):
            continue
        link = link.split("#", 1)[0].split("?", 1)[0]
        if link:
            links.append(link)
    return links


def relative(path: Path) -> str:
    """Render a path relative to the repository root when possible."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def check_links(file_path: Path) -> None:
    """Record every relative Markdown link whose target does not exist."""
    content = file_path.read_text(encoding="utf-8")
    for link in extract_relative_links(content):
        resolved = (file_path.parent / link).resolve()
        if not resolved.exists():
            errors.append(
                f'{relative(file_path)}: "{link}" points to missing {relative(resolved)}'
            )


markdown_files = sorted(ROOT.glob("docs/**/*.md"))
for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
    path = ROOT / name
    if path.exists():
        markdown_files.append(path)

print(f"Checking relative links in {len(markdown_files)} public Markdown files...")
for markdown_file in markdown_files:
    check_links(markdown_file)

if errors:
    print(f"Found {len(errors)} documentation issue(s):", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    raise SystemExit(1)

print("All public documentation links are valid.")
