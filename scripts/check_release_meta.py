#!/usr/bin/env python3
"""Release-boundary metadata gate.

Verifies the three release-hygiene invariants that only make sense at the
moment a release is cut (and would be noise on every dev push):

1. ``pyproject.toml`` ``version`` is a valid PEP 440 version.
2. When a tag is supplied (``--tag`` or ``$GITHUB_REF_NAME``), it is ``v<version>``
   and its version is PEP 440-equal to the pyproject version
   (so ``v0.4.0-beta`` == pyproject ``0.4.0b0``).
3. ``CHANGELOG.md`` carries a ``##`` heading for that version.

Run with no tag (locally, before tagging) it checks 1 + 3 only — i.e. "is this
working tree describing a coherent release". CI runs it on the tag with all three.

Exit 0 = release-ready, exit 1 = a hygiene invariant failed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

from packaging.version import InvalidVersion, Version

VERSION_RE = re.compile(r"(?m)^version\s*=\s*\"([^\"]+)\"")
HEADING_RE = re.compile(r"(?m)^##\s+(.*)$")
VERSION_TOKEN_RE = re.compile(r"v?\d+(?:\.\d+)*[A-Za-z0-9.\-+!]*")


def _die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_pyproject_version(text: str) -> str:
    match = VERSION_RE.search(text)
    if not match:
        _die("no 'version = \"...\"' line found in pyproject.toml")
    return match.group(1)  # type: ignore[union-attr]


def tag_version_matches(tag: str, version: str) -> bool:
    """True when ``tag`` is ``v<x>`` and ``<x>`` is PEP 440-equal to ``version``."""
    if not tag.startswith("v"):
        return False
    try:
        return Version(tag[1:]) == Version(version)
    except InvalidVersion:
        return False


def changelog_has_version(text: str, version: str) -> bool:
    """True when any ``##`` heading carries a version token equal to ``version``."""
    target = Version(version)
    for heading in HEADING_RE.findall(text):
        for token in VERSION_TOKEN_RE.findall(heading):
            candidate = token[1:] if token.startswith("v") else token
            try:
                if Version(candidate) == target:
                    return True
            except InvalidVersion:
                continue
    return False


def _resolve_tag(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    ref = os.environ.get("GITHUB_REF_NAME", "")
    # GITHUB_REF_NAME is the tag name on a tag push; ignore branch names.
    if ref.startswith("v") and VERSION_TOKEN_RE.fullmatch(ref):
        return ref
    return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=None, help="release tag (default: $GITHUB_REF_NAME if it looks like v<x>)")
    parser.add_argument("--repo-root", default=".", help="repository root holding pyproject.toml + CHANGELOG.md")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = Path(args.repo_root)

    pyproject = root / "pyproject.toml"
    changelog = root / "CHANGELOG.md"
    if not pyproject.is_file():
        _die(f"{pyproject} not found")
    if not changelog.is_file():
        _die(f"{changelog} not found")

    version = read_pyproject_version(pyproject.read_text(encoding="utf-8"))

    try:
        Version(version)
    except InvalidVersion:
        _die(f"pyproject version {version!r} is not a valid PEP 440 version")
    print(f"OK  version {version} is valid PEP 440")

    tag = _resolve_tag(args.tag)
    if tag is not None:
        if not tag_version_matches(tag, version):
            _die(f"tag {tag!r} does not match pyproject version {version!r} (expected v{version} or PEP 440-equal)")
        print(f"OK  tag {tag} matches pyproject version {version}")
    else:
        print("--  no tag supplied; skipping tag/version match")

    if not changelog_has_version(changelog.read_text(encoding="utf-8"), version):
        _die(f"CHANGELOG.md has no '##' heading for version {version}")
    print(f"OK  CHANGELOG.md has an entry for {version}")

    print("Release metadata is consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
