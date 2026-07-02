#!/usr/bin/env python3
"""Release-boundary metadata gate.

Verifies the release-hygiene invariants that only make sense at the
moment a release is cut (and would be noise on every dev push):

1. ``pyproject.toml`` and ``.claude-plugin/plugin.json`` carry PEP 440-equal
   release versions; the plugin analysis compatibility declaration is valid.
2. ``CHANGELOG.md`` has no pending release notes under ``Unreleased`` and has
   a dated heading matching the release version.
3. When a tag is supplied (``--tag`` or ``$GITHUB_REF_NAME``), it is ``v<version>``
   and its version is PEP 440-equal to the pyproject version
   (so ``v0.4.0-beta`` == pyproject ``0.4.0b0``).

Run with no tag (locally, before tagging) it checks 1 + 2 only — i.e. "is this
working tree describing a coherent release". CI runs it on the tag with all three.

Exit 0 = release-ready, exit 1 = a hygiene invariant failed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import date
from pathlib import Path

from packaging.version import InvalidVersion, Version

VERSION_RE = re.compile(r"(?m)^version\s*=\s*\"([^\"]+)\"")
HEADING_RE = re.compile(r"(?m)^##\s+(.*)$")
VERSION_TOKEN_RE = re.compile(r"v?\d+(?:\.\d+)*[A-Za-z0-9.\-+!]*")
RELEASE_DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
UNRELEASED_RE = re.compile(
    r"(?ms)^##\s+Unreleased[^\n]*\n(?P<body>.*?)(?=^##\s+|\Z)",
    re.IGNORECASE,
)


def _die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_pyproject_version(text: str) -> str:
    match = VERSION_RE.search(text)
    if not match:
        _die("no 'version = \"...\"' line found in pyproject.toml")
    return match.group(1)  # type: ignore[union-attr]


def read_plugin_manifest(text: str) -> dict:
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as exc:
        _die(f".claude-plugin/plugin.json is invalid JSON: {exc}")
    if not isinstance(manifest, dict):
        _die(".claude-plugin/plugin.json root must be an object")
    return manifest


def tag_version_matches(tag: str, version: str) -> bool:
    """True when ``tag`` is ``v<x>`` and ``<x>`` is PEP 440-equal to ``version``."""
    if not tag.startswith("v"):
        return False
    try:
        return Version(tag[1:]) == Version(version)
    except InvalidVersion:
        return False


def changelog_release_heading(text: str, version: str) -> str | None:
    """Return the dated release heading matching ``version``, if present."""
    target = Version(version)
    for heading in HEADING_RE.findall(text):
        has_valid_date = False
        for token in RELEASE_DATE_RE.findall(heading):
            try:
                date.fromisoformat(token)
            except ValueError:
                continue
            has_valid_date = True
            break
        for token in VERSION_TOKEN_RE.findall(heading):
            candidate = token[1:] if token.startswith("v") else token
            try:
                matches = Version(candidate) == target
            except InvalidVersion:
                continue
            if matches and has_valid_date:
                return heading
    return None


def changelog_has_version(text: str, version: str) -> bool:
    """True when a dated ``##`` heading carries a token equal to ``version``."""
    return changelog_release_heading(text, version) is not None


def changelog_unreleased_has_content(text: str) -> bool:
    """Return True when ``## Unreleased`` still contains release-note content."""
    match = UNRELEASED_RE.search(text)
    if not match:
        return False
    body = re.sub(r"<!--.*?-->", "", match.group("body"), flags=re.DOTALL)
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped == "---" or re.match(r"^#{3,6}\s+", stripped):
            continue
        return True
    return False


def _validate_plugin_manifest(manifest: dict, pyproject_version: str) -> None:
    plugin_version = manifest.get("version")
    if not isinstance(plugin_version, str) or not plugin_version:
        _die(".claude-plugin/plugin.json version must be a non-empty string")
    try:
        versions_match = Version(plugin_version) == Version(pyproject_version)
    except InvalidVersion:
        _die(f"plugin manifest version {plugin_version!r} is not a valid PEP 440 version")
    if not versions_match:
        _die(f"plugin manifest version {plugin_version!r} does not match pyproject version {pyproject_version!r}")

    analysis_version = manifest.get("analysis_version")
    compatible = manifest.get("compatible_analysis_versions")
    if not isinstance(analysis_version, int) or isinstance(analysis_version, bool) or analysis_version < 1:
        _die("plugin manifest analysis_version must be an integer >= 1")
    if (
        not isinstance(compatible, list)
        or not compatible
        or any(not isinstance(item, int) or isinstance(item, bool) or item < 1 for item in compatible)
    ):
        _die("plugin manifest compatible_analysis_versions must be a non-empty list of positive integers")
    if len(set(compatible)) != len(compatible):
        _die("plugin manifest compatible_analysis_versions contains duplicates")
    if compatible != sorted(compatible):
        _die("plugin manifest compatible_analysis_versions must be sorted")
    if analysis_version not in compatible:
        _die("plugin manifest compatible_analysis_versions must include the current analysis_version")

    print(f"OK  plugin manifest version {plugin_version} matches pyproject")
    print(f"OK  analysis_version={analysis_version} is self-compatible within {compatible}")


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
    plugin_manifest = root / ".claude-plugin" / "plugin.json"
    if not pyproject.is_file():
        _die(f"{pyproject} not found")
    if not changelog.is_file():
        _die(f"{changelog} not found")
    if not plugin_manifest.is_file():
        _die(f"{plugin_manifest} not found")

    version = read_pyproject_version(pyproject.read_text(encoding="utf-8"))

    try:
        parsed_version = Version(version)
    except InvalidVersion:
        _die(f"pyproject version {version!r} is not a valid PEP 440 version")
    if parsed_version.is_devrelease:
        _die(f"pyproject version {version!r} is a development version, not a release")
    print(f"OK  version {version} is valid PEP 440")

    manifest = read_plugin_manifest(plugin_manifest.read_text(encoding="utf-8"))
    _validate_plugin_manifest(manifest, version)

    changelog_text = changelog.read_text(encoding="utf-8")
    if not UNRELEASED_RE.search(changelog_text):
        _die("CHANGELOG.md has no '## Unreleased' heading")
    if changelog_unreleased_has_content(changelog_text):
        _die("CHANGELOG.md still has content under '## Unreleased'; promote it into the release heading")
    if not changelog_has_version(changelog_text, version):
        _die(f"CHANGELOG.md has no dated '##' heading for version {version}")
    print(f"OK  CHANGELOG.md has a dated entry for {version}")

    tag = _resolve_tag(args.tag)
    if tag is not None:
        if not tag_version_matches(tag, version):
            _die(f"tag {tag!r} does not match pyproject version {version!r} (expected v{version} or PEP 440-equal)")
        print(f"OK  tag {tag} matches pyproject version {version}")
    else:
        print("--  no tag supplied; skipping tag/version match")

    print("Release metadata is consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
