#!/usr/bin/env python3
"""Validate and safely normalize ``.threat-modeling-context.md``.

The context document is Markdown, but its ordered top-level headings and
untrusted-data fences are an inter-stage API. The context resolver runs this
validator before completion and the controller runs the same contract at the
post-recon boundary.

``--repair-missing-headings`` inserts only absent level-2 contract headings,
with an explicit neutral placeholder, at their canonical position. It never
reorders authored sections or repairs malformed fences.
"""

from __future__ import annotations

import argparse
import re
import sys
from functools import cache
from pathlib import Path

from _atomic_io import atomic_write_text

CONTRACT = "threat-modeling-context-markdown-v1"
MAX_BYTES = 262_144
_TEMPLATE_MARKER = "```markdown\n# Threat Modeling Context\n"
_FENCE_RE = re.compile(r"</?untrusted-data(?:\s+source=\"[^\"\n]{1,200}\")?>")
_MISSING_SECTION_TEXT = "No context was emitted for this section."


class ThreatModelingContextValidationError(ValueError):
    """Raised when the context document violates its Markdown contract."""


def _default_template_path() -> Path:
    return Path(__file__).resolve().parent.parent / "agents" / "appsec-context-resolver.md"


@cache
def required_headings(template_path: Path | None = None) -> tuple[str, ...]:
    """Return ordered headings from the context resolver's output template."""
    path = (template_path or _default_template_path()).resolve()
    try:
        template = path.read_text(encoding="utf-8")
        tail = template.split(_TEMPLATE_MARKER, 1)[1]
        fenced = "# Threat Modeling Context\n" + tail.split("\n```", 1)[0]
    except (OSError, UnicodeDecodeError, IndexError) as exc:
        raise ThreatModelingContextValidationError(f"cannot load {CONTRACT} template: {exc}") from exc
    headings = tuple(line for line in fenced.splitlines() if re.match(r"^#{1,2} ", line))
    if not headings or headings[0] != "# Threat Modeling Context":
        raise ThreatModelingContextValidationError(f"{CONTRACT} template has no canonical root heading")
    return headings


def _validate_fences(text: str) -> None:
    tokens = _FENCE_RE.findall(text)
    if len(tokens) < 2 or len(tokens) != text.count("<untrusted-data") + text.count("</untrusted-data>"):
        raise ThreatModelingContextValidationError(f"{CONTRACT} has malformed untrusted-data fences")
    depth = 0
    for token in tokens:
        depth += -1 if token.startswith("</") else 1
        if depth not in {0, 1}:
            raise ThreatModelingContextValidationError(f"{CONTRACT} has nested or unbalanced fences")
    if depth:
        raise ThreatModelingContextValidationError(f"{CONTRACT} has nested or unbalanced fences")


def _contract_heading_positions(text: str, required: tuple[str, ...]) -> dict[str, int]:
    """Return canonical heading positions, ignoring repository text in fences."""
    required_set = set(required)
    positions: dict[str, int] = {}
    depth = 0
    for line_number, line in enumerate(text.splitlines()):
        tokens = _FENCE_RE.findall(line)
        if not depth and line in required_set:
            if line in positions:
                raise ThreatModelingContextValidationError(f"{CONTRACT} contains duplicate heading {line!r}")
            positions[line] = line_number
        for token in tokens:
            depth += -1 if token.startswith("</") else 1
    return positions


def _missing_or_reordered(required: tuple[str, ...], positions: dict[str, int]) -> tuple[str, ...]:
    present = [(index, positions[heading]) for index, heading in enumerate(required) if heading in positions]
    if any(left[1] >= right[1] for left, right in zip(present, present[1:])):
        raise ThreatModelingContextValidationError(f"{CONTRACT} reorders required headings")
    return tuple(heading for heading in required if heading not in positions)


def _load(path: Path, *, max_bytes: int) -> tuple[bytes, str]:
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ThreatModelingContextValidationError(f"cannot read {CONTRACT} artifact {path}: {exc}") from exc
    if len(payload) > max_bytes:
        raise ThreatModelingContextValidationError(f"{CONTRACT} exceeds the {max_bytes}-byte cap")
    return payload, text


def validate_threat_modeling_context(
    path: Path,
    *,
    template_path: Path | None = None,
    max_bytes: int = MAX_BYTES,
) -> None:
    """Validate the context document without mutating it."""
    _payload, text = _load(path, max_bytes=max_bytes)
    _validate_fences(text)
    required = required_headings(template_path)
    positions = _contract_heading_positions(text, required)
    missing = _missing_or_reordered(required, positions)
    if missing:
        raise ThreatModelingContextValidationError(f"{CONTRACT} is missing heading {missing[0]!r}")


def repair_missing_headings(
    path: Path,
    *,
    template_path: Path | None = None,
    max_bytes: int = MAX_BYTES,
) -> tuple[str, ...]:
    """Insert missing level-2 headings without changing authored sections."""
    _payload, text = _load(path, max_bytes=max_bytes)
    _validate_fences(text)
    required = required_headings(template_path)
    positions = _contract_heading_positions(text, required)
    missing = _missing_or_reordered(required, positions)
    if not missing:
        return ()
    if required[0] in missing:
        raise ThreatModelingContextValidationError(f"{CONTRACT} is missing root heading {required[0]!r}")

    lines = text.splitlines()
    insertions: dict[int, list[str]] = {}
    for heading in missing:
        canonical_index = required.index(heading)
        next_position = next(
            (positions[candidate] for candidate in required[canonical_index + 1 :] if candidate in positions),
            len(lines),
        )
        insertions.setdefault(next_position, []).append(heading)

    repaired: list[str] = []
    for line_number in range(len(lines) + 1):
        for heading in insertions.get(line_number, []):
            if repaired and repaired[-1] != "":
                repaired.append("")
            repaired.extend((heading, "", _MISSING_SECTION_TEXT, ""))
        if line_number < len(lines):
            repaired.append(lines[line_number])
    rendered = "\n".join(repaired).rstrip() + "\n"
    if len(rendered.encode("utf-8")) > max_bytes:
        raise ThreatModelingContextValidationError(f"{CONTRACT} exceeds the {max_bytes}-byte cap after repair")
    atomic_write_text(path, rendered)
    validate_threat_modeling_context(path, template_path=template_path, max_bytes=max_bytes)
    return missing


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("context", type=Path, help="Path to .threat-modeling-context.md")
    parser.add_argument("--template", type=Path, help="Override the canonical template (tests only)")
    parser.add_argument(
        "--repair-missing-headings",
        action="store_true",
        help="Insert missing level-2 contract headings before validation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        repaired = (
            repair_missing_headings(args.context, template_path=args.template) if args.repair_missing_headings else ()
        )
        validate_threat_modeling_context(args.context, template_path=args.template)
    except ThreatModelingContextValidationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    if repaired:
        print(f"REPAIRED: {CONTRACT} inserted {', '.join(repaired)}")
    print(f"VALID: {CONTRACT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
