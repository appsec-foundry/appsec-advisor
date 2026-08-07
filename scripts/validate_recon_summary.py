#!/usr/bin/env python3
"""Validate the bounded Markdown contract for ``.recon-summary.md``.

The recon summary is Markdown rather than JSON, but its numbered headings are
an inter-stage API.  The recon producer runs this validator before publishing
its companion signal artifact, and the orchestration controller runs the same
validator again at the post-recon boundary.
"""

from __future__ import annotations

import argparse
import sys
from functools import cache
from pathlib import Path

CONTRACT = "recon-summary-markdown-v1"
MAX_BYTES = 262_144
MAX_LINES = 1_000
_TEMPLATE_MARKER = "````markdown"


class ReconSummaryValidationError(ValueError):
    """Raised when a recon summary violates its Markdown contract."""


def _default_template_path() -> Path:
    return Path(__file__).resolve().parent.parent / "agents" / "shared" / "recon-output-template.md"


@cache
def required_headings(template_path: Path | None = None) -> tuple[str, ...]:
    """Return the ordered headings from the canonical fenced template."""
    path = (template_path or _default_template_path()).resolve()
    try:
        template = path.read_text(encoding="utf-8")
        fenced = template.split(_TEMPLATE_MARKER, 1)[1].split("````", 1)[0]
    except (OSError, UnicodeDecodeError, IndexError) as exc:
        raise ReconSummaryValidationError(f"cannot load {CONTRACT} template: {exc}") from exc
    headings = tuple(line for line in fenced.splitlines() if line.startswith("#"))
    if not headings:
        raise ReconSummaryValidationError(f"{CONTRACT} template has no headings")
    return headings


def _missing_heading_message(heading: str) -> str:
    if heading.startswith("### 7."):
        section = heading.split(maxsplit=1)[1].split(maxsplit=1)[0]
        return f"{CONTRACT} is missing or reorders security section {section} (expected {heading!r})"
    return f"{CONTRACT} is missing or reorders heading {heading!r}"


def validate_recon_summary(
    path: Path,
    *,
    template_path: Path | None = None,
    max_bytes: int = MAX_BYTES,
    max_lines: int = MAX_LINES,
) -> int:
    """Validate *path* and return its line count on success."""
    try:
        payload = path.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReconSummaryValidationError(f"cannot read {CONTRACT} artifact {path}: {exc}") from exc
    if len(payload) > max_bytes:
        raise ReconSummaryValidationError(f"{CONTRACT} exceeds the {max_bytes}-byte cap")
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise ReconSummaryValidationError(f"{CONTRACT} exceeds the {max_lines}-line cap")

    headings = [line for line in lines if line.startswith("#")]
    cursor = 0
    for required in required_headings(template_path):
        try:
            cursor = headings.index(required, cursor) + 1
        except ValueError as exc:
            raise ReconSummaryValidationError(_missing_heading_message(required)) from exc
    return len(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path, help="Path to .recon-summary.md")
    parser.add_argument("--template", type=Path, help="Override the canonical template (tests only)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        line_count = validate_recon_summary(args.summary, template_path=args.template)
    except ReconSummaryValidationError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"VALID: {CONTRACT} ({line_count} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
