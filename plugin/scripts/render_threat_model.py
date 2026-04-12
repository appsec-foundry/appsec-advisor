#!/usr/bin/env python3
"""
render_threat_model.py — deterministic template resolver for threat-model.md.

Reads a Markdown template containing include markers and replaces each marker
with the contents of the corresponding fragment file. The resolver does not
call an LLM — it is a pure string substitution + heading scan. It is intended
to be invoked from the orchestrator at the end of Phase 11, once all section
fragments have been written to the fragments directory.

Marker syntax supported in the template:

    {{include: <path>}}      required — abort if <path> is missing (strict mode)
    {{include?: <path>}}     optional — silently dropped if <path> is missing

Paths in markers are resolved relative to the --fragments-dir argument.
Nested includes are not resolved: if a fragment body contains another
{{include: ...}} marker, it is left as literal text and a warning is emitted.

CLI usage (typically from Phase 11 via Bash):

    python3 render_threat_model.py \\
      --template   <plugin>/templates/threat-model.template.md \\
      --fragments-dir <output>/fragments \\
      --output     <output>/threat-model.md

Exit codes:
    0 — rendered successfully
    1 — missing required fragment (strict mode)
    2 — template parse error or usage error
    3 — IO error
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Marker parsing
# ---------------------------------------------------------------------------

# Matches {{include: path}} and {{include?: path}}. Whitespace around the
# colon and inside the braces is tolerated; the path itself may not contain
# a closing brace.
_MARKER_RE = re.compile(r"\{\{\s*include(?P<opt>\?)?\s*:\s*(?P<path>[^}]+?)\s*\}\}")

# Catches any stray {{...}} marker that did not match the include form, so
# we can error instead of silently leaving it in the rendered output.
_ANY_MARKER_RE = re.compile(r"\{\{[^}]*\}\}")


class TemplateError(Exception):
    """Raised on malformed template markers."""


class MissingFragmentError(Exception):
    """Raised when a required fragment is missing in strict mode."""

    def __init__(self, missing: list[str]) -> None:
        super().__init__(f"missing required fragment(s): {', '.join(missing)}")
        self.missing = missing


# ---------------------------------------------------------------------------
# Core rendering
# ---------------------------------------------------------------------------

def _load_fragment(fragments_dir: Path, rel_path: str) -> str | None:
    """Read a fragment file; return None if it does not exist."""
    fragment_path = fragments_dir / rel_path
    if not fragment_path.is_file():
        return None
    return fragment_path.read_text(encoding="utf-8")


def _validate_template(template_text: str) -> None:
    """Reject templates containing malformed {{...}} markers.

    Any {{...}} sequence that does not match the include-marker grammar is a
    template author mistake — fail loudly instead of silently passing it
    through to the rendered output.
    """
    for match in _ANY_MARKER_RE.finditer(template_text):
        token = match.group(0)
        if not _MARKER_RE.fullmatch(token):
            raise TemplateError(
                f"unrecognised template marker: {token!r} "
                f"(expected '{{{{include: <path>}}}}' or '{{{{include?: <path>}}}}')"
            )


def render(
    template_text: str,
    fragments_dir: Path,
    *,
    strict: bool = True,
) -> tuple[str, list[str]]:
    """Render a template against a fragments directory.

    Returns (rendered_text, warnings). Raises TemplateError on malformed
    markers and MissingFragmentError when strict mode hits a missing
    required fragment.
    """
    _validate_template(template_text)

    warnings: list[str] = []
    missing_required: list[str] = []

    def _substitute(match: re.Match[str]) -> str:
        rel_path = match.group("path")
        optional = match.group("opt") == "?"
        body = _load_fragment(fragments_dir, rel_path)

        if body is None:
            if optional:
                return ""  # silently drop
            if strict:
                missing_required.append(rel_path)
                return match.group(0)  # leave marker in place; we abort below
            # lenient mode — insert a visible stub
            warnings.append(f"missing required fragment (lenient): {rel_path}")
            return (
                f"> ⚠ **Renderer:** Fragment `{rel_path}` was not written "
                f"during Phase 11. This section is empty.\n"
            )

        if _MARKER_RE.search(body):
            warnings.append(
                f"fragment {rel_path} contains a nested include marker; "
                f"nested includes are not resolved"
            )
        return body

    rendered = _MARKER_RE.sub(_substitute, template_text)

    if missing_required:
        raise MissingFragmentError(missing_required)

    return rendered, warnings


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="render_threat_model.py",
        description="Render threat-model.md from a template and section fragments.",
    )
    parser.add_argument("--template",      required=True, type=Path,
                        help="Path to the threat-model.template.md file.")
    parser.add_argument("--fragments-dir", required=True, type=Path,
                        help="Directory containing NN-*.md fragment files.")
    parser.add_argument("--output",        required=True, type=Path,
                        help="Path to write the rendered threat-model.md.")
    parser.add_argument("--lenient", action="store_true",
                        help="Do not abort on missing required fragments; "
                             "insert a visible stub instead.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    try:
        template_text = args.template.read_text(encoding="utf-8")
    except OSError as e:
        print(f"RENDER_FAILED: cannot read template: {e}", file=sys.stderr)
        return 3

    if not args.fragments_dir.is_dir():
        print(
            f"RENDER_FAILED: fragments directory not found: {args.fragments_dir}",
            file=sys.stderr,
        )
        return 3

    try:
        rendered, warnings = render(
            template_text,
            args.fragments_dir,
            strict=not args.lenient,
        )
    except TemplateError as e:
        print(f"RENDER_FAILED: {e}", file=sys.stderr)
        return 2
    except MissingFragmentError as e:
        for m in e.missing:
            print(f"RENDER_FAILED: missing required fragment: {m}", file=sys.stderr)
        return 1

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    except OSError as e:
        print(f"RENDER_FAILED: cannot write output: {e}", file=sys.stderr)
        return 3

    for w in warnings:
        print(f"RENDER_WARN: {w}", file=sys.stderr)

    n_fragments = len(list(args.fragments_dir.glob("*.md")))
    print(
        f"RENDERED: {args.output.name} "
        f"({n_fragments} fragments on disk, {len(warnings)} warnings)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
