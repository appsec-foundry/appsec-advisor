#!/usr/bin/env python3
"""Lint a rendered threat-model.md for reference-link format consistency.

Every reference to a finding (F-NNN), threat (T-NNN), or mitigation (M-NNN) must
use exactly one of two forms (see compose_threat_model.linkify_with_label):

  * Full:  ``<glyph> [ID](#id) — <label> (`file:line`)``  (locator optional, but
           when present it MUST be fully backticked)
  * Short: ``<glyph> [ID](#id)``                          (ID only, still linked)

This linter flags the deviations the producer historically shipped:

  A. ID inside the link text:        ``[F-NNN — title](#f-nnn)``
  B. Un-backticked parens locator:   ``[F-NNN](#f-nnn) — title (routes/x.ts:9)``
  C. Em-dash locator after a ref:    ``[F-NNN](#f-nnn) — title — routes/x.ts:9``

It is REFERENCE-ADJACENT: it only inspects the text immediately after an
``[ID](#anchor)`` link, so prose file mentions, URLs, and code spans elsewhere
are never false-positives.

Usage: check_reference_format.py <rendered.md> [...]
Exit 0 = clean, 1 = violations found (printed to stderr).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_EXT = r"(?:ts|tsx|js|jsx|mjs|cjs|yml|yaml|html|json|java|py|rb|go|php|sh|sql|xml|env)"
_LOC = r"[\w./\\-]+\." + _EXT + r"(?::\d+(?:-\d+)?)?"

# A link whose visible text is more than a bare ID (carries a separator/title).
_ID_IN_LINK = re.compile(r"\[([FTM]-\d+)\s*[—–-][^\]]*\]\(#[ftm]-\d+\)")
# A reference link, capturing the trailing segment up to a cell/line boundary.
_REF = re.compile(r"\[([FTM]-\d+)\]\(#[ftm]-\d+\)([^\n|]*?)(?=$|\n|\||<br/?>|\[)", re.M)
# Un-backticked parens locator and em-dash locator inside that trailing segment.
_PAREN_LOC = re.compile(r"\((?!`)(" + _LOC + r")\)")
_EMDASH_LOC = re.compile(r"—\s*(?!`)(" + _LOC + r")")

# A `**Reference:** <value>` line (§9 mitigation cards). The value must be a
# titled Markdown link `[title](url)` — never a bare `CWE-NNN` (unlinked) or a
# naked URL (untitled). compose._normalize_reference is the producer.
_BARE_REF_CWE = re.compile(r"^\*\*Reference:\*\*\s+(CWE-\d+)\s*$", re.M)
_BARE_REF_URL = re.compile(r"^\*\*Reference:\*\*\s+(?!\[)(https?://\S+)\s*$", re.M)


def lint_text(md: str) -> list[str]:
    """Return a list of human-readable violation messages ("" → clean)."""
    out: list[str] = []
    for m in _ID_IN_LINK.finditer(md):
        out.append(f"ID inside link text: {m.group(0)!r}")
    for m in _REF.finditer(md):
        ref, seg = m.group(1), m.group(2)
        for pm in _PAREN_LOC.finditer(seg):
            out.append(f"{ref}: un-backticked locator '({pm.group(1)})' — must be (`{pm.group(1)}`)")
        for em in _EMDASH_LOC.finditer(seg):
            out.append(f"{ref}: em-dash locator '— {em.group(1)}' — locator belongs in backticked parens")
    for m in _BARE_REF_CWE.finditer(md):
        out.append(f"bare CWE reference '{m.group(1)}' — must be a titled link [{m.group(1)}: <title>](url)")
    for m in _BARE_REF_URL.finditer(md):
        out.append(f"untitled URL reference '{m.group(1)}' — must be a titled link [<title>](url)")
    return out


def main(argv: list[str]) -> int:
    if not argv:
        sys.stderr.write("usage: check_reference_format.py <rendered.md> [...]\n")
        return 2
    total = 0
    for p in argv:
        violations = lint_text(Path(p).read_text(encoding="utf-8"))
        if violations:
            total += len(violations)
            sys.stderr.write(f"\n{p}: {len(violations)} reference-format violation(s)\n")
            for v in violations[:50]:
                sys.stderr.write(f"  - {v}\n")
            if len(violations) > 50:
                sys.stderr.write(f"  … and {len(violations) - 50} more\n")
    if total:
        sys.stderr.write(f"\nTOTAL: {total} violation(s)\n")
        return 1
    print("reference-format: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
