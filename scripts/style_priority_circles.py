#!/usr/bin/env python3
"""Tint the mitigation rollout-priority circles (❶❷❸❹) with a gray ramp so the
URGENCY of a measure reads at a glance — darker = more urgent — on top of the
digit that already names the priority.

  ❶ P1 (ship now)  → #111111  (black)
  ❷ P2             → #555555  (dark gray)
  ❸ P3             → #888888  (medium gray)
  ❹ P4 (backlog)   → #bbbbbb  (light gray)

Why a final deliverable pass and NOT a change inside the renderers
------------------------------------------------------------------
The priority circle is emitted from FOUR inline sites in
``compose_threat_model.py`` AND re-validated by an idempotent annotation pass in
BOTH ``compose_threat_model.py`` (``_prepend_mitigation_prio_circles``) and
``qa_checks.py`` (``_M_REF_RE`` / autofix), every one of which pattern-matches
the BARE glyph immediately before ``[M-NNN]``. Wrapping the glyph in a color
span at the source would make those bare-glyph regexes miss the circle and
prepend a SECOND one (double circle). So the whole pipeline keeps emitting bare
circles and this pass runs LAST — after Stage 3 QA and its autofix have settled
— tinting only the delivered Markdown. The digit itself encodes the priority, so
the pass needs no model/context: ❶→P1 … ❹→P4.

Filled circles (U+2776–2779) are used ONLY for mitigation priority; the OUTLINE
circles ①②③④ (U+2460+) used for attack-path classes are a different code point
and are left untouched. Idempotent (a re-run re-wraps to the identical span, and
corrects a stale shade). Skips fenced code blocks. Exit 0 on success (incl.
no-op), 2 on read/write error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# User-specified gray ramp (2026-06-29). Keep in sync with the priority order in
# compose_threat_model.py::_PRIO_DIGIT_TBL (p1→❶ … p4→❹).
CIRCLE_COLOR = {"❶": "#111111", "❷": "#555555", "❸": "#888888", "❹": "#bbbbbb"}

# A priority circle — optionally already wrapped in a color span (idempotency /
# stale-shade correction) — followed by its separator and the M-NNN link.
_CIRCLE_RE = re.compile(
    r'(?:<span style="color:#[0-9a-fA-F]{3,6}">)?'  # optional existing color wrapper (open)
    r"(?P<g>[❶❷❸❹])"
    r"(?:</span>)?"  # optional existing color wrapper (close)
    r"(?P<sep>(?:\s|&nbsp;|•)*)"
    r"(?P<link>\[M-\d+\]\(#m-\d+\))"
)
_FENCE_RE = re.compile(r"^\s*(```|~~~)")


def _tint(m: re.Match[str]) -> str:
    g = m.group("g")
    color = CIRCLE_COLOR.get(g)
    if not color:
        return m.group(0)
    return f'<span style="color:{color}">{g}</span>{m.group("sep")}{m.group("link")}'


def style_circles(text: str) -> tuple[str, int]:
    """Return (rewritten_text, count). Fence-aware; only touches lines outside
    fenced code blocks."""
    lines = text.split("\n")
    fence: str | None = None
    count = 0
    for i, line in enumerate(lines):
        fm = _FENCE_RE.match(line)
        if fm:
            tok = fm.group(1)
            if fence is None:
                fence = tok
            elif fence == tok:
                fence = None
            continue
        if fence is not None:
            continue
        if "[M-" not in line:
            continue
        new, n = _CIRCLE_RE.subn(_tint, line)
        if n:
            count += n
            lines[i] = new
    return "\n".join(lines), count


def main() -> int:
    ap = argparse.ArgumentParser(description="Tint mitigation priority circles with a gray ramp in a composed threat-model.md.")
    ap.add_argument("md_path", help="path to threat-model.md (or a stamped copy)")
    ap.add_argument("--in-place", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    p = Path(args.md_path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        print(f"style_priority_circles: cannot read {p}: {e}", file=sys.stderr)
        return 2

    out, count = style_circles(text)

    if args.in_place:
        try:
            p.write_text(out, encoding="utf-8")
        except OSError as e:
            print(f"style_priority_circles: cannot write {p}: {e}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(out)

    if not args.quiet:
        print(f"style_priority_circles: {p.name} — {count} priority circle(s) tinted", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
