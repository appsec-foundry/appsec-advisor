#!/usr/bin/env python3
"""Deterministic compactness gate for the §1 management-summary LLM fragments.

Purpose (perf 2026-06-05 — "MS rewrite-churn"): the renderer used to re-author
``ms-verdict.json`` + ``ms-architecture-assessment.json`` 2-3× each, shrinking
the prose toward the soft "~25 / ~50 word" targets by eye. That speculative
polishing burned ~2-3 min of Stage-2 wall time for no content gain.

This script gives the renderer an OBJECTIVE pass/fail so it authors ONCE and
stops. The budgets below are calibrated to PASS well-formed output with margin
(they catch runaway prose, not good prose) — so a clean first write exits 0 and
the renderer moves on without a single rewrite.

Exit codes:
  0 — all present fragments within budget (or fragments absent — nothing to check)
  1 — at least one field over budget; stdout lists each offending field + count

Only the fields named in a violation should be re-authored. Do NOT rewrite a
field the validator did not flag.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# --- Budgets (hard fails). Calibrated against real juice-shop output with
# --- margin above the contract's soft targets so good prose never churns.
VERDICT_PROSE_MAX_WORDS = 28          # contract target ~25
WEAKNESS_DESC_MAX_WORDS = 55          # contract target ~50
WEAKNESS_DESC_MAX_SENTENCES = 3       # contract target 1-2
FRAMING_MAX_WORDS = 38                # one introducing sentence
VERDICT_OPENING_MAX_WORDS = 78        # generous — catches only runaway openings
VERDICT_BULLET_BODY_MAX_WORDS = 48    # per worst-case-scenario bullet


def _words(text: str) -> int:
    return len((text or "").split())


def _sentences(text: str) -> int:
    # Lenient: split on sentence-final punctuation followed by space/end.
    # Markdown bold markers and a trailing period are stripped first so a
    # field like "**Verdict — ... by design.**" counts as one sentence.
    cleaned = (text or "").replace("**", "").strip()
    parts = [p for p in re.split(r"[.!?]+(?:\s|$)", cleaned) if p.strip()]
    return max(1, len(parts))


def _check_verdict(path: Path, violations: list[str]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    opening = data.get("opening") or ""
    if _words(opening) > VERDICT_OPENING_MAX_WORDS:
        violations.append(
            f"ms-verdict.json: opening is {_words(opening)} words "
            f"(max {VERDICT_OPENING_MAX_WORDS})"
        )
    for i, b in enumerate(data.get("bullets") or []):
        if not isinstance(b, dict):
            continue
        body = b.get("body") or ""
        if _words(body) > VERDICT_BULLET_BODY_MAX_WORDS:
            violations.append(
                f"ms-verdict.json: bullets[{i}].body is {_words(body)} words "
                f"(max {VERDICT_BULLET_BODY_MAX_WORDS})"
            )


def _check_assessment(path: Path, violations: list[str]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    vp = data.get("verdict_prose") or ""
    if _words(vp) > VERDICT_PROSE_MAX_WORDS:
        violations.append(
            f"ms-architecture-assessment.json: verdict_prose is {_words(vp)} words "
            f"(max {VERDICT_PROSE_MAX_WORDS})"
        )
    framing = data.get("framing") or ""
    if _words(framing) > FRAMING_MAX_WORDS:
        violations.append(
            f"ms-architecture-assessment.json: framing is {_words(framing)} words "
            f"(max {FRAMING_MAX_WORDS})"
        )
    for w in data.get("weaknesses") or []:
        if not isinstance(w, dict):
            continue
        cat = (w.get("category") or "?")[:40]
        desc = w.get("description") or ""
        if _words(desc) > WEAKNESS_DESC_MAX_WORDS:
            violations.append(
                f"ms-architecture-assessment.json: weakness '{cat}' description is "
                f"{_words(desc)} words (max {WEAKNESS_DESC_MAX_WORDS})"
            )
        if _sentences(desc) > WEAKNESS_DESC_MAX_SENTENCES:
            violations.append(
                f"ms-architecture-assessment.json: weakness '{cat}' description has "
                f"{_sentences(desc)} sentences (max {WEAKNESS_DESC_MAX_SENTENCES})"
            )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output_dir", help="run output dir (contains .fragments/)")
    args = ap.parse_args()

    frag = Path(args.output_dir) / ".fragments"
    violations: list[str] = []

    checks = [
        (frag / "ms-verdict.json", _check_verdict),
        (frag / "ms-architecture-assessment.json", _check_assessment),
    ]
    for path, fn in checks:
        if not path.exists():
            continue
        try:
            fn(path, violations)
        except (json.JSONDecodeError, OSError) as e:
            # A malformed fragment is the composer's problem, not ours — do not
            # block the run on a parse error here.
            print(f"warn: could not read {path.name}: {e}", file=sys.stderr)

    if violations:
        print("MS compactness: FAIL — re-author ONLY these fields:")
        for v in violations:
            print(f"  - {v}")
        return 1

    print("MS compactness: PASS — fragments within budget, do not rewrite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
