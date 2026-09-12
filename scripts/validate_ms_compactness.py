#!/usr/bin/env python3
"""Deterministic readability gate for the §1 management-summary LLM fragments.

Purpose (perf 2026-06-05 — "MS rewrite-churn"): the renderer used to re-author
``ms-verdict.json`` 2-3× each, shrinking the prose toward the soft "~25 / ~50 word"
targets by eye. That speculative polishing burned ~2-3 min of Stage-2 wall time
for no content gain.

This script gives the renderer an objective pass/fail so it authors once and
stops. It catches both runaway prose and engineering-level terminology in the
product-owner Verdict. A bullet body may name the weakness class (SQL injection,
XSS); opening, titles and closing state outcomes only. Technology identifiers,
code and locations belong in §§7–8, never in the short management summary.

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

# --- Management-summary hard limits. These are intentionally tighter than the
# --- JSON schema: the schema preserves the shape, while this gate protects the
# --- product-owner reading level and concise worst-case scenarios.
VERDICT_OPENING_MAX_WORDS = 52
# A bullet body names the weakness class in plain words, optionally with its
# standard term in parentheses ("database query injection (SQL injection)").
# That costs 4-6 words over an outcome-only sentence, so the authoring contract
# targets 20 words and 26 stays a runaway catcher above that target rather than
# a second authoring rule. At the former 20-word cap, runs produced bodies that
# named no weakness at all and read as vague to the engineers who act on them.
VERDICT_BULLET_BODY_MAX_WORDS = 26
VERDICT_CLOSING_MAX_CHARS = 220

# Technology and implementation identifiers: nobody in the verdict's audience
# can act on them, so every field rejects them. Keep this list conservative:
# common business words such as "account", "data", and "session" remain valid.
# `xml` stays allowed only as the first word of the class "XML external entity".
_TECHNICAL_DETAIL_RE = re.compile(
    r"\b(?:api|csp|cve|cwe|jwt|llm|oauth|oidc|rsa|tls|http|https|"
    r"xml(?!\s+external\s+entit)|localstorage|httponly|samesite|middleware|endpoint|"
    r"parameteri[sz]ed|sandbox(?:ing)?|allow-?list)\b",
    re.IGNORECASE,
)
# Weakness-class names and the plain names of what a class exposes. A bullet
# body names the class so an engineer can map the scenario to its finding;
# opening, titles and closing state outcomes only and keep rejecting them.
# `llm` is a technology, not a weakness, and stays in the list above.
_ATTACK_CLASS_RE = re.compile(
    r"\b(?:csrf|idor|sql|xss|xxe|prompt[ -]injection|system prompt|directory listing|"
    r"private key|public key)\b",
    re.IGNORECASE,
)
_CODE_OR_LOCATION_RE = re.compile(
    r"`|\b[\w./-]+\.(?:c|cs|go|java|js|json|jsx|py|rb|rs|sh|ts|tsx|yaml|yml)(?::\d+)?\b|"
    r"\b(?:routes|src|lib|server)\/",
    re.IGNORECASE,
)


def _words(text: str) -> int:
    return len((text or "").split())


def _sentences(text: str) -> int:
    # Lenient: split on sentence-final punctuation followed by space/end.
    # Markdown bold markers and a trailing period are stripped first so a
    # field like "**Verdict — ... by design.**" counts as one sentence.
    cleaned = (text or "").replace("**", "").strip()
    parts = [p for p in re.split(r"[.!?]+(?:\s|$)", cleaned) if p.strip()]
    return max(1, len(parts))


def _check_management_language(value: str, field: str, violations: list[str], *, body: bool = False) -> None:
    """Reject implementation detail in prose intended for non-experts.

    A bullet body may name the weakness class; every other field states outcomes only.
    """
    patterns = [_TECHNICAL_DETAIL_RE, _CODE_OR_LOCATION_RE] + ([] if body else [_ATTACK_CLASS_RE])
    for pattern in patterns:
        match = pattern.search(value or "")
        if match:
            violations.append(f"ms-verdict.json: {field} contains technical detail {match.group(0)!r}")
            return


def _check_verdict(path: Path, violations: list[str]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    opening = data.get("opening") or ""
    if _words(opening) > VERDICT_OPENING_MAX_WORDS:
        violations.append(f"ms-verdict.json: opening is {_words(opening)} words (max {VERDICT_OPENING_MAX_WORDS})")
    _check_management_language(opening, "opening", violations)
    closing = data.get("closing") or ""
    if len(closing) > VERDICT_CLOSING_MAX_CHARS:
        violations.append(f"ms-verdict.json: closing is {len(closing)} chars (max {VERDICT_CLOSING_MAX_CHARS})")
    _check_management_language(closing, "closing", violations)
    for i, b in enumerate(data.get("bullets") or []):
        if not isinstance(b, dict):
            continue
        _check_management_language(b.get("title") or "", f"bullets[{i}].title", violations)
        body = b.get("body") or ""
        if _words(body) > VERDICT_BULLET_BODY_MAX_WORDS:
            violations.append(
                f"ms-verdict.json: bullets[{i}].body is {_words(body)} words (max {VERDICT_BULLET_BODY_MAX_WORDS})"
            )
        if _sentences(body) > 1:
            violations.append(f"ms-verdict.json: bullets[{i}].body has {_sentences(body)} sentences (max 1)")
        _check_management_language(body, f"bullets[{i}].body", violations, body=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output_dir", help="run output dir (contains .fragments/)")
    args = ap.parse_args()

    frag = Path(args.output_dir) / ".fragments"
    violations: list[str] = []

    checks = [
        (frag / "ms-verdict.json", _check_verdict),
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
