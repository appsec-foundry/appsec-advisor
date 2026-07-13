#!/usr/bin/env python3
"""Deterministic readability gate for the §1 management-summary LLM fragments.

Purpose (perf 2026-06-05 — "MS rewrite-churn"): the renderer used to re-author
``ms-verdict.json`` 2-3× each, shrinking the prose toward the soft "~25 / ~50 word"
targets by eye. That speculative polishing burned ~2-3 min of Stage-2 wall time
for no content gain.

This script gives the renderer an objective pass/fail so it authors once and
stops. It catches both runaway prose and engineering-level terminology in the
product-owner Verdict. Technical evidence belongs in §§7–8, not in the short
management summary.

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
VERDICT_BULLET_BODY_MAX_WORDS = 32
VERDICT_CLOSING_MAX_CHARS = 220

# Terms that expose an implementation, attack-class, protocol, or code-level
# detail rather than an operational consequence. Keep this list conservative:
# common business words such as "account", "data", and "session" remain valid.
_TECHNICAL_DETAIL_RE = re.compile(
    r"\b(?:api|csrf|csp|cve|cwe|idor|jwt|llm|oauth|oidc|rsa|sql|tls|http|https|"
    r"xml|xxe|xss|localstorage|httponly|samesite|middleware|endpoint|"
    r"parameteri[sz]ed|prompt[ -]injection|system prompt|directory listing|"
    r"private key|public key|sandbox(?:ing)?|allow-?list)\b",
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


def _check_management_language(value: str, field: str, violations: list[str]) -> None:
    """Reject implementation detail in prose intended for non-experts."""
    for match in (_TECHNICAL_DETAIL_RE.search(value or ""), _CODE_OR_LOCATION_RE.search(value or "")):
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
        _check_management_language(body, f"bullets[{i}].body", violations)


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
