#!/usr/bin/env python3
"""Release-blocker scan over `.qa-status.json` `manual_review_items`.

The skill's Re-Render Loop short-circuits to the manual-review banner when
`.qa-repair-plan.json.status == "manual_review"`. That short-circuit is
correct for cosmetic items (checker false-positives) but unsafe for
defects that make the rendered model unfit for release — e.g. a
`mitigation_title`/`addresses` schema drift that produces `(untitled)`
Mitigation Register headings and empty Mitigation columns across every
Management Summary table.

This helper inspects `.qa-status.json` and exits:

    0 — no release-blocker matched (cosmetic items only; safe to ship)
    2 — at least one release-blocker matched (skill MUST abort the run)
    1 — input file missing or unreadable (caller decides)

Patterns are matched case-insensitively against each entry's combined
``issue`` + ``description`` text. The list is deliberately curated — every
new pattern blocks otherwise-shipping runs, so additions are a conscious
trade-off.

Usage:
    python3 qa_release_gate.py <path-to-.qa-status.json>

Output is one JSON object per call so the caller (skill / CI) can parse
it without screen-scraping. Stderr carries the same info in human form.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Patterns: case-insensitive substring match. Keep this list small — every
# entry is a release-blocker class. Adding one stops production runs.
RELEASE_BLOCKER_PATTERNS = (
    "untitled",                  # `(untitled)` Mitigation Register headings
    "(untitled)",
    "orphan",                    # orphan T-NNN / M-NNN cross-reference
    "broken anchor",             # broken-anchor diagnostics
    "mitigation column empty",   # MS Mitigations table empty cells
    "title fields missing",
    "linked but no title",       # bare `[X-NNN](#x-nnn)` without label
    "no title",                  # generic "no title" / "missing title"
    "missing title",
)


def scan(path: Path) -> tuple[int, dict]:
    """Return (exit_code, json_payload)."""
    if not path.is_file():
        return 1, {"status": "missing", "path": str(path)}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return 1, {"status": "unreadable", "path": str(path), "error": str(e)}

    items = data.get("manual_review_items") or []
    blockers: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        haystack = " ".join(str(item.get(k, "")) for k in ("issue", "description")).lower()
        for pat in RELEASE_BLOCKER_PATTERNS:
            if pat.lower() in haystack:
                blockers.append({
                    "issue": item.get("issue", ""),
                    "description": item.get("description", ""),
                    "matched_pattern": pat,
                })
                break  # one match per item is enough to flag it

    payload = {
        "status": "blocked" if blockers else "ok",
        "items_total": len(items),
        "blockers_count": len(blockers),
        "blockers": blockers,
        "patterns": list(RELEASE_BLOCKER_PATTERNS),
    }
    return (2 if blockers else 0), payload


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <path-to-.qa-status.json>", file=sys.stderr)
        return 1
    rc, payload = scan(Path(argv[1]))
    print(json.dumps(payload, indent=2))
    if payload.get("blockers"):
        print(
            f"\nRELEASE-BLOCKER: {payload['blockers_count']} of "
            f"{payload['items_total']} manual-review item(s) match the "
            f"release-blocker allowlist. Skill MUST abort.",
            file=sys.stderr,
        )
        for b in payload["blockers"]:
            print(f"  - [{b['matched_pattern']}] {b['issue']}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
