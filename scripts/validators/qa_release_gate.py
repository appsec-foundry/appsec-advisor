#!/usr/bin/env python3
"""Stage-3 release decision over the QA state next to `.qa-status.json`.

The QA gate classifies every repair-plan action as blocking, cosmetic or
manual review (`qa_checks._action_severity`, backed by
`BLOCKING_ACTION_TYPES`). A blocking action that is still in the plan when the
release gate runs has no writable fragment left to repair it: its producer is
deterministic code. Releasing it as "manual review" let a report pass Stage 3
and then fail the completion gate on the same defect, so this gate refuses:

1. any blocking action in `.qa-repair-plan.json`;
2. any blocking final-structure issue in `threat-model.md`, using the same
   function as the completion gate (`qa_checks.final_structure_reports`);
3. any reviewer `manual_review_items` entry whose `action_type` is blocking;
4. any reviewer entry whose `issue`/`description` text matches a curated
   pattern — a backstop for entries that carry no structured type.

Exit codes:

    0 — no release blocker; safe to ship
    2 — at least one release blocker (skill MUST abort the run)
    1 — `.qa-status.json` missing or unreadable (caller decides)

Usage:
    python3 validators/qa_release_gate.py <path-to-.qa-status.json>

Output is one JSON object per call so the caller (skill / CI) can parse
it without screen-scraping. Stderr carries the same info in human form.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import json
import sys
from pathlib import Path

from validators.qa_checks import _action_severity, final_structure_reports

# Patterns: case-insensitive substring match over reviewer prose. Keep this
# list small — every entry is a release-blocker class. Adding one stops
# production runs.
RELEASE_BLOCKER_PATTERNS = (
    "untitled",  # `(untitled)` Mitigation Register headings
    "(untitled)",
    "orphan",  # orphan T-NNN / M-NNN cross-reference
    "broken anchor",  # broken-anchor diagnostics
    "mitigation column empty",  # MS Mitigations table empty cells
    "title fields missing",
    "linked but no title",  # bare `[X-NNN](#x-nnn)` without label
    "no title",  # generic "no title" / "missing title"
    "missing title",
)

_ISSUE_EXCERPT = 300


def _plan_blockers(output_dir: Path) -> list[dict]:
    path = output_dir / ".qa-repair-plan.json"
    if not path.is_file():
        return []
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [{"source": "repair_plan", "type": "unreadable", "issue": f"{path.name}: {exc}"}]
    actions = plan.get("actions") if isinstance(plan, dict) else None
    blockers = []
    for action in actions if isinstance(actions, list) else []:
        if not isinstance(action, dict):
            continue
        action_type = str(action.get("type") or "unclassified")
        if _action_severity(action_type) != "blocking":
            continue
        blockers.append(
            {
                "source": "repair_plan",
                "type": action_type,
                "issue": str(action.get("raw_issue") or "")[:_ISSUE_EXCERPT],
                "fragments_to_rewrite": list(action.get("fragments_to_rewrite") or []),
                "unresolved_issues": list(action.get("unresolved_issues") or []),
            }
        )
    return blockers


def _structure_blockers(output_dir: Path) -> list[dict]:
    # Stage 3 and the editorial pass only call this gate once the report
    # exists; a missing report is their own blocking precondition.
    md_path = output_dir / "threat-model.md"
    if not md_path.is_file():
        return []
    reports, blocking = final_structure_reports(md_path)
    if not blocking:
        return []
    issues = [issue for report in reports.values() for issue in report.get("issues", [])]
    return [
        {
            "source": "final_structure",
            "type": "final_structure",
            "issue": f"{blocking} blocking structural issue(s) the completion gate rejects",
            "issues": issues[:25],
        }
    ]


def _reviewer_blockers(items: list) -> list[dict]:
    blockers = []
    for item in items:
        if not isinstance(item, dict):
            continue
        action_type = item.get("action_type") or item.get("type")
        if isinstance(action_type, str) and action_type and _action_severity(action_type) == "blocking":
            blockers.append({"source": "manual_review_item", "type": action_type, "issue": str(item.get("issue", ""))})
            continue
        haystack = " ".join(str(item.get(k, "")) for k in ("issue", "description")).lower()
        for pat in RELEASE_BLOCKER_PATTERNS:
            if pat.lower() in haystack:
                blockers.append(
                    {
                        "source": "manual_review_item",
                        "issue": item.get("issue", ""),
                        "description": item.get("description", ""),
                        "matched_pattern": pat,
                    }
                )
                break  # one match per item is enough to flag it
    return blockers


def scan(path: Path) -> tuple[int, dict]:
    """Return (exit_code, json_payload)."""
    if not path.is_file():
        return 1, {"status": "missing", "path": str(path)}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return 1, {"status": "unreadable", "path": str(path), "error": str(e)}

    items = data.get("manual_review_items") or []
    output_dir = path.parent
    blockers = _plan_blockers(output_dir) + _structure_blockers(output_dir) + _reviewer_blockers(items)

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
            f"\nRELEASE-BLOCKER: {payload['blockers_count']} blocker(s) — the report is not "
            f"releasable. Skill MUST abort.",
            file=sys.stderr,
        )
        for b in payload["blockers"]:
            label = b.get("matched_pattern") or b.get("type") or b.get("source")
            print(f"  - [{label}] {b['issue']}", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
