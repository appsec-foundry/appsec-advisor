#!/usr/bin/env python3
"""
apply_repair_plan.py — deterministic applier for mechanical action types
in `.qa-repair-plan.json` (the contract-violation plan emitted by
`qa_checks.py build_repair_plan`).

Background. Before this script existed, every non-empty `.qa-repair-plan.json`
caused the skill's Re-Render Loop to dispatch the heavy `appsec-threat-analyst`
agent (sonnet, ~125 KB system prompt, ~16 min per iteration). For mechanical
defects like `toc_nested_link` — where the composer emits
`[Walkthrough [§3.9](#39-f-008-xss)](#39-f-008-xss)` (outer and inner link
pointing at the same anchor) — that LLM round trip is pure waste: the fix is
a one-line regex substitution.

This applier handles the deterministic subset of action types and exits with
a clear signal so the skill can skip the LLM dispatch when nothing semantic
remains. Non-mechanical action types are passed through unchanged for the
existing REPAIR_MODE Stage-1 dispatch to handle.

Supported action types (mechanical):
  * toc_nested_link — strip the inner `[label](#anchor)` from any
    `[<prefix>[<label>](#x)<suffix>](#y)` pattern. Both #x == #y and
    #x != #y are handled (the inner link is always redundant since the
    outer link is what the renderer actually navigates).

Unsupported action types (non-mechanical — semantic reasoning required):
  * control_subsection_coverage, walkthrough_coverage, walkthrough_depth,
    relevant_findings_bullet_list, recon_iam_bridge, auth_method_decomposition,
    chain_compactness, chain_tid_consistency, diagram_compactness,
    mermaid_syntax, infobox_incomplete, missing_required_subsection,
    required_subsection_order_drift, …

  When any unsupported action is present in the plan, this script applies
  every supported action it can, then exits `1` so the skill knows it must
  still dispatch the heavy agent.

Write target. The Composer's nested-link defect is in
`threat-model.md` itself (the source fragments contain no nested links —
the pattern is produced by `compose_threat_model.py` doing two passes of
linkification). Fixing the fragment is therefore impossible; the only
deterministic remedy is a post-compose textual pass against
`threat-model.md`. This script restricts itself to that single file plus
fragments under `.fragments/` for action types that target fragments.

This deliberately bends the "only `compose_threat_model.py` writes
`threat-model.md`" invariant for the narrow case of post-compose cleanup
of known composer bugs. The bend is small, documented, and saves ~16 min
of agent time per repair iteration.

Exit codes:
  0 — every action applied; plan is now empty/clean
  1 — at least one unsupported action remained; the caller must fall back
      to the REPAIR_MODE Stage-1 dispatch
  2 — invalid arguments / unreadable plan / IO error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PLAN_FILENAME = ".qa-repair-plan.json"
TARGET_MD = "threat-model.md"

# Action types this applier knows how to fix deterministically.
SUPPORTED_TYPES = frozenset({"toc_nested_link"})


# ---------------------------------------------------------------------------
# Per-action fixers
# ---------------------------------------------------------------------------


def _fix_toc_nested_link(md_text: str) -> tuple[str, int]:
    """Strip the inner `[label](#anchor)` from any nested-link pattern.

    Matches `[<prefix>[<label>](#x)<suffix>](#y)` and rewrites to
    `[<prefix><label><suffix>](#y)`. Whatever target the inner link had is
    discarded — the outer link is what the renderer actually navigates, and
    GitHub / VS Code / MkDocs all fail to render the nested form anyway.

    Idempotent: a clean document is left untouched. Returns the new text
    and the number of substitutions performed.
    """
    # The outer link target may or may not equal the inner — both are
    # broken from a renderer point of view, so we accept either.
    pattern = re.compile(
        r"\["  # outer [
        r"([^\[\]]*?)"  # group 1: prefix text inside outer label (lazy, no brackets)
        r"\["  # inner [
        r"([^\]]+?)"  # group 2: inner label
        r"\]\(#[^)]+\)"  # inner ](#anchor)
        r"([^\[\]]*?)"  # group 3: suffix text inside outer label
        r"\]"  # outer ]
        r"\((#[^)]+)\)"  # group 4: outer (#anchor)
    )

    new_text, count = pattern.subn(r"[\1\2\3](\4)", md_text)
    return new_text, count


# ---------------------------------------------------------------------------
# Plan dispatch
# ---------------------------------------------------------------------------


def _read_plan(plan_path: Path) -> dict:
    try:
        return json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(2) from exc


def apply_plan(output_dir: Path, plan: dict) -> dict:
    """Apply every supported action; report what was fixed and what was left.

    Returns a dict with keys:
      applied_types: list[str] — action types that were applied
      skipped_types: list[str] — action types this script does not handle
      changes:       dict[str, int] — per-type substitution counts
      md_changed:    bool — whether threat-model.md was rewritten
    """
    md_path = output_dir / TARGET_MD
    if not md_path.is_file():
        raise SystemExit(2)

    actions = plan.get("actions") or []
    md_text = md_path.read_text(encoding="utf-8")
    original = md_text

    applied: list[str] = []
    skipped: list[str] = []
    changes: dict[str, int] = {}

    for action in actions:
        atype = action.get("type", "<missing>")
        if atype == "toc_nested_link":
            new_text, count = _fix_toc_nested_link(md_text)
            md_text = new_text
            changes["toc_nested_link"] = changes.get("toc_nested_link", 0) + count
            applied.append("toc_nested_link")
        elif atype in SUPPORTED_TYPES:
            # Reserved for future expansion. Falling here means the type
            # is declared supported but the dispatch arm is missing.
            print(
                f"[repair-plan] internal: type {atype!r} declared supported but no handler dispatched",
                file=sys.stderr,
            )
            skipped.append(atype)
        else:
            skipped.append(atype)

    md_changed = md_text != original
    if md_changed:
        md_path.write_text(md_text, encoding="utf-8")

    return {
        "applied_types": applied,
        "skipped_types": skipped,
        "changes": changes,
        "md_changed": md_changed,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="apply_repair_plan.py",
        description=__doc__.splitlines()[0] if __doc__ else "",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="$OUTPUT_DIR (contains threat-model.md, .qa-repair-plan.json, .fragments/)",
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=None,
        help=f"Plan path (default: <output_dir>/{PLAN_FILENAME})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change but do not write threat-model.md.",
    )
    args = parser.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"error: output_dir is not a directory: {args.output_dir}", file=sys.stderr)
        return 2

    plan_path = args.plan or (args.output_dir / PLAN_FILENAME)
    if not plan_path.is_file():
        # No plan = no work. Common case on clean runs.
        print(f"[repair-plan] no plan at {plan_path} — nothing to do", file=sys.stderr)
        return 0

    plan = _read_plan(plan_path)
    actions = plan.get("actions") or []
    if not actions:
        print("[repair-plan] plan has 0 actions — nothing to do", file=sys.stderr)
        return 0

    # Dry-run path runs the same dispatch but discards writes.
    if args.dry_run:
        md_path = args.output_dir / TARGET_MD
        if not md_path.is_file():
            print(f"error: {md_path} not found", file=sys.stderr)
            return 2
        md_text = md_path.read_text(encoding="utf-8")
        skipped: list[str] = []
        changes: dict[str, int] = {}
        for action in actions:
            atype = action.get("type", "<missing>")
            if atype == "toc_nested_link":
                _, count = _fix_toc_nested_link(md_text)
                changes["toc_nested_link"] = count
            else:
                skipped.append(atype)
        print(
            json.dumps(
                {"dry_run": True, "would_change": changes, "skipped_types": skipped},
                indent=2,
            )
        )
        return 0 if not skipped else 1

    report = apply_plan(args.output_dir, plan)
    print(json.dumps(report, indent=2))

    # Per-type log line (concise, grep-friendly).
    for t, n in report["changes"].items():
        print(f"[repair-plan] {t}: {n} substitution(s)", file=sys.stderr)
    if report["skipped_types"]:
        print(
            f"[repair-plan] skipped (non-mechanical): {sorted(set(report['skipped_types']))}",
            file=sys.stderr,
        )

    # Exit 0 only when every action was supported. Otherwise the caller
    # must still dispatch the heavy threat-analyst REPAIR_MODE pass.
    return 0 if not report["skipped_types"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
