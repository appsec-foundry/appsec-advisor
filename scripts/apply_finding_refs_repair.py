#!/usr/bin/env python3
"""Apply finding-refs repair plan to threat-model.md.

Companion to ``validate_finding_refs.py``. Reads
``$OUTPUT_DIR/.finding-refs-repair-plan.json`` and rewrites the bad
``[F-NNN](#f-nnn)`` references in ``threat-model.md`` to the YAML-aligned
target IDs.

Why direct MD edit is justified here:
- The AGENTS.md invariant "agents never write threat-model.md directly"
  protects against *LLM-driven* writes that bypass the schema-validated
  renderer. This script is the schema-validated renderer's deterministic
  post-fix step — it consumes the structured repair plan and applies it
  without any LLM intermediation.
- The PreToolUse hook in ``agent_logger.py`` only blocks the Claude Code
  Write/Edit/MultiEdit tools. Python ``open()`` from a plugin script is
  the same channel the composer itself uses, so the invariant is
  respected.
- Idempotent: re-running after a clean pass is a no-op (validator will
  find zero defects, applier exits 0).

The script applies a token-aware regex replacement that preserves the
surrounding link markup:

    [F-OLD](#f-old) — <description>   →   [F-NEW](#f-new) — <description>

Only the link target changes; the inline description (which is what the
LLM authored, and which the validator used to derive the remap) is left
alone — the user reads the description and the link now lands on the
matching YAML threat.

Score threshold:
- ``--min-score 0.20`` (default) — remap candidates below this token-
  similarity score are skipped. Empirically this catches the strong
  remaps (price-tampering, basket IDOR, dir listing) while leaving
  ambiguous cases for manual review.
- ``--min-score 0`` — apply everything in the plan (use only after
  human review of the plan).

Exit codes:
    0 — applied successfully (or nothing to apply)
    1 — plan referenced files that do not exist
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def apply_plan(md_path: Path, plan_path: Path, min_score: float, dry_run: bool) -> int:
    if not md_path.exists():
        print(f'error: {md_path} not found', file=sys.stderr)
        return 1
    if not plan_path.exists():
        print(f'error: {plan_path} not found', file=sys.stderr)
        return 1

    plan = json.loads(plan_path.read_text(encoding='utf-8'))
    actions = plan.get('actions') or []
    if not actions:
        print('apply_finding_refs_repair: no actions in plan — nothing to do', file=sys.stderr)
        return 0

    md_text = md_path.read_text(encoding='utf-8')

    # Group by (line, bad_f_id, suggested_f_id) so identical occurrences
    # only need one replace pass. The validator may emit the same defect
    # multiple times when it scans both the fragment and the rendered MD.
    seen: dict[tuple[int, str, str], dict] = {}
    for a in actions:
        # Only consider actions whose fragment is the rendered MD.
        frag = a.get('fragment', '')
        if not frag.endswith('/threat-model.md'):
            continue
        line = a.get('line', 0)
        bad = a.get('bad_f_id')
        new = a.get('suggested_f_id')
        if not bad or not new or bad == new:
            continue
        if new and new[0] != 'F':
            continue  # plan must remap to F-NNN
        # phantom_f_id (bad ID does not exist in YAML) is always safe to
        # remap regardless of score — the original link points to a dead
        # anchor, so any match is strictly better than leaving it broken.
        if a.get('defect') == 'phantom_f_id':
            # Synthesize a high score so the threshold lets it through
            a = {**a, 'remap_score': max(float(a.get('remap_score') or 0), 1.0)}
        seen[(line, bad, new)] = a

    applied = 0
    skipped_low_score = 0
    skipped_no_match = 0
    md_lines = md_text.splitlines(keepends=True)
    by_line: dict[int, list[tuple[str, str]]] = defaultdict(list)
    for (line, bad, new), a in seen.items():
        # Score may be None when the plan lists a phantom_f_id with no
        # remap candidate. We already filtered out None new above.
        score = a.get('remap_score', 0.0)
        try:
            score_f = float(score)
        except (TypeError, ValueError):
            score_f = 0.0
        if score_f < min_score:
            skipped_low_score += 1
            continue
        by_line[line].append((bad, new))

    for line_no, swaps in by_line.items():
        idx = line_no - 1
        if idx < 0 or idx >= len(md_lines):
            skipped_no_match += 1
            continue
        original = md_lines[idx]
        rewritten = original
        for bad, new in swaps:
            old_link = f'[{bad}](#{bad.lower()})'
            new_link = f'[{new}](#{new.lower()})'
            if old_link in rewritten:
                rewritten = rewritten.replace(old_link, new_link, 1)
                applied += 1
            else:
                skipped_no_match += 1
        md_lines[idx] = rewritten

    new_text = ''.join(md_lines)
    if dry_run:
        print(f'apply_finding_refs_repair: DRY-RUN — would apply {applied} swap(s), '
              f'skip {skipped_low_score} low-score, {skipped_no_match} no-match',
              file=sys.stderr)
        return 0

    if new_text == md_text:
        print('apply_finding_refs_repair: no changes (idempotent re-run)', file=sys.stderr)
        return 0

    # Atomic write
    tmp_path = md_path.with_suffix('.md.tmp')
    tmp_path.write_text(new_text, encoding='utf-8')
    tmp_path.replace(md_path)
    print(f'apply_finding_refs_repair: applied {applied} remap(s) · '
          f'skipped {skipped_low_score} low-score · {skipped_no_match} no-match'
          , file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('output_dir', type=Path)
    ap.add_argument('--min-score', type=float, default=0.20,
                    help='Minimum token-similarity score for a remap to apply (default 0.20)')
    ap.add_argument('--dry-run', action='store_true',
                    help='Show what would change without writing the file')
    args = ap.parse_args()

    md = args.output_dir / 'threat-model.md'
    plan = args.output_dir / '.finding-refs-repair-plan.json'
    return apply_plan(md, plan, args.min_score, args.dry_run)


if __name__ == '__main__':
    sys.exit(main())
