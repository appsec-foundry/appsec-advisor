#!/usr/bin/env python3
"""Replace §2.4.x layer-table data rows in threat-model.md with the
canonical rows from the freshly-pre-generated
``.fragments/architecture-diagrams.md``.

Root-cause fix for the 2026-05-21 juice-shop run defect where repair
iteration 2 manually edited ``.fragments/architecture-diagrams.md`` to
add T-NNN traceability and accidentally introduced ``· `` separators
+ duplicated short-titles. The deterministic pregenerator emits clean
``<br/>``-separated rows by construction, so this script just lifts
those rows back into the rendered MD.

Why direct MD edit is justified here: same reasoning as
``apply_finding_refs_repair.py`` — the script is part of the
plugin pipeline, runs deterministically from a structured source
(the pregenerated fragment), and consumes no LLM intermediation.

Heuristic: locate any data row in threat-model.md whose first column
matches a component name from the YAML AND whose third column contains
the pattern ``[F-NNN](#f-nnn) — ... · [F-MMM]`` (the broken inline
``·`` separator). Replace it with the row from the fragment whose
first column matches the same component.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


COMP_RE = re.compile(r'^\|\s*([a-z][a-z0-9-]+)\s+([^|]+?)\s*\|')


def index_fragment_rows(frag_path: Path) -> dict[str, str]:
    """Return {component_id: full-row-line} from the §2.4.x layer tables
    in the pregenerated architecture-diagrams.md."""
    out: dict[str, str] = {}
    if not frag_path.exists():
        return out
    for raw in frag_path.read_text(encoding='utf-8').splitlines():
        if not raw.startswith('|'):
            continue
        if ' Layer ' not in raw:  # only the §2.4.x layer table rows carry this
            continue
        m = COMP_RE.match(raw)
        if not m:
            continue
        comp = m.group(1)
        # Prefer the first occurrence (express-backend appears twice — the
        # first row is the High-severity row, the second is the Critical-
        # severity row; the YAML keeps both via Critical-merging).
        if comp not in out:
            out[comp] = raw
        else:
            # Concat additional rows so the rendered MD keeps both
            out[comp] = out[comp] + '\n' + raw
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('output_dir', type=Path)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    md = args.output_dir / 'threat-model.md'
    frag = args.output_dir / '.fragments' / 'architecture-diagrams.md'
    if not md.exists():
        print(f'error: {md} not found', file=sys.stderr); return 2
    if not frag.exists():
        print(f'error: {frag} not found — run pregenerate_fragments first',
              file=sys.stderr); return 2

    canonical = index_fragment_rows(frag)
    if not canonical:
        print('error: no §2.4 layer-table rows found in fragment',
              file=sys.stderr); return 1

    lines = md.read_text(encoding='utf-8').splitlines(keepends=True)
    out_lines: list[str] = []
    replaced = 0
    skipped: list[int] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        # Detect rendered §2.4.x broken row: pipe-row with ' · ' between
        # F-NNN link spans.
        stripped = ln.rstrip('\n')
        has_dot_sep = ' · ' in stripped
        has_f_link = bool(re.search(r'\[F-\d+\]\(#f-\d+\)', stripped))
        if has_dot_sep and has_f_link and stripped.startswith('|'):
            m = COMP_RE.match(stripped)
            if m:
                comp = m.group(1)
                replacement = canonical.get(comp)
                if replacement is not None:
                    # Each replacement may contain multiple rows; ensure trailing newline.
                    out_lines.append(replacement + '\n')
                    replaced += 1
                    i += 1
                    continue
                else:
                    skipped.append(i + 1)
        out_lines.append(ln)
        i += 1

    new_text = ''.join(out_lines)
    if args.dry_run:
        print(f'patch_layer_tables: DRY-RUN — would replace {replaced} row(s), '
              f'skip {len(skipped)} no-match', file=sys.stderr)
        return 0

    if replaced == 0:
        print('patch_layer_tables: no broken rows found — nothing to do',
              file=sys.stderr); return 0

    tmp = md.with_suffix('.md.tmp')
    tmp.write_text(new_text, encoding='utf-8')
    tmp.replace(md)
    print(f'patch_layer_tables: replaced {replaced} broken row(s) in §2.4.x',
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
