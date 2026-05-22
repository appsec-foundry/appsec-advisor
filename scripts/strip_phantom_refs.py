#!/usr/bin/env python3
"""Strip dangling `[F-NNN](#f-nnn) — ` references with empty descriptions
from threat-model.md. Companion to validate_finding_refs.py — handles the
phantom-with-no-text case where the LLM allocated an F-NNN slot, wrote
the link, but never filled in the description.

Reads `.finding-refs-report.json` for the list of phantom IDs, and
removes any list-item / bullet line in `threat-model.md` whose entire
content is `[F-NNN](#f-nnn) — ` (optionally followed by whitespace).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


PHANTOM_LINE_RE_TPL = r'^\s*-\s*\[{fid}\]\(#{fid_lc}\)\s*[-—]\s*$'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('output_dir', type=Path)
    args = ap.parse_args()

    md = args.output_dir / 'threat-model.md'
    report = args.output_dir / '.finding-refs-report.json'
    if not md.exists() or not report.exists():
        print('error: required files missing', file=sys.stderr)
        return 2

    data = json.loads(report.read_text(encoding='utf-8'))
    phantom_ids = sorted(
        {d['f_id'] for d in data.get('defects', []) if d.get('defect') == 'phantom_f_id'}
    )
    if not phantom_ids:
        print('strip_phantom_refs: no phantoms to strip', file=sys.stderr)
        return 0

    text = md.read_text(encoding='utf-8')
    lines = text.splitlines(keepends=True)
    removed = 0
    out_lines: list[str] = []
    patterns = [
        re.compile(PHANTOM_LINE_RE_TPL.format(fid=re.escape(p), fid_lc=re.escape(p.lower())))
        for p in phantom_ids
    ]
    for ln in lines:
        if any(rx.match(ln) for rx in patterns):
            removed += 1
            continue
        out_lines.append(ln)

    new_text = ''.join(out_lines)
    if new_text == text:
        print('strip_phantom_refs: no matching lines (phantoms may have descriptions)',
              file=sys.stderr)
        return 0

    tmp = md.with_suffix('.md.tmp')
    tmp.write_text(new_text, encoding='utf-8')
    tmp.replace(md)
    print(f'strip_phantom_refs: removed {removed} dangling phantom line(s) — IDs: {phantom_ids}',
          file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
