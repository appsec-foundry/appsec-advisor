#!/usr/bin/env python3
"""Apply residual deterministic fixes to threat-model.md and threat-model.yaml
that the QA pipeline can detect but does not auto-resolve:

- RC-3 subcontrol_naming_canonical — rename §7.2.1 to "Password Login"
  (matches the canonical IAM vocabulary in sections-contract.yaml).
- RC-4 evidence_integrity — patch evidence.line/.excerpt for known noise-
  line drift (T-021 routes/changePassword.ts, T-028 routes/metrics.ts).
- RC-7 rhetorical_severity — replace "trivially" with concrete prose in
  §7.3 (key-pair obtainable) and §7.9 (cookie secret).
- RC-6 inline_code_format — wrap unbacked path tokens via apply_prose_fixes
  (delegated to the existing script).

The script is deterministic; running twice is a no-op (idempotent string
matches). Writes via Python ``open()`` — same channel as the composer,
so the AGENTS.md "no direct LLM writes to MD" invariant is respected.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import yaml


def _read(p: Path) -> str:
    return p.read_text(encoding='utf-8')


def _write(p: Path, text: str) -> None:
    tmp = p.with_suffix(p.suffix + '.tmp')
    tmp.write_text(text, encoding='utf-8')
    tmp.replace(p)


def fix_subcontrol_naming(md: Path) -> int:
    """RC-3 — §7.2.1 'Authentication Mechanisms' → 'Password Login'."""
    text = _read(md)
    if '#### 7.2.1 Password Login' in text:
        return 0  # already applied
    # Rename heading + anchor for the dominant mechanism
    new_text = text.replace(
        '#### 7.2.1 Authentication Mechanisms',
        '#### 7.2.1 Password Login',
        1,
    )
    if new_text != text:
        _write(md, new_text)
        return 1
    return 0


def fix_rhetorical_severity(md: Path) -> int:
    """RC-7 — replace 'trivially' / 'trivially obtainable' with concrete prose."""
    text = _read(md)
    swaps = [
        # §7.3 — key pair obtainable
        ('trivially obtainable from the running application',
         'served without authentication, allowing any unauthenticated HTTP GET to retrieve the key'),
        # §7.9 — cookie secret guessable
        ('The cookie secret `kekse` is trivially guessable.',
         'The cookie secret `kekse` is a 5-character dictionary word with no production-grade entropy.'),
        # §1 Architecture Assessment — "trivially bypassable"
        ('making every cryptographic control trivially bypassable',
         'allowing every cryptographic control to be reproduced offline by anyone with read access to the repository'),
    ]
    applied = 0
    new_text = text
    for old, new in swaps:
        if old in new_text:
            new_text = new_text.replace(old, new, 1)
            applied += 1
    if applied:
        _write(md, new_text)
    return applied


def fix_evidence_lines(yaml_path: Path, md: Path) -> int:
    """RC-4 — patch known noise-line evidence for T-021 and T-028.

    Note: T-015 evidence (server.ts:369 commented-auth) is intentionally
    left as-is — the commented line IS the vulnerability marker (Juice
    Shop convention `vuln-line changeProductChallenge`). The integrity
    check has no per-finding override yet; this is a documented false
    positive.
    """
    with open(yaml_path, encoding='utf-8') as fh:
        data = yaml.safe_load(fh)
    threats = data.get('threats') or []
    applied = 0

    patches = {
        'T-021': {
            'line': 39,
            'excerpt': (
                "if (currentPassword && security.hash(currentPassword) "
                "!== loggedInUser.data.password) {"
            ),
            'reason': 'conditional accepts missing currentPassword and skips verification',
        },
        'T-028': {
            'line': 718,
            'file': 'server.ts',
            'excerpt': "app.get('/metrics', metrics.serveMetrics())  // exposed unauthenticated",
            'reason': 'route registration without isAuthorized middleware',
        },
    }

    for t in threats:
        if not isinstance(t, dict):
            continue
        tid = t.get('id') or t.get('t_id')
        if tid not in patches:
            continue
        p = patches[tid]
        ev = t.get('evidence')
        if isinstance(ev, list) and ev:
            ev_item = ev[0]
        elif isinstance(ev, dict):
            ev_item = ev
        else:
            continue
        if not isinstance(ev_item, dict):
            continue
        before = (ev_item.get('line'), ev_item.get('file'), ev_item.get('excerpt'))
        ev_item['line'] = p['line']
        if 'file' in p:
            ev_item['file'] = p['file']
        ev_item['excerpt'] = p['excerpt']
        if before != (ev_item.get('line'), ev_item.get('file'), ev_item.get('excerpt')):
            applied += 1

    if applied:
        with open(yaml_path, 'w', encoding='utf-8') as fh:
            yaml.safe_dump(data, fh, default_flow_style=False, sort_keys=False,
                           allow_unicode=True, width=200)
        # Patch the rendered MD too — find the F-NNN row and rewrite the
        # `file:line` token and the language-typescript code block. This
        # is best-effort: a future re-compose will overwrite it correctly.
        md_text = _read(md)
        md_changed = False
        for tid, p in patches.items():
            fid = tid.replace('T-', 'F-').lower()
            # Pattern: `<old_file>`:<old_line> · ...
            # Find anchor row by id and replace the `file:N` token in it.
            row_re = re.compile(
                r'(<a id="' + tid.lower() + r'"></a><a id="' + fid + r'"></a>[^|]+?'
                r'`[^`]+`:)\d+( ·)',
            )
            new_token = f'{p.get("file") or ""}'  # may be empty when only line changed
            replaced = row_re.sub(
                lambda m: m.group(1).split('`')[0] + '`' + (
                    p.get('file') or md_text[m.start():m.end()].split('`')[1]
                ) + '`:' + str(p['line']) + m.group(2),
                md_text,
            )
            if replaced != md_text:
                md_text = replaced
                md_changed = True
        if md_changed:
            _write(md, md_text)
    return applied


def run_prose_fixes(plugin_root: Path, md: Path) -> int:
    """RC-6 — re-run apply_prose_fixes (covers path-token backticking)."""
    script = plugin_root / 'scripts' / 'apply_prose_fixes.py'
    if not script.exists():
        return 0
    result = subprocess.run(
        ['python3', str(script), str(md)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
    sys.stderr.write(result.stderr)
    # Count applied fixes if surfaced in stderr
    m = re.search(r'applied (\d+) fix', result.stderr)
    return int(m.group(1)) if m else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('output_dir', type=Path)
    ap.add_argument('--plugin-root', type=Path,
                    default=Path('/home/mrohr/appsec-advisor'))
    args = ap.parse_args()

    md = args.output_dir / 'threat-model.md'
    yml = args.output_dir / 'threat-model.yaml'
    if not md.exists() or not yml.exists():
        print('error: required files missing', file=sys.stderr); return 2

    print(f'apply_residual_fixes: RC-3 subcontrol_naming → {fix_subcontrol_naming(md)} change(s)',
          file=sys.stderr)
    print(f'apply_residual_fixes: RC-7 rhetorical_severity → {fix_rhetorical_severity(md)} change(s)',
          file=sys.stderr)
    print(f'apply_residual_fixes: RC-4 evidence_lines (T-021, T-028) → '
          f'{fix_evidence_lines(yml, md)} change(s)', file=sys.stderr)
    print(f'apply_residual_fixes: RC-6 path-token backticks → '
          f'{run_prose_fixes(args.plugin_root, md)} change(s)', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
