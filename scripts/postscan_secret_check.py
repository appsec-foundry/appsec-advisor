#!/usr/bin/env python3
"""postscan_secret_check.py — final unmasked-secret check on artifacts.

Wraps ``scripts/secret_scan.py`` and runs it against every artifact
that may contain text copied from the scanned repo (rendered report,
recon summary, dispatch/merger contexts, etc.). Designed to be the
last gate before a run is considered complete — fails the run if any
file leaks an unmasked secret value.

The rendered report and ``threat-model.yaml`` are masked deterministically
upstream (composer ``mask_text`` + ``secret_scan.py --mask``), but the
LLM-authored intermediates (``.recon-summary.md``, ``.threat-modeling-context.md``,
``.architect-review.md``) are only masked if the agent remembered to redact at
authoring time — an LLM-compliance dependency that silently leaks a real
secret value when the agent slips (e.g. a kept ``-----BEGIN … PRIVATE KEY-----``
marker). ``--mask`` closes that gap: it runs the deterministic ``mask_file``
twin of the detector over every candidate file BEFORE verifying, so masking no
longer depends on the LLM. Because ``mask_text`` is the masking twin of
``scan_text``, a masked file is guaranteed to pass the subsequent scan; the scan
remains as a backstop for anything masking could not neutralise.

Exit codes::

    0   no unmasked secrets found
    2   one or more files contain unmasked secret values
    3   output directory missing or unreadable
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from secret_scan import mask_file, scan_file  # noqa: E402

_DEFAULT_TARGETS = (
    "threat-model.md",
    "threat-model.yaml",
    ".recon-summary.md",
    ".threat-modeling-context.md",
    ".architect-review.md",
)


def _candidate_files(output_dir: Path, extra: list[str]) -> list[Path]:
    out: list[Path] = []
    for rel in (*_DEFAULT_TARGETS, *extra):
        p = output_dir / rel
        if p.is_file():
            out.append(p)
    return out


def run(output_dir: Path, *, extra: list[str] | None = None, mask: bool = False) -> dict:
    extra = extra or []
    files = _candidate_files(output_dir, extra)
    masked: dict[str, list[str]] = {}
    if mask:
        # Deterministic neutralisation BEFORE the verify pass — closes the
        # LLM-compliance gap on the authored intermediates. Idempotent on the
        # already-masked report/yaml (no markers to add → no write).
        for f in files:
            applied = mask_file(f)
            if applied:
                masked[str(f.relative_to(output_dir))] = applied
    by_file: dict[str, list[dict]] = {}
    total = 0
    for f in files:
        hits = scan_file(f)
        if hits:
            by_file[str(f.relative_to(output_dir))] = [
                {"pattern": h.pattern, "snippet": h.snippet, "line": h.line} for h in hits
            ]
            total += len(hits)
    return {
        "output_dir": str(output_dir),
        "checked_files": [str(f.relative_to(output_dir)) for f in files],
        "masked_files": masked,
        "hit_count": total,
        "by_file": by_file,
    }


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument(
        "--also",
        action="append",
        default=[],
        help="extra relative path to check (repeatable)",
    )
    p.add_argument("--json", action="store_true", help="emit a JSON summary")
    p.add_argument(
        "--mask",
        action="store_true",
        help="deterministically mask every candidate file in place before "
        "verifying (closes the LLM-compliance gap on authored intermediates)",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.output_dir.is_dir():
        print(f"postscan-secret-check: output dir not found: {args.output_dir}", file=sys.stderr)
        return 3
    report = run(args.output_dir, extra=args.also, mask=args.mask)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        for relpath, applied in report.get("masked_files", {}).items():
            print(
                f"postscan-secret-check: masked {relpath} ({', '.join(sorted(set(applied)))})",
                file=sys.stderr,
            )
        if report["hit_count"] == 0:
            print(
                f"postscan-secret-check: clean ({len(report['checked_files'])} files scanned)",
                file=sys.stderr,
            )
        else:
            print(
                f"postscan-secret-check: {report['hit_count']} unmasked secret hit(s) across {len(report['by_file'])} file(s):",
                file=sys.stderr,
            )
            for relpath, hits in report["by_file"].items():
                for h in hits:
                    print(f"  {relpath}:{h['line']}  [{h['pattern']}]  {h['snippet']!r}", file=sys.stderr)
    return 2 if report["hit_count"] else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
