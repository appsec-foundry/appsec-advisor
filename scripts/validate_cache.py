#!/usr/bin/env python3
"""
validate_cache.py — pre-flight integrity check for assessment intermediates.

Where check_state.py cares about run-state (lock / checkpoint / session map),
this script cares about **data integrity**: the intermediate JSON and
Markdown files that a crashed or hung prior run may have left truncated,
half-written, or otherwise malformed. Specifically:

  * `.stride-<id>.json`             — per-component STRIDE output
  * `.threats-merged.json`          — finalized threat register
  * `.merge-candidates.json`        — pre-LLM merge payload
  * `.merge-decisions.json`         — LLM merge decisions (if present)
  * `.triage-flags.json`            — triage validator output
  * `.triage-ranking.json`          — optional ranking block
  * `.pre-render-report.json`       — fragment gate output
  * `.appsec-cache/baseline.json`   — incremental baseline
  * `.fragments/*.json`             — composer input (JSON fragments)
  * `.fragments/*.md`               — composer input (Markdown fragments)

For each file we check:

  * JSON files: parse with `json.loads()`; must be a non-empty object/list.
  * Markdown files: must be non-empty (zero-byte = half-write).

Corrupt or truncated files are (with ``--quarantine``) moved under
`$OUTPUT_DIR/.quarantine/<ISO-timestamp>/` preserving their original
relative name. The orchestrator will treat the missing intermediate as a
fresh cache-miss on the next run — a phase that would have carried the
corrupt file forward re-generates it instead.

Design choices:

  * Absent files are **not** a concern here — cache-miss is the baseline
    expected state for a fresh or post-quarantine repo.
  * Schema validation is intentionally out of scope; `validate_intermediate.py`
    and `validate_fragment.py` run later in the pipeline and perform the
    stricter checks. This script is a cheap-and-fast JSON-parse smoke screen.
  * The script is **always** safe to run: in `--quarantine` mode it only
    moves corrupt files; healthy files are untouched.

Exit codes
----------

  0 — all inspected files parsed cleanly (or corrupt files were quarantined)
  1 — corrupt files found and ``--quarantine`` was NOT passed
  2 — usage error / output dir missing

Usage
-----

  python3 validate_cache.py <output_dir>                   # report only
  python3 validate_cache.py <output_dir> --quarantine      # move corrupt files
  python3 validate_cache.py <output_dir> --json            # JSON output
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


# Files we inspect. ``kind`` drives the integrity check:
#   "json"  — must parse with json.loads() and be a dict or list
#   "text"  — must be non-empty (zero-byte = corrupted half-write)
_TOP_LEVEL: tuple[tuple[str, str], ...] = (
    (".threats-merged.json",    "json"),
    (".merge-candidates.json",  "json"),
    (".merge-decisions.json",   "json"),
    (".triage-flags.json",      "json"),
    (".triage-ranking.json",    "json"),
    (".pre-render-report.json", "json"),
)

_GLOB_PATTERNS: tuple[tuple[str, str], ...] = (
    (".stride-*.json", "json"),
    (".fragments/*.json", "json"),
    (".fragments/*.md",   "text"),
)

_BASELINE_PATH = ".appsec-cache/baseline.json"  # checked separately (always json)


def _check_json(path: Path) -> str | None:
    """Return None when the file parses cleanly, else a short error string."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return f"unreadable: {e}"
    if not text.strip():
        return "empty file"
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        return f"invalid JSON: {e.msg} (line {e.lineno}, col {e.colno})"
    if not isinstance(obj, (dict, list)):
        return f"unexpected top-level type: {type(obj).__name__}"
    return None


def _check_text(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError as e:
        return f"unreadable: {e}"
    if size == 0:
        return "zero bytes (likely half-written)"
    return None


def _collect_targets(output_dir: Path) -> list[tuple[Path, str]]:
    targets: list[tuple[Path, str]] = []
    for name, kind in _TOP_LEVEL:
        p = output_dir / name
        if p.is_file():
            targets.append((p, kind))
    for pattern, kind in _GLOB_PATTERNS:
        for p in sorted(output_dir.glob(pattern)):
            if p.is_file():
                targets.append((p, kind))
    baseline = output_dir / _BASELINE_PATH
    if baseline.is_file():
        targets.append((baseline, "json"))
    return targets


def _quarantine_dir(output_dir: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return output_dir / ".quarantine" / stamp


def _quarantine(target: Path, output_dir: Path, qdir: Path) -> Path:
    """Move ``target`` under ``qdir`` preserving its output-relative name.

    Returns the new absolute path.
    """
    try:
        rel = target.relative_to(output_dir)
    except ValueError:
        rel = Path(target.name)
    dest = qdir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(target), str(dest))
    return dest


def run(output_dir: Path, *, quarantine: bool) -> dict:
    report: dict = {
        "output_dir":       str(output_dir),
        "checked_count":    0,
        "ok_count":         0,
        "corrupt":          [],       # list[{path, kind, error, quarantined_to}]
        "quarantine_dir":   None,
    }

    targets = _collect_targets(output_dir)
    report["checked_count"] = len(targets)

    corrupt_pairs: list[tuple[Path, str, str]] = []
    for path, kind in targets:
        if kind == "json":
            err = _check_json(path)
        else:
            err = _check_text(path)
        if err is None:
            report["ok_count"] += 1
        else:
            corrupt_pairs.append((path, kind, err))

    if corrupt_pairs and quarantine:
        qdir = _quarantine_dir(output_dir)
        report["quarantine_dir"] = str(qdir)
        for path, kind, err in corrupt_pairs:
            try:
                dest = _quarantine(path, output_dir, qdir)
                report["corrupt"].append({
                    "path":             str(path.relative_to(output_dir)),
                    "kind":             kind,
                    "error":            err,
                    "quarantined_to":   str(dest.relative_to(output_dir)),
                })
            except OSError as e:
                # Best-effort: if the move itself fails, record it and leave
                # the file in place so the next step can still see the issue.
                report["corrupt"].append({
                    "path":             str(path.relative_to(output_dir)),
                    "kind":             kind,
                    "error":            err,
                    "quarantine_error": str(e),
                })
    elif corrupt_pairs:
        for path, kind, err in corrupt_pairs:
            report["corrupt"].append({
                "path":  str(path.relative_to(output_dir)),
                "kind":  kind,
                "error": err,
            })

    return report


def _render_text(report: dict, quarantine: bool) -> str:
    checked = report["checked_count"]
    ok      = report["ok_count"]
    corrupt = report["corrupt"]
    lines: list[str] = []

    if checked == 0:
        lines.append("✓ No intermediate files to validate (clean state).")
        return "\n".join(lines) + "\n"

    if not corrupt:
        lines.append(f"✓ All {checked} intermediate file(s) parse cleanly.")
        return "\n".join(lines) + "\n"

    if quarantine:
        qdir = report.get("quarantine_dir") or "(failed to create)"
        lines.append(
            f"⚠ Found {len(corrupt)} corrupt file(s) out of {checked} — quarantined to {qdir}:"
        )
    else:
        lines.append(
            f"⚠ Found {len(corrupt)} corrupt file(s) out of {checked} "
            f"(re-run with --quarantine to move them):"
        )
    for entry in corrupt:
        lines.append(f"  • {entry['path']} — {entry['error']}")
        if entry.get("quarantined_to"):
            lines.append(f"    → {entry['quarantined_to']}")
        if entry.get("quarantine_error"):
            lines.append(f"    (quarantine failed: {entry['quarantine_error']})")
    lines.append(f"  ({ok} file(s) healthy, left in place)")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_cache.py",
        description=(
            "Pre-flight integrity check for assessment intermediate files. "
            "Optionally quarantines corrupt files so the next run sees a "
            "clean cache."
        ),
    )
    parser.add_argument("output_dir", help="Assessment output directory (docs/security).")
    parser.add_argument(
        "--quarantine",
        action="store_true",
        help="Move corrupt files under .quarantine/<iso-timestamp>/",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as machine-readable JSON on stdout.",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        # Missing output dir is effectively "nothing to validate".
        payload = {
            "output_dir":    str(output_dir),
            "checked_count": 0,
            "ok_count":      0,
            "corrupt":       [],
            "quarantine_dir": None,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print("✓ Output dir does not exist — nothing to validate.")
        return 0

    report = run(output_dir, quarantine=args.quarantine)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_render_text(report, args.quarantine), end="")

    if report["corrupt"] and not args.quarantine:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
