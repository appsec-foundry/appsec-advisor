#!/usr/bin/env python3
"""requirements_report.py — deterministic validation + stats for an audit verdict.

audit-security-requirements grades each requirement and writes the structured
verdict (`schemas/requirements-audit.schema.json`). The agent fills the
per-requirement fields, but the **counts must not be hand-tallied** — a 63-item
mental count drifts. This script is the authority on the summary: it validates
the verdict against the schema and recomputes `summary` from `results[]`, so the
Result block, the saved reports, and `requirements_gate.py` all agree.

Usage:
    requirements_report.py --audit <path> [--write] [--quiet]

    --write   persist the recomputed summary back into the verdict file.
    --quiet   emit only the machine-readable stats line.

Exit codes:
    0  verdict valid; stats printed
    2  verdict missing / unreadable / schema-invalid
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "requirements-audit.schema.json"

_STATUS_KEYS = {
    "PASS": "pass",
    "PARTIAL": "partial",
    "FAIL": "fail",
    "UNVERIFIABLE": "unverifiable",
    "NOT_APPLICABLE": "not_applicable",
}


def recompute_summary(data: dict) -> dict:
    """Recompute the summary tally from results[] — the single source of truth."""
    summary = {"total": 0, "pass": 0, "partial": 0, "fail": 0, "unverifiable": 0, "not_applicable": 0}
    for r in data.get("results", []) or []:
        if not isinstance(r, dict):
            continue
        summary["total"] += 1
        key = _STATUS_KEYS.get(r.get("status", ""))
        if key:
            summary[key] += 1
    return summary


def _schema_errors(data: dict) -> list[str]:
    try:
        import jsonschema  # noqa: PLC0415

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        return [
            f"{'.'.join(str(p) for p in e.absolute_path) or 'root'}: {e.message}"
            for e in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
        ]
    except ImportError:
        # Minimal structural check without jsonschema.
        errors: list[str] = []
        if not isinstance(data, dict):
            return ["top level is not an object"]
        if not isinstance(data.get("results"), list):
            errors.append("results: must be an array")
        for i, r in enumerate(data.get("results", []) or []):
            if not isinstance(r, dict) or not r.get("id"):
                errors.append(f"results[{i}]: missing id")
        return errors
    except OSError as exc:
        return [f"cannot read schema: {exc}"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate and recompute stats for a requirements-audit verdict.")
    p.add_argument("--audit", required=True, help="Path to .requirements-audit.json")
    p.add_argument("--write", action="store_true", help="Persist the recomputed summary back into the file")
    p.add_argument("--quiet", action="store_true", help="Print only the machine-readable stats line")
    args = p.parse_args(argv)

    path = Path(args.audit)
    if not path.exists():
        print(f"requirements-report: verdict not found: {path}", file=sys.stderr)
        return 2
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"requirements-report: could not read verdict: {exc}", file=sys.stderr)
        return 2

    errors = _schema_errors(data)
    if errors:
        print(f"requirements-report: verdict is schema-invalid ({len(errors)} error(s)):", file=sys.stderr)
        for e in errors[:8]:
            print(f"  - {e}", file=sys.stderr)
        return 2

    summary = recompute_summary(data)
    stored = data.get("summary")
    if args.write or stored != summary:
        data["summary"] = summary
        if args.write:
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    stats_line = " ".join(f"{k}={summary[k]}" for k in ("total", "pass", "partial", "fail", "unverifiable", "not_applicable"))
    print(stats_line)
    if not args.quiet:
        if stored is not None and stored != recompute_summary(data):
            print("requirements-report: note — stored summary disagreed with results[]; recomputed value is authoritative.", file=sys.stderr)
        open_n = summary["fail"] + summary["partial"]
        print(
            f"requirements-report: {summary['total']} graded · {open_n} open "
            f"({summary['fail']} fail, {summary['partial']} partial) · "
            f"{summary['pass']} pass · {summary['unverifiable']} unverifiable · {summary['not_applicable']} n/a",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
