#!/usr/bin/env python3
"""Evaluate opt-in release gates declared by resolved abuse cases.

The gate is intentionally narrow: a case can block only when its own
``release_gate.fail_on`` explicitly names the final deterministic chain
verdict.  Missing verdicts and inconclusive chains stay visible in the report
but do not become surprise release failures.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _preset_name(output_dir: Path) -> str | None:
    preset = _load(output_dir / ".skill-config.json").get("preset") or {}
    return preset.get("name") if isinstance(preset, dict) else None


def evaluate(output_dir: Path, preset: str | None = None) -> list[dict]:
    """Return explicit gate violations from the run's audit sidecars."""
    matches = _load(output_dir / ".abuse-case-matches.json").get("matches") or []
    verdicts = _load(output_dir / ".abuse-case-verdicts.json").get("verdicts") or []
    verdict_by_id = {v.get("abuse_case_id"): v for v in verdicts if isinstance(v, dict)}
    active_preset = preset if preset is not None else _preset_name(output_dir)
    violations: list[dict] = []

    for match in matches:
        if not isinstance(match, dict):
            continue
        case = match.get("case") or {}
        gate = case.get("release_gate") or {}
        if not isinstance(gate, dict):
            continue
        applies = gate.get("applies_to_presets") or []
        if applies and active_preset not in applies:
            continue
        cid = match.get("abuse_case_id")
        verdict = verdict_by_id.get(cid) or {}
        chain_verdict = verdict.get("chain_verdict")
        if chain_verdict in set(gate.get("fail_on") or []):
            violations.append(
                {
                    "abuse_case_id": cid,
                    "title": case.get("title") or match.get("title") or cid,
                    "chain_verdict": chain_verdict,
                    "preset": active_preset,
                }
            )
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail closed on configured abuse-case release gates.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--preset", default=None, help="override the resolved org-profile preset")
    args = parser.parse_args(argv)
    violations = evaluate(Path(args.output_dir), args.preset)
    if not violations:
        print("ABUSE_CASE_GATE: pass (no configured gate violation)")
        return 0
    for item in violations:
        print(
            f"ABUSE_CASE_GATE: violation {item['abuse_case_id']} ({item['chain_verdict']}) — {item['title']}",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
