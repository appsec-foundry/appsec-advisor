#!/usr/bin/env python3
"""Deterministic `threats[].severity_rationale` for ratings ABOVE baseline.

A Critical rating is sometimes *higher than the usual standard* for a
weakness class, and the reason is contextual rather than intrinsic:

  * A hardcoded key / secret (CWE-321/798/312/…) is individually capped at
    High (``never_individual_critical``), but becomes Critical when the
    secret is committed to a **public source repo** — anyone who clones the
    repo can extract it, so exploitation needs no prior access.
  * A mass assignment (CWE-915) or missing-auth (CWE-306) is High on its own
    but Critical when it reaches a privileged field / admin operation on an
    **unauthenticated endpoint** (the always-critical context threshold).
  * Any individually-capped CWE that reaches Critical did so as an
    **attack-chain keystone**.

When the report shows such a finding as Critical without saying *why it is
above the usual baseline*, the rating reads as arbitrary or alarmist. This
emitter writes a short, scannable ``severity_rationale`` that the composer
renders inline on the §8 Story-Card Severity line.

Only findings whose Critical rating is genuinely above their class baseline
get a note — naturally-Critical classes (SQL injection CWE-89, RCE CWE-94)
get none, because Critical is their expected rating and a note would be noise.

Idempotent: auto-written notes are recomputed every run (a downgrade clears a
stale note); a hand-authored ``severity_rationale_manual: true`` is preserved.

Usage:
    python3 emit_severity_rationale.py <output_dir>
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

_CRITERIA_PATH = Path(__file__).resolve().parent.parent / "data" / "critical-criteria.yaml"

# always_critical CWEs whose Critical rating is CONTEXTUAL (only Critical on an
# unauthenticated / low-distance endpoint) rather than intrinsic. These warrant
# a "why above baseline" note; SQLi/RCE/deserialization/command-injection do not.
_CONTEXT_PROMOTED_CWES = {"CWE-915", "CWE-306"}

_REPO_READ_NOTE = "secret committed to the public source repo — extractable on clone, no prior access needed"
_UNAUTH_NOTE = "reaches a privileged operation on an unauthenticated endpoint"
_KEYSTONE_NOTE = "elevated as an attack-chain keystone (individual baseline: High)"


def _load_baseline_high_cwes() -> set[str]:
    """The `never_individual_critical` CWE set — these are individually capped
    below Critical, so a Critical rating is always above their baseline."""
    try:
        crit = yaml.safe_load(_CRITERIA_PATH.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return set()
    out: set[str] = set()
    for entry in crit.get("never_individual_critical") or []:
        if isinstance(entry, dict) and entry.get("cwe"):
            out.add(str(entry["cwe"]).strip().upper())
        elif isinstance(entry, str):
            out.add(entry.strip().upper())
    return out


def _rationale_for(t: dict, baseline_high: set[str]) -> str:
    """Return the short rationale, or '' when no above-baseline note applies."""
    sev = (t.get("risk") or t.get("severity") or "").strip().lower()
    if sev != "critical":
        return ""
    cwe = (t.get("cwe") or "").strip().upper()
    vektor = (t.get("vektor") or "").strip().lower()

    if vektor == "repo-read":
        return _REPO_READ_NOTE
    if cwe in _CONTEXT_PROMOTED_CWES and vektor == "internet-anon":
        return _UNAUTH_NOTE
    if cwe in baseline_high:
        return _KEYSTONE_NOTE
    return ""


def emit(output_dir: Path) -> tuple[int, int]:
    """Returns (total_threats, annotated)."""
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_severity_rationale: no yaml at {yaml_path}", file=sys.stderr)
        return (0, 0)
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"emit_severity_rationale: parse failed: {exc}", file=sys.stderr)
        return (0, 0)
    if not isinstance(data, dict):
        return (0, 0)

    baseline_high = _load_baseline_high_cwes()
    threats = data.get("threats") or []
    annotated = 0
    changed = False
    for t in threats:
        if not isinstance(t, dict):
            continue
        if t.get("severity_rationale_manual"):
            annotated += 1
            continue
        note = _rationale_for(t, baseline_high)
        prior = t.get("severity_rationale")
        if note:
            if prior != note:
                t["severity_rationale"] = note
                changed = True
            annotated += 1
        elif prior is not None:
            # stale auto-note (e.g. finding was downgraded) — clear it.
            t.pop("severity_rationale", None)
            changed = True

    if changed:
        yaml_path.write_text(
            yaml.safe_dump(
                data,
                sort_keys=False,
                allow_unicode=True,
                width=4096,
                default_flow_style=False,
            ),
            encoding="utf-8",
        )
    return (len(threats), annotated)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: emit_severity_rationale.py <output_dir>", file=sys.stderr)
        return 2
    total, annotated = emit(Path(argv[0]))
    print(f"emit_severity_rationale: total={total} annotated={annotated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
