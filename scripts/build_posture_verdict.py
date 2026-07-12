#!/usr/bin/env python3
"""build_posture_verdict.py — Layer-2 systemic posture verdict (P4).

The deterministic join that answers "incidental bugs vs. systemically broken":
per security principle (architectural_theme), fuse the weakness register +
confirmed findings + implementation strategy into a scored
VIOLATED / WEAK / ADEQUATE row. Reads `threat-model.yaml` (threats[] +
weaknesses[]) and `data/posture-rubric.yaml`; writes
`$OUTPUT_DIR/.posture-verdict.json`.

Rubric lives in data/posture-rubric.yaml (versioned, not inline magic numbers —
proposal §7.4). Rendered by compose_threat_model as the "Security Principles"
table + "Top Systemic Risks"; the LLM verdict then narrates this computed row
instead of inventing one.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_json

_HERE = Path(__file__).resolve().parent
_RUBRIC = _HERE.parent / "data" / "posture-rubric.yaml"

_VERDICT_RANK = {"VIOLATED": 0, "WEAK": 1, "ADEQUATE": 2}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _load_rubric() -> dict[str, Any]:
    try:
        import yaml

        doc = yaml.safe_load(_RUBRIC.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — missing/broken rubric → empty (no verdict)
        return {}
    return doc if isinstance(doc, dict) else {}


def _classify_cwe(cwe: str) -> str:
    """weakness_class for a threat CWE, via the shared classifier."""
    try:
        from weakness_classifier import classify_cwe

        return classify_cwe(cwe, warn=False)
    except Exception:  # noqa: BLE001
        return "_unmapped"


def build_posture_verdict(yaml_data: dict, rubric: dict | None = None) -> list[dict]:
    """Return one scored principle row per architectural_theme that has any
    signal. Rows: {theme, label, verdict, confirmed_instances, weakness_ids,
    weakness_classes, strategies, max_component_spread, drivers[]}."""
    rubric = rubric or _load_rubric()
    theme_by_class = rubric.get("theme_by_weakness_class") or {}
    labels = rubric.get("theme_labels") or {}
    scoring = rubric.get("scoring") or {}
    spread_min = int(scoring.get("systemic_spread_min") or 2)
    aggravating = {s.lower() for s in (scoring.get("aggravating_strategies") or ["home-grown", "none"])}
    exculpatory = (scoring.get("exculpatory_strategy") or "standard-vetted").lower()

    def theme_for_class(wcid: str) -> str:
        return theme_by_class.get(wcid) or "InsecureDesign"

    # Aggregate per theme.
    agg: dict[str, dict] = {}

    def bucket(theme: str) -> dict:
        return agg.setdefault(
            theme,
            {
                "confirmed_instances": 0,
                "weakness_ids": [],
                "weakness_classes": set(),
                "strategies": set(),
                "max_spread": 0,
                "pervasive_homegrown": False,
                "worst_severity": "low",
            },
        )

    for w in yaml_data.get("weaknesses") or []:
        if not isinstance(w, dict):
            continue
        wcid = w.get("weakness_class") or "_unmapped"
        theme = theme_for_class(wcid)
        b = bucket(theme)
        b["weakness_ids"].append(w.get("id"))
        b["weakness_classes"].add(wcid)
        strat = (w.get("implementation_strategy") or "").lower()
        if strat:
            b["strategies"].add(strat)
        spread = len(w.get("affected_components") or [])
        b["max_spread"] = max(b["max_spread"], spread)
        n_inst = len(w.get("instances") or [])
        b["confirmed_instances"] += n_inst
        sev = (w.get("severity") or "low").lower()
        if _SEV_RANK.get(sev, 3) < _SEV_RANK.get(b["worst_severity"], 3):
            b["worst_severity"] = sev
        if (
            (w.get("kind") == "design")
            and (strat in aggravating or not strat)
            and spread >= spread_min
        ):
            b["pervasive_homegrown"] = True

    # Confirmed threats NOT already folded under a weakness still count toward
    # the theme (the §4b "control present" row — instances without a weakness).
    folded_ids = {
        (i.get("id") or "").strip().upper()
        for w in (yaml_data.get("weaknesses") or [])
        if isinstance(w, dict)
        for i in (w.get("instances") or [])
        if isinstance(i, dict)
    }
    for t in yaml_data.get("threats") or []:
        if not isinstance(t, dict):
            continue
        # Design-level threats and folded insecure-practice sites must NOT
        # escalate a principle to VIOLATED as "confirmed instances" — their
        # signal already reaches the theme via the weakness loop above.
        # Keep _design_src in sync with _shared_sources.DESIGN_LEVEL_SOURCES.
        _design_src = {
            "requirements-compliance", "known-threats", "architecture-coverage",
            "threat-hypothesis", "architectural-anti-pattern", "coverage-gap",
        }
        if (t.get("source") or "").strip() in _design_src:
            continue
        if (t.get("evidence_tier") or "confirmed-exploitable") == "insecure-practice":
            continue
        tid = (t.get("id") or t.get("t_id") or "").strip().upper()
        if tid and tid in folded_ids:
            continue  # already counted via its weakness's instances[]
        wcid = _classify_cwe(t.get("cwe") or "")
        theme = theme_for_class(wcid)
        b = bucket(theme)
        b["confirmed_instances"] += 1
        b["weakness_classes"].add(wcid)

    rows: list[dict] = []
    for theme, b in agg.items():
        confirmed = b["confirmed_instances"] > 0
        if confirmed or b["pervasive_homegrown"]:
            verdict = "VIOLATED"
        elif b["weakness_ids"] or b["confirmed_instances"]:
            verdict = "WEAK"
        else:
            verdict = "ADEQUATE"
        # An exculpatory vetted control with no confirmed instance softens WEAK.
        if verdict == "WEAK" and exculpatory in b["strategies"] and not confirmed:
            verdict = "ADEQUATE"

        drivers: list[str] = []
        if confirmed:
            drivers.append(f"{b['confirmed_instances']} confirmed-exploitable instance(s)")
        if b["pervasive_homegrown"]:
            drivers.append(f"pervasive home-grown/absent control across {b['max_spread']} components")
        if b["strategies"]:
            drivers.append("strategy: " + ", ".join(sorted(b["strategies"])))
        rows.append(
            {
                "theme": theme,
                "label": labels.get(theme) or theme,
                "verdict": verdict,
                "confirmed_instances": b["confirmed_instances"],
                "weakness_ids": [wid for wid in b["weakness_ids"] if wid],
                "weakness_classes": sorted(b["weakness_classes"]),
                "max_component_spread": b["max_spread"],
                "worst_severity": b["worst_severity"],
                "drivers": drivers,
            }
        )

    # Worst verdict first, then most confirmed instances, then theme name.
    rows.sort(key=lambda r: (_VERDICT_RANK.get(r["verdict"], 9), -r["confirmed_instances"], r["theme"]))
    return rows


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="build_posture_verdict.py", description=__doc__)
    p.add_argument("--output-dir", required=True, help="Run dir with threat-model.yaml.")
    args = p.parse_args(argv)

    out_dir = Path(args.output_dir).resolve()
    yaml_path = out_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"build_posture_verdict: {yaml_path} not found", file=sys.stderr)
        return 1
    import yaml

    yaml_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    rows = build_posture_verdict(yaml_data)
    target = out_dir / ".posture-verdict.json"
    atomic_write_json(target, {"version": 1, "principles": rows}, indent=2)
    print(f"build_posture_verdict: wrote {target} ({len(rows)} principle row(s))")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
