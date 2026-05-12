#!/usr/bin/env python3
"""
export_sarif.py — generate `threat-model.sarif.json` (SARIF v2.1.0)
deterministically from a `threat-model.yaml` export.

Replaces the previous LLM-authored SARIF write in
`agents/appsec-threat-analyst.md`. The yaml is the single source of truth;
the SARIF shape and CVSS / mitigation / location handling rules are pinned
in `agents/appsec-threat-analyst.md:524-608` and reproduced verbatim here.

CLI:

    python3 export_sarif.py \
        --threat-model $OUTPUT_DIR/threat-model.yaml \
        --output       $OUTPUT_DIR/threat-model.sarif.json

Exit codes: 0 success, 1 yaml not found, 2 schema-invalid yaml, 3 write error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main"
    "/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "appsec-advisor"
DEFAULT_TOOL_VERSION = "0.9.0-beta"

RISK_TO_LEVEL = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
}

_SENTENCE_BREAK = re.compile(r"(?<=[.!?])\s+")
_SLUG = re.compile(r"[^a-z0-9]+")


def _slugify(text: str, max_len: int = 40) -> str:
    s = _SLUG.sub("-", (text or "").lower()).strip("-")
    return s[:max_len] or "unnamed"


def _first_sentence(text: str) -> str:
    if not text:
        return ""
    parts = _SENTENCE_BREAK.split(text.strip(), maxsplit=1)
    return parts[0].strip() if parts else text.strip()


def _evidence_entries(threat: dict) -> list[dict]:
    """Normalise `evidence` to a list. The canonical yaml schema declares it as
    `array[object]`, but legacy producers still emit a single dict; accept
    both."""
    ev = threat.get("evidence")
    if isinstance(ev, list):
        return [e for e in ev if isinstance(e, dict) and e.get("file")]
    if isinstance(ev, dict) and ev.get("file"):
        return [ev]
    return []


def _mitigation_ids(threat: dict) -> list[str]:
    """Return mitigation IDs from the canonical `mitigation_ids` field, or the
    legacy `mitigations` field used by older fixtures."""
    raw = threat.get("mitigation_ids") or threat.get("mitigations") or []
    if not isinstance(raw, list):
        return []
    return [m for m in raw if isinstance(m, str) and m.startswith("M-")]


def _threat_id(threat: dict) -> str | None:
    """Canonical field is `id` (T-NNN or F-NNN). Legacy fixtures use `t_id`."""
    for key in ("id", "t_id"):
        v = threat.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _help_uri(threat: dict, mitigations_by_id: dict[str, dict]) -> str | None:
    direct = threat.get("remediation_reference")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    for mid in _mitigation_ids(threat):
        m = mitigations_by_id.get(mid)
        if not m:
            continue
        ref = m.get("reference")
        if isinstance(ref, str) and ref.strip():
            return ref.strip()
    return None


def _build_rule(threat: dict, mitigations_by_id: dict[str, dict]) -> dict:
    tid = _threat_id(threat)
    stride = threat.get("stride") or threat.get("stride_category") or ""
    title = threat.get("title") or ""
    scenario = threat.get("scenario") or ""
    risk = threat.get("risk") or threat.get("severity")

    rule: dict[str, Any] = {
        "id":   tid,
        "name": f"{stride}/{_slugify(title)}" if stride else _slugify(title),
        "shortDescription": {"text": _first_sentence(scenario) or title or tid},
        "fullDescription":  {"text": scenario or title or tid},
        "defaultConfiguration": {"level": RISK_TO_LEVEL.get(risk, "warning")},
        "properties": {
            "tags": ["security", (stride or "").lower()] if stride else ["security"],
            "stride":     stride or None,
            "likelihood": threat.get("likelihood"),
            "impact":     threat.get("impact"),
            "risk":       risk,
        },
    }

    help_uri = _help_uri(threat, mitigations_by_id)
    if help_uri:
        rule["helpUri"] = help_uri

    cwe = threat.get("cwe")
    if isinstance(cwe, str) and cwe.strip():
        rule["properties"]["cwe"] = cwe.strip()

    cvss = threat.get("cvss_v4")
    if isinstance(cvss, dict):
        score = cvss.get("base_score")
        vector = cvss.get("vector")
        version = "4.0" if (isinstance(vector, str) and vector.startswith("CVSS:4")) else cvss.get("version_fallback")
        if score is not None:
            rule["properties"]["security-severity"] = f"{float(score):.1f}"
        if isinstance(vector, str) and vector.strip():
            rule["properties"]["cvss-v4-vector"] = vector.strip()
        if version:
            rule["properties"]["cvss-version"] = str(version)

    # Drop null property values so the SARIF stays clean.
    rule["properties"] = {k: v for k, v in rule["properties"].items() if v is not None}
    return rule


def _build_result(threat: dict, mitigations_by_id: dict[str, dict]) -> dict:
    tid = _threat_id(threat)
    risk = threat.get("risk") or threat.get("severity")
    scenario = threat.get("scenario") or threat.get("title") or tid

    result: dict[str, Any] = {
        "ruleId":  tid,
        "level":   RISK_TO_LEVEL.get(risk, "warning"),
        "message": {"text": scenario},
    }

    locations: list[dict] = []
    for ev in _evidence_entries(threat):
        line = ev.get("line")
        physical: dict[str, Any] = {
            "artifactLocation": {
                "uri":       ev["file"],
                "uriBaseId": "%SRCROOT%",
            }
        }
        if isinstance(line, int) and line > 0:
            physical["region"] = {"startLine": line}
        else:
            physical["region"] = {"startLine": 1}
        locations.append({"physicalLocation": physical})
    if locations:
        result["locations"] = locations

    mids = _mitigation_ids(threat)
    if mids:
        fixes: list[dict] = []
        for mid in mids:
            m = mitigations_by_id.get(mid)
            if not m:
                continue
            title = m.get("title") or m.get("mitigation_title")
            if isinstance(title, str) and title.strip():
                fixes.append({"description": {"text": title.strip()}})
        if fixes:
            result["fixes"] = fixes
        result["properties"] = {"mitigationIds": mids}

    return result


def build_sarif(
    data: dict,
    tool_version: str = DEFAULT_TOOL_VERSION,
) -> dict:
    threats = [t for t in (data.get("threats") or []) if isinstance(t, dict)]
    mitigations = [m for m in (data.get("mitigations") or []) if isinstance(m, dict)]
    mitigations_by_id: dict[str, dict] = {}
    for m in mitigations:
        mid = m.get("id") or m.get("m_id")
        if isinstance(mid, str):
            mitigations_by_id[mid] = m

    rules: list[dict] = []
    results: list[dict] = []
    seen_rule_ids: set[str] = set()
    for threat in threats:
        tid = _threat_id(threat)
        if not tid:
            continue
        if tid not in seen_rule_ids:
            rules.append(_build_rule(threat, mitigations_by_id))
            seen_rule_ids.add(tid)
        results.append(_build_result(threat, mitigations_by_id))

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            TOOL_NAME,
                        "version":         tool_version,
                        "semanticVersion": tool_version,
                        "rules":           rules,
                    }
                },
                "results":    results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--threat-model", required=True,
                   help="Path to threat-model.yaml")
    p.add_argument("--output", required=True,
                   help="Destination threat-model.sarif.json")
    p.add_argument("--tool-version", default=None,
                   help=f"Tool version string (default: {DEFAULT_TOOL_VERSION} "
                        f"or meta.plugin_version when present in yaml)")
    args = p.parse_args()

    yaml_path = Path(args.threat_model)
    if not yaml_path.is_file():
        print(f"ERROR: threat-model.yaml not found: {yaml_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with yaml_path.open() as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"ERROR: cannot parse threat-model.yaml: {e}", file=sys.stderr)
        sys.exit(2)

    if not isinstance(data, dict):
        print("ERROR: threat-model.yaml root is not a mapping", file=sys.stderr)
        sys.exit(2)

    tool_version = args.tool_version
    if not tool_version:
        meta = data.get("meta") or {}
        if isinstance(meta, dict):
            tool_version = meta.get("plugin_version") or DEFAULT_TOOL_VERSION
        else:
            tool_version = DEFAULT_TOOL_VERSION

    sarif = build_sarif(data, tool_version=tool_version)

    out_path = Path(args.output)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError as e:
        print(f"ERROR: cannot write SARIF output: {e}", file=sys.stderr)
        sys.exit(3)

    n_rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])
    n_results = len(sarif["runs"][0]["results"])
    print(
        f"VALID: wrote SARIF v{SARIF_VERSION} with {n_rules} rules and "
        f"{n_results} results → {out_path}"
    )


if __name__ == "__main__":
    main()
