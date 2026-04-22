#!/usr/bin/env python3
"""
triage_validate_ratings.py — deterministic pre-flight validation for
`.threats-merged.json` before the triage-validator agent runs.

Replaces Steps 1–5 of the `appsec-triage-validator` agent with fast,
model-free Python checks. The agent retains Step 6 (breach-distance
inference, compound-chain detection, effective-severity computation,
ranking) which genuinely requires LLM reasoning.

Checks performed:
  1. Cross-component consistency   — same CWE across 2+ components, 2+ level diff
  2. Severity plausibility         — CWE-based must-be-at-least-High rules
  3. Priority validation (P1/P2)   — Critical RCE/injection on public files
  4. Rating completeness           — mandatory fields + Likelihood×Impact matrix
  5. CVSS scope validation         — eligibility list + required/forbidden rules

Output:
  Appends flags into `$OUTPUT_DIR/.triage-flags.json` (creating it if absent,
  preserving existing flags if present). Exits 0 on success (including when
  flags are found), 1 on a fatal error (unreadable input, missing output).

Usage:
  python3 triage_validate_ratings.py <output_dir> [--depth quick|standard|thorough]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_VALID_RISK = frozenset({"Critical", "High", "Medium", "Low"})
_VALID_LIKELIHOOD = frozenset({"Critical", "High", "Medium", "Low"})
_VALID_IMPACT = frozenset({"Critical", "High", "Medium", "Low"})
_VALID_STRIDE = frozenset({
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
})
_VALID_SOURCES = frozenset({
    "stride", "requirements-compliance", "architectural-anti-pattern",
    "known-vuln", "dep-scan", "coverage-gap",
})
_CVSS_REQUIRED_SOURCES = frozenset({"dep-scan", "known-vuln"})
_CVSS_FORBIDDEN_SOURCES = frozenset({
    "requirements-compliance", "architectural-anti-pattern", "coverage-gap",
})

# Likelihood × Impact → expected Risk
_RISK_MATRIX: dict[tuple[str, str], str] = {
    ("High",   "Low"):      "Medium",
    ("High",   "Medium"):   "High",
    ("High",   "High"):     "Critical",
    ("High",   "Critical"): "Critical",
    ("Medium", "Low"):      "Low",
    ("Medium", "Medium"):   "Medium",
    ("Medium", "High"):     "High",
    ("Medium", "Critical"): "Critical",
    ("Low",    "Low"):      "Low",
    ("Low",    "Medium"):   "Low",
    ("Low",    "High"):     "Medium",
    ("Low",    "Critical"): "High",
}

# CWEs where evidence on a public-facing file → minimum High
_MUST_BE_HIGH_CWES = frozenset({"CWE-78", "CWE-89", "CWE-94", "CWE-502", "CWE-798"})

# CWEs that are in the RCE/injection family (for P1 inference)
_RCE_INJECTION_CWES = frozenset({"CWE-78", "CWE-89", "CWE-94", "CWE-502"})

_T_ID_RE = re.compile(r"^T-\d{3,}$")
_CWE_RE  = re.compile(r"^CWE-\d+$")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_diff(a: str, b: str) -> int:
    """Absolute difference in severity levels between two risk strings."""
    return abs(_SEVERITY_RANK.get(a, 0) - _SEVERITY_RANK.get(b, 0))


def _load_cvss_eligible(plugin_root: Path | None) -> frozenset[str]:
    if plugin_root is None:
        return frozenset()
    path = plugin_root / "data" / "cvss-eligible-cwes.yaml"
    if not path.exists():
        return frozenset()
    try:
        import yaml
        with path.open() as f:
            doc = yaml.safe_load(f) or {}
        entries = doc.get("eligible_cwes") or []
        return frozenset(e["cwe"] for e in entries if isinstance(e, dict) and "cwe" in e)
    except Exception:
        return frozenset()


def _resolve_plugin_root(output_dir: Path) -> Path | None:
    """Walk up from output_dir looking for appsec-advisor root."""
    candidate = output_dir
    for _ in range(8):
        if (candidate / "scripts" / "triage_validate_ratings.py").exists():
            return candidate
        candidate = candidate.parent
    return None


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------

def _step1_cross_component_consistency(
    threats: list[dict], depth: str
) -> list[dict]:
    """Step 1: Flag same CWE with 2+ severity level difference across components."""
    flags: list[dict] = []
    by_cwe: dict[str, list[dict]] = {}
    for t in threats:
        cwe = t.get("cwe", "")
        if cwe:
            by_cwe.setdefault(cwe, []).append(t)

    for cwe, group in by_cwe.items():
        if len(group) < 2:
            continue
        # Compare all pairs
        for i, ta in enumerate(group):
            for tb in group[i + 1:]:
                risk_a = ta.get("risk", "")
                risk_b = tb.get("risk", "")
                if _severity_diff(risk_a, risk_b) < 2:
                    continue
                # Skip if one has architectural_violation (escalation is expected)
                if ta.get("architectural_violation") or tb.get("architectural_violation"):
                    continue
                # Skip if different source types
                if ta.get("source") != tb.get("source"):
                    continue
                # Flag
                flags.append({
                    "type": "consistency",
                    "severity": "warning",
                    "threat_ids": [ta.get("t_id", "?"), tb.get("t_id", "?")],
                    "message": (
                        f"{cwe} has a {_severity_diff(risk_a, risk_b)}-level severity difference "
                        f"across components: {ta.get('component_id', '?')} ({risk_a}) vs "
                        f"{tb.get('component_id', '?')} ({risk_b}) without architectural_violation."
                    ),
                    "suggested_action": (
                        "Review whether the context difference justifies the severity gap, "
                        "or set architectural_violation:true on the higher-severity instance."
                    ),
                })

    # Title-pattern consistency (standard/thorough only)
    if depth in ("standard", "thorough"):
        by_stride_title: dict[str, list[dict]] = {}
        for t in threats:
            key = f"{t.get('stride','')}|{(t.get('title','') or '').lower()[:30]}"
            by_stride_title.setdefault(key, []).append(t)
        for _, group in by_stride_title.items():
            if len(group) < 2:
                continue
            for i, ta in enumerate(group):
                for tb in group[i + 1:]:
                    if ta.get("component_id") == tb.get("component_id"):
                        continue
                    ra, rb = ta.get("risk", ""), tb.get("risk", "")
                    if _severity_diff(ra, rb) >= 2:
                        if not ta.get("architectural_violation") and not tb.get("architectural_violation"):
                            flags.append({
                                "type": "consistency",
                                "severity": "warning",
                                "threat_ids": [ta.get("t_id", "?"), tb.get("t_id", "?")],
                                "message": (
                                    f"Similar {ta.get('stride','')} threats across components have "
                                    f"{_severity_diff(ra, rb)}-level severity gap: "
                                    f"{ta.get('title','')[:40]!r} — {ta.get('component_id','?')} ({ra}) "
                                    f"vs {tb.get('component_id','?')} ({rb})."
                                ),
                                "suggested_action": "Verify whether the context difference justifies the gap.",
                            })
    return flags


def _step2_severity_plausibility(
    threats: list[dict], depth: str
) -> list[dict]:
    """Step 2: CWE-based must-be-at-least-High and should-not-be-Critical rules."""
    if depth == "quick":
        return []

    flags: list[dict] = []
    for t in threats:
        cwe  = t.get("cwe", "")
        risk = t.get("risk", "")
        tid  = t.get("t_id", "?")
        stride   = t.get("stride", "")
        source   = t.get("source", "")
        evidence = t.get("evidence") or {}
        ev_file  = evidence.get("file", "") if isinstance(evidence, dict) else ""

        # Must be at least High
        if cwe in _MUST_BE_HIGH_CWES and ev_file and _SEVERITY_RANK.get(risk, 0) < _SEVERITY_RANK["High"]:
            flags.append({
                "type": "plausibility",
                "severity": "warning",
                "threat_ids": [tid],
                "message": (
                    f"{cwe} with evidence on file '{ev_file}' should be at least High, "
                    f"but risk is {risk}."
                ),
                "suggested_action": f"Elevate {tid} to High or provide justification for {risk} rating.",
            })

        # known-vuln + Elevation of Privilege → minimum High
        if source == "known-vuln" and stride == "Elevation of Privilege" and _SEVERITY_RANK.get(risk, 0) < _SEVERITY_RANK["High"]:
            flags.append({
                "type": "plausibility",
                "severity": "warning",
                "threat_ids": [tid],
                "message": (
                    f"known-vuln threat with Elevation of Privilege should be at least High, "
                    f"but risk is {risk}."
                ),
                "suggested_action": f"Elevate {tid} to High or provide justification.",
            })

        # Should not be Critical: Repudiation (logging gaps)
        if stride == "Repudiation" and risk == "Critical":
            flags.append({
                "type": "plausibility",
                "severity": "info",
                "threat_ids": [tid],
                "message": (
                    f"Repudiation threat rated Critical — logging gaps are rarely Critical "
                    f"unless they enable active cover-up of ongoing attacks."
                ),
                "suggested_action": "Consider whether High is more appropriate for a logging gap.",
            })

        # Should not be Critical: Info Disclosure behind auth without architectural_violation
        if (stride == "Information Disclosure"
                and risk == "Critical"
                and not t.get("architectural_violation")
                and ev_file
                and any(seg in ev_file.lower() for seg in ("admin", "internal", "mgmt", "management"))):
            flags.append({
                "type": "plausibility",
                "severity": "info",
                "threat_ids": [tid],
                "message": (
                    f"Information Disclosure on an apparent admin/internal path rated Critical "
                    f"without architectural_violation flag."
                ),
                "suggested_action": "Confirm the endpoint is unauthenticated or set architectural_violation:true.",
            })

    return flags


def _step3_priority_validation(
    threats: list[dict], depth: str
) -> list[dict]:
    """Step 3: P1/P2 alignment checks."""
    if depth == "quick":
        return []

    flags: list[dict] = []
    criticals = [t for t in threats if t.get("risk") == "Critical"]
    highs = [t for t in threats if t.get("risk") == "High"]

    # known-vuln Critical → P1 candidate — just informational
    for t in criticals:
        if t.get("source") == "known-vuln":
            flags.append({
                "type": "priority",
                "severity": "info",
                "threat_ids": [t.get("t_id", "?")],
                "message": (
                    f"{t.get('t_id','?')} is a known-vuln Critical — P1 candidate "
                    f"(active exploit potential)."
                ),
                "suggested_action": "Ensure this is listed first in the Immediate Actions table.",
            })

    # Critical RCE/injection not the highest-risk item (only when thorough)
    if depth == "thorough" and criticals and highs:
        rce_criticals = [
            t for t in criticals
            if t.get("cwe", "") in _RCE_INJECTION_CWES
        ]
        if rce_criticals:
            # Check if any non-RCE threat has same or higher assigned sort position
            # Heuristic: compare t_id sequence (T-001 = highest priority after sort)
            def t_num(t: dict) -> int:
                m = _T_ID_RE.match(t.get("t_id", "T-999"))
                return int(m.group(0).split("-")[1]) if m else 999

            lowest_rce = min(t_num(t) for t in rce_criticals)
            highest_non_rce = min(
                (t_num(t) for t in criticals if t.get("cwe", "") not in _RCE_INJECTION_CWES),
                default=lowest_rce + 1,
            )
            if highest_non_rce < lowest_rce:
                flags.append({
                    "type": "priority",
                    "severity": "warning",
                    "threat_ids": [t.get("t_id", "?") for t in rce_criticals],
                    "message": (
                        "RCE/injection Critical threats are not the highest-ranked items. "
                        "These should typically be P1."
                    ),
                    "suggested_action": "Review sort order — RCE/injection Criticals should lead the register.",
                })

    # Informational: no Criticals but multiple Highs
    if not criticals and len(highs) >= 3:
        flags.append({
            "type": "priority",
            "severity": "info",
            "threat_ids": [],
            "message": (
                f"No Critical threats found, but {len(highs)} High threats present. "
                f"None qualify for P1."
            ),
            "suggested_action": "Confirm P1 is not applicable; ensure High threats are tracked as P2.",
        })

    return flags


def _step4_rating_completeness(threats: list[dict]) -> list[dict]:
    """Step 4: Mandatory fields + Likelihood×Impact matrix coherence."""
    flags: list[dict] = []

    for t in threats:
        tid = t.get("t_id", "?")
        issues: list[str] = []

        # Mandatory field checks
        t_id_val = t.get("t_id")
        if not t_id_val or not _T_ID_RE.match(str(t_id_val)):
            issues.append("t_id missing or does not match T-NNN pattern")

        if not t.get("component_id"):
            issues.append("component_id missing")

        stride_val = t.get("stride")
        if stride_val not in _VALID_STRIDE:
            issues.append(f"stride '{stride_val}' is not a valid STRIDE value")

        risk_val = t.get("risk")
        if risk_val not in _VALID_RISK:
            issues.append(f"risk '{risk_val}' is not valid (expected Critical/High/Medium/Low)")

        likelihood_val = t.get("likelihood")
        if likelihood_val not in _VALID_LIKELIHOOD:
            issues.append(f"likelihood '{likelihood_val}' is not valid")

        impact_val = t.get("impact")
        if impact_val not in _VALID_IMPACT:
            issues.append(f"impact '{impact_val}' is not valid")

        cwe_val = t.get("cwe")
        if not cwe_val or not _CWE_RE.match(str(cwe_val)):
            issues.append("cwe missing or does not match CWE-NNN pattern")

        evidence = t.get("evidence")
        if not isinstance(evidence, dict) or not evidence.get("file"):
            issues.append("evidence.file missing or evidence is not an object")

        source_val = t.get("source")
        if source_val not in _VALID_SOURCES:
            issues.append(f"source '{source_val}' is not a valid source type")

        if issues:
            flags.append({
                "type": "completeness",
                "severity": "warning",
                "threat_ids": [tid],
                "message": f"Field validation failed for {tid}: {'; '.join(issues)}.",
                "suggested_action": "Fix the listed field issues before finalization.",
            })
            continue  # skip matrix check if fields are invalid

        # Likelihood×Impact matrix coherence
        # Skip 'Critical' likelihood — only High/Medium/Low appear in the matrix as row keys
        lh_for_matrix = likelihood_val if likelihood_val in ("High", "Medium", "Low") else None
        if lh_for_matrix:
            expected_risk = _RISK_MATRIX.get((lh_for_matrix, impact_val))
            if expected_risk and risk_val != expected_risk and not t.get("architectural_violation"):
                flags.append({
                    "type": "completeness",
                    "severity": "warning",
                    "threat_ids": [tid],
                    "message": (
                        f"{tid}: risk={risk_val} does not match Likelihood×Impact matrix "
                        f"({likelihood_val}×{impact_val} → expected {expected_risk}). "
                        f"No architectural_violation flag set."
                    ),
                    "suggested_action": (
                        "Adjust risk to match the matrix, or set architectural_violation:true "
                        "to document the intentional escalation."
                    ),
                })

    return flags


def _step5_cvss_scope(
    threats: list[dict], eligible_cwes: frozenset[str], depth: str
) -> list[dict]:
    """Step 5: CVSS v4 eligibility rules."""
    flags: list[dict] = []
    _CVSS_BAND = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    _RISK_BAND = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    for t in threats:
        tid    = t.get("t_id", "?")
        source = t.get("source", "")
        cvss   = t.get("cvss_v4")
        has_cvss = isinstance(cvss, dict)
        cwe    = t.get("cwe", "")
        evidence = t.get("evidence") or {}
        ev_line  = evidence.get("line") if isinstance(evidence, dict) else None
        risk   = t.get("risk", "")

        # Required
        if source in _CVSS_REQUIRED_SOURCES and not has_cvss:
            flags.append({
                "type": "cvss_missing",
                "severity": "warning",
                "threat_ids": [tid],
                "message": f"{tid}: cvss_v4 is required for source='{source}' but is absent.",
                "suggested_action": "Add CVSS v4.0 vector for this threat.",
            })
            continue

        # Forbidden
        if source in _CVSS_FORBIDDEN_SOURCES and has_cvss:
            flags.append({
                "type": "cvss_scope_violation",
                "severity": "warning",
                "threat_ids": [tid],
                "message": (
                    f"{tid}: cvss_v4 is not permitted for source='{source}' "
                    f"(design/policy/coverage gaps are not CVSS-scorable)."
                ),
                "suggested_action": "Remove cvss_v4 from this threat.",
            })
            continue

        # Stride eligibility
        if source == "stride" and has_cvss:
            if eligible_cwes and cwe not in eligible_cwes:
                flags.append({
                    "type": "cvss_scope_violation",
                    "severity": "warning",
                    "threat_ids": [tid],
                    "message": (
                        f"{tid}: cvss_v4 present for stride source but {cwe} "
                        f"is not in cvss-eligible-cwes.yaml."
                    ),
                    "suggested_action": "Remove cvss_v4 or add the CWE to cvss-eligible-cwes.yaml.",
                })
            if ev_line is None:
                flags.append({
                    "type": "cvss_scope_violation",
                    "severity": "warning",
                    "threat_ids": [tid],
                    "message": (
                        f"{tid}: cvss_v4 present for stride source but evidence.line is null. "
                        f"CVSS requires a concrete code location."
                    ),
                    "suggested_action": "Set evidence.line to the specific line number.",
                })

        # Band mismatch (standard/thorough)
        if has_cvss and depth in ("standard", "thorough"):
            sev = (cvss or {}).get("severity", "")
            if sev in _CVSS_BAND and risk in _RISK_BAND:
                cvss_band = max(_CVSS_BAND[sev], 1)
                if abs(cvss_band - _RISK_BAND[risk]) >= 2:
                    flags.append({
                        "type": "cvss_band_mismatch",
                        "severity": "info",
                        "threat_ids": [tid],
                        "message": (
                            f"{tid}: cvss_v4.severity='{sev}' is more than one band "
                            f"away from risk='{risk}'."
                        ),
                        "suggested_action": "Review CVSS score or risk rating for consistency.",
                    })

    return flags


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", help="Path to $OUTPUT_DIR")
    parser.add_argument(
        "--depth",
        choices=("quick", "standard", "thorough"),
        default="standard",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir).resolve()
    depth = args.depth

    threats_file = output_dir / ".threats-merged.json"
    flags_file   = output_dir / ".triage-flags.json"

    print(f"[triage-pre] ▶ Pre-flight rating validation  (depth: {depth})")
    print(f"  ↳ Input: {threats_file}")

    if not threats_file.exists():
        print(f"[triage-pre] ✗ {threats_file} not found — aborting", file=sys.stderr)
        return 1

    try:
        with threats_file.open() as f:
            merged = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[triage-pre] ✗ Failed to read {threats_file}: {e}", file=sys.stderr)
        return 1

    threats: list[dict] = merged.get("threats") or []
    print(f"  ↳ Threats loaded: {len(threats)}")

    plugin_root = _resolve_plugin_root(output_dir)
    eligible_cwes = _load_cvss_eligible(plugin_root)

    all_flags: list[dict] = []

    print(f"[triage-pre]   ↳ Step 1/5 — Cross-component consistency check…")
    all_flags.extend(_step1_cross_component_consistency(threats, depth))

    print(f"[triage-pre]   ↳ Step 2/5 — Severity plausibility check…")
    all_flags.extend(_step2_severity_plausibility(threats, depth))

    print(f"[triage-pre]   ↳ Step 3/5 — Priority validation (P1/P2 rules)…")
    all_flags.extend(_step3_priority_validation(threats, depth))

    print(f"[triage-pre]   ↳ Step 4/5 — Rating completeness check…")
    all_flags.extend(_step4_rating_completeness(threats))

    print(f"[triage-pre]   ↳ Step 5/5 — CVSS scope validation…")
    all_flags.extend(_step5_cvss_scope(threats, eligible_cwes, depth))

    # ------------------------------------------------------------------
    # Load or create .triage-flags.json and merge new flags in
    # ------------------------------------------------------------------
    existing: dict[str, Any] = {}
    if flags_file.exists():
        try:
            with flags_file.open() as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = {}

    existing_flags: list[dict] = existing.get("flags") or []

    # Assign sequential TF-NNN IDs starting after the last existing one
    next_id = 1
    for ef in existing_flags:
        fid = ef.get("flag_id", "")
        m = re.match(r"^TF-(\d+)$", fid)
        if m:
            next_id = max(next_id, int(m.group(1)) + 1)

    for flag in all_flags:
        flag["flag_id"] = f"TF-{next_id:03d}"
        flag.setdefault("source", "triage-pre-flight")
        next_id += 1

    combined_flags = existing_flags + all_flags

    warnings = sum(1 for f in combined_flags if f.get("severity") == "warning")
    info_cnt  = sum(1 for f in combined_flags if f.get("severity") == "info")
    threats_with_flags: set[str] = set()
    for f in combined_flags:
        threats_with_flags.update(f.get("threat_ids") or [])

    output: dict[str, Any] = {
        "version": existing.get("version", 1),
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "flags": combined_flags,
        "summary": {
            "total_flags": len(combined_flags),
            "warnings": warnings,
            "info": info_cnt,
            "threats_reviewed": len(threats),
            "pre_flight_flags": len(all_flags),
        },
    }
    # Preserve ranking block if already present
    if "ranking" in existing:
        output["ranking"] = existing["ranking"]

    try:
        with flags_file.open("w") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
    except OSError as e:
        print(f"[triage-pre] ✗ Failed to write {flags_file}: {e}", file=sys.stderr)
        return 1

    new_w = sum(1 for f in all_flags if f.get("severity") == "warning")
    new_i = sum(1 for f in all_flags if f.get("severity") == "info")
    print(
        f"[triage-pre] ✓ Pre-flight validation complete — "
        f"{len(all_flags)} new flags ({new_w} warnings, {new_i} info) "
        f"across {len(threats)} threats"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
