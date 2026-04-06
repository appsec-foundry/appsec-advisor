#!/usr/bin/env python3
"""
validate_intermediate.py — JSON schema validator for appsec-plugin intermediate files.

Can be used in two ways:

  1. As a module:
       from validate_intermediate import validate_dep_scan, validate_stride
       ok, errors = validate_dep_scan(data)

  2. As a CLI tool (called from agent shell steps):
       python3 validate_intermediate.py dep_scan /path/to/.dep-scan.json
       python3 validate_intermediate.py stride   /path/to/.stride-auth.json

Exit codes: 0 = valid, 1 = invalid, 2 = usage error.
Stdout: "VALID: <summary>" or "INVALID: <error list>"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

_DEP_SCAN_TOP = ["scanned_at", "repo_root", "summary", "hardcoded_secrets",
                 "vulnerable_dependencies", "insecure_defaults"]
_DEP_SCAN_SUMMARY = ["hardcoded_secrets", "vulnerable_dependencies", "insecure_defaults"]

_SECRET_FIELDS   = ["file", "line", "type", "snippet", "severity"]
_VULN_DEP_FIELDS = ["manifest", "package", "version_found", "issue", "severity"]
_INSECURE_FIELDS = ["file", "issue", "severity"]

_STRIDE_TOP     = ["component_id", "component_name", "analyzed_at", "threats"]
_THREAT_FIELDS  = ["local_id", "stride", "scenario", "likelihood", "impact", "risk"]

_VALID_STRIDE_CATS = {
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
}
_VALID_LIKELIHOOD = {"High", "Medium", "Low"}
_VALID_IMPACT     = {"Critical", "High", "Medium", "Low"}
_VALID_RISK       = {"Critical", "High", "Medium", "Low"}
_VALID_SEVERITY   = {"Critical", "High", "Medium", "Low"}


def _check_fields(obj: dict, required: list[str], path: str) -> list[str]:
    return [f"{path}: missing required field '{f}'" for f in required if f not in obj]


def validate_dep_scan(data: Any) -> tuple[bool, list[str]]:
    """Validate a parsed .dep-scan.json object. Returns (is_valid, error_list)."""
    errors: list[str] = []

    if not isinstance(data, dict):
        return False, ["root must be a JSON object"]

    errors += _check_fields(data, _DEP_SCAN_TOP, "root")

    # summary sub-object
    if "summary" in data:
        if not isinstance(data["summary"], dict):
            errors.append("root.summary must be an object")
        else:
            errors += _check_fields(data["summary"], _DEP_SCAN_SUMMARY, "summary")
            for k in _DEP_SCAN_SUMMARY:
                if k in data["summary"] and not isinstance(data["summary"][k], int):
                    errors.append(f"summary.{k} must be an integer")

    # hardcoded_secrets array
    secrets = data.get("hardcoded_secrets")
    if secrets is not None:
        if not isinstance(secrets, list):
            errors.append("hardcoded_secrets must be an array")
        else:
            for i, s in enumerate(secrets):
                if not isinstance(s, dict):
                    errors.append(f"hardcoded_secrets[{i}] must be an object")
                    continue
                errors += _check_fields(s, _SECRET_FIELDS, f"hardcoded_secrets[{i}]")
                if "severity" in s and s["severity"] not in _VALID_SEVERITY:
                    errors.append(
                        f"hardcoded_secrets[{i}].severity '{s['severity']}' "
                        f"not in {sorted(_VALID_SEVERITY)}"
                    )

    # vulnerable_dependencies array
    vulns = data.get("vulnerable_dependencies")
    if vulns is not None:
        if not isinstance(vulns, list):
            errors.append("vulnerable_dependencies must be an array")
        else:
            for i, v in enumerate(vulns):
                if not isinstance(v, dict):
                    errors.append(f"vulnerable_dependencies[{i}] must be an object")
                    continue
                errors += _check_fields(v, _VULN_DEP_FIELDS, f"vulnerable_dependencies[{i}]")
                if "severity" in v and v["severity"] not in _VALID_SEVERITY:
                    errors.append(
                        f"vulnerable_dependencies[{i}].severity '{v['severity']}' "
                        f"not in {sorted(_VALID_SEVERITY)}"
                    )

    # insecure_defaults array
    insecure = data.get("insecure_defaults")
    if insecure is not None:
        if not isinstance(insecure, list):
            errors.append("insecure_defaults must be an array")
        else:
            for i, d in enumerate(insecure):
                if not isinstance(d, dict):
                    errors.append(f"insecure_defaults[{i}] must be an object")
                    continue
                errors += _check_fields(d, _INSECURE_FIELDS, f"insecure_defaults[{i}]")

    return len(errors) == 0, errors


def validate_stride(data: Any) -> tuple[bool, list[str]]:
    """Validate a parsed .stride-*.json object. Returns (is_valid, error_list)."""
    errors: list[str] = []

    if not isinstance(data, dict):
        return False, ["root must be a JSON object"]

    # Error stubs (written by agent on validation failure) are always valid —
    # they signal a known failure state to the orchestrator.
    if "parse_error" in data:
        if not isinstance(data.get("threats"), list):
            errors.append("error stub: 'threats' must be an empty array")
        return len(errors) == 0, errors

    errors += _check_fields(data, _STRIDE_TOP, "root")

    threats = data.get("threats")
    if threats is not None:
        if not isinstance(threats, list):
            errors.append("threats must be an array")
        else:
            for i, t in enumerate(threats):
                if not isinstance(t, dict):
                    errors.append(f"threats[{i}] must be an object")
                    continue
                errors += _check_fields(t, _THREAT_FIELDS, f"threats[{i}]")

                if "stride" in t and t["stride"] not in _VALID_STRIDE_CATS:
                    errors.append(
                        f"threats[{i}].stride '{t['stride']}' "
                        f"not in valid STRIDE categories"
                    )
                if "likelihood" in t and t["likelihood"] not in _VALID_LIKELIHOOD:
                    errors.append(
                        f"threats[{i}].likelihood '{t['likelihood']}' "
                        f"not in {sorted(_VALID_LIKELIHOOD)}"
                    )
                if "impact" in t and t["impact"] not in _VALID_IMPACT:
                    errors.append(
                        f"threats[{i}].impact '{t['impact']}' "
                        f"not in {sorted(_VALID_IMPACT)}"
                    )
                if "risk" in t and t["risk"] not in _VALID_RISK:
                    errors.append(
                        f"threats[{i}].risk '{t['risk']}' "
                        f"not in {sorted(_VALID_RISK)}"
                    )

    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

_VALIDATORS = {
    "dep_scan": validate_dep_scan,
    "stride":   validate_stride,
}


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in _VALIDATORS:
        print(f"Usage: {sys.argv[0]} <dep_scan|stride> <path-to-json-file>", file=sys.stderr)
        sys.exit(2)

    schema_type = sys.argv[1]
    path = Path(sys.argv[2])

    try:
        with path.open() as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"INVALID JSON: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"INVALID: cannot read file: {e}")
        sys.exit(1)

    is_valid, errors = _VALIDATORS[schema_type](data)

    if is_valid:
        n_threats = len(data.get("threats", [])) if schema_type == "stride" else None
        summary = f"{n_threats} threats" if n_threats is not None else "ok"
        print(f"VALID: {summary}")
        sys.exit(0)
    else:
        for e in errors:
            print(f"INVALID: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
