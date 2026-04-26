#!/usr/bin/env python3
"""
validate_intermediate.py — schema validator for appsec-advisor intermediate files.

Structural validation is driven by the YAML JSONSchema contracts in
`schemas/` (single source of truth). Custom invariants that JSONSchema
Draft 2020-12 cannot express are enforced as Python post-checks:

  - Sequential T-NNN ordering and uniqueness in `.threats-merged.json`
  - Snippet redaction rule on `hardcoded_secrets[].snippet`
  - Trimmed length >= 10 chars on stride `scenario`

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
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"

_SCHEMA_FILES = {
    "dep_scan":            "dep-scan.schema.yaml",
    "stride":              "stride.schema.yaml",
    "threats_merged":      "threats-merged.schema.yaml",
    "triage_flags":        "triage-flags.schema.yaml",
    "threat_model_output": "threat-model.output.schema.yaml",
    "known_threats":       "known-threats.schema.yaml",
    "pentest_tasks":       "pentest-tasks.schema.yaml",
}


@lru_cache(maxsize=None)
def _load_schema(kind: str) -> dict:
    path = _SCHEMAS_DIR / _SCHEMA_FILES[kind]
    with path.open() as f:
        return yaml.safe_load(f)


def _validator(kind: str) -> Draft202012Validator:
    # Build a fresh validator per call so tests that patch the schema don't
    # hit stale state; the schema dict itself is LRU-cached.
    return Draft202012Validator(_load_schema(kind))


def _format_error_path(err) -> str:
    parts: list[str] = []
    for p in err.absolute_path:
        if isinstance(p, int):
            parts.append(f"[{p}]")
        else:
            parts.append(f".{p}" if parts else str(p))
    return "".join(parts) or "root"


def _schema_errors(kind: str, data: Any) -> list[str]:
    errs = []
    for e in _validator(kind).iter_errors(data):
        errs.append(f"{_format_error_path(e)}: {e.message}")
    return errs


# ---------------------------------------------------------------------------
# Post-check invariants (not expressible in Draft 2020-12)
# ---------------------------------------------------------------------------

_VALID_SEVERITY = {"Critical", "High", "Medium", "Low"}
_T_ID_RE = re.compile(r"^T-(\d{3,})$")
_TF_ID_RE = re.compile(r"^TF-(\d{3,})$")
_PT_ID_RE = re.compile(r"^PT-(\d{3,})$")
_CWE_RE = re.compile(r"^CWE-(\d+)$")

# Sources for which a CVSS v4 vector is required rather than optional.
_CVSS_REQUIRED_SOURCES = {"dep-scan", "known-vuln"}
# Sources for which a CVSS v4 vector MUST NOT be attached — these describe
# design/policy/coverage gaps that cannot be honestly scored on the CVSS
# Base metrics.
_CVSS_FORBIDDEN_SOURCES = {
    "requirements-compliance",
    "architectural-anti-pattern",
    "coverage-gap",
}
# CVSS severity band → risk-level mapping (used for cross-field coherence).
_CVSS_BAND = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_RISK_BAND = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


@lru_cache(maxsize=1)
def _eligible_cwes() -> frozenset[str]:
    """Load the CVSS eligibility positive list. Cached — the file is small
    and loaded once per process."""
    path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "cvss-eligible-cwes.yaml"
    )
    try:
        with path.open() as f:
            doc = yaml.safe_load(f) or {}
    except OSError:
        return frozenset()
    entries = doc.get("eligible_cwes") or []
    return frozenset(
        e["cwe"] for e in entries if isinstance(e, dict) and "cwe" in e
    )


def _check_cvss_eligibility(data: dict) -> list[str]:
    """Enforce CVSS v4 eligibility rules on merged threats:

      * source in {dep-scan, known-vuln}  → cvss_v4 required
      * source == stride                   → allowed iff CWE in positive
                                             list AND evidence.line set
      * source in {requirements-compliance,
                   architectural-anti-pattern,
                   coverage-gap}           → forbidden

    Also verifies that cvss.severity is within one band of the threat's
    risk rating — a larger gap indicates inconsistent scoring.
    """
    errors: list[str] = []
    eligible = _eligible_cwes()
    for i, t in enumerate(data.get("threats", []) or []):
        if not isinstance(t, dict):
            continue
        source = t.get("source")
        cvss = t.get("cvss_v4")
        has_cvss = isinstance(cvss, dict)

        if source in _CVSS_REQUIRED_SOURCES and not has_cvss:
            errors.append(
                f"threats[{i}].cvss_v4 is required for source='{source}'"
            )
            continue

        if source in _CVSS_FORBIDDEN_SOURCES and has_cvss:
            errors.append(
                f"threats[{i}].cvss_v4 is not permitted for "
                f"source='{source}' (design/policy gaps are not CVSS-scorable)"
            )
            continue

        if source == "stride" and has_cvss:
            cwe = t.get("cwe")
            evidence = t.get("evidence") or {}
            line = evidence.get("line") if isinstance(evidence, dict) else None
            if not isinstance(cwe, str) or not _CWE_RE.match(cwe):
                errors.append(
                    f"threats[{i}].cvss_v4 requires a valid CWE reference"
                )
            elif cwe not in eligible:
                errors.append(
                    f"threats[{i}].cvss_v4 is not permitted for {cwe} "
                    f"(not in cvss-eligible-cwes.yaml)"
                )
            if line is None:
                errors.append(
                    f"threats[{i}].cvss_v4 requires evidence.line "
                    f"(concrete code location)"
                )

        if has_cvss:
            sev = cvss.get("severity")
            risk = t.get("risk")
            if sev in _CVSS_BAND and risk in _RISK_BAND:
                # Map CVSS "None" to risk band 1 (Low) for the gap check —
                # None severity on a real threat row is itself suspicious
                # but handled as a separate plausibility concern.
                cvss_band = max(_CVSS_BAND[sev], 1)
                if abs(cvss_band - _RISK_BAND[risk]) >= 2:
                    errors.append(
                        f"threats[{i}].cvss_v4.severity='{sev}' is more "
                        f"than one band away from risk='{risk}'"
                    )
    return errors


def _check_snippet_redaction(data: dict) -> list[str]:
    """Hardcoded secret snippets must be redacted with `****` and may expose
    no more than 4 pre-redaction characters. Schema-level validation can't
    express this rule."""
    errors: list[str] = []
    secrets = data.get("hardcoded_secrets") or []
    if not isinstance(secrets, list):
        return errors
    for i, s in enumerate(secrets):
        if not isinstance(s, dict):
            continue
        snippet = s.get("snippet", "")
        if not isinstance(snippet, str) or not snippet:
            continue
        if "****" not in snippet:
            errors.append(
                f"hardcoded_secrets[{i}].snippet is not redacted "
                f"(must contain '****')"
            )
        elif len(snippet.replace("****", "")) > 4:
            errors.append(
                f"hardcoded_secrets[{i}].snippet exposes more than "
                f"4 characters before '****'"
            )
    return errors


def _check_scenario_stripped_length(data: dict) -> list[str]:
    """Stride scenarios must have >= 10 non-whitespace characters. JSONSchema
    minLength counts whitespace — this check enforces the stripped form."""
    errors: list[str] = []
    for i, t in enumerate(data.get("threats", []) or []):
        if not isinstance(t, dict):
            continue
        scenario = t.get("scenario")
        if isinstance(scenario, str) and len(scenario.strip()) < 10:
            errors.append(
                f"threats[{i}].scenario must be at least 10 characters "
                f"(got {len(scenario.strip())} chars)"
            )
    return errors


def _check_title_not_blank(data: dict) -> list[str]:
    """Merged threats must have a non-blank title. JSONSchema minLength counts
    whitespace, so `"   "` would pass — this catches the stripped-empty case."""
    errors: list[str] = []
    for i, t in enumerate(data.get("threats", []) or []):
        if not isinstance(t, dict):
            continue
        title = t.get("title")
        if isinstance(title, str) and not title.strip():
            errors.append(f"threats[{i}].title must not be empty")
    return errors


def _check_t_id_sequence(data: dict) -> list[str]:
    """`.threats-merged.json` uses global T-NNN IDs that must be unique and
    form a contiguous sequence starting at T-001."""
    errors: list[str] = []
    seen: set[str] = set()
    expected = 1
    for i, t in enumerate(data.get("threats", []) or []):
        if not isinstance(t, dict):
            continue
        t_id = t.get("t_id")
        if not isinstance(t_id, str):
            continue
        m = _T_ID_RE.match(t_id)
        if not m:
            continue  # structural issue already reported by schema
        if t_id in seen:
            errors.append(f"threats[{i}].t_id '{t_id}' is duplicated")
            continue
        seen.add(t_id)
        n = int(m.group(1))
        if n != expected:
            errors.append(
                f"threats[{i}].t_id '{t_id}' breaks sequential order "
                f"(expected T-{expected:03d})"
            )
        expected = n + 1
    return errors


def _check_tf_id_sequence(data: dict) -> list[str]:
    """`.triage-flags.json` uses TF-NNN IDs that must be unique and form a
    contiguous sequence starting at TF-001."""
    errors: list[str] = []
    seen: set[str] = set()
    expected = 1
    for i, f in enumerate(data.get("flags", []) or []):
        if not isinstance(f, dict):
            continue
        fid = f.get("flag_id")
        if not isinstance(fid, str):
            continue
        m = _TF_ID_RE.match(fid)
        if not m:
            continue
        if fid in seen:
            errors.append(f"flags[{i}].flag_id '{fid}' is duplicated")
            continue
        seen.add(fid)
        n = int(m.group(1))
        if n != expected:
            errors.append(
                f"flags[{i}].flag_id '{fid}' breaks sequential order "
                f"(expected TF-{expected:03d})"
            )
        expected = n + 1
    return errors


def _check_triage_summary(data: dict) -> list[str]:
    """Summary counters in `.triage-flags.json` must be consistent with the
    flags array (total == len(flags); warnings + info == total)."""
    errors: list[str] = []
    flags = data.get("flags") or []
    summary = data.get("summary") or {}
    if not isinstance(flags, list) or not isinstance(summary, dict):
        return errors
    total = summary.get("total_flags")
    warnings = summary.get("warnings")
    info = summary.get("info")
    if isinstance(total, int) and total != len(flags):
        errors.append(
            f"summary.total_flags={total} does not match flags length "
            f"({len(flags)})"
        )
    if (
        isinstance(total, int)
        and isinstance(warnings, int)
        and isinstance(info, int)
        and warnings + info != total
    ):
        errors.append(
            f"summary.warnings ({warnings}) + summary.info ({info}) "
            f"does not equal summary.total_flags ({total})"
        )
    actual_warnings = sum(
        1 for f in flags if isinstance(f, dict) and f.get("severity") == "warning"
    )
    actual_info = sum(
        1 for f in flags if isinstance(f, dict) and f.get("severity") == "info"
    )
    if isinstance(warnings, int) and warnings != actual_warnings:
        errors.append(
            f"summary.warnings={warnings} does not match actual warning "
            f"flag count ({actual_warnings})"
        )
    if isinstance(info, int) and info != actual_info:
        errors.append(
            f"summary.info={info} does not match actual info flag count "
            f"({actual_info})"
        )
    return errors


def _check_known_threats_unique_ids(data: dict) -> list[str]:
    """`docs/known-threats.yaml` entries must have unique `id` values — they
    are used downstream as `prior_finding_ref`."""
    errors: list[str] = []
    seen: set[str] = set()
    for i, t in enumerate(data.get("threats", []) or []):
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        if not isinstance(tid, str):
            continue
        if tid in seen:
            errors.append(f"threats[{i}].id '{tid}' is duplicated")
        seen.add(tid)
    return errors


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_dep_scan(data: Any) -> tuple[bool, list[str]]:
    """Validate a parsed .dep-scan.json object."""
    if not isinstance(data, dict):
        return False, ["root must be a JSON object"]
    errors = _schema_errors("dep_scan", data)
    # Redaction rule applies only to normal (non-error-stub) payloads.
    if "parse_error" not in data:
        errors.extend(_check_snippet_redaction(data))
    return len(errors) == 0, errors


def validate_stride(data: Any) -> tuple[bool, list[str]]:
    """Validate a parsed .stride-*.json object."""
    if not isinstance(data, dict):
        return False, ["root must be a JSON object"]
    errors = _schema_errors("stride", data)
    if "parse_error" not in data:
        errors.extend(_check_scenario_stripped_length(data))
    return len(errors) == 0, errors


def validate_threats_merged(data: Any) -> tuple[bool, list[str]]:
    """Validate a parsed .threats-merged.json object.

    The file is the canonical merged threat list produced by Phase 9 after
    global T-NNN assignment. Downstream tools (diagram annotator, YAML/SARIF
    export, changelog writer) consume it as structured input, so schema drift
    breaks them silently — this validator is the contract check.
    """
    if not isinstance(data, dict):
        return False, ["root must be a JSON object"]
    errors = _schema_errors("threats_merged", data)
    errors.extend(_check_title_not_blank(data))
    errors.extend(_check_t_id_sequence(data))
    errors.extend(_check_cvss_eligibility(data))
    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def validate_triage_flags(data: Any) -> tuple[bool, list[str]]:
    """Validate a parsed `.triage-flags.json` object produced by Phase 10b."""
    if not isinstance(data, dict):
        return False, ["root must be a JSON object"]
    errors = _schema_errors("triage_flags", data)
    errors.extend(_check_tf_id_sequence(data))
    errors.extend(_check_triage_summary(data))
    # M3.3: when analysis_version >= 2 the file must carry the v2 ranking
    # block. A v1 file means Phase 10b Step 6 silently skipped — surface
    # as SCHEMA_DRIFT (non-fatal at validation time; downstream renderers
    # already degrade gracefully when ranking is absent).
    version = data.get("version")
    if isinstance(version, int) and version < 2 and "ranking" not in data:
        errors.append(
            "SCHEMA_DRIFT: .triage-flags.json is version 1 with no ranking block. "
            "Phase 10b Step 6 (effective_severity, breach_distance, ranking) was "
            "skipped or crashed — re-run with APPSEC_TRIAGE_DETERMINISTIC=1 to "
            "enable the deterministic Python implementation."
        )
    return len(errors) == 0, errors


def _check_security_controls_shape(data: dict) -> list[str]:
    """``security_controls`` is documented as ``array<object>`` per
    schemas/threat-model.output.schema.yaml, but Phase 8 occasionally
    emits a degenerate list-of-strings. The renderers now normalize
    via ``_normalize_security_controls`` so the run does not crash, but
    we still surface the drift here as a hard validation error so it
    propagates to ``.run-issues.json`` and the SCHEMA_DRIFT signal in
    the Run Statistics appendix.
    """
    errors: list[str] = []
    items = data.get("security_controls")
    if not isinstance(items, list):
        return errors
    str_count = sum(1 for c in items if isinstance(c, str))
    if str_count and isinstance(data.get("meta"), dict):
        # Don't fail-hard on legacy/v1 baselines; only flag for v2+.
        analysis_v = (data.get("meta") or {}).get("analysis_version", 1)
        try:
            analysis_v = int(analysis_v)
        except (TypeError, ValueError):
            analysis_v = 1
        if analysis_v >= 2:
            errors.append(
                f"SCHEMA_DRIFT: security_controls contains {str_count} bare-string "
                f"entries (expected dict). Renderers will coerce, but Phase 8 "
                f"is emitting a degenerate shape — review agent prompt."
            )
    return errors


def _check_attack_surface_shape(data: dict) -> list[str]:
    """``attack_surface`` schema (M3.3): each entry must carry ``path``
    (or legacy ``route``), ``method``, and ideally ``threats[]`` so
    pregenerate_fragments.py can render meaningful tables. A degenerate
    entry shape was the proximate cause of the 2026-04-26 §5 "?" rendering
    bug. Surface as SCHEMA_DRIFT so the user sees it without crashing.
    """
    errors: list[str] = []
    surface = data.get("attack_surface")
    if not isinstance(surface, dict):
        return errors
    bad = 0
    for bucket in ("unauthenticated", "authenticated"):
        for entry in (surface.get(bucket) or []):
            if not isinstance(entry, dict):
                bad += 1
                continue
            if not (entry.get("path") or entry.get("route")):
                bad += 1
    if bad:
        errors.append(
            f"SCHEMA_DRIFT: attack_surface has {bad} entries missing required "
            f"`path` field (legacy `route` accepted). §5 will render with `?` "
            f"placeholders for these entries."
        )
    return errors


def _check_triage_flags_version(data: dict) -> list[str]:
    """``.triage-flags.json`` should be ``version: 2`` for analysis_version >= 2.
    A v1 file (no ``ranking`` block) means Phase 10b Step 6 either was
    skipped or crashed — surface so the user sees Phase 10b output is
    incomplete. Used by triage-flags JSON schema check.
    """
    # This validator runs on threat-model.yaml; triage-flags.json is checked
    # via validate_triage_flags() at line 424. Cross-link for visibility.
    return []


def validate_threat_model_output(data: Any) -> tuple[bool, list[str]]:
    """Validate the final `$OUTPUT_DIR/threat-model.yaml` export.

    This is the machine-readable contract consumed by CI/CD, DefectDojo,
    SonarQube, and sibling threat-model cross-repo discovery. Schema drift
    breaks integrations silently, so producers should validate before emit.
    """
    if not isinstance(data, dict):
        return False, ["root must be a mapping"]
    errors = _schema_errors("threat_model_output", data)
    errors.extend(_check_security_controls_shape(data))
    errors.extend(_check_attack_surface_shape(data))
    return len(errors) == 0, errors


def _check_pt_id_sequence(data: dict) -> list[str]:
    """`pentest-tasks.yaml` uses PT-NNN IDs that must be unique and
    contiguous starting at PT-001."""
    errors: list[str] = []
    seen: set[str] = set()
    expected = 1
    for i, t in enumerate(data.get("tasks", []) or []):
        if not isinstance(t, dict):
            continue
        pid = t.get("task_id")
        if not isinstance(pid, str):
            continue
        m = _PT_ID_RE.match(pid)
        if not m:
            continue
        if pid in seen:
            errors.append(f"tasks[{i}].task_id '{pid}' is duplicated")
            continue
        seen.add(pid)
        n = int(m.group(1))
        if n != expected:
            errors.append(
                f"tasks[{i}].task_id '{pid}' breaks sequential order "
                f"(expected PT-{expected:03d})"
            )
        expected = n + 1
    return errors


def validate_pentest_tasks(data: Any) -> tuple[bool, list[str]]:
    """Validate a `pentest-tasks.yaml` export."""
    if not isinstance(data, dict):
        return False, ["root must be a mapping"]
    errors = _schema_errors("pentest_tasks", data)
    errors.extend(_check_pt_id_sequence(data))
    return len(errors) == 0, errors


def validate_known_threats(data: Any) -> tuple[bool, list[str]]:
    """Validate a user-supplied `docs/known-threats.yaml` file before it is
    passed to downstream agents. Fails fast on malformed team input."""
    if not isinstance(data, dict):
        return False, ["root must be a mapping with a top-level `threats` key"]
    errors = _schema_errors("known_threats", data)
    errors.extend(_check_known_threats_unique_ids(data))
    return len(errors) == 0, errors


_VALIDATORS = {
    "dep_scan":            validate_dep_scan,
    "stride":              validate_stride,
    "threats_merged":      validate_threats_merged,
    "triage_flags":        validate_triage_flags,
    "threat_model_output": validate_threat_model_output,
    "known_threats":       validate_known_threats,
    "pentest_tasks":       validate_pentest_tasks,
}


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in _VALIDATORS:
        print(
            f"Usage: {sys.argv[0]} "
            f"<{'|'.join(_VALIDATORS)}> <path-to-json-file>",
            file=sys.stderr,
        )
        sys.exit(2)

    schema_type = sys.argv[1]
    path = Path(sys.argv[2])

    # YAML-native artifacts (user-supplied known-threats, final
    # threat-model.yaml export) are parsed with yaml.safe_load so the CLI
    # works against both `.json` and `.yaml` inputs.
    use_yaml = (
        schema_type in ("threat_model_output", "known_threats", "pentest_tasks")
        or path.suffix in (".yaml", ".yml")
    )
    try:
        with path.open() as f:
            if use_yaml:
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"INVALID JSON: {e}")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"INVALID YAML: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"INVALID: cannot read file: {e}")
        sys.exit(1)

    is_valid, errors = _VALIDATORS[schema_type](data)

    if is_valid:
        if schema_type in ("stride", "threats_merged", "known_threats"):
            n_threats = len(data.get("threats", []) or [])
            summary = f"{n_threats} threats"
        elif schema_type == "triage_flags":
            summary = f"{len(data.get('flags', []) or [])} flags"
        elif schema_type == "pentest_tasks":
            summary = f"{len(data.get('tasks', []) or [])} tasks"
        elif schema_type == "threat_model_output":
            summary = (
                f"{len(data.get('threats', []) or [])} threats, "
                f"{len(data.get('mitigations', []) or [])} mitigations"
            )
        else:
            summary = "ok"
        print(f"VALID: {summary}")
        sys.exit(0)
    else:
        for e in errors:
            print(f"INVALID: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
