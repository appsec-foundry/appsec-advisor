#!/usr/bin/env python3
"""
load_related_repos.py — deterministic loader for ``docs/related-repos.yaml``.

Replaces the LLM-driven Sub-step A of ``appsec-context-resolver`` (declared
cross-repo dependencies). Validates the user-authored YAML against
``schemas/related-repos.schema.yaml``, resolves each entry's threat-model
reference (relative path / absolute path / http(s) URL), reads metadata and
interface-relevant findings, and emits a single structured JSON document
that downstream stages (cross-repo register, STRIDE dispatch slice,
coverage_checks) consume.

Hardening over the previous ``curl -sf --max-time 10`` agent flow:

* schema-validated input — extra keys, wrong types, >16 entries fail loudly
* explicit URL scheme allow-list (http/https only — no file://, ftp://, etc.)
* optional auth header via ``RELATED_REPOS_AUTH_HEADER`` env var
* deterministic finding cap (default 12) — counts excluded findings
* ``meta.generated`` >90 days marks status=outdated (findings still loaded)

CLI usage::

    python3 load_related_repos.py \\
        --repo-root <REPO_ROOT> \\
        --output    <PATH-or-->          # `-` writes JSON to stdout
        [--cap N]                        # default 12 findings/dep
        [--http-timeout SEC]             # default 10s
        [--outdated-days N]              # default 90

Exit codes::

    0   loader ran (entries may be empty or partial — see status fields)
    2   bad arguments / unreadable YAML / schema violation
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

try:
    import jsonschema  # type: ignore
except ImportError:  # pragma: no cover - dependency is in scripts/requirements.txt
    jsonschema = None  # noqa: N816

_HERE = Path(__file__).resolve().parent
_DEFAULT_SCHEMA = _HERE.parent / "schemas" / "related-repos.schema.yaml"

_DEFAULT_CAP = 12
_DEFAULT_TIMEOUT = 10
_DEFAULT_OUTDATED_DAYS = 90

_ALLOWED_URL_SCHEMES = ("http", "https")
_INCLUDE_SEVERITIES_UNCONDITIONAL = {"Critical", "High"}
_INCLUDE_SEVERITIES_CONDITIONAL = {"Medium"}
_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


# ---------------------------------------------------------------------------
# Schema loading & validation
# ---------------------------------------------------------------------------


def _load_schema(path: Path | None = None) -> dict[str, Any]:
    path = path or _DEFAULT_SCHEMA
    if not path.is_file():
        raise FileNotFoundError(f"schema not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: schema is not a YAML mapping")
    return data


def _validate(payload: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    """Return a list of human-readable validation errors. Empty when valid."""
    if jsonschema is None:
        # Fall back to minimal structural checks so the loader still works in
        # bare environments. The schema file is the authoritative spec.
        errors: list[str] = []
        if not isinstance(payload, dict):
            return ["payload is not a mapping"]
        if "related" not in payload:
            errors.append("missing required key 'related'")
            return errors
        rel = payload.get("related")
        if not isinstance(rel, list) or not rel:
            errors.append("'related' must be a non-empty list")
        elif len(rel) > 16:
            errors.append(f"'related' has {len(rel)} entries (max 16)")
        for i, entry in enumerate(rel or []):
            if not isinstance(entry, dict):
                errors.append(f"related[{i}] is not a mapping")
                continue
            for required in ("name", "threat_model"):
                if required not in entry or not isinstance(entry[required], str):
                    errors.append(f"related[{i}].{required} is missing or not a string")
        return errors

    validator = jsonschema.Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    ]


# ---------------------------------------------------------------------------
# Threat-model fetching
# ---------------------------------------------------------------------------


def _resolve_tm_reference(tm_field: str, repo_root: Path) -> tuple[str, str]:
    """Return (kind, resolved) where kind is one of: 'url', 'absolute', 'relative'."""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", tm_field):
        return "url", tm_field
    p = Path(tm_field)
    if p.is_absolute():
        return "absolute", str(p)
    return "relative", str((repo_root / tm_field).resolve())


def _resolve_auth_header(auth_env: str | None) -> str | None:
    """Return the auth header value for this entry, or None.

    Resolution order:
      1. ``auth_env`` field on the entry (per-entry token — preferred for
         multi-SCM setups so each upstream can have its own credentials).
      2. ``RELATED_REPOS_AUTH_HEADER`` env var (global fallback).
    """
    if auth_env:
        value = os.environ.get(auth_env)
        if value:
            return value
    return os.environ.get("RELATED_REPOS_AUTH_HEADER") or None


def _fetch_url(url: str, timeout: int, *, auth_env: str | None = None) -> tuple[str | None, str]:
    """Fetch a URL and return (content, status). status is 'remote' or 'unavailable'."""
    parsed = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", url)
    scheme = parsed.group(1).lower() if parsed else ""
    if scheme not in _ALLOWED_URL_SCHEMES:
        return None, f"unavailable: scheme '{scheme}' not allowed (only http/https)"
    req = urllib.request.Request(url, headers={"Accept": "application/yaml, text/yaml, */*"})
    auth = _resolve_auth_header(auth_env)
    if auth:
        # Accept either "Header-Name: value" or just "value" (then Authorization)
        if ":" in auth:
            hname, hvalue = auth.split(":", 1)
            req.add_header(hname.strip(), hvalue.strip())
        else:
            req.add_header("Authorization", auth.strip())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            data = resp.read()
            return data.decode("utf-8", errors="replace"), "remote"
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        return None, f"unavailable: {exc}"


def _read_local(path: str) -> tuple[str | None, str]:
    p = Path(path)
    if not p.is_file():
        return None, "not found"
    try:
        return p.read_text(encoding="utf-8"), "local"
    except OSError as exc:
        return None, f"unavailable: {exc}"


# ---------------------------------------------------------------------------
# Threat-model parsing
# ---------------------------------------------------------------------------


def _parse_threat_model(raw: str) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _extract_threats(tm: dict[str, Any]) -> list[dict[str, Any]]:
    """Support both v1 flat ``threats[]`` and v2 ``threat_categories[].findings[]``."""
    if isinstance(tm.get("threats"), list):
        return [t for t in tm["threats"] if isinstance(t, dict)]
    out: list[dict[str, Any]] = []
    for cat in tm.get("threat_categories", []) or []:
        if not isinstance(cat, dict):
            continue
        for f in cat.get("findings", []) or []:
            if isinstance(f, dict):
                out.append(f)
    return out


def _is_outdated(generated: str | None, *, outdated_days: int, now: _dt.datetime) -> bool:
    if not generated:
        return False
    try:
        ts = _dt.datetime.fromisoformat(generated.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    delta = now - ts
    return delta.days > outdated_days


def _filter_findings(
    threats: list[dict[str, Any]],
    *,
    declared_components: list[str] | None,
    cap: int,
) -> tuple[list[dict[str, Any]], int]:
    """Apply the documented filter (status, severity, component) and cap."""
    declared_set = {c.lower() for c in (declared_components or [])}

    keep: list[dict[str, Any]] = []
    for t in threats:
        status = str(t.get("status", "")).strip().lower()
        if status != "open":
            continue
        severity = str(t.get("severity", "")).strip().title()
        component = str(t.get("component", "") or t.get("component_name", "")).strip()
        component_match = (component.lower() in declared_set) if declared_set else True

        if declared_set and not component_match:
            # When components are declared, every severity is gated on the match.
            continue

        if severity in _INCLUDE_SEVERITIES_UNCONDITIONAL:
            include = True
        elif severity in _INCLUDE_SEVERITIES_CONDITIONAL:
            # Medium: only when the entry restricts to specific components and
            # this finding's component is on that list. Without a component
            # filter, Medium is too noisy to inject into CROSS_REPO_CONTEXT.
            include = bool(declared_set)
        else:
            include = False

        if include:
            keep.append(_shape_finding(t))

    keep.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))
    excluded = max(0, len(keep) - cap)
    return keep[:cap], excluded


def _extract_upstream_properties(
    tm: dict[str, Any],
    *,
    interface: str | None,
    generated: str | None,
    now: _dt.datetime,
) -> dict[str, Any] | None:
    """Build the upstream_properties block for a declared cross-repo entry.

    Best-effort extraction from the dependency's threat-model.yaml:

    * substring-match the consumer-declared `interface` string against
      `attack_surface[].entry_point` — when found, lift protocol /
      auth_required / notes verbatim;
    * find components whose `paths[]` references the entry point and
      collect their `security_controls[]`;
    * stamp ``provenance: "upstream-asserted"`` so consumers never confuse
      claim with verified fact.

    Returns ``None`` when the dependency declared no interface, when the
    threat model lacks `attack_surface[]`, or when no entry point matched.
    """
    if not interface:
        return None
    interface_lower = interface.strip().lower()
    if not interface_lower:
        return None

    surface = tm.get("attack_surface")
    if not isinstance(surface, list):
        return None

    matched: dict[str, Any] | None = None
    matched_entry_point: str | None = None
    for item in surface:
        if not isinstance(item, dict):
            continue
        entry_point = item.get("entry_point")
        if not isinstance(entry_point, str):
            continue
        ep_lower = entry_point.strip().lower()
        if not ep_lower:
            continue
        # Match in either direction so "REST POST /api/v1/payments" matches
        # "POST /api/v1/payments" and vice versa.
        if ep_lower in interface_lower or interface_lower in ep_lower:
            matched = item
            matched_entry_point = entry_point
            break

    if matched is None:
        return None

    components_block = tm.get("components") or []
    handling: list[str] = []
    for comp in components_block:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name")
        paths = comp.get("paths") or []
        if not isinstance(name, str) or not isinstance(paths, list):
            continue
        for p in paths:
            if isinstance(p, str) and p and p.lower() in matched_entry_point.lower():
                handling.append(name)
                break

    controls_block = tm.get("security_controls") or []
    # Without component-level provenance on controls today, we attach all
    # controls when at least one handling component is identified, but tag
    # each control with its component for traceability when available.
    controls_out: list[dict[str, Any]] = []
    if handling:
        for ctrl in controls_block:
            if not isinstance(ctrl, dict):
                continue
            domain = ctrl.get("domain")
            name = ctrl.get("control")
            if not isinstance(domain, str) or not isinstance(name, str):
                continue
            controls_out.append(
                {
                    "domain": domain,
                    "control": name,
                    "effectiveness": ctrl.get("effectiveness"),
                    "component": ctrl.get("component"),
                }
            )

    staleness = None
    if generated:
        try:
            ts = _dt.datetime.fromisoformat(generated.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=_dt.timezone.utc)
            staleness = max(0, (now - ts).days)
        except (ValueError, TypeError):
            staleness = None

    auth_required = matched.get("auth_required")
    if not isinstance(auth_required, bool):
        auth_required = None

    upstream_auth_signal = None
    notes = matched.get("notes")
    if isinstance(notes, str) and notes.strip():
        upstream_auth_signal = notes.strip()

    return {
        "matched_entry_point": matched_entry_point,
        "match_confidence": "substring",
        "protocol": matched.get("protocol") if isinstance(matched.get("protocol"), str) else None,
        "auth_required": auth_required,
        "upstream_auth_signal": upstream_auth_signal,
        "handling_components": handling,
        "controls": controls_out,
        "provenance": "upstream-asserted",
        "staleness_days": staleness,
    }


def _compute_expectation_mismatch(
    *,
    consumer_declares: dict[str, Any] | None,
    upstream_properties: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Deterministic comparison: consumer expectations vs upstream signals.

    Returns ``None`` when no expectations were declared OR when nothing
    mismatched. Each populated field is a human-readable description; an
    absent field means that aspect matched (or was not declared).
    """
    if not consumer_declares:
        return None
    expected_auth = consumer_declares.get("expected_auth")
    expected_validation = consumer_declares.get("expected_validation")
    if not expected_auth and not expected_validation:
        return None

    out: dict[str, Any] = {"auth": None, "validation": None}

    if expected_auth:
        upstream_signal_pieces: list[str] = []
        if upstream_properties:
            if upstream_properties.get("auth_required") is True:
                upstream_signal_pieces.append("auth_required=true")
            elif upstream_properties.get("auth_required") is False:
                upstream_signal_pieces.append("auth_required=false")
            sig = upstream_properties.get("upstream_auth_signal")
            if isinstance(sig, str) and sig:
                upstream_signal_pieces.append(sig)
            for ctrl in upstream_properties.get("controls") or []:
                domain = str(ctrl.get("domain", "")).lower()
                if "auth" in domain:
                    upstream_signal_pieces.append(f"{ctrl.get('domain')}: {ctrl.get('control')}")
        signal_text = " | ".join(upstream_signal_pieces) if upstream_signal_pieces else "unknown"
        if expected_auth.lower() not in signal_text.lower():
            out["auth"] = (
                f"expected '{expected_auth}' but upstream signals '{signal_text}'"
            )

    if expected_validation:
        signal_pieces: list[str] = []
        if upstream_properties:
            for ctrl in upstream_properties.get("controls") or []:
                domain = str(ctrl.get("domain", "")).lower()
                control = str(ctrl.get("control", "")).lower()
                if "valid" in domain or "valid" in control or "schema" in control:
                    signal_pieces.append(f"{ctrl.get('domain')}: {ctrl.get('control')}")
        signal_text = " | ".join(signal_pieces) if signal_pieces else "unknown"
        if expected_validation.lower() not in signal_text.lower():
            out["validation"] = (
                f"expected '{expected_validation}' but upstream signals '{signal_text}'"
            )

    if not out["auth"] and not out["validation"]:
        return None
    return out


def _shape_finding(t: dict[str, Any]) -> dict[str, Any]:
    evidence = t.get("evidence")
    evidence_file = None
    if isinstance(evidence, dict):
        evidence_file = evidence.get("file")
    elif isinstance(t.get("evidence_file"), str):
        evidence_file = t["evidence_file"]
    return {
        "id": str(t.get("id") or t.get("threat_id") or ""),
        "title": str(t.get("title") or t.get("summary") or ""),
        "stride": str(t.get("stride") or t.get("stride_category") or ""),
        "cwe": str(t.get("cwe") or ""),
        "severity": str(t.get("severity") or "").strip().title(),
        "component": str(t.get("component") or t.get("component_name") or ""),
        "status": "open",
        "evidence_file": evidence_file,
    }


# ---------------------------------------------------------------------------
# Per-entry processing
# ---------------------------------------------------------------------------


def _count_threats(threats: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"total": len(threats), "critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0}
    for t in threats:
        sev = str(t.get("severity", "")).strip().title()
        if sev == "Critical":
            counts["critical"] += 1
        elif sev == "High":
            counts["high"] += 1
        elif sev == "Medium":
            counts["medium"] += 1
        elif sev == "Low":
            counts["low"] += 1
        if str(t.get("status", "")).lower() == "open":
            counts["open"] += 1
    return counts


def _process_entry(
    entry: dict[str, Any],
    *,
    repo_root: Path,
    cap: int,
    http_timeout: int,
    outdated_days: int,
    now: _dt.datetime,
) -> dict[str, Any]:
    name = entry["name"]
    tm_field = entry["threat_model"]
    interface = entry.get("interface")
    declared_components = entry.get("components") or []
    auth_env = entry.get("auth_env")
    expected_auth = entry.get("expected_auth")
    expected_validation = entry.get("expected_validation")

    consumer_declares: dict[str, Any] | None = None
    if expected_auth or expected_validation:
        consumer_declares = {
            "expected_auth": expected_auth,
            "expected_validation": expected_validation,
        }

    kind, resolved = _resolve_tm_reference(tm_field, repo_root)
    if kind == "url":
        raw, fetch_status = _fetch_url(resolved, http_timeout, auth_env=auth_env)
    else:
        raw, fetch_status = _read_local(resolved)

    record: dict[str, Any] = {
        "name": name,
        "source": "declared",
        "interface": interface,
        "auth_env": auth_env,
        "threat_model": {
            "status": "not found"
            if fetch_status == "not found"
            else ("unavailable" if fetch_status.startswith("unavailable") else "found"),
            "path": resolved,
            "ref_kind": kind,
            "generated": None,
            "commit_sha": None,
            "components": [],
            "threats_total": 0,
            "threats_critical": 0,
            "threats_high": 0,
            "threats_open": 0,
            "fetch_detail": fetch_status,
        },
        "interface_findings": None,
        "consumer_declares": consumer_declares,
        "upstream_properties": None,
        "expectation_mismatch": None,
    }

    if raw is None:
        return record

    tm = _parse_threat_model(raw)
    if tm is None:
        record["threat_model"]["status"] = "unavailable"
        record["threat_model"]["fetch_detail"] = "unavailable: yaml parse error"
        return record

    meta = tm.get("meta") if isinstance(tm.get("meta"), dict) else {}
    generated = meta.get("generated")
    git_info = meta.get("git") if isinstance(meta.get("git"), dict) else {}
    components = [
        c.get("name") for c in (tm.get("components") or []) if isinstance(c, dict) and isinstance(c.get("name"), str)
    ]
    threats = _extract_threats(tm)
    counts = _count_threats(threats)
    findings, excluded = _filter_findings(
        threats,
        declared_components=declared_components,
        cap=cap,
    )

    record["threat_model"].update(
        {
            "status": "outdated"
            if _is_outdated(
                generated,
                outdated_days=outdated_days,
                now=now,
            )
            else "found",
            "generated": generated,
            "commit_sha": git_info.get("commit_sha"),
            "components": components,
            "threats_total": counts["total"],
            "threats_critical": counts["critical"],
            "threats_high": counts["high"],
            "threats_open": counts["open"],
        }
    )
    record["interface_findings"] = {
        "included": len(findings),
        "excluded_count": excluded,
        "findings": findings,
    }
    upstream_properties = _extract_upstream_properties(
        tm,
        interface=interface,
        generated=generated,
        now=now,
    )
    record["upstream_properties"] = upstream_properties
    record["expectation_mismatch"] = _compute_expectation_mismatch(
        consumer_declares=consumer_declares,
        upstream_properties=upstream_properties,
    )
    return record


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def load(
    repo_root: Path,
    *,
    cap: int = _DEFAULT_CAP,
    http_timeout: int = _DEFAULT_TIMEOUT,
    outdated_days: int = _DEFAULT_OUTDATED_DAYS,
    schema_path: Path | None = None,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Load and process ``<repo_root>/docs/related-repos.yaml``.

    Returns a dict with:
        meta:    loader metadata
        related: [<record>, ...]   — may be empty when the file is absent
        errors:  list of validation/parse errors (non-fatal at the loader level)
    """
    yaml_path = repo_root / "docs" / "related-repos.yaml"
    out: dict[str, Any] = {
        "meta": {
            "loader_version": 1,
            "schema": str(schema_path or _DEFAULT_SCHEMA),
            "repo_root": str(repo_root),
            "yaml_path": str(yaml_path),
            "yaml_present": yaml_path.is_file(),
            "cap": cap,
            "outdated_days": outdated_days,
        },
        "related": [],
        "errors": [],
    }
    if not yaml_path.is_file():
        return out

    try:
        payload = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        out["errors"].append(f"yaml parse error: {exc}")
        return out
    if not isinstance(payload, dict):
        out["errors"].append("related-repos.yaml: top-level value is not a mapping")
        return out

    schema = _load_schema(schema_path)
    errs = _validate(payload, schema)
    if errs:
        out["errors"].extend(errs)
        # Schema violations are non-recoverable for the relevant entries — abort.
        return out

    now = now or _dt.datetime.now(tz=_dt.timezone.utc)
    for entry in payload.get("related", []):
        out["related"].append(
            _process_entry(
                entry,
                repo_root=repo_root,
                cap=cap,
                http_timeout=http_timeout,
                outdated_days=outdated_days,
                now=now,
            )
        )
    return out


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--output", required=True, help="destination JSON path, or '-' for stdout")
    p.add_argument("--cap", type=int, default=_DEFAULT_CAP)
    p.add_argument("--http-timeout", type=int, default=_DEFAULT_TIMEOUT)
    p.add_argument("--outdated-days", type=int, default=_DEFAULT_OUTDATED_DAYS)
    p.add_argument("--schema", type=Path, default=None)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    result = load(
        args.repo_root,
        cap=args.cap,
        http_timeout=args.http_timeout,
        outdated_days=args.outdated_days,
        schema_path=args.schema,
    )
    rendered = json.dumps(result, indent=2, sort_keys=False)
    if args.output == "-":
        print(rendered)
    else:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0 if not result.get("errors") else 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
