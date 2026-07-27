#!/usr/bin/env python3
"""Normalize trust boundaries and prepare bounded per-component STRIDE context.

``normalize`` is the sole semantic bridge from provisional/legacy Phase-7 data
and optional repository declarations to the strict v2 sidecar.
``contexts`` derives adjacency candidates only for components that the existing
STRIDE selector already chose; it never expands the dispatch set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

import jsonschema
import yaml
from _atomic_io import atomic_write_json
from reclassify_components import (  # shared path-ownership resolver — see _evidence_owners
    _glob_specificity as _rc_glob_specificity,
)
from reclassify_components import (
    _glob_to_regex as _rc_glob_to_regex,
)
from reserve_ids import ensure_counter_at_least, reserve
from sanitize_perimeter_claims import sanitize_perimeter_prose

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
NORMALIZED_SCHEMA = PLUGIN_ROOT / "schemas" / "fragments" / "trust-boundaries.schema.json"
REPO_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundaries-repo.schema.yaml"
DIAGNOSTICS_SCHEMA = PLUGIN_ROOT / "schemas" / "trust-boundary-diagnostics.schema.json"
KINDS = {"network", "process", "identity", "privilege", "tenant", "data-origin", "third-party", "build"}
LEGACY_FIELDS = {"controls", "description", "enforcement", "crossing_enforcement", "trust_level", "weakness"}
NEUTRAL_LEGACY_ASSUMPTION = "Assumption not recorded in legacy model"
MAX_BOUNDARY_ID = 999_999_999
_ID_RE = re.compile(r"^tb-(\d+)$")
_COMPONENT_ID_RE = re.compile(r"^[a-z][a-z0-9-]+$")
_CANONICAL_ENDPOINT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TRAILING_PAREN_RE = re.compile(r"\s*\([^()]*\)\s*$")
_EXTERNAL_ALIASES = {
    "external",
    "internet",
    "the internet",
    "public internet",
    "outside network",
    "untrusted network",
}


def _read_json(path: Path | None, default: Any = None) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _read_yaml(path: Path | None, default: Any = None) -> Any:
    if path is None or not path.is_file():
        return default
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return default


def _warn(message: str, warnings: list[str]) -> None:
    warnings.append(message)
    print(f"TRUST_BOUNDARY_WARN: {message}", file=sys.stderr)


def _clean_text(value: Any, *, fallback: str, limit: int) -> str:
    text = _CONTROL_RE.sub("", str(value or "")).strip()
    text, _removed = sanitize_perimeter_prose(text)
    text = " ".join(text.split())
    return (text or fallback)[:limit]


def _endpoint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = _CONTROL_RE.sub("", value).strip()
    if not value or len(value) > 128:
        return None
    return value


def _canonical_evidence(repo_root: Path, values: Any, warnings: list[str], label: str) -> list[dict]:
    result: list[dict] = []
    seen: set[tuple[str, int | None]] = set()
    root = repo_root.resolve()
    for raw in values if isinstance(values, list) else []:
        if not isinstance(raw, dict) or not isinstance(raw.get("file"), str):
            _warn(f"{label}: ignored malformed evidence entry", warnings)
            continue
        rel_text = raw["file"].replace("\\", "/").strip()
        rel = Path(rel_text)
        if not rel_text or len(rel_text) > 512 or rel.is_absolute() or ".." in rel.parts or "://" in rel_text:
            _warn(f"{label}: rejected unsafe evidence path {rel_text!r}", warnings)
            continue
        candidate = (root / rel).resolve()
        try:
            canonical_rel = candidate.relative_to(root).as_posix()
        except ValueError:
            _warn(f"{label}: rejected out-of-repository evidence path {rel_text!r}", warnings)
            continue
        if not candidate.is_file():
            _warn(f"{label}: rejected missing/non-regular evidence file {canonical_rel!r}", warnings)
            continue
        line = raw.get("line")
        if line is not None:
            if not isinstance(line, int) or isinstance(line, bool) or line < 1:
                _warn(f"{label}: rejected invalid evidence line for {canonical_rel!r}", warnings)
                continue
            try:
                line_count = sum(1 for _ in candidate.open("r", encoding="utf-8", errors="ignore"))
            except OSError:
                continue
            if line > max(line_count, 1):
                _warn(f"{label}: rejected out-of-range line {line} for {canonical_rel!r}", warnings)
                continue
        key = (canonical_rel, line)
        if key in seen:
            continue
        seen.add(key)
        item = {"file": canonical_rel}
        if line is not None:
            item["line"] = line
        result.append(item)
        if len(result) == 5:
            break
    return result


def _component_rows(sidecar: dict | None, prior: dict | None) -> list[dict]:
    rows = (sidecar or {}).get("components")
    if not isinstance(rows, list):
        rows = (prior or {}).get("components") or []
    return [
        row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("id"), str) and _COMPONENT_ID_RE.fullmatch(row["id"])
    ]


def _component_ids(sidecar: dict | None, prior: dict | None) -> set[str]:
    return {row["id"] for row in _component_rows(sidecar, prior)}


def _endpoint_lookup_key(value: str) -> str:
    """Conservative comparison form; never persisted as a public endpoint."""
    stripped = _TRAILING_PAREN_RE.sub("", value.strip())
    return " ".join(stripped.casefold().split())


def _resolve_endpoint(value: Any, components: dict[str, dict]) -> tuple[str | None, str, list[str]]:
    """Return ``(value, method, candidates)`` for one untrusted endpoint.

    Resolved methods are ``exact_id``, ``external_literal``,
    ``external_alias``, and ``component_name``. An unresolved result preserves
    the bounded raw string for the review catalogue.
    """
    raw = _endpoint(value)
    if raw is None:
        return None, "missing", []
    if raw == "external":
        return "external", "external_literal", []
    if raw in components:
        return raw, "exact_id", []

    key = _endpoint_lookup_key(raw)
    if key in _EXTERNAL_ALIASES or key.startswith("external "):
        return "external", "external_alias", []

    by_name: dict[str, list[str]] = defaultdict(list)
    for cid, row in components.items():
        name = row.get("name")
        if isinstance(name, str) and name.strip():
            by_name[_endpoint_lookup_key(name)].append(cid)
    matches = sorted(set(by_name.get(key, [])))
    if len(matches) == 1:
        return matches[0], "component_name", matches
    return raw, "ambiguous" if matches else "unresolved", matches[:8]


def boundary_endpoints_valid(boundary: dict, component_ids: set[str]) -> bool:
    """Dynamic resolved-row invariant shared by all downstream consumers."""
    if not isinstance(boundary, dict) or boundary.get("resolution_status") != "resolved":
        return False
    allowed = component_ids | {"external"}
    return boundary.get("from") in allowed and boundary.get("to") in allowed


def _boundary_endpoint_shape_valid(boundary: dict) -> bool:
    if not isinstance(boundary, dict) or boundary.get("resolution_status") != "resolved":
        return False
    return all(
        value == "external" or (isinstance(value, str) and _CANONICAL_ENDPOINT_RE.fullmatch(value))
        for value in (boundary.get("from"), boundary.get("to"))
    )


def _normalize_row(
    raw: Any,
    *,
    repo_root: Path,
    components: dict[str, dict],
    legacy_input: bool,
    warnings: list[str],
    source: str,
) -> dict | None:
    if not isinstance(raw, dict):
        _warn("ignored non-object boundary row", warnings)
        return None
    name = _clean_text(raw.get("name"), fallback="Unnamed trust boundary", limit=100)
    label = _clean_text(raw.get("id") or raw.get("key") or name, fallback=name, limit=100)
    from_ep, from_method, from_candidates = _resolve_endpoint(raw.get("from"), components)
    to_ep, to_method, to_candidates = _resolve_endpoint(raw.get("to"), components)
    kind = raw.get("kind") if raw.get("kind") in KINDS else "network"
    assumption_raw = raw.get("assumption")
    is_legacy = legacy_input or bool(LEGACY_FIELDS.intersection(raw))
    assumption = _clean_text(
        assumption_raw,
        fallback=NEUTRAL_LEGACY_ASSUMPTION if is_legacy else "Trust assumption requires review",
        limit=240,
    )
    evidence = _canonical_evidence(repo_root, raw.get("evidence"), warnings, label)
    sources = raw.get("sources") if isinstance(raw.get("sources"), list) else []
    sources = [s for s in sources if s in {"detected", "repo-declared", "legacy"}]
    required_source = "legacy" if is_legacy else source
    if required_source not in sources:
        sources.append(required_source)
    confidence = raw.get("confidence") if raw.get("confidence") in {"confirmed", "inferred", "unknown"} else "inferred"
    if is_legacy and not assumption_raw:
        confidence = "unknown"
    elif source == "repo-declared" and "detected" not in sources:
        confidence = "inferred"
    elif confidence == "confirmed" and (not evidence or "detected" not in sources):
        confidence = "inferred"
    valid_from = from_ep == "external" or from_ep in components
    valid_to = to_ep == "external" or to_ep in components
    resolution = "resolved" if valid_from and valid_to else "unresolved"
    resolution_details: list[dict] = []
    if resolution == "unresolved":
        _warn(f"{label}: unresolved endpoint(s) from={from_ep!r} to={to_ep!r}", warnings)
        authored_resolved = raw.get("resolution_status") == "resolved"
        for side, raw_value, valid, method, candidates in (
            ("from", raw.get("from"), valid_from, from_method, from_candidates),
            ("to", raw.get("to"), valid_to, to_method, to_candidates),
        ):
            if valid:
                continue
            bounded_raw = _endpoint(raw_value)
            resolution_details.append(
                {
                    "code": "invalid_resolved_endpoint" if authored_resolved else "unresolved_endpoint",
                    "side": side,
                    "raw_value": bounded_raw or "",
                    "reason": {
                        "missing": "endpoint is missing or outside the 128-character bound",
                        "ambiguous": "endpoint matches more than one component name",
                        "unresolved": "no exact component name or explicit external marker",
                    }.get(method, "endpoint does not satisfy the canonical contract"),
                    "candidates": candidates,
                }
            )
    if LEGACY_FIELDS.intersection(raw):
        _warn(f"{label}: discarded legacy fields {sorted(LEGACY_FIELDS.intersection(raw))}", warnings)
    row: dict[str, Any] = {
        "name": name,
        "kind": kind,
        "assumption": assumption,
        "evidence": evidence,
        "confidence": confidence,
        "resolution_status": resolution,
        "sources": list(dict.fromkeys(sources)),
    }
    if from_ep:
        row["from"] = from_ep
    if to_ep:
        row["to"] = to_ep
    if resolution_details:
        row["_resolution_details"] = resolution_details
    key = raw.get("declaration_key") or (raw.get("key") if source == "repo-declared" else None)
    if isinstance(key, str) and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", key) and len(key) <= 80:
        row["declaration_key"] = key
    authored_id = raw.get("id")
    if isinstance(authored_id, str) and _ID_RE.fullmatch(authored_id):
        row["_authored_id"] = authored_id
    # A prior normalized sidecar is a trusted cached artifact, not fresh LLM
    # authorship. This marker enables idempotent re-normalization.
    if (
        not legacy_input
        and raw.get("resolution_status") in {"resolved", "unresolved", "conflicted"}
        and isinstance(authored_id, str)
    ):
        row["_normalized_id"] = authored_id
    return row


def _load_declarations(
    repo_root: Path, components: dict[str, dict], warnings: list[str]
) -> tuple[list[dict], str | None]:
    path = repo_root / ".appsec" / "trust-boundaries.yaml"
    if not path.is_file():
        return [], None
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        _warn(f"rejected complete repository declaration input {path}: {exc}", warnings)
        return [], None
    fingerprint = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
    try:
        data = yaml.safe_load(raw_bytes) or {}
        schema = yaml.safe_load(REPO_SCHEMA.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(data)
        keys = [row.get("key") for row in data.get("boundaries", []) if isinstance(row, dict)]
        if len(keys) != len(set(keys)):
            raise jsonschema.ValidationError("boundaries[].key values must be unique")
    except (OSError, yaml.YAMLError, jsonschema.ValidationError) as exc:
        _warn(f"rejected complete repository declaration input {path}: {exc}", warnings)
        return [], fingerprint
    rows = [
        row
        for raw in data.get("boundaries", [])
        if (
            row := _normalize_row(
                raw,
                repo_root=repo_root,
                components=components,
                legacy_input=False,
                warnings=warnings,
                source="repo-declared",
            )
        )
    ]
    return rows, fingerprint


def _merge_evidence(left: list[dict], right: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for item in [*left, *right]:
        key = (item.get("file"), item.get("line"))
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out[:5]


def _merge_declarations(
    detected: list[dict],
    declared: list[dict],
    prior_rows: list[dict],
    warnings: list[str],
) -> list[dict]:
    rows = deepcopy(detected)
    for declaration in declared:
        key = declaration.get("declaration_key")
        keyed = [r for r in rows if r.get("declaration_key") == key] if key else []
        if key and not keyed:
            prior_keyed = [row for row in prior_rows if isinstance(row, dict) and row.get("declaration_key") == key]
            if len(prior_keyed) == 1:
                prior = prior_keyed[0]
                prior_exact = [
                    row
                    for row in rows
                    if (row.get("from"), row.get("to"), row.get("name", "").casefold())
                    == (prior.get("from"), prior.get("to"), str(prior.get("name", "")).casefold())
                ]
                prior_endpoint = [
                    row for row in rows if (row.get("from"), row.get("to")) == (prior.get("from"), prior.get("to"))
                ]
                inherited = (
                    prior_exact[0] if len(prior_exact) == 1 else prior_endpoint[0] if len(prior_endpoint) == 1 else None
                )
                if inherited is not None:
                    inherited["declaration_key"] = key
                    keyed = [inherited]
        exact_name = [
            r
            for r in rows
            if (r.get("from"), r.get("to"), r.get("name").casefold())
            == (declaration.get("from"), declaration.get("to"), declaration.get("name").casefold())
        ]
        endpoint = [r for r in rows if (r.get("from"), r.get("to")) == (declaration.get("from"), declaration.get("to"))]
        target = (
            keyed[0]
            if len(keyed) == 1
            else exact_name[0]
            if len(exact_name) == 1
            else endpoint[0]
            if len(endpoint) == 1
            else None
        )
        if (
            keyed
            and target
            and (target.get("from"), target.get("to")) != (declaration.get("from"), declaration.get("to"))
        ):
            target["resolution_status"] = "conflicted"
            target["sources"] = list(dict.fromkeys([*target["sources"], "repo-declared"]))
            declaration["resolution_status"] = "conflicted"
            detail = {
                "code": "conflicted_boundary",
                "side": "both",
                "raw_value": "",
                "reason": "repository declaration conflicts with detected or prior canonical endpoints",
                "candidates": [],
            }
            target.setdefault("_resolution_details", []).append(deepcopy(detail))
            declaration.setdefault("_resolution_details", []).append(deepcopy(detail))
            _warn(f"declaration {key!r} conflicts with detected/prior endpoints; retained both rows", warnings)
            rows.append(declaration)
            continue
        if target is None:
            rows.append(declaration)
            continue
        target["name"] = declaration["name"]
        target["kind"] = declaration["kind"]
        target["assumption"] = declaration["assumption"]
        target["evidence"] = _merge_evidence(target["evidence"], declaration["evidence"])
        target["sources"] = list(dict.fromkeys([*target["sources"], "repo-declared"]))
        target["declaration_key"] = key
        # Declaration prose/evidence cannot self-confirm. Existing independently
        # detected confirmation may survive.
        if "detected" not in target["sources"]:
            target["confidence"] = "inferred"
    return rows


def _compatible(left: dict, right: dict) -> bool:
    for field in ("from", "to"):
        if left.get(field) and right.get(field) and left.get(field) != right.get(field):
            return False
    return True


def _numeric_id(value: Any) -> int:
    match = _ID_RE.fullmatch(str(value or ""))
    return int(match.group(1)) if match else 0


def _assign_ids(rows: list[dict], prior_rows: list[dict], output_dir: Path, warnings: list[str]) -> None:
    trusted_prior = [r for r in prior_rows if isinstance(r, dict) and _ID_RE.fullmatch(str(r.get("id") or ""))]
    max_prior = max((_numeric_id(r.get("id")) for r in trusted_prior), default=0)
    ensure_counter_at_least(output_dir, "trust_boundary", max_prior + 1)
    prior_by_id = {r["id"]: r for r in trusted_prior}
    prior_by_key: dict[str, list[dict]] = defaultdict(list)
    prior_by_exact: dict[tuple, list[dict]] = defaultdict(list)
    prior_by_endpoint: dict[tuple, list[dict]] = defaultdict(list)
    for prior in trusted_prior:
        if prior.get("declaration_key"):
            prior_by_key[prior["declaration_key"]].append(prior)
        prior_by_exact[(prior.get("from"), prior.get("to"), str(prior.get("name", "")).casefold())].append(prior)
        prior_by_endpoint[(prior.get("from"), prior.get("to"))].append(prior)
    current_endpoint_counts = Counter((r.get("from"), r.get("to")) for r in rows)
    used: set[str] = set()
    for row in rows:
        candidates: list[dict] = []
        key = row.get("declaration_key")
        if key and len(prior_by_key[key]) == 1:
            candidates = prior_by_key[key]
        authored = row.pop("_authored_id", None)
        normalized = row.pop("_normalized_id", None)
        if not candidates and authored in prior_by_id and _compatible(row, prior_by_id[authored]):
            candidates = [prior_by_id[authored]]
        if not candidates:
            candidates = prior_by_exact[(row.get("from"), row.get("to"), str(row.get("name", "")).casefold())]
        if not candidates:
            endpoint_key = (row.get("from"), row.get("to"))
            prior_endpoint = prior_by_endpoint[endpoint_key]
            if len(prior_endpoint) == 1 and current_endpoint_counts[endpoint_key] == 1:
                candidates = prior_endpoint
        chosen = next((p for p in candidates if p["id"] not in used and _compatible(row, p)), None)
        if chosen:
            row["id"] = chosen["id"]
            used.add(chosen["id"])
            continue
        # Idempotence for an already normalized cached sidecar when no separate
        # prior YAML is available. It is accepted only if unique and advances
        # the shared counter; fresh LLM rows lack the deterministic marker.
        if normalized and _ID_RE.fullmatch(normalized) and normalized not in used:
            row["id"] = normalized
            used.add(normalized)
            ensure_counter_at_least(output_dir, "trust_boundary", _numeric_id(normalized) + 1)
            continue
        if candidates:
            _warn(f"ambiguous prior identity for {row.get('name')!r}; allocated a new ID", warnings)
        new_id = reserve(output_dir, "trust_boundary", 1)[0]
        row["id"] = new_id
        used.add(new_id)


def _prior_boundaries(prior_model: Path | None) -> tuple[dict | None, list[dict]]:
    prior = _read_yaml(prior_model, {}) if prior_model else {}
    if not isinstance(prior, dict):
        return None, []
    rows = prior.get("trust_boundaries")
    return prior, rows if isinstance(rows, list) else []


def _canonicalize_prior_rows(rows: list[dict], components: dict[str, dict]) -> list[dict]:
    """Canonicalize prior endpoints in memory for stable-ID migration matching."""
    result: list[dict] = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = deepcopy(raw)
        for side in ("from", "to"):
            endpoint, method, _candidates = _resolve_endpoint(row.get(side), components)
            if method in {"exact_id", "external_literal", "external_alias", "component_name"} and endpoint:
                row[side] = endpoint
        result.append(row)
    return result


def _write_diagnostics(output_dir: Path, rows: list[dict]) -> None:
    issues: list[dict] = []
    for row in rows:
        for detail in row.pop("_resolution_details", []) or []:
            if not isinstance(detail, dict):
                continue
            issues.append(
                {
                    "code": detail.get("code", "unresolved_endpoint"),
                    "boundary_id": row.get("id", "tb-0"),
                    "boundary_name": _clean_text(
                        row.get("name"),
                        fallback="Unnamed trust boundary",
                        limit=100,
                    ),
                    "side": detail.get("side", "both"),
                    "raw_value": _clean_text(detail.get("raw_value"), fallback="", limit=128),
                    "reason": _clean_text(
                        detail.get("reason"),
                        fallback="endpoint does not satisfy the canonical contract",
                        limit=240,
                    ),
                    "candidates": [
                        value
                        for value in detail.get("candidates", [])[:8]
                        if isinstance(value, str) and _COMPONENT_ID_RE.fullmatch(value)
                    ],
                }
            )
    issues.sort(key=lambda item: (_numeric_id(item["boundary_id"]), item["side"], item["code"]))
    result = {"schema_version": 1, "issues": issues}
    schema = json.loads(DIAGNOSTICS_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(result)
    atomic_write_json(output_dir / ".trust-boundary-diagnostics.json", result, sort_keys=False)


def _record_invalid_resolved_diagnostics(output_dir: Path, rows: list[dict]) -> None:
    """Merge consumer-side invariant failures into the normalized diagnostics."""
    path = output_dir / ".trust-boundary-diagnostics.json"
    current = _read_json(path, {}) or {}
    issues = [item for item in current.get("issues", []) if isinstance(item, dict)]
    existing = {(item.get("code"), item.get("boundary_id"), item.get("side")) for item in issues}
    for row in rows:
        key = ("invalid_resolved_endpoint", row.get("id"), "both")
        if key in existing:
            continue
        issues.append(
            {
                "code": "invalid_resolved_endpoint",
                "boundary_id": row["id"],
                "boundary_name": _clean_text(
                    row.get("name"),
                    fallback="Unnamed trust boundary",
                    limit=100,
                ),
                "side": "both",
                "raw_value": "",
                "reason": "resolved row failed dynamic component endpoint validation before dispatch",
                "candidates": [],
            }
        )
    result = {"schema_version": 1, "issues": issues}
    schema = json.loads(DIAGNOSTICS_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(result)
    atomic_write_json(path, result, sort_keys=False)


def _write_declaration_fingerprint(output_dir: Path, fingerprint: str | None) -> None:
    cache = output_dir / ".appsec-cache" / "baseline.json"
    state = _read_json(cache, {}) or {}
    if fingerprint is None:
        state.pop("trust_boundary_declaration_fingerprint", None)
    else:
        state["trust_boundary_declaration_fingerprint"] = fingerprint
    cache.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(cache, state)


def normalize(
    *,
    repo_root: Path,
    sidecar: Path,
    prior_model: Path | None,
    output_dir: Path,
) -> tuple[dict, list[str]]:
    repo_root, output_dir = repo_root.resolve(), output_dir.resolve()
    raw = _read_json(sidecar, None)
    if not isinstance(raw, dict) or not isinstance(raw.get("trust_boundaries"), list):
        raise ValueError(f"sidecar is missing or malformed: {sidecar}")
    prior, prior_rows = _prior_boundaries(prior_model)
    components_data = _read_json(output_dir / ".components.json", {})
    component_rows = _component_rows(components_data, prior)
    components = {row["id"]: row for row in component_rows}
    prior_rows = _canonicalize_prior_rows(prior_rows, components)
    warnings: list[str] = []
    legacy = raw.get("schema_version") != 2
    detected = [
        row
        for item in raw["trust_boundaries"]
        if (
            row := _normalize_row(
                item,
                repo_root=repo_root,
                components=components,
                legacy_input=legacy,
                warnings=warnings,
                source="detected",
            )
        )
    ]
    declarations, fingerprint = _load_declarations(repo_root, components, warnings)
    merged = _merge_declarations(detected, declarations, prior_rows, warnings)
    _assign_ids(merged, prior_rows, output_dir, warnings)
    if len({row["id"] for row in merged}) != len(merged):
        raise ValueError("normalization produced duplicate trust-boundary IDs")
    merged.sort(key=lambda row: _numeric_id(row["id"]))
    _write_diagnostics(output_dir, merged)
    result = {"schema_version": 2, "trust_boundaries": merged}
    schema = json.loads(NORMALIZED_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(result)
    atomic_write_json(sidecar, result, sort_keys=False)
    _write_declaration_fingerprint(output_dir, fingerprint)
    return result, warnings


def _component_map(output_dir: Path) -> dict[str, dict]:
    data = _read_json(output_dir / ".components.json", {}) or {}
    return {
        row["id"]: row for row in data.get("components", []) if isinstance(row, dict) and isinstance(row.get("id"), str)
    }


def _prior_boundary_refs(output_dir: Path) -> set[tuple[str, str]]:
    model = _read_yaml(output_dir / "threat-model.yaml", {}) or {}
    result: set[tuple[str, str]] = set()
    for finding in model.get("threats", []) if isinstance(model, dict) else []:
        if not isinstance(finding, dict):
            continue
        for ref in finding.get("boundary_refs", []) or []:
            if isinstance(ref, dict) and ref.get("boundary_id") and ref.get("origin_component_id"):
                result.add((ref["boundary_id"], ref["origin_component_id"]))
    return result


def _path_specificity(component: dict, file_path: str) -> int | None:
    """Highest specificity among the component globs claiming ``file_path``."""
    best: int | None = None
    for glob in component.get("paths") or []:
        if not isinstance(glob, str) or not glob.strip():
            continue
        glob = glob.strip()
        if _rc_glob_to_regex(glob).search(file_path):
            score = _rc_glob_specificity(glob)
            best = score if best is None else max(best, score)
    return best


def _evidence_owners(boundary: dict, components: dict[str, dict], endpoint_ids: set[str]) -> set[str]:
    """Components claiming a boundary's evidence more precisely than its endpoints.

    Endpoint adjacency alone cannot name the component that *implements* a
    crossing whose far side is ``external``. tb-5 ``backend-api -> external``
    is the LLM egress, yet ``llm-integration`` is never an endpoint and was
    therefore never offered the one boundary it owns — juice-shop 2026-07-27
    shipped that boundary with zero linked findings for exactly this reason.
    Ownership of the cited evidence file is the missing signal.

    Two guards keep this from inventing adjacency:

    * The endpoint must claim the evidence too. When it does not, the declared
      topology and the cited evidence disagree — a data-quality problem this
      function must surface rather than paper over by handing the boundary to
      whichever component happens to own the file.
    * The claim must be STRICTLY more specific. A file both sides claim equally
      well says nothing about ownership: ``server.ts`` sits in both
      ``backend-api`` and ``socket-io-realtime`` globs, and a loose match would
      hand the "Admin Zone" boundary to the WebSocket gateway.

    What remains is the narrow, intended case: the endpoint is the coarse owner
    (``routes/**``) and a finer-grained component claims the exact file
    (``routes/chat.ts``), so the latter is the component that implements it.
    """
    owners: set[str] = set()
    resolvable_endpoints = endpoint_ids & set(components)
    for entry in boundary.get("evidence") or []:
        if not isinstance(entry, dict):
            continue
        file_path = str(entry.get("file") or "").strip()
        if not file_path:
            continue
        endpoint_scores = [
            score
            for cid in resolvable_endpoints
            if (score := _path_specificity(components[cid], file_path)) is not None
        ]
        baseline = max(endpoint_scores, default=None)
        for cid, component in components.items():
            if cid in endpoint_ids:
                continue
            score = _path_specificity(component, file_path)
            if baseline is not None and score is not None and score > baseline:
                owners.add(cid)
    return owners


def _glob_probe(glob: str) -> str:
    """Representative concrete path for a component glob, for containment tests."""
    return glob.replace("/**", "/_").replace("**", "_").replace("*", "_")


def _containing_component_id(cid: str, components: dict[str, dict]) -> str | None:
    """The coarse component whose globs already claim every path of ``cid``.

    Role-folded components (an `auth` surface carved out of `backend-api`) are
    reconciled into the dispatch set after Phase 3, so no boundary names them as
    an endpoint and they start with no candidates at all — juice-shop
    2026-07-27 ran `auth` and `web3-nft`, 17 findings between them, with zero
    boundary context. Their parent's candidates are the closest correct answer.
    """
    own = [g.strip() for g in (components.get(cid, {}).get("paths") or []) if isinstance(g, str) and g.strip()]
    if not own:
        return None
    parents: list[tuple[int, str]] = []
    for pid, parent in components.items():
        if pid == cid:
            continue
        globs = [g.strip() for g in (parent.get("paths") or []) if isinstance(g, str) and g.strip()]
        if not globs:
            continue
        if all(any(_rc_glob_to_regex(g).search(_glob_probe(p)) for g in globs) for p in own):
            parents.append((max(_rc_glob_specificity(g) for g in globs), pid))
    if not parents:
        return None
    # Most specific containing component wins; id breaks ties deterministically.
    return min(parents, key=lambda item: (-item[0], item[1]))[1]


def _focus(boundary: dict, component: dict, prior_refs: set[tuple[str, str]]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    cid = component.get("id")
    if boundary.get("confidence") == "unknown" or boundary.get("assumption") == NEUTRAL_LEGACY_ASSUMPTION:
        return "catalog-only", ["unknown legacy assumption or confidence"]
    if (boundary["id"], cid) in prior_refs:
        reasons.append("prior verified boundary reference")
    if boundary.get("from") == "external":
        reasons.append("explicit external entry")
    if boundary.get("kind") in {"identity", "privilege", "tenant"}:
        reasons.append(f"{boundary['kind']} transition")
    if boundary.get("kind") in {"third-party", "build"}:
        reasons.append(f"{boundary['kind']} crossing")
    if reasons:
        return "primary", reasons
    if boundary.get("kind") == "data-origin":
        reasons.append("data-origin transition")
    if component.get("handles_sensitive_data"):
        reasons.append("crossing into sensitive-data component")
    if reasons:
        return "secondary", reasons
    return "catalog-only", ["ordinary crossing without prioritized trust-change signal"]


def prepare_contexts(
    *,
    repo_root: Path,
    output_dir: Path,
    component_ids: Iterable[str],
    depth: str,
) -> dict:
    from resolve_config import BOUNDARY_CANDIDATE_LIMITS

    if depth not in BOUNDARY_CANDIDATE_LIMITS:
        raise ValueError(f"unknown assessment depth: {depth}")
    sidecar = _read_json(output_dir / ".trust-boundaries.json", {}) or {}
    components = _component_map(output_dir)
    component_id_set = set(components)
    boundaries = [row for row in sidecar.get("trust_boundaries", []) if isinstance(row, dict)]
    invalid_resolved = [
        row
        for row in boundaries
        if row.get("resolution_status") == "resolved" and not boundary_endpoints_valid(row, component_id_set)
    ]
    # Fail open for the assessment but fail closed for boundary semantics. The
    # strict schema correctly rejects prose endpoints on resolved rows; context
    # preparation still needs to surface/defer such a persisted artifact rather
    # than abort before the diagnostics path can run.
    validation_doc = deepcopy(sidecar)
    invalid_ids = {row.get("id") for row in invalid_resolved}
    for row in validation_doc.get("trust_boundaries", []) if isinstance(validation_doc, dict) else []:
        if isinstance(row, dict) and row.get("id") in invalid_ids:
            row["resolution_status"] = "unresolved"
    schema = json.loads(NORMALIZED_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(validation_doc)
    if invalid_resolved:
        _record_invalid_resolved_diagnostics(output_dir, invalid_resolved)
        for row in invalid_resolved:
            print(
                f"TRUST_BOUNDARY_WARN: {row.get('id')}: invalid resolved endpoints "
                f"from={row.get('from')!r} to={row.get('to')!r}",
                file=sys.stderr,
            )
    prior_refs = _prior_boundary_refs(output_dir)
    # Precomputed once per boundary: endpoint adjacency cannot name the
    # component implementing an `-> external` crossing (see _evidence_owners).
    evidence_owners = {
        boundary["id"]: _evidence_owners(
            boundary,
            components,
            {boundary.get("from"), boundary.get("to")} & component_id_set,
        )
        for boundary in boundaries
        if boundary.get("id")
    }
    selected_component_ids = list(dict.fromkeys(str(x) for x in component_ids if x))
    context_root = output_dir / ".dispatch-context"
    context_root.mkdir(parents=True, exist_ok=True)
    audit: dict[str, Any] = {
        "schema_version": 1,
        "depth": depth,
        "max_candidates_per_component": BOUNDARY_CANDIDATE_LIMITS[depth],
        "components": {},
    }
    # Selection is decided across all components at once (inheritance and the
    # coverage guarantee below both need the global picture), so collect first
    # and write the context files only once every list is final.
    state: dict[str, dict[str, Any]] = {}
    for cid in selected_component_ids:
        context_path = context_root / cid / "trust-boundaries.json"
        try:
            context_path.unlink()
        except FileNotFoundError:
            pass
        component = components.get(cid)
        if component is None:
            audit["components"][cid] = {
                "eligible_ids": [],
                "selected_ids": [],
                "omitted_ids": [],
                "deferred_ids": [],
                "invalid_ids": [row["id"] for row in invalid_resolved],
                "reason": "selected STRIDE component absent from reconciled inventory",
            }
            continue
        candidates: list[tuple[tuple, dict, str, list[str]]] = []
        deferred: list[str] = []
        invalid: list[str] = []
        for boundary in boundaries:
            if boundary.get("resolution_status") != "resolved":
                deferred.append(boundary["id"])
                continue
            if not boundary_endpoints_valid(boundary, component_id_set):
                deferred.append(boundary["id"])
                invalid.append(boundary["id"])
                continue
            is_endpoint = cid in {boundary.get("from"), boundary.get("to")}
            owns_evidence = cid in evidence_owners.get(boundary["id"], set())
            if not is_endpoint and not owns_evidence:
                continue
            focus, reasons = _focus(boundary, component, prior_refs)
            if focus == "catalog-only" or (depth == "quick" and focus != "primary"):
                deferred.append(boundary["id"])
                continue
            if owns_evidence and not is_endpoint:
                reasons = [*reasons, "implements the crossing (owns cited evidence)"]
            rank = (
                0 if (boundary["id"], cid) in prior_refs else 1,
                0 if boundary.get("from") == "external" else 1,
                0 if boundary.get("kind") in {"identity", "privilege", "tenant"} else 1,
                0 if boundary.get("kind") == "data-origin" and component.get("handles_sensitive_data") else 1,
                0 if boundary.get("kind") in {"third-party", "build"} else 1,
                {"confirmed": 0, "inferred": 1, "unknown": 2}.get(boundary.get("confidence"), 2),
                _numeric_id(boundary["id"]),
            )
            candidates.append((rank, boundary, focus, reasons))
        candidates.sort(key=lambda item: item[0])
        state[cid] = {"candidates": candidates, "deferred": deferred, "invalid": invalid, "inherited_from": None}

    # A component with no candidates of its own inherits its parent's. Applied
    # ONLY when the list is empty: giving every folded sub-component the
    # parent's boundaries would crowd each one's own crossing out of the cap.
    for cid, entry in state.items():
        if entry["candidates"]:
            continue
        parent_id = _containing_component_id(cid, components)
        parent = state.get(parent_id) if parent_id else None
        if not parent or not parent["candidates"]:
            continue
        entry["candidates"] = [
            (rank, boundary, focus, [*reasons, f"inherited from containing component {parent_id}"])
            for rank, boundary, focus, reasons in parent["candidates"]
        ]
        entry["inherited_from"] = parent_id

    limit = BOUNDARY_CANDIDATE_LIMITS[depth]
    for entry in state.values():
        entry["chosen"], entry["omitted"] = entry["candidates"][:limit], entry["candidates"][limit:]

    # Coverage redistribution. The cap is per component, so a boundary ranked
    # just below it reaches no analyzer at all and can never acquire a finding —
    # juice-shop 2026-07-27 lost tb-5 (the LLM egress) this way, at rank 5 of 4
    # on its only eligible component.
    #
    # The fix must not simply append past the cap: with more boundaries than
    # capacity that degenerates into no cap at all. Instead swap, and only
    # against a boundary some OTHER component already covers. Each component
    # keeps exactly `limit` rows, and the trade is strictly positive — the
    # displaced crossing is still analyzed elsewhere, the uncovered one stops
    # being invisible. When nothing is displaceable the gap is real and gets
    # reported below rather than papered over.
    def _covered_elsewhere(bid: str, owner: str) -> bool:
        return any(item[1]["id"] == bid for cid, entry in state.items() if cid != owner for item in entry["chosen"])

    covered = {boundary["id"] for entry in state.values() for _r, boundary, _f, _rs in entry["chosen"]}
    redistributed: dict[str, str] = {}
    for boundary in boundaries:
        bid = boundary.get("id")
        if boundary.get("resolution_status") != "resolved" or bid in covered:
            continue
        best: tuple[str, tuple] | None = None
        for cid, entry in state.items():
            for item in entry["omitted"]:
                if item[1]["id"] == bid and (best is None or item[0] < best[1][0]):
                    best = (cid, item)
        if best is None:
            continue
        cid, item = best
        displaceable = [c for c in state[cid]["chosen"] if _covered_elsewhere(c[1]["id"], cid)]
        if not displaceable:
            continue
        victim = max(displaceable, key=lambda c: c[0])
        state[cid]["chosen"] = [c for c in state[cid]["chosen"] if c[1]["id"] != victim[1]["id"]] + [item]
        state[cid]["omitted"] = [o for o in state[cid]["omitted"] if o[1]["id"] != bid] + [victim]
        redistributed[bid] = cid
        covered.add(bid)

    for cid, entry in state.items():
        context_rows = [
            {
                key: deepcopy(boundary[key])
                for key in ("id", "name", "from", "to", "kind", "assumption", "evidence", "confidence")
                if key in boundary
            }
            | {"focus": focus, "focus_reasons": reasons}
            for _rank, boundary, focus, reasons in entry["chosen"]
        ]
        if context_rows:
            component_dir = context_root / cid
            component_dir.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                context_root / cid / "trust-boundaries.json",
                {"schema_version": 1, "adjacent_trust_boundaries": context_rows},
                sort_keys=False,
            )
        audit["components"][cid] = {
            "eligible_ids": [item[1]["id"] for item in entry["candidates"]],
            "selected_ids": [item[1]["id"] for item in entry["chosen"]],
            "omitted_ids": [item[1]["id"] for item in entry["omitted"]],
            "deferred_ids": sorted(set(entry["deferred"]), key=_numeric_id),
            "invalid_ids": sorted(set(entry["invalid"]), key=_numeric_id),
            "focus_reasons": {item[1]["id"]: item[3] for item in entry["candidates"]},
        }
        if entry["inherited_from"]:
            audit["components"][cid]["inherited_from"] = entry["inherited_from"]

    # Coverage is only derivable by cross-referencing every component, so state
    # it once. An uncovered resolved boundary reaches no analyzer and can never
    # acquire a finding — that is a reportable gap, not a quiet omission.
    resolved_ids = [b["id"] for b in boundaries if b.get("resolution_status") == "resolved"]
    uncovered = [bid for bid in resolved_ids if bid not in covered]
    audit["coverage"] = {
        "resolved_ids": sorted(resolved_ids, key=_numeric_id),
        "covered_ids": sorted(covered, key=_numeric_id),
        "uncovered_ids": sorted(uncovered, key=_numeric_id),
        "redistributed": redistributed,
    }
    for bid, cid in redistributed.items():
        print(
            f"TRUST_BOUNDARY_WARN: {bid}: swapped into {cid} to keep it covered — "
            "it fell below the per-component cap everywhere",
            file=sys.stderr,
        )
    for bid in uncovered:
        print(
            f"TRUST_BOUNDARY_WARN: {bid}: resolved boundary reached no STRIDE component — "
            "it can acquire no findings this run",
            file=sys.stderr,
        )
    atomic_write_json(context_root / "trust-boundary-selection.json", audit, sort_keys=False)
    return audit


def validate_finding_boundary_refs(
    finding: dict,
    *,
    boundaries: Iterable[dict],
    origin_component_id: str | None,
    candidate_ids: set[str] | None,
    require_candidate: bool,
    known_component_ids: set[str] | None = None,
) -> tuple[list[dict], list[str]]:
    """Fail-open validation for optional finding traceability.

    Invalid references are removed while the security finding is retained.
    ``candidate_ids`` is required only at the fresh analyzer→merge boundary;
    carried findings are checked against canonical existence, adjacency and
    surviving evidence instead.
    """
    boundary_by_id = {
        row.get("id"): row for row in boundaries if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    evidence: set[tuple[str, int | None]] = set()
    primary = finding.get("evidence")
    primary_rows = primary if isinstance(primary, list) else [primary]
    for item in [*primary_rows, *(finding.get("instances") or [])]:
        if isinstance(item, dict) and item.get("file"):
            evidence.add((str(item["file"]), item.get("line")))
    cleaned: list[dict] = []
    diagnostics: list[str] = []
    seen: set[tuple[str, str]] = set()
    for ref in finding.get("boundary_refs") or []:
        if not isinstance(ref, dict):
            diagnostics.append("removed malformed boundary reference")
            continue
        boundary_id = ref.get("boundary_id")
        origin = ref.get("origin_component_id")
        key = (str(boundary_id or ""), str(origin or ""))
        boundary = boundary_by_id.get(boundary_id)
        reason: str | None = None
        if key in seen:
            reason = f"removed duplicate reference {boundary_id!r}"
        elif boundary is None:
            reason = f"removed unknown boundary reference {boundary_id!r}"
        elif boundary.get("resolution_status") != "resolved" or boundary.get("confidence") != "confirmed":
            reason = f"removed non-confirmed/non-resolved boundary reference {boundary_id!r}"
        elif (
            not boundary_endpoints_valid(boundary, known_component_ids)
            if known_component_ids is not None
            else not _boundary_endpoint_shape_valid(boundary)
        ):
            reason = f"removed invalid-canonical-endpoint boundary reference {boundary_id!r}"
        elif origin_component_id is not None and origin != origin_component_id:
            reason = f"removed wrong-origin boundary reference {boundary_id!r}"
        elif not isinstance(origin, str) or origin not in {boundary.get("from"), boundary.get("to")}:
            reason = f"removed non-adjacent boundary reference {boundary_id!r}"
        elif require_candidate and (candidate_ids is None or boundary_id not in candidate_ids):
            reason = f"removed current-run non-candidate boundary reference {boundary_id!r}"
        elif not isinstance(ref.get("rationale"), str) or not 20 <= len(ref["rationale"].strip()) <= 240:
            reason = f"removed invalid-rationale boundary reference {boundary_id!r}"
        locations = ref.get("evidence_locations")
        if reason is None and (
            not isinstance(locations, list)
            or not locations
            or len(locations) > 3
            or any(
                not isinstance(location, dict) or (location.get("file"), location.get("line")) not in evidence
                for location in locations
            )
        ):
            reason = f"removed evidence-free/non-owned boundary reference {boundary_id!r}"
        if reason:
            diagnostics.append(reason)
            continue
        seen.add(key)
        cleaned.append(deepcopy(ref))
        if len(cleaned) == 2:
            break
    return cleaned, diagnostics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    norm = sub.add_parser("normalize")
    norm.add_argument("--repo-root", type=Path, required=True)
    norm.add_argument("--sidecar", type=Path, required=True)
    norm.add_argument("--prior-model", type=Path)
    norm.add_argument("--output-dir", type=Path, required=True)
    ctx = sub.add_parser("contexts")
    ctx.add_argument("--repo-root", type=Path, required=True)
    ctx.add_argument("--output-dir", type=Path, required=True)
    ctx.add_argument("--depth", choices=("quick", "standard", "thorough"), required=True)
    ctx.add_argument("--component", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.operation == "normalize":
            result, warnings = normalize(
                repo_root=args.repo_root,
                sidecar=args.sidecar,
                prior_model=args.prior_model,
                output_dir=args.output_dir,
            )
            print(json.dumps({"boundaries": len(result["trust_boundaries"]), "warnings": len(warnings)}))
        else:
            audit = prepare_contexts(
                repo_root=args.repo_root,
                output_dir=args.output_dir,
                component_ids=args.component,
                depth=args.depth,
            )
            print(json.dumps({"components": len(audit["components"])}))
    except (OSError, ValueError, jsonschema.ValidationError) as exc:
        print(f"prepare_trust_boundary_context: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
