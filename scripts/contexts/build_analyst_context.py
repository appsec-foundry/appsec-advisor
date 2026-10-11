#!/usr/bin/env python3
"""contexts/build_analyst_context.py — read-only context adapters of one analyst job.

Projects the requirements catalog, durable business context, an optional
structured threat model, the selected questions and methodology criteria, and
an optional feature declaration into one bounded ``analyst-context`` document.

Sources are data, never instructions, and never authority. A source the caller
marks as required must be present and valid, or the build fails with
``ContextError(required=True)``; the dependent assessment cannot complete. An
absent optional source is recorded and analysis continues. A configured
requirements catalog is never replaced by the packaged fallback; the fallback
applies only when no catalog is configured. Content with a detected secret is
withheld and recorded as ``sensitive``. Nothing here writes, fetches, or reads
live assessment intermediates.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import fnmatch
import hashlib
import json
import os
import stat
from pathlib import Path

import yaml
from requirements.requirements_state import validate_catalog
from validators.secret_scan import scan_text
from validators.validate_analyst import schema_errors
from validators.validate_intermediate import validate_threat_model_output

from contexts.load_business_context import repository_source

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
FALLBACK_CATALOG = PLUGIN_ROOT / "data" / "appsec-bestpractices-baseline.yaml"
MAX_SOURCE_BYTES = {"requirements": 512 * 1024, "business_context": 64 * 1024, "threat_model": 2 * 1024 * 1024}
MAX_REQUIREMENTS = 300
MAX_REQUIREMENT_TEXT = 1000
THREAT_FIELDS = ("id", "title", "component", "stride", "risk", "_status", "cwe", "controls_in_place", "mitigation_ids")
COMPONENT_FIELDS = ("id", "name", "description", "paths", "sensitive_data")
BOUNDARY_FIELDS = (
    "id",
    "name",
    "from",
    "to",
    "assumption",
    "assumption_verdict",
    "enforcement_point",
    "covers_components",
)
MITIGATION_FIELDS = ("id", "title", "priority", "threat_ids")
ACTOR_FIELDS = ("id", "label", "access")
CONTROL_FIELDS = ("domain", "control", "effectiveness", "linked_threats")
# The projection is bounded by size, not item counts, so a large model keeps
# the entries most relevant to the analyzed change instead of the first ones.
MAX_PROJECTION_BYTES = 96 * 1024
MAX_FIELD_CHARS = 300
MAX_EVIDENCE_FILES = 5
RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SECTION_CAPS = {"components": 200, "trust_boundaries": 200}
QUESTION_FIELDS = ("ref", "topic", "applies_when", "asks", "purpose", "evidence", "requirement_refs", "negative_tests")


class ContextContractError(Exception):
    """The built context violates its own schema: a defect, not missing input."""


class ContextError(Exception):
    """A source could not be delivered; ``required`` sources block the job."""

    def __init__(self, message: str, required: bool):
        super().__init__(message)
        self.required = required


def _read(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("not a regular file")
        body = handle.read(limit + 1)
    if len(body) > limit:
        raise OverflowError("too large")
    return body


def _load(kind: str, path: Path, origin: str, required: bool) -> tuple[dict, bytes | None]:
    """Read one source; return (source record, bytes or None when withheld)."""
    record = {"kind": kind, "origin": origin, "label": path.name, "required": required}
    try:
        body = _read(path, MAX_SOURCE_BYTES[kind])
    except FileNotFoundError:
        status = "absent"
    except OverflowError:
        status = "too_large"
    except (OSError, ValueError):
        status = "invalid"
    else:
        record["sha256"] = hashlib.sha256(body).hexdigest()
        if scan_text(body.decode("utf-8", "replace")):
            status = "sensitive"
        else:
            return dict(record, status="delivered"), body
    if required:
        raise ContextError(f"required {kind} source {path.name} is {status}", required=True)
    return dict(record, status=status), None


def _requirements(path: Path | None, required: bool) -> tuple[dict, list[dict]]:
    if path is None:
        record, body = _load("requirements", FALLBACK_CATALOG, "packaged_fallback", False)
    else:
        record, body = _load("requirements", path, "configured", required)
    if body is None:
        return record, []
    errors, _warnings = validate_catalog(body)
    if errors:
        if record["required"]:
            raise ContextError(f"required requirements catalog {record['label']} is invalid", required=True)
        return dict(record, status="invalid"), []
    entries = [
        {
            "id": str(req["id"]),
            "text": str(req.get("text") or "")[:MAX_REQUIREMENT_TEXT],
            **({"priority": str(req["priority"])} if req.get("priority") else {}),
        }
        for category in yaml.safe_load(body).get("categories") or []
        for req in category.get("requirements") or []
    ]
    if len(entries) > MAX_REQUIREMENTS:
        if record["required"]:
            raise ContextError("required requirements catalog exceeds the delivery limit", required=True)
        return dict(record, status="truncated"), entries[:MAX_REQUIREMENTS]
    return record, entries


def public_id(raw: object) -> str:
    """The finding id a reader sees: the report renders the model's ``T-NNN`` as ``F-NNN``."""
    text = str(raw)
    return "F-" + text[2:] if text.startswith("T-") else text


def _matches(path: str, pattern: str) -> bool:
    pattern = str(pattern)
    if pattern.endswith("/"):
        return path.startswith(pattern)
    return path == pattern or fnmatch.fnmatch(path, pattern) or path.startswith(pattern.rstrip("/") + "/")


def _clip(item: dict, fields: tuple[str, ...]) -> dict:
    out = {}
    for key in fields:
        if key in item and item[key] not in (None, "", []):
            value = item[key]
            out[key] = value[:MAX_FIELD_CHARS] if isinstance(value, str) else value
    return out


def _project(data: dict, focus_paths: list[str]) -> dict:
    """Relevance-ordered, size-bounded projection of a validated threat model.

    Components whose paths cover a focus path come first, then their threats,
    boundaries, and mitigations; the rest follows by risk. Entries that do not
    fit ``MAX_PROJECTION_BYTES`` are counted in ``omitted``.
    """
    components = [c for c in data.get("components") or [] if isinstance(c, dict)]
    focus = [
        str(c.get("id"))
        for c in components
        if any(_matches(fp, pattern) for fp in focus_paths for pattern in c.get("paths") or [])
    ]
    focus_set = set(focus)

    def rank_threat(t: dict) -> tuple:
        return (str(t.get("component")) not in focus_set, RISK_ORDER.get(str(t.get("risk")), 4), str(t.get("id")))

    threats = []
    for t in sorted((t for t in data.get("threats") or [] if isinstance(t, dict)), key=rank_threat):
        entry = _clip(t, THREAT_FIELDS)
        entry["id"] = public_id(t.get("id"))
        files = [str(e.get("file")) for e in t.get("evidence") or [] if isinstance(e, dict) and e.get("file")]
        if files:
            entry["files"] = list(dict.fromkeys(files))[:MAX_EVIDENCE_FILES]
        threats.append(entry)
    focus_threats = {t["id"] for t in threats if str(t.get("component")) in focus_set}
    mitigations = []
    for m in data.get("mitigations") or []:
        if isinstance(m, dict):
            entry = _clip(m, MITIGATION_FIELDS)
            entry["threat_ids"] = [public_id(x) for x in m.get("threat_ids") or []]
            mitigations.append(entry)
    mitigations.sort(key=lambda m: not set(m["threat_ids"]) & focus_threats)
    boundaries = [_clip(b, BOUNDARY_FIELDS) for b in data.get("trust_boundaries") or [] if isinstance(b, dict)]
    boundaries.sort(key=lambda b: not set(map(str, b.get("covers_components") or [])) & focus_set)
    sections = {
        "components": sorted(
            (_clip(c, COMPONENT_FIELDS) for c in components), key=lambda c: str(c.get("id")) not in focus_set
        ),
        "threats": threats,
        "trust_boundaries": boundaries,
        "mitigations": mitigations,
        "actors": [_clip(a, ACTOR_FIELDS) for a in data.get("actors") or [] if isinstance(a, dict)],
        "security_controls": [
            _clip(c, CONTROL_FIELDS) for c in data.get("security_controls") or [] if isinstance(c, dict)
        ],
    }
    projection = {"generated": str((data.get("meta") or {}).get("generated", ""))[:64], "focus_components": focus}
    projection.update({name: [] for name in sections})
    omitted: dict[str, int] = {}
    budget = MAX_PROJECTION_BYTES - len(json.dumps(projection))
    # Round-robin keeps every section represented when the budget runs out.
    queues = {name: list(items) for name, items in sections.items()}
    while any(queues.values()):
        for name, queue in queues.items():
            if not queue:
                continue
            item = queue.pop(0)
            size = len(json.dumps(item, ensure_ascii=False)) + 2
            if size <= budget and len(projection[name]) < SECTION_CAPS.get(name, 500):
                projection[name].append(item)
                budget -= size
            else:
                omitted[name] = omitted.get(name, 0) + 1
    if omitted:
        projection["omitted"] = omitted
    return projection


def _threat_model(path: Path | None, required: bool, focus_paths: list[str]) -> tuple[dict | None, dict | None]:
    if path is None:
        return None, None
    record, body = _load("threat_model", path, "caller", required)
    if body is None:
        return record, None
    try:
        data = yaml.safe_load(body)
        valid, _errors = validate_threat_model_output(data)
    except yaml.YAMLError:
        valid = False
    from shared.assessment_sources import is_portable_model, single_repository_only

    if valid and is_portable_model(data):
        # Its locations belong to several checkouts; the analysis reads one.
        raise ContextError(
            single_repository_only(
                "the threat analyst",
                f"Rerun without {path.name} (--isolated) or with a single-repository model of this repository",
            ),
            required=True,
        )
    if not valid:
        if required:
            raise ContextError(f"required threat model {path.name} is invalid", required=True)
        return dict(record, status="invalid"), None

    return record, _project(data, focus_paths)


def build(
    request: dict,
    resolved: dict,
    selection: dict,
    requirements_path: Path | None = None,
    requirements_required: bool = False,
    threat_model_path: Path | None = None,
    threat_model_required: bool = False,
    business_context_required: bool = False,
    feature: dict | None = None,
    focus_paths: list[str] | None = None,
) -> dict:
    """Build the context document of one job; ``focus_paths`` order the threat-model projection."""
    sources = []
    record, requirements = _requirements(requirements_path, requirements_required)
    sources.append(record)

    business_text = None
    business_path = repository_source(Path(request["repository"]["root"]))
    if business_path is None:
        if business_context_required:
            raise ContextError("required business context is absent", required=True)
        sources.append(
            {
                "kind": "business_context",
                "origin": "repository",
                "label": "business-context.md",
                "required": False,
                "status": "absent",
            }
        )
    else:
        record, body = _load("business_context", business_path, "repository", business_context_required)
        sources.append(record)
        business_text = body.decode("utf-8", "replace") if body is not None else None

    record, model = _threat_model(threat_model_path, threat_model_required, focus_paths or [])
    if record is not None:
        sources.append(record)
    if feature is not None:
        sources.append(
            {
                "kind": "feature",
                "origin": "caller",
                "label": feature["label"],
                "sha256": feature["sha256"],
                "required": False,
                "status": "delivered",
            }
        )

    context = {
        "schema_version": 1,
        "job_id": request["job_id"],
        "sources": sources,
        "requirements": requirements,
        "business_context": business_text,
        "threat_model": model,
        "feature": feature["declarations"] if feature is not None else None,
        "questions": [{k: q[k] for k in QUESTION_FIELDS if k in q} for q in selection["selected"]],
        "criteria": [
            {"ref": c["ref"], "asks": c["asks"], "principles": c["principle_text"]} for c in resolved["criteria"]
        ],
        "question_selection": {"omitted": selection["omitted"], "required_complete": selection["required_complete"]},
    }
    if schema_errors("context", context):
        raise ContextContractError("analysis context violates its schema")
    return context
