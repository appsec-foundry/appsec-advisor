#!/usr/bin/env python3
"""
merge_threats.py — mechanical preprocessing + deterministic finalization for
Phase 9 threat merging.

Designed as the Python half of a hybrid merger pipeline:

  Step A (collect):  read all .stride-<id>.json files, apply trivially-
                     mechanical dedup (same CWE + STRIDE letter + evidence
                     file+line), emit deterministic auto-decisions for
                     unambiguous groups, and emit only the remaining candidate
                     groups that need LLM judgment. Writes
                     .merge-candidates.json.

  Step B (optional): appsec-threat-merger sub-agent reads candidates, emits
                     merge/keep/consolidate decisions to .merge-decisions.json.

  Step C (finalize): read candidates + decisions, apply decisions, run the
                     deterministic 8-field sort, assign T-001..T-NNN, write
                     .threats-merged.json.

Either step is independently usable. When .merge-decisions.json is absent
during finalize, every candidate group is treated as "keep all" (no merge).

Usage
-----
    python3 merge_threats.py collect  --output-dir <DIR>
    python3 merge_threats.py finalize --output-dir <DIR>

Exit codes: 0 = success, 1 = validation / IO error, 2 = usage error.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import functools
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from _atomic_io import atomic_write_json, atomic_write_text
from _shared_sources import CODE_LEVEL_SOURCES, CONFIG_DEFECT_SOURCES, DESIGN_LEVEL_SOURCES
from weakness_classifier import classify_cwe, classify_threat, load_weakness_classes

# Stable ordering for the T-NNN deterministic sort.
_RISK_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_STRIDE_ORDER = {
    "Spoofing": 0,
    "Tampering": 1,
    "Repudiation": 2,
    "Information Disclosure": 3,
    "Denial of Service": 4,
    "Elevation of Privilege": 5,
}
_STRIDE_LETTER = {
    "Spoofing": "S",
    "Tampering": "T",
    "Repudiation": "R",
    "Information Disclosure": "I",
    "Denial of Service": "D",
    "Elevation of Privilege": "E",
}

_CWE_RE = re.compile(r"^CWE-(\d+)$")
_TH_ID_RE = re.compile(r"^TH-[0-9]{2}$")


@functools.lru_cache(maxsize=1)
def _load_cwe_to_th_map() -> dict[str, str]:
    """Load the cwe_to_th mapping from data/threat-category-taxonomy.yaml."""
    path = Path(__file__).resolve().parent.parent / "data" / "threat-category-taxonomy.yaml"
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError:
        return {}
    raw = doc.get("cwe_to_th") or {}
    # Values may be a list of TH-IDs; take the first.
    result: dict[str, str] = {}
    for cwe, val in raw.items():
        if isinstance(val, list) and val:
            result[str(cwe)] = val[0]
        elif isinstance(val, str):
            result[str(cwe)] = val
    return result


def _threat_category_id_for(t: dict) -> str | None:
    """Return the TH-XX id for a threat based on its CWE, or None."""
    cwe = t.get("cwe")
    if not isinstance(cwe, str):
        return None
    mapping = _load_cwe_to_th_map()
    return mapping.get(cwe)


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------


def _load_stride_outputs(output_dir: Path) -> list[tuple[str, dict]]:
    """Return [(component_id, parsed_json), ...] for every .stride-*.json.

    On invalid JSON: print a context window around the failure and the
    canonical recovery instruction, then exit 1. The orchestrator must
    fix or re-dispatch the single offending component and re-invoke
    merge_threats.py — it must NOT replace the whole pipeline with an
    inline rebuild (a 2026-05-07 production run lost ~5 minutes that way
    after one component emitted invalid JSON).
    """
    pairs: list[tuple[str, dict]] = []
    for path in sorted(output_dir.glob(".stride-*.json")):
        # .stride-auth-service.json → component_id="auth-service"
        comp_id = path.stem[len(".stride-") :]
        try:
            raw = path.read_text()
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            # Recovery: STRIDE analyzers occasionally emit invalid backslash
            # escapes inside code-snippet fields — most often `\!` (a `!` that
            # picked up a backslash crossing a shell / history-expansion layer
            # while the agent wrote the file). `\!` is not a valid JSON escape,
            # so json.loads raises "Invalid \escape". Strip invalid escapes
            # deterministically and retry ONCE before giving up, so the
            # orchestrator no longer has to hand-`sed` each offending escape
            # (a 2026-05-31 juice-shop run burned ~10 turns whack-a-moling
            # `\!=`, `\!currentPassword`, `OK\!` one at a time).
            cleaned = _strip_invalid_json_escapes(raw)
            try:
                data = json.loads(cleaned)
            except json.JSONDecodeError:
                window = _json_error_context(raw, exc.pos)
                sys.stderr.write(
                    f"merge_threats: invalid JSON in {path}\n"
                    f"  parser: {exc.msg} at line {exc.lineno} column {exc.colno} (char {exc.pos})\n"
                    f"  component: {comp_id}\n"
                    f"  context (±60 chars around offset {exc.pos}):\n"
                    f"    {window}\n"
                    f"  note: auto-repair of invalid backslash escapes was attempted and did NOT fix it.\n"
                    f"  recovery: fix or regenerate this single .stride-*.json, then re-run\n"
                    f"           `merge_threats.py collect`. Do NOT inline-rebuild .threats-merged.json.\n"
                )
                raise SystemExit(1)
            # Repaired. Persist atomically so every downstream re-read / QA
            # re-parse sees valid JSON, and report what was fixed.
            n_fixed = raw.count("\\") - cleaned.count("\\")
            atomic_write_text(path, cleaned)
            sys.stderr.write(
                f"merge_threats: auto-repaired {n_fixed} invalid JSON escape(s) "
                f"(e.g. \\! → !) in {path.name} and continued.\n"
            )
        pairs.append((comp_id, data))
    return pairs


# Valid JSON string escapes per RFC 8259 §7. A backslash followed by anything
# else is invalid and makes json.loads raise "Invalid \escape".
_VALID_JSON_ESCAPE = set('"\\/bfnrtu')


def _strip_invalid_json_escapes(raw: str) -> str:
    """Drop backslashes that don't begin a valid JSON escape, repairing the
    common `\\!` → `!` corruption STRIDE analyzers emit. `\\(.)` consumes a
    backslash+char as one unit (left-to-right, non-overlapping) so a legitimate
    `\\\\` survives whole and a valid `\\n`/`\\"`/`\\uXXXX`/`\\/` is preserved.
    Idempotent — a no-op on already-valid JSON."""
    return re.sub(
        r"\\(.)",
        lambda m: "\\" + m.group(1) if m.group(1) in _VALID_JSON_ESCAPE else m.group(1),
        raw,
        flags=re.DOTALL,
    )


def _json_error_context(raw: str, pos: int, radius: int = 60) -> str:
    """Return a single-line context window around `pos` with the offending
    char marked, escaping newlines/tabs so the message stays one line."""
    start = max(0, pos - radius)
    end = min(len(raw), pos + radius)
    snippet = raw[start:end]
    # Escape control chars so the diagnostic remains a single readable line.
    snippet = snippet.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    marker_offset = min(pos - start, len(snippet))
    return f"{snippet[:marker_offset]}»{snippet[marker_offset : marker_offset + 1]}«{snippet[marker_offset + 1 :]}"


def _flatten_threats(pairs: list[tuple[str, dict]]) -> list[dict]:
    """Collect all threat records with component provenance attached."""
    out: list[dict] = []
    for comp_id, data in pairs:
        threats = data.get("threats") or []
        if not isinstance(threats, list):
            continue
        comp_name = data.get("component_name") or comp_id
        for t in threats:
            if not isinstance(t, dict):
                continue
            t = dict(t)  # shallow copy — never mutate source
            t.setdefault("component_id", comp_id)
            t.setdefault("component_name", comp_name)
            # STRIDE analyzers write stride_category (not stride) and
            # source='stride-analyzer' (not the canonical 'stride').
            # Normalize here so downstream scripts see valid enum values.
            if not t.get("stride") and t.get("stride_category"):
                t["stride"] = t["stride_category"]
            if t.get("source") in (None, "", "stride-analyzer"):
                t["source"] = _classify_stride_source(t)
            # evidence: STRIDE analyzers sometimes emit a list; the
            # threats-merged schema requires a single object or null.
            # Coerce list→object by taking the first entry.
            ev = t.get("evidence")
            if isinstance(ev, list):
                t["evidence"] = ev[0] if ev and isinstance(ev[0], dict) else None
            # architectural_violation: required field — default False.
            t.setdefault("architectural_violation", False)
            # threat_category_id: required for source=stride; derive from
            # CWE→TH taxonomy when missing OR left as the UNCLASSIFIED
            # sentinel. The STRIDE analyzer is an LLM and sometimes emits
            # "TH-UNCLASSIFIED" even when the threat's CWE has a deterministic
            # mapping (e.g. CWE-829 → TH-14, a floating base-image tag).
            # Backstop those deterministically so the merged artifact meets
            # the ^TH-[0-9]{2}$ contract validate_intermediate enforces,
            # rather than trusting the LLM to apply the map it was handed.
            # If the CWE is genuinely unmappable the sentinel is left intact
            # so validation still surfaces it.
            tcid = t.get("threat_category_id")
            if not tcid or not _TH_ID_RE.match(str(tcid)):
                derived = _threat_category_id_for(t)
                if derived:
                    t["threat_category_id"] = derived
            # M-18 (configuration-defect tail): if the source ended up as
            # `configuration-defect` and the threat has no LLM-authored
            # mitigation_title yet, stamp a review-shaped hint so the §1
            # Top Findings cell renders an actionable next step instead of
            # a bare em-dash. Stride-class threats keep their LLM titles.
            if t.get("source") == "configuration-defect" and not (t.get("mitigation_title") or "").strip():
                t["mitigation_title"] = (
                    "Confirm the secret is committed (not gitignore'd) "
                    "before rotation; review handoff to a secrets-management "
                    "substrate"
                )
            out.append(t)
    return out


# M-3: CVE / configuration-defect signal patterns. These are CONSERVATIVE —
# a STRIDE-analyzer threat is only reclassified when there is strong
# evidence the finding is actually a library-CVE (manifest file in evidence
# + hardcoded-secret config defect (title says "hardcoded" + secret-shaped
# noun). Otherwise STRIDE remains the default — the goal is to AVOID false
# reclassification.
#
# Note: the `dep-scan` re-classification was removed in 2026-05 alongside
# the in-tree SCA producer. CVE-shaped findings no longer enter the merged
# threat set; supply-chain posture flows through emit_sca_practice.py +
# emit_known_bad_libs.py to meta_findings[] instead.
_HARDCODED_RE = re.compile(
    r"\bhardcoded\b.*\b(?:secret|key|token|password|credential|api[- ]?key)\b",
    re.IGNORECASE,
)


def _classify_stride_source(t: dict) -> str:
    """M-3 (safe): Decide whether a STRIDE-analyzer threat should be tagged
    `configuration-defect` (hardcoded secret) instead of the default `stride`.

    Conservative rule — both signals required:
      • configuration-defect → title matches "hardcoded <secret|key|token|…>"
                            AND has at least one evidence file (source location).

    Anything else falls back to `stride`. The goal is to avoid reclassifying
    legitimate STRIDE findings that happen to mention a CVE as a *symptom*.
    """
    title = str(t.get("title") or "")
    ev = t.get("evidence") or {}
    if isinstance(ev, list):
        ev_files = [(e.get("file") or "").strip() for e in ev if isinstance(e, dict) and e.get("file")]
    elif isinstance(ev, dict):
        ev_files = [(ev.get("file") or "").strip()] if ev.get("file") else []
    else:
        ev_files = []

    if _HARDCODED_RE.search(title) and ev_files:
        return "configuration-defect"
    return "stride"


# ---------------------------------------------------------------------------
# Config-scan ingestion (Phase 2.5 → .config-scan-findings.json)
# ---------------------------------------------------------------------------

# Map config-scanner `breach_vector` enum to a numeric breach_distance the
# downstream triage uses. Mirrors agents/appsec-config-scanner.md:106.
_BREACH_VECTOR_TO_DISTANCE = {
    "Internet Anon": 1,
    "Internet User": 2,
    "Internet Priv User": 3,
    "Victim-Required": 4,
    "Build-Time": 3,
    "Repo-Read": 4,
    "n/a": None,
}


def _config_finding_to_threat(f: dict) -> dict:
    """Convert one `.config-scan-findings.json` finding into the merged-threats
    threat shape used by Phase 10/11.

    Default STRIDE category is `Information Disclosure` — the dominant pattern
    for config/IaC misconfigurations (exposed ports, missing TLS, hardcoded
    secrets, missing SCA in CI). Config-scanner agents that emit
    `stride_category` override the default.
    """
    cwes = f.get("cwe") or []
    cwe = cwes[0] if cwes else ""
    severity = f.get("severity") or "Medium"
    stride = f.get("stride") or f.get("stride_category") or "Information Disclosure"
    return {
        "title": f.get("title") or "",
        "scenario": f.get("scenario") or "",
        "stride": stride,
        "risk": severity,
        "likelihood": severity,
        "impact": severity,
        "cwe": cwe,
        "evidence": {
            "file": f.get("file") or "",
            "line": f.get("line"),
        },
        "source": "config-scan",
        "architectural_violation": False,
        "component_id": "ci-cd-pipeline",
        "component_name": "CI/CD pipeline",
        "config_scan_ref": f.get("local_id"),
        "config_check_id": f.get("check_id"),
        # The scanner's slug (`cors-wildcard`, `csp-missing`, …) used by the
        # downstream `emit_config_scan_mitigations.py` to look up canonical
        # remediation prose from its built-in slug map. Falls back to the
        # `check` field, which is the slug form some scanner versions emit.
        # Without this carry-through, the auto-emitter has to guess the slug
        # from the threat title — fragile when the LLM rewrites the title.
        "config_check_slug": f.get("check_slug") or f.get("check"),
        "iac_type": f.get("iac_type"),
        "breach_distance": _BREACH_VECTOR_TO_DISTANCE.get(f.get("breach_vector") or "n/a"),
        "mitigation_title": f.get("recommended_mitigation_title"),
        "finding_type_id": f.get("finding_type_id"),
    }


# `dep-scan` ingestion (`.dep-scan.json` → CVE-shaped threats) was removed
# in 2026-05. Supply-chain posture now arrives via the §7.11 control rows
# emitted by `emit_sca_practice.py` and the architectural meta-findings
# emitted by `emit_known_bad_libs.py` — both written to dedicated sidecars
# and merged into the final yaml by `build_threat_model_yaml.py`.


# ---------------------------------------------------------------------------
# Source-auth ingestion (scripts/source_auth_scanner.py →
# .source-auth-findings.json). Deterministic AUTHZ-NNN pattern findings
# for IDOR / BFLA / mass-assignment / JWT-verify pitfalls / sensitive-route
# auth-middleware coverage. Loaded only when the sidecar file exists; the
# scanner is opt-in and the merger degrades gracefully when absent.
# ---------------------------------------------------------------------------

# Source-scanner check-id → STRIDE category. Conservative mapping — the
# scanner produces deterministic findings whose STRIDE class is fixed by the
# pattern semantics (so we do not have to LLM-classify after the fact).
_AUTHZ_TO_STRIDE: dict[str, str] = {
    "AUTHZ-001": "Tampering",  # BFLA via attacker-controlled owner ID
    "AUTHZ-002": "Tampering",  # IDOR via raw URL parameter
    "AUTHZ-003": "Elevation of Privilege",  # Mass assign privilege field
    "AUTHZ-004": "Elevation of Privilege",  # Mass assign whole body
    "AUTHZ-005": "Spoofing",  # JWT verify without algorithms
    "AUTHZ-006": "Spoofing",  # JWT decode without verify
    "AUTHZ-007": "Spoofing",  # express-jwt without algorithms
    "AUTHZ-008": "Elevation of Privilege",  # Missing auth middleware
    "AUTHZ-301": "Elevation of Privilege",  # Confirmed IDOR/BOLA (authz_confirm.py)
    "AUTHZ-302": "Elevation of Privilege",  # Confirmed missing route auth (authz_confirm.py)
    "INJ-001": "Tampering",  # SQL injection — request data in query string
    "INJ-002": "Elevation of Privilege",  # Command injection — shell RCE
    "INJ-003": "Information Disclosure",  # SSRF — reach internal targets
}


def _guess_component_from_path(file_path: str) -> tuple[str, str]:
    """Best-guess initial (component_id, component_name) from the file path.

    reclassify_components.py later refines this against the orchestrator's
    actual components[].paths globs — when exactly one component matches
    the evidence file the threat is reassigned automatically. The values
    we emit here only matter when the auto-reassignment can't decide.
    """
    p = file_path.replace("\\", "/").lower()
    if any(
        p.startswith(prefix)
        for prefix in (
            "frontend/",
            "client/",
            "web/",
            "ui/",
            "src/app/",
            "app/components/",
        )
    ):
        return ("frontend", "Frontend SPA")
    if any(
        p.startswith(prefix)
        for prefix in (
            "models/",
            "db/",
            "database/",
            "schema/",
            "prisma/",
            "migrations/",
        )
    ):
        return ("data-layer", "Data Layer")
    # Default for everything else (routes/, lib/, controllers/, server.ts,
    # app.ts, …) — the dominant case for Node.js backend apps.
    return ("backend-api", "Backend API")


def _source_auth_finding_to_threat(f: dict) -> dict:
    """Convert one `.source-auth-findings.json` finding into the merged-threats
    threat record shape used by Phase 10/11."""
    cwes = f.get("cwe") or []
    cwe = cwes[0] if cwes else ""
    check_id = f.get("check_id") or ""
    stride = _AUTHZ_TO_STRIDE.get(check_id, "Tampering")
    severity = f.get("severity") or "Medium"
    file_path = f.get("file") or ""
    component_id, component_name = _guess_component_from_path(file_path)
    return {
        "title": f.get("title") or "",
        "scenario": f.get("scenario") or "",
        "stride": stride,
        "risk": severity,
        "likelihood": severity,
        "impact": severity,
        "cwe": cwe,
        "evidence": {
            "file": file_path,
            "line": f.get("line"),
        },
        "source": "source-scan",
        "architectural_violation": False,
        "component_id": component_id,
        "component_name": component_name,
        "source_scan_ref": f.get("local_id"),
        "source_check_id": check_id,
        "source_type": f.get("source_type"),
        "breach_distance": _BREACH_VECTOR_TO_DISTANCE.get(f.get("breach_vector") or "n/a"),
        "mitigation_title": f.get("recommended_mitigation_title"),
        "finding_type_id": f.get("finding_type_id"),
    }


def _load_source_auth_findings(output_dir: Path, filename: str = ".source-auth-findings.json") -> list[dict]:
    """Load a source-auth-findings-shaped sidecar and convert each finding into
    a merged-threats threat record. Default file is
    `.source-auth-findings.json` (scripts/source_auth_scanner.py); the same
    loader also ingests `.authz-confirm-findings.json`
    (scripts/authz_confirm.py) — both share the schema and converter.

    Missing file → empty list (both producers are presence-gated; absence is the
    default state on repos that have not yet adopted them).
    """
    path = output_dir / filename
    if not path.exists():
        return []
    try:
        with path.open(encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(
            f"merge_threats: failed to read {path}: {exc}\n"
            f"  recovery: the source-auth ingestion is non-fatal — continuing "
            f"with STRIDE-only / config-scan threats.\n"
        )
        return []
    if isinstance(doc, dict) and doc.get("parse_error"):
        return []
    findings = doc.get("findings") or [] if isinstance(doc, dict) else []
    if not isinstance(findings, list):
        return []
    return [_source_auth_finding_to_threat(f) for f in findings if isinstance(f, dict)]


def _load_config_scan_findings(output_dir: Path) -> list[dict]:
    """Load `.config-scan-findings.json` (Phase 2.5 output) and convert each
    finding into a merged-threats threat record.

    Missing file or parse-error stub → empty list (graceful degradation; the
    config-scanner is optional and may be skipped on repos without any IaC
    artifacts).
    """
    path = output_dir / ".config-scan-findings.json"
    if not path.exists():
        return []
    try:
        with path.open(encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(
            f"merge_threats: failed to read {path}: {exc}\n"
            f"  recovery: the config-scan ingestion is non-fatal — continuing "
            f"with STRIDE-only threats.\n"
        )
        return []
    # Error stub shape (top-level parse_error + empty findings) → degrade.
    if isinstance(doc, dict) and doc.get("parse_error"):
        return []
    findings = doc.get("findings") or [] if isinstance(doc, dict) else []
    if not isinstance(findings, list):
        return []
    return [_config_finding_to_threat(f) for f in findings if isinstance(f, dict)]


# ---------------------------------------------------------------------------
# Candidate grouping
# ---------------------------------------------------------------------------

_TITLE_STOPWORDS = {
    "the",
    "a",
    "an",
    "in",
    "on",
    "of",
    "to",
    "for",
    "via",
    "due",
    "is",
    "are",
    "can",
    "may",
    "not",
    "no",
    "and",
    "or",
    "with",
}


def _normalize_title_keywords(title: str) -> tuple[str, ...]:
    """Tokenize title for near-duplicate detection — lowercase, stopword-
    filtered, deduplicated, sorted. Two titles with the same keyword set
    (modulo word order / articles) produce identical tuples."""
    if not isinstance(title, str):
        return ()
    words = re.findall(r"[A-Za-z0-9]+", title.lower())
    keep = tuple(sorted({w for w in words if w and w not in _TITLE_STOPWORDS}))
    return keep


def _exact_key(t: dict) -> tuple:
    """Trivially-identical dedup key. Two threats with equal keys are the
    same finding seen by two different STRIDE runs (e.g. after a retry)."""
    ev = t.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    return (
        t.get("cwe") or "",
        t.get("stride") or "",
        t.get("component_id") or "",
        ev.get("file") or "",
        ev.get("line"),
        _normalize_title_keywords(t.get("title") or ""),
    )


def _candidate_key(t: dict) -> tuple:
    """Weaker grouping key used for LLM judgment. Threats sharing this key
    *might* describe the same underlying defect across different components
    or endpoints — human/LLM judgment decides."""
    return (
        t.get("cwe") or "",
        t.get("stride") or "",
    )


# RC.G.2 — endpoint-signature extractor for the secondary candidate grouping.
# When two threats share an HTTP endpoint but have different (CWE, STRIDE)
# tuples — e.g. mass-assignment (CWE-915, Tampering) and admin-role-input
# (CWE-269, Elevation of Privilege) both targeting POST /api/Users — the
# legacy `_candidate_key` placed them in DIFFERENT groups and the merger
# agent never saw the pair. The 2026-05 juice-shop run shipped T-005 and
# T-010 as separate findings for exactly this reason (both link to M-004).
#
# This extractor walks the threat's title + scenario for HTTP path tokens
# and returns a normalised set. The secondary grouping bucket is
# (endpoint, cwe_family) so the merger sees the candidate but is not forced
# to merge — its own quality rules (same-TH, distinct-but-related) still
# apply.
_ENDPOINT_RE = re.compile(
    r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)?\s*"
    r"(/(?:api|rest|admin|auth|user|users|account|graphql|v1|v2|v3)"
    r"(?:/[A-Za-z0-9_.\-:{}]+)*)",
    re.IGNORECASE,
)


def _extract_endpoints(t: dict) -> tuple[str, ...]:
    """Return sorted, deduplicated, lowercased endpoint paths referenced in
    the threat's title and scenario. Empty when nothing recognisable was
    found. Path-parameters are stripped (`/api/Users/:id` →
    `/api/users/:id` after lowercase, kept as-is — the merger downstream
    decides whether two parameterised forms are equivalent)."""
    sources: list[str] = []
    title = t.get("title")
    if isinstance(title, str):
        sources.append(title)
    scenario = t.get("scenario")
    if isinstance(scenario, str):
        sources.append(scenario)
    hits: set[str] = set()
    for s in sources:
        for m in _ENDPOINT_RE.finditer(s):
            path = m.group(1).lower().rstrip("/")
            if path:
                hits.add(path)
    return tuple(sorted(hits))


# CWE → coarse exploitation-family bucket. Used by the endpoint grouping
# so that two threats sharing an endpoint AND belonging to the same broad
# class (e.g. access-control family) become merge candidates, while
# unrelated co-located findings (e.g. SQLi vs missing-CORS on the same
# route) stay separate.
_CWE_FAMILY: dict[str, str] = {
    # Access control / authorization
    "CWE-269": "authz",
    "CWE-285": "authz",
    "CWE-639": "authz",
    "CWE-862": "authz",
    "CWE-863": "authz",
    "CWE-915": "authz",
    # Authentication
    "CWE-287": "authn",
    "CWE-290": "authn",
    "CWE-306": "authn",
    "CWE-307": "authn",
    "CWE-347": "authn",
    "CWE-640": "authn",
    # Injection family
    "CWE-89": "injection",
    "CWE-78": "injection",
    "CWE-94": "injection",
    "CWE-77": "injection",
    "CWE-917": "injection",
    "CWE-943": "injection",
    "CWE-1336": "injection",
    # XSS
    "CWE-79": "xss",
    # File / SSRF / XXE
    "CWE-22": "file",
    "CWE-434": "file",
    "CWE-611": "file",
    "CWE-918": "file",
    # Crypto
    "CWE-321": "crypto",
    "CWE-327": "crypto",
    "CWE-328": "crypto",
    "CWE-330": "crypto",
    "CWE-798": "crypto",
    "CWE-916": "crypto",
    # Supply-chain / dependency integrity
    "CWE-829": "supply-chain",
    "CWE-1104": "supply-chain",
    "CWE-1357": "supply-chain",
}


def _cwe_family(cwe: str) -> str:
    return _CWE_FAMILY.get(cwe or "", "other")


def _endpoint_candidate_key(t: dict) -> tuple[str, str] | None:
    """Secondary candidate key — returns (endpoint, cwe_family) for the
    FIRST endpoint extracted from the threat (or None when no endpoint
    is detectable). When two threats share this key the merger agent
    will see them as a candidate group; the existing same-TH /
    distinct-sink rules keep distinct findings intact."""
    eps = _extract_endpoints(t)
    if not eps:
        return None
    return (eps[0], _cwe_family(t.get("cwe", "")))


def _dedupe_exact(threats: list[dict]) -> list[dict]:
    """Collapse threats that are trivially identical. Preserves first-seen
    order; subsequent duplicates are dropped after appending their
    component_id into `merged_from`."""
    out: list[dict] = []
    by_key: dict[tuple, dict] = {}
    for t in threats:
        k = _exact_key(t)
        if k in by_key:
            primary = by_key[k]
            mf = primary.setdefault("merged_from", [primary.get("component_id")])
            cid = t.get("component_id")
            if cid and cid not in mf:
                mf.append(cid)
            continue
        by_key[k] = t
        out.append(t)
    return out


def _evidence_identity_key(t: dict) -> tuple | None:
    """Evidence-centric identity key — the SAME code location + the SAME
    weakness class is the SAME finding, regardless of which STRIDE letter an
    analyzer assigned, which component scanned it, or how the title was
    phrased.

    This reunites the cross-STRIDE / cross-component duplicate that the
    ``(CWE, STRIDE)`` candidate key (``_candidate_key``) cannot: when two
    component analyzers scan an overlapping path glob (e.g. ``express-backend``
    over ``routes/**`` and ``b2b-api`` over ``routes/b2bOrder.ts``) they report
    the same defect but may disagree on STRIDE (Tampering vs Elevation of
    Privilege) and phrase the title differently ("Remote code execution…" vs
    "RCE…"). ``_exact_key`` includes STRIDE + component + title-keywords, so it
    misses them; the ``(CWE, STRIDE)`` grouping then splits them into separate
    buckets the merger never compares. (2026-06 juice-shop: T-004/T-009 shipped
    as two Critical findings for the identical ``routes/b2bOrder.ts:23`` RCE,
    both pointing at the same mitigation M-010.)

    Returns ``None`` when the evidence lacks a concrete positive line — a bare
    file (line 0 / absent) is too coarse to assert identity, since many
    distinct findings can legitimately share a file.

    The third key element is the CWE's exploitation FAMILY (``_cwe_family``),
    not the exact CWE. This reunites the same code object flagged under sibling
    CWEs from different STRIDE lenses — e.g. a hardcoded RSA key reported as
    CWE-321 (Spoofing) *and* CWE-798 (Information Disclosure), or weak+unsalted
    MD5 as CWE-327 *and* CWE-328 — which an exact-CWE key split into two
    findings the merger never compared. Families are coarse and curated; the
    catch-all ``other`` bucket falls back to the exact CWE, so two unclassified
    weaknesses at one line stay separate unless their CWE is literally identical
    (the pre-2026-06-26 behavior). Net: the OBJECT — not its STRIDE letter or
    its precise CWE label — is the identity, while ``other``-family findings
    keep the conservative exact-CWE guard."""
    ev = t.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    f = (ev.get("file") or "").strip().lower()
    ln = ev.get("line")
    cwe = (t.get("cwe") or "").strip()
    if not f or not cwe or not isinstance(ln, int) or isinstance(ln, bool) or ln <= 0:
        return None
    family = _cwe_family(cwe)
    return (f, ln, family if family != "other" else cwe)


def _declassify_config_title(title: str) -> str:
    """Strip a trailing per-instance file/line locator from a config-scan
    title so the consolidated systemic finding reads as a class label.

    `"Base image must be digest-pinned — Dockerfile"` → `"Base image must be
    digest-pinned"`; `"GITHUB_TOKEN scope minimization — ci.yml"` → `"GITHUB_TOKEN
    scope minimization"`; `"… permissions block (ci.yml)"` → `"… permissions
    block"`. Conservative: the dash-locator is only stripped when the tail looks
    like a filename (extension, path, line suffix, or Dockerfile), never on a
    title that merely contains a dash."""
    s = (title or "").strip()
    s = re.sub(r"\s*\([^()]*\)\s*$", "", s)  # trailing "(ci.yml)" parenthetical
    s = re.sub(
        r"\s+[—–-]\s+(?:[\w./-]+\.\w+(?::\d+)?|Dockerfile\S*(?::\d+)?)\s*$",
        "",
        s,
    )
    return s.strip() or (title or "").strip()


def _consolidate_config_checks(threats: list[dict]) -> list[dict]:
    """Collapse N config-scan findings sharing the same ``config_check_id`` into
    ONE systemic finding, preserving every hit as an ``instances[]`` entry.

    One mechanical IaC/CI check (e.g. IAC-001 "base image digest-pinned") fires
    once per matching file — or once per FROM stage of a single multi-stage
    Dockerfile. The coarse ``(CWE, STRIDE)`` candidate key bundles every config
    finding into one un-mergeable bucket (all share CWE-732 / Information
    Disclosure), and ``_auto_decision_for_group`` keys its fingerprints on
    ``evidence.file`` + line, so N different files/lines never auto-merge. The
    result was the 2026-06-13 juice-shop run shipping 74 config findings that
    were really ~13 distinct checks.

    This deterministic pass keys purely on ``config_check_id``: same id →
    one survivor (highest-risk member) carrying ``instances[]`` (each
    ``{file, line, snippet?}``), a derived ``affected_files[]`` summary,
    ``instance_count``, and ``systemic: true``. The survivor title is
    declassified (per-file locator stripped). Config findings WITHOUT a
    ``config_check_id`` (e.g. secret-scan hits like a hardcoded API key) and
    all non-config threats pass through untouched.

    Runs in ``cmd_collect`` AFTER ``_dedupe_evidence`` and BEFORE
    ``_group_candidates`` so the merger never sees the per-instance repeats.
    Deterministic; no LLM."""
    from collections import OrderedDict

    buckets: OrderedDict[str, list[dict]] = OrderedDict()
    out: list[dict] = []
    for t in threats:
        cid = t.get("config_check_id") if t.get("source") == "config-scan" else None
        if cid:
            buckets.setdefault(cid, []).append(t)
        else:
            out.append(t)

    for cid, members in buckets.items():
        if len(members) == 1:
            out.append(members[0])
            continue
        # Highest-risk member is the survivor base (tie → first-seen, stable).
        survivor = dict(sorted(members, key=lambda m: _risk_rank(m.get("risk")))[0])
        instances: list[dict] = []
        files: list[str] = []
        for m in members:
            ev = m.get("evidence") or {}
            f = (ev.get("file") or "").strip()
            inst: dict = {"file": f, "line": ev.get("line")}
            sn = (ev.get("snippet") or ev.get("excerpt") or "").strip()
            if sn:
                inst["snippet"] = sn
            instances.append(inst)
            if f and f not in files:
                files.append(f)
        survivor["instances"] = instances
        survivor["affected_files"] = sorted(files)
        survivor["instance_count"] = len(instances)
        survivor["systemic"] = True
        survivor["title"] = _declassify_config_title(survivor.get("title", ""))
        # Record the consolidated local_ids for traceability.
        refs = [m.get("config_scan_ref") for m in members if m.get("config_scan_ref")]
        if refs:
            survivor["consolidated_refs"] = refs
        out.append(survivor)
    return out


# ---------------------------------------------------------------------------
# Generalized consolidation (2026-06-15): collapse findings that are
# manifestations of ONE shared mechanism/object into a single systemic finding,
# driven by the declarative catalog data/consolidation-groups.yaml. This is the
# CWE-/source-agnostic superset of _consolidate_config_checks: it groups across
# STRIDE + scanner + config sources (e.g. JWT verification split over CWE-347/
# 287/345 and over lib/insecurity.ts + route call-sites). A finding that matches
# no group is left untouched (per_instance default) — IDOR/XSS stay distinct.
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _load_consolidation_groups() -> tuple:
    """Load + lightly validate data/consolidation-groups.yaml. Returns a tuple
    of group dicts (tuple so the lru_cache result is hashable/immutable-ish).
    Missing/unreadable catalog → empty tuple (consolidation becomes a no-op)."""
    path = Path(__file__).resolve().parent.parent / "data" / "consolidation-groups.yaml"
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError:
        return ()
    groups = doc.get("groups") or []
    out: list[dict] = []
    for g in groups:
        if isinstance(g, dict) and g.get("id") and isinstance(g.get("match_any"), list):
            out.append(g)
    return tuple(out)


def _glob_match(path: str, pattern: str) -> bool:
    """Glob match tolerant of a leading ``**/`` (fnmatch treats ``*`` as crossing
    ``/`` already, but ``**/foo`` should also match a bare ``foo`` basename)."""
    from fnmatch import fnmatch

    p = (path or "").replace("\\", "/")
    if pattern.startswith("**/"):
        suf = pattern[3:]
        return fnmatch(p, "*/" + suf) or fnmatch(p.rsplit("/", 1)[-1], suf) or fnmatch(p, suf)
    return fnmatch(p, pattern)


def _crit_matches(crit: dict, *, cwe: str, title: str, file_path: str, scid: str, ccid: str) -> bool:
    """True iff EVERY recognized predicate present in ``crit`` holds. An entry
    with no recognized predicate never matches (guards against an empty {} that
    would otherwise swallow every finding)."""
    seen = False
    if "cwe" in crit:
        seen = True
        if cwe not in {str(c).upper() for c in (crit.get("cwe") or [])}:
            return False
    if "source_check_id" in crit:
        seen = True
        if scid not in (crit.get("source_check_id") or []):
            return False
    if "config_check_id" in crit:
        seen = True
        if ccid not in (crit.get("config_check_id") or []):
            return False
    if "title_pattern" in crit:
        seen = True
        try:
            if not re.search(crit["title_pattern"], title or ""):
                return False
        except re.error:
            return False
    if "file_glob" in crit:
        seen = True
        if not any(_glob_match(file_path, gl) for gl in (crit.get("file_glob") or [])):
            return False
    return seen


def _match_consolidation_group(t: dict, groups: tuple) -> dict | None:
    """First group whose ``match_any`` has an entry matching this threat."""
    cwe = (t.get("cwe") or "").strip().upper()
    title = t.get("title") or ""
    ev = t.get("evidence")
    if isinstance(ev, list):
        ev = next((e for e in ev if isinstance(e, dict)), {})
    elif not isinstance(ev, dict):
        ev = {}
    file_path = ev.get("file") or ""
    scid = t.get("source_check_id") or ""
    ccid = t.get("config_check_id") or ""
    for g in groups:
        for crit in g.get("match_any") or []:
            if isinstance(crit, dict) and _crit_matches(
                crit, cwe=cwe, title=title, file_path=file_path, scid=scid, ccid=ccid
            ):
                return g
    return None


def _group_bucket_key(t: dict, g: dict) -> tuple:
    """Bucket identity for a group member. cross-component groups merge across
    components; per-component (default) keep components apart. ``split_by`` adds
    arbitrary threat-field dimensions (the severity-zone / distinct-flow escape
    hatch); an absent field is a no-op ('')."""
    parts: list[str] = [g["id"]]
    if g.get("scope") != "cross-component":
        parts.append((t.get("component_id") or t.get("component") or "").strip().lower())
    for dim in g.get("split_by") or []:
        parts.append(str(t.get(dim) or ""))
    return tuple(parts)


def _instances_of(m: dict) -> list[dict]:
    """Per-instance records for one member. If the member already carries
    ``instances[]`` (e.g. a config-scan survivor), flatten those; otherwise
    synthesize one from its evidence. Each instance carries its own severity +
    provenance ref so instance-level delta / suppression stays possible."""
    insts = m.get("instances")
    if isinstance(insts, list) and insts:
        out: list[dict] = []
        for i in insts:
            inst = dict(i) if isinstance(i, dict) else {}
            inst.setdefault("severity", m.get("risk"))
            out.append(inst)
        return out
    ev = m.get("evidence")
    if isinstance(ev, list):
        ev = next((e for e in ev if isinstance(e, dict)), {})
    elif not isinstance(ev, dict):
        ev = {}
    inst = {"file": (ev.get("file") or "").strip(), "line": ev.get("line"), "severity": m.get("risk")}
    sn = (ev.get("snippet") or ev.get("excerpt") or "").strip()
    if sn:
        inst["snippet"] = sn
    ref = m.get("local_id") or m.get("source_scan_ref") or m.get("config_scan_ref")
    if ref:
        inst["local_id"] = ref
    return [inst]


def _consolidate_by_group(threats: list[dict]) -> list[dict]:
    """Collapse findings sharing a consolidation-group bucket into ONE systemic
    finding carrying ``instances[]`` / ``affected_files[]`` / ``instance_count``
    / ``systemic`` / ``consolidation_group``. The survivor is the highest-risk
    member (tie → first-seen) and unions every member's ``mitigation_ids`` (so a
    consolidated finding legitimately carries MULTIPLE mitigations — finding↔
    mitigation is 1:n). Non-matching threats pass through untouched.

    Runs in ``cmd_collect`` AFTER ``_consolidate_config_checks`` (so config
    survivors are folded in as instances) and BEFORE ``_group_candidates``.
    Deterministic; no LLM."""
    from collections import OrderedDict

    groups = _load_consolidation_groups()
    if not groups:
        return list(threats)

    passthrough: list[dict] = []
    buckets: OrderedDict[tuple, list[dict]] = OrderedDict()
    bucket_group: dict[tuple, dict] = {}
    for t in threats:
        g = _match_consolidation_group(t, groups)
        if not g:
            passthrough.append(t)
            continue
        bkey = _group_bucket_key(t, g)
        buckets.setdefault(bkey, []).append(t)
        bucket_group.setdefault(bkey, g)

    out: list[dict] = list(passthrough)
    for bkey, members in buckets.items():
        if len(members) == 1:
            out.append(members[0])  # lone match → not systemic, leave as-is
            continue
        g = bucket_group[bkey]
        survivor = dict(sorted(members, key=lambda m: _risk_rank(m.get("risk")))[0])
        instances: list[dict] = []
        files: list[str] = []
        mids: list[str] = []
        refs: list[str] = []
        for m in members:
            for inst in _instances_of(m):
                instances.append(inst)
                f = (inst.get("file") or "").strip()
                if f and f not in files:
                    files.append(f)
            for mid in m.get("mitigation_ids") or []:
                if mid not in mids:
                    mids.append(mid)
            ref = m.get("local_id") or m.get("source_scan_ref") or m.get("config_scan_ref")
            if ref and ref not in refs:
                refs.append(ref)
        survivor["instances"] = instances
        survivor["affected_files"] = sorted(files)
        survivor["instance_count"] = len(instances)
        survivor["systemic"] = True
        survivor["consolidation_group"] = g["id"]
        if g.get("title"):
            survivor["title"] = g["title"]
        if mids:
            survivor["mitigation_ids"] = mids
        if refs:
            survivor["consolidated_refs"] = refs
        out.append(survivor)
    return out


def _dedupe_evidence(threats: list[dict]) -> list[dict]:
    """Collapse threats sharing ``(file, line, CWE)`` — the same vulnerability
    seen by two analyzers that disagreed on STRIDE / component / title.

    Runs AFTER ``_dedupe_exact`` and BEFORE the ``(CWE, STRIDE)`` candidate
    grouping, so the cross-STRIDE duplicate is reunited deterministically in
    the collect phase — before STRIDE-based identity can split it and before
    the (separately fragile) endpoint-grouping / LLM-merger / finalize path is
    reached at all.

    Merge policy: the higher-risk member stays primary (tie → first-seen, for
    order-stable output); the dropped member's ``component_id`` and ``stride``
    are recorded in ``merged_from`` / ``merged_strides`` for traceability.
    Component re-attribution is left to the downstream ``reclassify_components``
    pass, which keys on ``evidence.file``."""
    out: list[dict] = []
    by_key: dict[tuple, dict] = {}
    for t in threats:
        k = _evidence_identity_key(t)
        if k is None:
            out.append(t)
            continue
        prev = by_key.get(k)
        if prev is None:
            by_key[k] = t
            out.append(t)
            continue
        if _risk_rank(t.get("risk")) < _risk_rank(prev.get("risk")):
            keep, dropped = t, prev
            by_key[k] = t
            out[out.index(prev)] = t
        else:
            keep, dropped = prev, t
        mf = keep.setdefault("merged_from", [keep.get("component_id")])
        cid = dropped.get("component_id")
        if cid and cid not in mf:
            mf.append(cid)
        ms = keep.setdefault("merged_strides", [keep.get("stride")])
        ds = dropped.get("stride")
        if ds and ds not in ms:
            ms.append(ds)
        # The family-keyed merge can now collapse SIBLING CWEs (e.g. CWE-321 +
        # CWE-798 for the same key). Record the dropped CWE so the surviving
        # finding still carries every classification facet it absorbed.
        mc = keep.setdefault("merged_cwes", [keep.get("cwe")])
        dc = dropped.get("cwe")
        if dc and dc not in mc:
            mc.append(dc)
    return out


def _group_candidates(threats: list[dict]) -> list[dict]:
    """Group threats sharing the candidate key (CWE + STRIDE). Groups of
    size >= 2 are candidates for LLM-adjudicated merge. Single-element
    groups never need adjudication and are omitted.

    RC.G.2 — adds a SECONDARY grouping pass keyed on (endpoint,
    cwe_family). The primary (CWE, STRIDE) key misses pairs like T-005
    (CWE-915 Tampering) and T-010 (CWE-269 Elevation of Privilege) that
    target the same endpoint via the same exploit primitive. The
    endpoint extractor walks title + scenario for `/api/...`-style paths
    and the family map collapses CWEs into broad exploit classes.

    Groups produced by either pass enter the candidate list with
    distinct `group_id`s; the merger agent applies the contract rules
    (same-TH constraint, distinct-sink rule) and decides per-group.
    """
    primary: dict[tuple, list[dict]] = {}
    for t in threats:
        primary.setdefault(_candidate_key(t), []).append(t)

    out: list[dict] = []
    grouped_ids: set[int] = set()
    for key, members in primary.items():
        if len(members) < 2:
            continue
        cwe, stride = key
        group_hash = hashlib.sha256(f"{cwe}|{stride}|{len(members)}".encode()).hexdigest()[:8]
        out.append(
            {
                "group_id": f"G-{group_hash}",
                "group_key": "cwe_stride",
                "cwe": cwe,
                "stride": stride,
                "member_count": len(members),
                "members": [
                    {
                        "component_id": m.get("component_id"),
                        "component_name": m.get("component_name"),
                        "title": m.get("title"),
                        "evidence": m.get("evidence"),
                        "risk": m.get("risk"),
                        "threat_category_id": m.get("threat_category_id"),
                    }
                    for m in members
                ],
            }
        )
        for m in members:
            grouped_ids.add(id(m))

    # RC.G.2 — secondary endpoint-based grouping. Operates only on
    # threats not already in a primary group (avoids exposing the same
    # pair twice). Produces candidate groups for the LLM merger.
    secondary: dict[tuple[str, str], list[dict]] = {}
    for t in threats:
        if id(t) in grouped_ids:
            continue
        key2 = _endpoint_candidate_key(t)
        if key2 is None:
            continue
        secondary.setdefault(key2, []).append(t)

    for (endpoint, family), members in secondary.items():
        if len(members) < 2:
            continue
        # Distinct CWE / STRIDE values across members is the signal that
        # this group exists because of endpoint co-location, not the
        # primary key. Skip if everyone has the same CWE+STRIDE — that
        # would have been caught by the primary pass.
        sig = {(m.get("cwe") or "", m.get("stride") or "") for m in members}
        if len(sig) <= 1:
            continue
        group_hash = hashlib.sha256(f"{endpoint}|{family}|{len(members)}".encode()).hexdigest()[:8]
        out.append(
            {
                "group_id": f"GE-{group_hash}",
                "group_key": "endpoint_family",
                "endpoint": endpoint,
                "cwe_family": family,
                "member_count": len(members),
                "members": [
                    {
                        "component_id": m.get("component_id"),
                        "component_name": m.get("component_name"),
                        "title": m.get("title"),
                        "evidence": m.get("evidence"),
                        "risk": m.get("risk"),
                        "cwe": m.get("cwe"),
                        "stride": m.get("stride"),
                        "threat_category_id": m.get("threat_category_id"),
                    }
                    for m in members
                ],
            }
        )

    # Deterministic ordering — primary groups first (by CWE then STRIDE
    # then group_id), then secondary groups (by endpoint then group_id).
    def _order(g: dict) -> tuple[int, str, str, str]:
        if g.get("group_key") == "cwe_stride":
            return (0, g.get("cwe") or "", g.get("stride") or "", g["group_id"])
        return (1, g.get("endpoint") or "", g.get("cwe_family") or "", g["group_id"])

    out.sort(key=_order)
    return out


def _risk_rank(risk: Any) -> int:
    return _RISK_ORDER.get(str(risk), 99)


def _auto_decision_for_group(group: dict) -> dict | None:
    """Return a deterministic decision for unambiguous candidate groups.

    Keep this deliberately conservative. Anything that needs semantic
    judgement stays in ``candidate_groups`` for the merger agent.
    """
    members = group.get("members") or []
    if not isinstance(members, list) or len(members) < 2:
        return None

    categories = {m.get("threat_category_id") for m in members if isinstance(m, dict) and m.get("threat_category_id")}
    if len(categories) > 1:
        return {
            "group_id": group.get("group_id"),
            "action": "keep",
            "keep_indices": list(range(len(members))),
            "rationale": (
                "Auto-keep: members span different threat_category_id values; "
                "cross-category findings are distinct architectural patterns."
            ),
            "source": "merge_threats.py:auto",
        }

    fingerprints: set[tuple] = set()
    for m in members:
        if not isinstance(m, dict):
            return None
        ev = m.get("evidence") or {}
        if not isinstance(ev, dict):
            ev = {}
        file_ = ev.get("file")
        line = ev.get("line")
        title = m.get("title")
        cat = m.get("threat_category_id") or ""
        if not file_ or line is None or not title:
            return None
        fingerprints.add(
            (
                cat,
                file_,
                line,
                _normalize_title_keywords(title),
            )
        )

    if len(fingerprints) == 1:
        target = min(
            range(len(members)),
            key=lambda i: (_risk_rank(members[i].get("risk")), str(members[i].get("component_id") or "")),
        )
        return {
            "group_id": group.get("group_id"),
            "action": "merge",
            "merge_target_index": target,
            "rationale": (
                "Auto-merge: same CWE, STRIDE, threat category, normalized title, evidence file, and evidence line."
            ),
            "source": "merge_threats.py:auto",
        }

    return None


def _split_auto_decisions(candidate_groups: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return (remaining_groups_for_agent, deterministic_decisions)."""
    remaining: list[dict] = []
    decisions: list[dict] = []
    for group in candidate_groups:
        decision = _auto_decision_for_group(group)
        if decision is None:
            remaining.append(group)
        else:
            decisions.append(decision)
    return remaining, decisions


# ---------------------------------------------------------------------------
# Deterministic finalize — Step 3 sort + T-NNN assignment
# ---------------------------------------------------------------------------


def _cwe_sort_value(cwe: str | None) -> tuple[int, int]:
    """Return (priority, cwe_number). priority=0 means 'has CWE', 1 means
    'no CWE' (sorts last within its tie group)."""
    if not isinstance(cwe, str):
        return (1, 0)
    m = _CWE_RE.match(cwe)
    if not m:
        return (1, 0)
    return (0, int(m.group(1)))


def _sort_key(t: dict) -> tuple:
    ev = t.get("evidence") or {}
    line = ev.get("line") if isinstance(ev, dict) else None
    return (
        0 if t.get("architectural_violation") else 1,  # 1. arch. violation first
        _RISK_ORDER.get(t.get("risk"), 99),  # 2. risk
        _STRIDE_ORDER.get(t.get("stride"), 99),  # 3. stride
        (t.get("component_id") or "").lower(),  # 4. component_id
        _cwe_sort_value(t.get("cwe")),  # 5. cwe
        (ev.get("file") or "").lower() if isinstance(ev, dict) else "",  # 6. evidence.file
        line if isinstance(line, int) else 10**9,  # 7. evidence.line (None last)
        (t.get("title") or "").lower(),  # 8. title
    )


def _assign_t_ids(threats: list[dict]) -> list[dict]:
    sorted_threats = sorted(threats, key=_sort_key)
    for i, t in enumerate(sorted_threats, start=1):
        t["t_id"] = f"T-{i:03d}"
    return sorted_threats


_SCENARIO_REF_RE = re.compile(r"\b[FT]-(\d{2,3})\b")


def _remap_scenario_local_refs(threats: list[dict]) -> list[dict]:
    """Rewrite analyzer-local cross-references in ``scenario`` prose to the
    assigned GLOBAL T-ids.

    STRIDE analyzers reference their own findings by component-LOCAL F-id (with
    a stray ``T-`` prefix) when writing scenarios — e.g. the rate-limit
    finding's scenario reads "Combined with MD5 password hashing (T-009)" where
    ``T-009`` is the analyzer's local ``F-009`` (MD5). ``_assign_t_ids`` then
    assigns a global T-id by sorting across ALL components + config-scan, with
    no relation to the local number, and never rewrites the prose — so the ref
    silently points at an unrelated global threat (2026-06 juice-shop: T-024
    "wildcard CORS (T-019)" where T-019 was zip-slip; the local F-019 was CORS).

    Local ids are globally unique by construction (the orchestrator hands each
    analyzer a non-overlapping F-range), so a single ``local-id → t_id`` table
    suffices. Each ``[TF]-NNN`` scenario token is interpreted as local
    ``F-NNN`` and replaced with the resolved global T-id. Tokens that don't
    resolve to a known local id (a deduped finding, a config-scan ``CFG-``
    finding, or a hallucinated number) are left untouched — the pass never
    emits a ref it cannot justify. Idempotent w.r.t. re-running finalize, which
    always starts from the local-ref scenarios in ``.merge-candidates.json``."""
    loc2tid = {t["id"]: t["t_id"] for t in threats if isinstance(t.get("id"), str) and isinstance(t.get("t_id"), str)}
    n_fixed = 0

    def _sub(m: re.Match[str]) -> str:
        nonlocal n_fixed
        tid = loc2tid.get("F-%03d" % int(m.group(1)))
        if tid and tid != m.group(0):
            n_fixed += 1
            return tid
        return m.group(0)

    for t in threats:
        sc = t.get("scenario")
        if isinstance(sc, str) and ("T-" in sc or "F-" in sc):
            t["scenario"] = _SCENARIO_REF_RE.sub(_sub, sc)
    if n_fixed:
        print(
            f"merge_threats: remapped {n_fixed} scenario cross-reference(s) from analyzer-local F-ids to global T-ids",
            file=sys.stderr,
        )
    return threats


def _reconstruct_group_member_indices(threats: list[dict]) -> dict[str, list[int]]:
    """Rebuild the ``{group_id: [member_indices]}`` map that ``_group_candidates``
    produced, so ``_apply_decisions`` can resolve a decision's ``group_id`` back
    to the live threat indices **regardless of which pass created it** — the
    primary ``(CWE, STRIDE)`` ``G-`` pass OR the secondary ``(endpoint,
    cwe_family)`` ``GE-`` pass.

    Before 2026-06-26 the apply path only rebuilt the primary ``G-`` keys, so a
    merger decision on a ``GE-`` endpoint group was silently dropped
    (``gid_to_key.get("GE-…")`` → ``None`` → skipped): the entire RC.G.2
    secondary pass was non-functional in finalize, shipping the cross-CWE
    endpoint duplicates it was built to merge.

    Must stay in lockstep with ``_group_candidates``: identical grouping order,
    identical hash inputs (``cwe|stride|len`` / ``endpoint|family|len``), and
    identical member ordering (threat order), so the reconstructed ``group_id``s
    and member positions match what the agent's decisions reference."""
    out: dict[str, list[int]] = {}

    # Primary pass — (CWE, STRIDE). Mirrors _group_candidates' primary loop.
    primary: dict[tuple, list[int]] = {}
    for idx, t in enumerate(threats):
        primary.setdefault(_candidate_key(t), []).append(idx)
    grouped: set[int] = set()
    for key, members in primary.items():
        if len(members) < 2:
            continue
        cwe, stride = key
        gid = "G-" + hashlib.sha256(f"{cwe}|{stride}|{len(members)}".encode()).hexdigest()[:8]
        out[gid] = members
        grouped.update(members)

    # Secondary pass — (endpoint, cwe_family), only on threats not already in a
    # primary group, and only when the members span >1 (CWE, STRIDE) signature
    # (the same guard _group_candidates applies).
    secondary: dict[tuple[str, str], list[int]] = {}
    for idx, t in enumerate(threats):
        if idx in grouped:
            continue
        key2 = _endpoint_candidate_key(t)
        if key2 is None:
            continue
        secondary.setdefault(key2, []).append(idx)
    for (endpoint, family), members in secondary.items():
        if len(members) < 2:
            continue
        sig = {(threats[i].get("cwe") or "", threats[i].get("stride") or "") for i in members}
        if len(sig) <= 1:
            continue
        gid = "GE-" + hashlib.sha256(f"{endpoint}|{family}|{len(members)}".encode()).hexdigest()[:8]
        out[gid] = members

    return out


def _apply_decisions(threats: list[dict], decisions: list[dict]) -> list[dict]:
    """Apply LLM-produced merge decisions.

    Decision schema (produced by appsec-threat-merger):
      {
        "group_id": "G-abcd1234",       # or "GE-…" for endpoint groups
        "action": "merge" | "keep" | "consolidate",
        "keep_indices": [0, 2],         # for "keep": which group members survive
        "merge_target_index": 0,        # for "merge": which member absorbs the rest
        "consolidated_title": "...",    # for "consolidate": new systemic title
        "rationale": "..."
      }

    Unknown group_ids and malformed decisions are ignored (safe-by-default:
    every threat survives). Over time, the triage-validator can flag
    suspiciously absent decisions, but the Python layer never drops a
    threat it cannot justify dropping.
    """
    if not decisions:
        return threats

    # Rebuild the group_id → member-indices map for BOTH the primary (G-) and
    # secondary (GE-) candidate passes, so endpoint-group decisions apply too.
    gid_to_indices = _reconstruct_group_member_indices(threats)

    drop: set[int] = set()
    for d in decisions:
        if not isinstance(d, dict):
            continue
        gid = d.get("group_id")
        action = d.get("action")
        member_indices = gid_to_indices.get(gid)
        if member_indices is None:
            continue
        if action == "merge":
            target = d.get("merge_target_index", 0)
            if not isinstance(target, int) or target < 0 or target >= len(member_indices):
                continue
            survivor = member_indices[target]
            for pos, idx in enumerate(member_indices):
                if pos == target:
                    continue
                # Record provenance on survivor
                surv = threats[survivor]
                other = threats[idx]
                mf = surv.setdefault("merged_from", [surv.get("component_id")])
                cid = other.get("component_id")
                if cid and cid not in mf:
                    mf.append(cid)
                drop.add(idx)
        elif action == "keep":
            keep_positions = d.get("keep_indices")
            if not isinstance(keep_positions, list):
                continue
            for pos, idx in enumerate(member_indices):
                if pos not in keep_positions:
                    drop.add(idx)
        elif action == "consolidate":
            target = d.get("merge_target_index", 0)
            new_title = d.get("consolidated_title")
            if not isinstance(target, int) or target < 0 or target >= len(member_indices):
                continue
            survivor = member_indices[target]
            surv = threats[survivor]
            if isinstance(new_title, str) and new_title.strip():
                surv["title"] = new_title.strip()
            surv["architectural_violation"] = True
            mf = surv.setdefault("merged_from", [surv.get("component_id")])
            for pos, idx in enumerate(member_indices):
                if pos == target:
                    continue
                other = threats[idx]
                cid = other.get("component_id")
                if cid and cid not in mf:
                    mf.append(cid)
                drop.add(idx)

    return [t for i, t in enumerate(threats) if i not in drop]


# ---------------------------------------------------------------------------
# CLI entry points
# ---------------------------------------------------------------------------


def _collect_resolved_prior_findings(pairs: list[tuple[str, dict]]) -> list[dict]:
    """Union the per-component ``resolved_prior_findings[]`` (incremental
    affirmed-fix lists, stride.schema.yaml) from every stride file. Stamps each
    entry with its ``component_id`` so the reconciler in build_threat_model_yaml
    can match the dropped prior threat by component + fingerprint."""
    out: list[dict] = []
    for cid, data in pairs:
        for r in data.get("resolved_prior_findings") or []:
            if not isinstance(r, dict) or not r.get("prior_id"):
                continue
            entry = dict(r)
            entry.setdefault("component_id", cid)
            out.append(entry)
    return out


def cmd_collect(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir).resolve()
    if not out_dir.exists():
        print(f"merge_threats: output dir not found: {out_dir}", file=sys.stderr)
        return 1

    pairs = _load_stride_outputs(out_dir)
    if not pairs:
        print(f"merge_threats: no .stride-*.json files found in {out_dir}", file=sys.stderr)
        return 1

    resolved_prior = _collect_resolved_prior_findings(pairs)
    flat = _flatten_threats(pairs)
    # Phase 2.5 — append config/IaC findings as additional threats with
    # source='config-scan' so the downstream dedup/grouping/T-ID assignment
    # treats them uniformly with STRIDE-source threats.
    config_threats = _load_config_scan_findings(out_dir)
    if config_threats:
        flat.extend(config_threats)
    # Source-auth: deterministic AUTHZ-NNN findings from
    # `scripts/source_auth_scanner.py`. Loaded only when
    # `.source-auth-findings.json` is on disk (the scanner is opt-in).
    source_auth_threats = _load_source_auth_findings(out_dir)
    # Route-inventory-driven IDOR/BOLA + missing-route-auth confirmations
    # (scripts/authz_confirm.py → .authz-confirm-findings.json), same schema.
    source_auth_threats += _load_source_auth_findings(out_dir, ".authz-confirm-findings.json")
    if source_auth_threats:
        flat.extend(source_auth_threats)
    # `.dep-scan.json` ingestion was removed 2026-05 — supply-chain
    # posture now arrives as §7.11 control rows + meta_findings[] sidecars,
    # not as CVE-shaped threats in this merged set.
    deduped = _dedupe_exact(flat)
    # Evidence-identity dedup (2026-06): collapse the cross-STRIDE /
    # cross-component duplicate (same file:line + CWE) that _exact_key and the
    # (CWE,STRIDE) candidate grouping both miss. Runs here, before grouping, so
    # the merger / finalize path never has to reunite a STRIDE-split pair.
    deduped = _dedupe_evidence(deduped)
    # Systemic config-scan consolidation (2026-06-13): collapse N hits of one
    # IaC/CI check (same config_check_id, across many files or many stages of
    # one Dockerfile) into a single finding whose instances[] lists every hit.
    # Runs before grouping so the coarse (CWE, STRIDE) merger never faces the
    # un-mergeable per-instance pile. See _consolidate_config_checks.
    deduped = _consolidate_config_checks(deduped)
    # Generalized systemic consolidation (2026-06-15): collapse findings that
    # are manifestations of one shared mechanism/object per the declarative
    # data/consolidation-groups.yaml catalog (JWT verification, missing route
    # auth, dependabot, websocket channel, …). Runs AFTER the config pass so its
    # survivors fold in as instances, and BEFORE grouping so the LLM merger never
    # sees the per-instance pile. Non-matching findings (IDOR, XSS) untouched.
    deduped = _consolidate_by_group(deduped)
    all_candidates = _group_candidates(deduped)
    candidates, auto_decisions = _split_auto_decisions(all_candidates)

    payload = {
        "version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_files": [p.name for p in sorted(out_dir.glob(".stride-*.json"))],
        "threat_count_raw": len(flat),
        "threat_count_after_exact_dedup": len(deduped),
        "candidate_group_count": len(candidates),
        "candidate_group_count_total": len(all_candidates),
        "auto_decision_count": len(auto_decisions),
        "auto_decisions": auto_decisions,
        "threats": deduped,  # fully flattened, exact-dedup applied
        "candidate_groups": candidates,  # groups >= 2 that need LLM judgment
        "resolved_prior_findings": resolved_prior,  # incremental affirmed-fix union
    }

    out_path = out_dir / ".merge-candidates.json"
    # Atomic write — a crash mid-serialize would leave a truncated JSON that
    # the downstream cmd_finalize step would fail to parse, stranding the run.
    atomic_write_json(out_path, payload, indent=2, sort_keys=False)
    print(
        f"merge_threats: wrote {out_path} "
        f"({len(flat)} raw → {len(deduped)} after exact dedup, "
        f"{len(candidates)} candidate groups, "
        f"{len(auto_decisions)} auto decisions)"
    )
    return 0


# ---------------------------------------------------------------------------
# Weakness-class register (P1 weakness-class evidence model, proposal §4a/§4b/
# §4d-bis). The reconciler that folds confirmed findings + non-exploitable
# practice sites + arch-coverage design signals into ONE weakness heading per
# (weakness_class, scope), instead of emitting them as peers (or as a separate
# `threat_hypotheses[]` list beside proven findings — Fact R).
#
# Emitted ADDITIVELY into .threats-merged.json as `weaknesses[]`; `threats[]`
# is left untouched so existing consumers keep working. Deterministic; no LLM.
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
_SYSTEMIC_SPREAD_MIN_DEFAULT = 2


def _spread_min_for_class(wcid: str, vocab: dict) -> int:
    """Per-class `systemic_spread_min` override (weakness-classes.yaml), else 2.
    A `kind: implementation` class rolls up into one app-wide `kind: design`
    weakness once it recurs across ≥ this many components with no central
    control present (that co-occurrence IS the systemic signal — §4d-bis)."""
    for c in vocab.get("clusters") or []:
        if c.get("id") == wcid:
            try:
                return int(c.get("systemic_spread_min") or _SYSTEMIC_SPREAD_MIN_DEFAULT)
            except (TypeError, ValueError):
                return _SYSTEMIC_SPREAD_MIN_DEFAULT
    return _SYSTEMIC_SPREAD_MIN_DEFAULT


def _first_evidence(t: dict) -> dict:
    ev = t.get("evidence")
    if isinstance(ev, list):
        ev = next((e for e in ev if isinstance(e, dict)), {})
    elif not isinstance(ev, dict):
        ev = {}
    return ev


# Weak-crypto family (weakness-classes.yaml weak_crypto cluster). A weak hash /
# low KDF rounds / ECB mode / non-CSPRNG is a *definite bad practice* but its
# exploitability (actual cracking / forgery) is not statically established — so
# it is insecure-practice, never confirmed-exploitable, and folds under a
# weak_crypto weakness rather than standing as a proven vuln (proposal §3/§4a).
_PRACTICE_TIER_CWES = frozenset({"CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-916", "CWE-326"})


def _instance_evidence_tier(t: dict) -> str:
    """Evidence basis of a code/config threat. Respects an explicit
    `evidence_tier` set upstream (STRIDE analyzer, P1); otherwise a proven sink
    (code/config source WITH file evidence) defaults to confirmed-exploitable,
    everything else to insecure-practice. Weak-crypto CWEs are always
    insecure-practice (definite bad practice, exploit not established)."""
    et = t.get("evidence_tier")
    if et in ("confirmed-exploitable", "insecure-practice"):
        return et
    if (t.get("cwe") or "").strip().upper() in _PRACTICE_TIER_CWES:
        return "insecure-practice"
    src = (t.get("source") or "").strip()
    has_file = bool((_first_evidence(t).get("file") or "").strip())
    if src in (CODE_LEVEL_SOURCES | CONFIG_DEFECT_SOURCES) and has_file:
        return "confirmed-exploitable"
    return "insecure-practice"


def _max_severity(sevs: list[str]) -> str:
    idx = -1
    for s in sevs:
        try:
            idx = max(idx, _SEVERITY_ORDER.index((s or "").strip().title()))
        except ValueError:
            continue
    return _SEVERITY_ORDER[idx] if idx >= 0 else "Medium"


def _lower_severity(sev: str) -> str:
    """Drop one severity band (floor Low) — the exculpatory effect of a
    standard-vetted control (P2 / §4e)."""
    try:
        i = _SEVERITY_ORDER.index((sev or "").strip().title())
    except ValueError:
        return sev
    return _SEVERITY_ORDER[max(0, i - 1)]


def build_weakness_register(
    threats: list[dict],
    design_signals: list[dict] | None = None,
    impl_strategy: dict[str, str] | None = None,
) -> list[dict]:
    """Fold confirmed findings, non-exploitable practice sites, and arch-coverage
    design signals into one `weaknesses[]` heading per weakness class (§4b fold).

    Grouping key is (weakness_class, scope): `kind: design` weaknesses are
    app-wide (one per class, `affected_components[]` lists the spread);
    `kind: implementation` groups per component but rolls up to a single
    app-wide design weakness once the class recurs across ≥ SYSTEMIC_SPREAD_MIN
    components with no central control (§4d-bis). Instances keep their own
    T-/F-NNN + file:line + basis. Emits a weakness ONLY when it carries
    observable backing — an absent-control signal OR practice evidence (I2 /
    proposal §0); a class with only confirmed instances and no absent-control
    signal stays as plain `threats[]` (the "control present" §4b row)."""
    vocab = load_weakness_classes()
    # wcid -> aggregate
    agg: dict[str, dict] = {}

    def _bucket(wcid: str) -> dict:
        return agg.setdefault(
            wcid,
            {
                "instances": [],
                "instance_severities": [],
                "practice": [],
                "absent": [],
                "statements": [],
                "components": [],
                "strategies": [],
                "design_severities": [],
            },
        )

    def _add_component(b: dict, comp: str) -> None:
        comp = (comp or "").strip()
        if comp and comp not in b["components"]:
            b["components"].append(comp)

    for t in threats:
        src = (t.get("source") or "").strip()
        wcid = classify_threat(t, vocab, warn=False)
        b = _bucket(wcid)
        _add_component(b, t.get("component_id") or t.get("component") or "")
        if src in DESIGN_LEVEL_SOURCES:
            # A design-level threat contributes the absent-control backing, not
            # an instance (design gaps are never CVSS-scored / exploit-proven).
            for a in t.get("controls_absent_evidence") or []:
                b["absent"].append(a)
            st = (t.get("title") or "").strip()
            if st:
                b["statements"].append(st)
            b["design_severities"].append(t.get("risk") or "Medium")
            continue
        tier = _instance_evidence_tier(t)
        # Stamp the resolved basis back onto the threat so downstream consumers
        # (yaml export → composer count breakdown) can distinguish a confirmed
        # finding from a folded practice site without re-deriving it. Additive
        # key; unknown to SARIF/changelog, so no export regresses.
        t["evidence_tier"] = tier
        ev = _first_evidence(t)
        tid = (t.get("t_id") or t.get("id") or "").strip().upper()
        if tier == "confirmed-exploitable" and tid:
            inst = {
                "id": tid,
                "file": (ev.get("file") or "").strip(),
                "line": ev.get("line"),
                "basis": "confirmed-exploitable",
            }
            if t.get("poc_hint"):
                inst["poc_hint"] = t["poc_hint"]
            b["instances"].append(inst)
            b["instance_severities"].append(t.get("risk") or "Medium")
        else:
            pe = {"file": (ev.get("file") or "").strip(), "line": ev.get("line")}
            # Carry the source T-id so the renderer can dedupe a folded practice
            # site against the primary register (honest post-consolidation count).
            if tid:
                pe["id"] = tid
            if pe["file"]:
                b["practice"].append(pe)

    # Fold externally-supplied design signals (P1.3 bridge output).
    for ds in design_signals or []:
        if not isinstance(ds, dict):
            continue
        # Clamp the externally-supplied class to a known cluster id; a malformed
        # bridge file must not inject an out-of-enum class that later fails
        # schema validation. Fall back to CWE-derived classification.
        _raw_wc = (ds.get("weakness_class") or "").strip()
        _valid_wc = {c.get("id") for c in (vocab.get("clusters") or [])}
        wcid = _raw_wc if _raw_wc in _valid_wc else classify_cwe(ds.get("cwe") or "", vocab, warn=False)
        b = _bucket(wcid)
        for a in ds.get("absent_control_signal") or ds.get("controls_absent_evidence") or []:
            b["absent"].append(a)
        st = (ds.get("statement") or ds.get("title") or "").strip()
        if st:
            b["statements"].append(st)
        strat = (ds.get("implementation_strategy") or "").strip()
        if strat:
            b["strategies"].append(strat)
        b["design_severities"].append(ds.get("severity") or "Medium")
        comps = ds.get("affected_components")
        if not comps and ds.get("component"):
            comps = [ds["component"]]
        for c in comps or []:
            _add_component(b, c)

    weaknesses: list[dict] = []
    seq = 0
    for wcid in sorted(agg):
        b = agg[wcid]
        has_absent = bool(b["absent"])
        has_practice = bool(b["practice"])
        # I2 / §4b: a weakness needs observable backing. Confirmed instances
        # alone (no absent-control signal, no practice site) → NOT a systemic
        # weakness; those stay as plain findings in threats[].
        if not (has_absent or has_practice):
            continue

        spread = len(b["components"])
        systemic = spread >= _spread_min_for_class(wcid, vocab)
        # A weakness is `design` when a central control is observably absent
        # (absent-control signal) OR the class recurs systemically across
        # components; otherwise it is an isolated `implementation` weakness.
        kind = "design" if (has_absent or systemic) else "implementation"

        # Implementation strategy (P2): a design-signal strategy wins; else the
        # repo-wide detector's class verdict (detect_impl_strategy.py).
        resolved_strategy = b["strategies"][0] if b["strategies"] else (impl_strategy or {}).get(wcid)

        confirmed = bool(b["instances"])
        # Fall B (§4b "control present"): a standard-vetted control IS the
        # central control, so a PURE design gap (no confirmed instance, no
        # bad-practice site) is exculpated — suppressed, not shown.
        if resolved_strategy == "standard-vetted" and kind == "design" and not confirmed and not has_practice:
            continue

        if confirmed:
            # Driven by a proven exploit: keep the real instance severity band.
            severity_basis = "confirmed"
            severity = _max_severity(b["instance_severities"])
        else:
            severity_basis = "design-risk"
            base = _max_severity(b["design_severities"] or ["Medium"])
            strat_set = {s.lower() for s in b["strategies"]}
            if resolved_strategy:
                strat_set.add(resolved_strategy.lower())
            homegrown = bool(strat_set & {"none", "home-grown"})
            # §4e: design-risk scales with pervasiveness × strategy. Pervasive +
            # (home-grown|none) may reach Critical; pervasive alone bumps once.
            if systemic and homegrown:
                severity = "Critical"
            elif systemic:
                severity = _max_severity([base, "High"])
            else:
                severity = base
        # Exculpatory: a standard-vetted control lowers the residual severity
        # one band (the deviation is an isolated slip against a sound baseline).
        # NEVER for a `confirmed` weakness — a proven exploit must not be
        # de-ranked below its own instance severity (risk-register R1); the
        # softening applies to design-risk gaps only.
        if resolved_strategy == "standard-vetted" and severity_basis != "confirmed":
            severity = _lower_severity(severity)

        statement = (
            b["statements"][0]
            if b["statements"]
            else (f"Recurring {wcid.replace('_', ' ')} handling across {spread} component(s) with no central control.")
        )

        observable_backing: dict = {}
        if has_absent:
            observable_backing["absent_control_signal"] = b["absent"]
        if has_practice:
            observable_backing["practice_evidence"] = b["practice"]

        seq += 1
        w = {
            "id": f"W-{seq:03d}",
            "weakness_class": wcid,
            "kind": kind,
            "statement": statement,
            "severity": severity,
            "severity_basis": severity_basis,
            "observable_backing": observable_backing,
        }
        if b["components"]:
            w["affected_components"] = sorted(b["components"])
        if resolved_strategy:
            w["implementation_strategy"] = resolved_strategy
        if b["instances"]:
            w["instances"] = b["instances"]
        weaknesses.append(w)
    return weaknesses


def _load_design_signals(out_dir: Path) -> list[dict]:
    """Optional arch-coverage design-signal records (P1.3 bridge output),
    consumed by the weakness reconciler. Absent file → no design fold."""
    path = out_dir / ".arch-design-signals.json"
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(doc, dict):
        return list(doc.get("design_signals") or [])
    return list(doc) if isinstance(doc, list) else []


def _load_impl_strategy(out_dir: Path) -> dict[str, str]:
    """Optional per-weakness-class implementation strategy (P2 —
    detect_impl_strategy.py output). Returns {weakness_class: strategy};
    absent/malformed file → {} (no strategy effect)."""
    path = out_dir / ".impl-strategy.json"
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    strategies = (doc or {}).get("strategies") if isinstance(doc, dict) else None
    if not isinstance(strategies, dict):
        return {}
    out: dict[str, str] = {}
    for wclass, entry in strategies.items():
        if isinstance(entry, dict) and entry.get("strategy"):
            out[wclass] = str(entry["strategy"])
        elif isinstance(entry, str):
            out[wclass] = entry
    return out


def cmd_finalize(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir).resolve()
    cand_path = out_dir / ".merge-candidates.json"
    if not cand_path.exists():
        print(f"merge_threats: {cand_path} not found — run 'collect' first", file=sys.stderr)
        return 1

    with cand_path.open() as fh:
        cand = json.load(fh)
    threats: list[dict] = list(cand.get("threats") or [])

    decisions: list[dict] = list(cand.get("auto_decisions") or [])
    dec_path = out_dir / ".merge-decisions.json"
    if dec_path.exists():
        with dec_path.open() as fh:
            dec_doc = json.load(fh)
        if isinstance(dec_doc, dict):
            decisions.extend(dec_doc.get("decisions") or [])
        elif isinstance(dec_doc, list):
            decisions.extend(dec_doc)

    threats = _apply_decisions(threats, decisions)
    threats = _assign_t_ids(threats)
    # Rewrite analyzer-local scenario cross-refs (F-NNN with a stray T- prefix)
    # to the global T-ids just assigned — must run AFTER _assign_t_ids.
    threats = _remap_scenario_local_refs(threats)

    # Weakness-class register (P1) — folds confirmed findings + non-exploitable
    # practice sites + arch-coverage design signals into one weakness heading
    # per class. Runs AFTER _assign_t_ids so instances[] reference real T-ids.
    # Additive: `threats[]` is untouched. `weaknesses` omitted when empty so
    # legacy consumers and golden diffs are unaffected until a signal exists.
    weaknesses = build_weakness_register(threats, _load_design_signals(out_dir), _load_impl_strategy(out_dir))

    payload = {
        "version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threats": threats,
        "resolved_prior_findings": cand.get("resolved_prior_findings") or [],
    }
    if weaknesses:
        payload["weaknesses"] = weaknesses

    out_path = out_dir / ".threats-merged.json"
    # Atomic write — `.threats-merged.json` is a canonical intermediate
    # consumed by Phase 10+; a truncated file from a crashed run would cause
    # downstream phases to emit wrong counts or T-ID collisions.
    atomic_write_json(out_path, payload, indent=2, sort_keys=False)
    print(f"merge_threats: wrote {out_path} ({len(threats)} threats, {len(decisions)} decisions applied)")

    # Attack-surface coverage check: every threat must be reachable via at
    # least one attack_surface entry in threat-model.yaml. Threats with no
    # AS entry are invisible in Section 5, breaking entry-point → threat →
    # mitigation traceability. Write gaps to .coverage-gaps-as.json so the
    # orchestrator can extend the attack surface model before Phase 11.
    yaml_path = out_dir / "threat-model.yaml"
    if yaml_path.exists():
        try:
            import yaml as _yaml

            yaml_data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            covered_tids: set[str] = set()
            for as_entry in (yaml_data or {}).get("attack_surface") or []:
                for tid in as_entry.get("linked_threats") or []:
                    covered_tids.add(str(tid).upper())
            threat_ids = [str(t.get("id") or "").upper() for t in threats if t.get("id")]
            gaps = [tid for tid in threat_ids if tid not in covered_tids]
            if gaps:
                gaps_path = out_dir / ".coverage-gaps-as.json"
                atomic_write_json(
                    gaps_path,
                    {"threats_without_attack_surface_entry": gaps, "count": len(gaps)},
                    indent=2,
                )
                print(
                    f"merge_threats: WARNING — {len(gaps)} threat(s) have no attack_surface "
                    f"entry: {', '.join(gaps[:10])}{'...' if len(gaps) > 10 else ''} "
                    f"(see {gaps_path.name})",
                    file=sys.stderr,
                )
        except Exception:
            pass  # best-effort; never block the merge

    return 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="merge_threats",
        description="Preprocess and finalize Phase 9 threat merging.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser(
        "collect",
        help="Flatten .stride-*.json, exact-dedup, group candidates.",
        epilog="Takes ONLY --output-dir. Inputs (.stride-*.json, .config-scan-findings.json, "
        ".source-auth-findings.json) are auto-discovered from it — there is no --stride-files flag.",
    )
    c.add_argument("--output-dir", required=True, help="Directory containing .stride-*.json files.")
    c.set_defaults(func=cmd_collect)

    f = sub.add_parser(
        "finalize",
        help="Apply decisions, assign T-IDs, write .threats-merged.json.",
        epilog="Takes ONLY --output-dir. Reads .merge-candidates.json (and optionally "
        ".merge-decisions.json) from it — there is no --decisions flag.",
    )
    f.add_argument(
        "--output-dir",
        required=True,
        help="Directory containing .merge-candidates.json (and optionally .merge-decisions.json).",
    )
    f.set_defaults(func=cmd_finalize)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
