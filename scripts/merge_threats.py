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
            # CWE→TH taxonomy when missing.
            if not t.get("threat_category_id"):
                t["threat_category_id"] = _threat_category_id_for(t)
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

# AUTHZ check-id → STRIDE category. Conservative mapping — the scanner
# produces deterministic findings whose STRIDE class is fixed by the
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


def _load_source_auth_findings(output_dir: Path) -> list[dict]:
    """Load `.source-auth-findings.json` (output of
    `scripts/source_auth_scanner.py`) and convert each finding into a
    merged-threats threat record.

    Missing file → empty list (the scanner is opt-in; absence is the
    default state on repos that have not yet adopted it).
    """
    path = output_dir / ".source-auth-findings.json"
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
    "CWE-330": "crypto",
    "CWE-798": "crypto",
    "CWE-916": "crypto",
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
    distinct findings can legitimately share a file. CWE is part of the key so
    two genuinely-different weaknesses at the same line (rare) stay separate."""
    ev = t.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    f = (ev.get("file") or "").strip().lower()
    ln = ev.get("line")
    cwe = (t.get("cwe") or "").strip()
    if not f or not cwe or not isinstance(ln, int) or isinstance(ln, bool) or ln <= 0:
        return None
    return (f, ln, cwe)


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


def _apply_decisions(threats: list[dict], decisions: list[dict]) -> list[dict]:
    """Apply LLM-produced merge decisions.

    Decision schema (produced by appsec-threat-merger):
      {
        "group_id": "G-abcd1234",
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

    # We grouped by (cwe, stride) — to apply a decision we need to re-group
    groups: dict[tuple, list[int]] = {}
    for idx, t in enumerate(threats):
        groups.setdefault(_candidate_key(t), []).append(idx)

    # Build group_id → group key mapping from _group_candidates logic
    def _gid_for_key(k: tuple) -> str:
        cwe, stride = k
        return "G-" + hashlib.sha256(f"{cwe}|{stride}|{len(groups[k])}".encode()).hexdigest()[:8]

    gid_to_key = {_gid_for_key(k): k for k in groups if len(groups[k]) >= 2}

    drop: set[int] = set()
    for d in decisions:
        if not isinstance(d, dict):
            continue
        gid = d.get("group_id")
        action = d.get("action")
        key = gid_to_key.get(gid)
        if key is None:
            continue
        member_indices = groups[key]
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


def cmd_collect(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir).resolve()
    if not out_dir.exists():
        print(f"merge_threats: output dir not found: {out_dir}", file=sys.stderr)
        return 1

    pairs = _load_stride_outputs(out_dir)
    if not pairs:
        print(f"merge_threats: no .stride-*.json files found in {out_dir}", file=sys.stderr)
        return 1

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

    payload = {
        "version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "threats": threats,
    }

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

    c = sub.add_parser("collect", help="Flatten .stride-*.json, exact-dedup, group candidates.")
    c.add_argument("--output-dir", required=True, help="Directory containing .stride-*.json files.")
    c.set_defaults(func=cmd_collect)

    f = sub.add_parser("finalize", help="Apply decisions, assign T-IDs, write .threats-merged.json.")
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
