#!/usr/bin/env python3
"""
build_threat_model_yaml.py — deterministic Phase 11 Substep 2 replacement.

Composes threat-model.yaml from on-disk intermediates + new Phase 3/5/7/8
input sidecars (.components.json, .assets.json, .trust-boundaries.json,
.security-controls.json). Replaces the LLM yaml-composition that previously
burned 15-20 turns at the end of Stage 1 (and caused the 2026-05-24
juice-shop MAX_TURNS bootstrap-stub failure).

Sidecar-first with prior-yaml fallback: if a required sidecar is missing
but a prior `threat-model.yaml` exists on disk, the field is carried
forward from it. This allows incremental adoption — the script works
today (using the prior LLM-composed yaml as fallback) and tomorrow
(once Phase 3/5/7/8 agents start writing sidecars).

Hard-required intermediates (script aborts if missing):
  .threats-merged.json, .route-inventory.json, .architecture-coverage.json,
  .skill-config.json

Optional intermediates (gracefully degraded):
  .config-scan-findings.json, .cross-repo-register.json, .triage-flags.json,
  .org-profile-effective.json, .stage-stats.jsonl

Phase-output sidecars (NEW — preferred when present, falls back to prior yaml):
  .components.json, .assets.json, .trust-boundaries.json, .security-controls.json

Output: $OUTPUT_DIR/threat-model.yaml (atomic write, schema-validated).

Exit codes:
  0 = success
  1 = IO / validation / unexpected error
  2 = usage error
  3 = required intermediate missing
  4 = sidecar AND prior-yaml fallback both missing for a required field
  5 = schema validation failed
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write("FATAL: PyYAML required (pip install pyyaml)\n")
    sys.exit(1)

# Add scripts/ to path so we can import sibling helpers
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from _atomic_io import atomic_write_text  # noqa: E402

# ─── Helpers ──────────────────────────────────────────────────────────────


def _load_json(path: Path, *, required: bool = False) -> Any:
    """Return parsed JSON, None if missing (unless required=True → exit 3)."""
    if not path.exists():
        if required:
            sys.stderr.write(f"FATAL: required intermediate missing: {path.name}\n")
            sys.exit(3)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"FATAL: malformed JSON in {path.name}: {exc}\n")
        sys.exit(1)


def _load_yaml(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        sys.stderr.write(f"warning: malformed YAML in {path.name}: {exc}\n")
        return None


def _git(args: list[str], cwd: Path) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=5)
        if out.returncode != 0:
            return None
        return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _read_recon_project(recon_path: Path) -> str | None:
    """Extract project name from .recon-summary.md Section 1 (best-effort)."""
    if not recon_path.exists():
        return None
    text = recon_path.read_text(encoding="utf-8", errors="ignore")
    # Look for "**Project**: <name>" or "## 1. Business Context\n... Project: <name>"
    m = re.search(r"\*\*Project\*\*:\s*([^\n]+)", text)
    if m:
        return m.group(1).strip()
    return None


def _plugin_version(plugin_root: Path) -> tuple[str, int]:
    """Read plugin_version + analysis_version from .claude-plugin/plugin.json."""
    pj = plugin_root / ".claude-plugin" / "plugin.json"
    if not pj.exists():
        return ("unknown", 1)
    try:
        d = json.loads(pj.read_text(encoding="utf-8"))
        return (d.get("version", "unknown"), int(d.get("analysis_version", 1)))
    except (json.JSONDecodeError, ValueError):
        return ("unknown", 1)


def _carry_forward(prior_yaml: dict | None, field: str, sidecar_name: str) -> Any:
    """Return prior_yaml[field] or exit 4 with remediation message."""
    if prior_yaml and field in prior_yaml and prior_yaml[field]:
        return prior_yaml[field]
    sys.stderr.write(
        f"FATAL: neither {sidecar_name} sidecar nor prior threat-model.yaml "
        f"has '{field}'. The corresponding phase must write the sidecar, "
        f"or run --full once with the legacy LLM Substep 2 to bootstrap.\n"
    )
    sys.exit(4)


# ─── Field builders ───────────────────────────────────────────────────────


def build_meta(
    *,
    skill_cfg: dict,
    org: dict | None,
    recon_project: str | None,
    plugin_root: Path,
    repo_root: Path,
    prior_yaml: dict | None,
) -> dict:
    plugin_ver, analysis_ver = _plugin_version(plugin_root)
    commit_sha = _git(["rev-parse", "HEAD"], repo_root) or "unknown"
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo_root) or "unknown"
    repo_url = _git(["remote", "get-url", "origin"], repo_root)

    # project: sidecar fallback chain — recon-summary, then prior yaml meta.project, then repo basename
    project = recon_project or (prior_yaml or {}).get("meta", {}).get("project") or repo_root.name

    return {
        "schema_version": 1,
        "project": project,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "mode": skill_cfg.get("mode", "full"),
        "model": skill_cfg.get("stride_model", "sonnet"),
        "analyst": f"appsec-threat-analyst ({skill_cfg.get('stride_model', 'sonnet')})",
        "plugin_version": plugin_ver,
        "analysis_version": analysis_ver,
        "assessment_depth": skill_cfg.get("assessment_depth", "standard"),
        "reasoning_model": skill_cfg.get("reasoning_model", "sonnet-economy"),
        "scope": skill_cfg.get("scope", []),
        "repo_url": repo_url,
        "team_owner": (org or {}).get("team_owner"),
        "asset_classification": (org or {}).get("asset_classification"),
        "compliance_scope": (org or {}).get("compliance_scope", []),
        "git": {"commit_sha": commit_sha, "branch": branch},
        "accepted_risks": (org or {}).get("accepted_risks", []),
        # Carry the resolved requirements gate into meta. The contract-driven
        # renderer gates the entire Requirements Compliance surface (§7b
        # traceability table, the MS compliance subsection, and authoring of
        # the requirements-compliance.md fragment) on
        # `meta.check_requirements`. Without this, a run with --requirements /
        # CHECK_REQUIREMENTS=true that ran Phase 8b still rendered nothing —
        # the flag lived in .skill-config.json but never reached the yaml.
        "check_requirements": bool(skill_cfg.get("check_requirements", False)),
    }


# Collapse dash *separators* (spaced hyphen/en/em, or a bare em/en dash) to a
# single space — but NEVER a bare ASCII hyphen inside an identifier or path
# (`search-result`, `X-Frame-Options`). The old `\s*[—–-]\s*` matched any
# hyphen regardless of surrounding whitespace, rewriting
# `search-result/search-result.component.ts` → `search result/search result...`
# in every finding title (juice-shop 2026-06-11).
_TITLE_DASH_RE = re.compile(r"\s+[—–-]\s+|[—–]")
_TITLE_PARENS_RE = re.compile(r"\(([^)]*)\)")
_TITLE_WS_RE = re.compile(r"\s+")

# Schema rejects titles containing exact attack/CVE syntax (anyOf negative
# pattern in threats[].title). Replace each with a natural-language equivalent
# so the deterministic builder produces schema-clean titles. Source of forbidden
# patterns: schemas/threat-model.output.schema.yaml threats[].title.
_TITLE_FORBIDDEN_REPLACEMENTS = [
    (re.compile(r"\bnoent:true\b"), "external entity resolution"),
    (re.compile(r"\balg:none\b"), "algorithm none"),
    (re.compile(r"\bpackage-lock=false\b"), "lockfile disabled"),
    (re.compile(r"\bbypassSecurityTrustHtml\b"), "trust HTML bypass"),
    (re.compile(r"\bcrypto\.createHash\b"), "weak hash"),
    (re.compile(r"\bmodels\.sequelize\.query\b"), "raw SQL query"),
    (re.compile(r"\(CVE-[^)]+\)"), "CVE"),
    (re.compile(r"@\d+(?:\.\d+){0,2}"), ""),  # version suffixes like jsonwebtoken@0.4.0
]


_TITLE_MAXLEN = 80


def _clamp_title(title: str, limit: int = _TITLE_MAXLEN) -> str:
    """Enforce the schema title maxLength, preserving a trailing
    ``file.ext:line`` (or ``— file.ext:line``) locator when present so the
    weakness body is what gets shortened, not the evidence pointer."""
    title = (title or "").strip()
    if len(title) <= limit:
        return title
    m = re.search(r"\s+(?:[—-]\s+)?\(?[\w./-]+:\d+\)?\s*$", title)
    if m:
        tail = title[m.start() :].strip()
        head = title[: m.start()].rstrip()
        keep = limit - len(tail) - 2  # room for "… " join
        if keep >= 8:
            return f"{head[:keep].rstrip()}… {tail}"
    return title[: limit - 1].rstrip() + "…"


def _normalize_cvss_v4(v4):
    """Coerce a STRIDE-emitted cvss_v4 to the output-schema shape
    ({vector, base_score, severity, source}, additionalProperties:false) or
    return None to drop it. Analyzers commonly write ``score`` instead of
    ``base_score`` and omit ``source``."""
    if not isinstance(v4, dict):
        return None
    vector = v4.get("vector")
    if not isinstance(vector, str) or not vector.startswith("CVSS:4.0"):
        return None
    score = v4.get("base_score", v4.get("score"))
    sev = v4.get("severity")
    if not isinstance(score, (int, float)) or sev not in ("None", "Low", "Medium", "High", "Critical"):
        return None
    src = v4.get("source")
    valid_src = {"stride-analyzer", "dep-scan", "nvd", "osv", "known-vuln", "manual"}
    return {
        "vector": vector,
        "base_score": float(score),
        "severity": sev,
        "source": src if src in valid_src else "stride-analyzer",
    }


def _clean_title(raw: str) -> str:
    """Best-effort transform of merged-threat title to schema pattern.

    Schema pattern: ^[A-Z][^()@`]+?(?:\s*\([^()]+\))?$
      - first char uppercase
      - no parens/at/backtick in body
      - optionally one parenthesized suffix at end

    Plus a negative anyOf list of forbidden substrings (alg:none, noent:true,
    package-lock=false, etc.) — these must be replaced with natural-language
    equivalents because the schema treats them as raw attack syntax.

    Titles that still fail after cleanup are surfaced as schema warnings —
    the migration plan moves first-class title cleanup into stride-analyzer
    output later. For v1 we accept residual warnings on edge cases.
    """
    if not raw:
        return raw
    s = raw.strip()
    s = _TITLE_DASH_RE.sub(" ", s)
    s = s.replace("`", "")
    # Replace forbidden tokens BEFORE paren extraction so we don't lose them.
    # If the replacement phrase already appears elsewhere in the title,
    # just strip the forbidden token (avoids "external entity resolution
    # enables external entity resolution" duplications).
    for pat, repl in _TITLE_FORBIDDEN_REPLACEMENTS:
        if pat.search(s):
            if repl and repl.lower() in s.lower():
                s = pat.sub("", s)
            else:
                s = pat.sub(repl, s)
    # Pull parens out — drop empty ones; keep the most specific (last non-empty).
    parens = [p for p in _TITLE_PARENS_RE.findall(s) if p.strip()]
    s = _TITLE_PARENS_RE.sub("", s).strip()
    s = _TITLE_WS_RE.sub(" ", s)
    if s and not s[0].isupper():
        s = s[0].upper() + s[1:]
    # Schema docs cap "weakness class" at ~80 chars; total with suffix can
    # exceed maxLength. Prefer shortening the file-path suffix to its basename
    # over chopping the weakness wording — a long path
    # (`frontend/src/app/search-result/search-result.component.ts:132`) was
    # crushing the description to "Stored and Refl…"; the full path still lives
    # in evidence_file / location (juice-shop 2026-06-11).
    suffix_inner = parens[-1] if parens else ""
    suffix = f" ({suffix_inner})" if suffix_inner else ""
    if suffix_inner and "/" in suffix_inner and len(s) + len(suffix) > 80:
        suffix_inner = suffix_inner.rsplit("/", 1)[-1]
        suffix = f" ({suffix_inner})"
    if len(s) + len(suffix) > 80:
        # The weakness phrase + locator overflows the schema's 80-char title
        # cap. NEVER ellipsis-truncate the weakness wording: a clipped
        # "…Cookie Prot…" title is propagated verbatim to every cross-reference
        # link (qa _load_label_index reads title as-is) AND slugged into
        # anchors, producing inconsistent finding titles across the document
        # and ugly "…" §3 walkthrough headings (juice-shop 2026-06-11). The
        # locator already lives in evidence_file and the §8 Location cell, so
        # DROP the "(file)" suffix and keep the FULL weakness phrase whenever
        # the weakness fits on its own. Only hard-truncate when the weakness
        # wording itself exceeds the cap (genuinely unavoidable, very rare).
        if len(s) <= 80:
            suffix = ""
        else:
            s = s[:79].rstrip().rstrip(",;:-") + "…"
            suffix = ""
    return f"{s}{suffix}"


def build_threats(merged: dict) -> tuple[list[dict], list[str]]:
    """Transform .threats-merged.json[threats] into yaml.threats[] shape.

    Field renames per output schema: t_id→id, component_id→component.
    Evidence wrap: object → list (schema requires array).
    Title cleanup: deterministic transform to match schema pattern.

    Filters out observation-stub entries (Phase 10b sometimes parks notes
    in threats[] with id=None, likelihood='info', empty cwe/scenario).
    These would fail output schema validation; skip them with a warning.
    Returns (threats, warnings).
    """
    out: list[dict] = []
    warnings: list[str] = []
    skipped_stubs = 0
    for t in merged.get("threats", []):
        threat = dict(t)
        threat["id"] = threat.pop("t_id", threat.get("id"))
        # Observation-stub filter: Phase 10b's config-scan path sometimes
        # parks positive observations or low-quality findings in threats[]
        # with sentinel values likelihood='info'/risk='info' and empty
        # scenario/cwe. They fail the output schema (likelihood/impact/risk
        # enum requires Critical/High/Medium/Low/Informational, cwe must
        # match ^CWE-\d+$). Skip them — they belong in observations[] not
        # threats[].
        is_info_stub = (threat.get("likelihood") or "").lower() == "info" or (
            threat.get("risk") or ""
        ).lower() == "info"
        if not threat.get("id") or is_info_stub:
            skipped_stubs += 1
            continue
        threat["component"] = threat.pop("component_id", threat.get("component", ""))
        threat["title"] = _clamp_title(_clean_title(threat.get("title", "")))
        # Schema hard limits (output schema: title<=80, affected_parameter<=40)
        # + cvss_v4 shape ({vector, base_score, severity, source}, no extra
        # keys). STRIDE analyzers occasionally emit verbose titles, long
        # affected_parameter lists, or a cvss_v4 with `score` instead of
        # `base_score` and no `source` — normalise here so the deterministic
        # builder always yields a schema-valid yaml (2026-06-02).
        if threat.get("affected_parameter"):
            ap = str(threat["affected_parameter"]).strip()
            threat["affected_parameter"] = ap if len(ap) <= 40 else (ap[:39].rstrip() + "…")
        threat["cvss_v4"] = _normalize_cvss_v4(threat.get("cvss_v4"))
        if threat["cvss_v4"] is None:
            threat.pop("cvss_v4", None)
        ev = threat.get("evidence")
        if isinstance(ev, dict):
            threat["evidence"] = [ev]
        elif ev is None:
            threat["evidence"] = []
        out.append(threat)
    if skipped_stubs:
        warnings.append(
            f"threats: {skipped_stubs} observation-stub entries skipped (id=None — Phase 10b notes mis-parked in threats[])"
        )
    return out, warnings


def build_mitigations(threats: list[dict]) -> list[dict]:
    """Derive yaml.mitigations[] from threats' mitigation_ids + remediation.

    Each unique M-ID becomes one mitigation entry. threat_ids[] lists every
    threat that references that M-ID. Title from first threat's
    mitigation_title; severity = max risk of linked threats.
    """
    by_mid: dict[str, dict] = {}
    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

    for t in threats:
        for mid in t.get("mitigation_ids", []):
            if mid not in by_mid:
                by_mid[mid] = {
                    "id": mid,
                    "title": t.get("mitigation_title") or t.get("title", ""),
                    "threat_ids": [],
                    "priority": "P2",
                    "severity": t.get("risk", "Medium"),
                    "effort": (t.get("remediation") or {}).get("effort", "Medium"),
                    "kind": "fix",
                }
            entry = by_mid[mid]
            if t["id"] not in entry["threat_ids"]:
                entry["threat_ids"].append(t["id"])
            # Severity = max risk
            cur_rank = risk_order.get(entry["severity"], 4)
            new_rank = risk_order.get(t.get("risk", "Low"), 4)
            if new_rank < cur_rank:
                entry["severity"] = t.get("risk", entry["severity"])

    # Priority from severity
    sev_to_pri = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Informational": "P4"}
    for m in by_mid.values():
        m["priority"] = sev_to_pri.get(m["severity"], "P3")

    return sorted(by_mid.values(), key=lambda m: m["id"])


# Sidecar's mitigation kind enum (process/architectural) is broader than
# threat-model output schema's enum (fix/review/investigate/accept_risk).
# Coerce sidecar-only kinds to the closest output-schema equivalent so the
# yaml passes downstream schema validation without losing the LLM's intent.
_KIND_COERCE = {
    "process": "review",  # process gaps → human review action
    "architectural": "investigate",  # arch changes → investigate scope
}


def apply_mitigation_overrides(baseline: list[dict], sidecar: dict | None) -> tuple[list[dict], list[str]]:
    """Apply .mitigation-overrides.json splits + additions to the baseline.

    Defensive against the common LLM-drift pattern (verified 2026-05-24
    juice-shop run) where the LLM writes ALL baseline mitigations into
    additions[], producing duplicate M-IDs and inflated mitigation counts.

    Dedup rules for additions:
      1. Skip if addition.id collides with an existing baseline M-ID
      2. Skip if addition.threat_ids is a SUBSET of any baseline mitigation's
         threat_ids (the addition is just re-describing the baseline)

    Defaults applied to additions missing optional fields:
      - severity: 'Medium' (LLM consistently forgets — schema relaxed in §2.6)
      - priority: derived from severity
      - effort: 'Medium'
      - kind: 'fix'

    Returns (final_mitigations, warnings_list).
    """
    warnings: list[str] = []
    if not sidecar:
        return baseline, warnings

    sev_to_pri = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Informational": "P4"}
    out = {m["id"]: dict(m) for m in baseline}

    # Apply splits — replace baseline M-ID with multiple sub-mitigations
    for split in sidecar.get("splits", []) or []:
        src = split.get("source_mid")
        if src not in out:
            warnings.append(f"mitigation-overrides.splits: source_mid {src!r} not in baseline — split ignored")
            continue
        baseline_entry = out.pop(src)
        for sub in split.get("into", []) or []:
            suffix = sub.get("id_suffix", "")
            new_id = f"{src}{suffix}"
            out[new_id] = {
                **baseline_entry,
                "id": new_id,
                "title": sub.get("title", baseline_entry["title"]),
                "threat_ids": sub.get("threat_ids", baseline_entry["threat_ids"]),
                "remediation": sub.get("remediation", baseline_entry.get("remediation")),
            }

    # Pre-compute baseline threat_id sets for subset-check
    baseline_tids = {m["id"]: set(m.get("threat_ids", [])) for m in out.values()}

    def _overlay_authored(base: dict, add: dict) -> None:
        """Merge an addition's AUTHORED remediation fields onto a baseline
        mitigation. The baseline (derived from threats) carries only the
        threat title + grouping; the sidecar addition carries the LLM's
        action-oriented title, the `description` (the *why/what* of the
        fix) and a `reference` link. Those are exactly what §9 needs and
        were previously discarded when the addition collided with the
        baseline by ID or threat_ids. Authored, non-empty values win;
        otherwise the baseline value is kept.
        """
        for field in ("title", "description", "reference", "remediation", "how", "how_code", "verification"):
            val = add.get(field)
            if isinstance(val, str):
                val = val.strip()
            if val:
                base[field] = add[field]
        # Prefer explicitly-authored priority/effort; coerce kind enum.
        if add.get("priority"):
            base["priority"] = add["priority"]
        if add.get("effort"):
            base["effort"] = add["effort"]
        if add.get("kind"):
            base["kind"] = _KIND_COERCE.get(add["kind"], add["kind"])

    # Apply additions — merge authored content onto matching baseline
    # entries (do NOT discard the LLM's remediation guidance); only append
    # as a new mitigation when it covers a genuinely new threat set.
    merged = 0
    added = 0
    for add in sidecar.get("additions", []) or []:
        aid = add.get("id", "")
        # Rule 1: ID collision → merge authored fields onto the baseline.
        if aid in out:
            _overlay_authored(out[aid], add)
            merged += 1
            continue
        # Rule 2: threat_ids subset of an existing baseline mitigation →
        # same fix under a different ID; merge onto that baseline entry.
        add_tids = set(add.get("threat_ids", []))
        host_mid = next(
            (mid for mid, bt in baseline_tids.items() if add_tids and add_tids.issubset(bt)),
            None,
        )
        if host_mid is not None:
            _overlay_authored(out[host_mid], add)
            merged += 1
            continue
        # Apply defaults for optional fields
        sev = add.get("severity", "Medium")
        kind_raw = add.get("kind", "fix")
        kind_out = _KIND_COERCE.get(kind_raw, kind_raw)
        out[aid] = {
            "id": aid,
            "title": add.get("title", ""),
            "threat_ids": add.get("threat_ids", []),
            "kind": kind_out,
            "priority": add.get("priority", sev_to_pri.get(sev, "P3")),
            "severity": sev,
            "effort": add.get("effort", "Medium"),
            **({"description": add["description"]} if add.get("description") else {}),
            **({"reference": add["reference"]} if add.get("reference") else {}),
            **({"remediation": add["remediation"]} if "remediation" in add else {}),
        }
        added += 1

    if merged:
        warnings.append(
            f"mitigation-overrides.additions: {merged} merged onto baseline (authored title/description/reference preserved)"
        )
    if added:
        warnings.append(f"mitigation-overrides.additions: {added} accepted (true additions)")

    return sorted(out.values(), key=lambda m: m["id"]), warnings


def build_attack_surface(routes: dict | None, sidecar: dict | None = None) -> tuple[list[dict], list[str]]:
    """Compose yaml.attack_surface[] from .route-inventory.json (baseline)
    overlaid with .attack-surface-overrides.json (Phase-6 sidecar).

    Pipeline:
      1. Baseline = route inventory routes[] mapped 1:1 to attack_surface entries
         (tracks each baseline entry's source route_id for sidecar curation lookups).
      2. Curations (sidecar.curations object):
         - include_route_ids[] → allowlist filter on baseline
         - exclude_route_ids[] → denylist filter
         - rationale_by_id{} → overwrite notes field per route
      3. Additions (sidecar.additions[]) appended (skipping entry_point collisions).

    If baseline is empty AND sidecar has additions, sidecar IS the source —
    Phase 6 sidecar can carry the entire surface for repos without route inventory.

    Schema: required [entry_point, protocol]. Optional auth_required, notes.
    Returns (entries, warnings).
    """
    warnings: list[str] = []
    # Pairs of (entry, source_route_id) so curations can address baseline entries.
    baseline_pairs: list[tuple[dict, str | None]] = []
    if routes:
        for r in routes.get("routes", []):
            notes_parts = []
            if r.get("management_surface"):
                notes_parts.append("Management surface")
            if r.get("handler_file"):
                notes_parts.append(f"handler: {r['handler_file']}:{r.get('handler_line', '')}")
            # authn_signal is a STRING enum from route_inventory.py:
            #   "middleware_present" / "decorator_present" → a guard was seen
            #   "unknown" (the default) / "absent" / "" → no guard observed
            # bool() of the raw string is WRONG: bool("unknown") is True, which
            # would mark every route — including public ones — as authenticated
            # (2026-06-04 juice-shop: 112/112 flipped to auth_required when the
            # inventory was present). Only the positive signals count as auth.
            authn_sig = str(r.get("authn_signal") or "").strip().lower()
            auth_required = authn_sig in ("middleware_present", "decorator_present", "present", "required")
            entry = {
                "entry_point": f"{r.get('method', '?')} {r.get('path', '/')}",
                "protocol": "HTTP",
                "auth_required": auth_required,
                "notes": "; ".join(notes_parts) or None,
            }
            baseline_pairs.append((entry, r.get("route_id")))

    # Dedup baseline by entry_point. route_inventory.py can emit the same
    # method+path more than once (finale auto-CRUD registers a model both via
    # app.use(prefix) and app.METHOD(...), plus framework-challenge re-registers
    # of POST /api/Users) — without collapsing them §5 shows 3-4 identical rows.
    # Auth verdict is security-conservative: a route is "authenticated" only if
    # EVERY occurrence is guarded; if any registration of that path is reachable
    # without a guard, the path is reachable unauthenticated → auth_required=False.
    if baseline_pairs:
        collapsed: dict[str, tuple[dict, str | None]] = {}
        for entry, rid in baseline_pairs:
            ep = entry["entry_point"]
            if ep not in collapsed:
                collapsed[ep] = (entry, rid)
            else:
                prev, prev_rid = collapsed[ep]
                prev["auth_required"] = bool(prev.get("auth_required")) and bool(entry.get("auth_required"))
                if not prev.get("notes") and entry.get("notes"):
                    prev["notes"] = entry["notes"]
        baseline_pairs = list(collapsed.values())

    # Snapshot the full deduped baseline + the exclude set so the class-coverage
    # guard below can restore an auth class that an include allowlist emptied.
    full_baseline_pairs: list[tuple[dict, str | None]] = list(baseline_pairs)
    exclude_ids: set = set()

    if sidecar:
        cur = sidecar.get("curations") or {}
        include = set(cur.get("include_route_ids") or [])
        exclude = set(cur.get("exclude_route_ids") or [])
        exclude_ids = exclude
        rationale = cur.get("rationale_by_id") or {}

        if include:
            before = len(baseline_pairs)
            baseline_pairs = [(e, rid) for (e, rid) in baseline_pairs if rid in include]
            warnings.append(f"attack-surface-overrides.curations.include: kept {len(baseline_pairs)}/{before} routes")
        if exclude:
            before = len(baseline_pairs)
            baseline_pairs = [(e, rid) for (e, rid) in baseline_pairs if rid not in exclude]
            warnings.append(
                f"attack-surface-overrides.curations.exclude: dropped {before - len(baseline_pairs)} routes"
            )
        if rationale:
            applied = 0
            for entry, rid in baseline_pairs:
                if rid and rid in rationale:
                    entry["notes"] = rationale[rid]
                    applied += 1
            if applied:
                warnings.append(f"attack-surface-overrides.curations.rationale: applied to {applied} entries")

    out = [e for (e, _rid) in baseline_pairs]

    if sidecar:
        by_ep = {e["entry_point"]: i for i, e in enumerate(out)}
        merged = 0
        added = 0
        for add in sidecar.get("additions") or []:
            ep = add.get("entry_point")
            if not ep:
                continue
            if ep in by_ep:
                # Entry-point collision with a baseline (route-inventory) entry.
                # The Phase-6 analyst hand-read the code, so its explicit
                # auth_required / notes OVERRIDE the heuristic baseline value —
                # the route_inventory window-scan can mis-tag auth (e.g. an
                # unauthenticated POST /api/Users sitting next to a guarded
                # GET /api/Users gets a false middleware_present). Merge the
                # addition's authoritative fields onto the baseline entry instead
                # of dropping it.
                base = out[by_ep[ep]]
                if "auth_required" in add and add.get("auth_required") is not None:
                    base["auth_required"] = bool(add["auth_required"])
                if add.get("notes"):
                    base["notes"] = add["notes"]
                for k in ("linked_threats", "threats"):
                    if add.get(k):
                        base[k] = add[k]
                merged += 1
                continue
            out.append(add)
            by_ep[ep] = len(out) - 1
            added += 1
        if added:
            warnings.append(f"attack-surface-overrides.additions: {added} entries added")
        if merged:
            warnings.append(
                f"attack-surface-overrides.additions: {merged} merged onto baseline (analyst auth/notes override)"
            )

    # Completeness guard (2026-06-11): §5 must represent the FULL reachable
    # attack surface — the entire deduped route-inventory baseline minus
    # explicit excludes — NOT just the analyst's vuln-focused `include_route_ids`
    # pick. The earlier class-coverage guard only restored a class when it was
    # ENTIRELY empty, so an include allowlist that happened to keep a few routes
    # in each class still silently dropped the rest of the surface (juice-shop
    # 2026-06-11: include kept 8 authenticated + 19 unauthenticated of 112, both
    # classes non-empty → guard never fired → §5 reported 27/112). The LLM-written
    # include list is unreliable and must NOT govern §5 membership; it only marks
    # which rows carry the analyst's curated notes/priority (applied above via
    # `rationale_by_id` + additions). Restore every post-exclude baseline route
    # not already present so the count is honest. An explicit `exclude_route_ids`
    # still wins, and the §5 renderer's large-bucket cap keeps the display short
    # (finding-linked rows listed individually + a "_N further entry point(s)…_"
    # summary line). The pentest export already consumes the full attack_surface[].
    if full_baseline_pairs:
        seen_eps: set[str] = {e.get("entry_point") for e in out}
        restored = 0
        for entry, rid in full_baseline_pairs:
            if rid in exclude_ids:
                continue  # an explicit exclude is honoured even by the guard
            if entry.get("entry_point") not in seen_eps:
                out.append(entry)
                seen_eps.add(entry.get("entry_point"))
                restored += 1
        if restored:
            warnings.append(
                f"attack-surface completeness guard: restored {restored} baseline "
                f"route(s) so §5 reflects the full reachable surface (include "
                f"allowlist governs per-row notes/priority, not membership)"
            )

    return out, warnings


def build_threat_hypotheses(arch_cov: dict | None, hyp_start_id: int = 1) -> list[dict]:
    """Transform .architecture-coverage.json[threat_hypotheses] → yaml shape.

    Schema requires:
      id ~ ^HYP-\\d{3,}$
      source_hypothesis_id ~ ^ARCH-HYP-[A-Z]+-[0-9]{3}$  (already in source as hypothesis_id)
      rule_id, title, threat_category_id, cwe, proof_state, confidence
    """
    if not arch_cov:
        return []
    out = []
    for i, h in enumerate(arch_cov.get("threat_hypotheses", []), start=hyp_start_id):
        entry = dict(h)
        # Rename: source's hypothesis_id → output's source_hypothesis_id, assign new HYP-NNN
        entry["source_hypothesis_id"] = entry.pop("hypothesis_id", entry.get("source_hypothesis_id", ""))
        entry["id"] = f"HYP-{i:03d}"
        out.append(entry)
    return out


def build_critical_findings(threats: list[dict]) -> list[dict]:
    """Schema: required [threat_id, summary]. Optional mitigation_id."""
    out = []
    for t in threats:
        sev = t.get("effective_severity", t.get("risk", ""))
        if sev in ("Critical", "High"):
            mids = t.get("mitigation_ids", [])
            out.append(
                {
                    "threat_id": t["id"],
                    "summary": t.get("title", ""),
                    "mitigation_id": mids[0] if mids else None,
                }
            )
    return out


def build_tier_root_causes(threats: list[dict], components: list[dict], sidecar: dict | None = None) -> dict:
    """Phase 10b sidecar (.tier-root-causes.json) is the canonical source —
    architectural-level prose like "missing input neutralization on raw SQL
    paths" needs LLM synthesis and cannot be derived from threat titles.

    Falls back to title-frequency derivation only when the sidecar is absent
    (legacy / no-Phase-10b runs).

    Tier mapping: 'client' → 'edge' (yaml uses edge/server/data),
    'application' → 'server', 'data' → 'data'.
    """
    if sidecar:
        # Sidecar shape: {"schema_version": 1, "tier_root_causes": {"edge|server|data": [...]}}
        nested = sidecar.get("tier_root_causes") or {}
        out = {}
        for tier in ("edge", "server", "data"):
            bullets = nested.get(tier) or []
            if bullets:
                out[tier] = [str(b)[:80] for b in bullets if b]
        return out

    tier_alias = {"client": "edge", "application": "server", "data": "data"}
    comp_tier = {c["id"]: tier_alias.get(c.get("tier", ""), c.get("tier", "")) for c in components}

    by_tier: dict[str, list[str]] = defaultdict(list)
    for t in threats:
        tier = comp_tier.get(t.get("component", ""), "")
        if not tier:
            continue
        # Use title as the root-cause hint (already terse, file:line included)
        title = t.get("title", "")
        if title:
            by_tier[tier].append(title)

    out = {}
    for tier, titles in by_tier.items():
        # Take top-5 unique by frequency
        counted = Counter(titles).most_common(5)
        bullets = [title[:80] for title, _ in counted]
        if bullets:
            out[tier] = bullets
    return out


def build_changelog(
    skill_cfg: dict,
    threats: list[dict],
    components: list[dict],
    attack_surface: list[dict],
    baseline_path: Path | None,
    plugin_root: Path,
) -> list[dict]:
    """Append new entry to existing baseline changelog (or create new).

    Schema: required [version, date, mode]. added/changed/resolved are
    OBJECTS containing typed sub-arrays (threats[], components[], etc.).
    """
    existing: list[dict] = []
    if baseline_path and baseline_path.exists():
        try:
            existing = (json.loads(baseline_path.read_text()) or {}).get("changelog", []) or []
        except json.JSONDecodeError:
            pass

    plugin_ver, analysis_ver = _plugin_version(plugin_root)
    mode = skill_cfg.get("mode", "full")

    # For full runs, every component+threat is "added" vs the empty baseline.
    # Incremental runs would need a baseline-diff; v1 treats incremental as full.
    new_entry = {
        "version": 1,  # changelog entry schema version, not plugin version
        "date": _dt.date.today().isoformat(),
        "mode": mode,
        "assessment_depth": skill_cfg.get("assessment_depth", "standard"),
        "reasoning_model": skill_cfg.get("reasoning_model", "sonnet-economy"),
        "plugin_version": plugin_ver,
        "analysis_version": analysis_ver,
        "baseline_sha": None,
        "current_sha": None,  # patched by main() after _git call
        "changed_files": None,
        "reanalyzed_components": sorted({c.get("id", "") for c in components if c.get("id")}),
        "carried_forward_components": [],
        "added": {
            "threats": [t["id"] for t in threats],
            "components": sorted({c.get("id", "") for c in components if c.get("id")}),
            "attack_surface": [],
        },
        "changed": {"threats": []},
        "resolved": {"threats": [], "reason_by_id": {}},
    }
    return [new_entry, *existing]


# ─── Main ─────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("output_dir", type=Path, help="$OUTPUT_DIR (e.g. docs/security)")
    ap.add_argument("--repo-root", type=Path, default=None)
    ap.add_argument("--plugin-root", type=Path, default=Path(os.environ.get("CLAUDE_PLUGIN_ROOT", _SCRIPT_DIR.parent)))
    ap.add_argument("--dry-run", action="store_true", help="Print the composed yaml to stdout instead of writing.")
    args = ap.parse_args()

    od = args.output_dir
    if not od.is_dir():
        sys.stderr.write(f"FATAL: output_dir does not exist: {od}\n")
        return 2

    repo_root = args.repo_root or Path(json.loads((od / ".skill-config.json").read_text()).get("repo_root", "."))

    # Load required intermediates
    skill_cfg = _load_json(od / ".skill-config.json", required=True)
    merged = _load_json(od / ".threats-merged.json", required=True)
    routes = _load_json(od / ".route-inventory.json")
    arch_cov = _load_json(od / ".architecture-coverage.json")

    # Load optional intermediates
    org = _load_json(od / ".org-profile-effective.json")
    cross_repo = _load_json(od / ".cross-repo-register.json")
    config_findings = _load_json(od / ".config-scan-findings.json")

    # Load NEW sidecars (preferred)
    sidecar_components = _load_json(od / ".components.json")
    sidecar_assets = _load_json(od / ".assets.json")
    sidecar_tb = _load_json(od / ".trust-boundaries.json")
    sidecar_sc = _load_json(od / ".security-controls.json")
    sidecar_mo = _load_json(od / ".mitigation-overrides.json")
    sidecar_as = _load_json(od / ".attack-surface-overrides.json")
    sidecar_trc = _load_json(od / ".tier-root-causes.json")

    # Prior yaml (fallback source for fields whose sidecar is missing)
    prior_yaml = _load_yaml(od / "threat-model.yaml")
    # Refuse the bootstrap stub — it has no usable content
    if prior_yaml and (prior_yaml.get("meta") or {}).get("_bootstrap"):
        prior_yaml = None

    recon_project = _read_recon_project(od / ".recon-summary.md")

    # Build sections
    meta = build_meta(
        skill_cfg=skill_cfg,
        org=org,
        recon_project=recon_project,
        plugin_root=args.plugin_root,
        repo_root=repo_root,
        prior_yaml=prior_yaml,
    )

    threats, threat_warnings = build_threats(merged)
    for w in threat_warnings:
        sys.stderr.write(f"  {w}\n")
    mitigations = build_mitigations(threats)
    mitigations, mit_warnings = apply_mitigation_overrides(mitigations, sidecar_mo)
    for w in mit_warnings:
        sys.stderr.write(f"  {w}\n")

    components = (sidecar_components or {}).get("components") or _carry_forward(
        prior_yaml, "components", ".components.json"
    )
    assets = (sidecar_assets or {}).get("assets") or _carry_forward(prior_yaml, "assets", ".assets.json")
    trust_boundaries = (sidecar_tb or {}).get("trust_boundaries") or _carry_forward(
        prior_yaml, "trust_boundaries", ".trust-boundaries.json"
    )
    security_controls = (sidecar_sc or {}).get("security_controls") or _carry_forward(
        prior_yaml, "security_controls", ".security-controls.json"
    )

    # threat_ids per component (derived)
    for comp in components:
        cid = comp.get("id", "")
        comp["threat_ids"] = sorted(t["id"] for t in threats if t.get("component") == cid)

    attack_surface, as_warnings = build_attack_surface(routes, sidecar_as)
    for w in as_warnings:
        sys.stderr.write(f"  {w}\n")
    threat_hypotheses = build_threat_hypotheses(arch_cov)
    critical = build_critical_findings(threats)
    tier_rcs = build_tier_root_causes(threats, components, sidecar_trc)

    changelog = build_changelog(
        skill_cfg,
        threats,
        components,
        attack_surface,
        args.plugin_root / ".appsec-cache" / "baseline.json",
        args.plugin_root,
    )
    if changelog:
        changelog[0]["current_sha"] = meta["git"]["commit_sha"]

    # Compose final document
    doc: dict[str, Any] = {
        "meta": meta,
        "changelog": changelog,
        "components": components,
        "assets": assets,
        "attack_surface": attack_surface,
        "trust_boundaries": trust_boundaries,
        "security_controls": security_controls,
        "threats": threats,
        "mitigations": mitigations,
        "critical_findings": critical,
    }
    if tier_rcs:
        doc["tier_root_causes"] = tier_rcs
    if cross_repo:
        doc["cross_repo_dependencies"] = (
            cross_repo if isinstance(cross_repo, list) else cross_repo.get("dependencies", [])
        )
    if threat_hypotheses:
        # Only emit if every entry has the required schema fields; otherwise
        # skip — meta_findings/threat_hypotheses synthesis from raw intermediates
        # is non-trivial and is queued for a follow-up migration step.
        if all(
            h.get("threat_category_id") and h.get("proof_state") and h.get("confidence") is not None
            for h in threat_hypotheses
        ):
            doc["threat_hypotheses"] = threat_hypotheses
        elif prior_yaml and prior_yaml.get("threat_hypotheses"):
            doc["threat_hypotheses"] = prior_yaml["threat_hypotheses"]
    # meta_findings synthesis (config-scan-findings → MF-NNN with category enum)
    # is judgment-heavy — carry forward from prior yaml when available, else skip.
    if prior_yaml and prior_yaml.get("meta_findings"):
        doc["meta_findings"] = prior_yaml["meta_findings"]
    if prior_yaml and "security_architecture" in prior_yaml:
        doc["security_architecture"] = prior_yaml["security_architecture"]
    if prior_yaml and prior_yaml.get("threat_categories"):
        doc["threat_categories"] = prior_yaml["threat_categories"]

    # Render
    rendered = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120)

    if args.dry_run:
        sys.stdout.write(rendered)
        return 0

    out_path = od / "threat-model.yaml"
    atomic_write_text(out_path, rendered)

    # Schema validate
    plugin_root = args.plugin_root
    validator = plugin_root / "scripts" / "validate_intermediate.py"
    if validator.exists():
        rc = subprocess.run(
            ["python3", str(validator), "threat_model_output", str(out_path)],
            capture_output=True,
            text=True,
        )
        if rc.returncode != 0:
            sys.stderr.write("FATAL: schema validation failed\n")
            sys.stderr.write(rc.stdout)
            sys.stderr.write(rc.stderr)
            return 5

    sys.stderr.write(
        f"✓ threat-model.yaml built deterministically — "
        f"{len(threats)} threats, {len(mitigations)} mitigations, "
        f"{len(attack_surface)} attack-surface entries, {len(components)} components\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
