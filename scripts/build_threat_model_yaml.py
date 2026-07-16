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
  .sca-practice-findings.json, .known-bad-libs-findings.json

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
import hashlib
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


# ─── Incremental threat reconciliation (depth-downgrade preservation) ──────
#
# When a DIRTY component is re-scanned at a SHALLOWER depth than the run that
# produced the baseline, its `.stride-<id>.json` is overwritten and prior
# threats the shallow scan did not re-emit would silently vanish. This
# deterministic reconciler is the authoritative safety net (the analyzer-side
# carry rule in appsec-stride-analyzer.md is advisory): it re-injects such prior
# threats — unless the analyzer affirmatively confirmed a fix — and records
# honest changelog buckets. See
# docs/internal/analysis/proposal-depth-downgrade-incremental-preservation.md.

_DEPTH_RANK = {"quick": 0, "standard": 1, "thorough": 2}


def _normalize_fp_title(title: str) -> str:
    """Normalize a finding/mitigation title into a stable cross-run identity
    token, resilient to the LLM rewording that causes phantom resolved/added
    churn (2026-06-26). Conservative — keeps the common case byte-identical to
    the prior `(file:line)`-trailing-strip so migration churn is minimal:

    * strip ALL parentheticals (file:line, payloads, lib versions) — not only a
      trailing one, so a mid-title `(routes/x.ts:9)` no longer perturbs identity;
    * strip a trailing ``- CWE-NNN`` tagline;
    * collapse whitespace; lowercase.
    """
    s = title or ""
    s = re.sub(r"\s*\([^()]*\)", "", s)  # drop ALL parentheticals (was: only trailing :NN)
    s = re.sub(r"\s*[-—:]\s*CWE-\d+\s*$", "", s, flags=re.IGNORECASE)  # trailing CWE tagline
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower()


def _threat_fingerprint(t: dict) -> tuple:
    """Stable cross-run identity: component + cwe + normalized title.
    Mirrors the re-dispatch fingerprint contract in phase-group-threats.md:50."""
    comp = (t.get("component") or t.get("component_id") or "").strip().lower()
    cwe = (t.get("cwe") or "").strip().upper()
    title = _normalize_fp_title(t.get("title") or "")
    return (comp, cwe, title)


def _fp_str(t: dict) -> str:
    """Serialize _threat_fingerprint() to a stable `comp|cwe|title` string for
    persistence in the changelog entry (enables cross-run delta computation)."""
    comp, cwe, title = _threat_fingerprint(t)
    return f"{comp}|{cwe}|{title}"


# ─── Cross-run diff key (file | cwe-family) ─────────────────────────────────
#
# The changelog diffs findings by ``evidence-file | cwe-family`` rather than the
# display fingerprint ``component|cwe|title``. Component IDs, CWE numbers, AND
# titles are ALL LLM-generated and drift between two ``--full`` runs over
# identical code: 2026-06-26 (juice-shop) two quick runs an hour apart, repo
# unchanged, had only 2 of 33 finding fingerprints match → 27 bogus "added" +
# 31 bogus "resolved", a false "fixed" claim the changelog must never make.
# Measured churn by key on that data: comp|cwe|title=58, file|cwe=49,
# file-only=11. file|cwe still churned because the CWE itself swaps on the
# highest-value findings (RSA key 798↔321, JWT verify 347↔345). Folding CWE into
# a FAMILY absorbs that swap while the file path — the one signal derived from
# source, not phrasing — anchors identity.
#
# Families are deliberately NARROW: only CWEs observed to swap for the SAME
# finding. Since the file is already in the key, a family only needs to
# disambiguate findings WITHIN one file, so narrowness keeps two genuinely
# distinct findings in the same file apart (e.g. lib/insecurity.ts holds a
# hardcoded RSA key AND weak password hashing — different families, so they keep
# separate identities and a partial fix is still visible). Unlisted CWEs map to
# themselves. Add a pair here only when a real same-finding CWE swap is observed.
_CWE_FAMILIES: dict[str, str] = {
    # Hard-coded key / cryptographic material / cleartext secret.
    "CWE-798": "hardcoded-key",
    "CWE-321": "hardcoded-key",
    "CWE-320": "hardcoded-key",
    "CWE-312": "hardcoded-key",
    "CWE-522": "hardcoded-key",
    # Weak / plaintext password storage & hashing.
    "CWE-256": "password-weak",
    "CWE-257": "password-weak",
    "CWE-259": "password-weak",
    "CWE-261": "password-weak",
    "CWE-916": "password-weak",
    # Signature / data-authenticity verification.
    "CWE-347": "sig-verify",
    "CWE-345": "sig-verify",
    "CWE-295": "sig-verify",
    "CWE-924": "sig-verify",
    # Uncontrolled resource consumption / missing resource limits (DoS).
    "CWE-400": "resource-exhaustion",
    "CWE-770": "resource-exhaustion",
    "CWE-405": "resource-exhaustion",
    "CWE-1333": "resource-exhaustion",
}


def _cwe_family(cwe: str) -> str:
    """Map a CWE to its drift-absorbing family, or itself when unlisted."""
    c = (cwe or "").strip().upper()
    return _CWE_FAMILIES.get(c, c)


def _norm_file(path: str) -> str:
    """Lowercased, ``./``-stripped path for stable cross-run file comparison."""
    return (path or "").strip().lstrip("./").strip().lower()


def _anchor_file(t: dict) -> str:
    """Primary evidence file for a threat — its diff anchor. Uses the first
    instance location for a consolidated finding, else the evidence anchor.
    Mirrors the anchor selection in _instance_fingerprints()."""
    insts = t.get("instances")
    if isinstance(insts, list):
        for i in insts:
            if isinstance(i, dict) and i.get("file"):
                return _norm_file(i["file"])
    ev = t.get("evidence")
    if isinstance(ev, list):
        ev = next((e for e in ev if isinstance(e, dict)), {})
    elif not isinstance(ev, dict):
        ev = {}
    return _norm_file(ev.get("file") or "")


def _match_key(t: dict) -> str:
    """Stable cross-run identity for the changelog diff: ``file|cwe-family``.
    Falls back to the legacy ``comp|cwe|title`` fingerprint when a threat has no
    evidence file, so file-less findings still get a stable-enough identity."""
    f = _anchor_file(t)
    if not f:
        return _fp_str(t)
    return f"{f}|{_cwe_family(t.get('cwe') or '')}"


def _prior_match_index(entry: dict | None) -> tuple[set[str], dict[str, str]]:
    """Return ``(match-key set, match-key → display-label)`` for a prior
    changelog entry, so the current run can diff against it AND render resolved
    findings with a human-readable label.

    Resolution order:
      1. explicit ``match_keys`` (written by current builds, paired positionally
         with ``fingerprints``) — exact, no re-derivation;
      2. derive ``file|family`` keys from ``instance_fingerprints`` (which carry
         ``comp|cwe|title|file:line``) — lets the fix work retroactively against
         entries written before ``match_keys`` existed;
      3. legacy fallback: the ``fingerprints`` themselves (``comp|cwe|title`` —
         no file, so they only match another legacy entry's fingerprints).
    """
    if not entry:
        return set(), {}
    mks = entry.get("match_keys")
    fps = entry.get("fingerprints") or []
    if isinstance(mks, list) and mks and len(mks) == len(fps):
        return set(mks), {mk: fp for mk, fp in zip(mks, fps)}
    ifps = entry.get("instance_fingerprints") or []
    if ifps:
        keys: set[str] = set()
        label: dict[str, str] = {}
        for ifp in ifps:
            parts = str(ifp).split("|")
            # Format is comp|cwe|title|file:line. The title MAY contain a '|',
            # so anchor on the OUTER fields: cwe is parts[1], file:line is the
            # LAST segment, and the display label is everything but that last
            # segment (the comp|cwe|title fingerprint).
            if len(parts) < 4:
                continue
            cwe, loc = parts[1], parts[-1]
            f = _norm_file(loc.rsplit(":", 1)[0])
            if not f:
                continue
            mk = f"{f}|{_cwe_family(cwe)}"
            keys.add(mk)
            label.setdefault(mk, "|".join(parts[:-1]))
        if keys:
            return keys, label
    return set(fps), {fp: fp for fp in fps}


def _mitigation_fp(m: dict) -> str:
    """Stable cross-run identity for a mitigation: its location-stripped,
    lowercased title. M-IDs are derived from threats and renumber every run
    (merge_threats restarts numbering), so — exactly like threats are diffed by
    `_fp_str` rather than T-ID — the changelog diffs mitigations by this title
    fingerprint, persisted per entry as `mitigation_fingerprints[]`."""
    return _normalize_fp_title(m.get("title") or "")


def _instance_fingerprints(t: dict) -> list[str]:
    """Per-instance cross-run identities for a threat: ``<finding-fp>|file:line``.
    A consolidated systemic finding (with ``instances[]``) yields one fp per
    instance, so the changelog can show "3 of 17 locations resolved" even while
    the finding itself stays present. A non-consolidated finding yields exactly
    one fp at its evidence location, so the instance-delta degrades cleanly to
    the finding-delta for everything that was never grouped."""
    base = _fp_str(t)
    insts = t.get("instances")
    if isinstance(insts, list) and insts:
        return [f"{base}|{(i.get('file') or '').strip()}:{i.get('line')}" for i in insts if isinstance(i, dict)]
    # `evidence` is a dict at merge time but a LIST of {file,line} in the final
    # yaml — tolerate both; use the first location as the finding's anchor.
    ev = t.get("evidence")
    if isinstance(ev, list):
        ev = next((e for e in ev if isinstance(e, dict)), {})
    elif not isinstance(ev, dict):
        ev = {}
    return [f"{base}|{(ev.get('file') or '').strip()}:{ev.get('line')}"]


def _changelog_note(
    *,
    delta_basis: str,
    prior_entry: dict | None,
    prior_depth: str | None,
    cur_depth: str | None,
    prior_n: int | None,
    cur_n: int,
    n_added: int,
    n_resolved: int,
) -> str:
    """Short auto-summary for the changelog Note column (≤~12 words).

    Examples:
      first run                         → "first full scan"
      fp-delta, depth changed           → "depth standard→thorough; +5/-17 vs prior"
      fp-delta, depth same              → "+5/-17 vs prior"
      count-only (legacy prior, no fps) → "depth standard→thorough; 60→48 (count-only)"
    """
    if delta_basis == "initial" or prior_entry is None:
        return "first full scan"
    if delta_basis == "shallower-scan":
        # Honest framing for a shallower re-scan: no +A/-R delta (the prior's
        # deeper findings were not re-examined, not resolved).
        d = f"shallower than {prior_depth} run" if prior_depth else "shallower re-scan"
        return f"{cur_n} total; {d}; deltas vs prior not comparable"
    if delta_basis == "rescan-unchanged":
        # Same commit, same depth as the prior run — no source change, findings
        # re-derived. Per-finding delta withheld (analysis varies run-to-run).
        # Lead with "no real change" so the note agrees with the Δ +0/~0/-0 cell;
        # the raw count drift is labelled re-derivation noise, not a real delta.
        if prior_n is not None and prior_n != cur_n:
            return f"same commit; no real change; count {prior_n}→{cur_n} re-derived"
        return f"same commit as prior; {cur_n} findings re-derived (no change)"
    parts: list[str] = []
    if prior_depth and cur_depth and prior_depth != cur_depth:
        parts.append(f"depth {prior_depth}→{cur_depth}")
    if delta_basis == "fingerprint":
        parts.append(f"+{n_added}/-{n_resolved} vs prior")
    else:  # count-only / incremental fallback
        if prior_n is not None and prior_n != cur_n:
            parts.append(f"{prior_n}→{cur_n} threats")
        elif prior_n is not None:
            parts.append(f"{cur_n} threats (stable)")
        if delta_basis == "count-only":
            parts.append("count-only")
    return "; ".join(parts)


def _depth_is_shallower(cur: str | None, prior: str | None) -> bool:
    """True iff `cur` is strictly shallower than `prior` (both known)."""
    c = _DEPTH_RANK.get((cur or "").strip().lower())
    p = _DEPTH_RANK.get((prior or "").strip().lower())
    return c is not None and p is not None and c < p


def _load_last_run_depth(output_dir: Path) -> str | None:
    """The baseline run's assessment depth from `.appsec-cache/baseline.json`.
    At builder time baseline.json still reflects the PRIOR run (it is rewritten
    only after compose — same contract the §7 carry-forward relies on)."""
    bpath = output_dir / ".appsec-cache" / "baseline.json"
    if not bpath.is_file():
        return None
    try:
        return json.loads(bpath.read_text()).get("last_run_depth") or None
    except (OSError, ValueError):
        return None


def _reanalyzed_component_ids(output_dir: Path) -> set[str] | None:
    """Components whose `.stride-<id>.json` changed vs the baseline hash → were
    re-analyzed this run. Returns None when no baseline exists (full/first run),
    signalling the caller to skip reconciliation entirely.

    Carried-forward components reuse their exact prior stride file, so their
    sha256 matches the baseline and they are excluded — their threats survive
    naturally through the merge and need no re-injection."""
    bpath = output_dir / ".appsec-cache" / "baseline.json"
    if not bpath.is_file():
        return None
    try:
        prior_hashes = json.loads(bpath.read_text()).get("stride_files") or {}
    except (OSError, ValueError):
        return None
    changed: set[str] = set()
    for cid, rec in prior_hashes.items():
        sfile = output_dir / f".stride-{cid}.json"
        if not sfile.is_file():
            continue  # removed component — handled by the removal path, not here
        actual = "sha256:" + hashlib.sha256(sfile.read_bytes()).hexdigest()
        if actual != (rec or {}).get("sha256"):
            changed.add(cid)
    return changed


def _index_resolved_prior(merged: dict) -> dict[str, str]:
    """Map every analyzer-affirmed fix to a reason, keyed by BOTH the prior id
    and the comp|cwe|title fingerprint, so the reconciler can match either way.

    The fingerprint key stays `_fp_str` (comp|cwe|title), NOT the file|cwe-family
    match key: `resolved_prior_findings` carry no `file` (stride.schema.yaml:
    only prior_id/cwe/title/reason), so a match key can't be computed for them.
    This is fine — `prior_id` is required on every entry and is the reliable
    match; the fingerprint is only a secondary fallback. The reconciler probes
    this dict with `_fp_str(prior_threat)`, keeping both sides comp|cwe|title."""
    out: dict[str, str] = {}
    for r in merged.get("resolved_prior_findings") or []:
        if not isinstance(r, dict):
            continue
        reason = (r.get("reason") or "").strip() or "fix confirmed by re-scan"
        pid = r.get("prior_id")
        if pid:
            out[pid] = reason
        out[_fp_str({"component": r.get("component_id"), "cwe": r.get("cwe"), "title": r.get("title")})] = reason
    return out


def reconcile_incremental_threats(
    threats: list[dict],
    prior_yaml: dict | None,
    components: list[dict],
    output_dir: Path,
    cur_depth: str | None,
    resolved_prior: dict,
) -> tuple[list[dict], dict | None]:
    """Re-inject prior threats of RE-ANALYZED components that a shallower
    re-scan dropped without an affirmative fix. Mutates/extends ``threats`` and
    returns ``(threats, recon_info)`` where ``recon_info`` is None for
    full/first runs (no baseline) or a dict of honest changelog buckets.

    Only carries when the current depth is strictly shallower than the baseline
    depth — at equal/deeper depth a non-reproduced prior threat is genuinely
    resolved (recorded, no longer silently dropped)."""
    reanalyzed = _reanalyzed_component_ids(output_dir)
    if reanalyzed is None or not prior_yaml:
        return threats, None

    prior_depth = _load_last_run_depth(output_dir)
    shallower = _depth_is_shallower(cur_depth, prior_depth)

    # Diff on the stable file|cwe-family match key, NOT comp|cwe|title: an
    # analyzer that re-emits a prior finding with a drifted CWE/title/component
    # would otherwise look "not reproduced" → bogus resolved (equal/deeper) or a
    # duplicate carry (shallower). The match key absorbs that drift, matching the
    # full-run changelog diff. prior threats carry `evidence`, so a file anchor
    # is available on both sides. (2026-06-26)
    present = {_match_key(t) for t in threats}
    prior_keys = {_match_key(pt) for pt in (prior_yaml.get("threats") or [])}

    # merge_threats._assign_t_ids restarts global T-numbering at T-001 every run,
    # so a carried threat's prior id may collide with a freshly-assigned one.
    # Continue numbering after the current maximum to stay collision-free.
    next_t_num = max(
        (int(m.group(1)) for t in threats for m in [re.match(r"^T-(\d+)$", str(t.get("id") or ""))] if m),
        default=0,
    )

    resolved_reason_by_id: dict[str, str] = {}
    carried_ids: list[str] = []

    for pt in prior_yaml.get("threats") or []:
        comp = pt.get("component") or pt.get("component_id") or ""
        if comp not in reanalyzed:
            continue  # carried-forward component → threats already intact
        key = _match_key(pt)
        if key in present:
            continue  # re-emitted by the analyzer (B1) → keep, no double-inject
        pid = pt.get("id", "")
        # resolved_prior is keyed by prior_id (reliable) + _fp_str fallback (the
        # resolved findings carry no file, so probe with the prior threat's
        # comp|cwe|title — both sides agree on that representation).
        fp = _fp_str(pt)
        if pid in resolved_prior or fp in resolved_prior:
            resolved_reason_by_id[pid] = resolved_prior.get(pid) or resolved_prior.get(fp)
            continue
        if shallower:
            next_t_num += 1
            carried = dict(pt)
            carried["id"] = f"T-{next_t_num:03d}"
            carried["evidence_check"] = "carried-unverified-shallower-depth"
            threats.append(carried)
            present.add(key)
            carried_ids.append(carried["id"])
        else:
            resolved_reason_by_id[pid] = "not reproduced at equal-or-deeper depth"

    all_ids = {c.get("id", "") for c in components if c.get("id")}
    recon_info = {
        "reanalyzed_ids": sorted(reanalyzed & all_ids),
        "carried_forward_ids": sorted(all_ids - reanalyzed),
        "resolved_reason_by_id": resolved_reason_by_id,
        "carried_ids": sorted(carried_ids),
        "added_ids": sorted(t["id"] for t in threats if t.get("id") and _match_key(t) not in prior_keys),
    }
    return threats, recon_info


# ─── Field builders ───────────────────────────────────────────────────────


def build_component_selection(sel: dict | None, components: list) -> dict | None:
    """Summarise `.stride-selection.json` into a reader-facing scope block.

    Returns ``{mode, analyzed, total, selected:[{id,name,reasons}],
    excluded:[{id,name,reason}]}`` or ``None`` when no selection sidecar exists.
    Lets §1 Scope state *how many* of the modeled components received full STRIDE
    analysis and *why*, and which were not analyzed and why — instead of implying
    every modeled component was assessed equally.
    """
    if not isinstance(sel, dict) or not sel.get("selected"):
        return None
    name_by_id = {
        c.get("id"): (c.get("name") or c.get("id")) for c in (components or []) if isinstance(c, dict) and c.get("id")
    }

    def _name(cid: str) -> str:
        return name_by_id.get(cid, cid)

    def _norm_sel(e: object) -> dict:
        if isinstance(e, dict):
            cid = e.get("id")
            return {"id": cid, "name": _name(cid), "reasons": list(e.get("reasons") or [])}
        return {"id": e, "name": _name(e), "reasons": []}

    def _norm_exc(e: object) -> dict:
        if isinstance(e, dict):
            cid = e.get("id")
            return {"id": cid, "name": _name(cid), "reason": e.get("reason") or "not selected at this depth"}
        return {"id": e, "name": _name(e), "reason": "not selected at this depth"}

    selected = [_norm_sel(e) for e in (sel.get("selected") or [])]
    excluded = [_norm_exc(e) for e in (sel.get("excluded") or [])]
    return {
        "mode": sel.get("mode"),
        "analyzed": len(selected),
        "total": len(selected) + len(excluded),
        "selected": selected,
        "excluded": excluded,
    }


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
        # Exact create-threat-model invocation flags (depth, reasoning tier,
        # per-stage overrides, --stride-cap, mode, …) so the report can show the
        # precise parameterization that produced it — reproducibility anchor.
        # Survives runtime cleanup, unlike .skill-config.json.
        "invocation": skill_cfg.get("invocation_args"),
        "reasoning_model": skill_cfg.get("reasoning_model", "sonnet-economy"),
        # Per-stage reasoning models. The ``reasoning_model`` above is only the
        # tier NAME (e.g. "sonnet-economy"); it does NOT reveal per-stage env
        # overrides like APPSEC_TRIAGE_MODEL=opus (triage→opus while STRIDE stays
        # sonnet). Persist the resolved per-stage models so the report can
        # honestly disclose the actual mix (Run Statistics row).
        "stride_model": skill_cfg.get("stride_model"),
        "triage_model": skill_cfg.get("triage_model"),
        "merger_model": skill_cfg.get("merger_model"),
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
        # Opt-in --stride-cap N transparency. When the per-category STRIDE cap is
        # active, persist it so the rendered report self-discloses the reduced
        # scope (analogous to component_selection). None when no cap → the
        # renderer omits the Run-Statistics row. meta has additionalProperties:true
        # so no schema bump is needed.
        "stride_per_category_cap": (skill_cfg.get("stride_profile") or {}).get("max_threats_per_category"),
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

    Schema pattern: ^[A-Z][^()@`]+?(?:\\s*\\([^()]+\\))?$
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


_SEVERITY_FLOOR_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


def build_threats(merged: dict, register_floor: str = "medium") -> tuple[list[dict], list[str]]:
    """Transform .threats-merged.json[threats] into yaml.threats[] shape.

    Field renames per output schema: t_id→id, component_id→component.
    Evidence wrap: object → list (schema requires array).
    Title cleanup: deterministic transform to match schema pattern.

    Filters out observation-stub entries (Phase 10b sometimes parks notes
    in threats[] with id=None, likelihood='info', empty cwe/scenario).
    These would fail output schema validation; skip them with a warning.

    ``register_floor`` (default ``"medium"``) drops any threat whose effective
    severity ranks below the floor from the canonical threats[]. Because every
    downstream consumer (counts, risk distribution, register, attack tree,
    SARIF, mitigations, changelog) reads this one list, filtering here keeps all
    totals consistent with zero extra recompute. The default excludes Low /
    Informational — low-risk findings are noise in a threat model. Set the floor
    to ``"low"`` (or ``"informational"``) via ``register_severity_floor`` in
    ``.skill-config.json`` to keep them. Severity is read with the same
    effective_severity → risk → severity precedence the composer's
    ``_severity_counts`` uses, so the filtered set matches the rendered tally.

    Evidence-refuted candidates are also excluded from the canonical list. A
    current threat model is an active-risk snapshot, not a review queue: a
    candidate whose cited evidence contradicts the claim must never reach the
    report, exports, or mitigation register. The merged intermediate retains
    the verdict for audit, while incremental reconciliation records a prior
    finding as resolved in the changelog when applicable.
    Returns (threats, warnings).
    """
    floor_rank = _SEVERITY_FLOOR_RANK.get((register_floor or "medium").strip().lower(), 2)
    out: list[dict] = []
    warnings: list[str] = []
    skipped_stubs = 0
    skipped_below_floor = 0
    skipped_refuted = 0
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
        if (threat.get("evidence_check") or "").strip().lower() == "refuted":
            skipped_refuted += 1
            continue
        # Severity-floor filter. Mirror the composer's effective_severity →
        # risk → severity precedence so the dropped set matches the rendered
        # tally. Anything below the floor (default: Low/Informational) is
        # excluded from the canonical threats[] entirely.
        sev = threat.get("effective_severity") or threat.get("risk") or threat.get("severity") or "medium"
        if _SEVERITY_FLOOR_RANK.get(str(sev).strip().lower(), 2) < floor_rank:
            skipped_below_floor += 1
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
    if skipped_below_floor:
        warnings.append(
            f"threats: {skipped_below_floor} below severity floor ({(register_floor or 'medium').lower()}) dropped from register"
        )
    if skipped_refuted:
        warnings.append(f"threats: {skipped_refuted} evidence-refuted candidate(s) excluded from active model")
    return out, warnings


def _remediation_how_text(t: dict) -> str:
    """Build a 'how' string from a threat's remediation block — prose only.

    Mirrors emit_finding_fix_mitigations._remediation_how so the in-builder
    fallback produces the same shape as the auto-emitter pass. When
    `remediation.steps` is a structured list, returns "" instead of joining
    them into prose: compose's render-time fallback already harvests
    `remediation.steps` and renders it as an ordered list, so joining it here
    too would duplicate the same content twice under one mitigation card
    (juice-shop 2026-07-02 / M-038).
    """
    rem = t.get("remediation")
    if not isinstance(rem, dict):
        return ""
    steps = rem.get("steps")
    if isinstance(steps, list) and steps and any(str(s).strip() for s in steps):
        return ""
    return str(rem.get("how") or "").strip()


def build_mitigations(threats: list[dict]) -> list[dict]:
    """Derive yaml.mitigations[] from threats' mitigation_ids + remediation.

    Each unique M-ID becomes one mitigation entry. threat_ids[] lists every
    threat that references that M-ID. Title from first threat's
    mitigation_title; severity = max risk of linked threats.

    Fallback (2026-06-26): when a threat carries NO ``mitigation_ids`` but DOES
    carry ``mitigation_title``/``remediation`` content, synthesise an M-card and
    link it here. This is the deterministic safety net for the failure mode where
    the LLM yaml-write left ``mitigation_ids=[]`` AND the skill-body auto-emitter
    pass (``emit_finding_fix_mitigations.py``) was skipped (e.g. a mid-run
    session abort) — which leaves §10 Mitigation Register empty even though the
    raw remediation content exists. With this fallback a non-empty register is
    guaranteed-by-construction whenever threats carry remediation content,
    independent of the auto-emitter pass surviving. ``threats`` is mutated in
    place (synthesised ``mitigation_ids`` are written back) so §8 finding links
    resolve too.
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

    # Fallback synthesis for threats that reached here with no link but with
    # remediation content. Group by normalised mitigation title so threats that
    # share a fix converge onto one M-card (dedupe_mitigation_controls later
    # converges the rest). New M-IDs continue past the highest existing number.
    def _next_num() -> int:
        nums = [int(mid.split("-")[1]) for mid in by_mid if mid.startswith("M-") and mid.split("-")[1].isdigit()]
        return (max(nums) + 1) if nums else 1

    fallback_groups: dict[str, dict] = {}
    fallback_order: list[str] = []
    for t in threats:
        if t.get("mitigation_ids"):
            continue
        title = (t.get("mitigation_title") or "").strip()
        how = _remediation_how_text(t)
        rem = t.get("remediation")
        has_steps = isinstance(rem, dict) and any(str(s).strip() for s in (rem.get("steps") or []))
        if not title and not how and not has_steps:
            # No remediation content at all — nothing to synthesise. (`how`
            # is deliberately "" when `remediation.steps` exists — see
            # _remediation_how_text — so `has_steps` covers that case here.)
            continue
        if not title:
            title = f"Remediate {t.get('title', t.get('id', ''))}"
        key = re.sub(r"\s+", " ", title.lower()).strip()
        if key not in fallback_groups:
            fallback_groups[key] = {"title": title, "threats": [], "how": how}
            fallback_order.append(key)
        fallback_groups[key]["threats"].append(t)

    for key in fallback_order:
        g = fallback_groups[key]
        members = g["threats"]
        sev = min(
            (m.get("risk") or "Medium" for m in members),
            key=lambda s: risk_order.get(s, 4),
        )
        efforts = [
            (m.get("remediation") or {}).get("effort", "Medium") if isinstance(m.get("remediation"), dict) else "Medium"
            for m in members
        ]
        effort = min(efforts, key=lambda e: {"Low": 0, "Medium": 1, "High": 2}.get(str(e).capitalize(), 1))
        mid = f"M-{_next_num():03d}"
        entry = {
            "id": mid,
            "title": g["title"],
            "threat_ids": [m["id"] for m in members],
            "priority": "P2",
            "severity": sev,
            "effort": str(effort).capitalize(),
            "kind": "fix",
            "auto_emitted": True,
            "auto_source": "build-mitigations-fallback",
        }
        if g["how"]:
            entry["how"] = g["how"]
        by_mid[mid] = entry
        for m in members:
            m.setdefault("mitigation_ids", []).append(mid)

    # Priority from severity
    sev_to_pri = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Informational": "P4"}
    for m in by_mid.values():
        m["priority"] = sev_to_pri.get(m["severity"], "P3")

    return sorted(by_mid.values(), key=lambda m: m["id"])


def prune_dangling_mitigation_threat_ids(threats: list[dict], mitigations: list[dict]) -> tuple[list[dict], list[str]]:
    """Drop ``mitigation.threat_ids[]`` entries that reference no existing threat.

    ``apply_mitigation_overrides`` is intentionally threat-agnostic: a sidecar
    *addition* (e.g. an LLM-authored supply-chain mitigation) carries whatever
    ``threat_ids`` the analyst wrote, verbatim. When that list names a T-ID the
    final threat set does not contain — an LLM hallucination such as the 2026-06-28
    juice-shop ``M-901→T-034`` (only T-001…T-032 existed) — the dangling link
    fails the ``mitigation_links_resolve`` completeness gate and aborts the run.

    This is the deterministic reconciliation point: the caller invokes it once the
    final ``threats`` set is known (after incremental reconcile) and BEFORE
    ``dedupe_mitigation_controls`` unions threat_ids, so a survivor never inherits
    a dangling reference. Returns ``(mitigations, warnings)``; mutates in place.
    """
    valid_tids = {t.get("id") for t in threats if isinstance(t, dict) and t.get("id")}
    warnings: list[str] = []
    for m in mitigations:
        tids = m.get("threat_ids") or []
        kept = [tid for tid in tids if tid in valid_tids]
        if len(kept) != len(tids):
            dropped = [tid for tid in tids if tid not in valid_tids]
            warnings.append(
                f"mitigation {m.get('id')}: dropped {len(dropped)} dangling threat_id(s) {dropped} (no matching threat)"
            )
            m["threat_ids"] = kept
    return mitigations, warnings


def prune_dangling_weakness_instances(
    threats: list[dict], weaknesses: list[dict]
) -> tuple[list[dict], list[str]]:
    """Drop ``weakness.instances[]`` entries that reference no surviving threat.

    ``merge_threats.build_weakness_register`` builds the register from the FULL
    pre-drop threat set, so an instance names whatever T-ID the merge stage
    assigned. ``build_threats`` then drops threats below the severity floor
    *without renumbering* — the register goes sparse (e.g. T-067 → T-075) but the
    weakness ``instances[]`` still name the dropped ids. The composer renders each
    instance as a finding link ``[F-NNN](#f-nnn)``; a dropped instance therefore
    becomes a titleless phantom link plus a stale positional anchor, and inflates
    the md finding count so ``qa_checks.yaml_md_consistency`` trips (2026-07-16
    juice-shop: W-006 kept T-068 after it was floored out).

    This is the deterministic reconciliation point — the caller invokes it once
    the final surviving ``threats`` set is known. Only ``instances[]`` (the
    confirmed-exploitable legs) are pruned; ``observable_backing`` is left intact
    because its practice / absent-control evidence intentionally references sites
    that are not standalone threats. Returns ``(weaknesses, warnings)``; mutates
    in place.
    """
    valid_tids = {t.get("id") for t in threats if isinstance(t, dict) and t.get("id")}

    def _inst_id(i: object) -> object:
        return i.get("id") if isinstance(i, dict) else i

    warnings: list[str] = []
    for w in weaknesses:
        insts = w.get("instances") or []
        kept = [i for i in insts if _inst_id(i) in valid_tids]
        if len(kept) != len(insts):
            dropped = [_inst_id(i) for i in insts if _inst_id(i) not in valid_tids]
            warnings.append(
                f"weakness {w.get('id')}: dropped {len(dropped)} dangling instance(s) "
                f"{dropped} (threat below severity floor / not in register)"
            )
            w["instances"] = kept
            if "instance_count" in w:
                w["instance_count"] = len(kept)
    return weaknesses, warnings


def dedupe_mitigation_controls(threats: list[dict], mitigations: list[dict]) -> tuple[list[dict], list[dict]]:
    """Collapse mitigations that express the SAME control (identical
    ``_mitigation_fp`` — location-stripped, lowercased title) into one shared
    M-ID, and remap every threat's ``mitigation_ids`` onto the survivor.

    M-IDs are LLM-authored upstream and renumber every run, so two threats that
    independently wrote the same control text get distinct M-IDs (the 19×
    "Enforce object-level authorization" pile). This pass converges them: the
    lowest-numbered M-ID per control survives, unions ``threat_ids``, and the
    threats are rewritten so many separate findings (IDOR, XSS) point at ONE
    shared mitigation instead of N identical copies. Findings are NOT merged —
    only the mitigation list and the threat→mitigation links converge.

    Returns (threats, deduped_mitigations); ``threats`` is mutated in place."""
    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    sev_to_pri = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Informational": "P4"}

    by_fp: dict[str, list[dict]] = {}
    for m in mitigations:
        by_fp.setdefault(_mitigation_fp(m), []).append(m)

    remap: dict[str, str] = {}
    survivors: list[dict] = []
    for _fp, group in by_fp.items():
        if len(group) == 1:
            survivors.append(group[0])
            continue
        canonical = dict(min(group, key=lambda m: str(m.get("id") or "")))
        merged_tids: list[str] = []
        best_sev, best_rank = canonical.get("severity", "Medium"), 99
        for m in group:
            for tid in m.get("threat_ids") or []:
                if tid not in merged_tids:
                    merged_tids.append(tid)
            rk = risk_order.get(m.get("severity"), 4)
            if rk < best_rank:
                best_rank, best_sev = rk, m.get("severity")
            if m.get("id") != canonical.get("id"):
                remap[m["id"]] = canonical["id"]
        canonical["threat_ids"] = sorted(merged_tids)
        canonical["severity"] = best_sev
        canonical["priority"] = sev_to_pri.get(best_sev, "P3")
        survivors.append(canonical)

    if remap:
        for t in threats:
            mids = t.get("mitigation_ids")
            if not mids:
                continue
            new: list[str] = []
            for mid in mids:
                rid = remap.get(mid, mid)
                if rid not in new:
                    new.append(rid)
            t["mitigation_ids"] = new

    survivors.sort(key=lambda m: str(m.get("id") or ""))
    return threats, survivors


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
            is_graphql = (
                str(r.get("framework") or "").lower() == "graphql" or str(r.get("method") or "").upper() == "GRAPHQL"
            )
            if r.get("management_surface"):
                notes_parts.append("Management surface")
            for note in r.get("notes") or []:
                if isinstance(note, str) and note and note not in notes_parts:
                    notes_parts.append(note)
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
                "protocol": "GraphQL" if is_graphql else "HTTP",
                "auth_required": auth_required,
                "notes": "; ".join(notes_parts) or None,
            }
            # Carry the route inventory's display-relevance tags so §5 can keep a
            # finding-free auth/registration/management/suspect route out of the
            # large-inventory collapse (see pregenerate_fragments.gen_attack_surface).
            rel_tags = [t for t in (r.get("relevance_tags") or []) if isinstance(t, str)]
            if rel_tags:
                entry["relevance_tags"] = rel_tags
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
                merged_tags = set(prev.get("relevance_tags") or []) | set(entry.get("relevance_tags") or [])
                if merged_tags:
                    prev["relevance_tags"] = sorted(merged_tags)
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


_MF_ID_RE = re.compile(r"^MF-(\d{3,})$")


def build_meta_findings(prior_yaml: dict | None, sidecars: list[dict | None]) -> list[dict]:
    """Build final meta_findings[] from current-run sidecars.

    The passive supply-chain emitters write MF-shaped candidates without IDs.
    This builder is the deterministic fan-in point: it allocates stable dense
    MF-NNN IDs in sidecar order and preserves hand-authored prior entries.
    When no current-run sidecar produced findings, prior yaml is carried
    forward for backwards-compatible incremental runs.
    """
    raw_findings: list[dict] = []
    for sidecar in sidecars:
        if not isinstance(sidecar, dict):
            continue
        findings = sidecar.get("findings") or []
        if not isinstance(findings, list):
            continue
        raw_findings.extend(f for f in findings if isinstance(f, dict))

    prior_findings = (prior_yaml or {}).get("meta_findings") or []
    if not raw_findings:
        return prior_findings if isinstance(prior_findings, list) else []

    out: list[dict] = []
    if isinstance(prior_findings, list):
        out.extend(m for m in prior_findings if isinstance(m, dict) and m.get("manual") is True)

    max_seen = 0
    for existing in out:
        m = _MF_ID_RE.fullmatch(str(existing.get("id") or ""))
        if m:
            max_seen = max(max_seen, int(m.group(1)))
    counter = max_seen + 1

    seen_keys: set[tuple[str, str, str]] = set()
    for raw in raw_findings:
        title = _clamp_title(str(raw.get("title") or raw.get("control") or "Architectural meta-finding"), 100)
        category = str(raw.get("category") or "Insufficient Patch Management")
        summary = str(raw.get("summary") or title).strip()
        source = str(raw.get("source") or "sidecar")
        key = (source, title, category)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        derived_from = [
            tid for tid in (raw.get("derived_from") or []) if isinstance(tid, str) and re.fullmatch(r"T-\d{3,}", tid)
        ]
        entry = dict(raw)
        entry["id"] = f"MF-{counter:03d}"
        entry["title"] = title
        entry["category"] = category
        entry["summary"] = summary or title
        entry["derived_from"] = derived_from
        if source:
            entry["source"] = source
        out.append(entry)
        counter += 1

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
    existing_changelog: list[dict] | None,
    plugin_root: Path,
    current_sha: str | None = None,
    recon_info: dict | None = None,
    mitigations: list[dict] | None = None,
    run_id: str | None = None,
) -> list[dict]:
    """Prepend a new entry to the prior changelog history (newest first).

    `existing_changelog` is the prior ``threat-model.yaml``'s ``changelog[]`` —
    the committed, accumulating store (see baseline_state.py "Separation of
    concerns": the yaml owns the changelog, NOT the .appsec-cache runtime
    baseline.json). The history is additive: each genuine run extends it,
    never overwrites. A re-build against an identical state (same commit /
    date / mode / plugin+analysis version) replaces the matching prior entry
    instead of piling up a duplicate, so the builder is idempotent.

    Schema: required [version, date, mode]. added/changed/resolved are
    OBJECTS containing typed sub-arrays (threats[], components[], etc.).
    """
    existing: list[dict] = list(existing_changelog or [])

    plugin_ver, analysis_ver = _plugin_version(plugin_root)
    mode = skill_cfg.get("mode", "full")
    cur_depth = skill_cfg.get("assessment_depth", "standard")
    cur_n = len(threats)

    # Self-contained delta source: every entry stores its threat FINGERPRINTS
    # ("component|cwe|location-stripped-title"). A full run cannot diff against
    # the prior threat OBJECTS (the yaml was overwritten in place), but it CAN
    # diff its fingerprints against the PRIOR ENTRY's stored fingerprints. This
    # makes a --full re-run over an existing model surface a real per-finding
    # delta (the flag's promise) instead of marking every threat "added".
    cur_fps = [_fp_str(t) for t in threats]
    # Stable cross-run diff keys (file|cwe-family — see _match_key). Parallel to
    # cur_fps (same order), persisted as `match_keys` so the next run diffs
    # against an exact key set rather than re-deriving from instance fingerprints.
    # The diff (added/resolved) runs on these keys; cur_fps stays the human-
    # readable display/identity label.
    cur_match_keys = [_match_key(t) for t in threats]
    cur_match_set = set(cur_match_keys)
    # Select the prior entry to diff against — but SKIP an existing entry that
    # describes THIS SAME run (this run's own earlier yaml build — Phase-11 may
    # build the yaml more than once), NOT a genuine previous run; treating it as
    # a baseline makes a first/full run self-diff into a bogus "+0 (stable)"
    # delta. The idempotent dedup at the end of this function replaces that
    # same-run entry anyway, so excluding it as a baseline here is consistent.
    #
    # Run identity is keyed on `run_id` (the per-invocation `.scan-start-epoch`,
    # written ONCE at every real-run start). This is the only token that is
    # stable across a single run's multiple Phase-11 yaml builds yet DISTINCT
    # between two separate user invocations. The previous key —
    # (current_sha, date, mode, depth, reasoning, plugin_ver, analysis_ver) —
    # could not tell apart "one run rebuilt its yaml" from "the user ran --full
    # twice on the same commit on the same day with the same params": both
    # collapsed, so the second genuine run SILENTLY OVERWROTE the first as a
    # fresh "initial" entry instead of appending a v2 delta (2026-06-26 juice-
    # shop: two --full quick runs on commit 08fc2760 → second reset to v1).
    # `run_id` fixes that — same epoch ⇒ same run ⇒ collapse; different epoch ⇒
    # distinct runs ⇒ accumulate with a real fingerprint delta.
    _cur_reasoning = skill_cfg.get("reasoning_model", "sonnet-economy")
    # Legacy fallback identity (used only when run_id is unavailable on this run
    # — e.g. no .scan-start-epoch — so the 2026-06-19 self-diff protection still
    # holds for runs that cannot identify themselves).
    _new_key = (
        current_sha,
        _dt.date.today().isoformat(),
        mode,
        cur_depth,
        _cur_reasoning,
        plugin_ver,
        analysis_ver,
    )

    def _legacy_key(e: dict) -> tuple:
        return (
            e.get("current_sha"),
            e.get("date"),
            e.get("mode"),
            e.get("assessment_depth"),
            e.get("reasoning_model"),
            e.get("plugin_version"),
            e.get("analysis_version"),
        )

    def _is_same_run(e: dict) -> bool:
        """True iff `e` is this run's own earlier yaml build (must be collapsed,
        never diffed against). When this run has a `run_id`, identity is the
        run_id alone: an entry with a different run_id — or NO run_id at all
        (written by a pre-run_id invocation, hence necessarily a prior run) — is
        a genuine previous run and is preserved. Only when this run has no
        run_id do we fall back to the legacy param-key match."""
        if run_id:
            return e.get("run_id") == run_id
        return _legacy_key(e) == _new_key

    prior_entry = next((e for e in existing if not _is_same_run(e)), None)
    # Stable match keys + display labels for the prior entry. Diffs are computed
    # on the match keys (file|cwe-family), but resolved findings are RENDERED via
    # the prior entry's comp|cwe|title label so the changelog stays readable.
    prior_match_set, prior_label_by_key = _prior_match_index(prior_entry)
    prior_has_fps = bool(prior_entry) and bool(prior_match_set)
    prior_depth = (prior_entry or {}).get("assessment_depth")
    prior_n = (
        (prior_entry or {}).get("threat_count")
        if (prior_entry or {}).get("threat_count") is not None
        else len(((prior_entry or {}).get("added") or {}).get("threats") or [])
        if prior_entry
        else None
    )

    if recon_info is not None:
        # Incremental path (baseline-diff already computed upstream) — unchanged.
        delta_basis = "incremental"
        added_threats = recon_info["added_ids"]
        carried_components = recon_info["carried_forward_ids"]
        reanalyzed = recon_info["reanalyzed_ids"]
        resolved_block = {
            "threats": sorted(recon_info["resolved_reason_by_id"].keys()),
            "reason_by_id": dict(recon_info["resolved_reason_by_id"]),
        }
    elif prior_has_fps and _depth_is_shallower(cur_depth, prior_depth):
        # Full run over a FINGERPRINTED prior, but at a SHALLOWER depth
        # (e.g. standard → quick). The current run did not examine everything
        # the deeper prior did, so a fingerprint set-diff would mis-report every
        # prior finding the shallow scan didn't reach as "resolved" — a false
        # "fixed" claim, the one thing a security changelog must never make.
        # Suppress the delta and report an honest snapshot count with an explicit
        # shallower-scan note. The findings still live in the prior run's entry;
        # they are NOT resolved, merely not re-examined. (2026-06-26)
        delta_basis = "shallower-scan"
        added_threats = [t["id"] for t in threats]
        reanalyzed = sorted({c.get("id", "") for c in components if c.get("id")})
        carried_components = []
        resolved_block = {"threats": [], "reason_by_id": {}}
    elif (
        prior_has_fps
        and current_sha
        and (prior_entry or {}).get("current_sha") == current_sha
        and (cur_depth or "").strip().lower() == (prior_depth or "").strip().lower()
    ):
        # Same HEAD commit re-scanned at the SAME depth. The source did not
        # change between the two runs, so a per-finding fingerprint diff surfaces
        # only LLM analysis nondeterminism — title rewording, CWE swaps outside a
        # family, anchor-file and instance-count drift, component folding — NOT
        # findings the developer added or fixed. Reporting that churn as
        # "resolved" is the false-fixed claim a security changelog must never
        # make (2026-06-27 juice-shop: five quick re-runs of commit 08fc2760,
        # repo untouched, each reported ~16 added / ~37 resolved). Suppress the
        # delta and report an honest re-derived snapshot. The entry still
        # persists its own fingerprints/match_keys (below), so a LATER run over
        # CHANGED code diffs against this snapshot normally. For reliable
        # per-edit deltas use the incremental path (git baseline diff), not a
        # full re-scan.
        delta_basis = "rescan-unchanged"
        added_threats = []
        reanalyzed = sorted({c.get("id", "") for c in components if c.get("id")})
        carried_components = []
        resolved_block = {"threats": [], "fingerprints": [], "reason_by_id": {}}
    elif prior_has_fps:
        # Full run over a FINGERPRINTED prior entry at SAME-OR-DEEPER depth →
        # real per-finding delta, computed on stable file|cwe-family match keys
        # (NOT comp|cwe|title — those drift between runs and churn the diff).
        delta_basis = "fingerprint"
        added_threats = sorted(t["id"] for t in threats if t.get("id") and _match_key(t) not in prior_match_set)
        resolved_keys = sorted(prior_match_set - cur_match_set)
        reanalyzed = sorted({c.get("id", "") for c in components if c.get("id")})
        carried_components = []
        resolved_block = {
            # T-IDs are not stable across full runs, so resolved findings are
            # identified by their (prior) comp|cwe|title label, not a dangling
            # T-NNN anchor. The template renders these as plain text. Each
            # resolved match key is mapped back to the prior entry's readable
            # label; a key with no recorded label degrades to the key itself.
            "threats": [],
            "fingerprints": [prior_label_by_key.get(k, k) for k in resolved_keys],
            "reason_by_id": {},
        }
    else:
        # First run, OR a prior entry that predates fingerprinting (legacy) →
        # no comparable baseline, so we honestly report a snapshot count rather
        # than a fake "+N added" delta. A prior entry with NO threats (prior_n
        # falsy) is not a real baseline either — e.g. a noise-only no-op that
        # left a fingerprint-less, zero-threat entry. Treating it as a baseline
        # mis-frames the first real full scan as "0→N threats; count-only (vs
        # v1)". Require a non-empty prior before choosing count-only; otherwise
        # this IS the initial substantive scan. (2026-06-26)
        delta_basis = "count-only" if (prior_entry and prior_n) else "initial"
        added_threats = [t["id"] for t in threats]
        reanalyzed = sorted({c.get("id", "") for c in components if c.get("id")})
        carried_components = []
        resolved_block = {"threats": [], "reason_by_id": {}}

    # Mitigation-level delta (added 2026-06-13). Mirrors the threat fingerprint
    # mechanism above: every entry stores its mitigation fingerprints (normalized
    # titles) and a run diffs its current mitigations against the PRIOR entry's
    # stored set. Independent of the threat `delta_basis` — a self-contained
    # fingerprint diff that works uniformly across full/incremental runs.
    cur_mits = [(m.get("id"), _mitigation_fp(m)) for m in (mitigations or []) if m.get("id")]
    cur_mit_fps = [fp for _, fp in cur_mits]
    prior_mit_fps = set((prior_entry or {}).get("mitigation_fingerprints") or [])
    if prior_entry is None:
        added_mitigations = [mid for mid, _ in cur_mits]  # first run — all are new
    elif not prior_mit_fps:
        added_mitigations = []  # legacy prior entry predates mitigation fps → no baseline
    else:
        added_mitigations = sorted(mid for mid, fp in cur_mits if fp not in prior_mit_fps)

    # Instance-level delta (added 2026-06-15). Self-contained fingerprint diff,
    # like the mitigation block above and independent of `delta_basis`: every
    # entry stores its per-instance fingerprints and a run diffs them against the
    # PRIOR entry's stored set. This keeps partial-progress visible after
    # consolidation — fixing 3 of 17 locations of a systemic finding now shows up
    # as 3 resolved instances even though the finding itself is unchanged.
    cur_instance_fps = [fp for t in threats for fp in _instance_fingerprints(t)]
    cur_instance_fp_set = set(cur_instance_fps)
    prior_instance_fps = set((prior_entry or {}).get("instance_fingerprints") or [])
    if prior_entry is None or not prior_instance_fps:
        # First run, or a prior entry predating instance fps → the finding-level
        # delta already covers it; stay quiet rather than emit a huge baseline.
        added_instances: list[str] = []
        resolved_instances: list[str] = []
    else:
        added_instances = sorted(cur_instance_fp_set - prior_instance_fps)
        resolved_instances = sorted(prior_instance_fps - cur_instance_fp_set)
    resolved_block["instances"] = resolved_instances

    # Same-commit same-depth re-scan: the mitigation- and instance-level diffs
    # (computed above independently of `delta_basis`) churn for the same reason
    # the finding diff does — re-derived, not changed. Suppress them too so the
    # entry reports an honest "no change since prior" instead of dozens of
    # phantom new mitigations / resolved instances on untouched code.
    if delta_basis == "rescan-unchanged":
        added_mitigations = []
        added_instances = []
        resolved_instances = []
        resolved_block["instances"] = []

    note = _changelog_note(
        delta_basis=delta_basis,
        prior_entry=prior_entry,
        prior_depth=prior_depth,
        cur_depth=cur_depth,
        prior_n=prior_n,
        cur_n=cur_n,
        n_added=len(added_threats),
        n_resolved=len(resolved_block.get("fingerprints") or resolved_block.get("threats") or []),
    )

    new_entry = {
        "version": 1,  # changelog entry SCHEMA version (the run sequence number
        # is derived positionally at render time — newest entry = highest vN).
        "date": _dt.date.today().isoformat(),
        # Local wall-clock time of the run, e.g. "14:32 CEST" (2026-06-26). `date`
        # stays a bare ISO date — it is part of the entry identity key and is
        # parsed by date regexes — so the time is a separate display-only field.
        "time_local": _dt.datetime.now().astimezone().strftime("%H:%M %Z"),
        "mode": mode,
        "assessment_depth": cur_depth,
        "reasoning_model": skill_cfg.get("reasoning_model", "sonnet-economy"),
        "plugin_version": plugin_ver,
        "analysis_version": analysis_ver,
        # Per-invocation identity (the run's .scan-start-epoch). Stable across
        # this run's Phase-11 yaml rebuilds, distinct between separate runs — so
        # two --full runs on the same commit/day/params accumulate instead of
        # the second overwriting the first. None on runs with no scan-start-epoch.
        "run_id": run_id,
        "baseline_sha": None,
        "current_sha": current_sha,
        "changed_files": None,
        # Delta bookkeeping (new 2026-06-13).
        "threat_count": cur_n,
        "fingerprints": cur_fps,
        # Stable cross-run diff keys (file|cwe-family), positionally paired with
        # `fingerprints`. The diff runs on these; `fingerprints` stays the
        # display label. Next run reads these back via _prior_match_index.
        "match_keys": cur_match_keys,
        "mitigation_fingerprints": cur_mit_fps,
        "instance_fingerprints": cur_instance_fps,
        "delta_basis": delta_basis,
        # On an `initial` basis there is no comparable prior, so leave
        # previous_* unset — otherwise the changelog template's `has_prior`
        # gate (driven by previous_date) renders a misleading "(vs vN)" against
        # a non-baseline (e.g. a noise-only no-op entry). (2026-06-26)
        "previous_date": (prior_entry or {}).get("date") if delta_basis != "initial" else None,
        "previous_threat_count": prior_n if delta_basis != "initial" else None,
        "reanalyzed_components": reanalyzed,
        "carried_forward_components": carried_components,
        "added": {
            "threats": added_threats,
            "mitigations": added_mitigations,
            "instances": added_instances,
            "components": sorted({c.get("id", "") for c in components if c.get("id")}),
            "attack_surface": [],
            # `abuse_cases` is patched in late by render_abuse_cases.py — abuse
            # cases are produced AFTER this builder runs and are not in the yaml
            # at changelog-build time. See enrich_changelog_with_abuse_cases().
        },
        "changed": {"threats": []},
        "resolved": resolved_block,
        "note": note,
    }

    # Idempotent re-build: drop only THIS run's own earlier yaml build (same
    # run_id), then prepend the fresh one. Two genuine invocations have distinct
    # run_ids — even on the same commit/day/params — so both keep their entries
    # and accumulate (the second now shows a real v2 fingerprint delta instead
    # of overwriting v1 as "initial"). `_is_same_run` falls back to the legacy
    # param-key match only when this run has no run_id. (2026-06-26)
    deduped = [e for e in existing if not _is_same_run(e)]
    return [new_entry, *deduped]


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
    sidecar_sca_findings = _load_json(od / ".sca-practice-findings.json")
    sidecar_known_bad_findings = _load_json(od / ".known-bad-libs-findings.json")

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

    threats, threat_warnings = build_threats(merged, register_floor=skill_cfg.get("register_severity_floor", "medium"))
    for w in threat_warnings:
        sys.stderr.write(f"  {w}\n")

    components = (sidecar_components or {}).get("components") or _carry_forward(
        prior_yaml, "components", ".components.json"
    )

    # Incremental depth-downgrade preservation: re-inject prior threats of
    # re-analyzed components that a shallower re-scan dropped without an
    # affirmative fix. Runs BEFORE build_mitigations so carried threats get a §10
    # register entry, and BEFORE the threat_ids derivation so they are counted
    # per component. Carried threats receive fresh, collision-free T-ids
    # (merge_threats._assign_t_ids restarts global numbering every run, so the
    # prior id cannot be reused safely). No-op on full/first runs.
    # Incremental reconciliation is an INCREMENTAL-only operation (depth-downgrade
    # carry-forward). On full/rebuild/first runs it must be a no-op — gate on the
    # resolved run mode, NOT on the mere presence of .appsec-cache/baseline.json.
    # A same-run yaml rebuild (Phase-11 Substep 2 writes baseline.json, then the
    # yaml is rebuilt) leaves baseline.json + a self-written threat-model.yaml on
    # disk; keying "incremental" off those files made a first/full run self-diff
    # into a bogus "+0 / ~0 / -0 · incremental · N threats (stable)" changelog.
    recon_info = None
    if (skill_cfg.get("mode") or "full").lower() == "incremental":
        threats, recon_info = reconcile_incremental_threats(
            threats,
            prior_yaml,
            components,
            od,
            skill_cfg.get("assessment_depth", "standard"),
            _index_resolved_prior(merged),
        )

    mitigations = build_mitigations(threats)
    mitigations, mit_warnings = apply_mitigation_overrides(mitigations, sidecar_mo)
    # Dangling-link prune (2026-06-28): sidecar additions can carry hallucinated
    # threat_ids (juice-shop M-901→T-034). Drop them against the final threat set
    # BEFORE dedupe unions threat_ids, so a survivor never inherits a dead link
    # and the mitigation_links_resolve completeness gate passes.
    mitigations, prune_warnings = prune_dangling_mitigation_threat_ids(threats, mitigations)
    mit_warnings.extend(prune_warnings)
    # Control-dedup (2026-06-15): collapse identical-control mitigations (same
    # title fingerprint, distinct LLM-minted M-IDs) into one shared M-ID and
    # remap threats' mitigation_ids. Runs LAST so it sees the final mitigation
    # set (incl. override splits/additions) and converges the threat links
    # before threat_ids/changelog derivation below.
    threats, mitigations = dedupe_mitigation_controls(threats, mitigations)
    for w in mit_warnings:
        sys.stderr.write(f"  {w}\n")

    # Scope transparency: surface which components received full STRIDE analysis
    # and why, and which were not analyzed and why (from .stride-selection.json).
    component_selection = build_component_selection(_load_json(od / ".stride-selection.json"), components)
    if component_selection:
        meta["component_selection"] = component_selection
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

    # Resolve the prior changelog history. The committed threat-model.yaml is
    # the canonical store, but it is fragile (often untracked, wiped by a crash
    # or a stray rm). When it is absent or carries no changelog, fall back to
    # the cache mirror (.appsec-cache/baseline.json -> changelog_mirror, written
    # by baseline_state.py cmd_update) so a lost yaml does not silently reset an
    # accumulating history to "first full scan". When even the mirror is gone
    # but the cache still proves a prior run happened, warn rather than quietly
    # claiming this is the initial scan — a false "first scan" is exactly the
    # kind of misleading audit claim the changelog must never make.
    existing_changelog = (prior_yaml or {}).get("changelog")
    if not existing_changelog:
        _baseline = _load_json(od / ".appsec-cache" / "baseline.json")
        _mirror = (_baseline or {}).get("changelog_mirror")
        if _mirror:
            existing_changelog = _mirror
            _n = len(_mirror)
            sys.stderr.write(
                f"⚠ changelog: threat-model.yaml carried no changelog history; "
                f"recovered {_n} prior entr{'y' if _n == 1 else 'ies'} from the "
                f".appsec-cache mirror (lost/deleted yaml).\n"
            )
        elif _baseline and _baseline.get("last_run_at"):
            sys.stderr.write(
                "⚠ changelog: a prior run is recorded in .appsec-cache "
                f"(last_run_at={_baseline.get('last_run_at')}) but no changelog "
                "history survived in threat-model.yaml or the cache mirror — "
                "recording this run as the initial entry; earlier run history "
                "is unrecoverable.\n"
            )

    # Per-invocation run identity for changelog dedup: the skill writes this
    # epoch once at every real-run start (overwriting any stale value), so it is
    # stable across this run's Phase-11 yaml rebuilds yet distinct between two
    # separate invocations. Absent → run_id stays None and build_changelog falls
    # back to legacy param-key dedup.
    _run_id = None
    try:
        _epoch = (od / ".scan-start-epoch").read_text(encoding="utf-8").strip()
        if _epoch:
            _run_id = _epoch
    except OSError:
        _run_id = None

    changelog = build_changelog(
        skill_cfg,
        threats,
        components,
        attack_surface,
        existing_changelog,
        args.plugin_root,
        current_sha=(meta.get("git") or {}).get("commit_sha"),
        recon_info=recon_info,
        mitigations=mitigations,
        run_id=_run_id,
    )

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
    # Weakness-class register (P1) — carry the deterministic `weaknesses[]` folded
    # by merge_threats.build_weakness_register straight through to the export.
    # Instances reference the same T-NNN ids as threats[]. Absent on legacy/first
    # runs → key omitted.
    weaknesses = merged.get("weaknesses") or []
    if weaknesses:
        # Prune instances that reference threats dropped below the severity floor.
        # build_threats drops without renumbering, so a stale instance would render
        # as a titleless [F-NNN] phantom link + inflate the md finding count
        # (yaml_md_consistency trip — 2026-07-16 juice-shop W-006→T-068).
        weaknesses, weakness_prune_warnings = prune_dangling_weakness_instances(threats, weaknesses)
        for w in weakness_prune_warnings:
            sys.stderr.write(f"  {w}\n")
        doc["weaknesses"] = weaknesses
    if threat_hypotheses and not weaknesses:
        # P1.3c: when the weakness register exists, unpromoted design signals are
        # folded into weaknesses[] (rendered as design-weakness headings), so
        # `threat_hypotheses[]` — the retired user-facing "hypothesis" list — is
        # suppressed to avoid showing the same design gap twice (Fact R). Legacy
        # runs with no register keep emitting it (readable one release, §Migration).
        #
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
    meta_findings = build_meta_findings(prior_yaml, [sidecar_sca_findings, sidecar_known_bad_findings])
    if meta_findings:
        doc["meta_findings"] = meta_findings
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
