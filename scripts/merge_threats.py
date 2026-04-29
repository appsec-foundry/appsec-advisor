#!/usr/bin/env python3
"""
merge_threats.py — mechanical preprocessing + deterministic finalization for
Phase 9 threat merging.

Designed as the Python half of a hybrid merger pipeline:

  Step A (collect):  read all .stride-<id>.json files, apply trivially-
                     mechanical dedup (same CWE + STRIDE letter + evidence
                     file+line), and emit candidate groups that need LLM
                     judgment. Writes .merge-candidates.json.

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
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from _atomic_io import atomic_write_json

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


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------

def _load_stride_outputs(output_dir: Path) -> list[tuple[str, dict]]:
    """Return [(component_id, parsed_json), ...] for every .stride-*.json."""
    pairs: list[tuple[str, dict]] = []
    for path in sorted(output_dir.glob(".stride-*.json")):
        # .stride-auth-service.json → component_id="auth-service"
        comp_id = path.stem[len(".stride-"):]
        try:
            with path.open() as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"merge_threats: invalid JSON in {path}: {exc}")
        pairs.append((comp_id, data))
    return pairs


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
                t["source"] = "stride"
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# Candidate grouping
# ---------------------------------------------------------------------------

_TITLE_STOPWORDS = {
    "the", "a", "an", "in", "on", "of", "to", "for", "via", "due",
    "is", "are", "can", "may", "not", "no", "and", "or", "with",
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


def _group_candidates(threats: list[dict]) -> list[dict]:
    """Group threats sharing the candidate key (CWE + STRIDE). Groups of
    size >= 2 are candidates for LLM-adjudicated merge. Single-element
    groups never need adjudication and are omitted."""
    groups: dict[tuple, list[dict]] = {}
    for t in threats:
        groups.setdefault(_candidate_key(t), []).append(t)

    out: list[dict] = []
    for key, members in groups.items():
        if len(members) < 2:
            continue
        cwe, stride = key
        group_hash = hashlib.sha256(
            f"{cwe}|{stride}|{len(members)}".encode()
        ).hexdigest()[:8]
        out.append({
            "group_id": f"G-{group_hash}",
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
                }
                for m in members
            ],
        })
    # Deterministic ordering — by CWE then STRIDE then group_id
    out.sort(key=lambda g: (g["cwe"], g["stride"], g["group_id"]))
    return out


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
        0 if t.get("architectural_violation") else 1,    # 1. arch. violation first
        _RISK_ORDER.get(t.get("risk"), 99),              # 2. risk
        _STRIDE_ORDER.get(t.get("stride"), 99),          # 3. stride
        (t.get("component_id") or "").lower(),           # 4. component_id
        _cwe_sort_value(t.get("cwe")),                   # 5. cwe
        (ev.get("file") or "").lower() if isinstance(ev, dict) else "",  # 6. evidence.file
        line if isinstance(line, int) else 10**9,        # 7. evidence.line (None last)
        (t.get("title") or "").lower(),                  # 8. title
    )


def _assign_t_ids(threats: list[dict]) -> list[dict]:
    sorted_threats = sorted(threats, key=_sort_key)
    for i, t in enumerate(sorted_threats, start=1):
        t["t_id"] = f"T-{i:03d}"
    return sorted_threats


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
        return "G-" + hashlib.sha256(
            f"{cwe}|{stride}|{len(groups[k])}".encode()
        ).hexdigest()[:8]

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
            if (not isinstance(target, int)
                    or target < 0 or target >= len(member_indices)):
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
    deduped = _dedupe_exact(flat)
    candidates = _group_candidates(deduped)

    payload = {
        "version": 1,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_files": [p.name for p in sorted(out_dir.glob(".stride-*.json"))],
        "threat_count_raw": len(flat),
        "threat_count_after_exact_dedup": len(deduped),
        "candidate_group_count": len(candidates),
        "threats": deduped,          # fully flattened, exact-dedup applied
        "candidate_groups": candidates,  # groups >= 2 that need LLM judgment
    }

    out_path = out_dir / ".merge-candidates.json"
    # Atomic write — a crash mid-serialize would leave a truncated JSON that
    # the downstream cmd_finalize step would fail to parse, stranding the run.
    atomic_write_json(out_path, payload, indent=2, sort_keys=False)
    print(f"merge_threats: wrote {out_path} "
          f"({len(flat)} raw → {len(deduped)} after exact dedup, "
          f"{len(candidates)} candidate groups)")
    return 0


def cmd_finalize(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir).resolve()
    cand_path = out_dir / ".merge-candidates.json"
    if not cand_path.exists():
        print(f"merge_threats: {cand_path} not found — run 'collect' first",
              file=sys.stderr)
        return 1

    with cand_path.open() as fh:
        cand = json.load(fh)
    threats: list[dict] = list(cand.get("threats") or [])

    decisions: list[dict] = []
    dec_path = out_dir / ".merge-decisions.json"
    if dec_path.exists():
        with dec_path.open() as fh:
            dec_doc = json.load(fh)
        if isinstance(dec_doc, dict):
            decisions = dec_doc.get("decisions") or []
        elif isinstance(dec_doc, list):
            decisions = dec_doc

    threats = _apply_decisions(threats, decisions)
    threats = _assign_t_ids(threats)

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
    print(f"merge_threats: wrote {out_path} ({len(threats)} threats, "
          f"{len(decisions)} decisions applied)")

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
    c.add_argument("--output-dir", required=True,
                   help="Directory containing .stride-*.json files.")
    c.set_defaults(func=cmd_collect)

    f = sub.add_parser("finalize", help="Apply decisions, assign T-IDs, write .threats-merged.json.")
    f.add_argument("--output-dir", required=True,
                   help="Directory containing .merge-candidates.json "
                        "(and optionally .merge-decisions.json).")
    f.set_defaults(func=cmd_finalize)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
