#!/usr/bin/env python3
"""reclassify_components.py — fix attack-target-tier vs control-location-tier
drift in Stage-1 threat→component classification.

Background: the threat-analyst merge step classifies threats by what is
being *attacked* (data tier, identity tier, …) rather than by where the
defect *lives* (express handler, model class, frontend component). When
the attack target and the control location are in different components,
the result is a finding like `T-024 component=data-layer evidence=routes/
updateProductReviews.ts:16` — visible to `validate_intermediate.py` as an
ADVISORY (paths-glob mismatch) but never repaired.

This script applies a conservative deterministic reassignment:

  - For every threat with `evidence.file` that does NOT match its current
    `component`'s paths globs, scan all other components.
  - If exactly ONE other component's paths globs match the evidence file,
    reassign the threat to that component. Add `evidence_flags` entry
    `tier_reclassified_from_<old>` so the change is auditable.
  - If 0 or >1 other components match (ambiguous), leave the threat alone
    and emit an advisory line on stderr — same shape as the existing
    validate_intermediate.py advisory.

The script mutates both `threat-model.yaml.threats[].component` and
`.threats-merged.json.threats[].component_id` (when present) so the two
artefacts stay consistent. Idempotent — a second run on the same input
produces no further changes.

Usage:
    python3 reclassify_components.py <output_dir>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    """Convert a gitignore-style glob to a regex. `**` matches any depth."""
    parts: list[str] = []
    i = 0
    while i < len(glob):
        ch = glob[i]
        if ch == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                parts.append(".*")
                i += 2
                # Skip a trailing slash so `routes/**` matches `routes/foo`.
                if i < len(glob) and glob[i] == "/":
                    i += 1
            else:
                parts.append("[^/]*")
                i += 1
        elif ch == "?":
            parts.append("[^/]")
            i += 1
        elif ch in r".+()[]{}|^$\\":
            parts.append(re.escape(ch))
            i += 1
        else:
            parts.append(ch)
            i += 1
    return re.compile(r"\A" + "".join(parts) + r"\Z")


def _build_matcher(component: dict) -> tuple[str, list[re.Pattern[str]]]:
    cid = component.get("id") or "<anon>"
    raw = component.get("paths") or []
    patterns: list[re.Pattern[str]] = []
    if isinstance(raw, list):
        for g in raw:
            if isinstance(g, str) and g.strip():
                patterns.append(_glob_to_regex(g.strip()))
    return cid, patterns


def _evidence_files(threat: dict) -> list[str]:
    ev = threat.get("evidence")
    out: list[str] = []
    if isinstance(ev, dict):
        f = (ev.get("file") or "").strip()
        if f:
            out.append(f)
    elif isinstance(ev, list):
        for e in ev:
            if isinstance(e, dict):
                f = (e.get("file") or "").strip()
                if f:
                    out.append(f)
    return out


def _component_for(file_path: str, matchers: list[tuple[str, list[re.Pattern[str]]]]) -> list[str]:
    """Return component IDs whose globs match this file path."""
    hits: list[str] = []
    for cid, pats in matchers:
        if any(p.search(file_path) for p in pats):
            hits.append(cid)
    return hits


def _sort_tid(tid: str) -> tuple[int, str]:
    """Sort key that keeps T-NNN in numeric order."""
    try:
        return (int(tid.split("-", 1)[1]), tid)
    except (IndexError, ValueError):
        return (10**9, tid)


def _sync_component_threat_ids(components: list, changes: list[dict]) -> None:
    """Apply `changes` to components[].threat_ids[] so the per-component list
    stays in sync with the mutated threats[]."""
    by_id = {c["id"]: c for c in components if isinstance(c, dict) and c.get("id")}
    for c in changes:
        old = by_id.get(c["from"])
        new = by_id.get(c["to"])
        tid = c["id"]
        if old and isinstance(old.get("threat_ids"), list) and tid in old["threat_ids"]:
            old["threat_ids"].remove(tid)
        if new and isinstance(new.get("threat_ids"), list):
            if tid not in new["threat_ids"]:
                new["threat_ids"].append(tid)
                new["threat_ids"].sort(key=_sort_tid)
        elif new is not None:
            new["threat_ids"] = [tid]


def reclassify(data: dict) -> tuple[dict, list[dict]]:
    components = data.get("components") or []
    if not isinstance(components, list) or not components:
        return data, []

    matchers = [_build_matcher(c) for c in components if isinstance(c, dict)]
    matchers = [m for m in matchers if m[1]]  # drop components without paths
    if not matchers:
        return data, []
    matcher_index = {cid: pats for cid, pats in matchers}

    changes: list[dict] = []
    threats = data.get("threats") or []
    if not isinstance(threats, list):
        return data, []

    for t in threats:
        if not isinstance(t, dict):
            continue
        current = (t.get("component") or t.get("component_id") or "").strip()
        files = _evidence_files(t)
        if not files:
            continue
        # If ANY evidence file matches the current component, accept the
        # current assignment (the threat may have multi-file evidence
        # spanning the component boundary).
        current_pats = matcher_index.get(current)
        if current_pats and any(any(p.search(f) for p in current_pats) for f in files):
            continue
        # Find candidate components matching at least one evidence file.
        candidate_hits: dict[str, int] = {}
        for f in files:
            for cid in _component_for(f, matchers):
                if cid == current:
                    continue
                candidate_hits[cid] = candidate_hits.get(cid, 0) + 1
        if len(candidate_hits) != 1:
            # 0 or 2+ candidates — too ambiguous to reassign deterministically.
            continue
        new_cid = next(iter(candidate_hits))
        if t.get("component"):
            t["component"] = new_cid
        if t.get("component_id"):
            t["component_id"] = new_cid
        flags = list(t.get("evidence_flags") or [])
        token = f"tier_reclassified_from_{current or 'unknown'}"
        if token not in flags:
            flags.append(token)
        t["evidence_flags"] = flags
        changes.append({
            "id": t.get("id") or "<anon>",
            "from": current or "<unset>",
            "to": new_cid,
            "evidence_files": files,
        })

    if changes:
        _sync_component_threat_ids(components, changes)

    return data, changes


def _sync_threats_merged(output_dir: Path, changes: list[dict]) -> int:
    if not changes:
        return 0
    path = output_dir / ".threats-merged.json"
    if not path.is_file():
        return 0
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0
    threats = doc.get("threats")
    if not isinstance(threats, list):
        return 0
    by_id = {c["id"]: c for c in changes}
    n = 0
    for t in threats:
        if not isinstance(t, dict):
            continue
        c = by_id.get(t.get("id"))
        if not c:
            continue
        if t.get("component_id"):
            t["component_id"] = c["to"]
        if t.get("component"):
            t["component"] = c["to"]
        n += 1
    if n:
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return n


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: reclassify_components.py <output_dir>", file=sys.stderr)
        return 2
    output_dir = Path(argv[0])
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"reclassify_components: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"reclassify_components: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"reclassify_components: {yaml_path} did not parse to a mapping", file=sys.stderr)
        return 1

    data, changes = reclassify(data)
    if changes:
        yaml_path.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096,
                           default_flow_style=False),
            encoding="utf-8",
        )
        n_merged = _sync_threats_merged(output_dir, changes)
        details = ", ".join(f"{c['id']}:{c['from']}→{c['to']}" for c in changes[:8])
        more = f" (+{len(changes)-8} more)" if len(changes) > 8 else ""
        print(
            f"reclassify_components: reassigned {len(changes)} threat(s) "
            f"[{details}{more}]; updated .threats-merged.json={n_merged}"
        )
    else:
        print("reclassify_components: no tier-confusion drift found — nothing to reassign")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
