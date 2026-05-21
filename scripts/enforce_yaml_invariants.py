#!/usr/bin/env python3
"""enforce_yaml_invariants.py — RC.G.3 / RC.K — deterministic post-write
gate on Phase-11 Substep-2.

Background
==========
Phase 11 Substep 2 assembles ``threat-model.yaml`` in LLM working memory
from ``.threats-merged.json`` (canonical merged threats) plus Phase 5–8
context. The LLM is supposed to copy ``stride`` / ``cwe`` /
``component_id`` / ``evidence`` VERBATIM from the merged file and only
add narrative / mitigations / attack_surface / etc. fields. In practice
the LLM silently mutates 3 of 36 ``stride`` values and 29 of 36 titles
across the merge → yaml boundary, with no audit trail — the
``.threats-merged.json`` claims one thing, the yaml claims another, and
downstream renderers (§8, attack-walkthroughs, mitigation links) pick up
the divergence as if it were authoritative.

What this script does
=====================
For every yaml threat whose ``id`` resolves to a ``.threats-merged.json``
entry (matched on T-NNN via ``t_id`` OR ``id``):

  * Compare ``stride`` / ``cwe`` / ``component`` (yaml) vs
    ``stride`` / ``cwe`` / ``component_id`` (merged).
  * Compare evidence file+line tuples.
  * On drift:
      - Default mode: **restore the merged value** in yaml and append a
        ``yaml_invariant_drift`` flag to ``evidence_flags`` plus a
        per-threat ``invariant_repaired`` block on the threat.
      - ``--report-only``: print the drift to stderr without rewriting.
      - Always: emit one log line per drift to ``.agent-run.log`` so the
        audit trail survives.

The script is idempotent — re-running on a drift-free yaml produces no
changes. It is safe to call multiple times in the Phase-11 finalisation
sequence.

Usage
-----
    python3 enforce_yaml_invariants.py <OUTPUT_DIR> [--report-only]

Exit codes:
  0 — yaml + merged are in lock-step (no drift detected)
  0 — drift detected and repaired (default mode)
  1 — drift detected; ``--report-only`` was set
  2 — usage / IO error
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

import yaml


_TRACKED_FIELDS = (
    # (yaml_field, merged_field) — fields that MUST be byte-identical
    # between .threats-merged.json and threat-model.yaml after Phase-11
    # Substep 2. Limited to ``stride`` and ``cwe`` because:
    #   * ``component`` legitimately changes via reclassify_components.py
    #     after yaml-write; RC.J keeps merged in sync separately.
    #   * ``evidence`` may legitimately gain additional rows in yaml
    #     (LLM is allowed to enrich with extra cite locations).
    # If a third field becomes drift-prone, add it here AND audit the
    # auto-emitter pass so legitimate post-yaml-write mutations are not
    # treated as drift.
    ("stride", "stride"),
    ("cwe", "cwe"),
)


def _evidence_tuples(threat: dict, prefer_dict: bool) -> list[tuple[str, int | None]]:
    """Normalise evidence to a comparable shape."""
    ev = threat.get("evidence")
    out: list[tuple[str, int | None]] = []
    if isinstance(ev, dict):
        f = (ev.get("file") or "").strip()
        line = ev.get("line")
        try:
            line_norm = int(line) if line is not None else None
        except (TypeError, ValueError):
            line_norm = None
        if f:
            out.append((f, line_norm))
    elif isinstance(ev, list):
        for e in ev:
            if not isinstance(e, dict):
                continue
            f = (e.get("file") or "").strip()
            line = e.get("line")
            try:
                line_norm = int(line) if line is not None else None
            except (TypeError, ValueError):
                line_norm = None
            if f:
                out.append((f, line_norm))
    return out


def _merged_by_tid(doc: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for t in doc.get("threats", []) or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("t_id") or t.get("id")
        if isinstance(tid, str) and tid:
            out[tid] = t
    return out


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(output_dir: Path, msg: str) -> None:
    log_path = output_dir / ".agent-run.log"
    try:
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"{_now()}  [--------]  WARN   skill  YAML_INVARIANT_DRIFT  {msg}\n")
    except OSError:
        pass  # best-effort logging


def enforce(output_dir: Path, report_only: bool) -> tuple[int, list[dict]]:
    """Return (drift_count, drift_records)."""
    yaml_path = output_dir / "threat-model.yaml"
    merged_path = output_dir / ".threats-merged.json"
    if not yaml_path.is_file():
        print(f"enforce_yaml_invariants: no yaml at {yaml_path}", file=sys.stderr)
        return -1, []
    if not merged_path.is_file():
        print(f"enforce_yaml_invariants: no merged file at {merged_path}", file=sys.stderr)
        return -1, []

    try:
        ydoc = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
        mdoc = json.loads(merged_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, json.JSONDecodeError, OSError) as exc:
        print(f"enforce_yaml_invariants: parse error: {exc}", file=sys.stderr)
        return -1, []

    merged_by = _merged_by_tid(mdoc)
    drifts: list[dict] = []
    for t in ydoc.get("threats", []) or []:
        if not isinstance(t, dict):
            continue
        tid = t.get("id") or t.get("t_id")
        if not isinstance(tid, str) or tid not in merged_by:
            continue
        m = merged_by[tid]
        per_threat: dict[str, dict] = {}

        for ykey, mkey in _TRACKED_FIELDS:
            yv = t.get(ykey)
            mv = m.get(mkey)
            # ``component`` in yaml maps to ``component_id`` in merged.
            # Either may be None when the run is incremental.
            if yv != mv and not (yv is None and mv is None):
                per_threat[ykey] = {"yaml": yv, "merged": mv}

        # Evidence comparison — sets, not order-sensitive.
        ye = set(_evidence_tuples(t, prefer_dict=True))
        me = set(_evidence_tuples(m, prefer_dict=False))
        if ye != me and (me - ye):
            # Only flag when merged carries evidence that yaml lost.
            # (yaml may legitimately add additional evidence entries.)
            per_threat["evidence"] = {
                "yaml": sorted(ye),
                "merged": sorted(me),
            }

        if not per_threat:
            continue

        drift_record = {"threat_id": tid, "fields": per_threat}
        drifts.append(drift_record)

        if report_only:
            continue

        # Repair: copy merged values into yaml.
        for ykey, mkey in _TRACKED_FIELDS:
            if ykey in per_threat:
                mv = m.get(mkey)
                if mv is not None:
                    t[ykey] = mv
        # Restore missing evidence rows from merged.
        if "evidence" in per_threat:
            existing = set(_evidence_tuples(t, prefer_dict=True))
            recovered = []
            for f, line in _evidence_tuples(m, prefer_dict=False):
                if (f, line) not in existing:
                    recovered.append({"file": f, "line": line})
            if recovered:
                ev = t.get("evidence")
                if isinstance(ev, dict):
                    t["evidence"] = [ev, *recovered]
                elif isinstance(ev, list):
                    t["evidence"] = [*ev, *recovered]
                else:
                    t["evidence"] = recovered

        # Audit trail on the threat itself.
        existing_flags = list(t.get("evidence_flags") or [])
        if "yaml_invariant_drift" not in existing_flags:
            existing_flags.append("yaml_invariant_drift")
        t["evidence_flags"] = existing_flags
        t.setdefault("invariant_repaired", []).append({
            "at": _now(),
            "fields": list(per_threat.keys()),
        })

        _log(output_dir,
             f"{tid} drift: " + ", ".join(
                 f"{k}({per_threat[k]['yaml']!r}→{per_threat[k]['merged']!r})"
                 for k in per_threat if k != "evidence"
             ))

    if drifts and not report_only:
        yaml_path.write_text(
            yaml.safe_dump(ydoc, sort_keys=False, allow_unicode=True, width=4096,
                           default_flow_style=False),
            encoding="utf-8",
        )

    return len(drifts), drifts


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="enforce_yaml_invariants",
        description="RC.G.3/RC.K — deterministic post-Phase-11 yaml invariant gate.",
    )
    p.add_argument("output_dir", help="$OUTPUT_DIR containing threat-model.yaml + .threats-merged.json.")
    p.add_argument("--report-only", action="store_true",
                   help="Print drift but do not rewrite yaml.")
    args = p.parse_args(argv)

    output_dir = Path(args.output_dir)
    count, drifts = enforce(output_dir, args.report_only)
    if count < 0:
        return 2
    if count == 0:
        print("enforce_yaml_invariants: yaml ↔ merged in lock-step (0 drifts)")
        return 0
    label = "reported (no rewrite)" if args.report_only else "repaired"
    print(f"enforce_yaml_invariants: {label} {count} drift(s) "
          f"across {len({d['threat_id'] for d in drifts})} threat(s)")
    for d in drifts[:6]:
        keys = ", ".join(d["fields"].keys())
        print(f"  {d['threat_id']}: {keys}")
    if len(drifts) > 6:
        print(f"  ... and {len(drifts)-6} more")
    return 1 if args.report_only else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
