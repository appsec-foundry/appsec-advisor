#!/usr/bin/env python3
"""Full, uncapped change-log audit export for a threat model.

The report's own `## Changelog` section (rendered by
`compose_threat_model.py:_render_changelog`) is a *windowed* summary — it caps
each delta bucket at five IDs for readability. This module emits the COMPLETE
audit trail beside the report, outside `threat-model.md`:

  * `threat-model-changelog.md`    — human-readable, every entry, every ID, no cap
  * `threat-model-changelog.jsonl` — one JSON object per run, machine-readable

Both are a pure function of `threat-model.yaml`'s `changelog[]` (the committed,
accumulating store built by `build_threat_model_yaml.build_changelog`), so a
re-run with identical input reproduces identical bytes. Nothing here computes a
new delta — it only renders what the builder already tracked: added / changed /
resolved threats, mitigations, abuse cases, instances, and components per run.

`--archive` (called by the `--rebuild` pre-flight wipe before it discards the
prior model) MOVES the live audit files into `changelog-history/` with a
timestamped name instead of letting the wipe delete them, so a rebuild starts
fresh on disk without losing the prior audit trail.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

import yaml

LIVE_MD = "threat-model-changelog.md"
LIVE_JSONL = "threat-model-changelog.jsonl"
ARCHIVE_DIR = "changelog-history"

# Bulky internal diff state — full per-run fingerprint snapshots the builder
# stores so the NEXT run can diff against them. They are not "changes", so the
# machine export drops them; the markdown never shows them either.
_JSONL_DROP_KEYS = frozenset({"fingerprints", "match_keys", "mitigation_fingerprints", "instance_fingerprints"})


# ─── Loading ────────────────────────────────────────────────────────────────


def load_changelog(output_dir: Path) -> tuple[list[dict], dict[str, str], dict[str, str]]:
    """Read `threat-model.yaml` from `output_dir`.

    Returns (changelog, threat_title_by_id, mitigation_title_by_id). The title
    maps let the markdown render `T-014 — <title>` instead of a bare ID. A
    missing or malformed yaml yields empty results (caller treats as no-op).
    """
    yaml_path = Path(output_dir) / "threat-model.yaml"
    if not yaml_path.is_file():
        return [], {}, {}
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return [], {}, {}
    if not isinstance(data, dict):
        return [], {}, {}
    changelog = data.get("changelog")
    if not isinstance(changelog, list):
        changelog = []
    threats_by_id = {
        t.get("id"): (t.get("title") or "") for t in (data.get("threats") or []) if isinstance(t, dict) and t.get("id")
    }
    mits_by_id = {
        m.get("id"): (m.get("title") or "")
        for m in (data.get("mitigations") or [])
        if isinstance(m, dict) and m.get("id")
    }
    return changelog, threats_by_id, mits_by_id


# ─── Markdown ───────────────────────────────────────────────────────────────


def _label(id_: str, title_by_id: dict[str, str]) -> str:
    title = (title_by_id or {}).get(id_)
    return f"{id_} — {title}" if title else str(id_)


def _id_lines(ids: list, title_by_id: dict[str, str], notes: dict | None = None) -> list[str]:
    """One markdown bullet per ID — uncapped. `notes` appends a parenthetical."""
    out: list[str] = []
    for i in ids:
        text = _label(i, title_by_id)
        if notes and i in notes and notes[i]:
            text += f" — {notes[i]}"
        out.append(f"  - {text}")
    return out


def _entry_markdown(seq: int, entry: dict, threats_by_id: dict, mits_by_id: dict) -> list[str]:
    date = entry.get("date") or "—"
    time_local = entry.get("time_local") or ""
    mode = (entry.get("mode") or "full").lower()
    depth = entry.get("assessment_depth")
    model = entry.get("reasoning_model")

    head = f"## v{seq} — {date}"
    if time_local:
        head += f" {time_local}"
    meta_bits = [mode]
    if depth:
        meta_bits.append(str(depth))
    if model:
        meta_bits.append(str(model))
    head += " · " + " · ".join(meta_bits)
    lines = [head, ""]

    # Run context line.
    cur = entry.get("current_sha")
    base = entry.get("baseline_sha")
    ctx_bits = []
    if cur:
        ctx_bits.append(f"commit `{str(cur)[:7]}`")
    if base:
        ctx_bits.append(f"baseline `{str(base)[:7]}`")
    n = entry.get("threat_count")
    prev = entry.get("previous_threat_count")
    if n is not None:
        cnt = f"{n} finding" + ("" if n == 1 else "s")
        if prev is not None:
            cnt += f" (prev {prev})"
        ctx_bits.append(cnt)
    basis = entry.get("delta_basis")
    if basis:
        ctx_bits.append(f"delta basis: {basis}")
    if ctx_bits:
        lines.append("_" + " · ".join(ctx_bits) + "_")
        lines.append("")

    added = entry.get("added") or {}
    changed = entry.get("changed") or {}
    resolved = entry.get("resolved") or {}

    a_t = added.get("threats") or []
    a_m = added.get("mitigations") or []
    a_ac = added.get("abuse_cases") or []
    a_inst = added.get("instances") or []
    a_c = added.get("components") or []
    a_e = added.get("attack_surface") or []

    added_blocks: list[str] = []
    if a_t:
        added_blocks.append(f"- **Findings ({len(a_t)}):**")
        added_blocks += _id_lines(a_t, threats_by_id)
    if a_m:
        added_blocks.append(f"- **Mitigations ({len(a_m)}):**")
        added_blocks += _id_lines(a_m, mits_by_id)
    if a_ac:
        added_blocks.append(f"- **Abuse cases ({len(a_ac)}):** {', '.join(map(str, a_ac))}")
    if a_inst:
        added_blocks.append(f"- **Instances ({len(a_inst)}):**")
        added_blocks += [f"  - {i}" for i in a_inst]
    if a_c:
        added_blocks.append(f"- **Components ({len(a_c)}):** {', '.join(map(str, a_c))}")
    if a_e:
        added_blocks.append(f"- **Entry points ({len(a_e)}):** {', '.join(map(str, a_e))}")
    if added_blocks:
        lines.append("### Added")
        lines += added_blocks
        lines.append("")

    c_t = changed.get("threats") or []
    c_n = changed.get("notes_by_id") or {}
    if c_t:
        lines.append("### Changed")
        lines.append(f"- **Findings ({len(c_t)}):**")
        lines += _id_lines(c_t, threats_by_id, c_n)
        lines.append("")

    r_t = resolved.get("threats") or []
    r_fp = resolved.get("fingerprints") or []
    r_r = resolved.get("reason_by_id") or {}
    r_inst = resolved.get("instances") or []
    removed_blocks: list[str] = []
    if r_t:
        removed_blocks.append(f"- **Findings ({len(r_t)}):**")
        removed_blocks += _id_lines(r_t, threats_by_id, r_r)
    if r_fp:
        removed_blocks.append(f"- **Findings ({len(r_fp)}):**")
        removed_blocks += [f"  - {f}" for f in r_fp]
    if r_inst:
        removed_blocks.append(f"- **Instances ({len(r_inst)}):**")
        removed_blocks += [f"  - {i}" for i in r_inst]
    if removed_blocks:
        lines.append("### Removed / Resolved")
        lines += removed_blocks
        lines.append("")

    reanalyzed = entry.get("reanalyzed_components") or []
    carried = entry.get("carried_forward_components") or []
    arch_bits = []
    if reanalyzed:
        arch_bits.append(f"- **Re-analyzed:** {', '.join(map(str, reanalyzed))}")
    if carried:
        arch_bits.append(f"- **Carried forward:** {', '.join(map(str, carried))}")
    if arch_bits:
        lines.append("### Scope")
        lines += arch_bits
        lines.append("")

    note = (entry.get("note") or "").strip()
    if note:
        lines.append(f"> {note}")
        lines.append("")

    return lines


def render_markdown(changelog: list[dict], threats_by_id: dict, mits_by_id: dict) -> str:
    total = len(changelog)
    out = [
        "# Threat Model — Full Change Log",
        "",
        "> Complete, uncapped audit trail of every assessment run for this threat",
        "> model: all added, changed, and removed findings, mitigations, abuse",
        "> cases, instances, and components. The report's own Change Log section is",
        "> a summarized window of this history. Generated deterministically from",
        "> `threat-model.yaml`; do not hand-edit.",
        "",
    ]
    for idx, entry in enumerate(changelog):
        if not isinstance(entry, dict):
            continue
        seq = total - idx  # newest entry (idx 0) gets the highest version number
        out += _entry_markdown(seq, entry, threats_by_id, mits_by_id)
    return "\n".join(out).rstrip() + "\n"


# ─── JSONL ──────────────────────────────────────────────────────────────────


def render_jsonl(changelog: list[dict]) -> str:
    total = len(changelog)
    lines: list[str] = []
    for idx, entry in enumerate(changelog):
        if not isinstance(entry, dict):
            continue
        rec = {k: v for k, v in entry.items() if k not in _JSONL_DROP_KEYS}
        rec["seq"] = total - idx
        lines.append(json.dumps(rec, sort_keys=True, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


# ─── Public ops ─────────────────────────────────────────────────────────────


def write_audit(output_dir: Path) -> bool:
    """Render both audit files from `output_dir/threat-model.yaml`.

    Returns True when files were written, False when there is no changelog to
    export (missing/empty yaml). Never raises on a missing source.
    """
    output_dir = Path(output_dir)
    changelog, threats_by_id, mits_by_id = load_changelog(output_dir)
    if not changelog:
        return False
    (output_dir / LIVE_MD).write_text(render_markdown(changelog, threats_by_id, mits_by_id), encoding="utf-8")
    (output_dir / LIVE_JSONL).write_text(render_jsonl(changelog), encoding="utf-8")
    return True


def archive_audit(output_dir: Path, stamp: str | None = None) -> list[str]:
    """Move live audit files into `changelog-history/` with a timestamped name.

    Called by the `--rebuild` pre-flight wipe so the prior audit trail survives
    a rebuild that discards `threat-model.yaml`. No-op when nothing exists.
    """
    output_dir = Path(output_dir)
    live = [output_dir / LIVE_MD, output_dir / LIVE_JSONL]
    existing = [p for p in live if p.is_file()]
    if not existing:
        return []
    hist = output_dir / ARCHIVE_DIR
    hist.mkdir(exist_ok=True)
    ts = stamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    moved: list[str] = []
    for p in existing:
        dest = hist / f"{p.stem}-{ts}{p.suffix}"
        shutil.move(str(p), str(dest))
        moved.append(dest.name)
    return moved


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-dir", default=".", help="Directory holding threat-model.yaml.")
    ap.add_argument(
        "--archive",
        action="store_true",
        help="Move live audit files into changelog-history/ instead of rendering "
        "(used by the --rebuild pre-flight wipe).",
    )
    args = ap.parse_args(argv)
    out = Path(args.output_dir)

    if args.archive:
        moved = archive_audit(out)
        if moved:
            print(f"changelog-audit: archived {len(moved)} file(s) -> {ARCHIVE_DIR}/")
        else:
            print("changelog-audit: nothing to archive")
        return 0

    if write_audit(out):
        print(f"changelog-audit: wrote {LIVE_MD} + {LIVE_JSONL}")
    else:
        print("changelog-audit: no changelog in threat-model.yaml — skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
