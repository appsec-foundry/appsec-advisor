#!/usr/bin/env python3
"""Restore deep-only fragments preserved from a prior deeper run.

Companion to ``snapshot_preserved_sections.py``. Run right before composing the
report (Stage 2 pre-generation), AFTER the .fragments wipe and BEFORE the
renderer/compose. When the current run is shallower (``quick``) than the depth
the snapshot was authored at (``standard``/``thorough``), this restores the
fragment-driven deep sections that the shallow run does not regenerate so they
survive into the rendered report.

Currently restores:

* ``ms-ai-exposure.json`` — the AI/LLM Exposure callout fragment. Copied back
  into ``.fragments/`` only when the current run did not author one, so the
  composer's existing presence-gated render path emits the preserved callout.

§7 Security Architecture is handled directly by the composer's
``_resolve_security_arch_override`` (it reads the snapshot's ``prior-report.md``
verbatim), so it needs no fragment restore here.

Best-effort: never blocks the run. No-op on first runs, non-downgrade runs, or
when the current run already authored the fragment.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from preserve_lib import depth_rank as _depth_rank  # noqa: E402
from preserve_lib import preservable_sections, source_fingerprint  # noqa: E402


def _is_stale(section_meta: dict, declared: dict, repo_root: Path | None) -> bool:
    """A carried section is STALE (must be dropped, not preserved) when the repo
    files it describes changed since capture. Only enforced when source_globs are
    declared for the section AND a captured fingerprint exists. (2026-06-26)"""
    globs = declared.get("source_globs") or []
    captured_fp = (section_meta or {}).get("source_fingerprint")
    if not globs or not captured_fp or repo_root is None:
        return False  # staleness check disabled for this section
    return source_fingerprint(repo_root, globs) != captured_fp


def restore(output_dir: Path, current_depth: str, plugin_root: Path, repo_root: Path | None) -> int:
    snap_dir = output_dir / ".appsec-cache" / "preserved-sections"
    manifest_path = snap_dir / "manifest.json"
    if not manifest_path.is_file():
        return 0

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return 0

    origin_depth = (manifest.get("origin_depth") or "").strip().lower()
    origin_date = (manifest.get("origin_date") or "").strip()
    # Only restore when the current run is strictly SHALLOWER than the snapshot.
    if _depth_rank(origin_depth) <= _depth_rank(current_depth):
        return 0

    declared = {s["id"]: s for s in preservable_sections(plugin_root)}
    captured = {s.get("id"): s for s in (manifest.get("sections") or [])}
    fragments_dir = output_dir / ".fragments"
    restored = []
    carried_sections = []
    dropped_stale = []

    for sid, dmeta in declared.items():
        cmeta = captured.get(sid)
        # Back-compat with v1 manifests (no per-section block): treat AI as captured.
        if cmeta is None and sid == "ai_exposure_ms" and manifest.get("has_ai_exposure"):
            cmeta = {"id": sid, "fragment": "ms-ai-exposure.json", "captured": True}
        if not cmeta or not cmeta.get("captured"):
            continue
        if _is_stale(cmeta, dmeta, repo_root):
            dropped_stale.append(sid)
            continue
        if dmeta["substrate"] == "fragment" and dmeta.get("fragment"):
            snap_frag = snap_dir / dmeta["fragment"]
            live_frag = fragments_dir / dmeta["fragment"]
            if snap_frag.is_file() and not live_frag.is_file():
                fragments_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(snap_frag, live_frag)
                restored.append(dmeta["fragment"])
                carried_sections.append(sid)
        elif dmeta["substrate"] == "md-slice":
            # Restored by the composer's _resolve_security_arch_override directly
            # from prior-report.md; nothing to copy here, but it IS carried — the
            # composer records its own provenance entry when it carries.
            pass

    # Record provenance so the composer renders a "carried forward" marker on the
    # restored section(s) — the user requirement: a shallow re-run must MARK
    # preserved deeper content as carried, not pass it off as freshly analysed.
    if carried_sections:
        _record_provenance(output_dir, origin_depth, origin_date, carried_sections)

    if restored:
        sys.stdout.write(
            f"restore-sections: restored {', '.join(restored)} from "
            f"{origin_depth} snapshot (current depth: {current_depth})\n"
        )
    if dropped_stale:
        sys.stdout.write(
            f"restore-sections: dropped {', '.join(dropped_stale)} — source changed "
            "since capture (carried content would be stale)\n"
        )
    return 0


def record_provenance(output_dir: Path, origin_depth: str, origin_date: str, sections: list) -> None:
    """Merge carried-section provenance into .preserved-provenance.json. Shared
    by restore_preserved_sections.py (AI fragment) and the composer's §7
    carry-forward path so the rendered report can mark every carried section."""
    _record_provenance(output_dir, origin_depth, origin_date, sections)


def _record_provenance(output_dir: Path, origin_depth: str, origin_date: str, sections: list) -> None:
    path = output_dir / ".preserved-provenance.json"
    data = {"origin_depth": origin_depth, "origin_date": origin_date, "sections": []}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                data = existing
                data.setdefault("sections", [])
                # keep the deepest origin we've seen
                if origin_depth and not data.get("origin_depth"):
                    data["origin_depth"] = origin_depth
                if origin_date and not data.get("origin_date"):
                    data["origin_date"] = origin_date
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    for s in sections:
        if s not in data["sections"]:
            data["sections"].append(s)
    if not data.get("origin_depth"):
        data["origin_depth"] = origin_depth
    if not data.get("origin_date"):
        data["origin_date"] = origin_date
    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--current-depth", default="quick")
    p.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    p.add_argument("--repo-root", type=Path, default=None)
    args = p.parse_args()
    if not args.output_dir.is_dir():
        return 0
    try:
        return restore(args.output_dir, args.current_depth, args.plugin_root, args.repo_root)
    except Exception as e:  # best-effort
        sys.stderr.write(f"restore-sections: non-fatal error: {e}\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
