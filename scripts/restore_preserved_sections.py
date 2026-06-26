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

_DEPTH_RANK = {"quick": 0, "standard": 2, "thorough": 3}


def _depth_rank(depth: str | None) -> int:
    return _DEPTH_RANK.get((depth or "").strip().lower(), -1)


def restore(output_dir: Path, current_depth: str) -> int:
    if (current_depth or "").strip().lower() != "quick":
        return 0  # only a shallow (quick) run needs to restore deeper content

    snap_dir = output_dir / ".appsec-cache" / "preserved-sections"
    manifest_path = snap_dir / "manifest.json"
    if not manifest_path.is_file():
        return 0

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return 0

    origin_depth = (manifest.get("origin_depth") or "").strip().lower()
    if _depth_rank(origin_depth) <= _depth_rank("quick"):
        return 0  # snapshot is not deeper than the current run — nothing to restore

    fragments_dir = output_dir / ".fragments"
    restored = []

    # AI/LLM exposure callout.
    if manifest.get("has_ai_exposure"):
        snap_ai = snap_dir / "ms-ai-exposure.json"
        live_ai = fragments_dir / "ms-ai-exposure.json"
        if snap_ai.is_file() and not live_ai.is_file():
            fragments_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(snap_ai, live_ai)
            restored.append("ms-ai-exposure.json")

    if restored:
        sys.stdout.write(
            f"restore-sections: restored {', '.join(restored)} from "
            f"{origin_depth} snapshot (current depth: quick)\n"
        )
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--current-depth", default="quick")
    args = p.parse_args()
    if not args.output_dir.is_dir():
        return 0
    try:
        return restore(args.output_dir, args.current_depth)
    except Exception as e:  # best-effort
        sys.stderr.write(f"restore-sections: non-fatal error: {e}\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
