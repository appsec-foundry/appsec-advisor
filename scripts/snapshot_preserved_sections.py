#!/usr/bin/env python3
"""Snapshot deep-only report sections before a (potentially shallower) re-run.

Problem this solves
--------------------
A ``--quick`` re-run over an output directory that previously held a
``standard``/``thorough`` report would DELETE the deep-only sections that quick
mode does not author (§7 Security Architecture, the AI/LLM Exposure callout).
The user's contract: a shallower re-scan must PRESERVE deeper content from a
prior run — sections only disappear when they are genuinely no longer valid,
not merely because this run was too shallow to regenerate them.

The composer already has a §7 "preserve verbatim from the prior report" path
(``compose_threat_model._resolve_security_arch_override``), but it read the
*live* ``threat-model.md`` — which the orchestrator overwrites in place before
compose — and the prior depth from ``baseline.json.last_run_depth``, which the
prior run often never persisted. Both inputs were unreliable, so the preserve
silently failed and the deep sections vanished.

This script captures a STABLE snapshot at run-start, BEFORE the wipe/overwrite:

* ``.appsec-cache/preserved-sections/prior-report.md`` — the full prior
  ``threat-model.md`` (the composer extracts §7 verbatim from it and runs its
  F-NNN stability gate against this stable copy).
* ``.appsec-cache/preserved-sections/ms-ai-exposure.json`` — the prior AI/LLM
  exposure fragment, when one existed.
* ``.appsec-cache/preserved-sections/manifest.json`` — ``origin_depth`` (the
  depth the snapshot content was authored at) + capture metadata.

Keep-deeper rule
----------------
The snapshot is only refreshed when the prior report's depth is at least as deep
as the stored snapshot's ``origin_depth``. So a quick run (whose own §7 may be a
*preserved, inherited* copy) never clobbers a genuine standard/thorough
snapshot; a fresh standard run refreshes it.

Depth comparison reads the prior report's depth from ``threat-model.yaml``
``meta.assessment_depth`` (robust — same file §7 is extracted from), falling back
to ``baseline.json.last_run_depth``.

Run at the start of every assessment (before the full-run wipe). No-op when no
prior report exists. Best-effort: any failure is non-fatal — the composer's own
fallbacks still apply.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import shutil
import sys
from pathlib import Path

_DEPTH_RANK = {"quick": 0, "standard": 2, "thorough": 3}


def _depth_rank(depth: str | None) -> int:
    return _DEPTH_RANK.get((depth or "").strip().lower(), -1)


def _read_prior_depth(output_dir: Path) -> str:
    """Return the prior report's assessment depth.

    Prefer ``threat-model.yaml meta.assessment_depth`` (root-aligned match, the
    same robustness used by resolve_config._extract_baseline_assessment_depth);
    fall back to ``.appsec-cache/baseline.json.last_run_depth``.
    """
    yaml_path = output_dir / "threat-model.yaml"
    if yaml_path.is_file():
        try:
            text = yaml_path.read_text(encoding="utf-8")
        except OSError:
            text = ""
        m = re.search(r"(?m)^\s{2}assessment_depth:\s*\"?(\w+)\"?\s*$", text)
        if m:
            return m.group(1).strip().lower()
    baseline = output_dir / ".appsec-cache" / "baseline.json"
    if baseline.is_file():
        try:
            return (
                (json.loads(baseline.read_text(encoding="utf-8")).get("last_run_depth") or "")
                .strip()
                .lower()
            )
        except (OSError, ValueError, json.JSONDecodeError):
            return ""
    return ""


def _read_prior_date(output_dir: Path) -> str:
    """Return the prior report's run date for provenance ("carried forward from
    the <date> run"). Reads the newest changelog entry's date from
    threat-model.yaml; empty string if unavailable."""
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        return ""
    try:
        text = yaml_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    # The first date: under changelog: is the newest entry's date (newest-first).
    m = re.search(r"(?ms)^changelog:\s*\n.*?^\s*-?\s*.*?\bdate:\s*\"?(\d{4}-\d{2}-\d{2})", text)
    if m:
        return m.group(1)
    return ""


def snapshot(output_dir: Path) -> int:
    # Clear any stale carried-section provenance from a PRIOR run first — it is
    # repopulated within THIS run by restore_preserved_sections (AI) and the
    # composer's §7 carry path. Without this, a later non-downgrade run would
    # render bogus "carried forward" banners. (2026-06-26)
    prov = output_dir / ".preserved-provenance.json"
    if prov.is_file():
        try:
            prov.unlink()
        except OSError:
            pass

    prior_md = output_dir / "threat-model.md"
    if not prior_md.is_file():
        # First run / nothing to preserve.
        return 0

    prior_depth = _read_prior_depth(output_dir)
    snap_dir = output_dir / ".appsec-cache" / "preserved-sections"
    manifest_path = snap_dir / "manifest.json"

    stored_rank = -1
    if manifest_path.is_file():
        try:
            stored = json.loads(manifest_path.read_text(encoding="utf-8"))
            stored_rank = _depth_rank(stored.get("origin_depth"))
        except (OSError, ValueError, json.JSONDecodeError):
            stored_rank = -1

    # Keep-deeper rule: only refresh if the prior report is at least as deep as
    # what we already have stored. A quick run carrying an inherited §7 must not
    # overwrite a genuine standard/thorough snapshot.
    if _depth_rank(prior_depth) < stored_rank:
        sys.stdout.write(
            f"snapshot-sections: kept existing (stored depth rank {stored_rank} "
            f"> prior '{prior_depth or '?'}')\n"
        )
        return 0

    snap_dir.mkdir(parents=True, exist_ok=True)

    captured = []
    # §7 + everything else lives in the full prior report; the composer extracts
    # what it needs verbatim and runs its F-NNN gate against this stable copy.
    shutil.copy2(prior_md, snap_dir / "prior-report.md")
    captured.append("prior-report.md")

    # AI/LLM exposure renders from a fragment, not a verbatim md slice — snapshot
    # the fragment so the composer can restore the callout on a shallow re-run.
    ai_fragment = output_dir / ".fragments" / "ms-ai-exposure.json"
    has_ai = ai_fragment.is_file()
    if has_ai:
        shutil.copy2(ai_fragment, snap_dir / "ms-ai-exposure.json")
        captured.append("ms-ai-exposure.json")

    manifest = {
        "schema_version": 1,
        "origin_depth": prior_depth,
        "origin_date": _read_prior_date(output_dir),
        "captured_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "has_prior_report": True,
        "has_ai_exposure": has_ai,
        "files": captured,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(
        f"snapshot-sections: captured {', '.join(captured)} "
        f"(origin depth: {prior_depth or '?'})\n"
    )
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output_dir", type=Path)
    args = p.parse_args()
    if not args.output_dir.is_dir():
        sys.stderr.write(f"snapshot-sections: output dir not found: {args.output_dir}\n")
        return 0  # non-fatal
    try:
        return snapshot(args.output_dir)
    except Exception as e:  # best-effort — never block the run
        sys.stderr.write(f"snapshot-sections: non-fatal error: {e}\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
