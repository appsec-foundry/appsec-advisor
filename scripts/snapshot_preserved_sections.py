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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from preserve_lib import depth_rank as _depth_rank  # noqa: E402
from preserve_lib import preservable_sections, source_fingerprint  # noqa: E402


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
            return (json.loads(baseline.read_text(encoding="utf-8")).get("last_run_depth") or "").strip().lower()
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
    # The first `date:` after the `changelog:` key is the newest entry's date
    # (newest-first). Scan line-by-line — a single `.*?` regex over the whole
    # 100KB+ yaml backtracks catastrophically and hangs. (2026-06-26)
    in_changelog = False
    date_re = re.compile(r"""^\s*-?\s*date:\s*['"]?(\d{4}-\d{2}-\d{2})""")
    for line in text.splitlines():
        if not in_changelog:
            if re.match(r"^changelog:\s*$", line):
                in_changelog = True
            continue
        # stop at the next top-level key (column-0, non-list, ends with ':')
        if re.match(r"^\S", line) and not line.lstrip().startswith("-"):
            break
        m = date_re.match(line)
        if m:
            return m.group(1)
    return ""


def snapshot(output_dir: Path, plugin_root: Path, repo_root: Path | None) -> int:
    # Clear any stale carried-section provenance from a PRIOR run first — it is
    # repopulated within THIS run by restore_preserved_sections (fragments) and
    # the composer's §7 carry path. Without this, a later non-downgrade run would
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
            f"snapshot-sections: kept existing (stored depth rank {stored_rank} > prior '{prior_depth or '?'}')\n"
        )
        return 0

    sections = preservable_sections(plugin_root)
    snap_dir.mkdir(parents=True, exist_ok=True)

    captured = ["prior-report.md"]
    # The full prior report backs every md-slice section; the composer extracts
    # what it needs verbatim and runs its F-NNN gate against this stable copy.
    shutil.copy2(prior_md, snap_dir / "prior-report.md")

    # Per-section capture, driven entirely by the contract's preserve block.
    section_meta: list[dict] = []
    for s in sections:
        entry = {
            "id": s["id"],
            "substrate": s["substrate"],
            "fragment": s.get("fragment"),
            "md_section_number": s.get("md_section_number"),
            "captured": False,
        }
        if s["substrate"] == "fragment" and s.get("fragment"):
            src = output_dir / ".fragments" / s["fragment"]
            if src.is_file():
                shutil.copy2(src, snap_dir / s["fragment"])
                captured.append(s["fragment"])
                entry["captured"] = True
        elif s["substrate"] == "md-slice":
            # Backed by prior-report.md — captured iff the section heading exists.
            num = s.get("md_section_number")
            if num is not None and re.search(
                rf"(?m)^## {int(num)}\. ", prior_md.read_text(encoding="utf-8", errors="ignore")
            ):
                entry["captured"] = True
        # Staleness input: hash the repo files the section describes, if declared.
        if repo_root is not None and s.get("source_globs"):
            entry["source_fingerprint"] = source_fingerprint(repo_root, s["source_globs"])
        section_meta.append(entry)

    manifest = {
        "schema_version": 2,
        "origin_depth": prior_depth,
        "origin_date": _read_prior_date(output_dir),
        "captured_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "has_prior_report": True,
        # legacy field retained for the composer's older read path
        "has_ai_exposure": any(e["id"] == "ai_exposure_ms" and e["captured"] for e in section_meta),
        "files": captured,
        "sections": section_meta,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"snapshot-sections: captured {', '.join(captured)} (origin depth: {prior_depth or '?'})\n")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output_dir", type=Path)
    p.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    p.add_argument("--repo-root", type=Path, default=None)
    args = p.parse_args()
    if not args.output_dir.is_dir():
        sys.stderr.write(f"snapshot-sections: output dir not found: {args.output_dir}\n")
        return 0  # non-fatal
    try:
        return snapshot(args.output_dir, args.plugin_root, args.repo_root)
    except Exception as e:  # best-effort — never block the run
        sys.stderr.write(f"snapshot-sections: non-fatal error: {e}\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
