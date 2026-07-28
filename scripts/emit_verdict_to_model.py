#!/usr/bin/env python3
"""Persist the Management-Summary verdict into ``threat-model.yaml``.

The assessment's own conclusion — the ``### Verdict`` block the report leads
with, plus the worst-case scenarios behind it — existed in exactly two places:
the rendered ``threat-model.md`` and ``.fragments/ms-verdict.json``. Cleanup
deletes the fragment directory (``runtime_cleanup.POST_QA_DIRS``), so once a
run finished, the semantic model could not state its own verdict and every
consumer (``show-threat-model``, ``ask-threat-model``, exports) had to either
omit it or scrape markdown.

This emitter closes that gap. It reads the fragment the composer just
rendered, resolves it to the ids the reader sees (``F-NNN`` / ``W-NNN``) and
the verified-attack-path signal, and writes a top-level ``verdict`` block.

Runs AFTER ``compose_threat_model.py``: the composer is read-only for
``threat-model.yaml`` (``test_analysis_version_upgrade`` pins that a render
never rewrites the model), and the fragment is only guaranteed present and
schema-valid once compose has accepted it.

Idempotent — re-running against an unchanged fragment rewrites nothing.
Best-effort: a failure here leaves a complete, correct report in place, so it
warns and exits 0 rather than failing a run after Stage 2.

Usage:
    python3 emit_verdict_to_model.py <output_dir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from _atomic_io import atomic_write_text


def build_verdict(output_dir: Path) -> dict | None:
    """Resolve ``.fragments/ms-verdict.json`` into the persisted shape.

    Returns ``None`` when the fragment is absent or unusable — an
    architecture-only document or a run that never reached Stage 2.
    """
    frag = Path(output_dir) / ".fragments" / "ms-verdict.json"
    yaml_path = Path(output_dir) / "threat-model.yaml"
    try:
        data = json.loads(frag.read_text(encoding="utf-8"))
        yaml_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, yaml.YAMLError):
        return None
    if not isinstance(data, dict) or not isinstance(yaml_data, dict):
        return None
    if not str(data.get("opening") or "").strip():
        return None

    # The composer owns the ref → finding/weakness/chain resolution; reuse it
    # rather than re-deriving, so the persisted block and the rendered block
    # can never disagree.
    import compose_threat_model as compose

    ctx = compose.RenderContext(
        output_dir=Path(output_dir),
        contract={},
        yaml_data=yaml_data,
        triage={},
        fragments_dir=frag.parent,
    )
    return compose._build_verdict_export(ctx, data, compose._verified_chain_map(ctx))


def emit(output_dir: Path) -> str:
    """Write the verdict block. Returns a short status for the log line."""
    verdict = build_verdict(output_dir)
    if verdict is None:
        return "no verdict fragment — nothing to do"
    yaml_path = Path(output_dir) / "threat-model.yaml"
    try:
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return f"skipped — {type(exc).__name__}: {exc}"
    if not isinstance(doc, dict):
        return "skipped — threat-model.yaml is not a mapping"
    if doc.get("verdict") == verdict:
        return "unchanged"
    doc["verdict"] = verdict
    try:
        atomic_write_text(
            yaml_path,
            # Same dump options as build_threat_model_yaml.py so re-serialising
            # here does not reformat the whole file.
            yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120),
        )
    except (OSError, yaml.YAMLError) as exc:
        return f"skipped — {type(exc).__name__}: {exc}"
    return f"written ({len(verdict.get('bullets') or [])} worst-case scenario(s))"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: emit_verdict_to_model.py <output_dir>", file=sys.stderr)
        return 2
    print(f"emit_verdict_to_model: {emit(Path(argv[0]))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
