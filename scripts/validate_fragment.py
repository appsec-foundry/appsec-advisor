#!/usr/bin/env python3
"""Validate an LLM-authored fragment against its JSON schema.

Fragments are the ONLY way the orchestrator can influence the rendered
Markdown — the renderer then consumes the validated data. This script is
the hard gate that prevents malformed fragments from reaching the renderer.

Typical use (from phase-group-threats.md / phase-group-finalization.md):

    python3 validate_fragment.py verdict "$OUTPUT_DIR/.fragments/ms-verdict.json"

Bulk pre-render gate — validates all JSON fragments before compose runs:

    python3 validate_fragment.py pre-render-gate "$OUTPUT_DIR" [--json]

Exit codes:
    0 — fragment is valid (or all fragments passed the gate)
    1 — schema violation (or at least one fragment failed the gate)
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jsonschema

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _atomic_io import atomic_write_json

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = PLUGIN_ROOT / "schemas" / "fragments"

# Map fragment type → schema file. This is the single source of truth for
# which fragments validate against which schemas.
FRAGMENT_SCHEMAS: dict[str, str] = {
    "verdict": "verdict.schema.json",
    "architecture-assessment": "architecture-assessment.schema.json",
    "critical-attack-tree": "critical-attack-tree.schema.json",
    "compound-chains": "compound-chains.schema.json",
    "operational-strengths-overrides": "operational-strengths-overrides.schema.json",
    "security-posture-attack-paths": "security-posture-attack-paths.schema.json",
    "anti-patterns": "anti-patterns.schema.json",
    "ai-exposure": "ai-exposure.schema.json",
    "ms-top-mitigations": "ms-top-mitigations.schema.json",
    # Substep 2 deterministic migration sidecars. These are INPUTS to
    # scripts/build_threat_model_yaml.py, NOT render fragments — they
    # live at $OUTPUT_DIR/.X.json (dot-prefix, repo root of output_dir)
    # rather than $OUTPUT_DIR/.fragments/X.json. They share the validator
    # because the underlying JSON-Schema machinery is identical; the
    # fragment_filename map below stays empty for them so the pre-render
    # gate keeps ignoring them.
    "components": "components.schema.json",
    "assets": "assets.schema.json",
    "trust-boundaries": "trust-boundaries.schema.json",
    "security-controls": "security-controls.schema.json",
    "attack-surface-overrides": "attack-surface-overrides.schema.json",
    "mitigation-overrides": "mitigation-overrides.schema.json",
    "tier-root-causes": "tier-root-causes.schema.json",
}

# Reverse map: schema file stem → fragment type (used by pre-render-gate to
# identify the type of each .json fragment found on disk).
_STEM_TO_TYPE: dict[str, str] = {v.replace(".schema.json", ""): k for k, v in FRAGMENT_SCHEMAS.items()}

# Canonical fragment filenames used by the renderer (from sections-contract.yaml
# + phase-group-finalization.md). Keyed by fragment type for reverse lookup.
# Substep-2 sidecars are intentionally NOT listed here — they are NOT render
# fragments, they are aggregator inputs (live at OUTPUT_DIR/.X.json).
_FRAGMENT_FILENAMES: dict[str, str] = {
    "verdict": "ms-verdict.json",
    "architecture-assessment": "ms-architecture-assessment.json",
    "critical-attack-tree": "ms-critical-attack-tree.json",
    "compound-chains": "compound-chains.json",
    "operational-strengths-overrides": "operational-strengths-overrides.json",
    "security-posture-attack-paths": "security-posture-attack-paths.json",
    "anti-patterns": "ms-anti-patterns.json",
    "ai-exposure": "ms-ai-exposure.json",
    "ms-top-mitigations": "ms-top-mitigations.json",
}


def _load_schema(fragment_type: str) -> dict:
    schema_name = FRAGMENT_SCHEMAS.get(fragment_type)
    if not schema_name:
        raise SystemExit(
            f"VALIDATE_FAILED: unknown fragment type {fragment_type!r}. "
            f"Known types: {', '.join(sorted(FRAGMENT_SCHEMAS))}"
        )
    schema_path = SCHEMAS_DIR / schema_name
    if not schema_path.is_file():
        raise SystemExit(f"VALIDATE_FAILED: schema file not found: {schema_path}")
    try:
        return json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"VALIDATE_FAILED: schema {schema_path} is not JSON: {e}")


def _load_fragment(path: Path) -> object:
    if not path.is_file():
        raise SystemExit(f"VALIDATE_FAILED: fragment not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(
            f"VALIDATE_FAILED: {path} is not valid JSON — the orchestrator "
            f"must emit a JSON object, not Markdown. Parse error: {e}"
        )


def validate(fragment_type: str, path: Path) -> int:
    schema = _load_schema(fragment_type)
    data = _load_fragment(path)
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        where = "/".join(str(p) for p in e.absolute_path) or "<root>"
        print(
            f"VALIDATE_FAILED: {path.name} ({fragment_type}) — schema violation at {where}: {e.message}",
            file=sys.stderr,
        )
        return 1
    print(f"VALIDATE_OK: {path.name} matches {fragment_type}")
    return 0


def _fragment_type_for_file(path: Path) -> str | None:
    """Identify the fragment type for a .json file in .fragments/.

    Uses the canonical filename map first; falls back to schema-stem matching.
    Returns None when the file is not a known JSON data fragment (e.g. prose .md,
    or an unrecognized json sidecar).
    """
    name = path.name
    for ftype, fname in _FRAGMENT_FILENAMES.items():
        if name == fname:
            return ftype
    # Fallback: strip ".json" and check if the stem matches a schema name.
    stem = name.removesuffix(".json")
    return _STEM_TO_TYPE.get(stem)


def run_pre_render_gate(
    output_dir: Path,
    emit_json: bool = False,
) -> int:
    """Validate fragment presence + schema under output_dir/.fragments/ before
    the renderer runs.  Writes a .pre-render-report.json summary to output_dir.

    Returns 0 when all required fragments are present and schema-valid;
    1 when any fragment is missing or fails schema validation.

    Required fragment set (unconditional — they exist on every legitimate
    compose_threat_model.py run):

        ms-verdict.json
        ms-architecture-assessment.json
        system-overview.md
        architecture-diagrams.md
        attack-walkthroughs.md
        assets.md
        attack-surface.md
        security-architecture.md

    Missing `.fragments/` directory or absent required fragments count as a
    hard failure — the only way they can disappear mid-run is if the
    orchestrator took the inline-shortcut and bypassed compose_threat_model.py
    entirely, which is a policy violation. The legacy behaviour (skip when
    `.fragments/` absent) let that failure mode slip through Phase 11 silently.
    """
    # Unconditional fragment set — mirrors qa_checks.REQUIRED_FRAGMENTS.
    # Kept as a local tuple to avoid a circular import between the two
    # scripts (both are run standalone from the skill layer).
    required_fragments = (
        "ms-verdict.json",
        "ms-architecture-assessment.json",
        "system-overview.md",
        "architecture-diagrams.md",
        "attack-walkthroughs.md",
        "assets.md",
        "attack-surface.md",
        "security-architecture.md",
    )

    fragments_dir = output_dir / ".fragments"
    report: dict = {
        "passed": [],
        "failed": [],
        "missing_required": [],
        "skipped": [],
    }

    if not fragments_dir.is_dir():
        report["error"] = (
            f".fragments/ directory not found under {output_dir} — the "
            "orchestrator did not go through the fragment pipeline. "
            "Re-run Phase 8-11 with compose_threat_model.py; direct Write "
            "of threat-model.md is a policy violation."
        )
        report["missing_required"] = list(required_fragments)
        _write_report(output_dir, report)
        if emit_json:
            print(json.dumps(report, indent=2))
        else:
            print(
                "PRE_RENDER_GATE: .fragments/ not found — hard fail. Orchestrator bypassed compose_threat_model.py.",
                file=sys.stderr,
            )
        return 1

    # Check required fragment presence before schema validation so a missing
    # file is reported as "missing_required" instead of an invalid file.
    present = {p.name for p in fragments_dir.iterdir() if p.is_file()}
    report["missing_required"] = [name for name in required_fragments if name not in present]

    for path in sorted(fragments_dir.glob("*.json")):
        ftype = _fragment_type_for_file(path)
        if ftype is None:
            report["skipped"].append(path.name)
            continue

        schema_name = FRAGMENT_SCHEMAS[ftype]
        schema_path = SCHEMAS_DIR / schema_name
        if not schema_path.is_file():
            report["skipped"].append(f"{path.name} (schema {schema_name} not found)")
            continue

        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            report["failed"].append({"file": path.name, "type": ftype, "error": str(e)})
            continue

        try:
            jsonschema.validate(instance=data, schema=schema)
            report["passed"].append(path.name)
        except jsonschema.ValidationError as e:
            where = "/".join(str(p) for p in e.absolute_path) or "<root>"
            report["failed"].append(
                {
                    "file": path.name,
                    "type": ftype,
                    "error": f"schema violation at {where}: {e.message}",
                }
            )

    _write_report(output_dir, report)

    failed = len(report["failed"])
    missing = len(report["missing_required"])
    passed = len(report["passed"])
    skipped = len(report["skipped"])

    if emit_json:
        print(json.dumps(report, indent=2))
    elif failed or missing:
        if missing:
            print(
                f"PRE_RENDER_GATE: {missing} required fragment(s) missing — "
                f"passed={passed} failed={failed} skipped={skipped}",
                file=sys.stderr,
            )
            for name in report["missing_required"]:
                print(f"  MISSING {name}", file=sys.stderr)
        if failed:
            print(
                f"PRE_RENDER_GATE: {failed} fragment(s) failed schema — "
                f"passed={passed} missing={missing} skipped={skipped}",
                file=sys.stderr,
            )
            for entry in report["failed"]:
                print(f"  FAILED {entry['file']} ({entry['type']}): {entry['error']}", file=sys.stderr)
    else:
        print(f"PRE_RENDER_GATE: all {passed} fragment(s) valid (skipped={skipped})")

    return 1 if (failed or missing) else 0


def _write_report(output_dir: Path, report: dict) -> None:
    try:
        atomic_write_json(
            output_dir / ".pre-render-report.json",
            report,
            indent=2,
            sort_keys=False,
        )
    except OSError:
        pass  # non-fatal — the gate result is printed to stderr regardless


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    # Route by first token: "pre-render-gate" dispatches to the bulk gate;
    # anything else falls through to the legacy single-fragment interface.
    if args and args[0] == "pre-render-gate":
        gate_p = argparse.ArgumentParser(
            prog="validate_fragment.py pre-render-gate",
            description="Bulk-validate all known JSON fragments in "
            "<output_dir>/.fragments/. Writes .pre-render-report.json "
            "and exits 1 if any fragment fails.",
        )
        gate_p.add_argument("output_dir", type=Path, help="Path to $OUTPUT_DIR (must contain .fragments/).")
        gate_p.add_argument("--json", action="store_true", help="Print structured JSON report to stdout.")
        gargs = gate_p.parse_args(args[1:])
        if not gargs.output_dir.is_dir():
            print(f"error: output_dir not a directory: {gargs.output_dir}", file=sys.stderr)
            return 2
        return run_pre_render_gate(gargs.output_dir, emit_json=gargs.json)

    # Legacy positional mode — original single-fragment interface:
    #   validate_fragment.py <fragment_type> <path>
    legacy = argparse.ArgumentParser(
        prog="validate_fragment.py",
        description="Validate an LLM-authored data fragment against its "
        "JSON schema. Used as a hard gate before the renderer.",
    )
    legacy.add_argument(
        "fragment_type",
        choices=sorted(FRAGMENT_SCHEMAS),
        help="Fragment type (maps to a schema in schemas/fragments/).",
    )
    legacy.add_argument("path", type=Path, help="Path to the fragment file.")
    largs = legacy.parse_args(args)
    return validate(largs.fragment_type, largs.path)


if __name__ == "__main__":
    sys.exit(main())
