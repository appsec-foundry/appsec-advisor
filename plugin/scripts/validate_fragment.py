#!/usr/bin/env python3
"""Validate an LLM-authored fragment against its JSON schema.

Fragments are the ONLY way the orchestrator can influence the rendered
Markdown — the renderer then consumes the validated data. This script is
the hard gate that prevents malformed fragments from reaching the renderer.

Typical use (from phase-group-threats.md / phase-group-finalization.md):

    python3 validate_fragment.py verdict "$OUTPUT_DIR/.fragments/ms-verdict.json"

Exit codes:
    0 — fragment is valid
    1 — schema violation
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jsonschema

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = PLUGIN_ROOT / "schemas" / "fragments"

# Map fragment type → schema file. This is the single source of truth for
# which fragments validate against which schemas.
FRAGMENT_SCHEMAS: dict[str, str] = {
    "verdict":                            "verdict.schema.json",
    "architecture-assessment":            "architecture-assessment.schema.json",
    "critical-attack-chain":              "critical-attack-chain.schema.json",
    "compound-chains":                    "compound-chains.schema.json",
    "architectural-findings":             "architectural-findings.schema.json",
    "operational-strengths-overrides":    "operational-strengths-overrides.schema.json",
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
            f"VALIDATE_FAILED: {path.name} ({fragment_type}) — "
            f"schema violation at {where}: {e.message}",
            file=sys.stderr,
        )
        return 1
    print(f"VALIDATE_OK: {path.name} matches {fragment_type}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="validate_fragment.py",
        description="Validate an LLM-authored data fragment against its "
                    "JSON schema. Used as a hard gate before the renderer.",
    )
    p.add_argument("fragment_type", choices=sorted(FRAGMENT_SCHEMAS),
                   help="Fragment type (maps to a schema in schemas/fragments/).")
    p.add_argument("path", type=Path, help="Path to the fragment file.")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    return validate(args.fragment_type, args.path)


if __name__ == "__main__":
    sys.exit(main())
