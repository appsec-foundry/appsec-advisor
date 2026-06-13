#!/usr/bin/env python3
"""Fragment-registry drift linter (Phase A1 of docs/internal/runbooks/refactoring-plan.md).

Cross-checks the fragment ↔ schema ↔ section relation that is implicitly
encoded across five Python maps + the YAML contract + the on-disk schema
directory:

    1. data/sections-contract.yaml          (human-edited declaration)
    2. scripts/compose_threat_model.py
         _SECTION_FRAGMENT_MAP
         _KNOWN_JSON_FRAGMENT_SCHEMAS
    3. scripts/validate_fragment.py
         FRAGMENT_SCHEMAS
         _FRAGMENT_FILENAMES
    4. scripts/qa_checks.py
         CONTRACT_SECTION_FRAGMENTS
    5. schemas/fragments/*.schema.json      (on-disk JSON Schemas)

Exits 1 on any drift, 0 when everything aligns. See schema-invariants §4f.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import yaml

# Substep-2 deterministic-migration sidecars: validator-only INPUT types that
# share the JSON-Schema machinery but are NOT render fragments. They live in
# FRAGMENT_SCHEMAS only (never in _FRAGMENT_FILENAMES). Keep in sync with the
# design note above the maps in scripts/validate_fragment.py.
_SIDECAR_ONLY_TYPES = frozenset(
    {
        "components",
        "assets",
        "trust-boundaries",
        "security-controls",
        "attack-surface-overrides",
        "mitigation-overrides",
        "tier-root-causes",
    }
)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = PLUGIN_ROOT / "data" / "sections-contract.yaml"
SCHEMAS_DIR = PLUGIN_ROOT / "schemas" / "fragments"
COMPOSE_PATH = PLUGIN_ROOT / "scripts" / "compose_threat_model.py"
VALIDATE_PATH = PLUGIN_ROOT / "scripts" / "validate_fragment.py"
QA_PATH = PLUGIN_ROOT / "scripts" / "qa_checks.py"


def _extract_dict_literal(source: str, name: str) -> dict:
    """Return the literal value of ``name = {...}`` from ``source`` via AST.

    Imports the module's text only; no Python execution side-effects.
    """
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [t for t in node.targets if isinstance(t, ast.Name) and t.id == name]
            if not targets:
                continue
            try:
                return ast.literal_eval(node.value)
            except (ValueError, SyntaxError) as exc:
                raise SystemExit(f"{name}: value is not a literal — refactor the linter or simplify the map ({exc})")
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name and node.value is not None:
                try:
                    return ast.literal_eval(node.value)
                except (ValueError, SyntaxError) as exc:
                    raise SystemExit(f"{name}: value is not a literal ({exc})")
    raise SystemExit(f"{name}: not found in {source[:50]!r}")


def _load_contract() -> dict:
    return yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))


def _contract_sections_by_fragment_type(contract: dict) -> tuple[dict, dict, dict, dict]:
    """Return four maps derived from sections-contract.yaml:

    - data_sections:     section_id -> { fragment, schema } where fragment_type=data|hybrid
    - markdown_sections: section_id -> fragment path where fragment_type=markdown
    - all_sections:      section_id -> dict (full sections[] entry)
    - section_order:     ordered list of (section_id, condition) from document.order
    """
    sections = contract.get("sections", {}) or {}
    data_sections: dict = {}
    markdown_sections: dict = {}
    for sid, sec in sections.items():
        if not isinstance(sec, dict):
            continue
        ftype = sec.get("fragment_type")
        if ftype in ("data", "hybrid"):
            data_sections[sid] = {"fragment": sec.get("fragment"), "schema": sec.get("schema")}
        elif ftype == "markdown":
            markdown_sections[sid] = sec.get("fragment")
    order = []
    for raw in contract.get("document", {}).get("order", []) or []:
        if isinstance(raw, str):
            order.append((raw, None))
        elif isinstance(raw, dict):
            order.append((raw.get("id"), raw.get("condition")))
    return data_sections, markdown_sections, sections, order


def _on_disk_schema_stems() -> set[str]:
    return {p.name for p in SCHEMAS_DIR.glob("*.schema.json")}


def check() -> list[str]:
    errors: list[str] = []
    contract = _load_contract()
    data_sections, md_sections, all_sections, _order = _contract_sections_by_fragment_type(contract)

    compose_src = COMPOSE_PATH.read_text(encoding="utf-8")
    validate_src = VALIDATE_PATH.read_text(encoding="utf-8")
    qa_src = QA_PATH.read_text(encoding="utf-8")

    section_fragment_map = _extract_dict_literal(compose_src, "_SECTION_FRAGMENT_MAP")
    known_json_schemas = _extract_dict_literal(compose_src, "_KNOWN_JSON_FRAGMENT_SCHEMAS")
    fragment_schemas = _extract_dict_literal(validate_src, "FRAGMENT_SCHEMAS")
    fragment_filenames = _extract_dict_literal(validate_src, "_FRAGMENT_FILENAMES")
    contract_section_fragments = _extract_dict_literal(qa_src, "CONTRACT_SECTION_FRAGMENTS")

    on_disk_schemas = _on_disk_schema_stems()

    # 1. schemas/fragments/*.schema.json ↔ FRAGMENT_SCHEMAS bidirectional
    declared_schemas = set(fragment_schemas.values())
    for schema_file in on_disk_schemas:
        if schema_file not in declared_schemas:
            errors.append(f"schemas/fragments/{schema_file} exists but is not in validate_fragment.FRAGMENT_SCHEMAS")
    for ftype, schema_file in fragment_schemas.items():
        if schema_file not in on_disk_schemas:
            errors.append(f"FRAGMENT_SCHEMAS[{ftype!r}] points to {schema_file}, not present in schemas/fragments/")

    # 2. FRAGMENT_SCHEMAS keys ↔ _FRAGMENT_FILENAMES keys
    #    Substep-2 sidecars (components, assets, …) intentionally appear ONLY in
    #    FRAGMENT_SCHEMAS — they share the JSON-Schema validator but are aggregator
    #    INPUTS (live at OUTPUT_DIR/.X.json), NOT render fragments, so they are
    #    deliberately kept out of _FRAGMENT_FILENAMES (see the design note in
    #    validate_fragment.py above the maps). Exempt them from this direction.
    schemas_keys = set(fragment_schemas)
    filenames_keys = set(fragment_filenames)
    for k in schemas_keys - filenames_keys - _SIDECAR_ONLY_TYPES:
        errors.append(f"validate_fragment.FRAGMENT_SCHEMAS has {k!r} but _FRAGMENT_FILENAMES does not")
    for k in filenames_keys - schemas_keys:
        errors.append(f"validate_fragment._FRAGMENT_FILENAMES has {k!r} but FRAGMENT_SCHEMAS does not")

    # 3. _KNOWN_JSON_FRAGMENT_SCHEMAS schema files ↔ on-disk schemas
    for fname, (_section_id, schema_file) in known_json_schemas.items():
        if schema_file not in on_disk_schemas:
            errors.append(
                f"compose._KNOWN_JSON_FRAGMENT_SCHEMAS[{fname!r}] -> {schema_file}, not present in schemas/fragments/"
            )

    # 4. _SECTION_FRAGMENT_MAP ↔ CONTRACT_SECTION_FRAGMENTS exact match for shared section_ids
    shared = set(section_fragment_map) & set(contract_section_fragments)
    for sid in shared:
        a = section_fragment_map[sid]
        b = contract_section_fragments[sid]
        if a != b:
            errors.append(f"_SECTION_FRAGMENT_MAP[{sid!r}]={a!r} but CONTRACT_SECTION_FRAGMENTS[{sid!r}]={b!r}")

    # 5. data/hybrid sections from the contract must be present in _SECTION_FRAGMENT_MAP and
    #    CONTRACT_SECTION_FRAGMENTS, and have a schema file on disk.
    for sid, decl in data_sections.items():
        if sid not in section_fragment_map:
            errors.append(f"contract section {sid!r} (data/hybrid) missing from _SECTION_FRAGMENT_MAP")
        if sid not in contract_section_fragments:
            errors.append(f"contract section {sid!r} (data/hybrid) missing from CONTRACT_SECTION_FRAGMENTS")
        schema_name = decl.get("schema")
        if schema_name and schema_name not in on_disk_schemas:
            errors.append(
                f"contract section {sid!r} declares schema {schema_name!r}, not present in schemas/fragments/"
            )

    # 6. Markdown sections from the contract should also have their fragment in
    #    _SECTION_FRAGMENT_MAP — but only when the contract actually has a fragment path.
    for sid in md_sections:
        if sid not in section_fragment_map and md_sections[sid]:
            errors.append(f"contract markdown section {sid!r} missing from _SECTION_FRAGMENT_MAP")

    return errors


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fragment-registry drift linter")
    p.add_argument("--quiet", action="store_true", help="Suppress success message")
    args = p.parse_args(argv)
    errors = check()
    if errors:
        print("Fragment-registry drift detected:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            f"\n{len(errors)} drift(s) found. See docs/internal/contracts/schema-invariants.md §4f "
            "and docs/internal/runbooks/adding-a-section.md for the canonical paths.",
            file=sys.stderr,
        )
        return 1
    if not args.quiet:
        print("Fragment registry is consistent across all 5 maps + schemas + contract.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
