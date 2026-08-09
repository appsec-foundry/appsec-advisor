#!/usr/bin/env python3
"""Finalize the component registry before trust-boundary assessment.

This command is the stage handoff between architecture discovery and every
consumer that uses component IDs. It validates and reconciles the inventory,
writes it atomically, and emits a deterministic fingerprint receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import jsonschema
from _atomic_io import atomic_write_json
from build_stride_dispatch_manifest import reconcile_inventory
from validate_fragment import repository_path_errors

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
COMPONENT_SCHEMA = PLUGIN_ROOT / "schemas" / "fragments" / "components.schema.json"
RECEIPT_SCHEMA = PLUGIN_ROOT / "schemas" / "component-inventory-finalization.schema.json"
FINGERPRINT_FIELDS = (
    "id",
    "name",
    "paths",
    "tier",
    "deployment_zones",
    "handles_sensitive_data",
)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read valid JSON from {path}: {exc}") from exc


def _validate(document: Any, schema_path: Path) -> None:
    schema = _load_json(schema_path)
    jsonschema.Draft202012Validator(schema).validate(document)


def component_inventory_fingerprint(components: list[dict[str, Any]]) -> str:
    """Fingerprint only fields that can change boundary endpoint semantics."""
    cards = [{key: row.get(key) for key in FINGERPRINT_FIELDS} for row in components]
    payload = json.dumps(cards, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def finalize(repo_root: Path, output_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    component_path = output_dir / ".components.json"
    document = _load_json(component_path)
    _validate(document, COMPONENT_SCHEMA)
    original = document["components"]
    path_errors = repository_path_errors("components", document, repo_root)
    if path_errors:
        raise ValueError("component repository path validation failed: " + "; ".join(path_errors))
    finalized, injected = reconcile_inventory(original, repo_root)
    payload = dict(document)
    payload["components"] = finalized
    _validate(payload, COMPONENT_SCHEMA)
    path_errors = repository_path_errors("components", payload, repo_root)
    if path_errors:
        raise ValueError("reconciled component path validation failed: " + "; ".join(path_errors))

    original_ids = [row.get("id") for row in original if isinstance(row, dict)]
    collapsed = max(0, len(original_ids) + len(injected) - len(finalized))
    receipt = {
        "schema_version": 1,
        "component_inventory_fingerprint": component_inventory_fingerprint(finalized),
        "component_ids": [row["id"] for row in finalized],
        "injected_component_ids": [row["id"] for row in injected],
        "collapsed_duplicate_count": collapsed,
    }
    _validate(receipt, RECEIPT_SCHEMA)
    atomic_write_json(component_path, payload, sort_keys=False)
    atomic_write_json(output_dir / ".component-inventory-finalization.json", receipt, sort_keys=False)
    return payload, receipt


def validate_receipt(output_dir: Path, repo_root: Path | None = None) -> dict[str, Any]:
    """Validate the receipt and ensure it still describes `.components.json`."""
    output_dir = output_dir.resolve()
    components = _load_json(output_dir / ".components.json")
    receipt = _load_json(output_dir / ".component-inventory-finalization.json")
    _validate(components, COMPONENT_SCHEMA)
    _validate(receipt, RECEIPT_SCHEMA)
    if repo_root is not None:
        path_errors = repository_path_errors("components", components, repo_root.resolve())
        if path_errors:
            raise ValueError("component repository path validation failed: " + "; ".join(path_errors))
    actual_ids = [row["id"] for row in components["components"]]
    actual_fp = component_inventory_fingerprint(components["components"])
    if receipt["component_ids"] != actual_ids:
        raise ValueError("component ID set/order changed after inventory finalization")
    if not set(receipt["injected_component_ids"]) <= set(actual_ids):
        raise ValueError("finalization receipt names an injected component that is not present")
    if receipt["component_inventory_fingerprint"] != actual_fp:
        raise ValueError("component inventory fingerprint changed after finalization")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            receipt = validate_receipt(args.output_dir, args.repo_root)
        else:
            _payload, receipt = finalize(args.repo_root, args.output_dir)
    except (ValueError, jsonschema.ValidationError) as exc:
        print(f"COMPONENT_FINALIZATION_FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        "COMPONENT_FINALIZATION_OK: "
        f"{len(receipt['component_ids'])} components "
        f"({len(receipt['injected_component_ids'])} injected, "
        f"{receipt['collapsed_duplicate_count']} duplicates collapsed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
