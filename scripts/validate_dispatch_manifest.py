#!/usr/bin/env python3
"""Hard gate for the Full-M1 STRIDE dispatch manifest.

Analyst-A writes ``$OUTPUT_DIR/.stride-dispatch-manifest.json`` at the Phase-8/9
boundary; the skill validates it with this script BEFORE fanning out the
parallel ``appsec-stride-analyzer`` dispatches. A malformed or incomplete
manifest would make the skill dispatch analyzers with missing parameters, so
this gate must pass before any dispatch.

Checks
------
1. JSON loads + validates against ``schemas/stride-dispatch-manifest.schema.yaml``.
2. Every component's ``index_paths`` value is either the literal ``"none"`` or
   an existing file (resolved relative to ``output_dir`` when not absolute).
3. No phantom components — every ``component_id`` in the manifest also exists in
   ``$OUTPUT_DIR/.components.json`` (when that file is present).
4. Coverage warning (non-fatal) — components present in ``.components.json`` but
   absent from the manifest are reported (they may be legit carry-forward /
   trivial stubs, so this is a warning, not a failure).

Exit codes
----------
0  Manifest valid (warnings allowed).
1  Manifest invalid — do NOT dispatch.
2  Usage / IO error (bad path, unreadable schema).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-dispatch-manifest.schema.yaml"

_INDEX_KEYS = (
    "prior_findings",
    "known_threats",
    "cross_repo",
    "requirements_violations",
    "relevant_actors",
)


def _load_schema() -> dict:
    import yaml  # local import: yaml is a runtime dep of the plugin scripts

    with SCHEMA_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _resolve(output_dir: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (output_dir / value)


def validate(manifest_path: Path, output_dir: Path) -> tuple[bool, list[str], list[str]]:
    """Return (ok, errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, [f"manifest not found: {manifest_path}"], []
    except (OSError, json.JSONDecodeError) as e:
        return False, [f"manifest unreadable / invalid JSON: {e}"], []

    # 1. Schema validation.
    try:
        from jsonschema import Draft202012Validator

        schema = _load_schema()
        for err in sorted(Draft202012Validator(schema).iter_errors(data), key=lambda e: list(e.path)):
            loc = "/".join(str(p) for p in err.path) or "<root>"
            errors.append(f"schema: {loc}: {err.message}")
    except ModuleNotFoundError:
        warnings.append("jsonschema not installed — skipped structural validation")
    except (OSError, ValueError) as e:
        return False, [f"schema load failed: {e}"], warnings

    if errors:  # structural errors make the semantic checks unreliable
        return False, errors, warnings

    components = data.get("components", [])

    # 2. index_paths existence.
    for comp in components:
        cid = comp.get("component_id", "<unknown>")
        idx = comp.get("index_paths", {})
        for key in _INDEX_KEYS:
            val = idx.get(key)
            if val is None or val == "none":
                continue
            if not _resolve(output_dir, val).is_file():
                errors.append(f"{cid}: index_paths.{key} points at a missing file: {val}")

    # 3 + 4. Component coverage vs .components.json.
    comp_json = output_dir / ".components.json"
    if comp_json.is_file():
        try:
            cj = json.loads(comp_json.read_text(encoding="utf-8"))
            known = cj.get("components", cj) if isinstance(cj, dict) else cj
            known_ids = {c.get("id") for c in known if isinstance(c, dict)}
            manifest_ids = {c.get("component_id") for c in components}
            for phantom in sorted(manifest_ids - known_ids):
                errors.append(f"phantom component not in .components.json: {phantom}")
            for missing in sorted(known_ids - manifest_ids):
                warnings.append(
                    f"component '{missing}' in .components.json is absent from the manifest "
                    "(ok if carry-forward / trivial stub; verify it is intentional)"
                )
        except (OSError, json.JSONDecodeError):
            warnings.append("could not read .components.json for coverage check")

    return (not errors), errors, warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="validate_dispatch_manifest.py")
    ap.add_argument("manifest", type=Path, help="path to .stride-dispatch-manifest.json")
    ap.add_argument("output_dir", type=Path, help="$OUTPUT_DIR (for path resolution + coverage)")
    ns = ap.parse_args(argv)

    if not SCHEMA_PATH.is_file():
        print(f"FATAL: schema missing at {SCHEMA_PATH}", file=sys.stderr)
        return 2

    ok, errors, warnings = validate(ns.manifest, ns.output_dir)
    for w in warnings:
        print(f"WARN  {w}", file=sys.stderr)
    for e in errors:
        print(f"ERROR {e}", file=sys.stderr)
    if ok:
        n = len(json.loads(ns.manifest.read_text(encoding="utf-8")).get("components", []))
        print(f"OK: dispatch manifest valid — {n} component(s) ready to fan out.")
        return 0
    print(f"INVALID: {len(errors)} error(s) — do NOT dispatch.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
