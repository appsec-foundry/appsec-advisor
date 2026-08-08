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

sys.path.insert(0, str(Path(__file__).resolve().parent))

from build_stride_evidence_bundles import (  # noqa: E402
    BundleError,
    architecture_context_projection,
    business_context_projection,
    load_repository_registry,
    validate_architecture_context_bytes,
    validate_bundle,
    validate_business_context_bytes,
)

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "stride-dispatch-manifest.schema.yaml"

_INDEX_KEYS = (
    "prior_findings",
    "known_threats",
    "cross_repo",
    "requirements_violations",
    "relevant_actors",
    "trust_boundaries",
)


def _load_schema() -> dict:
    import yaml  # local import: yaml is a runtime dep of the plugin scripts

    with SCHEMA_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _resolve(output_dir: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (output_dir / value)


def _resolve_contained(output_dir: Path, value: str) -> Path:
    output_dir = output_dir.resolve()
    candidate = Path(value)
    if "\\" in value or any(part == ".." for part in candidate.parts):
        raise ValueError(f"unsafe path: {value}")
    resolved = candidate.resolve() if candidate.is_absolute() else (output_dir / candidate).resolve()
    resolved.relative_to(output_dir)
    return resolved


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
    context_v2 = data.get("context_version") == 2
    try:
        from jsonschema import Draft202012Validator

        schema = _load_schema()
        for err in sorted(Draft202012Validator(schema).iter_errors(data), key=lambda e: list(e.path)):
            loc = "/".join(str(p) for p in err.path) or "<root>"
            errors.append(f"schema: {loc}: {err.message}")
    except ModuleNotFoundError:
        if context_v2:
            return False, ["jsonschema not installed — context-v2 validation fails closed"], warnings
        warnings.append("jsonschema not installed — skipped structural validation")
    except (OSError, ValueError) as e:
        return False, [f"schema load failed: {e}"], warnings

    if errors:  # structural errors make the semantic checks unreliable
        return False, errors, warnings

    components = data.get("components", [])

    # 2. index_paths existence.
    seen_component_ids: set[str] = set()
    for comp in components:
        cid = comp.get("component_id", "<unknown>")
        if context_v2:
            if cid in seen_component_ids:
                errors.append(f"duplicate component_id in context-v2 manifest: {cid}")
            seen_component_ids.add(cid)
        idx = comp.get("index_paths", {})
        for key in _INDEX_KEYS:
            val = idx.get(key)
            if val is None or val == "none":
                continue
            try:
                path = _resolve_contained(output_dir, val) if context_v2 else _resolve(output_dir, val)
            except ValueError:
                errors.append(f"{cid}: index_paths.{key} escapes output_dir: {val}")
                continue
            if not path.is_file():
                errors.append(f"{cid}: index_paths.{key} points at a missing file: {val}")

    if context_v2 and not errors:
        cfg_path = output_dir / ".skill-config.json"
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            repo_root = Path(cfg["repo_root"])
        except (OSError, json.JSONDecodeError, KeyError, TypeError):
            errors.append("context-v2 requires .skill-config.json with repo_root")
        else:
            registry_path = output_dir / ".stride-repository-registry.json"
            try:
                analyst_context: dict = {}
                if any(
                    component.get("business_context_path") is not None
                    or component.get("architecture_context_path") is not None
                    for component in components
                ):
                    analyst_context_path = output_dir / ".stride-analyst-context.json"
                    analyst_context = json.loads(analyst_context_path.read_text(encoding="utf-8"))
                    if not isinstance(analyst_context, dict):
                        raise BundleError("stride-analyst-context-v1 must be an object")
                registry = load_repository_registry(
                    repo_root,
                    registry_path if registry_path.is_file() else None,
                )
                for comp in components:
                    cid = comp["component_id"]
                    expected = f".dispatch-context/{cid}/evidence-bundle.json"
                    bundle_value = comp["evidence_bundle_path"]
                    if bundle_value != expected:
                        raise BundleError(f"evidence bundle path for {cid} must be {expected}, got {bundle_value}")
                    bundle_path = _resolve_contained(output_dir, bundle_value)
                    bundle = validate_bundle(
                        bundle_path,
                        registry,
                        expected_component_id=cid,
                        expected_sha256=comp["evidence_bundle_sha256"],
                        expected_focus_paths=comp.get("focus_paths", []),
                        expected_exclude_paths=comp.get("exclude_paths", []),
                        output_dir=output_dir,
                    )
                    if bundle["limits"]["estimated_tokens"] != comp["evidence_bundle_estimated_tokens"]:
                        raise BundleError(f"evidence-bundle token estimate is stale for {cid}")
                    business_value = comp.get("business_context_path")
                    if business_value is not None:
                        expected_business = f".dispatch-context/{cid}/business-context.json"
                        if business_value != expected_business:
                            raise BundleError(
                                f"business-context path for {cid} must be {expected_business}, got {business_value}"
                            )
                        business_path = _resolve_contained(output_dir, business_value)
                        try:
                            business_payload = business_path.read_bytes()
                        except OSError as exc:
                            raise BundleError(f"business-context projection is unreadable for {cid}: {exc}") from exc
                        projection = validate_business_context_bytes(
                            business_payload,
                            expected_component_id=cid,
                            expected_sha256=comp["business_context_sha256"],
                        )
                        overlay = analyst_context.get(cid)
                        source_value = overlay.get("business_context") if isinstance(overlay, dict) else None
                        current_projection = business_context_projection(source_value, cid)
                        if current_projection != projection:
                            raise BundleError(f"business-context projection is stale for {cid}")
                        estimated_tokens = (len(business_payload) + 3) // 4
                        if estimated_tokens != comp["business_context_estimated_tokens"]:
                            raise BundleError(f"business-context token estimate is stale for {cid}")
                    architecture_value = comp.get("architecture_context_path")
                    if architecture_value is not None:
                        expected_architecture = f".dispatch-context/{cid}/architecture-context.json"
                        if architecture_value != expected_architecture:
                            raise BundleError(
                                f"architecture-context path for {cid} must be {expected_architecture}, "
                                f"got {architecture_value}"
                            )
                        architecture_path = _resolve_contained(output_dir, architecture_value)
                        try:
                            architecture_payload = architecture_path.read_bytes()
                        except OSError as exc:
                            raise BundleError(
                                f"architecture-context projection is unreadable for {cid}: {exc}"
                            ) from exc
                        projection = validate_architecture_context_bytes(
                            architecture_payload,
                            expected_component_id=cid,
                            expected_sha256=comp["architecture_context_sha256"],
                        )
                        overlay = analyst_context.get(cid)
                        source_value = overlay.get("architecture_context") if isinstance(overlay, dict) else None
                        current_projection = architecture_context_projection(source_value, cid)
                        if current_projection != projection:
                            raise BundleError(f"architecture-context projection is stale for {cid}")
                        estimated_tokens = (len(architecture_payload) + 3) // 4
                        if estimated_tokens != comp["architecture_context_estimated_tokens"]:
                            raise BundleError(f"architecture-context token estimate is stale for {cid}")
            except (BundleError, OSError, json.JSONDecodeError, ValueError) as exc:
                errors.append(f"context-v2 evidence validation failed: {exc}")

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
