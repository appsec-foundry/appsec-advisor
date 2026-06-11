#!/usr/bin/env python3
"""slice_actors.py — Per-component actor slicing for the Actor Layer.

For each component identified by the orchestrator, produces a
.actors-for-<component-id>.json file listing which resolved actors
are relevant to that component.

Relevance heuristic (deterministic, no LLM):
  actor_relevant_to_component(actor, component) :=
      actor.access ∩ component.deployment_zones ≠ ∅
      OR actor.id ∈ COMPONENT_ALWAYS_RELEVANT[component.type]

COMPONENT_ALWAYS_RELEVANT is loaded from data/actors/default-library.yaml
and extended by org-profile/repo-layer component-relevance.yaml files.

CLI:
  python3 slice_actors.py \\
    --plugin-root /path/to/appsec-advisor \\
    --repo-root   /path/to/target-repo \\
    --output-dir  /path/to/output \\
    --components  '[{"component_id":"auth-service","component_type":"auth-service","deployment_zones":["internet","authenticated-user-session"]}]'
    [--org-profile-effective /path/to/.org-profile-effective.json]

Outputs:
  $OUTPUT_DIR/.actors-for-<component-id>.json  — per component
  $OUTPUT_DIR/.actors-slice-manifest.json      — summary of all slices + fingerprint
"""

import argparse
import hashlib
import json
import os
import sys

import yaml


def _load_yaml(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _load_json_str(s: str) -> list:
    return json.loads(s)


def _sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load_component_always_relevant(plugin_root: str) -> dict[str, list[str]]:
    """Load COMPONENT_ALWAYS_RELEVANT lookup from default-library.yaml.

    Returns a dict mapping component_type → list of actor labels (not IDs).
    IDs are resolved against the resolved actor set.
    """
    path = os.path.join(plugin_root, "data", "actors", "default-library.yaml")
    if not os.path.exists(path):
        return {}
    data = _load_yaml(path)
    raw = data.get("component_always_relevant", {})
    # Normalize: values can be lists of actor IDs or labels
    result = {}
    for comp_type, actor_refs in raw.items():
        result[comp_type] = [str(ref) for ref in (actor_refs or [])]
    return result


def actor_relevant(actor: dict, component: dict, always_relevant_ids: set[str]) -> tuple[bool, str]:
    """Return (relevant, rationale) for one actor-component pair."""
    actor_id = actor.get("id", "")
    actor_access = set(actor.get("access", []))
    comp_zones = set(component.get("deployment_zones", []))

    # Check COMPONENT_ALWAYS_RELEVANT
    if actor_id in always_relevant_ids:
        return True, f"actor.id in COMPONENT_ALWAYS_RELEVANT[{component.get('component_type')}]"

    # Check access ∩ deployment_zones
    intersection = actor_access & comp_zones
    if intersection:
        return True, f"actor.access {sorted(intersection)} ∩ component.deployment_zones"

    return False, ""


def slice_for_component(
    component: dict,
    resolved_actors: list[dict],
    always_relevant_map: dict[str, list[str]],
) -> dict:
    """Build the slice JSON for one component."""
    comp_type = component.get("component_type", "")
    always_relevant_ids = set(always_relevant_map.get(comp_type, []))

    relevant = []
    rationale_map = {}

    for actor in resolved_actors:
        if not actor.get("_provenance", {}).get("active", True):
            continue
        is_rel, reason = actor_relevant(actor, component, always_relevant_ids)
        if is_rel:
            relevant.append(actor)
            rationale_map[actor["id"]] = reason

    return {
        "schema_version": 1,
        "component_id": component.get("component_id"),
        "component_type": comp_type,
        "component_deployment_zones": component.get("deployment_zones", []),
        "relevant_actors": [
            {
                "id": a["id"],
                "label": a.get("label", ""),
                "access": a.get("access", []),
                "capabilities": a.get("capabilities", {}),
                "motivation": a.get("motivation", ""),
                "severity_modulation": a.get("severity_modulation", {}),
                "proposed": a.get("_provenance", {}).get("proposed", False),
                "stale": a.get("_provenance", {}).get("stale", False),
                "heatmap_slug": a.get("heatmap_slug", "internet-user"),
            }
            for a in relevant
        ],
        "relevance_rationale": rationale_map,
        "actor_count": len(relevant),
    }


def compute_fingerprint(slice_files: list[str]) -> str:
    content = ""
    for p in sorted(slice_files):
        if os.path.exists(p):
            with open(p) as f:
                content += f.read()
    return hashlib.sha256(content.encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Slice resolved actors per component")
    parser.add_argument("--plugin-root", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--components", required=True, help="JSON array of component dicts")
    parser.add_argument("--org-profile-effective")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Load resolved actors
    resolved_path = os.path.join(args.output_dir, ".actors-resolved.json")
    if not os.path.exists(resolved_path):
        print(f"[slice_actors] ERROR: .actors-resolved.json not found at {resolved_path}", file=sys.stderr)
        sys.exit(1)
    with open(resolved_path) as f:
        resolved_data = json.load(f)
    resolved_actors = resolved_data.get("resolved_actors", [])

    # Load component always-relevant map
    always_relevant_map = load_component_always_relevant(args.plugin_root)

    # TODO: extend with org-profile component-relevance.yaml if present

    # Parse components
    try:
        components = json.loads(args.components)
    except json.JSONDecodeError as e:
        print(f"[slice_actors] ERROR: invalid --components JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Produce slice files
    slice_files = []
    slice_summary = []

    for component in components:
        comp_id = component.get("component_id")
        if not comp_id:
            print(f"[slice_actors] WARNING: component missing component_id, skipping: {component}", file=sys.stderr)
            continue

        slice_data = slice_for_component(component, resolved_actors, always_relevant_map)
        out_path = os.path.join(args.output_dir, f".actors-for-{comp_id}.json")
        with open(out_path, "w") as f:
            json.dump(slice_data, f, indent=2)
        slice_files.append(out_path)
        slice_summary.append(
            {
                "component_id": comp_id,
                "component_type": component.get("component_type"),
                "actor_count": slice_data["actor_count"],
                "actor_ids": [a["id"] for a in slice_data["relevant_actors"]],
                "slice_path": out_path,
            }
        )
        print(f"[slice_actors]   {comp_id}: {slice_data['actor_count']} actors → {out_path}")

    # Write manifest
    manifest = {
        "schema_version": 1,
        "component_slices": slice_summary,
        "actors_input_fingerprint": _sha256_file(resolved_path),
        "slice_fingerprint": compute_fingerprint(slice_files),
    }
    manifest_path = os.path.join(args.output_dir, ".actors-slice-manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    print(f"[slice_actors] Done — {len(slice_summary)} component slices written")


if __name__ == "__main__":
    main()
