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


def load_access_zone_aliases(plugin_root: str) -> dict[str, str]:
    """Return alias → canonical access-zone mappings."""
    path = os.path.join(plugin_root, "data", "actors", "default-library.yaml")
    if not os.path.exists(path):
        return {}
    data = _load_yaml(path)
    result: dict[str, str] = {}
    for canonical, values in (data.get("access_zone_aliases") or {}).items():
        canonical_key = str(canonical).strip().lower()
        if not canonical_key:
            continue
        result[canonical_key] = canonical_key
        for value in values or []:
            alias = str(value).strip().lower()
            if alias:
                result[alias] = canonical_key
    return result


def _normalise_zones(values: object, aliases: dict[str, str]) -> set[str]:
    if not isinstance(values, list):
        return set()
    result: set[str] = set()
    for value in values:
        token = str(value).strip().lower()
        if token:
            result.add(aliases.get(token, token))
    return result


def _component_id(component: dict) -> str:
    return str(component.get("component_id") or component.get("id") or "")


def _component_type(component: dict) -> str:
    """Map the canonical `.components.json` shape to actor component roles."""
    explicit = component.get("component_type") or component.get("type")
    if explicit:
        return str(explicit)
    cid = _component_id(component)
    text = " ".join(str(component.get(key) or "") for key in ("component_id", "id", "name", "framework")).lower()
    if any(token in text for token in ("ci-cd", "cicd", "pipeline", "github-actions")):
        return "ci-cd-pipeline"
    if any(token in text for token in ("auth", "identity", "login", "session", "oauth", "jwt")):
        return "auth-service"
    if "admin" in text:
        return "admin-interface"
    if any(token in text for token in ("payment", "billing", "checkout")):
        return "payment-handler"
    if any(token in text for token in ("developer-workstation", "dev-workstation")):
        return "developer-workstation"
    return cid


def actor_relevant(
    actor: dict,
    component: dict,
    always_relevant_ids: set[str],
    access_aliases: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Return (relevant, rationale) for one actor-component pair."""
    aliases = access_aliases or {}
    actor_id = actor.get("id", "")
    actor_access = _normalise_zones(actor.get("access", []), aliases)
    comp_zones = _normalise_zones(component.get("deployment_zones", []), aliases)

    # Check COMPONENT_ALWAYS_RELEVANT
    if actor_id in always_relevant_ids:
        return True, f"actor.id in COMPONENT_ALWAYS_RELEVANT[{_component_type(component)}]"

    # Check access ∩ deployment_zones
    intersection = actor_access & comp_zones
    if intersection:
        return True, f"actor.access {sorted(intersection)} ∩ component.deployment_zones"

    return False, ""


def slice_for_component(
    component: dict,
    resolved_actors: list[dict],
    always_relevant_map: dict[str, list[str]],
    access_aliases: dict[str, str] | None = None,
) -> dict:
    """Build the slice JSON for one component."""
    comp_type = _component_type(component)
    always_relevant_ids = set(always_relevant_map.get(comp_type, []))

    relevant = []
    rationale_map = {}

    for actor in resolved_actors:
        if not actor.get("_provenance", {}).get("active", True):
            continue
        is_rel, reason = actor_relevant(actor, component, always_relevant_ids, access_aliases)
        if is_rel:
            relevant.append(actor)
            rationale_map[actor["id"]] = reason

    return {
        "schema_version": 1,
        "component_id": _component_id(component),
        "component_type": comp_type,
        "component_deployment_zones": component.get("deployment_zones", []),
        "relevant_actors": [
            {
                "id": a["id"],
                "label": a.get("label", ""),
                "access": a.get("access", []),
                "trust_positions": a.get("trust_positions", []),
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


def write_actor_slices(
    plugin_root: str,
    output_dir: str,
    components: list[dict],
    *,
    verbose: bool = False,
) -> dict:
    """Write per-component slices from the canonical component inventory."""
    resolved_path = os.path.join(output_dir, ".actors-resolved.json")
    if not os.path.exists(resolved_path):
        raise FileNotFoundError(f".actors-resolved.json not found at {resolved_path}")
    with open(resolved_path) as f:
        resolved_data = json.load(f)
    resolved_actors = resolved_data.get("resolved_actors", [])
    always_relevant_map = load_component_always_relevant(plugin_root)
    access_aliases = load_access_zone_aliases(plugin_root)

    slice_files: list[str] = []
    slice_summary: list[dict] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        comp_id = _component_id(component)
        if not comp_id:
            if verbose:
                print(f"[slice_actors] WARNING: component missing id: {component}", file=sys.stderr)
            continue
        slice_data = slice_for_component(component, resolved_actors, always_relevant_map, access_aliases)
        out_path = os.path.join(output_dir, f".actors-for-{comp_id}.json")
        with open(out_path, "w") as f:
            json.dump(slice_data, f, indent=2)
        slice_files.append(out_path)
        slice_summary.append(
            {
                "component_id": comp_id,
                "component_type": slice_data["component_type"],
                "actor_count": slice_data["actor_count"],
                "actor_ids": [a["id"] for a in slice_data["relevant_actors"]],
                "slice_path": out_path,
            }
        )
        if verbose:
            print(f"[slice_actors]   {comp_id}: {slice_data['actor_count']} actors → {out_path}")

    manifest = {
        "schema_version": 1,
        "component_slices": slice_summary,
        "actors_input_fingerprint": _sha256_file(resolved_path),
        "slice_fingerprint": compute_fingerprint(slice_files),
    }
    manifest_path = os.path.join(output_dir, ".actors-slice-manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    if verbose:
        print(f"[slice_actors] Done — {len(slice_summary)} component slices written")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Slice resolved actors per component")
    parser.add_argument("--plugin-root", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-dir", required=True)
    component_input = parser.add_mutually_exclusive_group(required=True)
    component_input.add_argument("--components", help="JSON array of component dicts")
    component_input.add_argument("--components-file", help="Canonical .components.json path")
    parser.add_argument("--org-profile-effective")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Parse components
    try:
        if args.components_file:
            with open(args.components_file) as f:
                component_doc = json.load(f)
            components = (
                component_doc.get("components", component_doc) if isinstance(component_doc, dict) else component_doc
            )
        else:
            components = json.loads(args.components)
        if not isinstance(components, list):
            raise ValueError("component input must contain a JSON array")
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"[slice_actors] ERROR: invalid component input: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        write_actor_slices(args.plugin_root, args.output_dir, components, verbose=True)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[slice_actors] ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
