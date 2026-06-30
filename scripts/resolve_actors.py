#!/usr/bin/env python3
"""resolve_actors.py — 4-layer actor resolver for the Actor Layer.

Layer order (additive merge, later layers override earlier):
  1. Plugin-Default-Library  (data/actors/default-library.yaml)
  2. Enterprise-Layer        (org-profile/<name>/actors/*.yaml  — from org-profile-effective.json)
  3. Repo-Layer              (<repo>/.appsec/actors.yaml)
  4. LLM-Discovery           (.actors-discovered.json  — proposed_additional only)

Outputs two files to OUTPUT_DIR:
  .actors-merged-static.json  — Plugin+Enterprise+Repo merged (input for discovery agent)
  .actors-resolved.json       — Full resolved set incl. discovery, with provenance

CLI:
  python3 resolve_actors.py \\
    --plugin-root /path/to/appsec-advisor \\
    --repo-root   /path/to/target-repo \\
    --output-dir  /path/to/output \\
    [--org-profile-effective /path/to/.org-profile-effective.json] \\
    [--discovery-output /path/to/.actors-discovered.json] \\
    [--signals /path/to/.recon-signals.json] \\
    [--quick]   (skip discovery layer, write .discovery-skipped.json)
"""

import argparse
import copy
import glob as glob_module
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

_DISCOVERY_SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "actors-discovered.schema.yaml"
_ACT_X_RE = re.compile(r"^ACT-X-[0-9]{1,4}$")

# ── helpers ─────────────────────────────────────────────────────────────────


def _load_yaml(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _deep_merge_actor(base: dict, override: dict) -> dict:
    """Field-level deep merge: override wins on scalar fields; lists are union-merged."""
    result = copy.deepcopy(base)
    for key, val in override.items():
        if key.startswith("_"):
            continue  # _provenance is managed separately
        if key in result and isinstance(result[key], list) and isinstance(val, list):
            # Union merge preserving order
            existing = set(str(x) for x in result[key])
            result[key] = result[key] + [x for x in val if str(x) not in existing]
        else:
            result[key] = copy.deepcopy(val)
    return result


def _activation_check(actor: dict, signals: dict) -> tuple[bool, str]:
    """Return (activate, reason) based on actor.activation_conditions and signals."""
    conditions = actor.get("activation_conditions", {})
    required = conditions.get("required_signals", [])
    logic = conditions.get("signal_logic", "all")

    if not required:
        return True, "always-active (no conditions defined)"

    if not signals:
        return True, "activate-with-warning (signals not available)"

    if logic == "any":
        met = [s for s in required if signals.get(s)]
        if met:
            return True, f"signal(s) met: {', '.join(met)}"
        return False, f"no signal from {required} is set"
    else:  # all
        unmet = [s for s in required if not signals.get(s)]
        if not unmet:
            return True, f"all required signals set: {', '.join(required)}"
        return False, f"signal(s) not set: {', '.join(unmet)}"


def _check_stale(actor: dict, repo_root: str) -> bool:
    """Return True when actor.evidence.pattern no longer matches any evidence.files."""
    evidence = actor.get("evidence")
    if not evidence:
        return False
    pattern = evidence.get("pattern", "")
    files = evidence.get("files", [])
    if not pattern or not files:
        return False
    for file_glob in files:
        full_glob = os.path.join(repo_root, file_glob)
        matched = glob_module.glob(full_glob, recursive=True)
        if not matched:
            continue
        try:
            result = subprocess.run(
                ["rg", "-l", "--pcre2", pattern] + matched, capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                return False  # pattern still matches
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False  # can't verify — assume not stale
    return True  # pattern matched no file


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _parse_disables(raw: list) -> list[dict]:
    """Normalize disable list: accept str IDs or {id, reason} objects (actors.md §3/§6/§7)."""
    out: list[dict] = []
    for item in raw or []:
        if isinstance(item, str):
            out.append({"id": item, "reason": None})
        elif isinstance(item, dict) and "id" in item:
            out.append({"id": item["id"], "reason": item.get("reason")})
    return out


def _validate_discovery_output(data: object) -> list[str]:
    """Return schema errors for an LLM-authored actor-discovery document."""
    try:
        schema = yaml.safe_load(_DISCOVERY_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        return [f"could not load discovery schema: {e}"]
    errors = sorted(Draft202012Validator(schema).iter_errors(data), key=lambda e: list(e.absolute_path))
    rendered: list[str] = []
    for error in errors:
        path = ".".join(str(part) for part in error.absolute_path) or "root"
        rendered.append(f"{path}: {error.message}")
    return rendered


def _access_alias_map(plugin_root: str) -> dict[str, str]:
    """Load alias → canonical access-zone mappings from the actor library."""
    path = os.path.join(plugin_root, "data", "actors", "default-library.yaml")
    if not os.path.exists(path):
        return {}
    data = _load_yaml(path)
    aliases: dict[str, str] = {}
    for canonical, values in (data.get("access_zone_aliases") or {}).items():
        canonical_key = str(canonical).strip().lower()
        if not canonical_key:
            continue
        aliases[canonical_key] = canonical_key
        for value in values or []:
            alias = str(value).strip().lower()
            if alias:
                aliases[alias] = canonical_key
    return aliases


def _trust_position_alias_map(plugin_root: str) -> dict[str, str]:
    """Load trust-position alias → canonical mappings from the actor library."""
    path = os.path.join(plugin_root, "data", "actors", "default-library.yaml")
    if not os.path.exists(path):
        return {}
    data = _load_yaml(path)
    aliases: dict[str, str] = {}
    for canonical, values in (data.get("trust_position_aliases") or {}).items():
        canonical_key = str(canonical).strip().lower()
        if not canonical_key:
            continue
        aliases[canonical_key] = canonical_key
        for value in values or []:
            alias = str(value).strip().lower()
            if alias:
                aliases[alias] = canonical_key
    return aliases


def _normalise_access(values: object, aliases: dict[str, str]) -> set[str]:
    if not isinstance(values, list):
        return set()
    normalised: set[str] = set()
    for value in values:
        token = str(value).strip().lower()
        if token:
            normalised.add(aliases.get(token, token))
    return normalised


def _normalise_trust_positions(
    values: object,
    aliases: dict[str, str] | None = None,
) -> set[str]:
    if not isinstance(values, list):
        return set()
    alias_map = aliases or {}
    return {
        alias_map.get(str(value).strip().lower(), str(value).strip().lower()) for value in values if str(value).strip()
    }


def _discovery_rejection_reason(
    proposed: dict,
    static_catalog: list[dict],
    aliases: dict[str, str],
    trust_aliases: dict[str, str] | None = None,
) -> tuple[str | None, str | None]:
    """Reject discovery actors that do not add a distinct trust position.

    Returns ``(reason, covered_by)``. ``reason is None`` means the proposal
    passes the deterministic admission gate.
    """
    aid = str(proposed.get("id") or "")
    if not _ACT_X_RE.fullmatch(aid):
        return "id must use the ACT-X-N discovery namespace", None
    if proposed.get("confidence") != "high":
        return "confidence must be high before a discovery actor can affect attribution", None

    access = _normalise_access(proposed.get("access"), aliases)
    trust_positions = _normalise_trust_positions(proposed.get("trust_positions"), trust_aliases)
    distinct = _normalise_trust_positions(proposed.get("distinct_trust_positions"), trust_aliases)
    if not distinct:
        return "distinct_trust_positions must identify a new trust position", None
    if not distinct.issubset(trust_positions):
        return "distinct_trust_positions must be a subset of trust_positions", None

    static_positions_union: set[str] = set()
    for actor in static_catalog:
        known = _normalise_access(actor.get("access"), aliases)
        known_positions = _normalise_trust_positions(actor.get("trust_positions"), trust_aliases)
        static_positions_union.update(known_positions)
        if trust_positions and trust_positions.issubset(known_positions) and (not access or access.issubset(known)):
            return "trust position is already covered by a static actor", str(actor.get("id") or "")

    if not (distinct - static_positions_union):
        return "distinct_trust_positions contains only positions already present in static actors", None

    return None, None


def _default_heatmap_slug(actor: dict) -> str:
    """Choose a stable display class for an admitted discovery actor."""
    access = {str(value).strip().lower() for value in actor.get("access", [])}
    trust_positions = _normalise_trust_positions(actor.get("trust_positions"))
    if access & {"build-pipeline", "ci-cd-runtime", "ci-cd-secrets", "deployment-pipeline"}:
        return "build-time"
    if access & {"local-fs", "internal-network", "staging-env", "prod-env"}:
        return "repo-read"
    if access & {"client-device", "mobile-device"}:
        return "victim-required"
    if any("privileged" in value or "admin" in value for value in trust_positions):
        return "internet-priv-user"
    if any(value.endswith(("credential", "authority", "membership")) for value in trust_positions):
        return "internet-user"
    if access == {"internet"}:
        return "internet-anon"
    return "internet-user"


def _compute_actors_inputs_fingerprint(plugin_root: str, profile_dir: str, add_glob: str, repo_root: str) -> str:
    """SHA256 over all actor input files for incremental cache invalidation (actors.md §13)."""
    parts: list[str] = []
    p = os.path.join(plugin_root, "data", "actors", "default-library.yaml")
    if os.path.exists(p):
        with open(p, "rb") as f:
            parts.append(f"plugin:{hashlib.sha256(f.read()).hexdigest()}")
    if profile_dir and add_glob:
        for fp in sorted(glob_module.glob(os.path.join(profile_dir, add_glob))):
            with open(fp, "rb") as f:
                rel = os.path.relpath(fp, profile_dir)
                parts.append(f"ent:{rel}:{hashlib.sha256(f.read()).hexdigest()}")
    rp = os.path.join(repo_root, ".appsec", "actors.yaml")
    if os.path.exists(rp):
        with open(rp, "rb") as f:
            parts.append(f"repo:{hashlib.sha256(f.read()).hexdigest()}")
    return hashlib.sha256("||".join(parts).encode()).hexdigest()


# ── layer loading ────────────────────────────────────────────────────────────


def load_plugin_defaults(plugin_root: str) -> list[dict]:
    path = os.path.join(plugin_root, "data", "actors", "default-library.yaml")
    if not os.path.exists(path):
        print(f"[resolve_actors] WARNING: default-library.yaml not found at {path}", file=sys.stderr)
        return []
    data = _load_yaml(path)
    actors = data.get("actors", [])
    for a in actors:
        a.setdefault("_provenance", {})
        a["_provenance"]["layer"] = "plugin"
        a["_provenance"]["source_file"] = "data/actors/default-library.yaml"
    return actors


def load_enterprise_actors(org_profile_effective: dict, profile_dir: str) -> tuple[list[dict], list[dict], bool, str]:
    """Returns (actors, disables, inherit_defaults, add_glob).

    disables is a list of {id, reason} dicts (actors.md §6 — disable_reason is required for audit).
    add_glob is exposed so the caller can compute actors_inputs_fingerprint over the same file set.
    """
    actors_config = org_profile_effective.get("actors", {})
    inherit = actors_config.get("inherit_defaults", True)
    disables = _parse_disables(actors_config.get("disable", []))
    add_glob = actors_config.get("add", "actors/*.yaml")

    actors = []
    if add_glob and profile_dir:
        full_glob = os.path.join(profile_dir, add_glob)
        for fpath in sorted(glob_module.glob(full_glob)):
            try:
                data = _load_yaml(fpath)
                file_actors = data.get("actors", [])
                for a in file_actors:
                    a.setdefault("_provenance", {})
                    a["_provenance"]["layer"] = "enterprise"
                    a["_provenance"]["source_file"] = os.path.relpath(fpath, profile_dir)
                actors.extend(file_actors)
            except Exception as e:
                print(f"[resolve_actors] WARNING: could not load {fpath}: {e}", file=sys.stderr)

    return actors, disables, inherit, add_glob


def load_repo_actors(
    repo_root: str,
) -> tuple[list[dict], list[dict], dict, bool]:
    """Returns (actors, disables, discovery_config, inherit_org) from .appsec/actors.yaml.

    disables is a list of {id, reason} dicts (actors.md §7).
    inherit_org defaults to True per actors.md §7 example.
    Actors with `renamed_from` get `_provenance.aliases` populated for downstream re-tagging
    (actors.md §3 Promotion-ID-Stabilität).
    """
    path = os.path.join(repo_root, ".appsec", "actors.yaml")
    if not os.path.exists(path):
        return [], [], {"enabled": True, "max_proposed": 5}, True

    data = _load_yaml(path)
    actors = data.get("actors", [])
    for a in actors:
        a.setdefault("_provenance", {})
        a["_provenance"]["layer"] = "repo"
        a["_provenance"]["source_file"] = ".appsec/actors.yaml"
        rf = a.get("renamed_from")
        if rf:
            aliases = rf if isinstance(rf, list) else [rf]
            a["_provenance"]["aliases"] = aliases

    disables = _parse_disables(data.get("disable", []))
    discovery_config = data.get("discovery", {"enabled": True, "max_proposed": 5})
    inherit_org = data.get("inherit_org", True)
    return actors, disables, discovery_config, inherit_org


# ── reach-equivalence ────────────────────────────────────────────────────────


def apply_reach_equivalence(resolved_map: dict, signals: dict, plugin_root: str) -> dict:
    """Apply reach-equivalence collapse rules from default-library.yaml."""
    lib_path = os.path.join(plugin_root, "data", "actors", "default-library.yaml")
    if not os.path.exists(lib_path):
        return resolved_map
    data = _load_yaml(lib_path)
    rules = data.get("reach_equivalence_rules", [])

    for rule in rules:
        sig = rule.get("condition_signal")
        if not signals.get(sig):
            continue
        ids = rule.get("actor_ids", [])
        if not all(i in resolved_map for i in ids):
            continue
        collapse_reason = rule.get("collapse_reason", sig)
        primary = rule.get("primary_actor", ids[0])
        note = rule.get("note", "")
        for actor_id in ids:
            resolved_map[actor_id]["equivalent_to"] = ids
            resolved_map[actor_id]["collapse_reason"] = collapse_reason
            resolved_map[actor_id]["collapse_primary"] = primary
            if note:
                resolved_map[actor_id]["_provenance"]["collapse_note"] = note

    return resolved_map


# ── main resolver ────────────────────────────────────────────────────────────


def resolve(
    plugin_root: str,
    repo_root: str,
    output_dir: str,
    org_profile_effective_path: str | None = None,
    discovery_output_path: str | None = None,
    signals_path: str | None = None,
    quick_mode: bool = False,
) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # Load signals
    signals: dict = {}
    if signals_path and os.path.exists(signals_path):
        try:
            signals = _load_json(signals_path).get("signals", {})
        except Exception as e:
            print(f"[resolve_actors] WARNING: could not load signals: {e}", file=sys.stderr)

    # Load org-profile
    org_profile: dict = {}
    profile_dir: str = ""
    if org_profile_effective_path and os.path.exists(org_profile_effective_path):
        try:
            org_profile = _load_json(org_profile_effective_path)
            profile_dir = os.path.dirname(org_profile_effective_path)
        except Exception as e:
            print(f"[resolve_actors] WARNING: could not load org-profile: {e}", file=sys.stderr)

    # --- Layer 1: Plugin defaults ---
    plugin_actors = load_plugin_defaults(plugin_root)

    # --- Layer 2: Enterprise ---
    ent_actors, ent_disable, ent_inherit, ent_add_glob = load_enterprise_actors(org_profile, profile_dir)

    # --- Layer 3: Repo ---
    repo_actors, repo_disable, discovery_config, repo_inherit_org = load_repo_actors(repo_root)

    # --- run-issues accumulator (used by activation + disable + fingerprint passes) ---
    run_issues: list[dict] = []

    # --- Merge: build ID-keyed map ---
    resolved_map: dict[str, dict] = {}

    if ent_inherit:
        for a in plugin_actors:
            resolved_map[a["id"]] = copy.deepcopy(a)

    if repo_inherit_org:
        for a in ent_actors:
            aid = a["id"]
            if aid in resolved_map:
                resolved_map[aid] = _deep_merge_actor(resolved_map[aid], a)
                resolved_map[aid]["_provenance"]["modified_by"] = resolved_map[aid]["_provenance"].get(
                    "modified_by", []
                ) + ["enterprise"]
            else:
                resolved_map[aid] = copy.deepcopy(a)
    elif ent_actors:
        run_issues.append(
            {
                "class": "repo_inherit_org_disabled",
                "severity": "info",
                "message": f"Repo set inherit_org: false — {len(ent_actors)} enterprise actor(s) excluded from this run.",
            }
        )

    for a in repo_actors:
        aid = a["id"]
        if aid in resolved_map:
            resolved_map[aid] = _deep_merge_actor(resolved_map[aid], a)
            resolved_map[aid]["_provenance"]["modified_by"] = resolved_map[aid]["_provenance"].get(
                "modified_by", []
            ) + ["repo"]
        else:
            resolved_map[aid] = copy.deepcopy(a)

    # --- Build alias map from renamed_from on repo actors (actors.md §3) ---
    alias_map: dict[str, str] = {}
    for a in repo_actors:
        for old_id in a.get("_provenance", {}).get("aliases", []):
            alias_map[old_id] = a["id"]

    # --- Apply disables (enterprise → terminal, repo → advisory) ---
    # disable_reason is required for audit (actors.md §6/§7).
    all_disables: list[dict] = []
    for d in ent_disable:
        did, reason = d["id"], d["reason"]
        if did in resolved_map:
            resolved_map[did]["_provenance"]["disabled_by"] = "enterprise"
            resolved_map[did]["_provenance"]["disable_reason"] = reason
            all_disables.append({"id": did, "by": "enterprise", "reason": reason})
            if not reason:
                run_issues.append(
                    {
                        "class": "disabled_actor_no_rationale",
                        "actor_id": did,
                        "severity": "defect",
                        "message": f"Enterprise disabled actor {did} without disable_reason (actors.md §6).",
                    }
                )
    for d in repo_disable:
        did, reason = d["id"], d["reason"]
        if did in resolved_map:
            if resolved_map[did]["_provenance"].get("disabled_by") == "enterprise":
                print(
                    f"[resolve_actors] WARNING: repo cannot re-enable enterprise-disabled actor {did}", file=sys.stderr
                )
                continue
            resolved_map[did]["_provenance"]["disabled_by"] = "repo"
            resolved_map[did]["_provenance"]["disable_reason"] = reason
            all_disables.append({"id": did, "by": "repo", "reason": reason})
            if not reason:
                run_issues.append(
                    {
                        "class": "disabled_actor_no_rationale",
                        "actor_id": did,
                        "severity": "defect",
                        "message": f"Repo disabled actor {did} without disable_reason (actors.md §7).",
                    }
                )

    # --- Apply activation conditions ---
    for aid, actor in resolved_map.items():
        if actor["_provenance"].get("disabled_by"):
            actor["_provenance"]["active"] = False
            continue
        active, reason = _activation_check(actor, signals)
        actor["_provenance"]["active"] = active
        actor["_provenance"]["activation_reason"] = reason
        if not active:
            # actors.md §0 Done-#1: skipped default-library actors must be visible in the audit
            # ("Kein Actor verschwindet stillschweigend").
            if actor["_provenance"].get("layer") == "plugin":
                run_issues.append(
                    {
                        "class": "default_actor_skipped",
                        "actor_id": aid,
                        "severity": "info",
                        "message": f"Default actor {aid} not activated — {reason}",
                    }
                )
            continue
        if "signals not available" in reason:
            actor["_provenance"]["signal_status"] = "activate-with-warning"
            run_issues.append(
                {
                    "class": "actor_signal_missing",
                    "actor_id": aid,
                    "severity": "info",
                    "message": f"Actor {aid} activated without signal verification — {reason}",
                }
            )
        else:
            actor["_provenance"]["signal_status"] = "normal"

    # --- Stale detection ---
    for aid, actor in resolved_map.items():
        if not actor["_provenance"].get("active"):
            continue
        if _check_stale(actor, repo_root):
            actor["_provenance"]["stale"] = True
            run_issues.append(
                {
                    "class": "stale_actor_evidence",
                    "actor_id": aid,
                    "severity": "advisory",
                    "message": f"Actor {aid} evidence pattern no longer matches — may be outdated",
                }
            )

    # --- Reach-equivalence ---
    resolved_map = apply_reach_equivalence(resolved_map, signals, plugin_root)

    # --- Compute actors_inputs_fingerprint (actors.md §13) ---
    actors_inputs_fingerprint = _compute_actors_inputs_fingerprint(plugin_root, profile_dir, ent_add_glob, repo_root)
    with open(os.path.join(output_dir, ".actor-fingerprints.json"), "w") as f:
        json.dump(
            {
                "schema_version": 1,
                "actors_inputs_fingerprint": actors_inputs_fingerprint,
            },
            f,
            indent=2,
        )

    # --- Write .actors-merged-static.json (input for discovery agent) ---
    merged_static = {
        "schema_version": 1,
        "actors_inputs_fingerprint": actors_inputs_fingerprint,
        "catalog_actors": list(resolved_map.values()),
        "resolved_actors": [a for a in resolved_map.values() if a["_provenance"].get("active")],
        "disabled_actors": [
            {
                "id": aid,
                "disabled_by": a["_provenance"]["disabled_by"],
                "disable_reason": a["_provenance"].get("disable_reason"),
            }
            for aid, a in resolved_map.items()
            if a["_provenance"].get("disabled_by")
        ],
    }
    merged_static_path = os.path.join(output_dir, ".actors-merged-static.json")
    with open(merged_static_path, "w") as f:
        json.dump(merged_static, f, indent=2)
    print(
        f"[resolve_actors] .actors-merged-static.json written ({len(merged_static['resolved_actors'])} active actors)"
    )

    # --- Quick-mode: skip discovery, write sentinel ---
    if quick_mode or not discovery_config.get("enabled", True):
        sentinel = {"reason": "quick-mode", "discovery_skipped": True}
        with open(os.path.join(output_dir, ".discovery-skipped.json"), "w") as f:
            json.dump(sentinel, f, indent=2)
        print("[resolve_actors] Quick-mode: discovery skipped — .discovery-skipped.json written")
        discovery_actors: list[dict] = []
    else:
        # --- Layer 4: LLM-Discovery ---
        discovery_actors = []
        rejected_discovery_actors: list[dict] = []
        if discovery_output_path and os.path.exists(discovery_output_path):
            try:
                disc = _load_json(discovery_output_path)
                validation_errors = _validate_discovery_output(disc)
                if validation_errors:
                    message = "; ".join(validation_errors[:3])
                    rejected_discovery_actors.append({"id": None, "reason": f"invalid discovery output: {message}"})
                    run_issues.append(
                        {
                            "class": "invalid_actor_discovery_output",
                            "severity": "defect",
                            "message": f"Actor discovery output rejected by schema: {message}",
                        }
                    )
                else:
                    max_proposed = min(int(discovery_config.get("max_proposed", 5)), 5)
                    static_catalog = list(resolved_map.values())
                    aliases = _access_alias_map(plugin_root)
                    trust_aliases = _trust_position_alias_map(plugin_root)
                    for proposed in disc.get("proposed_additional", [])[:max_proposed]:
                        aid = proposed["id"]
                        if aid in resolved_map:
                            rejected_discovery_actors.append(
                                {"id": aid, "reason": "actor ID already exists in a static layer", "covered_by": aid}
                            )
                            continue
                        reason, covered_by = _discovery_rejection_reason(
                            proposed,
                            static_catalog,
                            aliases,
                            trust_aliases,
                        )
                        if reason:
                            rejected = {"id": aid, "reason": reason}
                            if covered_by:
                                rejected["covered_by"] = covered_by
                            rejected_discovery_actors.append(rejected)
                            run_issues.append(
                                {
                                    "class": "discovery_actor_rejected",
                                    "actor_id": aid,
                                    "severity": "info",
                                    "covered_by": covered_by,
                                    "message": f"Discovery actor {aid} rejected — {reason}",
                                }
                            )
                            continue
                        proposed = copy.deepcopy(proposed)
                        proposed.setdefault("heatmap_slug", _default_heatmap_slug(proposed))
                        proposed.setdefault("_provenance", {})
                        proposed["_provenance"]["layer"] = "discovery"
                        proposed["_provenance"]["proposed"] = True
                        proposed["_provenance"]["active"] = True
                        resolved_map[aid] = proposed
                        discovery_actors.append(proposed)
            except Exception as e:
                print(f"[resolve_actors] WARNING: could not load discovery output: {e}", file=sys.stderr)
                rejected_discovery_actors.append({"id": None, "reason": f"could not load discovery output: {e}"})
                run_issues.append(
                    {
                        "class": "invalid_actor_discovery_output",
                        "severity": "defect",
                        "message": f"Actor discovery output could not be loaded: {e}",
                    }
                )

    if quick_mode or not discovery_config.get("enabled", True):
        rejected_discovery_actors = []

    # --- Write .actors-resolved.json ---
    resolved_out = {
        "schema_version": 1,
        "quick_mode": quick_mode,
        "actors_inputs_fingerprint": actors_inputs_fingerprint,
        "alias_map": alias_map,
        "resolved_actors": list(resolved_map.values()),
        "run_issues": run_issues,
        "discovery_actor_count": len(discovery_actors),
        "rejected_discovery_actors": rejected_discovery_actors,
    }
    resolved_path = os.path.join(output_dir, ".actors-resolved.json")
    with open(resolved_path, "w") as f:
        json.dump(resolved_out, f, indent=2)

    active_count = sum(1 for a in resolved_map.values() if a["_provenance"].get("active"))
    print(
        f"[resolve_actors] .actors-resolved.json written ({active_count} active, {len(discovery_actors)} from discovery, {len(run_issues)} run-issues)"
    )


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Resolve Actor Layer (4-layer merge)")
    parser.add_argument("--plugin-root", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--org-profile-effective")
    parser.add_argument("--discovery-output")
    parser.add_argument("--signals")
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    resolve(
        plugin_root=args.plugin_root,
        repo_root=args.repo_root,
        output_dir=args.output_dir,
        org_profile_effective_path=args.org_profile_effective,
        discovery_output_path=args.discovery_output,
        signals_path=args.signals,
        quick_mode=args.quick,
    )


if __name__ == "__main__":
    main()
