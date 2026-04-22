#!/usr/bin/env python3
"""Pre-filter taxonomy files to component-relevant CWE groups.

Writes sliced YAML files to $OUTPUT_DIR/.taxonomy-slices/<component-id>/.
Each STRIDE analyzer reads from its slice dir instead of the full data dir,
reducing per-analyzer input tokens by 20-30% for non-generic components.

Usage:
    slice_taxonomy.py <component-type> <output-dir>
                      [--component-id <id>]
                      [--data-dir <dir>]
                      [--taxonomies cwe,threats,controls,chains]

Exit codes:
    0 — slice written (possibly passthrough for unknown component type)
    1 — component type unrecognised — full passthrough slice written
    2 — IO error
"""

import argparse
import copy
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed — run: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Component-type keyword → relevant TH-IDs + CWE-IDs
# ---------------------------------------------------------------------------

# Each entry: list of (keywords, th_ids, cwe_ids)
# keywords  — matched against component_type (lower) and component_id (lower)
# th_ids    — TH categories to include (others are stripped)
# cwe_ids   — CWEs to include from cwe-taxonomy.yaml (superset: includes all
#             CWEs whose cwe_to_th maps to any included TH, plus the listed extras)
#
# "passthrough" means keep all — used as safe default for unknown types.

COMPONENT_PROFILES = [
    {
        "name": "frontend",
        "keywords": ["frontend", "spa", "web-app", "webclient", "browser", "react",
                     "angular", "vue", "svelte", "next", "nuxt", "client"],
        "th_ids": ["TH-01", "TH-02", "TH-04", "TH-06", "TH-10", "TH-11",
                   "TH-12", "TH-13", "TH-15", "TH-17", "TH-18"],
        "extra_cwes": ["CWE-79", "CWE-116", "CWE-352", "CWE-601", "CWE-346",
                       "CWE-284", "CWE-285", "CWE-614", "CWE-1004"],
    },
    {
        "name": "auth",
        "keywords": ["auth", "identity", "login", "session", "iam", "sso",
                     "jwt", "oauth", "oidc", "keycloak", "passport"],
        "th_ids": ["TH-02", "TH-03", "TH-06", "TH-10", "TH-15", "TH-16",
                   "TH-17", "TH-18"],
        "extra_cwes": ["CWE-287", "CWE-295", "CWE-307", "CWE-306", "CWE-640",
                       "CWE-384", "CWE-522", "CWE-290", "CWE-639"],
    },
    {
        "name": "backend-api",
        "keywords": ["backend", "rest-api", "graphql", "gateway", "api-server",
                     "service", "controller", "grpc", "bff"],
        "th_ids": ["TH-01", "TH-02", "TH-03", "TH-05", "TH-06", "TH-08",
                   "TH-12", "TH-16", "TH-17"],
        "extra_cwes": ["CWE-89", "CWE-943", "CWE-918", "CWE-502", "CWE-284",
                       "CWE-285", "CWE-862", "CWE-400"],
    },
    {
        "name": "database",
        "keywords": ["database", "data-layer", "repository", "db", "postgres",
                     "mysql", "mongo", "redis", "datastore"],
        "th_ids": ["TH-01", "TH-03", "TH-06", "TH-07", "TH-16"],
        "extra_cwes": ["CWE-89", "CWE-943", "CWE-312", "CWE-313", "CWE-22"],
    },
    {
        "name": "ci-cd",
        "keywords": ["ci-cd", "ci_cd", "cicd", "pipeline", "github-actions",
                     "gitlab-ci", "jenkins", "build", "deploy"],
        "th_ids": ["TH-14", "TH-03", "TH-06", "TH-16"],
        "extra_cwes": ["CWE-506", "CWE-829", "CWE-494", "CWE-285"],
    },
    {
        "name": "admin",
        "keywords": ["admin", "management", "backoffice", "back-office",
                     "dashboard", "cms", "console"],
        "th_ids": ["TH-02", "TH-06", "TH-09", "TH-16", "TH-17"],
        "extra_cwes": ["CWE-284", "CWE-285", "CWE-269", "CWE-287"],
    },
    {
        "name": "realtime",
        "keywords": ["websocket", "realtime", "real-time", "socket", "streaming",
                     "pubsub", "mqtt", "sse"],
        "th_ids": ["TH-02", "TH-06", "TH-12", "TH-13", "TH-15"],
        "extra_cwes": ["CWE-346", "CWE-284", "CWE-400"],
    },
]


def detect_profile(component_type: str, component_id: str) -> dict | None:
    """Return first matching profile or None for passthrough."""
    needle = (component_type + " " + component_id).lower()
    needle = re.sub(r"[^a-z0-9 _-]", " ", needle)
    for profile in COMPONENT_PROFILES:
        for kw in profile["keywords"]:
            if kw in needle:
                return profile
    return None


# ---------------------------------------------------------------------------
# Slicing helpers
# ---------------------------------------------------------------------------

def slice_threat_categories(data: dict, th_ids: set) -> dict:
    """Keep only the specified TH-IDs in the categories list.
    cwe_to_th is filtered to entries whose value intersects th_ids."""
    out = copy.deepcopy(data)
    out["categories"] = [c for c in out.get("categories", []) if c["id"] in th_ids]
    if "cwe_to_th" in out:
        out["cwe_to_th"] = {
            cwe: [th for th in ths if th in th_ids]
            for cwe, ths in out["cwe_to_th"].items()
            if any(th in th_ids for th in ths)
        }
    return out


def slice_cwe_taxonomy(data: dict, keep_cwes: set) -> dict:
    """Keep only the specified CWE entries in the cwes dict."""
    out = copy.deepcopy(data)
    if "cwes" in out:
        out["cwes"] = {k: v for k, v in out["cwes"].items() if k in keep_cwes}
    return out


def slice_controls(data: dict, th_ids: set) -> dict:
    """Controls are not per-TH — keep all; no meaningful slice available."""
    return copy.deepcopy(data)


def slice_compound_chains(data: dict, th_ids: set) -> dict:
    """Keep chain patterns where at least one involved TH is in scope."""
    out = copy.deepcopy(data)
    chains_key = next((k for k in out if "chain" in k.lower() or "pattern" in k.lower()), None)
    if not chains_key:
        return out
    def relevant(pattern: dict) -> bool:
        ths = pattern.get("th_ids", []) or pattern.get("categories", [])
        return not ths or any(t in th_ids for t in ths)
    out[chains_key] = [p for p in out[chains_key] if relevant(p)]
    return out


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("component_type", help="Component type keyword (e.g. 'frontend', 'auth', 'backend-api')")
    p.add_argument("output_dir", help="Assessment output directory (slices written to .taxonomy-slices/<id>/)")
    p.add_argument("--component-id", default=None, help="Component slug (used for output path and matching)")
    p.add_argument("--data-dir", default=None, help="Plugin data directory (defaults to auto-detected)")
    p.add_argument("--taxonomies", default="threats,cwe,controls,chains",
                   help="Comma-separated list of taxonomy files to slice (default: threats,cwe,controls,chains)")
    return p.parse_args()


def find_data_dir(explicit: str | None) -> str:
    if explicit:
        return explicit
    # Walk up from this script to find data/
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(4):
        candidate = os.path.join(here, "data")
        if os.path.isdir(candidate):
            return candidate
        here = os.path.dirname(here)
    raise FileNotFoundError("Cannot locate data/ directory — pass --data-dir explicitly")


def load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_yaml(data: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def main() -> int:
    args = parse_args()
    component_id = args.component_id or re.sub(r"[^a-z0-9-]", "-", args.component_type.lower())
    slice_dir = os.path.join(args.output_dir, ".taxonomy-slices", component_id)

    try:
        data_dir = find_data_dir(args.data_dir)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    want = {t.strip().lower() for t in args.taxonomies.split(",")}

    profile = detect_profile(args.component_type, component_id)
    passthrough = profile is None
    if passthrough:
        print(f"TAXONOMY_SLICE: {component_id} → passthrough (type '{args.component_type}' unrecognised)")
    else:
        print(f"TAXONOMY_SLICE: {component_id} → {profile['name']} profile "
              f"({len(profile['th_ids'])} TH categories)")

    th_ids = set(profile["th_ids"]) if profile else None
    extra_cwes = set(profile.get("extra_cwes", [])) if profile else set()

    file_map = {
        "threats": "threat-category-taxonomy.yaml",
        "cwe":     "cwe-taxonomy.yaml",
        "controls": "architectural-controls.yaml",
        "chains":  "compound-chain-patterns.yaml",
    }

    exit_code = 0 if not passthrough else 1

    for key, filename in file_map.items():
        if key not in want:
            continue
        src = os.path.join(data_dir, filename)
        if not os.path.isfile(src):
            print(f"WARN: {src} not found — skipping", file=sys.stderr)
            continue
        dst = os.path.join(slice_dir, filename)
        try:
            data = load_yaml(src)
            if passthrough:
                sliced = copy.deepcopy(data)
            elif key == "threats":
                sliced = slice_threat_categories(data, th_ids)
            elif key == "cwe":
                # Derive keep set: all CWEs whose cwe_to_th overlaps th_ids + extras
                th_taxonomy = load_yaml(os.path.join(data_dir, "threat-category-taxonomy.yaml"))
                keep = set(extra_cwes)
                for cwe_id, ths in th_taxonomy.get("cwe_to_th", {}).items():
                    if any(t in th_ids for t in ths):
                        keep.add(cwe_id)
                sliced = slice_cwe_taxonomy(data, keep)
            elif key == "controls":
                sliced = slice_controls(data, th_ids)
            elif key == "chains":
                sliced = slice_compound_chains(data, th_ids)
            else:
                sliced = copy.deepcopy(data)
            write_yaml(sliced, dst)
        except (OSError, yaml.YAMLError) as e:
            print(f"ERROR writing {dst}: {e}", file=sys.stderr)
            return 2

    print(f"TAXONOMY_SLICE: {component_id} → {slice_dir}/")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
