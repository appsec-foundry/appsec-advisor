#!/usr/bin/env python3
"""resolve_abuse_cases.py — assemble the active abuse-case set for a run.

Merges three sources into one validated list of abuse-case definitions:

  1. the plugin standard library (``data/abuse-cases/default-library.yaml``)
     unless the org profile sets ``abuse_cases.inherit_defaults: false``;
  2. org-specific case files matched by ``abuse_cases.add`` (a glob relative to
     the org-profile directory), validated against
     ``schemas/abuse-cases.schema.yaml``;
  3. minus any ids listed in ``abuse_cases.disable``.

Consumed by ``scripts/match_abuse_cases.py`` (deterministic matcher) and by
``scripts/validate_org_profile.py`` (semantic validation of the org glob).

The resolver is pure data assembly — no agent dispatch, no recon, no matching.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LIBRARY = PLUGIN_ROOT / "data" / "abuse-cases" / "default-library.yaml"
ABUSE_CASE_SCHEMA = PLUGIN_ROOT / "schemas" / "abuse-cases.schema.yaml"


def _load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_schema() -> dict:
    return _load_yaml(ABUSE_CASE_SCHEMA)


def _schema_errors(doc: Any, schema: dict, label: str) -> list[str]:
    try:
        import jsonschema
    except ImportError:
        return [f"{label}: jsonschema not installed; cannot validate abuse cases"]
    validator = jsonschema.Draft202012Validator(schema)
    out = []
    for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        out.append(f"{label}: {loc}: {err.message}")
    return out


def _check_grants_requires(case: dict, label: str) -> list[str]:
    """Each step's ``requires`` must be granted by an earlier step (or be an
    external precondition declared on step 1). A dangling ``requires`` means the
    chain cannot be verified end-to-end."""
    errors: list[str] = []
    granted: set[str] = set()
    chain = case.get("chain") or []
    for i, step in enumerate(chain):
        req = (step.get("requires") or "").strip()
        if req and req not in granted and i > 0:
            errors.append(
                f"{label}: step {step.get('step')} requires '{req}' "
                f"which no earlier step grants"
            )
        grants = (step.get("grants") or "").strip()
        if grants:
            granted.add(grants)
    return errors


def _load_case_file(path: Path, schema: dict) -> tuple[list[dict], list[str]]:
    """Load one library/org file (`{abuse_cases: [...]}`), validate, return
    (cases, errors)."""
    label = path.name
    try:
        doc = _load_yaml(path)
    except (OSError, yaml.YAMLError) as exc:
        return [], [f"{label}: cannot parse: {exc}"]
    if not isinstance(doc, dict):
        return [], [f"{label}: top-level must be a mapping with 'abuse_cases'"]
    errors = _schema_errors(doc, schema, label)
    cases = doc.get("abuse_cases") or []
    if not errors:
        for case in cases:
            errors += _check_grants_requires(case, f"{label}:{case.get('id')}")
    return (cases if not errors else []), errors


REPO_LOCAL_SUBDIR = Path(".appsec") / "abuse-cases"


def resolve_abuse_cases(
    org_profile: dict | None,
    profile_dir: Path | None,
    plugin_root: Path = PLUGIN_ROOT,
    repo_root: Path | None = None,
) -> tuple[list[dict], list[str]]:
    """Return (active_cases, errors).

    Sources, in load order:
      1. plugin standard library (unless ``inherit_defaults: false``);
      2. org-profile cases matched by ``abuse_cases.add`` (glob relative to
         ``profile_dir``);
      3. **repo-local** cases under ``<repo_root>/.appsec/abuse-cases/*.yaml``
         — a zero-config layer that needs no org profile, mirroring the
         known-threats convention so a single repository can ship its own
         scenarios checked into version control;
      minus any ids in ``abuse_cases.disable``.

    ``org_profile`` is the parsed profile dict (or None when no profile is
    active). ``profile_dir`` is the directory the profile lives in. ``repo_root``
    is the target repository root (or None to skip the repo-local layer).
    """
    schema = _load_schema()
    cfg = (org_profile or {}).get("abuse_cases") or {}
    inherit = cfg.get("inherit_defaults", True)
    disabled = set(cfg.get("disable") or [])
    add_glob = cfg.get("add", "abuse-cases/*.yaml")

    cases: list[dict] = []
    errors: list[str] = []

    library = plugin_root / "data" / "abuse-cases" / "default-library.yaml"
    if inherit and library.exists():
        lib_cases, lib_errors = _load_case_file(library, schema)
        cases += lib_cases
        errors += lib_errors

    if profile_dir is not None and add_glob:
        for path in sorted(profile_dir.glob(add_glob)):
            file_cases, file_errors = _load_case_file(path, schema)
            cases += file_cases
            errors += file_errors

    # Repo-local layer — zero-config, no org profile required. Any *.yaml under
    # <repo_root>/.appsec/abuse-cases/ is loaded and validated. The org
    # profile's `disable` list (below) still applies to repo-local ids, and a
    # duplicate id across layers is reported as an authoring error.
    if repo_root is not None:
        repo_dir = Path(repo_root) / REPO_LOCAL_SUBDIR
        if repo_dir.is_dir():
            for path in sorted(repo_dir.glob("*.yaml")):
                file_cases, file_errors = _load_case_file(path, schema)
                cases += file_cases
                errors += file_errors

    # Apply disable + detect duplicate ids (org override wins is NOT supported —
    # a duplicate id is an authoring error, surfaced rather than silently merged).
    seen: dict[str, str] = {}
    active: list[dict] = []
    for case in cases:
        cid = case.get("id")
        if cid in disabled:
            continue
        if cid in seen:
            errors.append(f"duplicate abuse-case id {cid!r} (already defined)")
            continue
        seen[cid] = case.get("title", "")
        active.append(case)

    return active, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve the active abuse-case set.")
    parser.add_argument("--org-profile", default=None, help="path to org-profile.yaml")
    parser.add_argument("--plugin-root", default=None)
    parser.add_argument("--repo-root", default=None, help="target repo root; loads <repo>/.appsec/abuse-cases/*.yaml")
    parser.add_argument("--list-ids", action="store_true", help="print active ids only")
    args = parser.parse_args(argv)

    plugin_root = Path(args.plugin_root) if args.plugin_root else PLUGIN_ROOT
    repo_root = Path(args.repo_root) if args.repo_root else None
    profile: dict | None = None
    profile_dir: Path | None = None
    if args.org_profile:
        p = Path(args.org_profile)
        profile = _load_yaml(p)
        profile_dir = p.parent

    cases, errors = resolve_abuse_cases(profile, profile_dir, plugin_root, repo_root)
    if errors:
        for e in errors:
            sys.stderr.write(f"ERROR: {e}\n")
        return 1
    if args.list_ids:
        for c in cases:
            print(c["id"])
    else:
        json.dump({"abuse_cases": cases}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
