#!/usr/bin/env python3
"""validate_org_profile.py — schema + semantic validator for org profiles.

Validates an org profile YAML against ``schemas/org-profile.schema.yaml``
and then enforces semantic rules that JSON Schema alone cannot express:

  * default_preset must exist in presets
  * llm_context document paths must stay under the profile directory
  * symlinks that escape the profile directory are rejected
  * preset context document_ids must resolve to llm_context.documents[].id
  * target.repo == profile_default requires target.repo_path
  * target.output_dir tokens are whitelisted and must not resolve into
    PLUGIN_ROOT or .git/
  * requirements_yaml_url must not embed credentials (user:pass@host)
  * mcp.servers entries must set url or command, and a server url must not
    embed credentials (secrets belong in ${ENV_VAR} headers)
  * skill_toggles keys must be known plugin skills
  * compatibility.core range must accept the current plugin version

Exit codes
    0 — profile valid
    1 — validation errors
    2 — usage / IO error
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = PLUGIN_ROOT / "schemas" / "org-profile.schema.yaml"

# user-facing skills shipped by the plugin; this allowlist is authoritative
# for skill_toggles keys. Keep this list in sync with skills/<name>/SKILL.md.
KNOWN_SKILLS: set[str] = {
    "create-threat-model",
    "audit-security-requirements",
    "check-permissions",
    "clean-run-state",
    "export-threat-model",
    "fix-run-issues",
    "publish-threat-model",
    "status",
    "threat-model-health",
}

ALLOWED_OUTPUT_DIR_TOKENS: set[str] = {"repo_name", "repo_slug", "preset", "date"}


# ---------------------------------------------------------------------------
# YAML / schema loaders
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> Any:
    import yaml

    with path.open() as fh:
        return yaml.safe_load(fh)


def _load_schema() -> dict:
    return _load_yaml(SCHEMA_PATH)


# ---------------------------------------------------------------------------
# JSON-Schema check
# ---------------------------------------------------------------------------


def _schema_errors(profile: Any, schema: dict) -> list[str]:
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema package not installed; cannot validate profile schema"]

    validator_cls = jsonschema.Draft202012Validator
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(profile), key=lambda e: list(e.absolute_path))
    out: list[str] = []
    for err in errors:
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        out.append(f"schema: {loc}: {err.message}")
    return out


# ---------------------------------------------------------------------------
# Semantic checks
# ---------------------------------------------------------------------------


def _rac_module():
    spec = importlib.util.spec_from_file_location(
        "resolve_abuse_cases",
        Path(__file__).resolve().parent / "resolve_abuse_cases.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _check_abuse_cases(profile: dict, profile_dir: Path) -> list[str]:
    """When the profile declares an ``abuse_cases`` block, resolve and validate
    the standard library + org glob files against the abuse-case schema and the
    grants/requires chain-consistency rule."""
    if "abuse_cases" not in profile:
        return []
    try:
        rac = _rac_module()
    except (OSError, ImportError) as exc:
        return [f"abuse_cases: cannot load resolver: {exc}"]
    _, errors = rac.resolve_abuse_cases(profile, profile_dir, PLUGIN_ROOT)
    return [f"abuse_cases: {e}" for e in errors]


def _check_default_preset(profile: dict) -> list[str]:
    default = profile.get("default_preset")
    presets = profile.get("presets") or {}
    if default and default not in presets:
        return [f"default_preset '{default}' is not defined in presets"]
    return []


def _resolve_under(profile_dir: Path, rel_path: str) -> tuple[Path | None, str | None]:
    """Resolve rel_path under profile_dir, returning (path, error_or_none).

    Rejects absolute paths, parent traversal, and symlinks that escape
    the profile directory.
    """
    if not rel_path:
        return None, "path is empty"
    if Path(rel_path).is_absolute():
        return None, f"path '{rel_path}' must be relative to the profile directory"
    candidate = (profile_dir / rel_path).resolve()
    try:
        candidate.relative_to(profile_dir.resolve())
    except ValueError:
        return None, f"path '{rel_path}' resolves outside the profile directory"
    # Reject symlinks anywhere in the chain after resolution.
    walker = profile_dir / rel_path
    for part in [walker, *walker.parents]:
        if part == profile_dir or part == profile_dir.parent:
            break
        if part.is_symlink():
            return None, f"path '{rel_path}' traverses a symlink"
    return candidate, None


def _check_llm_context_paths(profile: dict, profile_dir: Path) -> list[str]:
    errors: list[str] = []
    docs = ((profile.get("llm_context") or {}).get("documents")) or []
    seen_ids: set[str] = set()
    for doc in docs:
        doc_id = doc.get("id")
        if doc_id in seen_ids:
            errors.append(f"llm_context: duplicate document id '{doc_id}'")
        seen_ids.add(doc_id)
        rel = doc.get("path", "")
        resolved, err = _resolve_under(profile_dir, rel)
        if err:
            errors.append(f"llm_context: document '{doc_id}': {err}")
            continue
        if resolved is not None and not resolved.exists():
            errors.append(f"llm_context: document '{doc_id}': file not found at '{rel}'")
    return errors


def _check_preset_context_refs(profile: dict) -> list[str]:
    errors: list[str] = []
    ctx_ids: set[str] = {
        d.get("id") for d in ((profile.get("llm_context") or {}).get("documents") or []) if d.get("id")
    }
    for name, preset in (profile.get("presets") or {}).items():
        doc_ids = ((preset.get("context") or {}).get("document_ids")) or []
        for ref in doc_ids:
            if ref not in ctx_ids:
                errors.append(f"preset '{name}': context.document_ids references unknown id '{ref}'")
    return errors


def _check_target_rules(profile: dict) -> list[str]:
    errors: list[str] = []
    for name, preset in (profile.get("presets") or {}).items():
        target = preset.get("target") or {}
        repo = target.get("repo")
        repo_path = target.get("repo_path")
        if repo == "profile_default" and not repo_path:
            errors.append(f"preset '{name}': target.repo=profile_default requires target.repo_path")
        out_dir = target.get("output_dir")
        if out_dir:
            for token in re.findall(r"\{([^{}]+)\}", out_dir):
                if token not in ALLOWED_OUTPUT_DIR_TOKENS:
                    errors.append(
                        f"preset '{name}': target.output_dir uses unknown token "
                        f"'{{{token}}}'; allowed: {sorted(ALLOWED_OUTPUT_DIR_TOKENS)}"
                    )
            # Reject obvious dangerous targets early. Full plugin-root /
            # .git/ resolution happens at runtime once REPO_ROOT is known.
            normalized = re.sub(r"\{[^{}]+\}", "x", out_dir)
            if ".git" in Path(normalized).parts:
                errors.append(f"preset '{name}': target.output_dir must not contain '.git'")
    return errors


def _check_requirements_url(profile: dict) -> list[str]:
    errors: list[str] = []
    src = ((profile.get("requirements") or {}).get("source")) or {}
    url = src.get("requirements_yaml_url")
    if isinstance(url, str) and url:
        parsed = urlparse(url)
        if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
            errors.append("requirements.source.requirements_yaml_url must not embed credentials")
        if parsed.scheme and parsed.scheme not in ("http", "https", "file"):
            errors.append(
                f"requirements.source.requirements_yaml_url scheme '{parsed.scheme}' "
                f"is not http/https/file or a local path"
            )
    return errors


def _check_mcp(profile: dict) -> list[str]:
    """Structural checks for the mcp.servers block that JSON Schema cannot express:
    each server must be reachable (url or command), and a server url must not
    embed credentials — tokens belong in ${ENV_VAR} headers, not the URL."""
    errors: list[str] = []
    servers = ((profile.get("mcp") or {}).get("servers")) or {}
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url")
        command = cfg.get("command")
        has_url = isinstance(url, str) and url
        has_command = isinstance(command, str) and command
        if not has_url and not has_command:
            errors.append(f"mcp: server '{name}' must set either 'url' or 'command'")
        if has_url:
            parsed = urlparse(url)
            if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
                errors.append(f"mcp: server '{name}' url must not embed credentials; use a ${{ENV_VAR}} header instead")
    return errors


def _check_skill_toggles(profile: dict) -> list[str]:
    errors: list[str] = []
    toggles = profile.get("skill_toggles") or {}
    for skill, value in toggles.items():
        if skill not in KNOWN_SKILLS:
            errors.append(f"skill_toggles: unknown skill '{skill}'; known: {sorted(KNOWN_SKILLS)}")
        if isinstance(value, dict):
            if value.get("enabled") is False and not (value.get("reason") or "").strip():
                errors.append(f"skill_toggles: '{skill}' is disabled and should provide a reason")
    return errors


# ---------------------------------------------------------------------------
# Compatibility range matcher
# ---------------------------------------------------------------------------


_RANGE_TOKEN = re.compile(r"^\s*(>=|<=|==|<|>)\s*([0-9A-Za-z._\-+]+)\s*$")


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a SemVer-ish prefix into a comparable tuple of ints.

    Pre-release suffixes (``-beta``, ``+meta``) are dropped — we only
    compare the numeric prefix. Org-profile compatibility is informative
    and intentionally coarse.
    """
    core = re.split(r"[-+]", v, maxsplit=1)[0]
    parts: list[int] = []
    for chunk in core.split("."):
        if not chunk:
            continue
        try:
            parts.append(int(chunk))
        except ValueError:
            # Stop on the first non-numeric component.
            break
    return tuple(parts) or (0,)


def _check_compatibility(profile: dict, plugin_version: str) -> list[str]:
    spec = ((profile.get("compatibility") or {}).get("core")) or ""
    if not spec:
        return []
    plugin_tuple = _parse_version(plugin_version)
    for token in spec.split():
        match = _RANGE_TOKEN.match(token)
        if not match:
            return [f"compatibility.core token '{token}' is not understood"]
        op, ver = match.group(1), match.group(2)
        target = _parse_version(ver)
        # Pad to equal length for tuple comparison.
        ln = max(len(plugin_tuple), len(target))
        pad = lambda t: t + (0,) * (ln - len(t))  # noqa: E731
        a, b = pad(plugin_tuple), pad(target)
        ok = {
            ">=": a >= b,
            "<=": a <= b,
            "==": a == b,
            "<": a < b,
            ">": a > b,
        }[op]
        if not ok:
            return [f"compatibility.core '{spec}' rejects plugin_version '{plugin_version}'"]
    return []


def _read_plugin_version() -> str:
    meta = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
    if not meta.exists():
        return "0.0.0"
    try:
        return json.loads(meta.read_text()).get("version", "0.0.0")
    except (json.JSONDecodeError, OSError):
        return "0.0.0"


# ---------------------------------------------------------------------------
# Top-level entry
# ---------------------------------------------------------------------------


def validate(profile: Any, profile_dir: Path, plugin_version: str | None = None) -> list[str]:
    """Run schema + semantic checks. Returns a list of error strings."""
    errors: list[str] = []
    try:
        schema = _load_schema()
    except FileNotFoundError:
        return [f"schema file missing: {SCHEMA_PATH}"]

    errors += _schema_errors(profile, schema)
    if errors:
        # Skip semantic checks until the shape is valid; they assume the
        # JSON-Schema invariants hold.
        return errors

    errors += _check_default_preset(profile)
    errors += _check_llm_context_paths(profile, profile_dir)
    errors += _check_preset_context_refs(profile)
    errors += _check_target_rules(profile)
    errors += _check_requirements_url(profile)
    errors += _check_mcp(profile)
    errors += _check_skill_toggles(profile)
    errors += _check_compatibility(profile, plugin_version or _read_plugin_version())
    errors += _check_abuse_cases(profile, profile_dir)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate an org profile YAML against the org-profile schema.")
    parser.add_argument("profile", help="path to org-profile.yaml")
    parser.add_argument(
        "--plugin-version",
        default=None,
        help="override the plugin version for compatibility checks (test hook)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit errors as JSON instead of human-readable lines",
    )
    args = parser.parse_args(argv)

    profile_path = Path(args.profile).resolve()
    if not profile_path.exists():
        print(f"error: file not found: {profile_path}", file=sys.stderr)
        return 2
    try:
        profile = _load_yaml(profile_path)
    except Exception as exc:  # noqa: BLE001
        print(f"error: failed to parse YAML: {exc}", file=sys.stderr)
        return 2

    errors = validate(profile, profile_path.parent, args.plugin_version)
    if args.json:
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
    else:
        if errors:
            print(f"INVALID: {profile_path}")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"VALID: {profile_path}")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
