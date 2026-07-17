#!/usr/bin/env python3
"""resolve_org_profile.py — pick an org profile + preset and emit defaults.

Pipeline position:

    config.json / CLI / env
        -> validate_org_profile.py
        -> resolve_org_profile.py                    (this script)
        -> resolve_config.py merges these defaults
        -> .skill-config.json + .org-profile-effective.json
        -> existing Stage-1 → Stage-4 pipeline

The resolver does **not** read markdown context (that is
``load_org_context.py``) and does **not** dispatch agents. It only:

  * decides which org profile is active (CLI > env > config.json pointer)
  * decides which preset is active (CLI > env > profile default)
  * computes a profile_fingerprint (sha256 over profile YAML bytes)
  * flattens the active preset into structured defaults consumed by
    ``resolve_config.py``
  * emits ``.org-profile-effective.json`` so status / hooks / coach can
    inspect the resolved state without re-running the full resolver

CLI
---

    resolve_org_profile.py [options]

Options:
    --org-profile <path>     use this profile instead of the packaged default
    --preset <name>          use this preset instead of the profile default
    --no-org-profile         ignore any packaged default profile
    --repo <path>            target repo (required by cli_required presets)
    --output-dir <path>      where to write .org-profile-effective.json
    --emit-file              write .org-profile-effective.json to OUTPUT_DIR
    --plugin-root <path>     override the plugin root (test hook)

Env (overridden by CLI):
    APPSEC_ADVISOR_ORG_PROFILE       absolute path to a profile YAML
    APPSEC_ADVISOR_PRESET            preset name
    APPSEC_ADVISOR_NO_ORG_PROFILE    truthy → disable org profile

Exit codes
    0 — resolution succeeded (no profile is also a success → ``active=false``)
    1 — schema/semantic validation failed
    2 — usage / configuration error (missing --repo for cli_required, etc.)
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Lazy import of validate_org_profile to avoid duplicating schema loading
# ---------------------------------------------------------------------------


def _vop_module():
    spec = importlib.util.spec_from_file_location(
        "validate_org_profile",
        Path(__file__).resolve().parent / "validate_org_profile.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Profile discovery
# ---------------------------------------------------------------------------


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _config_pointer(plugin_root: Path) -> tuple[str | None, str | None, bool]:
    """Return (path, default_preset_override, enabled) from config.json.

    Missing pointer or disabled returns (None, None, False).
    """
    cfg = plugin_root / "config.json"
    if not cfg.exists():
        return None, None, False
    try:
        data = json.loads(cfg.read_text())
    except (json.JSONDecodeError, OSError):
        return None, None, False
    block = data.get("organization_profile") or {}
    if not block.get("enabled"):
        return None, None, False
    return block.get("path"), block.get("default_preset"), True


def discover_active_profile(
    cli_path: str | None,
    cli_no_profile: bool,
    plugin_root: Path,
    env: dict[str, str] | None = None,
) -> tuple[Path | None, str]:
    """Decide which profile YAML is active and where it came from.

    Returns (resolved_path_or_None, source) where source is one of:
    ``"cli"``, ``"env"``, ``"config"``, ``"disabled"``, ``"none"``.
    """
    env = env if env is not None else dict(os.environ)
    if cli_no_profile or _truthy(env.get("APPSEC_ADVISOR_NO_ORG_PROFILE")):
        return None, "disabled"
    if cli_path:
        return _resolve_path(cli_path, plugin_root), "cli"
    env_path = env.get("APPSEC_ADVISOR_ORG_PROFILE")
    if env_path:
        return _resolve_path(env_path, plugin_root), "env"
    cfg_path, _, enabled = _config_pointer(plugin_root)
    if enabled and cfg_path:
        return _resolve_path(cfg_path, plugin_root), "config"
    return None, "none"


def _resolve_path(p: str, plugin_root: Path) -> Path:
    path = Path(p)
    if not path.is_absolute():
        path = plugin_root / path
    return path.resolve()


def discover_active_preset(profile: dict, cli_preset: str | None, env: dict[str, str] | None = None) -> str:
    env = env if env is not None else dict(os.environ)
    if cli_preset:
        return cli_preset
    env_preset = env.get("APPSEC_ADVISOR_PRESET")
    if env_preset:
        return env_preset
    return profile.get("default_preset", "")


# ---------------------------------------------------------------------------
# Preset flattening
# ---------------------------------------------------------------------------


_BASE_MODE_TO_DEPTH = {"quick": "quick", "standard": "standard", "thorough": "thorough"}


def _expand_output_template(template: str | None, repo_path: Path | None, preset: str) -> str | None:
    if not template:
        return None
    from datetime import date

    repo_name = repo_path.name if repo_path else ""
    repo_slug = repo_name.lower().replace(" ", "-") if repo_name else ""
    tokens = {
        "repo_name": repo_name,
        "repo_slug": repo_slug,
        "preset": preset,
        "date": date.today().isoformat(),
    }
    out = template
    for k, v in tokens.items():
        out = out.replace("{" + k + "}", v)
    return out


def _flatten_requirements_gate(requirements: dict) -> dict | None:
    """Surface the preset's requirements gate policy as a small dict, or None
    when the preset carries no ``gate`` block (so the requirements skills fall
    back to their built-in defaults advisory/fail/MUST). Values are defaults
    only — the per-run CLI flags override them (CLI > preset > built-in)."""
    gate = requirements.get("gate") or {}
    if not gate:
        return None
    return {
        "mode": gate.get("mode"),
        "gate_on": gate.get("gate_on"),
        "priority_floor": gate.get("priority_floor"),
    }


def flatten_preset(
    profile: dict,
    preset_name: str,
    cli_repo: str | None,
) -> tuple[dict, list[str]]:
    """Return (defaults_dict, errors). Empty errors means OK."""
    errors: list[str] = []
    preset = (profile.get("presets") or {}).get(preset_name)
    if preset is None:
        return {}, [f"preset '{preset_name}' is not defined in this org profile"]

    target = preset.get("target") or {}
    outputs = preset.get("outputs") or {}
    scan = preset.get("scan") or {}
    requirements = preset.get("requirements") or {}
    quality = preset.get("quality") or {}
    verification = preset.get("verification") or {}
    guardrails = preset.get("guardrails") or {}

    repo_policy = target.get("repo") or "current"
    repo_path: Path | None = None
    if cli_repo:
        repo_path = Path(cli_repo).resolve()
    elif repo_policy == "cli_required":
        errors.append(f"preset '{preset_name}' requires --repo <path> (target.repo=cli_required)")
    elif repo_policy == "profile_default" and target.get("repo_path"):
        repo_path = Path(target["repo_path"]).resolve()

    output_dir_template = target.get("output_dir")
    output_dir = _expand_output_template(output_dir_template, repo_path, preset_name)

    defaults: dict[str, Any] = {
        "assessment_depth": _BASE_MODE_TO_DEPTH.get(preset["base_mode"], preset["base_mode"]),
        "repo_policy": repo_policy,
        "repo_root": str(repo_path) if repo_path else None,
        "output_dir_template": output_dir_template,
        "output_dir": output_dir,
        "write_yaml": outputs.get("yaml"),
        "write_sarif": outputs.get("sarif"),
        "write_pdf": outputs.get("pdf"),
        "write_pentest_tasks": outputs.get("pentest_tasks"),
        "pentest_format": outputs.get("pentest_format"),
        "pentest_target": outputs.get("pentest_target"),
        "incremental": scan.get("incremental"),
        "scan_manifest": scan.get("scan_manifest"),
        "check_requirements": requirements.get("enabled"),
        "requirements_gate": _flatten_requirements_gate(requirements),
        "qa_review": quality.get("qa_review"),
        "architecture_enrichment": quality.get("architecture_enrichment"),
        "architect_review": quality.get("architect_review"),
        "attack_walkthroughs": quality.get("attack_walkthroughs"),
        "evidence_recheck": verification.get("evidence_recheck"),
        "generate_pentest_verification_tasks": verification.get("generate_pentest_verification_tasks"),
        "max_wall_time": guardrails.get("max_wall_time"),
        "max_cost_usd": guardrails.get("max_cost_usd"),
        "max_resumes": guardrails.get("max_resumes"),
        "tracing": guardrails.get("tracing"),
        "verbose_report": guardrails.get("verbose_report"),
        "fail_on": guardrails.get("fail_on"),
    }
    return defaults, errors


# ---------------------------------------------------------------------------
# Requirements + toggles + context manifest
# ---------------------------------------------------------------------------


def build_requirements_source(profile: dict) -> dict | None:
    req = profile.get("requirements") or {}
    src = req.get("source") or {}
    if not src:
        return None
    enabled = bool(src.get("requirements_yaml_url"))
    return {
        "source": "org-profile",
        "enabled": enabled,
        "requirements_yaml_url": src.get("requirements_yaml_url"),
        "human_source_url": src.get("human_source_url"),
        "label": src.get("label"),
        "cache": src.get("cache", True),
        "fail_mode": src.get("fail_mode", "cache_fallback"),
        "create_threat_model": req.get("create_threat_model") or {},
        "standalone_audit": req.get("standalone_audit") or {},
    }


def normalize_skill_toggles(profile: dict) -> dict:
    out: dict[str, dict] = {}
    for name, value in (profile.get("skill_toggles") or {}).items():
        if isinstance(value, bool):
            out[name] = {"enabled": value, "reason": None}
        elif isinstance(value, dict):
            out[name] = {
                "enabled": bool(value.get("enabled", True)),
                "reason": value.get("reason"),
            }
    return out


def build_context_manifest(profile: dict, profile_dir: Path) -> list[dict]:
    """Lightweight manifest with sha256/size only; full markdown loading
    lives in ``load_org_context.py`` so the resolver stays cheap.
    """
    docs = ((profile.get("llm_context") or {}).get("documents")) or []
    manifest: list[dict] = []
    for d in docs:
        rel = d.get("path", "")
        full = (profile_dir / rel).resolve()
        try:
            data = full.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            size = len(data)
            loaded = True
            reason = None
        except OSError as exc:
            sha = None
            size = 0
            loaded = False
            reason = str(exc)
        manifest.append(
            {
                "id": d.get("id"),
                "path": str(full),
                "purpose": d.get("purpose"),
                "max_bytes": d.get("max_bytes", 50000),
                "bytes": size,
                "sha256": sha,
                "loaded": loaded,
                "reason": reason,
            }
        )
    return manifest


def profile_fingerprint(profile_yaml_bytes: bytes, manifest: list[dict]) -> str:
    h = hashlib.sha256()
    h.update(profile_yaml_bytes)
    for doc in manifest:
        sha = doc.get("sha256") or ""
        h.update(sha.encode("ascii"))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Resolver entry
# ---------------------------------------------------------------------------


def resolve(
    cli_org_profile: str | None,
    cli_preset: str | None,
    cli_no_profile: bool,
    cli_repo: str | None,
    plugin_root: Path,
    env: dict[str, str] | None = None,
) -> tuple[dict, list[str]]:
    """Return (effective_dict, errors). Effective is always populated; if
    ``active`` is False, the rest of the structure carries source metadata
    only and downstream callers should fall back to core defaults."""
    env = env if env is not None else dict(os.environ)
    profile_path, source = discover_active_profile(cli_org_profile, cli_no_profile, plugin_root, env)
    base: dict[str, Any] = {
        "org_profile": {
            "active": False,
            "source": source,
            "path": str(profile_path) if profile_path else None,
        },
        "preset": None,
        "defaults": {},
        "requirements_source": None,
        "llm_context_documents": [],
        "skill_toggles": {},
        "security_coach": None,
    }
    if not profile_path:
        return base, []

    if not profile_path.exists():
        return base, [f"org profile not found at {profile_path}"]

    profile_yaml_bytes = profile_path.read_bytes()
    vop = _vop_module()
    profile = vop._load_yaml(profile_path)
    errors = vop.validate(profile, profile_path.parent)
    if errors:
        return base, errors

    cfg_default_preset = _config_pointer(plugin_root)[1] if source == "config" else None
    chosen_preset = (
        cli_preset or env.get("APPSEC_ADVISOR_PRESET") or cfg_default_preset or profile.get("default_preset", "")
    )
    if chosen_preset not in (profile.get("presets") or {}):
        return base, [
            f"preset '{chosen_preset}' is not defined in profile "
            f"{profile_path} (available: {sorted((profile.get('presets') or {}).keys())})"
        ]
    defaults, flat_errs = flatten_preset(profile, chosen_preset, cli_repo)
    if flat_errs:
        return base, flat_errs

    # Profile-level policy (not preset-scoped) — folded into defaults so
    # resolve_config._apply_org_profile can pick it up uniformly. The Opus
    # ceiling is org-wide by design, hence profile-level rather than per-preset.
    policy = profile.get("policy") or {}
    defaults["disable_opus"] = bool(policy.get("disable_opus"))
    # Org-wide remote-fetch allowlist (SSRF posture). Surfaced into defaults so
    # it rides into .org-profile-effective.json; scripts/_url_guard.py reads it
    # from there and enforces it on every remote fetch.
    if isinstance(policy.get("url_allowlist"), list) and policy["url_allowlist"]:
        defaults["url_allowlist"] = [str(h).strip().lower() for h in policy["url_allowlist"] if str(h).strip()]

    # Profile-level cover branding (org-wide, not preset-scoped). Only set keys
    # that the profile actually carries so resolve_config can distinguish
    # "profile has no opinion" (None) from an explicit value.
    branding = profile.get("branding") or {}
    for _bkey in ("report_title", "contact_name", "contact_email", "logo"):
        val = branding.get(_bkey)
        if val is not None:
            defaults[_bkey] = val
    # Resolve a relative local logo path against the profile directory so the
    # value is unambiguous by the time it reaches the renderer (which runs from
    # a different CWD). URLs and absolute paths pass through unchanged.
    logo = defaults.get("logo")
    if logo and not str(logo).lower().startswith(("http://", "https://")):
        lp = Path(str(logo)).expanduser()
        if not lp.is_absolute():
            lp = profile_path.parent / lp
        defaults["logo"] = str(lp)

    manifest = build_context_manifest(profile, profile_path.parent)
    fingerprint = profile_fingerprint(profile_yaml_bytes, manifest)
    coach = profile.get("security_coach")

    base = {
        "org_profile": {
            "active": True,
            "source": source,
            "path": str(profile_path),
            "id": profile["organization"]["id"],
            "name": profile["organization"]["name"],
            "version": profile["organization"]["profile_version"],
            "owner": profile["organization"].get("owner"),
            "profile_fingerprint": fingerprint,
        },
        "preset": {
            "name": chosen_preset,
            "base_mode": profile["presets"][chosen_preset]["base_mode"],
        },
        "defaults": defaults,
        "requirements_source": build_requirements_source(profile),
        "llm_context_documents": manifest,
        "skill_toggles": normalize_skill_toggles(profile),
        "security_coach": coach,
    }
    return base, []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve the active org profile + preset and emit defaults.")
    parser.add_argument("--org-profile", default=None)
    parser.add_argument("--preset", default=None)
    parser.add_argument("--no-org-profile", action="store_true")
    parser.add_argument("--repo", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--emit-file", action="store_true")
    parser.add_argument("--plugin-root", default=None)
    args = parser.parse_args(argv)

    plugin_root = Path(args.plugin_root).resolve() if args.plugin_root else Path(__file__).resolve().parent.parent
    effective, errors = resolve(
        args.org_profile,
        args.preset,
        args.no_org_profile,
        args.repo,
        plugin_root,
    )
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1

    payload = json.dumps(effective, indent=2, sort_keys=False)
    print(payload)
    if args.emit_file and args.output_dir:
        out_dir = Path(args.output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / ".org-profile-effective.json").write_text(payload + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
