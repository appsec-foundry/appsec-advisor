#!/usr/bin/env python3
"""resolve_requirements_source.py — pick the active requirements source.

Merge order, highest priority first:

    1. ``--no-requirements``              → strongest disable override
    2. ``--requirements <url>``           → explicit URL override
    3. ``--demo``                         → packaged example catalog (DEMO)
    4. Local repo catalog                 → developer-authored
       ``<output-dir>/requirements.yaml`` (surfaced to the user; beats the
       org profile per project decision)
    5. Active org profile requirements    → ``requirements.source`` +
       ``requirements.create_threat_model``
    6. ``skills/audit-security-requirements/config.json`` (legacy default,
       when it carries an explicit URL)
    7. Remembered source sidecar          → the URL the catalog was last
       fetched from (``.cache/requirements.source.json``)
    8. Legacy default (disabled / no URL) — terminal fallback

For ``base_mode = quick``, ``requirements.create_threat_model.quick_default_active``
narrows the default further. The standalone audit skill respects
``requirements.standalone_audit.enabled``.

Output is a JSON object printed to stdout — meant for consumption by
``resolve_config.py`` and the audit-security-requirements skill.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Shared sidecar / local-file helpers live in one place.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_state as rstate  # noqa: E402

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def _load_effective(path: Path | None) -> dict | None:
    if not path:
        return None
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _load_legacy_default(plugin_root: Path) -> dict:
    cfg = plugin_root / "skills" / "audit-security-requirements" / "config.json"
    if not cfg.exists():
        return {}
    try:
        return json.loads(cfg.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------


def resolve(
    cli_url: str | None,
    cli_no_requirements: bool,
    base_mode: str | None,
    caller: str,
    effective: dict | None,
    legacy_default: dict,
    *,
    demo_path: str | None = None,
    local_path: str | None = None,
    remembered: dict | None = None,
) -> dict:
    """Return a single dict describing the active requirements source.

    Schema::

        {
            "enabled": bool,
            "url": str | None,
            "source": "cli" | "demo" | "local" | "org-profile" | "legacy"
                      | "remembered" | "disabled",
            "label": str | None,
            "human_source_url": str | None,
            "fail_mode": str,
            "cache": bool,
            "demo": bool,        # report must be stamped DEMO
            "surfaced": bool,    # banner must call this out (local file override)
        }

    ``demo_path`` / ``local_path`` are pre-resolved filesystem paths supplied by
    ``main`` (it knows the plugin root and output dir); ``remembered`` is the
    parsed source sidecar, if any.

    ``org_audit_disabled`` (governance signal) is set when the active org profile
    configures a requirements source but turns the standalone audit off. It is
    reported on every result independently of which source wins, so the audit
    skill can honour the org policy even when a local repo catalog would
    otherwise take precedence — only an explicit ``--requirements`` / ``--demo``
    per-run override (``source`` ``cli`` / ``demo``) bypasses it.
    """
    profile_rs0 = (effective or {}).get("requirements_source") or {}
    org_audit_disabled = bool(
        caller == "audit-security-requirements"
        and profile_rs0.get("requirements_yaml_url")
        and (profile_rs0.get("standalone_audit") or {}).get("enabled", True) is False
    )
    base = {"demo": False, "surfaced": False, "org_audit_disabled": org_audit_disabled}

    if cli_no_requirements:
        return {
            **base,
            "enabled": False,
            "url": None,
            "source": "disabled",
            "label": None,
            "human_source_url": None,
            "fail_mode": "disabled_on_fail",
            "cache": False,
            "override_reason": "--no-requirements",
        }
    if cli_url:
        return {
            **base,
            "enabled": True,
            "url": cli_url,
            "source": "cli",
            "label": None,
            "human_source_url": None,
            "fail_mode": "fail_closed",
            "cache": True,
            "override_reason": "--requirements",
        }
    if demo_path:
        return {
            **base,
            "enabled": True,
            "url": demo_path,
            "source": "demo",
            "label": "Packaged example (DEMO)",
            "human_source_url": None,
            "fail_mode": "fail_closed",
            "cache": False,
            "demo": True,
            "override_reason": "--demo",
        }
    if local_path:
        # Developer-authored local catalog beats the org profile, but the user
        # must be told it is in effect (surfaced=True drives the banner note).
        return {
            **base,
            "enabled": True,
            "url": local_path,
            "source": "local",
            "label": "Local repo catalog",
            "human_source_url": None,
            "fail_mode": "fail_closed",
            "cache": False,
            "surfaced": True,
        }

    profile_rs = (effective or {}).get("requirements_source") or {}
    if profile_rs.get("requirements_yaml_url"):
        ctm = profile_rs.get("create_threat_model") or {}
        if caller == "create-threat-model":
            enabled = bool(ctm.get("default_active", True))
            if base_mode == "quick":
                enabled = bool(ctm.get("quick_default_active", enabled))
        elif caller == "audit-security-requirements":
            standalone = profile_rs.get("standalone_audit") or {}
            enabled = bool(standalone.get("enabled", True))
        else:
            enabled = True
        return {
            **base,
            "enabled": enabled,
            "url": profile_rs.get("requirements_yaml_url"),
            "source": "org-profile",
            "label": profile_rs.get("label"),
            "human_source_url": profile_rs.get("human_source_url"),
            "fail_mode": profile_rs.get("fail_mode", "cache_fallback"),
            "cache": bool(profile_rs.get("cache", True)),
        }

    legacy_rs = legacy_default.get("requirements_source") or {}
    if legacy_rs.get("requirements_yaml_url"):
        return {
            **base,
            "enabled": bool(legacy_rs.get("enabled", True)),
            "url": legacy_rs.get("requirements_yaml_url"),
            "source": "legacy",
            "label": None,
            "human_source_url": None,
            "fail_mode": "cache_fallback",
            "cache": True,
        }

    if remembered and remembered.get("url"):
        # The catalog was fetched before; reuse the remembered URL. Treated as an
        # active source only for the explicit audit action — create-threat-model
        # must not be silently switched on by a leftover sidecar.
        return {
            **base,
            "enabled": caller == "audit-security-requirements",
            "url": remembered.get("url"),
            "source": "remembered",
            "label": remembered.get("label"),
            "human_source_url": None,
            "fail_mode": "cache_fallback",
            "cache": True,
        }

    return {
        **base,
        "enabled": bool(legacy_rs.get("enabled", False)),
        "url": legacy_rs.get("requirements_yaml_url"),
        "source": "legacy",
        "label": None,
        "human_source_url": None,
        "fail_mode": "cache_fallback",
        "cache": True,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve the active requirements source for a skill run.")
    parser.add_argument("--requirements", default=None, help="CLI requirements URL override")
    parser.add_argument(
        "--no-requirements",
        action="store_true",
        help="disable requirements for this run",
    )
    parser.add_argument(
        "--base-mode",
        default=None,
        choices=[None, "quick", "standard", "thorough"],
    )
    parser.add_argument(
        "--caller",
        default="create-threat-model",
        choices=["create-threat-model", "audit-security-requirements"],
    )
    parser.add_argument("--demo", action="store_true", help="resolve to the packaged example catalog (DEMO)")
    parser.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR"))
    parser.add_argument("--plugin-root", default=None)
    parser.add_argument("--cache-path", default=None, help="override plugin cache path (sidecar lives beside it)")
    args = parser.parse_args(argv)

    plugin_root = Path(args.plugin_root).resolve() if args.plugin_root else Path(__file__).resolve().parent.parent
    effective_path = Path(args.output_dir) / ".org-profile-effective.json" if args.output_dir else None
    effective = _load_effective(effective_path)
    legacy = _load_legacy_default(plugin_root)

    demo_path = str(plugin_root / "examples" / "appsec-requirements-example.yaml") if args.demo else None
    local_path = rstate.local_repo_source(Path(args.output_dir)) if args.output_dir else None
    cache_file = Path(args.cache_path) if args.cache_path else plugin_root / ".cache" / "requirements.yaml"
    remembered = rstate.read_sidecar(rstate.sidecar_path_for_cache(cache_file))

    result = resolve(
        args.requirements,
        args.no_requirements,
        args.base_mode,
        args.caller,
        effective,
        legacy,
        demo_path=demo_path,
        local_path=local_path,
        remembered=remembered,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
