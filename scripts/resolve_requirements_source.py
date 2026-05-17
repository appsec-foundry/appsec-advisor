#!/usr/bin/env python3
"""resolve_requirements_source.py — pick the active requirements source.

Merge order, highest priority first:

    1. ``--requirements <url>``           → strongest URL override
    2. ``--no-requirements``              → strongest disable override
    3. Active org profile requirements    → ``requirements.source`` +
       ``requirements.create_threat_model``
    4. ``skills/check-appsec-requirements/config.json`` (legacy default)

For ``base_mode = quick``, ``requirements.create_threat_model.quick_default_active``
narrows the default further. The standalone audit skill respects
``requirements.standalone_audit.enabled``.

Output is a JSON object printed to stdout — meant for consumption by
``resolve_config.py`` and the check-appsec-requirements skill.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

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
    cfg = plugin_root / "skills" / "check-appsec-requirements" / "config.json"
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
) -> dict:
    """Return a single dict describing the active requirements source.

    Schema::

        {
            "enabled": bool,
            "url": str | None,
            "source": "cli" | "org-profile" | "legacy" | "disabled",
            "label": str | None,
            "human_source_url": str | None,
            "fail_mode": str,
            "cache": bool
        }
    """
    if cli_no_requirements:
        return {
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
            "enabled": True,
            "url": cli_url,
            "source": "cli",
            "label": None,
            "human_source_url": None,
            "fail_mode": "fail_closed",
            "cache": True,
            "override_reason": "--requirements",
        }

    profile_rs = (effective or {}).get("requirements_source") or {}
    if profile_rs.get("requirements_yaml_url"):
        ctm = profile_rs.get("create_threat_model") or {}
        if caller == "create-threat-model":
            enabled = bool(ctm.get("default_active", True))
            if base_mode == "quick":
                enabled = bool(ctm.get("quick_default_active", enabled))
        elif caller == "check-appsec-requirements":
            standalone = profile_rs.get("standalone_audit") or {}
            enabled = bool(standalone.get("enabled", True))
        else:
            enabled = True
        return {
            "enabled": enabled,
            "url": profile_rs.get("requirements_yaml_url"),
            "source": "org-profile",
            "label": profile_rs.get("label"),
            "human_source_url": profile_rs.get("human_source_url"),
            "fail_mode": profile_rs.get("fail_mode", "cache_fallback"),
            "cache": bool(profile_rs.get("cache", True)),
        }

    legacy_rs = legacy_default.get("requirements_source") or {}
    return {
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
    parser = argparse.ArgumentParser(
        description="Resolve the active requirements source for a skill run."
    )
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
        choices=["create-threat-model", "check-appsec-requirements"],
    )
    parser.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR"))
    parser.add_argument("--plugin-root", default=None)
    args = parser.parse_args(argv)

    plugin_root = (
        Path(args.plugin_root).resolve()
        if args.plugin_root
        else Path(__file__).resolve().parent.parent
    )
    effective_path = (
        Path(args.output_dir) / ".org-profile-effective.json"
        if args.output_dir
        else None
    )
    effective = _load_effective(effective_path)
    legacy = _load_legacy_default(plugin_root)
    result = resolve(
        args.requirements,
        args.no_requirements,
        args.base_mode,
        args.caller,
        effective,
        legacy,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
