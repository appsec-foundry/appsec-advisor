#!/usr/bin/env python3
"""
validate_config.py — JSON schema validator for appsec-advisor configuration files.

Validates:
  1. config.json — main plugin configuration
  2. skills/check-appsec-requirements/config.json — requirements skill configuration

Usage:
  python3 validate_config.py [config_dir]

  config_dir defaults to $CLAUDE_PLUGIN_ROOT or the  directory
  relative to this script.

Exit codes: 0 = all valid, 1 = validation errors found, 2 = usage error.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Schema definitions
# ---------------------------------------------------------------------------


def _validate_main_config(data: Any, path: str) -> list[str]:
    """Validate the main plugin config.json."""
    errors: list[str] = []

    if not isinstance(data, dict):
        return [f"{path}: root must be a JSON object"]

    # external_context (required)
    ec = data.get("external_context")
    if ec is None:
        errors.append(f"{path}: missing required key 'external_context'")
    elif not isinstance(ec, dict):
        errors.append(f"{path}: 'external_context' must be an object")
    else:
        if "enabled" not in ec:
            errors.append(f"{path}: 'external_context.enabled' is required")
        elif not isinstance(ec["enabled"], bool):
            errors.append(f"{path}: 'external_context.enabled' must be a boolean")

        if "rest_url" not in ec:
            errors.append(f"{path}: 'external_context.rest_url' is required")
        elif ec["rest_url"] is not None and not isinstance(ec["rest_url"], str):
            errors.append(f"{path}: 'external_context.rest_url' must be a string or null")
        elif isinstance(ec["rest_url"], str):
            parsed = urlparse(ec["rest_url"])
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                errors.append(
                    f"{path}: 'external_context.rest_url' must be a valid http:// or https:// URL with a host"
                )

    # pricing (optional)
    pricing = data.get("pricing")
    if pricing is not None:
        if not isinstance(pricing, dict):
            errors.append(f"{path}: 'pricing' must be an object")
        else:
            for key in ("input_per_1m", "output_per_1m", "cache_write_per_1m", "cache_read_per_1m"):
                val = pricing.get(key)
                if val is not None and not isinstance(val, (int, float)):
                    errors.append(f"{path}: 'pricing.{key}' must be a number")
                elif isinstance(val, (int, float)) and val < 0:
                    errors.append(f"{path}: 'pricing.{key}' must be non-negative")

    # logging (optional)
    logging_cfg = data.get("logging")
    if logging_cfg is not None:
        if not isinstance(logging_cfg, dict):
            errors.append(f"{path}: 'logging' must be an object")
        else:
            max_bytes = logging_cfg.get("max_log_bytes")
            if max_bytes is not None:
                if not isinstance(max_bytes, int):
                    errors.append(f"{path}: 'logging.max_log_bytes' must be an integer")
                elif max_bytes < 1024:
                    errors.append(f"{path}: 'logging.max_log_bytes' must be at least 1024")

            verbose = logging_cfg.get("verbose")
            if verbose is not None and not isinstance(verbose, bool):
                errors.append(f"{path}: 'logging.verbose' must be a boolean")

    # organization_profile (optional)
    org = data.get("organization_profile")
    if org is not None:
        if not isinstance(org, dict):
            errors.append(f"{path}: 'organization_profile' must be an object")
        else:
            enabled = org.get("enabled")
            if "enabled" not in org:
                errors.append(f"{path}: 'organization_profile.enabled' is required")
            elif not isinstance(enabled, bool):
                errors.append(f"{path}: 'organization_profile.enabled' must be a boolean")
            prof_path = org.get("path")
            if prof_path is not None and not isinstance(prof_path, str):
                errors.append(f"{path}: 'organization_profile.path' must be a string or null")
            default_preset = org.get("default_preset")
            if default_preset is not None and not isinstance(default_preset, str):
                errors.append(
                    f"{path}: 'organization_profile.default_preset' must be a string or null"
                )
            if enabled is True and not prof_path:
                errors.append(
                    f"{path}: 'organization_profile.enabled' is true but 'path' is null"
                )
            unknown_org = set(org.keys()) - {"enabled", "path", "default_preset"}
            if unknown_org:
                errors.append(
                    f"{path}: unknown keys in 'organization_profile': {sorted(unknown_org)}"
                )

    # Reject unknown top-level keys
    # JSON has no native comments. The committed config permits a top-level
    # "_comment" field for human guidance while still rejecting operational
    # keys the runtime would silently ignore.
    known_keys = {"_comment", "external_context", "pricing", "logging", "organization_profile"}
    unknown = set(data.keys()) - known_keys
    if unknown:
        errors.append(f"{path}: unknown top-level keys: {sorted(unknown)}")

    return errors


def _validate_requirements_config(data: Any, path: str) -> list[str]:
    """Validate the check-appsec-requirements skill config.json."""
    errors: list[str] = []

    if not isinstance(data, dict):
        return [f"{path}: root must be a JSON object"]

    rs = data.get("requirements_source")
    if rs is None:
        errors.append(f"{path}: missing required key 'requirements_source'")
    elif not isinstance(rs, dict):
        errors.append(f"{path}: 'requirements_source' must be an object")
    else:
        if "enabled" not in rs:
            errors.append(f"{path}: 'requirements_source.enabled' is required")
        elif not isinstance(rs["enabled"], bool):
            errors.append(f"{path}: 'requirements_source.enabled' must be a boolean")

        url = rs.get("requirements_yaml_url")
        if "requirements_yaml_url" not in rs:
            errors.append(f"{path}: 'requirements_source.requirements_yaml_url' is required")
        elif url is not None and not isinstance(url, str):
            errors.append(f"{path}: 'requirements_source.requirements_yaml_url' must be a string or null")
        elif isinstance(url, str):
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                errors.append(
                    f"{path}: 'requirements_source.requirements_yaml_url' must be a valid http:// or https:// URL with a host"
                )

        # Warn if enabled=true but no URL configured (requirements will fail without cache)
        if isinstance(rs.get("enabled"), bool) and rs["enabled"] and rs.get("requirements_yaml_url") is None:
            errors.append(
                f"{path}: 'requirements_source.enabled' is true but "
                f"'requirements_yaml_url' is null — threat models will fail "
                f"unless a plugin cache exists. Set a URL or set enabled to false."
            )

    return errors


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    # Determine plugin root
    if len(sys.argv) > 1:
        plugin_root = Path(sys.argv[1])
    elif os.environ.get("CLAUDE_PLUGIN_ROOT"):
        plugin_root = Path(os.environ["CLAUDE_PLUGIN_ROOT"])
    else:
        plugin_root = Path(__file__).resolve().parent.parent

    all_errors: list[str] = []

    # Validate main config.json
    main_config = plugin_root / "config.json"
    if main_config.exists():
        try:
            with main_config.open() as f:
                data = json.load(f)
            all_errors += _validate_main_config(data, str(main_config))
        except json.JSONDecodeError as e:
            all_errors.append(f"{main_config}: invalid JSON: {e}")
    else:
        all_errors.append(f"{main_config}: file not found")

    # Validate requirements skill config
    req_config = plugin_root / "skills" / "check-appsec-requirements" / "config.json"
    if req_config.exists():
        try:
            with req_config.open() as f:
                data = json.load(f)
            all_errors += _validate_requirements_config(data, str(req_config))
        except json.JSONDecodeError as e:
            all_errors.append(f"{req_config}: invalid JSON: {e}")
    else:
        all_errors.append(f"{req_config}: file not found")

    if all_errors:
        for e in all_errors:
            print(f"INVALID: {e}")
        sys.exit(1)
    else:
        print("VALID: all configuration files pass schema validation")
        sys.exit(0)


if __name__ == "__main__":
    main()
