#!/usr/bin/env python3
"""Detect whether the app under analysis has open user self-registration.

Scans `threat-model.yaml → attack_surface[]` for an unauthenticated entry
that creates user accounts. The signal flips the heatmap-actor collapse
rule in `compose_threat_model.py:_build_actor_cards`: when open registration
is present, the spectrum `internet-anon → internet-user → internet-priv-user`
collapses to a single attacker on the heatmap card column, because reaching
the "authenticated" position takes one HTTP POST.

Detection pattern: `attack_surface[].entry_point` matches one of the common
registration paths AND `auth_required` is False/None.

Common patterns:
  POST /register, /signup, /sign-up
  POST /api/users, /users
  POST /accounts, /api/accounts
  POST /auth/register, /auth/signup
  POST /rest/user/register, /api/v*/users

Writes the result to `threat-model.yaml → meta.open_user_registration`.
An operator override `meta.open_user_registration_pinned: true|false`
takes precedence and is preserved across re-runs.

Usage:
    python3 detect_open_registration.py <output_dir>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


# Patterns that mark a route as user-registration. Case-insensitive.
# Anchored loosely — `/api/v2/users` should match `/users`.
_REGISTRATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bregister\b", re.IGNORECASE),
    re.compile(r"\bsign[-_]?up\b", re.IGNORECASE),
    re.compile(r"/sign[-_]?up\b", re.IGNORECASE),
    re.compile(r"/users?\s*$", re.IGNORECASE),       # POST /users, /api/users
    re.compile(r"/accounts?\s*$", re.IGNORECASE),
    re.compile(r"/users?/create", re.IGNORECASE),
    re.compile(r"/auth/(register|signup)\b", re.IGNORECASE),
]


def _is_registration_entry(entry_point: str) -> bool:
    if not entry_point:
        return False
    # Strip the HTTP method prefix if present so the regex sees the URL.
    parts = entry_point.split(None, 1)
    url = parts[1] if len(parts) == 2 else entry_point
    # Only consider POST (or unspecified method).
    method = (parts[0] if len(parts) == 2 else "").upper()
    if method and method != "POST":
        return False
    return any(p.search(url) for p in _REGISTRATION_PATTERNS)


def detect(yaml_data: dict) -> tuple[bool, str]:
    """Returns (open_registration, reason). The reason is a short
    human-readable string for the audit log.
    """
    meta = yaml_data.get("meta") or {}
    pinned = meta.get("open_user_registration_pinned")
    if isinstance(pinned, bool):
        return pinned, f"pinned in meta (operator override = {pinned})"

    surface = yaml_data.get("attack_surface") or []
    for entry in surface:
        if not isinstance(entry, dict):
            continue
        ep = entry.get("entry_point") or ""
        auth = entry.get("auth_required")
        if _is_registration_entry(ep) and not auth:
            return True, f"unauthenticated registration route: {ep}"
    return False, "no unauthenticated registration route found in attack_surface[]"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: detect_open_registration.py <output_dir>", file=sys.stderr)
        return 2
    yaml_path = Path(argv[0]) / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"detect_open_registration: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"detect_open_registration: parse failed: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        return 1

    open_reg, reason = detect(data)
    meta = data.setdefault("meta", {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    meta["open_user_registration"] = open_reg
    data["meta"] = meta

    yaml_path.write_text(
        yaml.safe_dump(
            data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False
        ),
        encoding="utf-8",
    )
    print(f"detect_open_registration: open_user_registration={open_reg}  ({reason})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
