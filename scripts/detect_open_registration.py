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

import json
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


# authz_signal values from route_inventory.py that denote an explicit role
# gate (decorator / middleware). Their presence on a `/users`-shaped POST is
# the signal that the route is an *admin* create-user endpoint, not public
# self-registration — so it must NOT count as open registration. Anything
# else ("unknown", "none", absent) is treated as no role gate.
_AUTHZ_GATE_SIGNALS = {"decorator_present", "middleware_present"}


def _route_is_open_registration(route: dict) -> bool:
    """True when a `.route-inventory.json` entry is a public self-registration POST.

    The route inventory only ever emits ``authn_signal ∈ {unknown,
    middleware_present}`` and cannot distinguish *authentication* middleware
    from rate-limit / challenge / body-parser middleware. On a registration
    endpoint ``middleware_present`` is therefore an unreliable "authenticated"
    signal (juice-shop's ``POST /api/Users`` carries ``registerAdminChallenge``
    middleware yet is fully open). A registration endpoint that genuinely
    required prior authentication would be a semantic contradiction — you
    cannot be logged in before you have an account. So the authn signal is
    deliberately ignored here; the only suppressors are signals that the route
    is an *admin* user-create endpoint rather than self-registration:

      * ``management_surface`` truthy — flagged as an admin/management route, or
      * ``authz_signal`` in {decorator_present, middleware_present} — an
        explicit role gate guards it.
    """
    if str(route.get("method", "")).upper() != "POST":
        return False
    if not _is_registration_entry(str(route.get("path", "") or "")):
        return False
    if route.get("management_surface"):
        return False
    if str(route.get("authz_signal", "") or "") in _AUTHZ_GATE_SIGNALS:
        return False
    return True


def detect(yaml_data: dict, routes: list | None = None) -> tuple[bool, str]:
    """Returns (open_registration, reason). The reason is a short
    human-readable string for the audit log.

    ``routes`` is the optional ``.route-inventory.json`` ``routes[]`` list. It
    is consulted only as a fallback when ``attack_surface[]`` carries no
    registration entry — ``attack_surface[]`` is a curated subset (often
    capped), so a real registration route can be absent from it while present
    in the full inventory. This closed the 2026-06-06 juice-shop miss where
    ``POST /api/Users`` was in the 112-route inventory but not in the 23
    curated attack-surface rows, so the heatmap actor-collapse never fired.
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

    # Fallback — attack_surface[] had nothing; consult the full route inventory.
    for route in routes or []:
        if isinstance(route, dict) and _route_is_open_registration(route):
            return True, (
                f"registration route in .route-inventory.json: "
                f"POST {route.get('path')}"
            )
    return False, "no unauthenticated registration route found in attack_surface[] or route inventory"


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

    # Load the full route inventory (fallback source when attack_surface[] is
    # a curated subset that dropped the registration route). Best-effort.
    routes: list = []
    inv_path = Path(argv[0]) / ".route-inventory.json"
    if inv_path.is_file():
        try:
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            if isinstance(inv, dict) and isinstance(inv.get("routes"), list):
                routes = inv["routes"]
        except (ValueError, OSError):
            routes = []

    open_reg, reason = detect(data, routes)
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
