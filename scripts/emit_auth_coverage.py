#!/usr/bin/env python3
"""emit_auth_coverage.py — guarantee §7.2 covers all canonical auth mechanisms.

The Phase-8 analyst catalogs ``security_controls[]`` free-hand and routinely
omits authentication variants the application actually exposes. On the
2026-06-06 juice-shop run, OAuth social login, user registration, and password
reset were all present in code — two of them anchoring Critical findings (OAuth
implicit flow F-003, registration mass-assignment F-007) — yet none were
cataloged, so §7.2 Identity & Authentication listed only Password + MFA.

§7.2 must ALWAYS identify, describe, and rate the full authentication surface:
  • every auth *method* the app offers (password login, MFA, social/OAuth, …), and
  • the password-credential *lifecycle* (registration, password reset).

This emitter backfills ``security_controls[]`` with any canonical auth mechanism
the catalog is missing, detected deterministically from ``.route-inventory.json``
and the repository:

  • a DETECTED-but-uncataloged mechanism is added with ``kind: mechanism`` so the
    §7 renderer emits a flow sub-block (with a sequenceDiagram) and rates it from
    the worst linked finding (Critical/High → Unsafe, Medium/Low → Weak, none →
    Partial "present, not individually assessed");
  • a lifecycle-required aspect (registration, password reset) that is genuinely
    ABSENT while password authentication is present is recorded
    ``effectiveness: Missing`` (``kind: lifecycle``) so the gap is explicit rather
    than silent.

Optional auth variants (social login, MFA) are NOT fabricated when absent — their
absence is not a defect. Idempotent: prior ``auto_source == "auth-coverage"`` rows
are stripped before recompute.

Usage:
    python3 emit_auth_coverage.py <output_dir> [--repo-root <path>]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

# Domain string the §7 renderer groups the Identity & Authentication section on
# (matches the value Phase-8 already uses for password/MFA controls).
_IAM_DOMAIN = "Identity and Authentication"

# Canonical auth mechanisms §7.2 must always account for. Each:
#   control            — canonical display name (also the §7 sub-block title)
#   coverage_re        — an existing control "already covers this" if its name matches
#   route_re           — route-inventory path signal of presence
#   repo_globs         — repo file-name signals (SPA/front-end flows have no route)
#   finding_re         — link findings whose title/evidence.file matches
#   lifecycle_required — when absent under password auth, record effectiveness:Missing
_MECHANISMS: list[dict] = [
    {
        "key": "password_login",
        "control": "Password-Based Login",
        "coverage_re": r"password.*(login|auth)|(login|auth).*password|credential",
        "route_re": r"/login\b|/signin\b|/sign-in\b|/session\b",
        "repo_globs": (),
        "finding_re": r"password|login|credential|brute",
        "lifecycle_required": False,
    },
    {
        "key": "registration",
        "control": "User Registration",
        "coverage_re": r"regist|sign[\s_-]?up|account creation",
        "route_re": r"/register\b|/signup\b|/sign-up\b|/api/users?\b|/accounts?\b",
        "repo_globs": (),
        "finding_re": r"regist|mass.?assign|/api/users",
        "lifecycle_required": True,
    },
    {
        "key": "password_reset",
        "control": "Password Reset",
        "coverage_re": r"reset|forgot|recover|security.question",
        "route_re": r"reset.?password|forgot|recover|security-question",
        "repo_globs": ("**/*[rR]eset[pP]assword*",),
        "finding_re": r"reset|forgot|recover|security.question",
        "lifecycle_required": True,
    },
    {
        "key": "mfa",
        "control": "Multi-Factor Authentication",
        "coverage_re": r"multi.?factor|\bmfa\b|\b2fa\b|two.factor|totp|authenticator",
        "route_re": r"/2fa\b|/totp\b|/mfa\b|second.factor",
        "repo_globs": (),
        "finding_re": r"\bmfa\b|\b2fa\b|totp|multi.?factor|two.factor",
        "lifecycle_required": False,
    },
    {
        "key": "social_login",
        "control": "Social Login (OAuth / OIDC)",
        "coverage_re": r"oauth|oidc|social|federated|\bsso\b|openid|saml",
        "route_re": r"/oauth\b|/oidc\b|/saml\b|/auth/(google|github|facebook|microsoft|apple)",
        "repo_globs": ("**/*oauth*", "**/*openid*", "**/*[sS][aA][mM][lL]*"),
        "finding_re": r"oauth|oidc|openid|social|federated|\bsso\b|saml",
        "lifecycle_required": False,
    },
]

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".angular", "vendor"}
_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _existing_covers(controls: list, coverage_re: str) -> bool:
    rx = re.compile(coverage_re, re.IGNORECASE)
    for c in controls:
        if not isinstance(c, dict):
            continue
        name = str(c.get("control") or c.get("name") or "")
        if rx.search(name):
            return True
    return False


def _route_evidence(routes: list, route_re: str) -> str | None:
    rx = re.compile(route_re, re.IGNORECASE)
    for r in routes:
        if not isinstance(r, dict):
            continue
        path = str(r.get("path") or "")
        if rx.search(path):
            return f"{r.get('method', '?')} {path}"
    return None


def _repo_evidence(repo_root: Path | None, globs: tuple) -> str | None:
    if not repo_root or not globs:
        return None
    for pattern in globs:
        try:
            for hit in repo_root.glob(pattern):
                parts = set(hit.relative_to(repo_root).parts)
                if parts & _SKIP_DIRS:
                    continue
                if hit.is_file() or hit.is_dir():
                    return str(hit.relative_to(repo_root))
        except (OSError, ValueError):
            continue
    return None


def _linked_findings(threats: list, finding_re: str) -> tuple[list[str], str]:
    """Return (threat_ids, worst_severity) for threats matching the mechanism."""
    rx = re.compile(finding_re, re.IGNORECASE)
    ids: list[str] = []
    worst = ""
    worst_rank = 0
    for t in threats:
        if not isinstance(t, dict):
            continue
        ev = t.get("evidence") or {}
        ev_file = ev.get("file", "") if isinstance(ev, dict) else ""
        blob = f"{t.get('title', '')} {ev_file} {t.get('component', '')}"
        if rx.search(blob):
            tid = t.get("id") or t.get("t_id")
            if tid:
                ids.append(str(tid))
            sev = str(t.get("risk") or t.get("severity") or "").lower()
            if _SEV_ORDER.get(sev, 0) > worst_rank:
                worst_rank, worst = _SEV_ORDER.get(sev, 0), sev
    return ids, worst


def _effectiveness_for(worst_sev: str, has_finding: bool) -> str:
    if not has_finding:
        return "Partial"  # present, not individually assessed
    if worst_sev in ("critical", "high"):
        return "Unsafe"  # present and relied upon but defeated
    return "Weak"


def build_auth_coverage(yaml_data: dict, routes: list, repo_root: Path | None) -> tuple[list[dict], list[str]]:
    """Return (new_control_rows, notes) to append to security_controls[]."""
    controls = yaml_data.get("security_controls") or []
    threats = yaml_data.get("threats") or []
    notes: list[str] = []

    # Is password authentication present at all? (gates the lifecycle-Missing rows)
    pw = next((m for m in _MECHANISMS if m["key"] == "password_login"), None)
    password_present = (
        bool(_existing_covers(controls, pw["coverage_re"]) or _route_evidence(routes, pw["route_re"])) if pw else False
    )

    additions: list[dict] = []
    for m in _MECHANISMS:
        if _existing_covers(controls, m["coverage_re"]):
            continue  # analyst already cataloged an equivalent control

        route_ev = _route_evidence(routes, m["route_re"])
        repo_ev = _repo_evidence(repo_root, m.get("repo_globs", ()))
        evidence = route_ev or repo_ev
        detected = evidence is not None

        if detected:
            ids, worst = _linked_findings(threats, m["finding_re"])
            eff = _effectiveness_for(worst, bool(ids))
            row = {
                "domain": _IAM_DOMAIN,
                "control": m["control"],
                "kind": "mechanism",
                "effectiveness": eff,
                "implementation": f"Detected in scope: {evidence}",
                "evidence": evidence,
                "main_reason": (
                    f"{m['control']} is present but was not in the Phase-8 control "
                    f"catalog; rated from linked finding(s)."
                    if ids
                    else f"{m['control']} is present in scope but was not individually assessed — review required."
                ),
                "auto_source": "auth-coverage",
            }
            if ids:
                row["linked_threats"] = ids
            additions.append(row)
            notes.append(
                f"auth-coverage: added '{m['control']}' (detected: {evidence}; "
                f"effectiveness={eff}; findings={ids or '—'})"
            )
        elif m["lifecycle_required"] and password_present:
            additions.append(
                {
                    "domain": _IAM_DOMAIN,
                    "control": m["control"],
                    "kind": "lifecycle",
                    "effectiveness": "Missing",
                    "implementation": None,
                    "evidence": "No endpoint detected in scope",
                    "main_reason": (
                        f"{m['control']} is an expected lifecycle control for "
                        f"password-based authentication but no endpoint was found — "
                        f"confirm whether the flow exists or is genuinely absent."
                    ),
                    "auto_source": "auth-coverage",
                }
            )
            notes.append(f"auth-coverage: added '{m['control']}' as Missing (lifecycle-required, not detected)")
        # else: optional variant, genuinely absent → do not fabricate.

    return additions, notes


def apply(output_dir: Path, repo_root: Path | None) -> int:
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_auth_coverage: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"emit_auth_coverage: parse failed: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        return 1

    routes = []
    inv = output_dir / ".route-inventory.json"
    if inv.is_file():
        try:
            raw = json.loads(inv.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("routes"), list):
                routes = raw["routes"]
        except (ValueError, OSError):
            routes = []

    controls = data.get("security_controls")
    if not isinstance(controls, list):
        controls = []
    # Idempotent: strip prior auto-emitted rows before recompute.
    controls = [c for c in controls if not (isinstance(c, dict) and c.get("auto_source") == "auth-coverage")]

    data["security_controls"] = controls
    additions, notes = build_auth_coverage(data, routes, repo_root)
    if not additions:
        print("emit_auth_coverage: all canonical auth mechanisms already covered")
        # Still rewrite to persist the strip of stale auto rows (idempotent).
        yaml_path.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
            encoding="utf-8",
        )
        return 0

    controls.extend(additions)
    yaml_path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
        encoding="utf-8",
    )
    for n in notes:
        print(n)
    print(f"emit_auth_coverage: appended {len(additions)} auth-coverage control(s)")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="emit_auth_coverage.py")
    ap.add_argument("output_dir", type=Path)
    ap.add_argument("--repo-root", type=Path, default=None)
    args = ap.parse_args(argv)
    return apply(args.output_dir, args.repo_root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
