#!/usr/bin/env python3
"""check_skill_enabled.py — early gate for org-profile skill toggles.

Each user-facing skill calls this once at the top of ``SKILL.md`` (or its
preflight section):

    python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_skill_enabled.py" <skill-name>

Exit codes mirror the plan's "soft-disable" semantics:

    0  — enabled (or no org profile active → fall through to default)
    10 — disabled but ``--help`` should still render
    20 — disabled, operational/repair skill → warn but do not block
    30 — disabled hard (user-facing skill)

The script reads ``$OUTPUT_DIR/.org-profile-effective.json`` if present;
without it, it falls through to ``enabled`` so the legacy code path is
preserved when no org profile is active.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

EXIT_ENABLED = 0
EXIT_DISABLED_HELP_OK = 10
EXIT_DISABLED_SOFT = 20
EXIT_DISABLED_HARD = 30

# Operational / repair skills only warn — disabling them hard would
# defeat the user's ability to recover from a broken state.
OPERATIONAL_SKILLS = {
    "status",
    "check-permissions",
    "clean-run-state",
    "fix-run-issues",
    "threat-model-health",
}


def _load_effective(output_dir: Path | None) -> dict | None:
    if output_dir is None:
        return None
    candidate = output_dir / ".org-profile-effective.json"
    if not candidate.exists():
        return None
    try:
        return json.loads(candidate.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def check(skill: str, output_dir: Path | None, help_only: bool) -> tuple[int, str]:
    effective = _load_effective(output_dir)
    if effective is None or not effective.get("org_profile", {}).get("active"):
        return EXIT_ENABLED, f"{skill}: no active org profile; default enabled"

    toggles = effective.get("skill_toggles") or {}
    cfg = toggles.get(skill)
    if cfg is None:
        return EXIT_ENABLED, f"{skill}: enabled by org profile"
    if isinstance(cfg, bool):
        # Tolerate raw bool entries written by a non-normalised caller —
        # err open if the value is unexpected.
        if cfg:
            return EXIT_ENABLED, f"{skill}: enabled by org profile"
        cfg = {"enabled": False, "reason": None}
    if cfg.get("enabled", True):
        return EXIT_ENABLED, f"{skill}: enabled by org profile"

    reason = cfg.get("reason") or "no reason provided"
    if help_only:
        return EXIT_DISABLED_HELP_OK, f"{skill}: disabled — help only ({reason})"
    if skill in OPERATIONAL_SKILLS:
        return EXIT_DISABLED_SOFT, f"{skill}: disabled (soft, operational) — {reason}"
    return EXIT_DISABLED_HARD, f"{skill}: disabled by org profile — {reason}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check whether a skill is enabled under the active org profile.")
    parser.add_argument("skill", help="user-facing skill name (e.g. export-threat-model)")
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR"),
        help="directory containing .org-profile-effective.json",
    )
    parser.add_argument(
        "--help-only",
        action="store_true",
        help="caller is rendering --help; emit help-OK exit code if disabled",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the explanatory message on stdout",
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir).resolve() if args.output_dir else None
    rc, message = check(args.skill, output_dir, args.help_only)
    if not args.quiet:
        print(message)
    return rc


if __name__ == "__main__":
    sys.exit(main())
