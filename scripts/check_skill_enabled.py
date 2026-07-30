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

The policy is read from two places, in this order:

1. ``$OUTPUT_DIR/.org-profile-effective.json`` — what the current run resolved,
   including preset and CLI effects. Authoritative while a run exists.
2. ``skill_toggles`` in the packaged ``config.json`` — what the build was
   packaged with.

The second source is what makes the gate work at all for the skills people
reach first. The effective file is written by a create-threat-model run into
its output directory, so before any scan has happened there was no policy to
find and every skill fell through to enabled — a control that reported itself
as active in ``status`` output while enforcing nothing. Packaging now resolves
the policy into ``config.json`` the way it already does for the banner and the
baseline, so a fresh clone gets the same answer as a scanned one.

With neither source the script falls through to ``enabled``, preserving the
upstream path where no org profile is active.
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


def _plugin_root() -> Path:
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        return Path(root)
    return Path(__file__).resolve().parent.parent


def _packaged_toggles() -> dict:
    """``skill_toggles`` resolved into config.json at package time.

    ``config.local.json`` wins when present, as everywhere else in the plugin.
    Any read or parse failure yields no policy, so a damaged config cannot
    block a skill the organization never restricted.
    """
    root = _plugin_root()
    local = root / "config.local.json"
    path = local if local.is_file() else root / "config.json"
    try:
        with open(path, encoding="utf-8") as fh:
            toggles = json.load(fh).get("skill_toggles")
    except Exception:  # noqa: BLE001
        return {}
    return toggles if isinstance(toggles, dict) else {}


def resolve_toggles(output_dir: Path | None) -> tuple[dict, str]:
    """Return the active skill policy and where it came from.

    A resolved run wins over the packaged default: it reflects the preset and
    CLI options this run actually resolved, which the build-time copy cannot
    know.
    """
    effective = _load_effective(output_dir)
    if effective is not None and effective.get("org_profile", {}).get("active"):
        return effective.get("skill_toggles") or {}, "org profile"
    return _packaged_toggles(), "packaged build"


def check(skill: str, output_dir: Path | None, help_only: bool) -> tuple[int, str]:
    toggles, source = resolve_toggles(output_dir)
    if not toggles:
        return EXIT_ENABLED, f"{skill}: no skill policy in effect; default enabled"

    cfg = toggles.get(skill)
    if cfg is None:
        return EXIT_ENABLED, f"{skill}: enabled ({source})"
    if isinstance(cfg, bool):
        # Tolerate raw bool entries written by a non-normalised caller —
        # err open if the value is unexpected.
        if cfg:
            return EXIT_ENABLED, f"{skill}: enabled ({source})"
        cfg = {"enabled": False, "reason": None}
    if cfg.get("enabled", True):
        return EXIT_ENABLED, f"{skill}: enabled ({source})"

    # Which source disabled it is the first thing anyone asks, and the two are
    # fixed in different places — the org profile for a run, the packaged
    # config for a build.
    reason = cfg.get("reason") or "no reason provided"
    if help_only:
        return EXIT_DISABLED_HELP_OK, f"{skill}: disabled by {source} — help only ({reason})"
    if skill in OPERATIONAL_SKILLS:
        return EXIT_DISABLED_SOFT, f"{skill}: disabled by {source} (soft, operational) — {reason}"
    return EXIT_DISABLED_HARD, f"{skill}: disabled by {source} — {reason}"


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
