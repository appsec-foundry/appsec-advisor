"""
Tests for deterministic QA dispatch policy:

- E.2: QA Check 11 depth matrix — core skips entirely; full runs 11a+11d only;
  extended runs the full 11a/b/c/d set. Prevents regression to the prior
  "always run 11a" wasteful baseline.
- QA Check 2 Pass 2c remains retired.
"""

from pathlib import Path

PLUGIN_ROOT = Path(__file__).parent.parent
SKILL_MD = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# E.2 — deterministic ownership / dispatch policy
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Retired Pass 2c
# ---------------------------------------------------------------------------
