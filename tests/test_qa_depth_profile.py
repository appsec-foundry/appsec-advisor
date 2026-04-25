"""
Tests for Sprint 1 Item E.2 + E.3:

- E.2: QA Check 11 depth matrix — core skips entirely; full runs 11a+11d only;
  extended runs the full 11a/b/c/d set. Prevents regression to the prior
  "always run 11a" wasteful baseline.
- E.3: QA Check 2 Pass 2c must be opt-in via --qa-scan-repo / QA_SCAN_REPO=true.
  The old 5-ref threshold auto-trigger is gone.
"""

import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parent.parent
QA_REVIEWER = PLUGIN_ROOT / "agents" / "appsec-qa-reviewer.md"
SKILL_MD = PLUGIN_ROOT / "skills" / "create-threat-model" / "SKILL.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# E.2 — QA Check 11 depth matrix
# ---------------------------------------------------------------------------

CHECK_11_ROW_RE = re.compile(
    r"^\|\s*11\. Badges & mitigation schema\s*\|\s*(?P<core>[^|]+?)\s*\|\s*"
    r"(?P<full>[^|]+?)\s*\|\s*(?P<extended>[^|]+?)\s*\|",
    re.MULTILINE,
)


def parse_check_11_row() -> dict[str, str]:
    m = CHECK_11_ROW_RE.search(_read(QA_REVIEWER))
    assert m, "Could not find Check 11 row in QA_DEPTH matrix"
    return {k: v.strip() for k, v in m.groupdict().items()}


class TestCheck11DepthProfile:
    def test_core_skips_check_11(self):
        row = parse_check_11_row()
        assert row["core"].lower() == "skip", (
            f"Check 11 at core depth should be 'Skip' (Phase-11 render hard-gate "
            f"handles badge correctness pre-QA); got {row['core']!r}"
        )

    def test_full_runs_11a_plus_11d_only(self):
        row = parse_check_11_row()
        cell = row["full"]
        assert "11a" in cell and "11d" in cell, (
            f"Check 11 at full should include 11a+11d; got {cell!r}"
        )
        assert "11b" not in cell and "11c" not in cell, (
            f"Check 11 at full should NOT include 11b/11c (schema-redundant "
            f"with Phase-11 render hard-gate); got {cell!r}"
        )

    def test_extended_runs_all_four(self):
        row = parse_check_11_row()
        cell = row["extended"]
        for sub in ("11a", "11b", "11c", "11d"):
            assert sub in cell, (
                f"Check 11 at extended must include {sub}; got {cell!r}"
            )

    def test_rationale_is_documented(self):
        """The depth-profile rationale must be documented so future contributors
        understand why core skips and full omits 11b/11c."""
        text = _read(QA_REVIEWER)
        assert "Rationale for Check 11 depth profile" in text, (
            "Rationale for the Check 11 depth profile must be documented "
            "in the agent prompt (not only in git history)"
        )


# ---------------------------------------------------------------------------
# E.3 — Pass 2c opt-in via --qa-scan-repo
# ---------------------------------------------------------------------------

class TestPass2cOptIn:
    def test_skill_documents_qa_scan_repo_flag(self):
        text = _read(SKILL_MD)
        assert "--qa-scan-repo" in text, (
            "SKILL.md must document the --qa-scan-repo flag in the Argument "
            "Parsing table"
        )
        assert "QA_SCAN_REPO=true" in text, (
            "SKILL.md must bind --qa-scan-repo to QA_SCAN_REPO=true"
        )

    def test_qa_reviewer_pass_2c_section_removed(self):
        """As of 2026-04 the Pass 2c proactive repo-scan was removed
        entirely — the `QA_SCAN_REPO` env var was never set in
        production and the `find`-traversal cost was disproportionate
        to the marginal coverage it added.

        This test guards against accidental reintroduction: neither the
        section heading nor the gating env var should reappear in the
        agent prompt. If a future iteration brings it back, change this
        test to assert the new contract.
        """
        text = _read(QA_REVIEWER)
        assert "### Pass 2c — Proactive repo scan" not in text, (
            "qa-reviewer.md should not reintroduce Pass 2c — see the "
            "2026-04 removal note inline in the agent file."
        )
        assert "QA_SCAN_REPO=true" not in text, (
            "qa-reviewer.md must not reference QA_SCAN_REPO — Pass 2c "
            "was retired."
        )
        assert not re.search(
            r"combined total from Passes 2a and 2b is fewer than 5", text
        ), (
            "qa-reviewer.md must not reintroduce the old 'fewer than 5' "
            "auto-trigger for Pass 2c."
        )
