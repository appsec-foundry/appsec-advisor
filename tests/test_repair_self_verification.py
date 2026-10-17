"""A repair executor must self-verify with the command that decides about it.

`validators/qa_checks.py contract` runs only `check_contract` — section order/presence,
forbidden Management-Summary patterns, table column counts. `validators/qa_checks.py gate`
runs the autofix tail plus `cmd_repair_plan`, which appends roughly twenty
further structural checks to that report. Of the sixteen
`BLOCKING_ACTION_TYPES` that can dispatch `appsec-fragment-fixer`, only
`missing_section`, `missing_required_subsection` and `table_schema_drift`
originate in `check_contract`; the rest live exclusively in the additive half.

`agents/appsec-fragment-fixer.md` used to verify its own repair with
`contract` and declared "Exit 0 means the repair worked". On
owasp-vulnerableapp 2026-08-18 the fixer resolved an `auth_method_decomposition`
violation by renaming a §6.2 H4, which orphaned the `**Controls covered:**`
links pointing at the old heading. `contract` reported the document unchanged
and the agent reported success; the skill's own gate returned two
`control_subsection_coverage` issues. With `MAX_REPAIR_ITERATIONS=1` that false
positive consumed the only repair iteration.

Two properties are pinned here, both repository-independent:

1. `contract` is not a proxy for the gate — it cannot observe a defect the gate
   blocks on. This is a property of the scripts and holds for any document.
2. The agent contract therefore names `gate`, the same command the compact
   Stage-3 runtime uses to decide whether the repair loop has converged.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import validators.qa_checks as qa  # noqa: E402

# §6 stub in the shape `check_control_subsection_coverage` parses. The two
# variants differ ONLY in the anchor the `**Controls covered:**` line names —
# `CLEAN` points at the subsection that exists, `BROKEN` at one that does not,
# which is exactly what renaming an H4 without updating its cross-references
# produces.
_SEC6 = (
    "## 6. Security Architecture\n\n"
    "### 6.2 Identity and Authentication Controls\n\n"
    "**Controls covered:** [{label}](#{anchor})\n\n"
    "#### Password-Based Authentication\n\n"
    "**Security assessment**\n\nok\n\n"
    "**Relevant findings**\n\n- none\n\n"
    "## 8. X\n\ny\n"
)
CLEAN_MD = _SEC6.format(label="Password-Based Authentication", anchor="password-based-authentication")
BROKEN_MD = _SEC6.format(label="Login Credential Validation", anchor="login-credential-validation")


def _write(tmp_path: Path, name: str, content: str) -> Path:
    d = tmp_path / name
    d.mkdir()
    f = d / "threat-model.md"
    f.write_text(content, encoding="utf-8")
    return f


def test_contract_cannot_observe_a_defect_the_gate_blocks_on(tmp_path):
    """The reproduction: `contract` sees no difference, the gate blocks."""
    clean = _write(tmp_path, "clean", CLEAN_MD)
    broken = _write(tmp_path, "broken", BROKEN_MD)

    # 1. `check_contract` — what `validators/qa_checks.py contract` reports — is blind to
    #    the difference. Compared as a delta so the stub's own unrelated
    #    section-order issues cannot mask the assertion.
    assert qa.check_contract(clean).issues == qa.check_contract(broken).issues

    # 2. The additive check the gate runs is not blind to it.
    assert not qa.check_control_subsection_coverage(clean).issues
    broken_issues = qa.check_control_subsection_coverage(broken).issues
    assert any("no matching" in i for i in broken_issues)

    # 3. And it reaches the plan the Re-Render Loop decides on.
    plan, _ = qa.build_repair_plan(broken, broken.parent)
    types = {a.get("type") for a in plan.get("actions", [])}
    assert "control_subsection_coverage" in types
    assert plan["status"] == "fail"


def test_control_subsection_coverage_is_a_blocking_dispatch_reason():
    """The defect `contract` misses is one that starts a repair dispatch."""
    assert "control_subsection_coverage" in qa.BLOCKING_ACTION_TYPES


@pytest.mark.parametrize(
    "action_type",
    sorted(qa.BLOCKING_ACTION_TYPES - {"missing_section", "missing_required_subsection", "table_schema_drift"}),
)
def test_blocking_types_outside_check_contract_are_not_named_by_the_contract_check(action_type):
    """Every blocking type but the three contract-derived ones is additive.

    `check_contract` builds a single `Report("contract")`; the additive checks
    each build their own named report and are appended by `build_repair_plan`.
    A blocking type whose check lives outside `check_contract` therefore cannot
    be verified by `validators/qa_checks.py contract` at all.
    """
    assert hasattr(qa, "check_contract")
    src = (REPO_ROOT / "scripts" / "validators/qa_checks.py").read_text(encoding="utf-8")
    start = src.index("def check_contract(")
    end = src.index("\ndef ", start + 1)
    assert action_type not in src[start:end], (
        f"{action_type} now appears inside check_contract; if the contract check "
        "has genuinely absorbed it, update this test AND the exclusion list above"
    )
