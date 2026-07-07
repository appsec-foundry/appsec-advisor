"""Regression tests for final Markdown structure and TOC closure."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import qa_checks as qa
import yaml

REPO_ROOT = Path(__file__).parent.parent
QA_SCRIPT = REPO_ROOT / "scripts" / "qa_checks.py"


def _contract(tmp_path: Path) -> Path:
    path = tmp_path / "sections-contract.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "document": {"order": ["toc", "one", "two"]},
                "sections": {
                    "toc": {"heading": "## Table of Contents"},
                    "one": {"heading": "## 1. One"},
                    "two": {"heading": "## 2. Two"},
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def _report(tmp_path: Path) -> Path:
    path = tmp_path / "threat-model.md"
    path.write_text(
        """# Threat Model

## Table of Contents

1. [One](#1-one)
2. [Two](#2-two)

---

## 1. One

First section body.

## 2. Two

Second section body.
""",
        encoding="utf-8",
    )
    return path


def test_final_structure_accepts_exact_toc_and_substantive_sections(
    tmp_path: Path,
    capsys,
) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)

    assert qa.check_toc_contract(md, contract).issues == []
    assert qa.cmd_final_structure(md, contract) == 0
    assert '"issue_count": 0' in capsys.readouterr().out


def test_toc_contract_mirrors_final_em_dash_normalization(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    data = yaml.safe_load(contract.read_text(encoding="utf-8"))
    data["sections"]["two"]["heading"] = "## Appendix A — Taxonomy"
    contract.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    md = _report(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8")
        .replace("2. [Two](#2-two)", "- [Appendix A - Taxonomy](#appendix-a-taxonomy)")
        .replace("## 2. Two", "## Appendix A — Taxonomy"),
        encoding="utf-8",
    )

    assert qa.check_toc_contract(md, contract).issues == []


def test_missing_toc_entry_fails_even_when_remaining_links_resolve(
    tmp_path: Path,
) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8").replace("2. [Two](#2-two)\n", ""),
        encoding="utf-8",
    )

    assert qa.check_toc_closure(md).issues == []
    assert qa.check_toc_contract(md, contract).issues
    assert qa.cmd_final_structure(md, contract) == 1


def test_wrong_but_existing_toc_target_fails_contract(tmp_path: Path) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8").replace(
            "2. [Two](#2-two)",
            "2. [Two](#1-one)",
        ),
        encoding="utf-8",
    )

    assert qa.check_toc_closure(md).issues == []
    assert qa.check_toc_contract(md, contract).issues


def test_reordered_toc_entries_fail_contract(tmp_path: Path) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8").replace(
            "1. [One](#1-one)\n2. [Two](#2-two)",
            "2. [Two](#2-two)\n1. [One](#1-one)",
        ),
        encoding="utf-8",
    )

    assert qa.check_toc_contract(md, contract).issues


def test_duplicate_explicit_anchor_fails_toc_contract(tmp_path: Path) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8") + '\n<a id="duplicate"></a>\n<a id="duplicate"></a>\n',
        encoding="utf-8",
    )

    assert any("duplicate explicit anchor" in issue for issue in qa.check_toc_contract(md, contract).issues)


def test_duplicate_top_level_heading_fails_contract(tmp_path: Path) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8") + "\n## 2. Two\n\nDuplicate body.\n",
        encoding="utf-8",
    )

    assert any("duplicate section heading" in issue for issue in qa.check_contract(md, contract).issues)


def test_heading_only_top_level_section_fails_contract(tmp_path: Path) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)
    text = md.read_text(encoding="utf-8")
    md.write_text(text[: text.index("## 2. Two")] + "## 2. Two\n", encoding="utf-8")

    assert any("section has no substantive body" in issue for issue in qa.check_contract(md, contract).issues)


def test_referenced_required_subsection_must_exist_and_have_body(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    data = yaml.safe_load(contract.read_text(encoding="utf-8"))
    data["sections"]["one"]["required_subsections"] = ["details"]
    data["sections"]["details"] = {"heading": "### Required Details"}
    contract.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    md = _report(tmp_path)

    missing = qa.check_contract(md, contract)
    assert any("required subsection missing" in issue for issue in missing.issues)

    md.write_text(
        md.read_text(encoding="utf-8").replace(
            "First section body.",
            "First section body.\n\n### Required Details",
        ),
        encoding="utf-8",
    )
    qa._PrePass.reset()
    empty = qa.check_contract(md, contract)
    assert any("required subsection has no substantive body" in issue for issue in empty.issues)

    md.write_text(
        md.read_text(encoding="utf-8").replace(
            "### Required Details",
            "### Required Details\n\nConcrete details.",
        ),
        encoding="utf-8",
    )
    qa._PrePass.reset()
    assert not any("required subsection" in issue for issue in qa.check_contract(md, contract).issues)


def test_title_pattern_required_subsection_is_enforced(tmp_path: Path) -> None:
    contract = _contract(tmp_path)
    data = yaml.safe_load(contract.read_text(encoding="utf-8"))
    data["sections"]["one"]["required_subsections"] = [{"level": 3, "title_pattern": r"^1\.1 Details$"}]
    contract.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    md = _report(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8").replace(
            "First section body.",
            "First section body.\n\n### 1.1 Details\n\nConcrete details.",
        ),
        encoding="utf-8",
    )

    assert not any("required subsection" in issue for issue in qa.check_contract(md, contract).issues)

    md.write_text(
        md.read_text(encoding="utf-8").replace("### 1.1 Details", "### Wrong"),
        encoding="utf-8",
    )
    qa._PrePass.reset()
    assert any("required subsection missing" in issue for issue in qa.check_contract(md, contract).issues)


def test_heading_inside_code_fence_cannot_satisfy_required_subsection(
    tmp_path: Path,
) -> None:
    contract = _contract(tmp_path)
    data = yaml.safe_load(contract.read_text(encoding="utf-8"))
    data["sections"]["one"]["required_subsections"] = ["details"]
    data["sections"]["details"] = {"heading": "### Required Details"}
    contract.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    md = _report(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8").replace(
            "First section body.",
            "First section body.\n\n```markdown\n### Required Details\nFake.\n```",
        ),
        encoding="utf-8",
    )

    assert any("required subsection missing" in issue for issue in qa.check_contract(md, contract).issues)


def test_final_structure_cli_blocks_structural_mutation(tmp_path: Path) -> None:
    md = _report(tmp_path)
    contract = _contract(tmp_path)
    md.write_text(
        md.read_text(encoding="utf-8").replace("2. [Two](#2-two)\n", ""),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(QA_SCRIPT),
            "final_structure",
            str(md),
            str(contract),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert '"toc_contract"' in result.stdout
