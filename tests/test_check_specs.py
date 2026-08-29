"""Guards for the separated product catalog and technical bindings."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_specs  # noqa: E402


def entry(
    rid: str = "REQ-XYZ-001",
    title: str = "A title",
    text: str = "The stable product requirement.",
) -> str:
    return f"# Plugin requirements\n\n## A section\n\n### {rid} — {title}\n\n{text}\n"


def binding_document(
    *,
    rid: str = "REQ-XYZ-001",
    applies: list[str] | None = None,
    decisions: list[str] | None = None,
    documents: list[str] | None = None,
    coverage: str = "direct",
    guards: list[str] | None = None,
    retired: list[str] | None = None,
) -> dict:
    return {
        "version": 1,
        "retired_ids": retired or [],
        "requirements": {
            rid: {
                "applies_to": applies or ["target.py"],
                "decisions": decisions or [],
                "documents": documents or [],
                "coverage": coverage,
                "guards": guards if guards is not None else ["tests/test_guard.py::test_rule"],
            }
        },
    }


@pytest.fixture
def catalog_root(tmp_path: Path) -> Path:
    (tmp_path / "target.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_guard.py").write_text("def test_rule():\n    pass\n", encoding="utf-8")
    (tmp_path / "docs" / "internal").mkdir(parents=True)
    (tmp_path / "docs" / "internal" / "decisions.md").write_text(
        "| ID | Decision | Guard | Rationale |\n|---|---|---|---|\n| XY-1 | A decision | test | reason |\n",
        encoding="utf-8",
    )
    return tmp_path


def problems(markdown: str, document: object, root: Path) -> list[str]:
    return check_specs.validate(check_specs.parse(markdown), document, root=root)


def test_shipped_catalog_and_bindings_are_valid():
    entries = check_specs.parse(check_specs.CATALOG.read_text(encoding="utf-8"))
    document = check_specs.load_binding_document()
    assert entries
    assert check_specs.validate(entries, document) == []


def test_parses_only_normative_text():
    parsed = check_specs.parse(entry())
    assert parsed == [
        check_specs.Entry(
            rid="REQ-XYZ-001",
            title="A title",
            section="A section",
            line=5,
            text="The stable product requirement.",
        )
    ]


def test_duplicate_id_is_rejected(catalog_root):
    doubled = entry() + entry(title="Another title").split("# Plugin requirements\n\n", 1)[1]
    assert any("duplicate id" in problem for problem in problems(doubled, binding_document(), catalog_root))


def test_missing_requirement_text_is_rejected(catalog_root):
    assert any(
        "no requirement text" in problem for problem in problems(entry(text=""), binding_document(), catalog_root)
    )


def test_implementation_metadata_is_rejected_from_catalog(catalog_root):
    markdown = entry(text="The promise.\n\n**Guard:** tests/test_guard.py::test_rule")
    assert any("implementation metadata" in problem for problem in problems(markdown, binding_document(), catalog_root))


def test_binding_schema_requires_every_field(catalog_root):
    document = binding_document()
    del document["requirements"]["REQ-XYZ-001"]["coverage"]
    assert any("coverage" in problem for problem in problems(entry(), document, catalog_root))


def test_active_requirement_requires_exactly_one_binding(catalog_root):
    document = binding_document(rid="REQ-XYZ-002")
    found = problems(entry(), document, catalog_root)
    assert any("missing binding" in problem for problem in found)
    assert any("inactive requirement" in problem for problem in found)


def test_retired_requirement_id_cannot_be_active(catalog_root):
    document = binding_document(retired=["REQ-XYZ-001"])
    assert any("also retired" in problem for problem in problems(entry(), document, catalog_root))


def test_exact_guard_node_must_exist(catalog_root):
    document = binding_document(guards=["tests/test_elsewhere.py::test_rule"])
    assert any("guard node does not exist" in problem for problem in problems(entry(), document, catalog_root))


def test_class_method_guard_node_is_resolved(catalog_root):
    (catalog_root / "tests" / "test_guard.py").write_text(
        "class TestRule:\n    def test_rule(self):\n        pass\n",
        encoding="utf-8",
    )
    document = binding_document(guards=["tests/test_guard.py::TestRule::test_rule"])
    assert problems(entry(), document, catalog_root) == []


def test_direct_and_partial_coverage_require_guards(catalog_root):
    for coverage in ("direct", "partial"):
        document = binding_document(coverage=coverage, guards=[])
        assert any("requires a guard" in problem for problem in problems(entry(), document, catalog_root))


def test_advisory_coverage_requires_an_empty_guard_list(catalog_root):
    document = binding_document(coverage="advisory")
    assert any("advisory coverage" in problem for problem in problems(entry(), document, catalog_root))
    document = binding_document(coverage="advisory", guards=[])
    assert problems(entry(), document, catalog_root) == []


def test_unknown_decision_is_rejected(catalog_root):
    document = binding_document(decisions=["ZZ-99"])
    assert any("unknown decision" in problem for problem in problems(entry(), document, catalog_root))


def test_known_decision_is_accepted(catalog_root):
    document = binding_document(decisions=["XY-1"])
    assert problems(entry(), document, catalog_root) == []


def test_missing_or_escaping_document_is_rejected(catalog_root):
    missing = binding_document(documents=["docs/missing.md"])
    assert any("document does not exist" in problem for problem in problems(entry(), missing, catalog_root))
    escaping = binding_document(documents=["../outside.md"])
    assert any("document escapes" in problem for problem in problems(entry(), escaping, catalog_root))


def test_applies_to_pattern_must_match(catalog_root):
    document = binding_document(applies=["scripts/missing.py"])
    assert any("matches nothing" in problem for problem in problems(entry(), document, catalog_root))


@pytest.mark.parametrize(
    "pattern",
    [
        "/etc/passwd",
        "../outside.py",
        "C:/outside.py",
        "https://example.invalid/file.py",
        r"scripts\outside.py",
    ],
)
def test_applies_to_pattern_must_be_repository_relative(catalog_root, pattern):
    document = binding_document(applies=[pattern])
    assert any("safe repository-relative" in problem for problem in problems(entry(), document, catalog_root))


def test_applicable_uses_external_bindings(catalog_root):
    entries = check_specs.parse(entry())
    bindings = check_specs.parse_bindings(binding_document(applies=["*.py"]))
    hits = check_specs.applicable(entries, bindings, "target.py", root=catalog_root)
    assert [(item.rid, binding.coverage) for item, binding in hits] == [("REQ-XYZ-001", "direct")]
    assert check_specs.applicable(entries, bindings, "README.md", root=catalog_root) == []


def test_applicable_ignores_paths_outside_repository(catalog_root):
    entries = check_specs.parse(entry())
    bindings = check_specs.parse_bindings(binding_document())
    assert check_specs.applicable(entries, bindings, "/etc/passwd", root=catalog_root) == []


def test_main_reports_requirement_and_coverage_counts(capsys):
    assert check_specs.main([]) == 0
    output = capsys.readouterr().out
    assert "28 requirements" in output
    assert "direct" in output and "partial" in output and "advisory" in output


def test_main_for_prints_governing_requirement_and_coverage(capsys):
    assert check_specs.main(["--for", "scripts/merge_threats.py"]) == 0
    output = capsys.readouterr().out
    assert "REQ-MOD-001" in output
    assert "Guard coverage: partial" in output


def test_main_for_unbound_file_says_no_requirement_is_bound(capsys):
    assert check_specs.main(["--for", "scripts/does_not_exist.py"]) == 0
    assert "No requirement is bound to scripts/does_not_exist.py." in capsys.readouterr().out


def test_held_file_without_changed_proposal_is_unapproved():
    assert check_specs.unapproved_changes(["specs/requirements.md"]) == [
        "specs/requirements.md changed with no proposal under specs/changes/"
    ]


def test_held_file_with_changed_proposal_is_recorded():
    changed = [
        "docs/internal/decisions.md",
        "specs/changes/some-change/proposal.md",
    ]
    assert check_specs.unapproved_changes(changed) == []


def test_tasks_file_alone_is_not_a_change_proposal():
    changed = ["specs/requirements.md", "specs/changes/some-change/tasks.md"]
    assert check_specs.unapproved_changes(changed)


def test_ordinary_changes_need_no_proposal():
    assert check_specs.unapproved_changes(["scripts/merge_threats.py", "README.md"]) == []


def test_changed_against_unknown_ref_reports_and_exits_two(capsys):
    assert check_specs.main(["--changed-against", "no-such-ref-xyz"]) == 2
    assert capsys.readouterr().err


def test_invalid_binding_document_does_not_mutate_fixture(catalog_root):
    document = binding_document()
    original = copy.deepcopy(document)
    assert problems(entry(), document, catalog_root) == []
    assert document == original
