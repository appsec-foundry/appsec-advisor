from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import validate_threat_modeling_context as contract  # noqa: E402


def _valid_context() -> str:
    headings = contract.required_headings()
    sections = [
        headings[0],
        "",
        headings[1],
        "",
        '<untrusted-data source="test">',
        "repository context",
        "</untrusted-data>",
    ]
    for heading in headings[2:]:
        sections.extend(("", heading, "", f"Content for {heading}."))
    return "\n".join(sections) + "\n"


def test_valid_context_passes_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    original = _valid_context()
    path.write_text(original, encoding="utf-8")

    contract.validate_threat_modeling_context(path)
    assert contract.repair_missing_headings(path) == ()
    assert path.read_text(encoding="utf-8") == original


def test_optional_level3_template_headings_are_not_contract_sections() -> None:
    headings = contract.required_headings()

    assert "## Cross-Repository Dependency Threat Models" in headings
    assert not any(heading.startswith("### ") for heading in headings)


def test_missing_level2_heading_is_inserted_at_canonical_position(tmp_path: Path) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    missing = "## Architecture Decisions (ADRs)"
    path.write_text(_valid_context().replace(f"\n{missing}\n\nContent for {missing}.\n", "\n"), encoding="utf-8")

    assert contract.repair_missing_headings(path) == (missing,)

    repaired = path.read_text(encoding="utf-8")
    assert repaired.index("## Data Model Summary") < repaired.index(missing)
    assert repaired.index(missing) < repaired.index("## Environment & Configuration")
    assert "No context was emitted for this section." in repaired
    contract.validate_threat_modeling_context(path)


def test_required_heading_inside_untrusted_data_does_not_satisfy_contract(tmp_path: Path) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    missing = "## Architecture Decisions (ADRs)"
    context = _valid_context().replace(f"\n{missing}\n\nContent for {missing}.\n", "\n")
    context = context.replace("repository context", f"repository context\n{missing}\nrepo-authored text")
    path.write_text(context, encoding="utf-8")

    assert contract.repair_missing_headings(path) == (missing,)
    assert path.read_text(encoding="utf-8").count(missing) == 2
    contract.validate_threat_modeling_context(path)


def test_reordered_sections_are_rejected_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    original = _valid_context()
    left = "## API Surface"
    right = "## Deployment Topology"
    reordered = original.replace(left, "TEMP", 1).replace(right, left, 1).replace("TEMP", right, 1)
    path.write_text(reordered, encoding="utf-8")

    with pytest.raises(contract.ThreatModelingContextValidationError, match="reorders required headings"):
        contract.repair_missing_headings(path)
    assert path.read_text(encoding="utf-8") == reordered


def test_malformed_fences_are_rejected_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    malformed = _valid_context().replace("</untrusted-data>", "")
    path.write_text(malformed, encoding="utf-8")

    with pytest.raises(contract.ThreatModelingContextValidationError, match="fences"):
        contract.repair_missing_headings(path)
    assert path.read_text(encoding="utf-8") == malformed


def test_missing_root_heading_is_not_repaired(tmp_path: Path) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    path.write_text(_valid_context().replace("# Threat Modeling Context\n", "", 1), encoding="utf-8")

    with pytest.raises(contract.ThreatModelingContextValidationError, match="missing root heading"):
        contract.repair_missing_headings(path)


def test_byte_cap_is_enforced_before_repair(tmp_path: Path) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    path.write_text(_valid_context(), encoding="utf-8")

    with pytest.raises(contract.ThreatModelingContextValidationError, match="byte cap"):
        contract.repair_missing_headings(path, max_bytes=10)


def test_cli_repairs_then_validates(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / ".threat-modeling-context.md"
    missing = "## Architecture Decisions (ADRs)"
    path.write_text(_valid_context().replace(f"\n{missing}\n\nContent for {missing}.\n", "\n"), encoding="utf-8")

    assert contract.main(["--repair-missing-headings", str(path)]) == 0
    output = capsys.readouterr().out
    assert "REPAIRED:" in output
    assert "VALID: threat-modeling-context-markdown-v1" in output
