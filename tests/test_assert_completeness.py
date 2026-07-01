"""Fail-closed tests for build and final-render completeness gates."""

from __future__ import annotations

from pathlib import Path

import assert_completeness as completeness


def _write_yaml(output_dir: Path, content: str) -> None:
    output_dir.mkdir(exist_ok=True)
    (output_dir / "threat-model.yaml").write_text(content, encoding="utf-8")


def _write_minimal_report(output_dir: Path, extra: str = "") -> None:
    (output_dir / "threat-model.md").write_text(
        """# Threat Model

## Management Summary

Summary body.

## 8. Findings Register

No findings.

## 10. Mitigation Register

No mitigations.
"""
        + extra,
        encoding="utf-8",
    )


def test_build_phase_accepts_valid_empty_model(
    tmp_path: Path,
    plugin_root: Path,
) -> None:
    _write_yaml(tmp_path, "threats: []\nmitigations: []\n")

    assert completeness.run(tmp_path, plugin_root, "build") == 0


def test_missing_contract_blocks(tmp_path: Path) -> None:
    _write_yaml(tmp_path, "threats: []\nmitigations: []\n")

    assert completeness.run(tmp_path, tmp_path / "missing-plugin", "build") == 2


def test_missing_yaml_blocks(tmp_path: Path, plugin_root: Path) -> None:
    assert completeness.run(tmp_path, plugin_root, "build") == 2


def test_malformed_yaml_blocks(tmp_path: Path, plugin_root: Path) -> None:
    _write_yaml(tmp_path, "threats: [\n")

    assert completeness.run(tmp_path, plugin_root, "build") == 2


def test_render_phase_requires_nonempty_markdown(
    tmp_path: Path,
    plugin_root: Path,
) -> None:
    _write_yaml(tmp_path, "threats: []\nmitigations: []\n")

    assert completeness.run(tmp_path, plugin_root, "render") == 2
    (tmp_path / "threat-model.md").write_text("", encoding="utf-8")
    assert completeness.run(tmp_path, plugin_root, "render") == 2


def test_render_phase_accepts_required_substantive_sections(
    tmp_path: Path,
    plugin_root: Path,
) -> None:
    _write_yaml(tmp_path, "threats: []\nmitigations: []\n")
    _write_minimal_report(tmp_path)

    assert completeness.run(tmp_path, plugin_root, "render") == 0


def test_ai_fragment_is_checked_at_render_phase(
    tmp_path: Path,
    plugin_root: Path,
) -> None:
    _write_yaml(
        tmp_path,
        """components:
  - id: chatbot
    name: LLM Chatbot
threats:
  - id: T-001
    title: Prompt injection reaches chatbot tools
    component: chatbot
    risk: High
mitigations: []
""",
    )
    _write_minimal_report(tmp_path, "\nF-001 concrete finding.\n")

    # Fragment completeness belongs to final rendering, not the YAML build gate.
    assert completeness.run(tmp_path, plugin_root, "build") == 0
    assert completeness.run(tmp_path, plugin_root, "render") == 2

    fragments = tmp_path / ".fragments"
    fragments.mkdir()
    (fragments / "ms-ai-exposure.json").write_text("{}\n", encoding="utf-8")
    report = tmp_path / "threat-model.md"
    report.write_text(
        report.read_text(encoding="utf-8") + "\n### AI / LLM Exposure\n",
        encoding="utf-8",
    )

    assert completeness.run(tmp_path, plugin_root, "render") == 2

    report.write_text(
        report.read_text(encoding="utf-8") + "\nConcrete AI exposure.\n",
        encoding="utf-8",
    )
    assert completeness.run(tmp_path, plugin_root, "render") == 0
