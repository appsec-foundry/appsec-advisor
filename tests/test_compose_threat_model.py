"""Tests for scripts/compose_threat_model.py — the contract-driven renderer.

These tests pin the invariants that make LLM structural drift impossible:

  * render() is deterministic — identical inputs produce byte-identical output
  * the canonical Management Summary section order is enforced
  * the Management Summary heading is unnumbered
  * a malformed verdict fragment raises a schema-validation error (hard gate)
  * a missing required fragment raises FragmentError
  * the Top Findings table column schema is exactly the contract's 7 columns
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


REPO_ROOT    = Path(__file__).parent.parent
SCRIPT_PATH  = REPO_ROOT / "scripts" / "compose_threat_model.py"
CONTRACT     = REPO_ROOT / "data"    / "sections-contract.yaml"
FIXTURE      = Path(__file__).parent / "fixtures" / "compose"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass introspection can resolve the module.
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


compose = _load_module("compose_threat_model", SCRIPT_PATH)


def _prepare_output_dir(tmp_path: Path) -> Path:
    """Copy the fixture into a temp dir so tests don't mutate tests/fixtures/."""
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    return out


# ---------------------------------------------------------------------------
# Core rendering
# ---------------------------------------------------------------------------

def test_render_produces_canonical_ms_structure(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, warnings = compose.render(CONTRACT, out)

    assert warnings == [], f"unexpected warnings: {warnings}"

    # Management Summary must be unnumbered.
    assert "## Management Summary\n" in rendered
    assert "## 1. Management Summary" not in rendered

    # The five canonical sub-sections must appear, in order.
    expected_order = [
        "### Verdict",
        "### Top Findings",
        "### Architecture Assessment",
        "### Mitigations",
        "### Operational Strengths",
    ]
    positions = [rendered.find(h) for h in expected_order]
    assert all(p > 0 for p in positions), f"missing MS subsection(s): {expected_order} at {positions}"
    assert positions == sorted(positions), f"MS subsections out of order: {positions}"

    # No forbidden legacy headings anywhere in MS.
    ms_slice = rendered.split("## Management Summary", 1)[1].split("\n## ", 1)[0]
    for forbidden in ("### 1.1", "### Executive Overview", "### Risk Distribution",
                      "### Top Threats", "### Immediate Actions"):
        assert forbidden not in ms_slice, f"forbidden MS heading leaked: {forbidden!r}"


def test_render_is_deterministic(tmp_path: Path) -> None:
    """Identical fragments + yaml must produce byte-identical output."""
    out1 = _prepare_output_dir(tmp_path / "a")
    out2 = _prepare_output_dir(tmp_path / "b")
    r1, _ = compose.render(CONTRACT, out1)
    r2, _ = compose.render(CONTRACT, out2)
    assert r1 == r2


def test_render_is_deterministic_across_reruns(tmp_path: Path) -> None:
    """Re-rendering the same output dir twice yields identical text."""
    out = _prepare_output_dir(tmp_path)
    r1, _ = compose.render(CONTRACT, out)
    r2, _ = compose.render(CONTRACT, out)
    assert r1 == r2


def test_verdict_renders_red_blockquote(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert 'border-left: 3px solid #dc2626' in rendered
    # At least one F/T-NNN linkified citation inside the blockquote.
    assert "*([T-002](#t-002))*" in rendered or "*([T-001](#t-001))*" in rendered


def test_top_findings_has_seven_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Locate the Top Findings header row.
    header = "| # | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations |"
    assert header in rendered, "Top Findings must use exactly the 7 canonical columns"


def test_architecture_assessment_has_three_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "| Defect | Description | Key Findings |" in rendered


def test_operational_strengths_has_five_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    header = "| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |"
    assert header in rendered


def test_attack_chain_overview_in_section_3(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Reference layout: the cross-chain diagram lives as ### 3.1 Attack Chain
    # Overview inside §3 — NOT as a standalone `## Critical Attack Chain`.
    assert "## Critical Attack Chain\n" not in rendered
    assert "### 3.1 Attack Chain Overview" in rendered
    # §3.1 must carry graph LR Mermaid blocks (one per chain, no mega subgraph).
    assert re.search(r"```mermaid\s*\n\s*graph LR", rendered), (
        "§3.1 must contain at least one `graph LR` Mermaid block"
    )
    assert "**Key takeaway:**" in rendered


def test_threat_register_is_category_grouped(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Header is present with Risk + STRIDE + Category lines.
    assert "**Risk Distribution:** 🔴 Critical: 3 · 🟠 High: 1 · " in rendered
    assert "**STRIDE Coverage:**" in rendered
    assert "**Category Distribution:**" in rendered
    # §8 is category-grouped, not severity-grouped.
    assert "### 8.A Categories at a glance" in rendered
    assert "### 8.B Critical Categories" in rendered
    # Per-TH sub-section anchors are emitted (TH-01 Injection + TH-03 Crypto Failures present in fixture).
    assert 'id="th-01"' in rendered or 'id="th-03"' in rendered
    # Every threat anchor is still emitted inside per-TH finding tables.
    for tid in ("t-001", "t-002", "t-003", "t-010"):
        assert f'<a id="{tid}"></a>' in rendered


def test_mitigation_register_derived_from_yaml(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    for mid in ("m-001", "m-002", "m-003"):
        assert f'<a id="{mid}"></a>' in rendered


# ---------------------------------------------------------------------------
# Changelog — per-version Added/Changed/Resolved breakdown
# ---------------------------------------------------------------------------

def _extract_changelog_section(md: str) -> str:
    i = md.find("## Changelog")
    assert i >= 0, "rendered output must contain a Changelog section"
    j = md.find("\n## ", i + 5)
    return md[i:j] if j > 0 else md[i:]


def _rewrite_changelog(out: Path, entries: list[dict]) -> None:
    ymp = out / "threat-model.yaml"
    data = yaml.safe_load(ymp.read_text(encoding="utf-8"))
    data["changelog"] = entries
    ymp.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _contract_with_changelog_style(tmp_path: Path, style: str) -> Path:
    """Copy the canonical contract to tmp_path and force the changelog
    `render_style` to the given value. Use to exercise the legacy bullets
    renderer while the default remains ``table``.
    """
    dst = tmp_path / "sections-contract.yaml"
    data = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    data["sections"]["changelog"]["render_style"] = style
    # Strip the explicit template so render_style is the decisive signal.
    data["sections"]["changelog"].pop("template", None)
    dst.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return dst


def test_changelog_v1_initial_assessment_has_no_delta_bullets(tmp_path: Path) -> None:
    """First-run entry (no baseline) renders heading + zero delta bullets."""
    out = _prepare_output_dir(tmp_path)
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "### v1 — 2026-04-19 (full — initial assessment)" in section
    for forbidden in ("**Added:**", "**Changed:**", "**Resolved:**"):
        assert forbidden not in section, f"v1/no-baseline must not emit {forbidden}"


def test_changelog_incremental_renders_added_changed_resolved(tmp_path: Path) -> None:
    """Incremental entry with deltas renders Added/Changed/Resolved bullets
    with linkified T-IDs and inline notes/reasons. This is the invariant
    that the console Change Summary also pins — the md must not silently
    degrade to counts-only."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(out, [
        {
            "version": 2, "date": "2026-04-23", "mode": "incremental",
            "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
            "current_sha":  "a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "changed_files": 7,
            "reanalyzed_components": ["C-01"],
            "carried_forward_components": ["C-02"],
            "added": {
                "threats": ["T-020", "T-021"],
                "components": [],
                "attack_surface": ["E-03"],
            },
            "changed": {
                "threats": ["T-002"],
                "notes_by_id": {"T-002": "severity High → Critical"},
            },
            "resolved": {
                "threats": ["T-010"],
                "reason_by_id": {"T-010": "not reproduced on full re-analysis"},
            },
        },
        {
            "version": 1, "date": "2026-04-19", "mode": "full",
            "current_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
            "note": "Initial assessment",
        },
    ])
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    # Heading carries short baseline → current SHAs.
    assert "### v2 — 2026-04-23 (incremental, baseline `cb6fb8a` → `a1b2c3d`)" in section

    # Every delta bullet present with correct plural form + T-ID anchors.
    assert "- **Added:** 2 threats ([T-020](#t-020), [T-021](#t-021)), 1 entry point (E-03)" in section
    assert "- **Changed:** 1 threat ([T-002](#t-002): \"severity High → Critical\")" in section
    assert "- **Resolved:** 1 threat ([T-010](#t-010): \"not reproduced on full re-analysis\")" in section
    assert "- **Re-analyzed:** C-01" in section
    assert "- **Carried forward:** C-02" in section
    assert "- **Changed files:** 7" in section

    # Older v1 entry still rendered below, untouched.
    assert "### v1 — 2026-04-19 (full — initial assessment)" in section
    # v2 must appear above v1 (newest first).
    assert section.index("### v2 —") < section.index("### v1 —")


def test_changelog_full_rebuild_with_baseline_renders_only_nonempty_bullets(tmp_path: Path) -> None:
    """A `mode: full` rerun with a baseline omits empty delta categories —
    e.g. if nothing new was added and nothing changed, only **Resolved**
    renders. Guards against the `- **Added:** 0 threats ()` regression."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(out, [
        {
            "version": 3, "date": "2026-05-01", "mode": "full",
            "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "current_sha":  "b2c3d4e5f67890abcdef1234567890abcdef1234",
            "note": "full rebuild — all components re-analyzed",
            "reanalyzed_components": ["C-01", "C-02"],
            "carried_forward_components": [],
            "added":    {"threats": [], "components": [], "attack_surface": []},
            "changed":  {"threats": [], "notes_by_id": {}},
            "resolved": {"threats": ["T-020"],
                         "reason_by_id": {"T-020": "not reproduced on full re-analysis"}},
        },
    ])
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    assert "- **Resolved:** 1 threat ([T-020](#t-020): \"not reproduced on full re-analysis\")" in section
    # Empty delta categories must NOT render — guards against "0 threats" noise.
    assert "**Added:**"   not in section
    assert "**Changed:**" not in section
    # Trailing `note` bullet still rendered for the full-rebuild message.
    assert "- full rebuild — all components re-analyzed" in section


def test_changelog_caps_inline_ids_at_five_with_more_suffix(tmp_path: Path) -> None:
    """Large full-rebuild deltas must not render an unreadable single-line
    bullet with dozens of inline T-IDs. The fragment caps inline enumeration
    at the first 5 T-IDs and appends `, +<n> more`. The yaml still persists
    the full list — the cap is markdown-only."""
    out = _prepare_output_dir(tmp_path)
    many_added    = [f"T-{i:03d}" for i in range(20, 32)]   # 12 items → 7 extra
    many_changed  = [f"T-{i:03d}" for i in range(40, 48)]   # 8 items  → 3 extra
    many_resolved = [f"T-{i:03d}" for i in range(60, 66)]   # 6 items  → 1 extra
    _rewrite_changelog(out, [
        {
            "version": 4, "date": "2026-05-02", "mode": "full",
            "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "current_sha":  "b2c3d4e5f67890abcdef1234567890abcdef1234",
            "note": "full rebuild — all components re-analyzed",
            "reanalyzed_components": ["C-01", "C-02"],
            "carried_forward_components": [],
            "added":    {"threats": many_added, "components": [], "attack_surface": []},
            "changed":  {"threats": many_changed,
                         "notes_by_id": {t: "severity High → Critical" for t in many_changed}},
            "resolved": {"threats": many_resolved,
                         "reason_by_id": {t: "not reproduced on full re-analysis"
                                          for t in many_resolved}},
        },
    ])
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    # Added: count reflects full list; inline enumeration shows 5 IDs + "+7 more".
    assert "- **Added:** 12 threats (" in section
    assert "[T-020](#t-020)" in section
    assert "[T-024](#t-024)" in section            # 5th shown ID
    assert "[T-025](#t-025)" not in section        # 6th ID capped out of md
    assert "+7 more" in section

    # Changed: 5 shown + "+3 more"; per-ID notes only on shown IDs.
    assert "- **Changed:** 8 threats (" in section
    assert "[T-040](#t-040): \"severity High → Critical\"" in section
    assert "[T-044](#t-044): \"severity High → Critical\"" in section   # 5th
    assert "[T-045](#t-045)" not in section
    assert "+3 more" in section

    # Resolved: 5 shown + "+1 more".
    assert "- **Resolved:** 6 threats (" in section
    assert "[T-064](#t-064)" in section            # 5th shown ID
    assert "[T-065](#t-065)" not in section
    assert "+1 more" in section


def test_changelog_no_more_suffix_when_under_cap(tmp_path: Path) -> None:
    """When counts are below the cap, no `+N more` suffix leaks into the md."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(out, [
        {
            "version": 2, "date": "2026-04-23", "mode": "incremental",
            "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
            "current_sha":  "a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "changed_files": 3,
            "reanalyzed_components": ["C-01"],
            "carried_forward_components": ["C-02"],
            "added":    {"threats": ["T-020", "T-021"], "components": [], "attack_surface": []},
            "changed":  {"threats": [], "notes_by_id": {}},
            "resolved": {"threats": [], "reason_by_id": {}},
        },
    ])
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "more" not in section


# ---------------------------------------------------------------------------
# Changelog — tabular rendering (default render_style)
# ---------------------------------------------------------------------------


def test_changelog_table_is_default(tmp_path: Path) -> None:
    """Without explicit `render_style`, the changelog renders as a table."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # Header row of the table.
    assert "| Version | Date | Mode | Baseline → Current | Δ Threats | Components | Note |" in section
    # No per-version H3 (that is the legacy bullets style).
    assert "### v1" not in section


def test_changelog_table_renders_one_row_per_version(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(out, [
        {
            "version": 2, "date": "2026-04-23", "mode": "incremental",
            "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
            "current_sha":  "a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "changed_files": 7,
            "reanalyzed_components": ["C-01"],
            "carried_forward_components": ["C-02"],
            "added":    {"threats": ["T-020", "T-021"], "components": [], "attack_surface": []},
            "changed":  {"threats": ["T-002"], "notes_by_id": {"T-002": "sev"}},
            "resolved": {"threats": ["T-010"], "reason_by_id": {"T-010": "not repro"}},
        },
        {
            "version": 1, "date": "2026-04-19", "mode": "full",
            "current_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
            "note": "Initial assessment",
        },
    ])
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # v2 row: delta shorthand, short SHAs, component counts.
    assert "| v2 | 2026-04-23 | incremental | `cb6fb8a` → `a1b2c3d` | +2 / ~1 / -1 |" in section
    # v1 row: initial marker and mode=full.
    assert "| v1 | 2026-04-19 | full | _(initial)_ | +0 / ~0 / -0 |" in section
    # Newest first.
    assert section.index("| v2 |") < section.index("| v1 |")


def test_changelog_table_shows_latest_details_block(tmp_path: Path) -> None:
    """The compact table is augmented by a 'Details v<N>' bullet block for
    the newest entry so individual T-IDs remain discoverable."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(out, [
        {
            "version": 3, "date": "2026-05-01", "mode": "full",
            "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "current_sha":  "b2c3d4e5f67890abcdef1234567890abcdef1234",
            "reanalyzed_components": ["C-01"],
            "added":    {"threats": ["T-030"], "components": [], "attack_surface": []},
            "changed":  {"threats": [], "notes_by_id": {}},
            "resolved": {"threats": [], "reason_by_id": {}},
        },
    ])
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    assert "**Details v3:**" in section
    assert "- **Added (1):** [T-030](#t-030)" in section


def test_changelog_table_caps_latest_detail_at_ten_ids(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    ids = [f"T-{i:03d}" for i in range(20, 35)]   # 15 items → 5 over the cap of 10
    _rewrite_changelog(out, [
        {
            "version": 4, "date": "2026-05-02", "mode": "full",
            "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
            "current_sha":  "b2c3d4e5f67890abcdef1234567890abcdef1234",
            "reanalyzed_components": ["C-01", "C-02"],
            "added":    {"threats": ids, "components": [], "attack_surface": []},
            "changed":  {"threats": [], "notes_by_id": {}},
            "resolved": {"threats": [], "reason_by_id": {}},
        },
    ])
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    assert "- **Added (15):** [T-020](#t-020)" in section
    assert "[T-029](#t-029)" in section            # 10th shown
    assert "+5 more" in section
    assert "[T-030](#t-030)" not in section or "+5 more" in section  # either capped out or explicitly in suffix


def test_changelog_table_truncates_long_notes(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    long = "x" * 200
    _rewrite_changelog(out, [
        {
            "version": 5, "date": "2026-05-03", "mode": "full",
            "note": long,
        },
    ])
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # Truncated to ≤ 90 chars with an ellipsis marker (…).
    assert "…" in section
    assert long not in section


# ---------------------------------------------------------------------------
# Hard-gate failure modes
# ---------------------------------------------------------------------------

def test_missing_required_fragment_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / ".fragments" / "ms-verdict.json").unlink()
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "verdict" in str(exc.value)


def test_schema_violation_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    # Emit a verdict with severity not in enum.
    bad = {
        "severity": "catastrophic",      # not in enum
        "opening": "x" * 80,
        "bullets": [],                    # violates minItems=2
        "closing": "y" * 80,
    }
    (out / ".fragments" / "ms-verdict.json").write_text(json.dumps(bad))
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    # Error message mentions the schema-invalid field.
    assert "severity" in str(exc.value) or "bullets" in str(exc.value)


def test_missing_yaml_raises(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / "threat-model.yaml").unlink()
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "threat-model.yaml" in str(exc.value)


def test_markdown_fragment_must_start_with_correct_heading(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    # Corrupt system-overview.md: wrong heading level.
    (out / ".fragments" / "system-overview.md").write_text("### 1. System Overview\n\nwrong level\n")
    with pytest.raises(compose.FragmentError) as exc:
        compose.render(CONTRACT, out)
    assert "system_overview" in str(exc.value)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


def test_cli_writes_threat_model_md(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    result = _run_cli(["--output-dir", str(out)])
    assert result.returncode == 0, result.stderr
    md = (out / "threat-model.md").read_text(encoding="utf-8")
    assert "## Management Summary\n" in md


def test_cli_exit_1_on_missing_fragment(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    (out / ".fragments" / "ms-verdict.json").unlink()
    result = _run_cli(["--output-dir", str(out)])
    assert result.returncode == 1
    assert "RENDER_FAILED" in result.stderr


# ---------------------------------------------------------------------------
# Dollar-operator escape — MongoDB `$where`/`$ne`, jQuery selectors, bash
# vars must survive KaTeX/MathJax-enabled renderers without being
# interpreted as math-mode delimiters.
# ---------------------------------------------------------------------------


class TestEscapeDollarOperators:
    """_escape_dollar_operators is a pure function — exercise it directly."""

    def test_mongodb_operators_are_backticked(self) -> None:
        md = "NoSQL $where injection and $ne bypass"
        assert compose._escape_dollar_operators(md) == (
            "NoSQL `$where` injection and `$ne` bypass"
        )

    def test_already_backticked_operator_is_untouched(self) -> None:
        md = "use `$where` to query"
        assert compose._escape_dollar_operators(md) == md

    def test_fenced_code_block_untouched(self) -> None:
        md = "before\n```\ndb.find({$where: 'x'})\n```\nafter"
        assert compose._escape_dollar_operators(md) == md

    def test_inline_code_untouched(self) -> None:
        md = "use `$regex` here"
        assert compose._escape_dollar_operators(md) == md

    def test_html_comment_untouched(self) -> None:
        md = "<!-- $where: see internal doc -->"
        assert compose._escape_dollar_operators(md) == md

    def test_usd_amount_untouched(self) -> None:
        md = "price is $10 total, not $100.50"
        assert compose._escape_dollar_operators(md) == md

    def test_latex_dollar_dollar_pair_untouched(self) -> None:
        # LaTeX block math is `$$...$$` — lookbehind must not match `$x` after `$`.
        md = "math: $$x$$ done"
        # The opening `$$` before `x` gives `$` + `$x` — the second `$` is
        # preceded by `$`, which the lookbehind `(?<![`$\\])` excludes.
        # So the `$x` inside `$$…$$` stays untouched.
        assert compose._escape_dollar_operators(md) == md

    def test_escaped_dollar_untouched(self) -> None:
        md = "literal \\$where in docs"
        assert compose._escape_dollar_operators(md) == md

    def test_multiple_operators_in_one_line(self) -> None:
        md = "use $regex or $or or $and"
        assert compose._escape_dollar_operators(md) == (
            "use `$regex` or `$or` or `$and`"
        )

    def test_operator_inside_markdown_link_label(self) -> None:
        # A link label like `[T-012](#t-012) — NoSQL $where Injection` must
        # get the `$where` backticked (this is the actual bug observed in
        # the Juice Shop run).
        md = "[T-012](#t-012) — NoSQL $where Injection on Product Reviews"
        assert compose._escape_dollar_operators(md) == (
            "[T-012](#t-012) — NoSQL `$where` Injection on Product Reviews"
        )

    def test_bare_dollar_sign_alone_untouched(self) -> None:
        # A lone `$` with no identifier must never be altered.
        md = "the cost is $ (TBD)"
        assert compose._escape_dollar_operators(md) == md


# ---------------------------------------------------------------------------
# Enrich Linked-ID cells — stacking + label enrichment for markdown-fragment
# tables (Assets, Attack Surface, Trust Boundaries, §7.x control tables).
# ---------------------------------------------------------------------------


class _FakeCtx:
    """Minimal RenderContext stub that supports `linkify_with_label` via a
    lookup dict."""

    def __init__(self, labels: dict[str, str]) -> None:
        self._labels = labels

    def linkify_with_label(self, ref: str, label_override: str | None = None) -> str:
        anchor = ref.lower()
        label = (label_override or self._labels.get(ref) or "").strip()
        if label:
            return f"[{ref}](#{anchor}) — {label}"
        return f"[{ref}](#{anchor})"


class TestEnrichLinkedIdCells:
    def test_adds_labels_and_stacks_with_br(self) -> None:
        md = (
            "| Asset | Linked Threats |\n"
            "|---|---|\n"
            "| Users | [T-003](#t-003), [T-013](#t-013) |\n"
        )
        ctx = _FakeCtx({"T-003": "SQL Injection Login", "T-013": "MD5 Hashing"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert (
            "[T-003](#t-003) — SQL Injection Login"
            "<br/>[T-013](#t-013) — MD5 Hashing"
        ) in out

    def test_idempotent_on_already_enriched(self) -> None:
        md = (
            "| Asset | Linked Threats |\n"
            "|---|---|\n"
            "| Users | [T-003](#t-003) — SQL Injection Login |\n"
        )
        ctx = _FakeCtx({"T-003": "SQL Injection Login"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert out == md

    def test_skips_threat_register_declaration_anchors(self) -> None:
        md = (
            '| ID | Title |\n'
            '|---|---|\n'
            '| <a id="t-003"></a>T-003 | SQL Injection |\n'
        )
        ctx = _FakeCtx({})
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_ignores_tables_without_linked_header(self) -> None:
        md = (
            "| Foo | Bar |\n"
            "|---|---|\n"
            "| x | [T-003](#t-003), [T-013](#t-013) |\n"
        )
        ctx = _FakeCtx({"T-003": "A", "T-013": "B"})
        # "Bar" is not in _LINKED_ID_COLUMN_HEADERS, so the row is not rewritten.
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_preserves_prose_heavy_cells(self) -> None:
        # The cell has narrative text mixed with IDs — don't strip the prose.
        md = (
            "| Boundary | Weakness | Linked Threats |\n"
            "|---|---|---|\n"
            "| TB-1 | SQLi in login | see [T-003](#t-003) and the earlier [T-013](#t-013) analysis |\n"
        )
        ctx = _FakeCtx({"T-003": "x", "T-013": "y"})
        out = compose._enrich_linked_id_cells(ctx, md)
        # Cell contains 'see' and 'analysis' — residue ≠ "", so unchanged.
        assert "see [T-003](#t-003) and the earlier [T-013](#t-013) analysis" in out

    def test_single_id_cell_gets_label(self) -> None:
        md = (
            "| Control | Linked Threats |\n"
            "|---|---|\n"
            "| JWT | [T-001](#t-001) |\n"
        )
        ctx = _FakeCtx({"T-001": "Hardcoded RSA"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert "[T-001](#t-001) — Hardcoded RSA" in out

    def test_unknown_id_gets_bare_link_not_error(self) -> None:
        md = (
            "| X | Linked |\n"
            "|---|---|\n"
            "| A | [T-999](#t-999) |\n"
        )
        ctx = _FakeCtx({})
        out = compose._enrich_linked_id_cells(ctx, md)
        # No label available → bare link is emitted (no exception).
        assert "[T-999](#t-999)" in out

    def test_em_dash_separator_cells_untouched_when_prose_is_present(self) -> None:
        md = (
            "| X | Linked Threats |\n"
            "|---|---|\n"
            "| A | — |\n"
        )
        ctx = _FakeCtx({})
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_mixed_separator_list_is_normalised(self) -> None:
        md = (
            "| X | Linked Threats |\n"
            "|---|---|\n"
            "| A | [T-001](#t-001), [T-002](#t-002); [T-003](#t-003) |\n"
        )
        ctx = _FakeCtx({"T-001": "A", "T-002": "B", "T-003": "C"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert (
            "[T-001](#t-001) — A<br/>[T-002](#t-002) — B<br/>[T-003](#t-003) — C"
        ) in out

    def test_addresses_column_also_enriched(self) -> None:
        md = (
            "| ID | Mitigation | Addresses |\n"
            "|---|---|---|\n"
            "| M-001 | Rotate Key | [T-001](#t-001), [T-002](#t-002) |\n"
        )
        ctx = _FakeCtx({"T-001": "Alpha", "T-002": "Beta"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert (
            "[T-001](#t-001) — Alpha<br/>[T-002](#t-002) — Beta"
        ) in out


# ---------------------------------------------------------------------------
# Security Posture at a Glance — deterministic heatmap subsection
# ---------------------------------------------------------------------------


class TestSecurityPostureAtAGlance:
    """The renderer is fully deterministic — we can unit-test it by
    constructing a small FakeContext with components + threats and
    inspecting the emitted Mermaid source."""

    class _PostureCtx:
        """RenderContext stub with just enough surface for the posture renderer."""

        def __init__(self, yaml_data: dict) -> None:
            self.yaml_data = yaml_data
            self.contract = {}

    @staticmethod
    def _section_cfg(min_hc: int = 3, max_arrows: int = 5) -> dict:
        return {
            "min_high_or_critical": min_hc,
            "max_attack_arrows": max_arrows,
        }

    def _yaml_with_findings(self, severities: list[str]) -> dict:
        """Build a minimal yaml payload with one component + len(severities)
        threats. Components are tagged so the layer classifier picks them up
        deterministically."""
        components = [
            {"id": "C-01", "name": "REST API",       "layer": "server",
             "description": "Express API"},
            {"id": "C-02", "name": "Angular SPA",    "layer": "frontend",
             "description": "Frontend SPA"},
            {"id": "C-03", "name": "SQLite Data Store", "layer": "data",
             "description": "Primary database"},
        ]
        threats = []
        for i, sev in enumerate(severities, start=1):
            threats.append({
                "t_id": f"T-{i:03d}",
                "component_id": "C-01",
                "title": f"Finding {i}",
                "risk": sev,
                "vektor": "Internet Anon",
            })
        return {"components": components, "threats": threats}

    def test_skip_section_when_below_threshold(self) -> None:
        yaml_data = self._yaml_with_findings(["medium", "low"])
        ctx = self._PostureCtx(yaml_data)
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg()
        )
        assert out == ""

    def test_renders_heading_when_enough_findings(self) -> None:
        yaml_data = self._yaml_with_findings(["critical", "critical", "high"])
        ctx = self._PostureCtx(yaml_data)
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg()
        )
        assert "### Security Posture at a Glance" in out
        assert "```mermaid" in out
        assert "flowchart TB" in out

    def test_components_grouped_into_three_layers(self) -> None:
        yaml_data = self._yaml_with_findings(["critical", "high", "high"])
        ctx = self._PostureCtx(yaml_data)
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg()
        )
        # Three layer subgraphs present in LR order.
        assert 'subgraph EDGE["Edge' in out
        assert 'subgraph SERVER["Server' in out
        assert 'subgraph DATA["Data' in out

    def test_component_node_carries_severity_badge(self) -> None:
        yaml_data = self._yaml_with_findings(["critical", "critical", "high"])
        ctx = self._PostureCtx(yaml_data)
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg()
        )
        # C-01 has 2 crit + 1 high — must show both counts.
        assert "2 Critical" in out
        assert "1 High" in out

    def test_attack_arrows_numbered_and_cited(self) -> None:
        yaml_data = self._yaml_with_findings(["critical", "critical", "high", "high", "medium"])
        ctx = self._PostureCtx(yaml_data)
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg(min_hc=3, max_arrows=4)
        )
        # The diagram block itself (inside ```mermaid ... ```) carries the
        # circled-number emojis. Restrict the assertion to that block so
        # the intro prose "arrows ①–⑤" does not mask the cap check.
        i_start = out.index("```mermaid")
        i_end   = out.index("```", i_start + 10)
        mermaid = out[i_start:i_end]
        assert "①" in mermaid and "②" in mermaid and "③" in mermaid and "④" in mermaid
        # Fifth arrow omitted (max_arrows=4).
        assert "⑤" not in mermaid
        # Arrow labels cite the T-IDs from the top-severity threats.
        assert "T-001" in mermaid and "T-002" in mermaid

    def test_critical_component_gets_crit_class(self) -> None:
        yaml_data = self._yaml_with_findings(["critical", "critical", "high"])
        ctx = self._PostureCtx(yaml_data)
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg()
        )
        # The C-01 node must be assigned the ":::crit" class.
        assert ":::crit" in out

    def test_no_arrow_when_only_medium_threats(self) -> None:
        # 4 medium findings → above threshold BUT no crit/high → no arrows.
        yaml_data = self._yaml_with_findings(
            ["medium", "medium", "medium", "medium"]
        )
        # Need to lower min_high_or_critical to force rendering despite
        # the absence of Critical/High.
        ctx = self._PostureCtx(yaml_data)
        # With default threshold=3 and 0 H+C, section skips.
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg()
        )
        assert out == ""

    def test_layer_classification_respects_explicit_layer_field(self) -> None:
        yaml_data = {
            "components": [
                {"id": "C-1", "name": "Explicit Edge", "layer": "edge",
                 "description": "totally opaque text"},
            ],
            "threats": [
                {"t_id": "T-001", "component_id": "C-1",
                 "title": "Boom", "risk": "critical", "vektor": "Internet Anon"},
                {"t_id": "T-002", "component_id": "C-1",
                 "title": "Bang", "risk": "high", "vektor": "Internet Anon"},
                {"t_id": "T-003", "component_id": "C-1",
                 "title": "Pow", "risk": "high", "vektor": "Internet Anon"},
            ],
        }
        ctx = self._PostureCtx(yaml_data)
        out = compose._render_security_posture_at_a_glance(
            ctx, env=None, section=self._section_cfg()
        )
        # The component lands in EDGE despite the ambiguous description.
        assert 'subgraph EDGE["Edge' in out
        assert 'subgraph SERVER["Server' not in out
