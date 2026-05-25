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

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "compose_threat_model.py"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "compose"


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


def test_infobox_tags_string_is_split_into_list(tmp_path: Path) -> None:
    """Regression guard for the infobox tags rendering bug.

    Historically the yaml shape for ``project.tags`` allowed either a list
    or a pre-joined comma-separated string. The Jinja template pipes the
    value through ``| join(', ')``; when it received a string, Jinja
    iterated it character-by-character and emitted ``w, e, b, ,, …``
    instead of ``web, security, owasp, …``. The renderer must normalise a
    string value to a list before handing it to the template."""
    out = _prepare_output_dir(tmp_path)
    # Force tags into the buggy shape directly on the fixture yaml.
    yml_path = out / "threat-model.yaml"
    data = yaml.safe_load(yml_path.read_text())
    data.setdefault("project", {})["tags"] = "web security, owasp, pentest"
    yml_path.write_text(yaml.safe_dump(data, sort_keys=False))

    rendered, _ = compose.render(CONTRACT, out)
    # Look at the Tags row of the project infobox blockquote.
    tag_line = next((l for l in rendered.splitlines() if "**Tags**" in l), "")
    assert tag_line, "Tags row missing from infobox"
    # Single-character fragments are the hallmark of the bug.
    assert " w, e, b," not in tag_line, f"infobox tags rendered character-by-character: {tag_line!r}"
    # The expected tokens must all appear intact.
    for tok in ("web security", "owasp", "pentest"):
        assert tok in tag_line, f"expected tag {tok!r} missing from: {tag_line!r}"


def test_render_produces_canonical_ms_structure(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, warnings = compose.render(CONTRACT, out)

    assert warnings == [], f"unexpected warnings: {warnings}"

    # Management Summary must be unnumbered.
    assert "## Management Summary\n" in rendered
    assert "## 1. Management Summary" not in rendered

    # Post-2026-05 — six canonical sub-sections, in order. `### Mitigations`
    # was renamed `### Top Mitigations` to distinguish the MS preview from
    # §9 Mitigation Register (the full P1/P2/P3 catalogue). `### Security
    # Posture at a Glance` was added between Verdict and Top Findings to
    # surface the path-grouped heatmap before the per-finding table.
    expected_order = [
        "### Verdict",
        "### Security Posture at a Glance",
        "### Top Findings",
        "### Architecture Assessment",
        "### Top Mitigations",
        "### Operational Strengths",
    ]
    positions = [rendered.find(h) for h in expected_order]
    assert all(p > 0 for p in positions), f"missing MS subsection(s): {expected_order} at {positions}"
    assert positions == sorted(positions), f"MS subsections out of order: {positions}"

    # No forbidden legacy headings anywhere in MS.
    ms_slice = rendered.split("## Management Summary", 1)[1].split("\n## ", 1)[0]
    for forbidden in (
        "### 1.1",
        "### Executive Overview",
        "### Risk Distribution",
        "### Top Threats",
        "### Immediate Actions",
    ):
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
    assert "border-left: 3px solid #dc2626" in rendered
    # At least one F/T-NNN linkified citation inside the blockquote.
    assert re.search(r"\*\(\[[FT]-00[12]\]\(#[ft]-00[12]\)(?: — [^)]+)?\)\*", rendered)


def test_top_findings_has_six_columns(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Locate the Top Findings header row.
    header = "| # | Criticality | Pfad | Finding | Component | Primary Mitigations |"
    assert header in rendered, "Top Findings must use exactly the 6 canonical columns"


def test_top_findings_path_glyphs_link_to_heatmap_anchors(tmp_path: Path) -> None:
    """Every Pfad glyph used in the Top Findings table must resolve to an
    anchor emitted by the Security Posture at a Glance bullet list."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    m = re.search(r"### Top Findings(.+?)(?=^### )", rendered, re.DOTALL | re.MULTILINE)
    assert m, "Top Findings section not found"
    table_section = m.group(1)
    used_anchors = set(re.findall(r"\[[①-⑦]\]\(#(path-[a-z-]+)\)", table_section))
    if not used_anchors:
        return  # fixture has no qualifying findings → nothing to verify
    for anchor in used_anchors:
        assert f'<a id="{anchor}"></a>' in rendered, (
            f"Top Findings references #{anchor} but heatmap bullets do not emit it"
        )


def test_architecture_assessment_has_four_columns(tmp_path: Path) -> None:
    """R-7 (2026-05): Architecture Assessment table is now 4 columns —
    Weakness category | Affected component(s) | Description | Key findings.
    The legacy 3-column `| Defect | Description | Key Findings |` form is
    retired; the fixture uses the new `weaknesses[]` schema shape."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "| Weakness category | Affected component(s) | Description | Key findings |" in rendered
    # And the retired 3-column form is gone.
    legacy = "| Defect | Description | Key Findings |"
    assert legacy not in rendered, (
        "retired 3-column Architecture Assessment header leaked into the render"
    )


def test_operational_strengths_has_three_columns(tmp_path: Path) -> None:
    """As of 2026-05 Operational Strengths is a 3-column cluster table
    (Strength / What's in Place / Effectiveness). The legacy 5-column
    form (Architectural Control / Implementation / Effectiveness / Gap /
    Mitigates) is retired — see agents/shared/ms-template.md and
    agents/appsec-qa-reviewer.md Check 3i."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    header = "| Strength | What's in Place | Effectiveness |"
    assert header in rendered
    # And the retired 5-column form is gone.
    legacy = "| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |"
    assert legacy not in rendered, (
        "retired 5-column Operational Strengths form leaked into the render"
    )


def test_attack_chain_overview_in_section_3(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Reference layout: the cross-chain diagram lives as ### 3.1 Attack Chain
    # Overview inside §3 — NOT as a standalone `## Critical Attack Chain`.
    assert "## Critical Attack Chain\n" not in rendered
    assert "### 3.1 Attack Chain Overview" in rendered
    # §3.1 must carry graph LR Mermaid blocks (one per chain, no mega subgraph).
    assert re.search(r"```mermaid\s*\n\s*graph LR", rendered), "§3.1 must contain at least one `graph LR` Mermaid block"
    assert "**Key takeaway:**" in rendered


def test_evidence_check_badge_renders_on_refuted_and_ambiguous(tmp_path: Path) -> None:
    """M3: rows with evidence_check=refuted carry a strikethrough title
    + ⚠ *(evidence refuted)* marker; rows with evidence_check=ambiguous
    carry an `evidence: ambiguous ◌` token in the location line. Verified
    rows show `evidence: verified` (silent — no badge). The §8 footer
    paragraph "**Evidence verification:**" is emitted once when any
    refuted/ambiguous row is present and omitted otherwise.

    Post-2026-05 layout note: the `◌ *(evidence ambiguous)*` marker that
    used to sit beside the title was moved into the LOC line as
    `evidence: ambiguous ◌` — keeping the title clean and lifting the
    evidence verdict to the same row that carries the file path. The
    refuted marker stays beside the title because strikethrough text
    needs the title context to read.
    """
    out = _prepare_output_dir(tmp_path)
    yml_path = out / "threat-model.yaml"
    data = yaml.safe_load(yml_path.read_text())
    # Tag the first three threats with each verdict; leave the rest alone.
    threats = data["threats"]
    assert len(threats) >= 3, "fixture must have at least 3 threats for this test"
    threats[0]["evidence_check"] = "refuted"
    threats[1]["evidence_check"] = "ambiguous"
    threats[2]["evidence_check"] = "verified"
    yml_path.write_text(yaml.safe_dump(data, sort_keys=False))

    rendered, _ = compose.render(CONTRACT, out)

    # Visible markers.
    assert "⚠ *(evidence refuted)*" in rendered, "refuted marker missing"
    assert "evidence: ambiguous ◌" in rendered, "ambiguous marker missing"
    # Verified rows show the verdict in the LOC line.
    assert "evidence: verified" in rendered
    # The unchecked verdict stays silent.
    assert "(evidence unchecked)" not in rendered

    # Footnote present once.
    assert "**Evidence verification:**" in rendered
    assert rendered.count("**Evidence verification:**") == 1


def test_evidence_check_footnote_omitted_when_no_drift(tmp_path: Path) -> None:
    """The evidence-check footnote is conditional — when no row carries
    refuted/ambiguous, the footnote MUST be absent. Avoids dead text in
    runs where every finding was verified."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    assert "**Evidence verification:**" not in rendered


def test_threat_register_is_flat_register(tmp_path: Path) -> None:
    """§8 Threat Register uses the post-2026-05 4-column Story-Card layout.

    The legacy 9-column header (`ID | Finding | Threat Category | Component
    | Criticality | CVSS | Vektor | Mitigation | References`) was retired —
    every per-row attribute (category, component, mitigation links, CWE/
    OWASP/TH references, code excerpt) now folds into the rich Finding
    cell. The columns shown to the reader are therefore:

        ID | Finding | Vektor | Criticality

    Per-TH anchors are emitted as an invisible block at the top of §8
    (no visible "Categories at a glance" catalogue since 2026-05).
    """
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    # Header is present with Risk + STRIDE summary lines plus the flat register.
    assert "**Risk Distribution:** 🔴 Critical: 3 · 🟠 High: 1 · " in rendered
    assert "**STRIDE Coverage:**" in rendered
    # Post-2026-05 R-6 — Story-Card layout with Component column replacing
    # Vektor (Vektor moved into the Finding cell as a labelled **Vektor:**
    # field). Post-actors.md §14 the Actor column was added between Component
    # and Criticality, surfacing primary_actor + [obsolete-actor] / _dormant_
    # markers per §10 Stable-ID-Garantie Fälle 2 & 3.
    assert "| ID | Finding | Component | Actor | Criticality |" in rendered
    # 8.A "Categories at a glance" subsection was removed in 2026-05; only
    # the invisible anchor block remains. The legacy 8.B Critical
    # Categories heading was also retired.
    assert "### 8.A Categories at a glance" not in rendered
    assert "### 8.B Critical Categories" not in rendered
    # Per-TH anchors are emitted in the invisible anchor block at the
    # top of §8 (the visible "Categories at a glance:" catalogue line
    # was removed).
    assert 'id="th-01"' in rendered or 'id="th-03"' in rendered
    # Every threat anchor is still emitted inside the register.
    for tid in ("t-001", "t-002", "t-003", "t-010"):
        assert f'<a id="{tid}"></a>' in rendered


# ---------------------------------------------------------------------------
# §8 Story-Card walkthrough back-links + severity-tiered snippet gate
# ---------------------------------------------------------------------------


def _slice_threat_register(rendered: str) -> str:
    """Return the rendered §8 Threat Register body."""
    i = rendered.find("## 8. Threat Register")
    assert i >= 0, "expected §8 in rendered output"
    j = rendered.find("\n## ", i + 5)
    return rendered[i:j] if j > 0 else rendered[i:]


def test_finding_cell_links_critical_finding_to_attack_walkthrough(tmp_path: Path) -> None:
    """Critical/High Story-Card rows surface a back-link to §3 Attack
    Walkthroughs when the chain map resolves the finding's id."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section8 = _slice_threat_register(rendered)

    # Fixture chains: Chain 1 references T-001; Chain 2 references T-003.
    # §3.2 covers SQL Injection bypass (matches T-001 / T-002). Per-finding
    # walkthrough (§3.2) outranks the chain link when both resolve.
    assert "**Attack Walkthrough:**" in section8, "expected at least one walkthrough back-link in §8"
    # Chain 2 → T-003 (no §3.2 entry for T-003 in the fixture) renders as
    # the chain link.
    assert "[Chain 2 — Admin Takeover](#chain-2-admin-takeover)" in section8


def test_finding_cell_omits_walkthrough_line_when_no_chains_resolve(tmp_path: Path) -> None:
    """When the §3 fragment contains no `#### Chain N` headings (e.g.
    skip-mode stub or empty), the cell renders without an Attack Walkthrough
    line (graceful no-op — chain map returns {})."""
    out = _prepare_output_dir(tmp_path)
    # Replace fragment with a stub that has the required H2 but no chains.
    stub_frag = (
        "## 3. Attack Walkthroughs\n\n"
        "_Skipped at this depth — see §8 Threat Register for finding-level detail._\n"
    )
    (out / ".fragments" / "attack-walkthroughs.md").write_text(stub_frag, encoding="utf-8")
    # The contract gates §3.1 subsection requirement on
    # `not skip_attack_walkthroughs` — set the flag so the missing §3.1
    # heading does not trip required_subsections validation.
    (out / ".skill-config.json").write_text(
        json.dumps({"skip_attack_walkthroughs": True}), encoding="utf-8"
    )
    rendered, _ = compose.render(CONTRACT, out)
    section8 = _slice_threat_register(rendered)
    assert "**Attack Walkthrough:**" not in section8


def test_chain_map_extracts_chain_anchors_from_fixture(tmp_path: Path) -> None:
    """`_build_finding_to_chain_map` parses `#### Chain N — Title` headings
    in the fixture and registers every T-NNN / F-NNN reference found in
    each chain body under the canonical `github_slug` anchor."""
    out = _prepare_output_dir(tmp_path)
    ctx = compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=out / ".fragments",
    )
    chain_map = compose._build_finding_to_chain_map(ctx)
    # Fixture Chain 1 references T-001; Chain 2 references T-003.
    assert chain_map.get("T-001") == ("Chain 1 — DB Compromise", "chain-1-db-compromise")
    assert chain_map.get("T-003") == ("Chain 2 — Admin Takeover", "chain-2-admin-takeover")
    # F-NNN alias mirrors T-NNN for every registered id.
    assert chain_map.get("F-001") == ("Chain 1 — DB Compromise", "chain-1-db-compromise")
    assert chain_map.get("F-003") == ("Chain 2 — Admin Takeover", "chain-2-admin-takeover")


def test_chain_map_prefers_per_finding_walkthrough_over_chain(tmp_path: Path) -> None:
    """When a finding appears in BOTH §3.1 (Chain) and §3.2+ (per-finding
    sequenceDiagram), the §3.2+ entry wins — it is the more specific
    walkthrough."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    (frag_dir / "attack-walkthroughs.md").write_text(
        "## 3. Attack Walkthroughs\n\n"
        "### 3.1 Attack Chain Overview\n\n"
        "#### Chain 1 — DB Compromise\n\n"
        "```mermaid\ngraph LR\n  A --> B[T-001 SQLi]\n```\n\n"
        "### 3.2 SQL Injection Detail\n\n"
        "Walks through T-001 step by step.\n",
        encoding="utf-8",
    )
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
    )
    chain_map = compose._build_finding_to_chain_map(ctx)
    label, anchor = chain_map["T-001"]
    assert label == "Walkthrough §3.2"
    assert anchor == "32-sql-injection-detail"


def test_chain_map_returns_empty_when_fragment_missing(tmp_path: Path) -> None:
    """No `.fragments/attack-walkthroughs.md` → empty map, no exception."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=frag_dir,
    )
    assert compose._build_finding_to_chain_map(ctx) == {}


# ---------------------------------------------------------------------------
# §8 Story-Card Component anchor + Issue/Impact disjointness regressions
# These two checks pin bugs that previously shipped to production:
#   1. _build_finding_cell linked the in-cell Component using the raw slug
#      (`#express-backend`) while the Component column used the canonical
#      `#c-01` anchor — two different anchors for the same component.
#   2. Issue and Impact frequently rendered the SAME sentence because Issue
#      kept N scenario sentences and Impact then drew the LAST sentence as
#      its consequence — overlap was the norm, not the exception.
# ---------------------------------------------------------------------------


def _make_threat_for_cell(scenario: str, *, comp_id: str = "rest-api",
                          file_: str = "routes/login.ts", line: int = 34,
                          severity: str = "Critical") -> dict:
    """Threat shape exercising _build_finding_cell end-to-end."""
    return {
        "t_id": "T-099",
        "id": "T-099",
        "component_id": comp_id,
        "component": comp_id,
        "stride": "Tampering",
        "stride_category": "Tampering",
        "title": "SQL injection",
        "scenario": scenario,
        "severity": severity,
        "risk": severity,
        "likelihood": "High",
        "impact": severity,
        "cwe": "CWE-89",
        "evidence": [{"file": file_, "line": line}],
        "mitigations": ["M-001"],
        "vektor": "internet-anon",
        "evidence_check": "verified",
    }


def test_finding_cell_component_uses_canonical_C_NN_anchor(tmp_path: Path) -> None:
    """The in-cell `**Component:**` link MUST resolve the raw slug to the
    canonical `C-NN` anchor — matching the Component column on the same row.

    Without this normalisation the cell renders
    `[express-backend](#express-backend)` while the column carries
    `[C-01 — Express.js Backend API](#c-01)`. Same component, two different
    anchors — broken cross-references and a confused reader.
    """
    components = {
        "C-01": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"},
        "rest-api": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"},
    }
    ctx = compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell("Login concatenates email into SQL.", comp_id="rest-api")

    cell = compose._build_finding_cell(
        t=threat,
        sev="critical",
        taxonomy={},
        components=components,
        repo_root=None,
        ctx=ctx,
    )

    assert "**Component:** [C-01](#c-01) — REST API" in cell, (
        "expected canonical C-NN anchor in the in-cell Component link; cell was:\n" + cell
    )
    # The raw slug must NOT appear as a link target.
    assert "(#rest-api)" not in cell, (
        "raw slug anchor leaked into Component link instead of canonical C-NN"
    )


def test_finding_cell_component_already_canonical_passes_through(tmp_path: Path) -> None:
    """When the threat already carries `component_id: C-01`, the cell renders
    the canonical anchor verbatim — no surprise resolution needed."""
    components = {"C-01": {"name": "REST API"}}
    ctx = compose.RenderContext(
        output_dir=tmp_path, contract={}, yaml_data={}, triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell("Login concatenates email into SQL.", comp_id="C-01")
    cell = compose._build_finding_cell(
        t=threat, sev="critical", taxonomy={}, components=components,
        repo_root=None, ctx=ctx,
    )
    assert "**Component:** [C-01](#c-01) — REST API" in cell


def test_finding_cell_issue_and_impact_carry_disjoint_sentences(tmp_path: Path) -> None:
    """Issue and Impact must NEVER share their final sentence.

    Before the carve-out fix, Issue kept up to 4 sentences of the scenario
    and Impact picked the LAST sentence as the consequence — the last
    sentence then appeared verbatim under both labels. This regression
    catches that exact pattern.
    """
    scenario = (
        "An attacker sends a UNION SELECT in the login email field. "
        "The raw query interpolates the input directly into SQL. "
        "Authentication is bypassed and the entire Users table is dumped to the response."
    )
    components = {"C-01": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"}}
    ctx = compose.RenderContext(
        output_dir=tmp_path, contract={}, yaml_data={}, triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell(scenario, comp_id="C-01")

    cell = compose._build_finding_cell(
        t=threat, sev="critical", taxonomy={}, components=components,
        repo_root=None, ctx=ctx,
    )

    # Locate the two labelled fields. Cells use `<br>` as field separator.
    parts = cell.split("<br>")
    issue_part = next(p for p in parts if p.startswith("**Issue:**"))
    impact_part = next(p for p in parts if p.startswith("**Impact:**"))

    issue_text = issue_part[len("**Issue:**"):].strip().rstrip(".")
    impact_text = impact_part[len("**Impact:**"):].strip().rstrip(".")

    assert issue_text and impact_text, "Issue and Impact must both be populated for Critical"
    # The consequence (last sentence) is the one carved into Impact, so it
    # must NOT be the tail of Issue.
    assert not issue_text.endswith(impact_text), (
        "Impact sentence is duplicated as the tail of Issue:\n"
        f"  Issue:  {issue_text!r}\n  Impact: {impact_text!r}"
    )
    # Specifically: the consequence sentence has been removed from Issue.
    assert "Authentication is bypassed" not in issue_text or "dumped to the response" not in issue_text, (
        "expected the consequence sentence to live in Impact, not Issue"
    )
    assert "Authentication is bypassed" in impact_text or "dumped to the response" in impact_text, (
        "expected Impact to carry the carved consequence sentence"
    )


def test_finding_cell_explicit_impact_description_does_not_carve_issue(tmp_path: Path) -> None:
    """When the YAML supplies an explicit `impact_description`, Issue keeps
    its full N-sentence window — the carve-out only applies when Impact is
    derived from scenario."""
    scenario = (
        "An attacker probes the endpoint. The application accepts the payload. "
        "No alert fires. Logs do not capture the attempt."
    )
    components = {"C-01": {"_canonical_id": "C-01", "_original_id": "rest-api", "name": "REST API"}}
    ctx = compose.RenderContext(
        output_dir=tmp_path, contract={}, yaml_data={}, triage={},
        fragments_dir=tmp_path,
    )
    threat = _make_threat_for_cell(scenario, comp_id="C-01")
    threat["impact_description"] = "Loss of forensic ability to reconstruct the attack."

    cell = compose._build_finding_cell(
        t=threat, sev="critical", taxonomy={}, components=components,
        repo_root=None, ctx=ctx,
    )

    parts = cell.split("<br>")
    issue_part = next(p for p in parts if p.startswith("**Issue:**"))
    impact_part = next(p for p in parts if p.startswith("**Impact:**"))

    # Explicit impact text must appear verbatim under Impact.
    assert "Loss of forensic ability to reconstruct the attack" in impact_part
    # Issue still includes its closing scenario sentences — no carve-out
    # happened because impact was supplied explicitly.
    assert "Logs do not capture the attempt" in issue_part


def test_evidence_snippet_summary_label_is_evidence_not_code(tmp_path: Path) -> None:
    """§8 code snippets use a `<summary><i>Evidence · file:line</i></summary>`
    disclosure widget — the legacy `Code · …` label is gone."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section8 = _slice_threat_register(rendered)
    if "<details>" in section8:
        # Fixture has Critical findings → at least one snippet expected.
        assert "<summary><i>Evidence · " in section8
        assert "<summary><i>Code · " not in section8


# ---------------------------------------------------------------------------
# Pregenerator skeleton — §3 + §3.1 intro paragraphs
# ---------------------------------------------------------------------------


def test_attack_walkthroughs_skeleton_includes_section_intros() -> None:
    """The pregenerator skeleton emits two intro paragraphs: one under
    `## 3. Attack Walkthroughs` explaining the §3.1/§3.2+ split, and one
    under `### 3.1 Attack Chain Overview` explaining how to read a chain
    diagram. Both must appear so the LLM (which copies the skeleton
    verbatim) carries them into the rendered fragment."""
    pregen_path = REPO_ROOT / "scripts" / "pregenerate_fragments.py"
    pf = _load_module("pregenerate_fragments", pregen_path)
    yaml_data = {
        "threats": [
            {"id": "T-001", "title": "SQL injection in login", "risk": "Critical"},
            {"id": "T-002", "title": "Hardcoded admin password", "risk": "Critical"},
        ]
    }
    md = pf.gen_attack_walkthroughs_skeleton(yaml_data)
    # §3 intro hooks
    assert "This section reconstructs how the most-impactful findings" in md
    # Structure-of-this-section bullet must reference §3.1 as the entry point.
    assert "§3.1 Attack Chain Overview" in md
    # §3.1 intro hooks
    assert "Each chain below is one realistic path" in md
    assert "Nodes coloured red are attacker-controlled" in md
    # Intros sit between the headings, not after the chain blocks.
    h2_idx = md.index("## 3. Attack Walkthroughs")
    h3_idx = md.index("### 3.1 Attack Chain Overview")
    chain_idx = md.index("#### Chain 1")
    intro3_idx = md.index("This section reconstructs how the most-impactful findings")
    intro31_idx = md.index("Each chain below is one realistic path")
    assert h2_idx < intro3_idx < h3_idx < intro31_idx < chain_idx


def test_mitigation_register_derived_from_yaml(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    for mid in ("m-001", "m-002", "m-003"):
        assert f'<a id="{mid}"></a>' in rendered


def test_mitigations_section_uses_single_table_with_component_dividers(tmp_path: Path) -> None:
    """The Management Summary Top Mitigations section uses per-component
    sub-tables with a bold paragraph divider per group (2026-05 update —
    the previous in-table divider-row form `| label | | | | |` rendered
    as one cell + 4 visually broken empty cells because Markdown
    pipe-tables have no colspan; the per-component `####` H4 form was
    rejected in a prior iteration as too noisy).

    Layout:
        **↳ <Component Name> (<c-id>) — N item(s)**           ← paragraph
        | # | Priority | Mitigation | Addresses | Effort |   ← per-bucket pipe table
        |---|---|---|---|---|
        | 1 | **P1** | ... |
        ...
        **↳ <Next Component> (<c-id>) — M item(s)**           ← next divider
        | # | Priority | Mitigation | Addresses | Effort |
        ...

    Numbering is continuous (1..N across all buckets) so the leader-board
    rank reads globally. Each pipe-table carries its own canonical header
    line so the contract checker (qa_checks.py table_checks for
    Top Mitigations) is satisfied — it only needs one occurrence.
    """
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)

    # Slice the Top Mitigations section out of the Management Summary.
    ms_slice = rendered.split("### Top Mitigations", 1)[1].split("\n### ", 1)[0]

    # Legacy headers from earlier layouts are gone.
    assert "#### Prioritized Mitigations" not in ms_slice
    assert "#### Follow-up Mitigations" not in ms_slice
    # Per-component `####` sub-headers were retired in favour of inline
    # paragraph dividers (less noisy than H4 headers).
    assert "####" not in ms_slice, "per-component layout must not emit `####` sub-headers"

    # Canonical 5-column pipe-table header (with leading `#` column).
    assert "| # | Priority | Mitigation | Addresses | Effort |" in ms_slice

    # 2026-05 layout: paragraph dividers OUTSIDE the table, of the form
    # `**↳ <Name> (<c-id>) — N item(s)**`. Accept both em-dash and ASCII
    # hyphen — the prose-style normaliser downgrades em-dashes mid-line.
    import re as _re
    assert _re.search(
        r"^\*\*↳\s+.+?\s+\([\w-]+\)\s+[—\-]\s+\d+\s+item\(s\)\*\*\s*$",
        ms_slice,
        flags=_re.MULTILINE,
    ), "expected at least one bold paragraph divider"

    # Old in-table divider-row form must NOT appear (regression guard —
    # the `| label | | | | |` pattern broke visually in pipe-tables).
    assert not _re.search(
        r"\|\s*\*\*↳\s+.+\s+[—\-]\s+\d+\s+item\(s\)\*\*\s*\|\s*\|\s*\|\s*\|",
        ms_slice,
    ), "in-table divider-row form is retired"

    # A priority cell renders as **P1** / **P2** in data rows.
    assert any(f"**P{n}**" in ms_slice for n in (1, 2)), "expected a bold P1/P2 priority cell"


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
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
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
                "version": 1,
                "date": "2026-04-19",
                "mode": "full",
                "current_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "note": "Initial assessment",
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    # Heading carries short baseline → current SHAs.
    assert "### v2 — 2026-04-23 (incremental, baseline `cb6fb8a` → `a1b2c3d`)" in section

    # Every delta bullet present with correct plural form + T-ID anchors.
    # Added/Changed/Resolved enumerate threats only — components and entry
    # points live in the dedicated **Architecture** bullet for readability.
    assert "- **Added:** 2 threats ([T-020](#t-020), [T-021](#t-021))" in section
    assert '- **Changed:** 1 threat ([T-002](#t-002): "severity High → Critical")' in section
    assert '- **Resolved:** 1 threat ([T-010](#t-010): "not reproduced on full re-analysis")' in section
    assert "- **Architecture:** +1 entry point (E-03)" in section
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
    _rewrite_changelog(
        out,
        [
            {
                "version": 3,
                "date": "2026-05-01",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "note": "full rebuild — all components re-analyzed",
                "reanalyzed_components": ["C-01", "C-02"],
                "carried_forward_components": [],
                "added": {"threats": [], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": ["T-020"], "reason_by_id": {"T-020": "not reproduced on full re-analysis"}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    assert '- **Resolved:** 1 threat ([T-020](#t-020): "not reproduced on full re-analysis")' in section
    # Empty delta categories must NOT render — guards against "0 threats" noise.
    assert "**Added:**" not in section
    assert "**Changed:**" not in section
    # Trailing `note` bullet still rendered for the full-rebuild message.
    # Post-2026-05 — _normalize_emdashes converts em-dashes in plain prose
    # bullets to ASCII hyphens (heading lines, anchor-link bullets and
    # GFM table rows are preserved). The note is a plain prose bullet, so
    # the em-dash in the YAML input is normalised on the way out.
    assert "- full rebuild - all components re-analyzed" in section


def test_changelog_caps_inline_ids_at_five_with_more_suffix(tmp_path: Path) -> None:
    """Large full-rebuild deltas must not render an unreadable single-line
    bullet with dozens of inline T-IDs. The fragment caps inline enumeration
    at the first 5 T-IDs and appends `, +<n> more`. The yaml still persists
    the full list — the cap is markdown-only."""
    out = _prepare_output_dir(tmp_path)
    many_added = [f"T-{i:03d}" for i in range(20, 32)]  # 12 items → 7 extra
    many_changed = [f"T-{i:03d}" for i in range(40, 48)]  # 8 items  → 3 extra
    many_resolved = [f"T-{i:03d}" for i in range(60, 66)]  # 6 items  → 1 extra
    _rewrite_changelog(
        out,
        [
            {
                "version": 4,
                "date": "2026-05-02",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "note": "full rebuild — all components re-analyzed",
                "reanalyzed_components": ["C-01", "C-02"],
                "carried_forward_components": [],
                "added": {"threats": many_added, "components": [], "attack_surface": []},
                "changed": {
                    "threats": many_changed,
                    "notes_by_id": {t: "severity High → Critical" for t in many_changed},
                },
                "resolved": {
                    "threats": many_resolved,
                    "reason_by_id": {t: "not reproduced on full re-analysis" for t in many_resolved},
                },
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)

    # Added: count reflects full list; inline enumeration shows 5 IDs + "+7 more".
    assert "- **Added:** 12 threats (" in section
    assert "[T-020](#t-020)" in section
    assert "[T-024](#t-024)" in section  # 5th shown ID
    assert "[T-025](#t-025)" not in section  # 6th ID capped out of md
    assert "+7 more" in section

    # Changed: 5 shown + "+3 more"; per-ID notes only on shown IDs.
    assert "- **Changed:** 8 threats (" in section
    assert '[T-040](#t-040): "severity High → Critical"' in section
    assert '[T-044](#t-044): "severity High → Critical"' in section  # 5th
    assert "[T-045](#t-045)" not in section
    assert "+3 more" in section

    # Resolved: 5 shown + "+1 more".
    assert "- **Resolved:** 6 threats (" in section
    assert "[T-064](#t-064)" in section  # 5th shown ID
    assert "[T-065](#t-065)" not in section
    assert "+1 more" in section


def test_changelog_no_more_suffix_when_under_cap(tmp_path: Path) -> None:
    """When counts are below the cap, no `+N more` suffix leaks into the md."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 3,
                "reanalyzed_components": ["C-01"],
                "carried_forward_components": ["C-02"],
                "added": {"threats": ["T-020", "T-021"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "more" not in section


def test_changelog_renders_line_stats_when_present(tmp_path: Path) -> None:
    """When `changed_lines.insertions` + `.deletions` are populated, the
    Changed-files bullet appends a `(+N/-M lines)` tail so reviewers see
    code-churn magnitude at a glance. Absent → bullet reduces to file count
    only."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 12,
                "changed_lines": {"insertions": 340, "deletions": 45},
                "reanalyzed_components": ["C-01"],
                "added": {"threats": ["T-020"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "- **Changed files:** 12 (+340/-45 lines)" in section


def test_changelog_architecture_bullet_lists_components_and_entry_points(tmp_path: Path) -> None:
    """Added components and entry points live in a dedicated Architecture
    bullet, separate from the Added-threats bullet. Keeps the threat view
    uncluttered and surfaces security-relevant architecture changes."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 3,
                "date": "2026-05-01",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "added": {
                    "threats": ["T-030"],
                    "components": ["C-06", "C-07"],
                    "attack_surface": ["E-04", "E-05"],
                },
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "- **Added:** 1 threat ([T-030](#t-030))" in section
    assert "- **Architecture:** +2 components (C-06, C-07), +2 entry points (E-04, E-05)" in section


def test_changelog_truncates_overly_long_note_prose(tmp_path: Path) -> None:
    """Guards against AI-generated run summaries leaking into the changelog.
    The template hard-truncates any `note` > 100 chars to 98 chars + `…`.
    Upstream guidance in phase-group-finalization.md forbids such prose in
    the first place — this is the defensive backstop."""
    out = _prepare_output_dir(tmp_path)
    prose = (
        "Full scan re-assessment with enhanced frontend analysis, SSRF "
        "identified, WebSocket trust boundary TB-6 added, fragment pipeline "
        "written for compose_threat_model.py renderer. All 28 threats and "
        "21 mitigations carried forward."
    )
    _rewrite_changelog(
        out,
        [
            {
                "version": 4,
                "date": "2026-05-02",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "note": prose,
                "added": {"threats": [], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    ctr = _contract_with_changelog_style(tmp_path, "bullets")
    rendered, _ = compose.render(ctr, out)
    section = _extract_changelog_section(rendered)
    assert "…" in section
    assert prose not in section


# ---------------------------------------------------------------------------
# Changelog — tabular rendering (default render_style)
# ---------------------------------------------------------------------------


def test_changelog_table_is_default(tmp_path: Path) -> None:
    """Without explicit `render_style`, the changelog renders as a table."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # Header row of the table.
    assert "| Version | Date | Mode | Depth | Reasoning | Baseline → Current | Δ Threats | Code | Note |" in section
    # No per-version H3 (that is the legacy bullets style).
    assert "### v1" not in section


def test_changelog_table_separator_and_first_row_on_separate_lines(tmp_path: Path) -> None:
    """The markdown separator `|---|---|…|` and the first data row must live
    on separate lines; otherwise the row gets concatenated into the
    separator (`|------|| v1 | …`) and the table collapses to a single
    visual line in rendered markdown. Regression guard for the
    `{%- for %}` whitespace-control bug that ate the trailing newline of
    the separator."""
    out = _prepare_output_dir(tmp_path)
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # Locate the separator line and confirm the next non-empty line is a
    # data row starting with `| v` — not a continuation of the separator.
    lines = section.splitlines()
    sep_idx = next((i for i, l in enumerate(lines) if l.startswith("|---")), None)
    assert sep_idx is not None, "separator line not found"
    # The separator itself must not carry appended row content.
    assert "| v" not in lines[sep_idx], f"separator line has a row concatenated to it: {lines[sep_idx]!r}"
    # Next non-empty line after the separator must be a `| v<N> |` row.
    nxt = next((l for l in lines[sep_idx + 1 :] if l.strip()), None)
    assert nxt is not None and nxt.lstrip().startswith("| v"), (
        f"expected a `| v<N> |` row after the separator, got {nxt!r}"
    )


def test_changelog_table_renders_one_row_per_version(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 2,
                "date": "2026-04-23",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 7,
                "reanalyzed_components": ["C-01"],
                "carried_forward_components": ["C-02"],
                "added": {"threats": ["T-020", "T-021"], "components": [], "attack_surface": []},
                "changed": {"threats": ["T-002"], "notes_by_id": {"T-002": "sev"}},
                "resolved": {"threats": ["T-010"], "reason_by_id": {"T-010": "not repro"}},
            },
            {
                "version": 1,
                "date": "2026-04-19",
                "mode": "full",
                "current_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "note": "Initial assessment",
            },
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # v2 row: delta shorthand, short SHAs, component counts.
    # Empty cells render as ASCII hyphen — `_normalize_emdashes` applies to
    # changelog table rows because the row carries no anchor links (anchor-
    # link rows are excluded from normalisation; this one is not).
    assert "| v2 | 2026-04-23 | incremental | - | - | `cb6fb8a` → `a1b2c3d` | +2 / ~1 / -1 | 7 files | - |" in section
    # v1 row: initial marker and mode=full.
    assert "| v1 | 2026-04-19 | full | - | - | _(initial)_ | +0 / ~0 / -0 | - | Initial assessment |" in section
    # Newest first.
    assert section.index("| v2 |") < section.index("| v1 |")


def test_changelog_table_latest_run_detail_block(tmp_path: Path) -> None:
    """Contract (F6.1): the table-style changelog renders the table AND a
    `**Latest run (vN) — threat-level detail:**` block enumerating the
    T-IDs of the most recent entry. Previous versions are not duplicated;
    the reader sees only the latest run's IDs to avoid the table-only
    `+N / ~M / -K` summary hiding the actual finding IDs.
    """
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 3,
                "date": "2026-05-01",
                "mode": "full",
                "baseline_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "current_sha": "b2c3d4e5f67890abcdef1234567890abcdef1234",
                "reanalyzed_components": ["C-01"],
                "added": {"threats": ["T-030"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    # The single-table format is preserved (table row exists).
    assert "| v3 |" in section
    # The latest-run detail block enumerates the T-IDs.
    assert "**Latest run (v3)" in section
    assert "- **Added (1):**" in section
    assert "T-030" in section
    # Architecture / changed / resolved bullets are NOT emitted because
    # those buckets are empty for this entry.
    assert "- **Changed" not in section
    assert "- **Resolved" not in section
    assert "- **Architecture:**" not in section


def test_changelog_table_code_column_combines_files_and_lines(tmp_path: Path) -> None:
    """The `Code` column replaces the old `Components` column. Files + line
    stats are joined so a reviewer sees churn magnitude in one glance."""
    out = _prepare_output_dir(tmp_path)
    _rewrite_changelog(
        out,
        [
            {
                "version": 6,
                "date": "2026-05-04",
                "mode": "incremental",
                "baseline_sha": "cb6fb8a83458fe3c63dd03c80f46ceda0438dc1f",
                "current_sha": "a1b2c3d4e5f67890abcdef1234567890abcdef12",
                "changed_files": 12,
                "changed_lines": {"insertions": 340, "deletions": 45},
                "added": {"threats": ["T-050"], "components": [], "attack_surface": []},
                "changed": {"threats": [], "notes_by_id": {}},
                "resolved": {"threats": [], "reason_by_id": {}},
            },
        ],
    )
    rendered, _ = compose.render(CONTRACT, out)
    section = _extract_changelog_section(rendered)
    assert "| 12 files, +340/-45 |" in section


def test_changelog_table_truncates_long_notes(tmp_path: Path) -> None:
    out = _prepare_output_dir(tmp_path)
    long = "x" * 200
    _rewrite_changelog(
        out,
        [
            {
                "version": 5,
                "date": "2026-05-03",
                "mode": "full",
                "note": long,
            },
        ],
    )
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
        "severity": "catastrophic",  # not in enum
        "opening": "x" * 80,
        "bullets": [],  # violates minItems=2
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
# interpreted as math-mode delimiters. Post-2026-05 the renderer uses the
# canonical Markdown backslash-escape (`\$word`) rather than backtick
# wrapping, so the visible glyph stays in the surrounding font weight.
# ---------------------------------------------------------------------------


class TestEscapeDollarOperators:
    """_escape_dollar_operators is a pure function — exercise it directly."""

    def test_mongodb_operators_are_backslash_escaped(self) -> None:
        # Post-2026-05 — renderer emits the canonical Markdown backslash-escape
        # (`\$where`) instead of backtick-wrapping. Backslash-escape keeps the
        # math-mode protection under KaTeX/MathJax while leaving the rendered
        # text in the surrounding font weight (backticks produced a visible
        # monospace span that read as literal source code).
        md = "NoSQL $where injection and $ne bypass"
        assert compose._escape_dollar_operators(md) == ("NoSQL \\$where injection and \\$ne bypass")

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
        assert compose._escape_dollar_operators(md) == ("use \\$regex or \\$or or \\$and")

    def test_operator_inside_markdown_link_label(self) -> None:
        # A link label like `[T-012](#t-012) — NoSQL $where Injection` must
        # get the `$where` escaped (this is the actual bug observed in
        # the Juice Shop run).
        md = "[T-012](#t-012) — NoSQL $where Injection on Product Reviews"
        assert compose._escape_dollar_operators(md) == ("[T-012](#t-012) — NoSQL \\$where Injection on Product Reviews")

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
        md = "| Asset | Linked Threats |\n|---|---|\n| Users | [T-003](#t-003), [T-013](#t-013) |\n"
        ctx = _FakeCtx({"T-003": "SQL Injection Login", "T-013": "MD5 Hashing"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert ("[T-003](#t-003) — SQL Injection Login<br/>[T-013](#t-013) — MD5 Hashing") in out

    def test_idempotent_on_already_enriched(self) -> None:
        md = "| Asset | Linked Threats |\n|---|---|\n| Users | [T-003](#t-003) — SQL Injection Login |\n"
        ctx = _FakeCtx({"T-003": "SQL Injection Login"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert out == md

    def test_skips_threat_register_declaration_anchors(self) -> None:
        md = '| ID | Title |\n|---|---|\n| <a id="t-003"></a>T-003 | SQL Injection |\n'
        ctx = _FakeCtx({})
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_ignores_tables_without_linked_header(self) -> None:
        md = "| Foo | Bar |\n|---|---|\n| x | [T-003](#t-003), [T-013](#t-013) |\n"
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
        md = "| Control | Linked Threats |\n|---|---|\n| JWT | [T-001](#t-001) |\n"
        ctx = _FakeCtx({"T-001": "Hardcoded RSA"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert "[T-001](#t-001) — Hardcoded RSA" in out

    def test_unknown_id_gets_bare_link_not_error(self) -> None:
        md = "| X | Linked |\n|---|---|\n| A | [T-999](#t-999) |\n"
        ctx = _FakeCtx({})
        out = compose._enrich_linked_id_cells(ctx, md)
        # No label available → bare link is emitted (no exception).
        assert "[T-999](#t-999)" in out

    def test_em_dash_separator_cells_untouched_when_prose_is_present(self) -> None:
        md = "| X | Linked Threats |\n|---|---|\n| A | — |\n"
        ctx = _FakeCtx({})
        assert compose._enrich_linked_id_cells(ctx, md) == md

    def test_mixed_separator_list_is_normalised(self) -> None:
        md = "| X | Linked Threats |\n|---|---|\n| A | [T-001](#t-001), [T-002](#t-002); [T-003](#t-003) |\n"
        ctx = _FakeCtx({"T-001": "A", "T-002": "B", "T-003": "C"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert ("[T-001](#t-001) — A<br/>[T-002](#t-002) — B<br/>[T-003](#t-003) — C") in out

    def test_addresses_column_also_enriched(self) -> None:
        md = (
            "| ID | Mitigation | Addresses |\n"
            "|---|---|---|\n"
            "| M-001 | Rotate Key | [T-001](#t-001), [T-002](#t-002) |\n"
        )
        ctx = _FakeCtx({"T-001": "Alpha", "T-002": "Beta"})
        out = compose._enrich_linked_id_cells(ctx, md)
        assert ("[T-001](#t-001) — Alpha<br/>[T-002](#t-002) — Beta") in out


# ---------------------------------------------------------------------------
# Security Posture at a Glance — contract v2 format (4-column heatmap with
# attack arrows + per-attack-class narrative bullets). Replaces the
# previous arrowless-with-tables format; see CHANGELOG / contract_version: 2.
# ---------------------------------------------------------------------------


class TestSecurityPostureV2:
    """Test the contract v2 layout:

    * Mermaid block uses `flowchart LR` with ELK init directive.
    * 3 subgraphs: ACTORS, TIERS, IMPACT (no VICTIMS — the victim now
      sits in ACTORS).
    * Empty subgraph titles + first-node header (HDR_A / HDR_T / HDR_I).
    * Cross-subgraph alignment edges keep the column headers on one Y line.
    * 1–7 attack arrows (==>) with numbered glyphs ① ⑦.
    * 1–6 dashed consequence arrows (-.->).
    * Below the diagram: Threat-actors paragraph, actor bullets, then
      1–7 attack-class bullets each with `Findings:` + `Impact:` plus
      optional `Architectural root cause:` and `Attack chain:`.
    """

    @staticmethod
    def _build_ctx(tmp_path, yaml_data: dict, fragment: dict | None = None):
        """Build a real RenderContext + Jinja env so the v2 renderer can
        actually call its templates.
        """
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        frag_dir = out_dir / ".fragments"
        frag_dir.mkdir()
        if fragment is not None:
            (frag_dir / "security-posture-attack-paths.json").write_text(json.dumps(fragment), encoding="utf-8")
        ctx = compose.RenderContext(
            output_dir=out_dir,
            contract={},
            yaml_data=yaml_data,
            triage={},
            fragments_dir=frag_dir,
        )
        env = compose._build_jinja_env(ctx)
        return ctx, env

    @staticmethod
    def _section_cfg(min_hc: int = 3) -> dict:
        return {"min_high_or_critical": min_hc}

    @staticmethod
    def _yaml_seven_classes() -> dict:
        """Reference fixture: one finding for each of the 7 attack classes
        so every glyph ① ⑦ is exercised.
        """
        components = [
            {"id": "spa-frontend", "name": "Angular SPA", "layer": "frontend"},
            {"id": "rest-api", "name": "REST API", "layer": "server"},
            {"id": "data-layer", "name": "Data Layer", "layer": "data"},
        ]
        threats = [
            # Class 1 (Injection — CWE-89 SQLi)
            {"id": "F-001", "title": "SQL Injection", "component_id": "rest-api", "cwe": "CWE-89", "risk": "Critical"},
            # Class 2 (Auth Bypass — CWE-287)
            {"id": "F-002", "title": "Auth Bypass", "component_id": "rest-api", "cwe": "CWE-287", "risk": "Critical"},
            # Class 3 (Privilege Escalation — CWE-269)
            {"id": "F-003", "title": "Priv Esc", "component_id": "rest-api", "cwe": "CWE-269", "risk": "Critical"},
            # Class 4 (Sensitive Data Exposure — CWE-200)
            {"id": "F-004", "title": "Data Exposure", "component_id": "rest-api", "cwe": "CWE-200", "risk": "High"},
            # Class 5 (RCE — CWE-94)
            {"id": "F-005", "title": "RCE", "component_id": "data-layer", "cwe": "CWE-94", "risk": "Critical"},
            # NB: CWE-94 is in BOTH injection and remote-code-execution; the
            # taxonomy lists injection FIRST so this would normally classify
            # as injection, but the LLM fragment can override. The fallback
            # path will put F-005 under injection, F-001 / F-002 / F-003 too.
            # For deterministic fixture, supply a fragment.
            # Class 6 (XSS — CWE-79)
            {"id": "F-006", "title": "Stored XSS", "component_id": "spa-frontend", "cwe": "CWE-79", "risk": "High"},
            # Class 7 (CSRF — CWE-352)
            {"id": "F-007", "title": "CSRF", "component_id": "spa-frontend", "cwe": "CWE-352", "risk": "High"},
        ]
        return {
            "components": components,
            "threats": threats,
            "assets": [],
            "tier_root_causes": {
                "client": ["no CSP"],
                "application": ["raw SQL", "weak crypto"],
                "data": ["no token revocation"],
            },
        }

    @staticmethod
    def _fragment_seven_classes() -> dict:
        """A fragment matching the seven-class fixture, so the glyph order
        is deterministic regardless of the CWE-fallback path."""
        return {
            "schema_version": 1,
            "actors": ["victim-required", "internet-anon"],
            "attack_paths": [
                {
                    "class": "injection",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "input flows into a server-side interpreter without parameterisation.",
                    "architectural_root_causes": [],
                    "findings": ["F-001"],
                    "attack_chains": [],
                    "impact": ["customer-data-exfiltration"],
                },
                {
                    "class": "auth-bypass",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "auth can be circumvented because credentials are weak or exposed.",
                    "architectural_root_causes": [],
                    "findings": ["F-002"],
                    "attack_chains": [],
                    "impact": ["full-admin-takeover"],
                },
                {
                    "class": "privilege-escalation",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "authorisation checks are bypassable.",
                    "architectural_root_causes": [],
                    "findings": ["F-003"],
                    "attack_chains": [],
                    "impact": ["full-admin-takeover"],
                },
                {
                    "class": "sensitive-data-exposure",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "secrets reachable on unauthenticated routes.",
                    "architectural_root_causes": [],
                    "findings": ["F-004"],
                    "attack_chains": [],
                    "impact": ["customer-data-exfiltration"],
                },
                {
                    "class": "remote-code-execution",
                    "actor": "internet-anon",
                    "target": "application",
                    "description": "user data reaches a code-execution sink.",
                    "architectural_root_causes": [],
                    "findings": ["F-005"],
                    "attack_chains": [],
                    "impact": ["full-server-compromise"],
                },
                {
                    "class": "cross-site-scripting",
                    "actor": "victim-required",
                    "target": "victim",
                    "description": "attacker-controlled content rendered without sanitisation.",
                    "architectural_root_causes": [],
                    "findings": ["F-006"],
                    "attack_chains": [],
                    "impact": ["customer-session-hijack"],
                },
                {
                    "class": "cross-site-request-forgery",
                    "actor": "victim-required",
                    "target": "victim",
                    "description": "permissive CORS lets external pages forge requests.",
                    "architectural_root_causes": [],
                    "findings": ["F-007"],
                    "attack_chains": [],
                    "impact": ["customer-session-hijack"],
                },
            ],
        }

    def test_skip_section_below_threshold(self, tmp_path):
        ctx, env = self._build_ctx(
            tmp_path,
            {
                "components": [],
                "threats": [
                    {"id": "F-001", "title": "T", "component_id": "x", "cwe": "CWE-89", "risk": "Medium"},
                ],
            },
        )
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert out == ""

    def test_v2_diagram_uses_elk_renderer(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert "defaultRenderer" in out and '"elk"' in out
        assert "flowchart LR" in out

    def test_v2_three_subgraphs_with_empty_titles(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert 'subgraph ACTORS[" "]' in out
        assert 'subgraph TIERS[" "]' in out
        assert 'subgraph IMPACT[" "]' in out

    def test_v2_header_nodes_present(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert 'HDR_A["<b>Threat Actors</b>"]' in out
        assert 'HDR_T["<b>Architecture Tiers</b>"]' in out
        assert 'HDR_I["<b>Impact</b>"]' in out

    def test_v2_alignment_edges_chain_headers(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert "HDR_A --- HDR_T" in out
        assert "HDR_T --- HDR_I" in out

    def test_v2_seven_attack_arrows_with_glyphs(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # Seven solid red arrows ==>, one per attack-class entry.
        for glyph in ("①", "②", "③", "④", "⑤", "⑥", "⑦"):
            assert glyph in out, f"glyph {glyph} missing from diagram"

    def test_v2_consequence_arrows_present(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # At least one dashed consequence arrow.
        assert "-.->" in out

    def test_v2_attack_paths_bullets_below_diagram(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert "**Threat actors.**" in out
        assert "**Attack paths (numbered arrows in the diagram):**" in out
        # One bullet per glyph.
        for glyph in ("①", "②", "③", "④", "⑤", "⑥", "⑦"):
            assert f"**{glyph}" in out

    def test_v2_findings_subbullet_links_only_id(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # Findings format: `[F-NNN](#f-nnn) — Title` (only ID is the link).
        assert "[F-001](#f-001) — SQL Injection" in out
        assert "[F-007](#f-007) — CSRF" in out

    def test_v2_impact_line_comma_separated(self, tmp_path):
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes(), self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        assert "Impact: Customer Data Exfiltration" in out
        assert "Impact: Full Admin Takeover" in out
        assert "Impact: Customer Session Hijack" in out

    def test_v2_no_low_findings_in_tier_counts(self, tmp_path):
        # Add a Low-severity finding; verify it is NOT shown in tier counts.
        yaml_data = self._yaml_seven_classes()
        yaml_data["threats"].append(
            {
                "id": "F-099",
                "title": "Low Sev",
                "component_id": "rest-api",
                "cwe": "CWE-200",
                "risk": "Low",
            }
        )
        ctx, env = self._build_ctx(tmp_path, yaml_data, self._fragment_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # The tier card severity counts line must not contain a Low marker.
        # Find the Application Tier line and check. Tier names render plain
        # since P1 (B1) — bold is reserved for the three column headers
        # HDR_A / HDR_T / HDR_I, not the tier-card name itself.
        app_card_match = re.search(r'Application Tier[^"]+', out)
        assert app_card_match, "Application Tier card not found"
        assert "🟢" not in app_card_match.group(0)
        assert "Low" not in app_card_match.group(0)

    def test_v2_fallback_when_fragment_missing(self, tmp_path):
        # No fragment file → renderer falls back to CWE→class derivation.
        ctx, env = self._build_ctx(tmp_path, self._yaml_seven_classes())
        out = compose._render_security_posture_at_a_glance(ctx, env, self._section_cfg())
        # Must still produce a valid diagram + at least one bullet.
        assert "```mermaid" in out
        assert "**Attack paths (numbered arrows in the diagram):**" in out

    def test_v2_classify_finding_class(self):
        taxonomy = compose._load_attack_class_taxonomy()
        assert compose._classify_finding_class({"cwe": "CWE-89"}, taxonomy) == "injection"
        assert compose._classify_finding_class({"cwe": "CWE-79"}, taxonomy) == "cross-site-scripting"
        assert compose._classify_finding_class({"cwe": "CWE-352"}, taxonomy) == "cross-site-request-forgery"
        # Unknown CWE returns None.
        assert compose._classify_finding_class({"cwe": "CWE-9999"}, taxonomy) is None


# ---------------------------------------------------------------------------
# Pre-render repair plan — attempt counter, exhaustion, cleanup
# ---------------------------------------------------------------------------


class TestPreRenderRepairPlan:
    """The compose-time repair plan carries an `attempt` counter so the
    orchestrator can escalate out of the Stage 1 turn budget after a
    bounded number of failed fix-loop iterations. See Bug 1 follow-up.
    """

    def _err(self, section_id: str = "security_architecture") -> compose.FragmentError:
        return compose.FragmentError(
            section_id,
            "required subsection missing: '### 7.8 Real-time / WebSocket'",
        )

    def test_attempt_increments_across_successive_failures(self, tmp_path: Path) -> None:
        import json as _json

        err = self._err()
        for expected in (1, 2, 3):
            attempt = compose._emit_pre_render_repair_plan(tmp_path, err)
            assert attempt == expected
            plan = _json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
            assert plan["attempt"] == expected
            assert plan["status"] == "fail"

    def test_status_flips_to_exhausted_beyond_cap(self, tmp_path: Path) -> None:
        import json as _json

        err = self._err()
        # Burn through the budget.
        for _ in range(compose._PRE_RENDER_REPAIR_MAX_ATTEMPTS):
            compose._emit_pre_render_repair_plan(tmp_path, err)
        # One more attempt → exhausted.
        attempt = compose._emit_pre_render_repair_plan(tmp_path, err)
        assert attempt == compose._PRE_RENDER_REPAIR_MAX_ATTEMPTS + 1
        plan = _json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
        assert plan["status"] == "exhausted"

    def test_successful_compose_clears_stale_plan(self, tmp_path: Path) -> None:
        plan_path = tmp_path / ".pre-render-repair-plan.json"
        plan_path.write_text('{"status":"fail","attempt":2}')
        compose._delete_pre_render_repair_plan(tmp_path)
        assert not plan_path.exists()

    def test_plan_includes_fragment_pointer_and_remediation(self, tmp_path: Path) -> None:
        import json as _json

        compose._emit_pre_render_repair_plan(tmp_path, self._err())
        plan = _json.loads((tmp_path / ".pre-render-repair-plan.json").read_text())
        action = plan["actions"][0]
        assert action["section_id"] == "security_architecture"
        assert ".fragments/security-architecture.md" in action["fragments_to_rewrite"]
        assert action["expected_heading"] == "### 7.8 Real-time / WebSocket"
        # Remediation must point at the missing heading (`7.8 Real-time /
        # WebSocket`) and warn against the two known drift patterns: the
        # 21-section intermediate scaffold and the 14-section v1 layout.
        rem = action["remediation"]
        assert "7.8" in rem
        assert "21-section" in rem and "14-section" in rem


# ---------------------------------------------------------------------------
# Real-time console progress — V3 (per-section COMPOSE: lines) + V4 (retry counter)
# ---------------------------------------------------------------------------


class TestComposeProgress:
    """Live-progress visibility during the 15-30 s render pass. The CLI
    (`main()`) must emit a `COMPOSE: [k/N] rendering §<id>` line to stderr
    before each section so the user sees activity instead of silent waiting.
    Library callers (`render(emit_progress=False)`) stay quiet so tests
    and programmatic users do not get surprise stderr noise.
    """

    def test_render_does_not_emit_progress_by_default(self, tmp_path: Path, capsys) -> None:
        out = _prepare_output_dir(tmp_path)
        compose.render(CONTRACT, out)
        captured = capsys.readouterr()
        assert "COMPOSE:" not in captured.err

    def test_render_emits_progress_when_opted_in(self, tmp_path: Path, capsys) -> None:
        out = _prepare_output_dir(tmp_path)
        compose.render(CONTRACT, out, emit_progress=True)
        captured = capsys.readouterr()
        # At least one per-section progress line — must carry a [k/N] counter
        # and a §<id> pointer so the user can see which section is being rendered.
        lines = [l for l in captured.err.splitlines() if l.startswith("COMPOSE:")]
        assert len(lines) >= 5, f"expected several COMPOSE: lines on opt-in, got {lines!r}"
        import re as _re

        assert _re.search(r"COMPOSE: \[\d+/\d+\] rendering §\w+", lines[0]), lines[0]

    def test_main_cli_emits_progress_on_success(self, tmp_path: Path) -> None:
        import subprocess as _sp
        import sys as _sys

        out = _prepare_output_dir(tmp_path)
        result = _sp.run(
            [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "COMPOSE:" in result.stderr
        assert "RENDERED:" in result.stdout


class TestComposeRetryCounter:
    """On a FragmentError, main() emits a `RENDER_ATTEMPT: k/max` line before
    the raw error so the user immediately knows whether they are in a
    fix-loop and how close they are to exhaustion (exit 4)."""

    def _break_fragment(self, out: Path) -> None:
        # Remove a required fragment to reliably trigger FragmentError.
        (out / ".fragments" / "ms-verdict.json").unlink(missing_ok=True)

    def test_first_failure_omits_counter(self, tmp_path: Path) -> None:
        import subprocess as _sp
        import sys as _sys

        out = _prepare_output_dir(tmp_path)
        self._break_fragment(out)
        result = _sp.run(
            [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
        assert "RENDER_FAILED:" in result.stderr
        # attempt=1 is a first-time failure — no counter shown to reduce noise.
        assert "RENDER_ATTEMPT:" not in result.stderr

    def test_repeated_failure_surfaces_counter(self, tmp_path: Path) -> None:
        import subprocess as _sp
        import sys as _sys

        out = _prepare_output_dir(tmp_path)
        self._break_fragment(out)
        # Run compose three times — attempt counter must appear from run 2 onward.
        for _ in range(2):
            _sp.run(
                [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
        third = _sp.run(
            [_sys.executable, str(SCRIPT_PATH), "--contract", str(CONTRACT), "--output-dir", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert "RENDER_ATTEMPT: 3/" in third.stderr, (
            f"expected RENDER_ATTEMPT on the 3rd failed run, got stderr: {third.stderr!r}"
        )


# ---------------------------------------------------------------------------
# F-NNN stability gate for verbatim §7 preservation in quick mode.
# ---------------------------------------------------------------------------


class TestVerbatimFnnnStabilityGate:
    """Guard against silent F-NNN cross-reference corruption when a
    quick-after-thorough run carries the prior §7 forward verbatim.

    `merge_threats._assign_t_ids` reassigns T-IDs every run from a
    deterministic sort key (severity, CWE, file, line, title). A re-sort
    can move a given F-NNN slot to a different threat. The gate
    `_verbatim_fnnn_refs_match` validates the F-NNN refs cited inside the
    extracted §7 against the current threat register; on any drift the
    caller drops the verbatim and skips §7 rather than render wrong links.
    """

    @staticmethod
    def _prior_md_with_threats(rows: list[tuple[str, str]]) -> str:
        """Return a minimal prior threat-model.md whose §7 cites every F-NNN
        in ``rows`` and whose §8 register declares each F-NNN with the
        given title. ``rows`` is ``[(digits, title), ...]``."""
        section7_refs = ", ".join(f"[F-{d}](#f-{d})" for d, _ in rows)
        section7 = f"## 7. Security Architecture\n\nBackground prose referencing {section7_refs}.\n"
        section8_rows = "\n".join(
            f'| <a id="t-{d}"></a><a id="f-{d}"></a>F-{d} | {title} | Tampering | C-01 — Service | High | 7.1 | A01 | M-001 | — |'
            for d, title in rows
        )
        section8 = (
            "## 8. Threat Register\n\n"
            "| ID | Title | STRIDE | Component | Severity | CVSS | Vektor | Mitigations | Refs |\n"
            "|----|-------|--------|-----------|----------|------|--------|-------------|------|\n"
            f"{section8_rows}\n"
        )
        return section7 + "\n" + section8

    def test_returns_true_when_titles_unchanged(self) -> None:
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        prior_md = self._prior_md_with_threats(rows)
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [
            {"t_id": "T-001", "title": "SQL Injection in Login"},
            {"t_id": "T-002", "title": "Stored XSS in Feedback"},
        ]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is True

    def test_returns_false_when_fnnn_now_points_to_different_threat(self) -> None:
        """The reflow scenario: prior had F-001=SQLi, F-002=XSS; current run
        re-sorted them so F-001=XSS now refers to a different finding. The
        verbatim §7 prose still says 'F-001 — SQL Injection' but the link
        target now resolves to XSS — must reject."""
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        prior_md = self._prior_md_with_threats(rows)
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [
            {"t_id": "T-001", "title": "Stored XSS in Feedback"},
            {"t_id": "T-002", "title": "SQL Injection in Login"},
        ]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is False

    def test_returns_false_when_referenced_fnnn_resolved(self) -> None:
        """Prior §7 cited F-002, but F-002 was resolved and is no longer in
        the current register — verbatim preservation would emit a dead link."""
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        prior_md = self._prior_md_with_threats(rows)
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [
            {"t_id": "T-001", "title": "SQL Injection in Login"},
        ]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is False

    def test_returns_true_when_section_cites_no_fnnn(self) -> None:
        """A §7 with no F-NNN refs at all has nothing to validate — the
        gate must not block preservation in that case."""
        prior_md = (
            "## 7. Security Architecture\n\n"
            "General defense-in-depth narrative without any F-NNN citation.\n"
            "\n## 8. Threat Register\n\n(empty)\n"
        )
        extracted = compose._extract_section_verbatim(prior_md, top_level_number=7)
        current = [{"t_id": "T-001", "title": "Anything"}]
        assert compose._verbatim_fnnn_refs_match(extracted, prior_md, current) is True

    def test_resolve_returns_empty_when_reflow_detected(self, tmp_path: Path) -> None:
        """End-to-end: `_resolve_security_arch_override` must return "" (skip
        §7) — not the verbatim text — when the prior md and current threats
        disagree on which threat F-NNN points to."""
        out = tmp_path / "output"
        out.mkdir()
        (out / ".appsec-cache").mkdir()
        (out / ".appsec-cache" / "baseline.json").write_text(
            json.dumps({"last_run_depth": "thorough"}), encoding="utf-8"
        )
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        (out / "threat-model.md").write_text(self._prior_md_with_threats(rows), encoding="utf-8")
        # Reflowed: F-001 now points to a different threat than the prior md
        # claimed. The verbatim §7 is unsafe and must be dropped.
        current_threats = [
            {"t_id": "T-001", "title": "Stored XSS in Feedback"},
            {"t_id": "T-002", "title": "SQL Injection in Login"},
        ]
        result = compose._resolve_security_arch_override(out, "quick", current_threats)
        assert result == "", f"expected verbatim §7 dropped on reflow, got: {result!r}"

    def test_resolve_returns_verbatim_when_stable(self, tmp_path: Path) -> None:
        """End-to-end: `_resolve_security_arch_override` must return the
        verbatim §7 text when titles haven't drifted, preserving the prior
        thorough-mode narrative on the quick re-run."""
        out = tmp_path / "output"
        out.mkdir()
        (out / ".appsec-cache").mkdir()
        (out / ".appsec-cache" / "baseline.json").write_text(
            json.dumps({"last_run_depth": "thorough"}), encoding="utf-8"
        )
        rows = [("001", "SQL Injection in Login"), ("002", "Stored XSS in Feedback")]
        (out / "threat-model.md").write_text(self._prior_md_with_threats(rows), encoding="utf-8")
        current_threats = [
            {"t_id": "T-001", "title": "SQL Injection in Login"},
            {"t_id": "T-002", "title": "Stored XSS in Feedback"},
        ]
        result = compose._resolve_security_arch_override(out, "quick", current_threats)
        assert result is not None and result != "", f"expected verbatim §7 preserved when stable, got: {result!r}"
        assert result.startswith("## 7. Security Architecture")

