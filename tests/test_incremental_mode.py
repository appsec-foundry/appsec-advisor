"""
Tests for the incremental-mode architecture introduced by the incremental-mode
redesign:

  M1  skill flag matrix, hard abort, orthogonal --dry-run
  M2  baseline cache (.appsec-cache/baseline.json), changelog schema,
      mode-aware stale cleanup, git-sha diff, --yaml always-on
  M3  phase-2 recon fingerprint skip, phase-9 STRIDE carry-forward

These tests are deliberately **document-level** — they grep the agent and
skill definition markdown files for the contract the runtime has to honour.
The runtime is an LLM, so we cannot assert behaviour directly; we can only
assert that the contract documented in those files matches the contract the
code in baseline_state.py implements.

The baseline_state.py helper is tested for real (it's pure Python, no LLM).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
PLUGIN = ROOT / "plugin"
SKILL_MD = PLUGIN / "skills" / "create-threat-model" / "SKILL.md"
ANALYST_MD = PLUGIN / "agents" / "appsec-threat-analyst.md"
RECON_MD = PLUGIN / "agents" / "phases" / "phase-group-recon.md"
THREATS_MD = PLUGIN / "agents" / "phases" / "phase-group-threats.md"
FINAL_MD = PLUGIN / "agents" / "phases" / "phase-group-finalization.md"
PLUGIN_CLAUDE_MD = PLUGIN / "CLAUDE.md"
BASELINE_STATE_PY = PLUGIN / "scripts" / "baseline_state.py"
RENDER_SCHEMA_PY = PLUGIN / "scripts" / "render_threat_model_schema.py"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# M1 — skill flag matrix
# ---------------------------------------------------------------------------

class TestFlagMatrix:
    def test_skill_declares_orthogonal_flags(self):
        """INCREMENTAL and DRY_RUN must be documented as independent."""
        txt = _read(SKILL_MD)
        assert "orthogonal" in txt.lower(), \
            "SKILL.md must document that INCREMENTAL and DRY_RUN are orthogonal"

    def test_skill_hard_aborts_incremental_without_baseline(self):
        """`--incremental` + no threat-model.yaml / .md must hard-abort."""
        txt = _read(SKILL_MD)
        assert "--incremental requires an existing threat model" in txt, \
            "SKILL.md must describe the hard abort message for --incremental w/o baseline"
        assert "exit 2" in txt, "SKILL.md must use exit code 2 for the abort"

    def test_skill_rejects_full_and_incremental_together(self):
        txt = _read(SKILL_MD)
        assert "--full` + `--incremental`" in txt or \
               "--full and --incremental" in txt, \
            "SKILL.md must document the --full/--incremental conflict"
        assert "conflicting flags" in txt.lower()

    def test_skill_auto_incremental_default_with_hint(self):
        """Auto-incremental is the default when a baseline exists. The user
        must be told it's happening and how to opt out."""
        txt = _read(SKILL_MD)
        # MODE_LABEL reflects the new consolidated Configuration Summary style
        assert "incremental (auto)" in txt, \
            "MODE_LABEL must distinguish auto-incremental from explicit"
        # Hint about --full escape hatch
        assert "--full" in txt and "force" in txt.lower()

    def test_analyst_no_longer_declares_always_full(self):
        """The old contradictory '...always runs a full assessment' text must
        be gone — replaced by the 4-way mode table."""
        txt = _read(ANALYST_MD)
        assert "always runs a full assessment" not in txt

    def test_analyst_has_hard_abort_safety_net(self):
        txt = _read(ANALYST_MD)
        assert "hard abort on missing baseline" in txt.lower()
        # Must not silently fall back
        assert "falling back to full assessment" not in txt


# ---------------------------------------------------------------------------
# M1 — dry-run is orthogonal now
# ---------------------------------------------------------------------------

class TestDryRunOrthogonality:
    def test_skill_describes_two_dry_run_variants(self):
        """Classic dry-run (no baseline) AND incremental dry-run (with
        baseline) must both be documented."""
        txt = _read(SKILL_MD)
        assert "incremental dry-run" in txt.lower()
        assert "threat-model.delta.md" in txt, \
            "Dry-incremental must document the delta.md preview artifact"

    def test_skill_no_longer_forces_full_on_dry_run(self):
        txt = _read(SKILL_MD)
        # The old rule 'dry-run always runs fresh' / 'INCREMENTAL=false' is gone
        assert "dry-run always runs fresh" not in txt.lower(), \
            "SKILL.md still has the old 'dry-run forces full' rule"

    def test_finalization_has_mode_aware_write_gate(self):
        txt = _read(FINAL_MD)
        assert "Mode-Aware Write Gate" in txt
        assert "delta-preview" in txt
        assert "WRITE_MODE" in txt


# ---------------------------------------------------------------------------
# M2 — yaml schema: meta, changelog, components
# ---------------------------------------------------------------------------

class TestYamlSchema:
    def test_meta_block_documented(self):
        txt = _read(FINAL_MD)
        assert "meta:" in txt
        assert "schema_version: 1" in txt
        assert "commit_sha:" in txt
        assert "baseline_ref:" in txt

    def test_changelog_block_documented(self):
        txt = _read(FINAL_MD)
        assert "changelog:" in txt
        assert "append-only" in txt.lower()
        assert "version:" in txt
        assert "baseline_sha:" in txt
        assert "current_sha:" in txt
        # Categories
        for cat in ("added:", "changed:", "resolved:"):
            assert cat in txt, f"changelog entry must document {cat}"

    def test_components_block_documented(self):
        txt = _read(FINAL_MD)
        assert "components:" in txt
        assert "threat_ids:" in txt
        assert "paths:" in txt

    def test_tid_stability_invariant_documented(self):
        txt = _read(FINAL_MD)
        assert "stable across runs" in txt.lower() or "stable across incremental" in txt.lower()

    def test_changelog_fragment_is_registered(self):
        """00b-changelog.md must be in OPTIONAL_FRAGMENTS for the renderer."""
        # Import the module dynamically from its path
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "render_threat_model_schema", RENDER_SCHEMA_PY
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert "00b-changelog.md" in mod.OPTIONAL_FRAGMENTS


# ---------------------------------------------------------------------------
# M2 — mode-aware stale cleanup
# ---------------------------------------------------------------------------

class TestModeAwareCleanup:
    def test_claude_md_documents_mode_awareness(self):
        txt = _read(PLUGIN_CLAUDE_MD)
        assert "mode-aware" in txt.lower()
        assert "INCREMENTAL=false" in txt or "full scan" in txt.lower()

    def test_analyst_preserves_carry_forward_files_in_incremental(self):
        txt = _read(ANALYST_MD)
        assert 'if [ "$INCREMENTAL" != "true" ]; then' in txt, \
            "Stale cleanup must be gated on $INCREMENTAL"
        assert "carry-forward source" in txt.lower()


# ---------------------------------------------------------------------------
# M2 — --yaml always-on
# ---------------------------------------------------------------------------

class TestYamlAlwaysOn:
    def test_skill_marks_yaml_as_always_on(self):
        txt = _read(SKILL_MD)
        # Flag table now shows yaml as no-op (always on)
        assert "no-op" in txt or "always" in txt.lower()
        assert "--no-yaml" in txt, "Escape hatch --no-yaml must be documented"

    def test_skill_has_yaml_resolution_block(self):
        """The most important fix: SKILL.md must have an explicit
        'Resolve WRITE_YAML' block that defaults to true. Without this,
        the orchestrator has no default and falls through to 'unset'."""
        txt = _read(SKILL_MD)
        assert "## YAML Output Resolution" in txt, \
            "SKILL.md must have an explicit YAML Output Resolution section"
        assert "WRITE_YAML=true" in txt
        assert "Default" in txt and "WRITE_YAML=true" in txt, \
            "Resolution order must state that default is true"

    def test_skill_detects_yaml_noyaml_conflict(self):
        txt = _read(SKILL_MD)
        assert "--yaml` + `--no-yaml`" in txt or \
               "--yaml and --no-yaml" in txt, \
            "SKILL.md must document conflict detection for --yaml + --no-yaml"

    # ----- Bug 2: no more "only if WRITE_YAML=true" gates -----

    GATE_PHRASES = [
        "only written when `WRITE_YAML=true`",
        "only written if `WRITE_YAML=true`",
        "only if `WRITE_YAML=true`",
        "only if WRITE_YAML=true",
    ]

    def test_analyst_has_no_yaml_gates(self):
        txt = _read(ANALYST_MD)
        for phrase in self.GATE_PHRASES:
            assert phrase not in txt, \
                f"appsec-threat-analyst.md still has gate phrase: {phrase!r}"

    def test_finalization_has_no_yaml_gates(self):
        txt = _read(FINAL_MD)
        for phrase in self.GATE_PHRASES:
            assert phrase not in txt, \
                f"phase-group-finalization.md still has gate phrase: {phrase!r}"

    def test_skill_has_no_yaml_gates(self):
        txt = _read(SKILL_MD)
        # The conditional "If WRITE_YAML=true and threat-model.yaml exists:"
        # pattern from the completion summary is gone
        assert "If `WRITE_YAML=true` and `$OUTPUT_DIR/threat-model.yaml` exists" not in txt

    # ----- Bug 3: yaml schema v1 in the agent -----

    V1_SCHEMA_FIELDS = [
        "schema_version: 1",
        "commit_sha:",
        "baseline_ref:",
        "components:",
        "changelog:",
        "threat_ids:",
        "paths:",
    ]

    def test_analyst_yaml_schema_is_v1(self):
        """The schema block in appsec-threat-analyst.md must be v1 — not the
        old schema. All five new fields must be present in the schema example."""
        txt = _read(ANALYST_MD)
        # Find the schema example block
        start = txt.find("### `threat-model.yaml` schema")
        assert start != -1, "Schema section not found"
        # Take the next ~150 lines after the header
        schema_block = txt[start:start + 6000]
        for field in self.V1_SCHEMA_FIELDS:
            assert field in schema_block, \
                f"yaml schema v1 in appsec-threat-analyst.md missing field: {field!r}"

    def test_analyst_schema_is_marked_mandatory(self):
        """The schema must explicitly say that the new incremental fields
        are mandatory, not optional — otherwise Claude will 'helpfully' omit
        them."""
        txt = _read(ANALYST_MD)
        assert "mandatory" in txt.lower() and "meta.git.commit_sha" in txt, \
            "Agent must state that meta.git.commit_sha is mandatory"

    # ----- Bug 1b: CURRENT_SHA captured on every run -----

    def test_analyst_captures_current_sha_in_pre_phase(self):
        """Pre-phase step must capture CURRENT_SHA regardless of mode, so that
        a full run also populates meta.git.commit_sha."""
        txt = _read(ANALYST_MD)
        # Anchor on the actual checklist header (not the Dry-Run section that
        # also contains the phrase "Pre-Phase checklist" in passing).
        start = txt.find("**Pre-Phase checklist — run in this exact order")
        assert start != -1, "Real Pre-Phase checklist header not found"
        pre_phase = txt[start:start + 6000]
        assert "CURRENT_SHA" in pre_phase, \
            "Pre-phase checklist must capture CURRENT_SHA on every run"
        assert 'git -C "$REPO_ROOT" rev-parse HEAD' in pre_phase, \
            "Pre-phase checklist must run git rev-parse HEAD explicitly"


class TestRunHeadlessScript:
    def test_run_headless_parses_no_yaml(self):
        txt = (ROOT / "scripts" / "run-headless.sh").read_text()
        assert "--no-yaml" in txt
        # And it must appear in the flag parsing case statement
        assert "|--no-yaml|" in txt


# ---------------------------------------------------------------------------
# Legacy md-only bootstrap path (the interactive-mode regression)
# ---------------------------------------------------------------------------

class TestLegacyBaselineBootstrap:
    """The critical UX path: users upgrading from pre-M2 plugin have a
    threat-model.md but no threat-model.yaml. Without the bootstrap path,
    their first run after the upgrade hits 'no baseline commit sha' and
    aborts. The skill + orchestrator must handle this gracefully."""

    def test_skill_documents_three_baseline_states(self):
        txt = _read(SKILL_MD)
        # The new three-way classification
        assert "BASELINE_STATE" in txt
        for state in ("empty", "legacy", "structured"):
            assert f'="{state}"' in txt or f'={state}' in txt or \
                   f'`{state}`' in txt, \
                f"SKILL.md must document BASELINE_STATE={state}"

    def test_skill_legacy_md_auto_bootstraps(self):
        """No flag + legacy md → full scan, NOT incremental."""
        txt = _read(SKILL_MD)
        assert "bootstrap" in txt.lower()
        assert "legacy threat-model.md detected" in txt or \
               "Legacy threat-model.md found" in txt
        # The bootstrap rule must explicitly set MODE=full, not incremental
        assert 'MODE=full` (**bootstrap run**)' in txt or \
               "MODE=full (**bootstrap run**)" in txt or \
               "bootstrap" in txt and "MODE=full" in txt

    def test_skill_incremental_flag_on_legacy_hard_aborts(self):
        """Explicit --incremental on legacy md must give an actionable error."""
        txt = _read(SKILL_MD)
        # Must mention the actionable fix: run without --incremental
        assert "run once without --incremental" in txt.lower() or \
               "run without --incremental" in txt.lower()
        assert "bootstrap threat-model.yaml" in txt

    def test_skill_distinguishes_legacy_from_structured(self):
        """The new resolution table must have separate rules for legacy and
        structured baselines — not just 'baseline present'."""
        txt = _read(SKILL_MD)
        assert "BASELINE_STATE=legacy" in txt
        assert "BASELINE_STATE=structured" in txt
        assert "BASELINE_STATE=empty" in txt


class TestCriticalAttackChainPromotion:
    """The unnumbered ## Critical Attack Chain block is the executive-level
    overview placed directly after the Management Summary. It contains the
    high-level Mermaid graph LR + the Quick-reference table. This class pins
    that layout + the forbidden Management Summary subsections.

    Section 3/9 layout is covered in TestSection3StubAndSection9Walkthroughs.
    """

    # ---- Management Summary: forbidden subsections ----

    FORBIDDEN_MGMT_SUMMARY_SUBSECTIONS = [
        "### Top Findings",
        "### Top Critical Findings",
        "### Critical Findings",
        "### Recommended Priority Actions",
        "### Key Strengths",
        "### Overall Security Rating",
    ]

    def test_mgmt_summary_forbidden_list_is_explicit(self):
        """The Management Summary spec must explicitly name each forbidden
        subsection — not just imply it by listing the allowed ones."""
        txt = _read(THREATS_MD)
        for forbidden in self.FORBIDDEN_MGMT_SUMMARY_SUBSECTIONS:
            assert forbidden in txt, \
                f"Management Summary spec must explicitly forbid {forbidden!r}"

    def test_mgmt_summary_forbidden_list_names_replacement(self):
        """Forbidding a subsection without telling Claude where the content
        went is worse than saying nothing. Verify each forbidden heading
        points to its replacement."""
        txt = _read(THREATS_MD)
        assert "Top Findings" in txt and "Critical Attack Chain" in txt
        assert "Recommended Priority Actions" in txt
        assert "Key Strengths" in txt and "Operational Strengths" in txt

    # ---- ## Critical Attack Chain layout ----

    def test_critical_attack_chain_layout_documented(self):
        txt = _read(THREATS_MD)
        assert "## Critical Attack Chain" in txt
        assert "#critical-attack-chain" in txt
        assert "unnumbered" in txt.lower()

    def test_critical_attack_chain_position_documented(self):
        """Position: directly after Management Summary, before Section 1."""
        txt = _read(THREATS_MD)
        lower = txt.lower()
        assert "immediately after the management summary" in lower or \
               "directly after the management summary" in lower
        assert "before section 1" in lower

    def test_critical_attack_chain_forbids_per_finding_blocks(self):
        """The Mermaid chain + quick-reference table are the only allowed
        formats in the Attack Chain block. Per-finding prose blocks belong
        in Section 9 Attack Walkthroughs, not here."""
        txt = _read(THREATS_MD)
        assert "No per-finding prose blocks" in txt
        assert "Quick-reference table is the only" in txt or \
               "Quick-reference table is the only per-finding presentation" in txt

    def test_finalization_section_order_places_attack_chain_after_mgmt_summary(self):
        txt = _read(FINAL_MD)
        # Order: Management Summary → Critical Attack Chain → Section 3 stub → 4 → … → 9 Attack Walkthroughs
        mgmt_idx = txt.find("**Management Summary**")
        chain_idx = txt.find("**Critical Attack Chain**")
        s3_idx = txt.find("## 3. Security-Relevant Use Cases`**")
        s4_idx = txt.find("Sections 4–7")
        assert mgmt_idx != -1 and chain_idx != -1 and s4_idx != -1, \
            "Section order markers missing from phase-group-finalization.md"
        assert mgmt_idx < chain_idx < s4_idx, \
            "Section order must be: Management Summary → Critical Attack Chain → … → Section 4+"
        # Section 3 stub also appears between Critical Attack Chain and Section 4
        if s3_idx != -1:
            assert chain_idx < s3_idx < s4_idx

    # ---- QA reviewer: no auto-fix back into old Section 9 format ----

    def test_qa_reviewer_no_longer_auto_adds_per_finding_blocks(self):
        """The old 3c auto-fix added ### 🔴 T-NNN blocks to Section 9.
        That was the opposite of what the current layout wants. Verify the
        old language is gone."""
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        assert "### 🔴 T-NNN — <short title" not in txt
        assert "ATTACK_CHAIN_TABLE" in txt
        assert "Add it to Section 9 in-place" not in txt


class TestSection3StubAndSection9Walkthroughs:
    """Section 3 is now a 2-line stub; Section 9 holds the attack
    walkthroughs (sequence diagrams, one per Critical finding, curated to
    max 5, tied to T-NNN, with fixed alt/else branch semantics).

    This class pins the Section-3-→-Section-9 move so it cannot regress.
    """

    # ---- Section 3 is a stub ----

    def test_section_3_intro_is_stub_only_directive(self):
        """phase-group-architecture.md must explicitly document Section 3
        as STUB ONLY in the intro-sentence rules."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "Section 3 (Security-Relevant Use Cases):** **STUB ONLY**" in txt or \
               "**STUB ONLY**" in txt

    def test_section_3_stub_template_exists(self):
        """The verbatim stub template must be in the spec."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "### Section 3 stub template" in txt
        # The template must point at Section 9 attack walkthroughs (not the old Critical Findings anchor)
        assert "[Section 9 — Attack Walkthroughs](#9-attack-walkthroughs)" in txt

    def test_section_3_stub_forbids_content(self):
        """Rules list must forbid tables, bullets, Mermaid blocks, and
        `### 3.x` sub-sections inside the stub."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "No tables, no bullets, no Mermaid blocks, no `### 3.x`" in txt

    def test_section_3_subsection_intro_rule_removed(self):
        """The old '### 3.x Flow name' sub-section-intro-sentence rule
        must no longer mandate sub-sections for Section 3."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        # The rule now targets Section 9 sub-sections, not Section 3
        assert "### 9.x" in txt or "Section 9 sub-sections" in txt
        # The old "every sequence diagram MUST open with ... attack path"
        # language tied to Section 3 specifically should be gone
        assert "### 3.x Flow name" not in txt

    # ---- Section 9 is real content (Attack Walkthroughs) ----

    def test_phase_4_renders_section_9_not_section_3(self):
        """Phase 4 renames target: Section 3 → Section 9."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "## Phase 4: Attack Walkthroughs (renders Section 9)" in txt
        # Phase number stays 4 for orchestrator ordering
        assert "Phase number stays 4" in txt or "stays 4" in txt

    def test_section_9_has_curation_rule(self):
        """Curation to Critical findings only, max 5, ordered by chain nodes."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "Curation — Critical only" in txt
        assert "max 5" in txt.lower() or "Cap at **5**" in txt
        # Explicit exclusion of non-critical
        assert "not add walkthroughs for High-" in txt or \
               "Phase 4 does not add walkthroughs for High" in txt

    def test_section_9_has_fixed_alt_else_semantics(self):
        """Labels are fixed: alt = Current state — T-NNN (attack-path),
        else = After M-NNN — <mitigation>."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "alt Current state — T-" in txt
        assert "else After M-" in txt
        # The old "normal vs attack" pattern is explicitly deleted
        assert '"normal vs attack" pattern from the old spec is **deleted**' in txt or \
               "is **deleted**" in txt

    def test_section_9_empty_state_documented(self):
        """CRIT_COUNT == 0 → Section 9 renders a 2-line empty-state stub
        pointing to Section 8."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "CRIT_COUNT == 0" in txt
        assert "Section 9 is a 2-line stub" in txt or \
               "No critical-severity attack walkthroughs" in txt

    def test_section_9_heading_renamed(self):
        """Heading is `## 9. Attack Walkthroughs`, anchor is
        `#9-attack-walkthroughs`. The old `#9-critical-findings` is
        deliberately broken."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-threats.md")
        assert "## 9. Attack Walkthroughs" in txt
        assert "#9-attack-walkthroughs" in txt
        # Must explicitly mark the old anchor as broken (not silent break)
        assert "is **broken** by this renaming" in txt or \
               "deliberately broken" in txt or \
               "old anchor `#9-critical-findings` is" in txt

    def test_phase_4_deferred_rendering_documented(self):
        """Phase 4 runs before Phase 9, so T-NNN don't exist yet at Phase 4
        time. The spec must document the deferred rendering via stable
        slugs + Phase 11 swap, or Phase 4 would produce walkthroughs with
        placeholder IDs that never get resolved."""
        txt = _read(PLUGIN / "agents" / "phases" / "phase-group-architecture.md")
        assert "deferred rendering" in txt.lower()
        assert "stable" in txt.lower() and "slug" in txt.lower()
        assert "Phase 11" in txt

    # ---- Finalization section order is correct ----

    def test_finalization_lists_section_9_as_attack_walkthroughs(self):
        txt = _read(FINAL_MD)
        assert "Section 9 — Attack Walkthroughs" in txt
        assert "#9-attack-walkthroughs" in txt
        # The old "Section 9 — stub" commentary is gone
        assert "Section 9 — **stub**" not in txt

    def test_finalization_lists_section_3_as_stub(self):
        txt = _read(FINAL_MD)
        assert "## 3. Security-Relevant Use Cases`**" in txt
        assert "two-line stub" in txt

    # ---- QA reviewer ----

    def test_qa_reviewer_section_3_presence_expects_stub(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        # Section 3 presence row now demands stub, not sequenceDiagram
        assert "Present as a **two-line stub**" in txt
        # The old "Present and contains at least one `sequenceDiagram`"
        # requirement for Section 3 is gone
        s3_row = txt.split("## 3. Security-Relevant Use Cases")[1][:400] \
            if "## 3. Security-Relevant Use Cases" in txt else ""
        assert "Present and contains at least one `sequenceDiagram`" not in s3_row

    def test_qa_reviewer_section_9_presence_expects_walkthroughs(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        assert "## 9. Attack Walkthroughs" in txt
        # The presence-check row in the structural-quality table specifically
        # — anchor on the row prefix so we don't match the Section 3 stub
        # description which also mentions Section 9 by name.
        row_anchor = "| `## 9. Attack Walkthroughs`"
        s9_idx = txt.find(row_anchor)
        assert s9_idx != -1, \
            f"Presence table row for Section 9 not found; expected {row_anchor!r}"
        s9_row = txt[s9_idx:s9_idx + 800]
        assert "sequenceDiagram" in s9_row
        assert "Critical finding" in s9_row or "Critical row" in s9_row
        # Empty-state fallback must be documented in the same row
        assert "empty-state" in s9_row.lower() or "CRIT_COUNT == 0" in s9_row

    def test_qa_reviewer_enforces_alt_else_label_semantics(self):
        """8e check must enforce `alt Current state — T-` and
        `else After M-` labelling."""
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        assert "alt Current state — T-" in txt
        assert "else After M-" in txt
        # Branch label check must exist
        assert "Branch labelling check" in txt or \
               "alt branch must be labelled" in txt

    def test_qa_reviewer_enforces_critical_only_curation(self):
        """T-NNN in a walkthrough alt-branch must resolve to a Critical
        finding in Section 8.1 — not a High/Medium/Low."""
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        assert "T-NNN anchor check" in txt or \
               "not a Critical finding in Section 8.1" in txt
        assert "Section 9 walkthroughs are curated to Critical" in txt

    def test_qa_reviewer_section_9_subsection_intros(self):
        """The sub-section intro check now targets Section 9 (attack
        walkthroughs), not Section 3."""
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        assert "### 9.x" in txt or "Section 9 sub-sections" in txt
        # Section 3 is explicitly skipped (it's a stub with no sub-sections)
        assert "Section 3 is a stub" in txt

    def test_qa_reviewer_sequence_diagram_checks_target_section_9(self):
        """Check 8e (alt/else required) and 8f (annotator markers) must
        target Section 9, not Section 3."""
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        # The check text should say "Section 9" now
        assert "sequenceDiagram` in Section 9" in txt
        # And not "Section 3" in the context of sequence diagrams
        assert "sequenceDiagram` in Section 3" not in txt


# ---------------------------------------------------------------------------
# C2 — Security Architecture Assessment: optional per-theme diagrams
# ---------------------------------------------------------------------------

ARCH_MD = PLUGIN / "agents" / "phases" / "phase-group-architecture.md"


class TestArchitectureAssessmentThemeDiagrams:
    """The Cross-Cutting Architecture Findings sub-section allows optional
    compact Mermaid diagrams for four of the six themes. This class pins
    the rules: which themes, which type, which size, which depth caps."""

    ALLOWED_THEMES = [
        "Secret Management",
        "Authentication",
        "Authorization & Access Control",
        "Separation & Isolation",
    ]

    FORBIDDEN_THEMES = [
        "Input Validation & Output Encoding",
        "Defense-in-Depth",
    ]

    def test_spec_has_optional_diagram_section(self):
        txt = _read(ARCH_MD)
        assert "Optional per-theme diagrams (Cross-Cutting Architecture Findings)" in txt

    def test_four_allowed_themes_named(self):
        txt = _read(ARCH_MD)
        # Each allowed theme must be mentioned by name in the guidance section
        # (not just in the theme list itself — the guidance paragraph must call it out)
        spec = txt.split("Optional per-theme diagrams")[-1]
        for theme in self.ALLOWED_THEMES:
            assert theme in spec, \
                f"Allowed theme {theme!r} missing from optional-diagram guidance"

    def test_two_forbidden_themes_explicit(self):
        txt = _read(ARCH_MD)
        spec = txt.split("Optional per-theme diagrams")[-1]
        # Both themes must be documented as prohibited, with a reason
        assert "Input Validation & Output Encoding" in spec
        assert "code-level" in spec.lower()
        assert "Defense-in-Depth" in spec
        assert "Technology Architecture" in spec, \
            "Defense-in-Depth must point readers to the existing Section 2.x tech stack"

    def test_diagram_type_restricted_to_graph(self):
        txt = _read(ARCH_MD)
        spec = txt.split("Optional per-theme diagrams")[-1]
        assert "`graph LR` or `graph TB`" in spec
        # sequenceDiagram is explicitly disallowed here
        assert "Never" in spec and "sequenceDiagram" in spec

    def test_node_count_capped(self):
        txt = _read(ARCH_MD)
        spec = txt.split("Optional per-theme diagrams")[-1]
        # Node budget: 3-7
        assert "3 to 7" in spec or "3-7" in spec or "maximum" in spec.lower()

    def test_key_takeaway_mandatory(self):
        txt = _read(ARCH_MD)
        spec = txt.split("Optional per-theme diagrams")[-1]
        assert "Key takeaway" in spec

    def test_depth_aware_limits_documented(self):
        """Limits: quick=0, standard=1-2, thorough=up to 4."""
        txt = _read(ARCH_MD)
        spec = txt.split("Optional per-theme diagrams")[-1]
        # Quick: 0
        assert "`minimal` (quick) | **0**" in spec or \
               "quick" in spec.lower() and "**0**" in spec
        # Standard: 1-2
        assert "`standard` | **1–2**" in spec or "**1–2**" in spec
        # Thorough: up to 4
        assert "**Up to 4**" in spec or "Up to 4" in spec

    def test_example_is_secret_management(self):
        """The worked example should demonstrate the most canonical fit
        (Secret Management current → target)."""
        txt = _read(ARCH_MD)
        spec = txt.split("Optional per-theme diagrams")[-1]
        assert "Example — Secret Management" in spec or \
               "Example" in spec and "Secret Management" in spec

    # ---- QA reviewer enforcement ----

    def test_qa_reviewer_check_documented(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        assert "Section 2.x per-theme diagram check" in txt
        # All five concrete sub-checks must be named
        assert "Wrong diagram type" in txt
        assert "Prohibited-theme diagram" in txt
        assert "Node-count overload" in txt
        assert "Missing Key takeaway" in txt
        assert "Depth-aware count cap" in txt

    def test_qa_reviewer_flags_sequence_diagram_inside_theme(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        # Wrong-type list must include sequenceDiagram
        theme_check = txt.split("Section 2.x per-theme diagram check")[-1]
        assert "sequenceDiagram" in theme_check
        assert "only `graph LR` or `graph TB`" in theme_check or \
               "graph LR" in theme_check and "graph TB" in theme_check

    def test_qa_reviewer_flags_prohibited_themes_by_name(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        theme_check = txt.split("Section 2.x per-theme diagram check")[-1]
        assert "Input Validation & Output Encoding" in theme_check
        assert "Defense-in-Depth" in theme_check

    def test_qa_reviewer_node_cap_is_7(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        theme_check = txt.split("Section 2.x per-theme diagram check")[-1]
        assert "> 7" in theme_check or "more than 7" in theme_check

    def test_qa_reviewer_depth_cap_matches_spec(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        theme_check = txt.split("Section 2.x per-theme diagram check")[-1]
        # Must mention minimal=0, standard=2, extended=4 exactly
        assert "cap is **0**" in theme_check
        assert "cap is **2**" in theme_check
        assert "cap is **4**" in theme_check


class TestOrchestratorGracefulFallback:
    """The orchestrator's safety-net downgrade. Even if the skill layer is
    bypassed (direct agent test invocation) or the yaml got corrupted, the
    orchestrator must downgrade to full instead of aborting hard."""

    def test_orchestrator_downgrades_on_missing_commit_sha(self):
        txt = _read(ANALYST_MD)
        assert "Downgrading to full scan" in txt, \
            "Orchestrator must downgrade on missing baseline commit sha"
        assert "Existing changelog[] history will be preserved" in txt

    def test_orchestrator_handles_force_push_baseline(self):
        """If yaml has a commit_sha but that commit no longer exists (force
        push, history rewrite), downgrade — don't crash."""
        txt = _read(ANALYST_MD)
        assert "git cat-file -e" in txt or \
               "no longer exists in the git history" in txt
        assert "force-push" in txt.lower() or "history rewrite" in txt.lower()

    def test_orchestrator_does_not_abort_hard_on_fallback(self):
        """The old 'exit 2' on missing commit_sha must be gone — replaced
        by the downgrade path. The fallback block sets INCREMENTAL=false
        and falls through to full-scan, NOT exit 2."""
        txt = _read(ANALYST_MD)
        # Find the baseline-sha resolution section
        idx = txt.find("Graceful fallback")
        assert idx != -1, "Graceful fallback section not found"
        fallback = txt[idx:idx + 3000]
        # Must set INCREMENTAL=false and NOT exit 2
        assert "INCREMENTAL=false" in fallback
        # The old 'exit 2' inside the fallback path is gone
        assert "  exit 2" not in fallback, \
            "Fallback path must not exit 2 — it must downgrade"

    def test_orchestrator_does_not_print_fallback_as_error(self):
        """The downgrade is a normal transition for pre-M2 users, not an
        error. Agent must document this explicitly."""
        txt = _read(ANALYST_MD)
        assert "not a failure" in txt.lower() or \
               "not print this as an error" in txt.lower()
        assert "one-time transition" in txt.lower()


# ---------------------------------------------------------------------------
# M2 — git-sha baseline resolution
# ---------------------------------------------------------------------------

class TestGitShaBaseline:
    def test_analyst_uses_yaml_commit_sha_not_head_tilde(self):
        txt = _read(ANALYST_MD)
        # The old HEAD~1..HEAD pattern as the only source is gone
        assert '"$BASELINE_SHA"..HEAD' in txt
        assert "APPSEC_BASELINE_REF" in txt, \
            "CI override env var must be documented"
        assert "meta.git.commit_sha" in txt

    def test_analyst_downgrades_instead_of_aborting_on_missing_sha(self):
        """M2-revision: the old hard abort on missing commit_sha was wrong for
        legacy users. It is now replaced by a graceful downgrade to full scan.
        This is verified in depth in TestOrchestratorGracefulFallback; here
        we just assert the obsolete abort message is gone."""
        txt = _read(ANALYST_MD)
        assert "no baseline commit sha available" not in txt, \
            "Old hard-abort message must be gone — replaced by graceful downgrade"


# ---------------------------------------------------------------------------
# M3 — phase 2 recon fingerprint skip
# ---------------------------------------------------------------------------

class TestReconFingerprintSkip:
    def test_recon_documents_skip_logic(self):
        txt = _read(RECON_MD)
        assert "fingerprint skip" in txt.lower()
        assert "check-fingerprint" in txt
        assert "RECON_SKIP" in txt

    def test_recon_has_conservative_fingerprint_rule(self):
        txt = _read(RECON_MD)
        assert "conservative" in txt.lower()


# ---------------------------------------------------------------------------
# M3 — phase 9 STRIDE carry-forward
# ---------------------------------------------------------------------------

class TestStrideCarryForward:
    def test_threats_documents_three_paths(self):
        """re-dispatch / carry-forward / fresh-for-new components"""
        txt = _read(THREATS_MD)
        assert "Re-dispatch" in txt
        assert "Carry forward" in txt
        assert "Fresh analysis for new components" in txt or \
               "new components" in txt.lower()

    def test_threats_documents_integrity_check(self):
        txt = _read(THREATS_MD)
        assert "sha256" in txt
        assert "CARRY_FORWARD_HASH_MISMATCH" in txt

    def test_threats_documents_removed_components(self):
        txt = _read(THREATS_MD)
        assert "component removed" in txt.lower() or \
               "removed components" in txt.lower()

    def test_threats_documents_stable_tids(self):
        txt = _read(THREATS_MD)
        assert "keep their T-IDs" in txt or \
               "T-IDs remain stable" in txt or \
               "T-IDs keep" in txt


# ---------------------------------------------------------------------------
# baseline_state.py — real Python tests
# ---------------------------------------------------------------------------

def _run_bs(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BASELINE_STATE_PY), *args],
        capture_output=True, text=True, cwd=cwd,
    )


class TestBaselineState:
    @pytest.fixture
    def repo(self, tmp_path: Path) -> Path:
        (tmp_path / "repo").mkdir()
        (tmp_path / "repo" / "package.json").write_text(
            '{"name":"x","version":"1.0.0"}'
        )
        (tmp_path / "repo" / "Dockerfile").write_text("FROM alpine\n")
        return tmp_path / "repo"

    @pytest.fixture
    def output_dir(self, tmp_path: Path) -> Path:
        d = tmp_path / "out"
        d.mkdir()
        (d / "threat-model.yaml").write_text(
            "meta:\n  git:\n    commit_sha: abc123\n"
            "threats:\n  - id: T-001\n  - id: T-007\n"
            "mitigations:\n  - id: M-003\n"
        )
        (d / ".stride-auth-svc.json").write_text('{"threats":[]}')
        return d

    def test_update_writes_baseline_json(self, repo, output_dir):
        r = _run_bs(
            "update", "--output-dir", str(output_dir),
            "--repo-root", str(repo), "--mode", "full",
        )
        assert r.returncode == 0, r.stderr
        cache = output_dir / ".appsec-cache" / "baseline.json"
        assert cache.is_file()
        data = json.loads(cache.read_text())
        assert data["schema_version"] == 1
        # next_threat_id must be past highest T-ID in yaml (T-007 → next = 8)
        assert data["id_counters"]["next_threat_id"] == 8
        # next_mitigation_id past M-003 → 4
        assert data["id_counters"]["next_mitigation_id"] == 4
        # Fingerprint captured manifest + dockerfile
        assert "package.json" in data["recon_fingerprint"]["manifests"]
        assert "Dockerfile" in data["recon_fingerprint"]["dockerfiles"]
        # Stride file hashed
        assert "auth-svc" in data["stride_files"]

    def test_validate_accepts_fresh_cache(self, repo, output_dir):
        _run_bs("update", "--output-dir", str(output_dir),
                "--repo-root", str(repo), "--mode", "full")
        r = _run_bs("validate", "--output-dir", str(output_dir))
        assert r.returncode == 0
        assert "VALID" in r.stdout

    def test_check_fingerprint_matches_unchanged_repo(self, repo, output_dir):
        _run_bs("update", "--output-dir", str(output_dir),
                "--repo-root", str(repo), "--mode", "full")
        r = _run_bs(
            "check-fingerprint", "--output-dir", str(output_dir),
            "--repo-root", str(repo),
        )
        assert r.returncode == 0
        assert "unchanged" in r.stdout

    def test_check_fingerprint_detects_dockerfile_change(self, repo, output_dir):
        _run_bs("update", "--output-dir", str(output_dir),
                "--repo-root", str(repo), "--mode", "full")
        (repo / "Dockerfile").write_text("FROM debian\n")
        r = _run_bs(
            "check-fingerprint", "--output-dir", str(output_dir),
            "--repo-root", str(repo),
        )
        assert r.returncode == 1
        assert "changed" in r.stdout.lower()

    def test_check_fingerprint_detects_new_manifest(self, repo, output_dir):
        _run_bs("update", "--output-dir", str(output_dir),
                "--repo-root", str(repo), "--mode", "full")
        (repo / "requirements.txt").write_text("flask==2.0\n")
        r = _run_bs(
            "check-fingerprint", "--output-dir", str(output_dir),
            "--repo-root", str(repo),
        )
        assert r.returncode == 1
        assert "+manifests:requirements.txt" in r.stdout

    def test_id_counter_never_regresses(self, repo, output_dir):
        """Even if the yaml has been edited to remove threats, the counter
        must never go backwards — that would risk ID reuse."""
        _run_bs("update", "--output-dir", str(output_dir),
                "--repo-root", str(repo), "--mode", "full")
        # Simulate yaml shrinking (T-007 removed)
        (output_dir / "threat-model.yaml").write_text(
            "meta:\n  git:\n    commit_sha: def456\n"
            "threats:\n  - id: T-001\n"
        )
        _run_bs("update", "--output-dir", str(output_dir),
                "--repo-root", str(repo), "--mode", "incremental")
        data = json.loads((output_dir / ".appsec-cache" / "baseline.json").read_text())
        assert data["id_counters"]["next_threat_id"] >= 8, \
            "counter must never go backwards"

    def test_missing_output_dir_errors(self, tmp_path):
        r = _run_bs(
            "update",
            "--output-dir", str(tmp_path / "does-not-exist"),
            "--repo-root", str(tmp_path),
            "--mode", "full",
        )
        assert r.returncode != 0
        assert "not found" in r.stderr.lower()
