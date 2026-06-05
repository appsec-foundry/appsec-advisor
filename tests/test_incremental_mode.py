"""
Tests for the incremental-mode architecture introduced by the incremental-mode
redesign:

  M1  skill flag matrix, hard abort, --dry-run as full preview to temp
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
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
PLUGIN = ROOT
SKILL_MD = PLUGIN / "skills" / "create-threat-model" / "SKILL.md"
SKILL_IMPL_MD = PLUGIN / "skills" / "create-threat-model" / "SKILL-impl.md"
ANALYST_MD = PLUGIN / "agents" / "appsec-threat-analyst.md"
RECON_MD = PLUGIN / "agents" / "phases" / "phase-group-recon.md"
THREATS_MD = PLUGIN / "agents" / "phases" / "phase-group-threats.md"
FINAL_MD = PLUGIN / "agents" / "phases" / "phase-group-finalization.md"
PLUGIN_AGENTS_MD = PLUGIN / "AGENTS.md"
BASELINE_STATE_PY = PLUGIN / "scripts" / "baseline_state.py"
RENDER_SCHEMA_PY = PLUGIN / "scripts" / "render_threat_model_schema.py"


def _read(p: Path) -> str:
    if p == SKILL_MD:
        return SKILL_MD.read_text(encoding="utf-8") + "\n" + SKILL_IMPL_MD.read_text(encoding="utf-8")
    return p.read_text(encoding="utf-8")


def _assert_doc_invariant(
    file_path: Path,
    any_of: list[str] | None = None,
    all_of: list[str] | None = None,
    none_of: list[str] | None = None,
    case_insensitive: bool = False,
    section_anchor: str | None = None,
) -> None:
    """Single engine used by every parametrized doc-assertion in this file.

    Each invariant can declare:
      any_of         — at least one of these phrases must appear (OR semantics)
      all_of         — every one of these phrases must appear (AND semantics)
      none_of        — every one of these phrases must be absent
      section_anchor — if set, the haystack is restricted to the text after the
                       LAST occurrence of this string. Used for "this phrase
                       must appear inside section X" style checks.

    Fails with a diagnostic message that names the file, the violated clause,
    and the specific missing/forbidden phrase — no silent `assert x in y`
    failures with blank tracebacks.
    """
    text = _read(file_path)
    if section_anchor:
        if section_anchor not in text:
            raise AssertionError(f"{file_path.name}: section anchor not found — {section_anchor!r}")
        text = text.split(section_anchor)[-1]
    haystack = text.lower() if case_insensitive else text

    def _match(phrase: str) -> bool:
        needle = phrase.lower() if case_insensitive else phrase
        return needle in haystack

    def _loc() -> str:
        return f"{file_path.name}" + (f" (after {section_anchor!r})" if section_anchor else "")

    if any_of and not any(_match(p) for p in any_of):
        raise AssertionError(
            f"{_loc()}: none of the required alternatives were present.\n"
            f"  any_of = {any_of!r}\n"
            f"  (case_insensitive={case_insensitive})"
        )
    if all_of:
        missing = [p for p in all_of if not _match(p)]
        if missing:
            raise AssertionError(
                f"{_loc()}: missing required phrase(s): {missing!r}\n  (case_insensitive={case_insensitive})"
            )
    if none_of:
        forbidden = [p for p in none_of if _match(p)]
        if forbidden:
            raise AssertionError(
                f"{_loc()}: forbidden phrase(s) found: {forbidden!r}\n  (case_insensitive={case_insensitive})"
            )


# Schema for the `_DOC_INVARIANTS` tables below: each row is a 7-tuple
#   (case_id, file_path, any_of, all_of, none_of, case_insensitive, section_anchor)
# Keep `any_of` / `all_of` / `none_of` as `None` (not empty list) when unused —
# makes pytest IDs and failure messages cleaner.


# ---------------------------------------------------------------------------
# M1 — skill flag matrix
# ---------------------------------------------------------------------------

# (case_id, file, any_of, all_of, none_of, case_insensitive)
#
# Since M3.2 the flag-resolution logic lives in scripts/resolve_config.py,
# so the "skill-*" invariants below now point at the Python source instead
# of SKILL.md prose. Behavioural tests live in tests/test_resolve_config.py —
# these are doc/source freezes that guarantee the concepts are present in
# the code (not accidentally dropped during a future refactor).
RESOLVE_CONFIG_PY = PLUGIN / "scripts" / "resolve_config.py"

_FLAG_MATRIX_INVARIANTS = [
    ("resolver-dry-run-forces-full", RESOLVE_CONFIG_PY, None, ["dry_run"], None, False),
    (
        "resolver-hard-aborts-without-baseline",
        RESOLVE_CONFIG_PY,
        None,
        ["--incremental requires an existing threat model"],
        None,
        False,
    ),
    (
        "resolver-rejects-full-and-incremental-together",
        RESOLVE_CONFIG_PY,
        None,
        ["--full and --incremental cannot be used together"],
        None,
        False,
    ),
    ("skill-auto-incremental-default-with-hint", SKILL_MD, None, ["--reasoning-model"], None, True),
    ("analyst-no-longer-declares-always-full", ANALYST_MD, None, None, ["always runs a full assessment"], False),
    (
        "analyst-has-hard-abort-safety-net",
        ANALYST_MD,
        None,
        ["hard abort on missing baseline"],
        ["falling back to full assessment"],
        True,
    ),
    (
        "analyst-does-not-receive-dry-run",
        ANALYST_MD,
        ["orchestrator does not receive or check", "does not receive or check `dry_run`"],
        None,
        None,
        True,
    ),
]


class TestFlagMatrix:
    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive",
        [(f, a, al, n, ci) for _, f, a, al, n, ci in _FLAG_MATRIX_INVARIANTS],
        ids=[cid for cid, *_ in _FLAG_MATRIX_INVARIANTS],
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive)


def _run_doc_table(table: list[tuple]) -> tuple[list[tuple], list[str]]:
    """Flatten a 7-tuple `_DOC_INVARIANTS`-style table into the
    (params, ids) pair pytest.mark.parametrize expects.

    Input row: (case_id, file_path, any_of, all_of, none_of, case_insensitive, section_anchor)
    Output row: (file_path, any_of, all_of, none_of, case_insensitive, section_anchor)
    """
    params = [(f, a, al, n, ci, sec) for _, f, a, al, n, ci, sec in table]
    ids = [cid for cid, *_ in table]
    return params, ids


# ---------------------------------------------------------------------------
# M1 — dry-run runs full analysis to temp, prints console summary
# ---------------------------------------------------------------------------

_DRY_RUN_INVARIANTS = [
    # case_id, file, any_of, all_of, none_of, case_insensitive, section_anchor
    (
        "skill-describes-dry-run-as-full-preview-pipeline",
        SKILL_MD,
        ["full assessment pipeline", "full analysis"],
        None,
        None,
        True,
        None,
    ),
    ("skill-describes-dry-run-as-full-preview-tempdir", SKILL_MD, ["/tmp", "temp"], None, None, True, None),
    ("skill-describes-dry-run-extracts-management-summary", SKILL_MD, None, ["management summary"], None, True, None),
    ("skill-dry-run-forces-full", SKILL_MD, ["incremental=false", "forces a full"], None, None, True, None),
    ("skill-dry-run-cleans-up-temp", SKILL_MD, None, ["rm -rf", "output_dir"], None, True, None),
    (
        "finalization-has-mode-aware-write-gate",
        FINAL_MD,
        None,
        ["Mode-Aware Write Gate", "WRITE_MODE"],
        None,
        False,
        None,
    ),
]


class TestDryRunMode:
    _params, _ids = _run_doc_table(_DRY_RUN_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)


# ---------------------------------------------------------------------------
# M2 — yaml schema: meta, changelog, components
# ---------------------------------------------------------------------------

_YAML_SCHEMA_INVARIANTS = [
    # case_id, file, any_of, all_of, none_of, case_insensitive, section_anchor
    (
        "meta-block-documented",
        FINAL_MD,
        None,
        ["meta:", "schema_version: 1", "commit_sha:", "baseline_ref:"],
        None,
        False,
        None,
    ),
    (
        "changelog-block-documented",
        FINAL_MD,
        None,
        ["changelog:", "append-only", "version:", "baseline_sha:", "current_sha:", "added:", "changed:", "resolved:"],
        None,
        True,
        None,
    ),
    ("components-block-documented", FINAL_MD, None, ["components:", "threat_ids:", "paths:"], None, False, None),
    (
        "tid-stability-invariant-documented",
        FINAL_MD,
        ["stable across runs", "stable across incremental"],
        None,
        None,
        True,
        None,
    ),
]


class TestYamlSchema:
    _params, _ids = _run_doc_table(_YAML_SCHEMA_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)

    def test_changelog_fragment_is_registered(self):
        """00b-changelog.md must be in OPTIONAL_FRAGMENTS for the renderer."""
        # Import the module dynamically from its path
        import importlib.util

        spec = importlib.util.spec_from_file_location("render_threat_model_schema", RENDER_SCHEMA_PY)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert "00b-changelog.md" in mod.OPTIONAL_FRAGMENTS


# ---------------------------------------------------------------------------
# M2 — mode-aware stale cleanup
# ---------------------------------------------------------------------------

_MODE_AWARE_CLEANUP_INVARIANTS = [
    (
        "agents-md-documents-mode-awareness",
        PLUGIN_AGENTS_MD,
        ["incremental=false", "full scan"],
        ["mode-aware"],
        None,
        True,
        None,
    ),
    (
        "analyst-preserves-carry-forward-files-in-incremental",
        ANALYST_MD,
        None,
        ['if [ "$INCREMENTAL" != "true" ]; then', "carry-forward source"],
        None,
        True,
        None,
    ),
]


class TestModeAwareCleanup:
    _params, _ids = _run_doc_table(_MODE_AWARE_CLEANUP_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)


# ---------------------------------------------------------------------------
# M2 — --yaml always-on
# ---------------------------------------------------------------------------


class TestYamlAlwaysOn:
    def test_skill_marks_yaml_as_always_on(self):
        txt = _read(SKILL_MD)
        # Flag table now shows yaml as no-op (always on)
        assert "no-op" in txt or "always" in txt.lower()
        assert "--no-yaml" in txt, "Escape hatch --no-yaml must be documented"

    def test_resolver_has_yaml_resolution_block(self):
        """Since M3.2 the yaml resolution lives in resolve_config.py. The
        critical property: `resolve_write_yaml` must default to enabled."""
        txt = _read(PLUGIN / "scripts" / "resolve_config.py")
        assert "def resolve_write_yaml" in txt, "resolve_config.py must expose resolve_write_yaml"
        assert 'write_yaml_label": "enabled (default)' in txt, "resolve_write_yaml default must be enabled"

    def test_resolver_detects_yaml_noyaml_conflict(self):
        txt = _read(PLUGIN / "scripts" / "resolve_config.py")
        assert "--yaml and --no-yaml cannot be used together" in txt, (
            "resolve_config.py must document the --yaml + --no-yaml conflict"
        )

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
            assert phrase not in txt, f"appsec-threat-analyst.md still has gate phrase: {phrase!r}"

    def test_finalization_has_no_yaml_gates(self):
        txt = _read(FINAL_MD)
        for phrase in self.GATE_PHRASES:
            assert phrase not in txt, f"phase-group-finalization.md still has gate phrase: {phrase!r}"

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
        schema_block = txt[start : start + 6000]
        for field in self.V1_SCHEMA_FIELDS:
            assert field in schema_block, f"yaml schema v1 in appsec-threat-analyst.md missing field: {field!r}"

    def test_analyst_schema_is_marked_mandatory(self):
        """The schema must explicitly say that the new incremental fields
        are mandatory, not optional — otherwise Claude will 'helpfully' omit
        them."""
        txt = _read(ANALYST_MD)
        assert "mandatory" in txt.lower() and "meta.git.commit_sha" in txt, (
            "Agent must state that meta.git.commit_sha is mandatory"
        )

    # ----- Bug 1b: CURRENT_SHA captured on every run -----

    def test_analyst_captures_current_sha_in_pre_phase(self):
        """Pre-phase step must capture CURRENT_SHA regardless of mode, so that
        a full run also populates meta.git.commit_sha."""
        txt = _read(ANALYST_MD)
        # Anchor on the actual checklist header (not the Dry-Run section that
        # also contains the phrase "Pre-Phase checklist" in passing).
        start = txt.find("**Pre-Phase checklist — run in this exact order")
        assert start != -1, "Real Pre-Phase checklist header not found"
        pre_phase = txt[start : start + 6000]
        assert "CURRENT_SHA" in pre_phase, "Pre-phase checklist must capture CURRENT_SHA on every run"
        assert 'git -C "$REPO_ROOT" rev-parse HEAD' in pre_phase, (
            "Pre-phase checklist must run git rev-parse HEAD explicitly"
        )


class TestRunHeadlessScript:
    def test_run_headless_parses_no_yaml(self):
        txt = (ROOT / "scripts" / "run-headless.sh").read_text()
        assert "--no-yaml" in txt
        # And it must appear in the flag parsing case statement
        assert "|--no-yaml|" in txt

    def test_run_headless_preserves_check_changes_exit_for_changed_repo(self, tmp_path, monkeypatch):
        """The headless fast-path must not normalize ``check-changes`` exit 1
        to exit 0. A security-relevant delta should fall through to Claude
        instead of fast-aborting as a false no-op.
        """
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)

        auth_dir = repo / "src" / "auth"
        auth_dir.mkdir(parents=True)
        auth_file = auth_dir / "login.py"
        auth_file.write_text("def login(): return False\n")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "add auth"], cwd=repo, check=True)

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        outdir = repo / "docs" / "security"
        outdir.mkdir(parents=True)
        (outdir / "threat-model.yaml").write_text(
            "meta:\n"
            f"  plugin_version: '{plugin_json.get('version', 'unknown')}'\n"
            f"  analysis_version: {plugin_json.get('analysis_version', 1)}\n"
            "  git:\n"
            f"    commit_sha: '{head}'\n"
        )
        r = _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        assert r.returncode == 0, r.stderr

        auth_file.write_text("def login(): return True\n")

        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        claude = bin_dir / "claude"
        claude.write_text("#!/bin/sh\nprintf 'CLAUDE_STUB_INVOKED\\n'\nexit 42\n")
        claude.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

        result = subprocess.run(
            [
                str(ROOT / "scripts" / "run-headless.sh"),
                "--repo",
                str(repo),
                "--output",
                str(outdir),
                "--incremental",
                "--no-qa",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 42, result.stdout + result.stderr
        assert "CLAUDE_STUB_INVOKED" in result.stdout

    def test_fast_path_exit_capture_is_not_or_true_wrapped(self):
        headless = (ROOT / "scripts" / "run-headless.sh").read_text()
        skill = _read(SKILL_IMPL_MD)
        forbidden = (
            'baseline_state.py" $FAST_PATH_ARGS 2>/dev/null || true',
            'baseline_state.py" $CHECK_ARGS 2>/dev/null || true',
        )
        for needle in forbidden:
            assert needle not in headless
            assert needle not in skill


class TestIncrementalDirtySetFiltering:
    def test_agent_prompts_filter_raw_git_diff_before_dirty_mapping(self):
        analyst = _read(ANALYST_MD)
        threats = _read(THREATS_MD)
        for text in (analyst, threats):
            assert "RAW_CHANGED_FILES" in text
            assert "filter-diff-paths" in text
            assert "Do not use `RAW_CHANGED_FILES`" in text or ("RAW_CHANGED_FILES` only for" in text)


# ---------------------------------------------------------------------------
# Legacy md-only bootstrap path (the interactive-mode regression)
# ---------------------------------------------------------------------------

_LEGACY_BOOTSTRAP_INVARIANTS = [
    # The three baseline states + the legacy bootstrap path now live in
    # resolve_config.py (function `_detect_baseline_state` and
    # `resolve_incremental_mode`). Behavioural coverage is in
    # tests/test_resolve_config.py — these are source-freeze guards.
    (
        "resolver-documents-three-baseline-states",
        PLUGIN / "scripts" / "resolve_config.py",
        None,
        ['"structured"', '"legacy"', '"empty"'],
        None,
        False,
        None,
    ),
    (
        "resolver-legacy-md-auto-bootstraps-names-detection",
        PLUGIN / "scripts" / "resolve_config.py",
        ["legacy threat-model.md detected", "Legacy threat-model.md found"],
        ["bootstrap"],
        None,
        True,
        None,
    ),
    (
        "resolver-legacy-md-auto-bootstraps-sets-mode-full",
        PLUGIN / "scripts" / "resolve_config.py",
        ['"mode":             "full"', '"mode_label":       "full (bootstrap'],
        None,
        None,
        False,
        None,
    ),
    (
        "resolver-incremental-flag-on-legacy-hard-aborts",
        PLUGIN / "scripts" / "resolve_config.py",
        ["run once without --incremental"],
        ["bootstrap threat-model.yaml"],
        None,
        True,
        None,
    ),
]


class TestLegacyBaselineBootstrap:
    """The critical UX path: users upgrading from pre-M2 plugin have a
    threat-model.md but no threat-model.yaml. Without the bootstrap path,
    their first run after the upgrade hits 'no baseline commit sha' and
    aborts. The skill + orchestrator must handle this gracefully."""

    _params, _ids = _run_doc_table(_LEGACY_BOOTSTRAP_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)


class TestCriticalAttackTreePromotion:
    """The unnumbered ## Critical Attack Tree block is the executive-level
    overview placed directly after the Management Summary. It contains the
    high-level Mermaid graph TD (goal-decomposition with AND/OR refinement)
    + the Quick-reference table. This class pins that layout + the forbidden
    Management Summary subsections.

    Renamed from TestCriticalAttackChainPromotion in the 2026-05 hybrid
    migration. §3.1 Attack Chain Overview (chain semantics) is untouched and
    covered separately. Legacy `#critical-attack-chain` anchor is preserved
    via a dual HTML anchor; both anchors must appear above the heading.

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
            assert forbidden in txt, f"Management Summary spec must explicitly forbid {forbidden!r}"

    def test_mgmt_summary_forbidden_list_names_replacement(self):
        """Forbidding a subsection without telling Claude where the content
        went is worse than saying nothing. Verify each forbidden heading
        points to its replacement."""
        txt = _read(THREATS_MD)
        assert "Top Findings" in txt and "Critical Attack Tree" in txt
        assert "Recommended Priority Actions" in txt
        assert "Key Strengths" in txt and "Operational Strengths" in txt

    # ---- ## Critical Attack Tree layout ----

    def test_critical_attack_tree_layout_documented(self):
        txt = _read(THREATS_MD)
        assert "## Critical Attack Tree" in txt
        assert "#critical-attack-tree" in txt
        # Legacy anchor preserved per AGENTS.md §5 ID stability
        assert "#critical-attack-chain" in txt
        assert "unnumbered" in txt.lower()

    def test_critical_attack_tree_position_documented(self):
        """Position: directly after Management Summary, before Section 1."""
        txt = _read(THREATS_MD)
        lower = txt.lower()
        assert "immediately after the management summary" in lower or "directly after the management summary" in lower
        assert "before section 1" in lower

    def test_critical_attack_tree_forbids_per_finding_blocks(self):
        """The Mermaid tree + the one-line Findings pointer are the only
        allowed formats in the Attack Tree block (the quick-reference table was
        retired in the 2026-05 hybrid migration). Per-finding prose blocks
        belong in Section 9 Attack Walkthroughs, not here."""
        txt = _read(THREATS_MD)
        assert "No per-finding prose blocks" in txt
        assert "Findings pointer is the only per-finding presentation" in txt

    def test_finalization_section_order_places_attack_tree_after_mgmt_summary(self):
        """The numbered composition-order list in phase-group-finalization.md
        must place Management Summary first, Critical Attack Tree second,
        and Section 1 (System Overview) after.

        Matches the numbered-list form produced by the ToC generator
        (`1. Management Summary`, `2. Critical Attack Tree`, `3. 1. System Overview`)
        rather than a bold-markered list — bold markers were used by an older
        spec version and would be over-specified here."""
        txt = _read(FINAL_MD)
        mgmt_idx = txt.find("1. Management Summary")
        tree_idx = txt.find("2. Critical Attack Tree", mgmt_idx) if mgmt_idx != -1 else -1
        # Find the first mention of "Section 1" or "1. System Overview" AFTER the tree line
        s1_idx = -1
        for needle in ("1. System Overview", "Section 1"):
            candidate = txt.find(needle, tree_idx) if tree_idx != -1 else -1
            if candidate != -1:
                s1_idx = candidate if s1_idx == -1 else min(s1_idx, candidate)
        assert mgmt_idx != -1, "Composition order must include '1. Management Summary'"
        assert tree_idx != -1, "Composition order must include '2. Critical Attack Tree' after Management Summary"
        assert s1_idx != -1, "Composition order must reference Section 1 after the tree"
        assert mgmt_idx < tree_idx < s1_idx, (
            "Section order must be: Management Summary → Critical Attack Tree → Section 1"
        )

    # ---- QA reviewer: no auto-fix back into old Section 9 format ----

    def test_qa_reviewer_no_longer_auto_adds_per_finding_blocks(self):
        """The old 3c auto-fix added ### 🔴 T-NNN blocks to Section 9.
        That was the opposite of what the current layout wants. Verify the
        old language is gone."""
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        assert "### 🔴 T-NNN — <short title" not in txt
        # Post-migration the Critical Attack Tree carries a deterministic
        # one-line Findings pointer — the quick-reference table was retired,
        # so the QA spec drives off the tree + pointer, never a per-finding edit.
        assert "Critical Attack Tree" in txt
        assert "Findings pointer" in txt
        assert "Add it to Section 9 in-place" not in txt


class TestSection3AttackWalkthroughs:
    """Section 3 is 'Attack Walkthroughs' — it contains Mermaid sequenceDiagrams,
    one per Critical finding, curated to max 5, tied to T-NNN, with fixed
    alt/else branch semantics rendered by Phase 4 of the orchestrator.

    The earlier direction (Section 3 = stub, Section 9 = Attack Walkthroughs)
    was superseded. These tests pin the current design so it cannot regress.
    """

    ARCH_MD_PATH = PLUGIN / "agents" / "phases" / "phase-group-architecture.md"
    QA_MD_PATH = PLUGIN / "agents" / "appsec-qa-reviewer.md"

    # ---- Section 3 is Attack Walkthroughs (not a stub) ----

    def test_section_3_is_attack_walkthroughs_not_use_cases(self):
        """phase-group-architecture.md must document Section 3 as 'Attack
        Walkthroughs' — the old 'Security-Relevant Use Cases' heading is gone."""
        txt = _read(self.ARCH_MD_PATH)
        assert 'Section 3 is now "Attack Walkthroughs"' in txt, (
            "Architecture doc must explicitly state Section 3 is now Attack Walkthroughs"
        )

    def test_section_3_has_subsection_rule(self):
        """Each walkthrough in Section 3 is a `### <Title>` sub-section with
        an opening intro sentence. The old Section-3-stub direction required
        forbidding sub-sections; the current direction requires them."""
        txt = _read(self.ARCH_MD_PATH)
        # Sub-section rule targets Section 3 attack walkthroughs
        assert "Section 3 sub-sections" in txt, "Architecture doc must document sub-section rule for Section 3"

    # ---- Phase 4 renders Section 3 ----

    def test_phase_4_renders_section_3(self):
        """Phase 4 of the orchestrator renders its output into Section 3.
        The phase number stays 4 for orchestrator ordering, but its output
        target is Section 3 (not Section 9 as an earlier refactor attempted)."""
        txt = _read(self.ARCH_MD_PATH)
        assert "output target is Section 3" in txt or "renders its diagrams into `## 3. Attack Walkthroughs`" in txt, (
            "Phase 4 must explicitly document Section 3 as its output target"
        )
        # The Phase-4 numbering rationale must be explicit
        assert "Phase number stays 4" in txt or "stays 4" in txt

    def test_section_3_has_curation_rule(self):
        """Curation to Critical findings only, max 5, ordered by chain nodes."""
        txt = _read(self.ARCH_MD_PATH)
        assert "Curation — Critical only" in txt, "Architecture doc must document the Critical-only curation rule"
        assert "max 5" in txt.lower() or "Cap at **5**" in txt
        # Explicit exclusion of non-critical
        assert "not add walkthroughs for High-" in txt or "Phase 4 does not add walkthroughs for High" in txt

    def test_section_3_has_fixed_alt_else_semantics(self):
        """Labels are fixed: alt = Current state — T-NNN (attack-path),
        else = After M-NNN — <mitigation>."""
        txt = _read(self.ARCH_MD_PATH)
        assert "alt Current state — T-" in txt
        assert "else After M-" in txt
        # The old "normal vs attack" pattern is explicitly deleted
        assert "is **deleted**" in txt, "Architecture doc must mark the old 'normal vs attack' pattern as deleted"

    def test_section_3_empty_state_documented(self):
        """CRIT_COUNT == 0 → Section 3 renders a 2-line empty-state stub
        pointing to Section 8 (Findings Register)."""
        txt = _read(self.ARCH_MD_PATH)
        assert "CRIT_COUNT == 0" in txt
        # Must mention that Section 3 has an empty-state stub pointing at Section 8
        assert "Section 3 is a 2-line empty-state stub" in txt or "No critical-severity attack walkthroughs" in txt

    def test_phase_4_deferred_rendering_documented(self):
        """Phase 4 runs before Phase 9, so T-NNN don't exist yet at Phase 4
        time. The spec must document the deferred rendering via stable
        slugs + Phase 11 swap, or Phase 4 would produce walkthroughs with
        placeholder IDs that never get resolved."""
        txt = _read(self.ARCH_MD_PATH)
        assert "deferred rendering" in txt.lower()
        assert "stable" in txt.lower() and "slug" in txt.lower()
        assert "Phase 11" in txt

    # ---- Finalization documents the current layout correctly ----

    def test_finalization_lists_section_3_as_attack_walkthroughs(self):
        """phase-group-finalization.md must describe Section 3 as Attack
        Walkthroughs (the previous 'Section 3 = stub' wording is gone)."""
        txt = _read(FINAL_MD)
        # Section 3 = Attack Walkthroughs in the composition/layout references
        assert "Section 3 — Attack Walkthroughs" in txt or "## 3. Attack Walkthroughs" in txt, (
            "Finalization doc must reference Section 3 as Attack Walkthroughs"
        )
        # The old stub wording for Section 3 must NOT appear as the authoritative description
        assert "Section 3 — **stub**" not in txt
        assert "## 3. Security-Relevant Use Cases" not in txt, (
            "Old Section 3 heading 'Security-Relevant Use Cases' must be gone"
        )

    # ---- QA reviewer presence checks target Section 3 ----

    def test_qa_reviewer_section_3_presence_expects_walkthroughs(self):
        """The QA reviewer's structural-quality presence table expects
        `## 3. Attack Walkthroughs` with sequenceDiagram content per Critical
        finding, with an empty-state fallback when CRIT_COUNT == 0."""
        txt = _read(self.QA_MD_PATH)
        row_anchor = "| `## 3. Attack Walkthroughs`"
        s3_idx = txt.find(row_anchor)
        assert s3_idx != -1, f"Presence-table row for Section 3 not found; expected {row_anchor!r}"
        s3_row = txt[s3_idx : s3_idx + 800]
        assert "sequenceDiagram" in s3_row
        assert "Critical finding" in s3_row or "Critical row" in s3_row
        # Empty-state fallback must be documented in the same row
        assert "empty-state" in s3_row.lower() or "CRIT_COUNT == 0" in s3_row

    def test_qa_reviewer_has_no_duplicate_section_8_attack_walkthroughs_row(self):
        """Regression guard: an earlier refactor left a duplicate
        `| ## 8. Attack Walkthroughs |` presence row alongside the real
        `## 8. Findings Register` row. The duplicate must not return — Section 8
        is Findings Register only."""
        txt = _read(self.QA_MD_PATH)
        assert "| `## 8. Attack Walkthroughs`" not in txt, "Duplicate Section 8 Attack Walkthroughs row must not exist"

    def test_qa_reviewer_enforces_alt_else_label_semantics(self):
        """Alt/else check must enforce `alt Current state — T-` and
        `else After M-` labelling."""
        txt = _read(self.QA_MD_PATH)
        assert "alt Current state — T-" in txt
        assert "else After M-" in txt
        assert "Branch labelling check" in txt or "alt branch must be labelled" in txt

    def test_qa_reviewer_sequence_diagram_checks_target_section_3(self):
        """The alt/else and annotator-marker checks must target Section 3
        (where the walkthroughs actually live), not Section 9."""
        txt = _read(self.QA_MD_PATH)
        # Either form of the check must reference Section 3
        assert "Section 3" in txt, "QA reviewer must reference Section 3 for walkthroughs"
        # The sequenceDiagram references in the QA doc must point at Section 3
        # (legacy 'Section 9' references in the context of sequenceDiagrams would be stale)
        assert "sequenceDiagram` in Section 9" not in txt, (
            "Stale 'sequenceDiagram in Section 9' reference in QA reviewer"
        )


# ---------------------------------------------------------------------------
# C2 — Security Architecture Assessment: optional per-theme diagrams
# ---------------------------------------------------------------------------

ARCH_MD = PLUGIN / "agents" / "phases" / "phase-group-architecture.md"


_QA_REVIEWER_MD = PLUGIN / "agents" / "appsec-qa-reviewer.md"

# All invariants below share section_anchor="Per-theme Mermaid diagrams" unless
# they are about the top-level section header itself or the QA reviewer doc.
_THEME_DIAGRAM_INVARIANTS = [
    ("spec-has-optional-diagram-section", ARCH_MD, None, ["Per-theme Mermaid diagrams"], None, False, None),
    (
        "four-allowed-themes-named",
        ARCH_MD,
        None,
        ["Secret Management", "Authentication", "Authorization & Access Control", "Separation & Isolation"],
        None,
        False,
        "Per-theme Mermaid diagrams",
    ),
    (
        "two-forbidden-themes-explicit",
        ARCH_MD,
        None,
        ["Input Validation & Output Encoding", "code-level", "Defense-in-Depth", "Technology Architecture"],
        None,
        True,
        "Per-theme Mermaid diagrams",
    ),
    (
        "diagram-type-restricted-to-graph",
        ARCH_MD,
        None,
        ["`graph LR`", "`graph TB`", "Never", "sequenceDiagram"],
        None,
        False,
        "Per-theme Mermaid diagrams",
    ),
    ("node-count-capped", ARCH_MD, ["3 to 7", "3-7", "maximum"], None, None, True, "Per-theme Mermaid diagrams"),
    ("key-takeaway-mandatory", ARCH_MD, None, ["Key takeaway"], None, False, "Per-theme Mermaid diagrams"),
    (
        "depth-aware-limits-documented-authentication",
        ARCH_MD,
        None,
        ["mandatory", "Authentication"],
        None,
        True,
        "Per-theme Mermaid diagrams",
    ),
    (
        "depth-aware-limits-documented-quick-prose",
        ARCH_MD,
        ["prose-only", "quick"],
        None,
        None,
        True,
        "Per-theme Mermaid diagrams",
    ),
    (
        "example-is-authentication",
        ARCH_MD,
        ["2.4.4 Authentication", "Example"],
        None,
        None,
        False,
        "Per-theme Mermaid diagrams",
    ),
    # QA reviewer enforcement
    (
        "qa-reviewer-check-documented",
        _QA_REVIEWER_MD,
        None,
        [
            "Section 2.4 per-theme diagram check",
            "Wrong diagram type",
            "Prohibited-theme diagram",
            "Node-count overload",
            "Missing Key takeaway",
            "Mandatory-diagram enforcement",
        ],
        None,
        False,
        None,
    ),
]


class TestArchitectureAssessmentThemeDiagrams:
    """The Cross-Cutting Architecture Findings sub-section allows optional
    compact Mermaid diagrams for four of the six themes. This class pins
    the rules: which themes, which type, which size, which depth caps."""

    _params, _ids = _run_doc_table(_THEME_DIAGRAM_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)

    def test_qa_reviewer_flags_sequence_diagram_inside_theme(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        theme_check = txt.split("Section 2.4 per-theme diagram check")[-1]
        assert "sequenceDiagram" in theme_check
        assert "graph LR" in theme_check and "graph TB" in theme_check

    def test_qa_reviewer_flags_prohibited_themes_by_name(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        theme_check = txt.split("Section 2.4 per-theme diagram check")[-1]
        assert "Input Validation & Output Encoding" in theme_check
        assert "Defense-in-Depth" in theme_check

    def test_qa_reviewer_node_cap_is_7(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        theme_check = txt.split("Section 2.4 per-theme diagram check")[-1]
        assert "> 7" in theme_check or "more than 7" in theme_check

    def test_qa_reviewer_depth_cap_matches_spec(self):
        txt = _read(PLUGIN / "agents" / "appsec-qa-reviewer.md")
        theme_check = txt.split("Section 2.4 per-theme diagram check")[-1]
        # Authentication mandatory at standard+, forbidden themes checked
        assert "mandatory" in theme_check.lower()
        assert "forbidden" in theme_check.lower()


_ORCH_FALLBACK_INVARIANTS = [
    # case_id, file, any_of, all_of, none_of, case_insensitive, section_anchor
    (
        "downgrades-on-missing-commit-sha",
        ANALYST_MD,
        None,
        ["Downgrading to full scan", "Existing changelog[] history will be preserved"],
        None,
        False,
        None,
    ),
    (
        "handles-force-push-baseline-detects-missing-commit",
        ANALYST_MD,
        ["git cat-file -e", "no longer exists in the git history"],
        None,
        None,
        False,
        None,
    ),
    (
        "handles-force-push-baseline-mentions-force-push",
        ANALYST_MD,
        ["force-push", "history rewrite"],
        None,
        None,
        True,
        None,
    ),
    # Fallback block scoped via section_anchor — stays out of exit 2 path
    (
        "fallback-sets-incremental-false-no-exit-2",
        ANALYST_MD,
        None,
        ["INCREMENTAL=false"],
        ["  exit 2"],
        False,
        "Graceful fallback",
    ),
    (
        "downgrade-is-not-an-error-callout",
        ANALYST_MD,
        ["not a failure", "not print this as an error"],
        ["one-time transition"],
        None,
        True,
        None,
    ),
]


class TestOrchestratorGracefulFallback:
    """The orchestrator's safety-net downgrade. Even if the skill layer is
    bypassed (direct agent test invocation) or the yaml got corrupted, the
    orchestrator must downgrade to full instead of aborting hard."""

    _params, _ids = _run_doc_table(_ORCH_FALLBACK_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)


# ---------------------------------------------------------------------------
# M2 — git-sha baseline resolution
# ---------------------------------------------------------------------------


class TestGitShaBaseline:
    def test_analyst_uses_yaml_commit_sha_not_head_tilde(self):
        txt = _read(ANALYST_MD)
        # The old HEAD~1..HEAD pattern as the only source is gone
        assert '"$BASELINE_SHA"..HEAD' in txt
        assert "APPSEC_BASELINE_REF" in txt, "CI override env var must be documented"
        assert "meta.git.commit_sha" in txt

    def test_analyst_downgrades_instead_of_aborting_on_missing_sha(self):
        """M2-revision: the old hard abort on missing commit_sha was wrong for
        legacy users. It is now replaced by a graceful downgrade to full scan.
        This is verified in depth in TestOrchestratorGracefulFallback; here
        we just assert the obsolete abort message is gone."""
        txt = _read(ANALYST_MD)
        assert "no baseline commit sha available" not in txt, (
            "Old hard-abort message must be gone — replaced by graceful downgrade"
        )


# ---------------------------------------------------------------------------
# M3 — phase 2 recon fingerprint skip
# ---------------------------------------------------------------------------

_RECON_FINGERPRINT_INVARIANTS = [
    (
        "recon-documents-skip-logic",
        RECON_MD,
        None,
        ["fingerprint skip", "check-fingerprint", "RECON_SKIP"],
        None,
        True,
        None,
    ),
    ("recon-has-conservative-fingerprint-rule", RECON_MD, None, ["conservative"], None, True, None),
]


class TestReconFingerprintSkip:
    _params, _ids = _run_doc_table(_RECON_FINGERPRINT_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)


# ---------------------------------------------------------------------------
# M3 — phase 9 STRIDE carry-forward
# ---------------------------------------------------------------------------

_STRIDE_CARRY_FORWARD_INVARIANTS = [
    (
        "three-paths-re-dispatch-carry-forward-fresh",
        THREATS_MD,
        ["Fresh analysis for new components", "new components"],
        ["Re-dispatch", "Carry forward"],
        None,
        True,
        None,
    ),
    ("integrity-check-sha256", THREATS_MD, None, ["sha256", "CARRY_FORWARD_HASH_MISMATCH"], None, False, None),
    ("removed-components-documented", THREATS_MD, ["component removed", "removed components"], None, None, True, None),
    (
        "stable-tids-documented",
        THREATS_MD,
        ["keep their T-IDs", "T-IDs remain stable", "T-IDs keep"],
        None,
        None,
        False,
        None,
    ),
]


class TestStrideCarryForward:
    _params, _ids = _run_doc_table(_STRIDE_CARRY_FORWARD_INVARIANTS)

    @pytest.mark.parametrize(
        "file_path,any_of,all_of,none_of,case_insensitive,section_anchor",
        _params,
        ids=_ids,
    )
    def test_doc_invariant(self, file_path, any_of, all_of, none_of, case_insensitive, section_anchor):
        _assert_doc_invariant(file_path, any_of, all_of, none_of, case_insensitive, section_anchor)


# ---------------------------------------------------------------------------
# baseline_state.py — real Python tests
# ---------------------------------------------------------------------------


def _run_bs(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BASELINE_STATE_PY), *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


class TestBaselineState:
    @pytest.fixture
    def repo(self, tmp_path: Path) -> Path:
        (tmp_path / "repo").mkdir()
        (tmp_path / "repo" / "package.json").write_text('{"name":"x","version":"1.0.0"}')
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
            "update",
            "--output-dir",
            str(output_dir),
            "--repo-root",
            str(repo),
            "--mode",
            "full",
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
        _run_bs("update", "--output-dir", str(output_dir), "--repo-root", str(repo), "--mode", "full")
        r = _run_bs("validate", "--output-dir", str(output_dir))
        assert r.returncode == 0
        assert "VALID" in r.stdout

    def test_check_fingerprint_matches_unchanged_repo(self, repo, output_dir):
        _run_bs("update", "--output-dir", str(output_dir), "--repo-root", str(repo), "--mode", "full")
        r = _run_bs(
            "check-fingerprint",
            "--output-dir",
            str(output_dir),
            "--repo-root",
            str(repo),
        )
        assert r.returncode == 0
        assert "unchanged" in r.stdout

    def test_check_fingerprint_detects_dockerfile_change(self, repo, output_dir):
        _run_bs("update", "--output-dir", str(output_dir), "--repo-root", str(repo), "--mode", "full")
        (repo / "Dockerfile").write_text("FROM debian\n")
        r = _run_bs(
            "check-fingerprint",
            "--output-dir",
            str(output_dir),
            "--repo-root",
            str(repo),
        )
        assert r.returncode == 1
        assert "changed" in r.stdout.lower()

    def test_check_fingerprint_detects_new_manifest(self, repo, output_dir):
        _run_bs("update", "--output-dir", str(output_dir), "--repo-root", str(repo), "--mode", "full")
        (repo / "requirements.txt").write_text("flask==2.0\n")
        r = _run_bs(
            "check-fingerprint",
            "--output-dir",
            str(output_dir),
            "--repo-root",
            str(repo),
        )
        assert r.returncode == 1
        assert "+manifests:requirements.txt" in r.stdout

    def test_id_counter_never_regresses(self, repo, output_dir):
        """Even if the yaml has been edited to remove threats, the counter
        must never go backwards — that would risk ID reuse."""
        _run_bs("update", "--output-dir", str(output_dir), "--repo-root", str(repo), "--mode", "full")
        # Simulate yaml shrinking (T-007 removed)
        (output_dir / "threat-model.yaml").write_text(
            "meta:\n  git:\n    commit_sha: def456\nthreats:\n  - id: T-001\n"
        )
        _run_bs("update", "--output-dir", str(output_dir), "--repo-root", str(repo), "--mode", "incremental")
        data = json.loads((output_dir / ".appsec-cache" / "baseline.json").read_text())
        assert data["id_counters"]["next_threat_id"] >= 8, "counter must never go backwards"

    def test_missing_output_dir_errors(self, tmp_path):
        r = _run_bs(
            "update",
            "--output-dir",
            str(tmp_path / "does-not-exist"),
            "--repo-root",
            str(tmp_path),
            "--mode",
            "full",
        )
        assert r.returncode != 0
        assert "not found" in r.stderr.lower()

    def test_update_stamps_plugin_and_analysis_version(self, repo, output_dir):
        """A freshly-written baseline must record the current plugin version
        and analysis_version read from plugin.json."""
        r = _run_bs(
            "update",
            "--output-dir",
            str(output_dir),
            "--repo-root",
            str(repo),
            "--mode",
            "full",
        )
        assert r.returncode == 0, r.stderr
        data = json.loads((output_dir / ".appsec-cache" / "baseline.json").read_text())
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        assert data["plugin_version"] == plugin_json["version"]
        assert data["analysis_version"] == plugin_json["analysis_version"]

    def test_validate_warns_on_legacy_baseline_without_version(self, repo, output_dir):
        """A baseline written by a pre-versioning plugin (no plugin_version /
        analysis_version fields) must still validate, but with a warning."""
        _run_bs("update", "--output-dir", str(output_dir), "--repo-root", str(repo), "--mode", "full")
        cache = output_dir / ".appsec-cache" / "baseline.json"
        data = json.loads(cache.read_text())
        data.pop("plugin_version", None)
        data.pop("analysis_version", None)
        cache.write_text(json.dumps(data, indent=2, sort_keys=True))
        r = _run_bs("validate", "--output-dir", str(output_dir))
        assert r.returncode == 0
        assert "VALID" in r.stdout
        assert "WARN" in r.stderr
        assert "analysis_version missing" in r.stderr


# ---------------------------------------------------------------------------
# plugin_meta.py — version metadata helper
# ---------------------------------------------------------------------------

PLUGIN_META_PY = PLUGIN / "scripts" / "plugin_meta.py"


def _run_pm(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PLUGIN_META_PY), *args],
        capture_output=True,
        text=True,
    )


class TestPluginMeta:
    def test_get_plugin_version_matches_plugin_json(self):
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        r = _run_pm("get", "plugin_version")
        assert r.returncode == 0
        assert r.stdout.strip() == plugin_json["version"]

    def test_get_analysis_version_is_int(self):
        r = _run_pm("get", "analysis_version")
        assert r.returncode == 0
        assert r.stdout.strip().isdigit()

    def test_check_compat_equal_version_exits_zero(self):
        current = int(_run_pm("get", "analysis_version").stdout.strip())
        r = _run_pm("check-compat", "--baseline-version", str(current))
        assert r.returncode == 0
        assert "unchanged" in r.stdout

    def test_check_compat_incompatible_older_baseline_hard_fails(self):
        """analysis_version=0 is not in compatible_analysis_versions for any
        release of this plugin — must always return exit 20."""
        r = _run_pm("check-compat", "--baseline-version", "0")
        assert r.returncode == 20
        assert "NOT in" in r.stderr

    def test_check_compat_missing_version_returns_baseline_missing(self):
        r = _run_pm("check-compat", "--baseline-version", "")
        assert r.returncode == 30
        assert "no analysis_version" in r.stderr


# ---------------------------------------------------------------------------
# baseline_state.py check-compat — integrates with plugin_meta
# ---------------------------------------------------------------------------


class TestBaselineCheckCompat:
    @pytest.fixture
    def output_dir_with_yaml(self, tmp_path: Path) -> Path:
        d = tmp_path / "out"
        d.mkdir()
        return d

    def _write_yaml(self, d: Path, analysis_version: int | None) -> None:
        lines = ["meta:", "  schema_version: 1"]
        if analysis_version is not None:
            lines.append(f"  analysis_version: {analysis_version}")
        lines.append("  git:")
        lines.append("    commit_sha: abc123")
        (d / "threat-model.yaml").write_text("\n".join(lines) + "\n")

    def test_equal_version_from_yaml(self, output_dir_with_yaml):
        current = int(_run_pm("get", "analysis_version").stdout.strip())
        self._write_yaml(output_dir_with_yaml, current)
        r = _run_bs("check-compat", "--output-dir", str(output_dir_with_yaml))
        assert r.returncode == 0
        assert "source=threat-model.yaml" in r.stdout

    def test_missing_version_in_yaml_is_legacy(self, output_dir_with_yaml):
        self._write_yaml(output_dir_with_yaml, None)
        r = _run_bs("check-compat", "--output-dir", str(output_dir_with_yaml))
        assert r.returncode == 30
        assert "source=missing" in r.stderr

    def test_incompatible_version_in_yaml(self, output_dir_with_yaml):
        self._write_yaml(output_dir_with_yaml, 0)
        r = _run_bs("check-compat", "--output-dir", str(output_dir_with_yaml))
        assert r.returncode == 20
        assert "baseline_version=0" in r.stderr

    def test_falls_back_to_cache_when_yaml_absent(self, tmp_path: Path):
        d = tmp_path / "out"
        (d / ".appsec-cache").mkdir(parents=True)
        current = int(_run_pm("get", "analysis_version").stdout.strip())
        (d / ".appsec-cache" / "baseline.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "plugin_version": "test",
                    "analysis_version": current,
                    "recon_fingerprint": {"manifests": {}, "dockerfiles": {}, "iac": {}},
                    "id_counters": {"next_threat_id": 1, "next_mitigation_id": 1},
                    "stride_files": {},
                }
            )
        )
        r = _run_bs("check-compat", "--output-dir", str(d))
        assert r.returncode == 0
        assert "source=baseline.json" in r.stdout


# ---------------------------------------------------------------------------
# Documentation contract — versioning fields surfaced in yaml/md/skill
# ---------------------------------------------------------------------------


class TestVersioningDocumentation:
    def test_finalization_schema_declares_plugin_and_analysis_version(self):
        txt = _read(FINAL_MD)
        assert "plugin_version:" in txt and "analysis_version:" in txt, (
            "Finalization phase must document plugin_version and analysis_version in the yaml schema"
        )
        assert "recommend_full_rerun" in txt, "Finalization phase must document the recommend_full_rerun flag"

    def test_finalization_declares_plugin_meta_stamping_step(self):
        txt = _read(FINAL_MD)
        assert "plugin_meta.py" in txt, "Finalization phase must read version fields via plugin_meta.py"

    def test_skill_documents_compat_gate(self):
        txt = _read(SKILL_MD)
        assert "Plugin Version Compatibility Gate" in txt, "SKILL.md must document the compatibility gate"
        assert "check-compat" in txt, "SKILL.md must invoke baseline_state.py check-compat"
        assert "older-compatible" in txt and "incompatible" in txt, "SKILL.md must classify the four compat outcomes"

    def test_plugin_json_declares_analysis_version(self):
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        assert "analysis_version" in plugin_json
        assert "compatible_analysis_versions" in plugin_json
        assert plugin_json["analysis_version"] in plugin_json["compatible_analysis_versions"], (
            "current analysis_version must be listed as self-compatible"
        )


# ---------------------------------------------------------------------------
# Fast-path helpers (M4) — plugin_meta.classify_plugin_version +
# baseline_state.check-changes + last-run-info
# ---------------------------------------------------------------------------


def _run_baseline(sub: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(BASELINE_STATE_PY), *sub],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


def _run_plugin_meta(sub: list[str]) -> subprocess.CompletedProcess:
    script = PLUGIN / "scripts" / "plugin_meta.py"
    return subprocess.run(
        [sys.executable, str(script), *sub],
        capture_output=True,
        text=True,
    )


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@test"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "tester"], cwd=path, check=True)
    (path / "README.md").write_text("hello\n")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=path, check=True)


class TestPluginVersionDrift:
    def test_equal_exits_zero(self):
        r = _run_plugin_meta(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "1.2.3"])
        assert r.returncode == 0, r.stderr
        assert "tier=equal" in r.stdout

    def test_patch_bump_exits_zero(self):
        r = _run_plugin_meta(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "1.2.9"])
        assert r.returncode == 0
        assert "tier=patch" in r.stdout

    def test_minor_bump_exits_10(self):
        r = _run_plugin_meta(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "1.3.0"])
        assert r.returncode == 10
        assert "tier=minor" in r.stdout

    def test_major_bump_exits_20(self):
        r = _run_plugin_meta(["compare-plugin-versions", "--baseline", "1.2.3", "--current", "2.0.0"])
        assert r.returncode == 20
        assert "tier=major" in r.stdout

    def test_non_semver_is_unknown(self):
        r = _run_plugin_meta(["compare-plugin-versions", "--baseline", "dev-abc", "--current", "1.0.0"])
        assert r.returncode == 30
        assert "tier=unknown" in r.stdout

    def test_prerelease_suffix_ignored(self):
        """0.4.0-beta and 0.4.0 should be treated as equal (pre-release stripped)."""
        r = _run_plugin_meta(["compare-plugin-versions", "--baseline", "0.4.0-beta", "--current", "0.4.0"])
        assert r.returncode == 0
        assert "tier=equal" in r.stdout or "tier=patch" in r.stdout


class TestCheckChanges:
    @pytest.fixture
    def repo_with_baseline(self, tmp_path):
        """A git repo with a committed file and a fake threat-model.yaml + baseline.json."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

        # Read the real current plugin version so the drift classifier sees
        # "equal" — otherwise an unrelated plugin bump would make this test
        # flaky.
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        current_version = plugin_json.get("version", "unknown")
        current_analysis = plugin_json.get("analysis_version", 1)

        outdir = repo / "docs" / "security"
        outdir.mkdir(parents=True)

        yaml_body = (
            "meta:\n"
            f"  plugin_version: '{current_version}'\n"
            f"  analysis_version: {current_analysis}\n"
            f"  git:\n"
            f"    commit_sha: '{head}'\n"
        )
        (outdir / "threat-model.yaml").write_text(yaml_body)

        # Write a baseline cache that matches the current repo state
        cache_dir = outdir / ".appsec-cache"
        cache_dir.mkdir()
        # Compute the fingerprint by calling update
        r = _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        assert r.returncode == 0, r.stderr
        return repo, outdir, head

    def test_unchanged_repo_exits_zero(self, repo_with_baseline):
        repo, outdir, _ = repo_with_baseline
        r = _run_baseline(
            [
                "check-changes",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
            ]
        )
        assert r.returncode == 0, f"expected unchanged fast-abort, got exit={r.returncode}\n{r.stdout}\n{r.stderr}"
        data = json.loads(r.stdout)
        assert data["status"] == "unchanged"
        assert data["fingerprint_match"] is True
        assert data["committed_change_count"] == 0
        assert data["working_tree_change_count"] == 0

    def test_working_tree_change_exits_one(self, repo_with_baseline):
        repo, outdir, _ = repo_with_baseline
        # Modify a security-relevant file (auth path segment → Tier 1 relevant).
        # README.md is now correctly classified as noise-only (exit 2), so we
        # use a source file in an auth/ subdirectory instead.
        auth_dir = repo / "src" / "auth"
        auth_dir.mkdir(parents=True, exist_ok=True)
        auth_file = auth_dir / "login.py"
        auth_file.write_text("def login(): pass\n")
        import subprocess as _sp

        _sp.run(["git", "-C", str(repo), "add", str(auth_file)], capture_output=True)
        _sp.run(
            ["git", "-C", str(repo), "commit", "-m", "add auth file", "--author", "Test <test@test.com>"],
            capture_output=True,
        )
        # Now introduce a working-tree change on the same security-relevant file.
        auth_file.write_text("def login(): return True\n")
        r = _run_baseline(
            [
                "check-changes",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
            ]
        )
        assert r.returncode == 1, f"expected security-relevant changes, got exit={r.returncode}\n{r.stdout}"
        data = json.loads(r.stdout)
        assert data["status"] == "changed"
        assert data["security_relevant_change_count"] >= 1

    def test_no_baseline_exits_three(self, tmp_path):
        repo = tmp_path / "empty"
        repo.mkdir()
        _init_git_repo(repo)
        outdir = repo / "docs" / "security"
        outdir.mkdir(parents=True)
        r = _run_baseline(
            [
                "check-changes",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
            ]
        )
        assert r.returncode == 3
        data = json.loads(r.stdout)
        assert data["status"] == "no_baseline"

    def test_uncommitted_output_dir_does_not_force_change(self, repo_with_baseline):
        """Files inside OUTPUT_DIR (the plugin's own writes) must be filtered
        out before the security-relevance classifier sees them. Without the
        pre-filter, every uncommitted plugin-output file flips the verdict
        to ``changed`` — which kills the fast-path on every second run.
        """
        repo, outdir, _ = repo_with_baseline
        # Simulate the bug scenario: the plugin's own output dir has
        # dirty files (fragments, taxonomy slices, intermediate JSONs).
        (outdir / ".fragments").mkdir(exist_ok=True)
        (outdir / ".fragments" / "system-overview.md").write_text("# x\n")
        (outdir / ".taxonomy-slices").mkdir(exist_ok=True)
        (outdir / ".taxonomy-slices" / "auth.yaml").write_text("paths: []\n")

        r = _run_baseline(
            [
                "check-changes",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
            ]
        )
        assert r.returncode == 0, (
            f"OUTPUT_DIR-internal files must not force a re-scan, got exit={r.returncode}\n{r.stdout}\n{r.stderr}"
        )
        data = json.loads(r.stdout)
        assert data["status"] == "unchanged"
        assert data["fingerprint_match"] is True

    def test_filter_diff_paths_cli_matches_output_dir_exclude(self, repo_with_baseline):
        """Agent-side dirty-set filtering must use the same OUTPUT_DIR exclude
        as the pre-flight check, otherwise docs/security artifacts can map to
        broad component globs and create false dirty components.
        """
        repo, outdir, _ = repo_with_baseline
        r = _run_baseline(
            [
                "filter-diff-paths",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "docs/security/threat-model.yaml",
                "src/auth/login.py",
                ".github/workflows/ci.yml",
            ]
        )
        assert r.returncode == 0, r.stderr
        assert r.stdout.splitlines() == [
            "src/auth/login.py",
            ".github/workflows/ci.yml",
        ]

    def test_filter_diff_paths_cli_json_reports_excluded_count(self, repo_with_baseline):
        repo, outdir, _ = repo_with_baseline
        r = _run_baseline(
            [
                "filter-diff-paths",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--format",
                "json",
                "docs/security/.fragments/system-overview.md",
                "src/auth/login.py",
            ]
        )
        assert r.returncode == 0, r.stderr
        data = json.loads(r.stdout)
        assert data["paths"] == ["src/auth/login.py"]
        assert data["excluded_count"] == 1

    def test_whitespace_only_manifest_is_noise(self, repo_with_baseline):
        """A whitespace-only edit to ``package.json`` (re-format, key reorder
        without semantic change) must NOT trigger the standard incremental
        path. Tier-1 marks manifests as always-relevant; the Tier-1b
        semantic-diff override downgrades them when ``git diff -w`` is empty.
        """
        repo, outdir, _ = repo_with_baseline
        # Seed a real package.json + commit it so we have a baseline.
        pkg = repo / "package.json"
        pkg.write_text('{"name":"app","version":"1.0.0"}\n')
        import subprocess as _sp

        _sp.run(["git", "-C", str(repo), "add", "package.json"], capture_output=True)
        _sp.run(
            ["git", "-C", str(repo), "commit", "-m", "add manifest", "--author", "Test <test@test.com>"],
            capture_output=True,
        )
        # Refresh baseline so the new HEAD matches the cache.
        head = _sp.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        yaml_body = (
            "meta:\n"
            f"  plugin_version: '{json.loads((PLUGIN / '.claude-plugin' / 'plugin.json').read_text()).get('version', 'unknown')}'\n"
            f"  analysis_version: {json.loads((PLUGIN / '.claude-plugin' / 'plugin.json').read_text()).get('analysis_version', 1)}\n"
            f"  git:\n"
            f"    commit_sha: '{head}'\n"
        )
        (outdir / "threat-model.yaml").write_text(yaml_body)
        _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        # Now apply a whitespace-only change: extra newlines + trailing space.
        pkg.write_text('{"name":"app",  "version":"1.0.0"}\n\n')

        r = _run_baseline(
            [
                "check-changes",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
            ]
        )
        # Either exit 2 (noise_only) or exit 0 (no source changes — fingerprint
        # ignores .json formatting). Both are acceptable: neither triggers an
        # agent dispatch.
        assert r.returncode in (0, 2), (
            f"whitespace-only manifest edit must fast-abort, got exit={r.returncode}\n{r.stdout}\n{r.stderr}"
        )
        data = json.loads(r.stdout)
        assert data["status"] in ("unchanged", "noise_only")

    def test_semantic_manifest_change_is_relevant(self, repo_with_baseline):
        """A real dependency add to ``package.json`` (added line with
        ``"express"``) MUST stay classified as security-relevant — the
        semantic-diff downgrade only kicks in when there is no semantic
        change at all.
        """
        repo, outdir, _ = repo_with_baseline
        pkg = repo / "package.json"
        pkg.write_text('{"name":"app","version":"1.0.0","dependencies":{}}\n')
        import subprocess as _sp

        _sp.run(["git", "-C", str(repo), "add", "package.json"], capture_output=True)
        _sp.run(
            ["git", "-C", str(repo), "commit", "-m", "seed manifest", "--author", "Test <test@test.com>"],
            capture_output=True,
        )
        head = _sp.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        yaml_body = (
            "meta:\n"
            f"  plugin_version: '{plugin_json.get('version', 'unknown')}'\n"
            f"  analysis_version: {plugin_json.get('analysis_version', 1)}\n"
            f"  git:\n"
            f"    commit_sha: '{head}'\n"
        )
        (outdir / "threat-model.yaml").write_text(yaml_body)
        _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        # Real change: add a dependency.
        pkg.write_text('{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}}\n')
        r = _run_baseline(
            [
                "check-changes",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
            ]
        )
        assert r.returncode == 1, (
            f"semantic manifest change must keep status=changed, got exit={r.returncode}\n{r.stdout}\n{r.stderr}"
        )
        data = json.loads(r.stdout)
        assert data["status"] == "changed"
        assert data["security_relevant_change_count"] >= 1


class TestDirtySet:
    """Component-mapping pre-check that decides whether Stage 1 needs to
    spawn at all. Three exit codes:

      0 — at least one component is dirty (proceed to Stage 1)
      2 — only top-level global manifests are dirty (skip Stage 1+2+3)
      3 — unmapped non-global files (potential new component — proceed
          conservatively to Stage 1)
    """

    @pytest.fixture
    def output_with_components(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        # Two components: one matches `routes/**`, one matches `frontend/src/**`.
        (out / "threat-model.yaml").write_text(
            "meta:\n"
            "  schema_version: 1\n"
            "components:\n"
            "- id: express-backend\n"
            "  paths:\n"
            "  - server.ts\n"
            "  - routes/**\n"
            "  - lib/**\n"
            "- id: angular-spa\n"
            "  paths:\n"
            "  - frontend/src/**\n"
        )
        return out

    def test_dirty_route_match(self, output_with_components):
        r = _run_baseline(
            [
                "dirty-set",
                "--output-dir",
                str(output_with_components),
                "--no-stdin",
                "--files",
                "routes/login.ts",
            ]
        )
        assert r.returncode == 0, r.stdout
        data = json.loads(r.stdout)
        assert data["decision"] == "dirty"
        assert data["dirty_component_ids"] == ["express-backend"]
        assert data["unmapped_files"] == []

    def test_glob_double_star_matches_nested(self, output_with_components):
        r = _run_baseline(
            [
                "dirty-set",
                "--output-dir",
                str(output_with_components),
                "--no-stdin",
                "--files",
                "frontend/src/auth/login.component.ts",
            ]
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert "angular-spa" in data["dirty_component_ids"]

    def test_top_level_package_json_is_global_noop(self, output_with_components):
        r = _run_baseline(
            [
                "dirty-set",
                "--output-dir",
                str(output_with_components),
                "--no-stdin",
                "--files",
                "package.json",
            ]
        )
        assert r.returncode == 2, (
            f"top-level manifest must be classified noop_global_only, got exit={r.returncode}\n{r.stdout}"
        )
        data = json.loads(r.stdout)
        assert data["decision"] == "noop_global_only"
        assert data["dirty_component_ids"] == []
        assert data["unmapped_files"] == ["package.json"]

    def test_unmapped_subdir_is_ambiguous(self, output_with_components):
        r = _run_baseline(
            [
                "dirty-set",
                "--output-dir",
                str(output_with_components),
                "--no-stdin",
                "--files",
                "services/payment/Dockerfile",
            ]
        )
        assert r.returncode == 3, (
            f"unmapped non-global path must be classified ambiguous, got exit={r.returncode}\n{r.stdout}"
        )
        data = json.loads(r.stdout)
        assert data["decision"] == "ambiguous_potential_new_component"

    def test_mixed_dirty_and_unmapped_proceeds(self, output_with_components):
        """A mixed input where ≥1 file maps to a component takes the
        ``dirty`` path — the unmapped file rides along (will be picked
        up by Phase 2 if it's a new component, or carried as noise)."""
        r = _run_baseline(
            [
                "dirty-set",
                "--output-dir",
                str(output_with_components),
                "--no-stdin",
                "--files",
                "routes/login.ts",
                "package.json",
            ]
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["decision"] == "dirty"
        assert data["dirty_component_ids"] == ["express-backend"]
        assert "package.json" in data["unmapped_files"]

    def test_empty_input_is_noop(self, output_with_components):
        r = _run_baseline(
            [
                "dirty-set",
                "--output-dir",
                str(output_with_components),
                "--no-stdin",
            ]
        )
        assert r.returncode == 2
        data = json.loads(r.stdout)
        assert data["decision"] == "noop_empty_input"

    def test_files_via_stdin(self, output_with_components):
        import subprocess as _sp

        r = _sp.run(
            [sys.executable, str(BASELINE_STATE_PY), "dirty-set", "--output-dir", str(output_with_components)],
            input="routes/foo.ts\npackage.json\n",
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["decision"] == "dirty"


class TestThreatModelHealth:
    """End-to-end probe of scripts/threat_model_health.py — must mirror the
    create-threat-model SKILL's pre-check decision tree exactly so the
    /appsec-advisor:threat-model-health status verdict cannot drift away
    from what the next run would actually do.
    """

    TMH_PY = PLUGIN / "scripts" / "threat_model_health.py"

    def _run_tmh(self, repo: Path, outdir: Path, json_mode: bool = True):
        args = ["--repo-root", str(repo), "--output-dir", str(outdir)]
        if json_mode:
            args.append("--json")
        return subprocess.run(
            [sys.executable, str(self.TMH_PY), *args],
            capture_output=True,
            text=True,
        )

    @pytest.fixture
    def repo_with_baseline(self, tmp_path):
        """A git-tracked repo with a one-component threat-model.yaml +
        a baseline cache that matches the committed state."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)
        (repo / "package.json").write_text('{"name":"x","version":"1.0.0","dependencies":{}}\n')
        (repo / "src").mkdir()
        (repo / "src" / "auth").mkdir()
        (repo / "src" / "auth" / "login.py").write_text("def login(): pass\n")
        subprocess.run(["git", "-C", str(repo), "add", "."], capture_output=True, check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "seed", "--author", "T <t@t>"],
            capture_output=True,
            check=True,
        )
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        outdir = repo / "docs" / "security"
        outdir.mkdir(parents=True)
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        (outdir / "threat-model.yaml").write_text(
            "meta:\n"
            f"  plugin_version: '{plugin_json.get('version', 'unknown')}'\n"
            f"  analysis_version: {plugin_json.get('analysis_version', 1)}\n"
            f"  git:\n"
            f"    commit_sha: '{head}'\n"
            "components:\n"
            "- id: backend\n"
            "  paths:\n"
            "  - src/auth/**\n"
        )
        (outdir / "threat-model.md").write_text("# model\n")
        _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        return repo, outdir

    def test_pristine_repo_is_fresh_clean(self, repo_with_baseline):
        repo, outdir = repo_with_baseline
        r = self._run_tmh(repo, outdir)
        assert r.returncode == 0, r.stdout + r.stderr
        d = json.loads(r.stdout)
        assert d["freshness"]["verdict"] == "FRESH"
        assert d["freshness"]["recommend"] == "noop"
        assert d["active_run"]["state"] == "clean"
        assert d["artifacts"]["tier1"] == []
        # tier-2 may contain .appsec-cache (excluded by NEVER) — assert it's not flagged
        assert ".appsec-cache" not in d["artifacts"]["tier2"]

    def test_global_only_pkgjson_is_fresh(self, repo_with_baseline):
        """A new dependency in the top-level package.json maps to no
        component → SKILL would fast-abort → status reports FRESH."""
        repo, outdir = repo_with_baseline
        pkg = repo / "package.json"
        d_pkg = json.loads(pkg.read_text())
        d_pkg["dependencies"] = {"express": "^4.19.0"}
        pkg.write_text(json.dumps(d_pkg, indent=2))
        r = self._run_tmh(repo, outdir)
        assert r.returncode == 0, r.stdout + r.stderr
        d = json.loads(r.stdout)
        assert d["freshness"]["verdict"] == "FRESH", d["freshness"]
        assert d["freshness"]["recommend"] == "noop"
        # The dirty-set must have been consulted to reach this verdict.
        assert d["freshness"]["dirty_set"] is not None
        assert d["freshness"]["dirty_set"]["decision"] == "noop_global_only"

    def test_component_dirty_is_stale(self, repo_with_baseline):
        repo, outdir = repo_with_baseline
        (repo / "src" / "auth" / "login.py").write_text(
            "def login(user, password): return verify_password(user, password)\n"
        )
        r = self._run_tmh(repo, outdir)
        assert r.returncode == 1, r.stdout + r.stderr
        d = json.loads(r.stdout)
        assert d["freshness"]["verdict"] == "STALE"
        assert d["freshness"]["recommend"] == "incremental"
        assert d["freshness"]["dirty_set"]["dirty_component_ids"] == ["backend"]

    def test_plugin_drift_is_stale(self, repo_with_baseline):
        repo, outdir = repo_with_baseline
        # Rewind the baseline plugin_version so the current-vs-baseline
        # tier becomes minor.
        yaml_path = outdir / "threat-model.yaml"
        text = yaml_path.read_text()
        import re as _re

        text = _re.sub(r"plugin_version: '[^']+'", "plugin_version: '0.5.0'", text)
        yaml_path.write_text(text)
        _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        r = self._run_tmh(repo, outdir)
        assert r.returncode == 1, r.stdout + r.stderr
        d = json.loads(r.stdout)
        assert d["freshness"]["verdict"] == "STALE"
        assert d["freshness"]["recommend"] == "full"
        assert "plugin upgraded" in d["freshness"]["reason"]

    def test_no_yaml_is_no_model(self, repo_with_baseline):
        repo, outdir = repo_with_baseline
        (outdir / "threat-model.yaml").unlink()
        r = self._run_tmh(repo, outdir)
        assert r.returncode == 1
        d = json.loads(r.stdout)
        assert d["freshness"]["verdict"] == "NO_MODEL"
        assert d["freshness"]["recommend"] == "full"

    def test_active_lock_returns_3_and_skips_freshness(self, repo_with_baseline):
        repo, outdir = repo_with_baseline
        import time as _t

        (outdir / ".appsec-lock").write_text(f"{os.getpid()}\n{int(_t.time())}\n")
        try:
            r = self._run_tmh(repo, outdir)
        finally:
            (outdir / ".appsec-lock").unlink(missing_ok=True)
        assert r.returncode == 3, r.stdout + r.stderr
        d = json.loads(r.stdout)
        assert d["active_run"]["state"] == "active"
        # checks 1 + 2 must have been skipped while a run was active
        assert "freshness" not in d
        assert "artifacts" not in d

    def test_debris_only_returns_2(self, repo_with_baseline):
        """No source changes + post-run intermediates present → exit 2."""
        repo, outdir = repo_with_baseline
        (outdir / ".recon-patterns.json").write_text("{}\n")
        (outdir / ".phase-epoch").write_text("1\n")
        r = self._run_tmh(repo, outdir)
        assert r.returncode == 2, r.stdout + r.stderr
        d = json.loads(r.stdout)
        assert d["freshness"]["verdict"] == "FRESH"
        assert ".recon-patterns.json" in d["artifacts"]["tier2"]


class TestLastRunInfo:
    def test_no_baseline_returns_empty(self, tmp_path):
        outdir = tmp_path / "out"
        outdir.mkdir()
        r = _run_baseline(["last-run-info", "--output-dir", str(outdir)])
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["has_baseline"] is False

    def test_populated_after_update(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)
        outdir = repo / "out"
        outdir.mkdir()
        # Write a minimal threat-model.yaml for commit_sha extraction
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        (outdir / "threat-model.yaml").write_text(
            f"meta:\n  plugin_version: '0.1.0'\n  git:\n    commit_sha: '{head}'\n"
        )
        r = _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        assert r.returncode == 0, r.stderr

        r = _run_baseline(["last-run-info", "--output-dir", str(outdir)])
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert data["has_baseline"] is True
        assert data["last_run_at"] is not None
        assert data["last_run_at"].endswith("Z")


# ---------------------------------------------------------------------------
# Clean subcommand (cache/all) — allowlist-based, dry-run-safe
# ---------------------------------------------------------------------------


class TestCleanSubcommand:
    def _seed(self, outdir: Path) -> None:
        """Populate a fake output dir with one file from each category."""
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "threat-model.yaml").write_text("meta: {}\n")
        (outdir / "threat-model.md").write_text("# model\n")
        (outdir / ".recon-summary.md").write_text("recon\n")
        (outdir / ".stride-auth.json").write_text("{}\n")
        (outdir / ".hook-events.log").write_text("logs\n")
        (outdir / ".appsec-lock").write_text("lock\n")
        (outdir / "unrelated-user.txt").write_text("mine\n")

    def test_cache_keeps_product_and_audit(self, tmp_path):
        out = tmp_path / "out"
        self._seed(out)
        r = _run_baseline(["clean", "--output-dir", str(out), "--mode", "cache", "--force"])
        assert r.returncode == 0, r.stderr
        assert (out / "threat-model.yaml").exists()
        assert (out / "threat-model.md").exists()
        assert (out / ".hook-events.log").exists()
        # Cache/transient removed
        assert not (out / ".recon-summary.md").exists()
        assert not (out / ".stride-auth.json").exists()
        assert not (out / ".appsec-lock").exists()
        # Unknown preserved
        assert (out / "unrelated-user.txt").exists()

    def test_all_removes_everything_known_but_skips_unknown(self, tmp_path):
        out = tmp_path / "out"
        self._seed(out)
        r = _run_baseline(["clean", "--output-dir", str(out), "--mode", "all", "--force"])
        assert r.returncode == 0, r.stderr
        # Known files gone
        for name in (
            "threat-model.yaml",
            "threat-model.md",
            ".recon-summary.md",
            ".stride-auth.json",
            ".hook-events.log",
            ".appsec-lock",
        ):
            assert not (out / name).exists(), f"{name} should have been removed"
        # Unknown preserved — never touched
        assert (out / "unrelated-user.txt").exists()

    def test_dry_run_removes_nothing(self, tmp_path):
        out = tmp_path / "out"
        self._seed(out)
        before = sorted(p.name for p in out.iterdir())
        r = _run_baseline(["clean", "--output-dir", str(out), "--mode", "all", "--force", "--dry-run"])
        assert r.returncode == 0
        after = sorted(p.name for p in out.iterdir())
        assert before == after, "dry-run must not delete anything"

    def test_empty_dir_is_a_success(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        r = _run_baseline(["clean", "--output-dir", str(out), "--mode", "cache"])
        assert r.returncode == 0
        assert "nothing to clean" in r.stdout.lower()

    def test_nonexistent_dir_is_a_silent_success(self, tmp_path):
        out = tmp_path / "never-created"
        r = _run_baseline(["clean", "--output-dir", str(out), "--mode", "cache"])
        assert r.returncode == 0

    def test_appsec_cache_directory_is_removed(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        cache = out / ".appsec-cache"
        cache.mkdir()
        (cache / "baseline.json").write_text("{}")
        r = _run_baseline(["clean", "--output-dir", str(out), "--mode", "cache", "--force"])
        assert r.returncode == 0
        assert not cache.exists()

    def test_stride_files_are_cache(self, tmp_path):
        """`.stride-*.json` must be treated as cache (carry-forward data)."""
        out = tmp_path / "out"
        out.mkdir()
        (out / ".stride-auth.json").write_text("{}")
        (out / ".stride-api.json").write_text("{}")
        (out / "threat-model.yaml").write_text("meta: {}")
        r = _run_baseline(["clean", "--output-dir", str(out), "--mode", "cache", "--force"])
        assert r.returncode == 0
        assert not (out / ".stride-auth.json").exists()
        assert not (out / ".stride-api.json").exists()
        assert (out / "threat-model.yaml").exists()


# ---------------------------------------------------------------------------
# appsec_status.py — read-only overview
# ---------------------------------------------------------------------------


class TestAppsecStatus:
    SCRIPT = PLUGIN / "scripts" / "appsec_status.py"

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(self.SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def test_text_output_has_expected_sections(self, tmp_path):
        r = self._run("--repo-root", str(tmp_path), "--output-dir", str(tmp_path / "out"))
        assert r.returncode == 0, r.stderr
        for heading in ("AppSec Plugin", "Environment", "Capsules", "Configuration sources", "Security Coach"):
            assert heading in r.stdout, f"missing heading: {heading}"

    def test_json_output_is_valid_and_has_required_keys(self, tmp_path):
        r = self._run("--json", "--repo-root", str(tmp_path))
        assert r.returncode == 0
        data = json.loads(r.stdout)
        for key in ("plugin", "paths", "capsules", "last_run", "config"):
            assert key in data
        assert "plugin_version" in data["plugin"]
        assert "coach" in data["capsules"]
        assert data["capsules"]["coach"]["state"] in ("active", "inactive", "unknown")

    def test_first_run_shows_no_baseline(self, tmp_path):
        r = self._run("--repo-root", str(tmp_path))
        assert r.returncode == 0
        assert "no baseline" in r.stdout

    def test_fast_path_preview_appears_with_baseline(self, tmp_path):
        """When a threat-model.yaml exists, the status helper runs check-changes
        and surfaces a 'Fast-path preview' block."""
        repo = tmp_path / "repo"
        repo.mkdir()
        _init_git_repo(repo)
        outdir = repo / "docs" / "security"
        outdir.mkdir(parents=True)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        plugin_json = json.loads((PLUGIN / ".claude-plugin" / "plugin.json").read_text())
        (outdir / "threat-model.yaml").write_text(
            "meta:\n"
            f"  plugin_version: '{plugin_json.get('version', 'unknown')}'\n"
            f"  analysis_version: {plugin_json.get('analysis_version', 1)}\n"
            "  git:\n"
            f"    commit_sha: '{head}'\n"
        )
        # Warm the baseline cache so check-changes can return a verdict
        _run_baseline(
            [
                "update",
                "--output-dir",
                str(outdir),
                "--repo-root",
                str(repo),
                "--mode",
                "full",
            ]
        )
        r = self._run("--repo-root", str(repo), "--output-dir", str(outdir))
        assert r.returncode == 0
        assert "Fast-path preview" in r.stdout
        assert "fast-abort" in r.stdout or "changes detected" in r.stdout
