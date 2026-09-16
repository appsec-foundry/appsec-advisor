"""Run reviewed maintainer test groups and conservative Git-based selections.

Exact membership detects additions and renames. Source routes are reviewed
producer/consumer selections, not an inferred dependency graph. Unknown paths,
shared inputs, and changes to multiple runtime modules require the full suite.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent


def _tests(names: str) -> tuple[str, ...]:
    """Expand explicit test module names; never infer membership from a glob."""
    return tuple(f"tests/test_{name}.py" for name in names.split())


# Every test file must appear here or in MANUAL_TESTS. Overlap is intentional:
# a consumer can guard more than one producer. Keep the frozen replay separate
# from the broader deterministic integration tests.
GROUPS = {
    "quick": _tests("""
        agent_definitions
        check_specs
        ci_test_workflow
        contract_integrity
        new_schemas
        run_tests
        runtime_cleanup
        schema_integrity
        taxonomy_coverage
    """),
    "report": _tests("""
        annotate_architecture
        annotate_sequences
        architect_structural_checks
        compose_depth_scoped_crossrefs
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        e2e_pipeline
        export_html
        export_pdf
        export_sarif
        export_threat_dragon
        export_threat_model_skill
        extract_report_section
        figure1_dfd
        figure1_detail
        figure1_layout_harness
        figure1_security
        figure1_svg
        figure2_svg
        final_render_guards
        fragment_authoring_fidelity
        fragment_invariant_parity
        fragment_registry
        inline_code_formatter
        mermaid_validator
        no_bare_ids
        p1_renderer_correctness
        p2_structural_determinism
        p3_behavior_tuning
        p4_cross_reference_coverage
        pentest_tasks
        pregenerate_fragments
        pregenerate_fragments_coverage
        publish_threat_model
        qa_checks
        qa_checks_cov_band1
        qa_checks_cov_band2
        qa_checks_cov_band3
        qa_checks_cov_band4
        query_threat_model
        reference_format
        render_abuse_cases
        render_changelog_audit
        render_editorial_receipt
        render_integrity
        render_pentest_tasks
        render_properties
        render_qa_receipt
        render_requirements_banner
        render_review_report
        render_threat_model
        sarif_validation
        section_condition_wiring
        section_integrity
        slug
        summarize_threat_model
        threat_fixture
        validate_fragment
        walkthrough_renderer
    """),
    "scanner": _tests("""
        agent_config_checks
        arch_coverage_bridge
        arch_coverage_bridge_coverage
        architecture_coverage_checks
        assess_supply_chain_controls
        authz_confirm
        backfill_scanner_remediation
        check_target_specificity
        config_iac_checks
        config_iac_scanner
        config_scanner_wireup
        credential_lifecycle_checks
        crypto_path_xxe_checks
        database_privilege_separation
        detect_open_registration
        lib_manifest
        manifest_readers
        mass_assignment_scanner
        normalize_config_scan
        postscan_secret_check
        recon_patterns
        repo_profile
        repo_scan
        route_inventory
        scan_excludes
        secret_scan
        source_auth_scanner
        source_lex
        supply_chain_config
        scanner_review_regressions
    """),
    "prompts": _tests("""
        agent_config_checks
        agent_definitions
        agent_doc_shell_snippets
        ask_threat_model_skill
        authnz_review_skill
        check_permissions
        check_permissions_coverage
        context_prompt_budgets
        context_routing
        dispatch_prompt_cache_order
        help_file
        help_reference
        lazy_phase_group_loading
        phase_group_prompts
        prompt_token_bounds
        runtime_doc_cli_contract
        skill_definitions
        stride_quick_profile
    """),
    "runtime": _tests("""
        acquire_lock_heartbeat
        active_tool_calls
        actor_discovery_cache
        agent_lifecycle
        agent_logger
        agent_logger_branches
        agent_logger_checkpoint_abort
        agent_logger_cov
        agent_logger_run_scope
        aggregate_run_issues
        appsec_status
        appsec_status_live
        artifact_stamp
        assert_completeness
        budget_watchdog
        check_state
        check_state_coverage
        check_state_hung_aborted
        check_stride_dispatch
        ci_dispatch_workflows
        completion_contract
        completion_relay
        context_window_report
        cost_running_total
        cutoff_cause
        diagnostic_bundle
        dispatch_manifest
        dispatch_model_and_diagnostics
        dispatch_prompt_cache_order
        dispatch_values_stage
        event_log
        gate_preconditions
        headless_usage
        hook_payload
        hook_payload_contract
        hooks_schema
        live_canary
        log_agent_end
        log_event
        log_shape_contract
        measure_run
        orchestration_controller
        recon_dispatch_contract
        record_component_durations
        record_stage_stats
        render_completion_summary
        render_completion_summary_config
        render_completion_summary_verdict
        render_progress
        render_run_diagnosis
        run_defect_fixes_2026_07_24
        run_diagnostics_recovery_2026_07_20
        run_headless_completion
        run_interruptible
        run_issues_pipeline
        run_ownership
        run_path_guard
        run_statistics_appendix
        run_summary
        run_timing
        runtime_cleanup
        runtime_doc_cli_contract
        runtime_helper_batch
        session_banner
        skill_auto_retry
        skill_watchdog
        stage1_coverage_recovery_2026_07_20
        stage1_coverage_recovery_2026_08_02
        stage3_runtime_contract
        stall_notice
        stamp_threat_model
        stride_dispatch_waves
        stride_outputs
        stride_progress
        stride_quick_profile
        stride_serial_dispatch_detection
        telemetry_consistency
        terminate_run
        thin_runtime_regressions_2026_07_20
        validate_dispatch_manifest
        verify_run_costs
        wait_abuse_progress
        wait_agent_calls
        wait_stride_progress
        watch_run
        write_stride_progress
    """),
    "incremental": _tests("""
        analysis_version_upgrade
        build_threat_model_yaml
        incremental_two_run_e2e
        persist_run_baseline
        validate_cache
    """),
    "e2e": _tests("""
        e2e_pipeline
    """),
    "qa-repair": _tests("""
        apply_content_repair
        apply_content_repair_coverage
        apply_editorial_plan
        apply_finding_refs_repair
        apply_prose_fixes
        apply_prose_fixes_coverage
        apply_repair_plan
        architect_structural_checks
        build_editorial_context
        check_editorial_diff
        check_inline_shortcut
        check_inline_shortcut_coverage
        editorial_gate
        eval_threat_model
        evidence_verification_schema
        guard_evidence_verification
        inline_code_formatter
        mermaid_validator
        pre_render_repair_scope
        qa_arch_coverage
        qa_arch_coverage_coverage
        qa_checks
        qa_checks_cov_band1
        qa_checks_cov_band2
        qa_checks_cov_band3
        qa_checks_cov_band4
        qa_depth_profile
        recommend_fixes
        repair_eligibility
        repair_proof_gate
        repair_self_verification
        review_threat_model
        validate_evidence_lines
        validate_finding_refs
        validate_mitigation_quality
        validate_ms_compactness
    """),
    "findings": _tests("""
        aggregate_threat_summary
        arch_coverage_bridge
        arch_coverage_bridge_coverage
        attack_step_quality
        auto_emitter_pass
        critical_findings_sync
        cvss_eligibility
        decision_register
        detect_impl_strategy
        emit_auth_coverage
        emit_clean_finding_titles
        emit_config_scan_mitigations
        emit_dep_update_activity
        emit_finding_fix_mitigations
        emit_general_mitigation_titles
        emit_known_bad_libs
        emit_meta_findings
        emit_review_mitigations
        emit_sca_practice
        emit_severity_rationale
        emit_threat_vektors
        emit_verdict_to_model
        enforce_control_taxonomy
        enforce_yaml_invariants
        enrich_asset_links
        enrichment_pass
        hydrate_mitigation_details
        merge_threats
        promote_verified_abuse_cases
        sanitize_perimeter_claims
        security_relevance_filter
        security_score
        severity_rollup
        team_questions
        threat_model_fields
        threat_model_health
        threats_merged_schema
        triage_compute_ranking
        triage_validate_ratings
        weakness_class_config_consistency
        weakness_signals
    """),
    "config": _tests("""
        detect_public_repo
        detect_session_model
        estimate_duration
        haiku_routing_per_depth
        load_business_context
        load_org_context
        model_lineup
        model_release_pricing
        org_profile_schema
        phase_budgets
        project_run_cost
        reasoning_model_resolution
        resolve_config
        resolve_config_org_profile
        resolve_config_slug
        resolve_org_profile
        security_steering
        security_steering_units
        validate_config
    """),
    "requirements": _tests("""
        build_verify_diff
        fetch_requirements
        harvest_requirements
        render_requirements_banner
        requirements_catalog_predicate
        requirements_gate
        requirements_hook
        requirements_mapping
        requirements_report
        requirements_resolution
        requirements_source_resolution
        requirements_state
        requirements_trace
        requirements_verification
        requirements_yaml
    """),
    "baseline": _tests("""
        baseline_check
        baseline_content_unchanged
        baseline_release
        baseline_state_coverage
        install_baseline
        remove_baseline
        sync_baseline
        update_baseline
    """),
    "packaging": _tests("""
        check_release_meta
        check_skill_enabled
        internal_packaging_end_to_end
        marketplace_manifest
        package_internal_plugin
        plugin_meta
        skill_policy_gate
        smoke_test_package
        version_status
    """),
    "context": _tests("""
        abuse_case_gate
        abuse_case_verdicts
        abuse_cases_schema
        build_abuse_case_contexts
        build_architecture_analysis_context
        build_cross_repo_register
        build_post_stride_contexts
        build_posture_verdict
        build_stride_evidence_bundles
        build_threat_modeling_context
        build_trust_boundary_assessment_input
        canonicalize_component_id
        classify_component
        context_prompt_budgets
        context_routing
        coverage_checks
        discover_identity_providers
        extract_data_relations
        finalize_component_inventory
        load_related_repos
        match_abuse_cases
        normalize_security_architecture
        prepare_trust_boundary_context
        reclassify_components
        recon_signals_schema
        resolve_abuse_cases
        resolve_actors
        slice_actors
        slice_cross_repo_for_component
        slice_taxonomy
        stage1_context_edge_inventory
        validate_recon_summary
        validate_threat_modeling_context
        verify_abuse_cases
    """),
    "trust": _tests("""
        ensure_output_gitignore
        path_guard
        plugin_read_gate
        plugin_write_gate
        postscan_secret_check
        preflight_untrusted
        redact_known_secrets
        run_path_guard
        url_guard
    """),
    "shared": _tests("""
        atomic_io
        intermediate_json
        reserve_ids
        safe_cond
        schema_drift
        schemas
        threat_model_fields
        validate_intermediate
        yaml_io
    """),
    "tooling": _tests("""
        acceptance_invocation
        check_fragment_registry
        check_specs
        check_target_specificity
        ci_dispatch_workflows
        ci_test_workflow
        enforcement_mutations
        run_tests
        spec_guard
    """),
    "integration": _tests("""
        e2e_cross_repo_fixture_script
        e2e_fixture_script
        e2e_spring_fixture_script
        full_run_e2e_driver
        integration
        single_repo_no_cross_repo_regression
        threat_fixture
        verify_full_run_oracle
    """),
}

MANUAL_TESTS = {
    "tests/test_full_run_e2e.py": "Assertions on live-run artifacts; only enabled by the manual E2E driver.",
}

# Start with bounded leaf/report and scanner entry points whose consumer tests
# have been reviewed. All other source paths deliberately fall back to all.
# Extend a route only after checking imports, CLI callers, data readers, and
# integration tests. Changes to shared contracts always use all.
SOURCE_GROUPS = {
    "scripts/export_sarif.py": ("report", "incremental", "findings"),
    "scripts/export_html.py": ("report", "qa-repair"),
    "scripts/export_pdf.py": ("report", "qa-repair"),
    "scripts/export_threat_dragon.py": ("report",),
    "scripts/figure2_svg.py": ("report", "qa-repair"),
    "scripts/walkthrough_renderer.py": ("report", "qa-repair", "findings"),
    "scripts/repo_scan.py": ("scanner", "trust", "integration"),
    "scripts/config_iac_scanner.py": ("scanner", "findings", "incremental", "report", "qa-repair", "e2e"),
    "scripts/mass_assignment_scanner.py": ("scanner", "findings", "incremental", "report", "qa-repair", "e2e"),
    "scripts/source_auth_scanner.py": (
        "scanner",
        "context",
        "findings",
        "incremental",
        "report",
        "qa-repair",
        "e2e",
    ),
}


def _safe_file(path: str, root: Path) -> bool:
    relative = PurePosixPath(path)
    return (
        not relative.is_absolute()
        and ".." not in relative.parts
        and relative.as_posix() == path
        and (root / path).is_file()
        and (root / path).resolve().is_relative_to(root.resolve())
    )


def select_tests(group: str, root: Path = ROOT) -> list[str]:
    """Resolve exact group membership, rejecting missing or escaped files."""
    if group == "all":
        return ["tests/"]
    if group not in GROUPS:
        raise ValueError(f"unknown test group: {group!r}")
    selected = []
    for path in GROUPS[group]:
        if not _safe_file(path, root):
            raise ValueError(f"test group {group!r} has a missing or unsafe file: {path!r}")
        selected.append(path)
    return list(dict.fromkeys(selected))


def group_problems(root: Path = ROOT) -> list[str]:
    """Check exact inventory, manual exceptions, and reviewed source routes."""
    problems = []
    grouped = set()
    for group, paths in GROUPS.items():
        if not paths or len(paths) != len(set(paths)):
            problems.append(f"empty group or duplicate membership: {group}")
        for path in paths:
            if (
                not path.startswith("tests/")
                or not PurePosixPath(path).name.startswith("test_")
                or not path.endswith(".py")
            ):
                problems.append(f"invalid test path in {group}: {path}")
            if not _safe_file(path, root):
                problems.append(f"missing or unsafe test in {group}: {path}")
            grouped.add(path)
    for path, reason in MANUAL_TESTS.items():
        if not reason.strip() or not _safe_file(path, root) or path in grouped:
            problems.append(f"invalid manual test exception: {path}")
    discovered = {path.relative_to(root).as_posix() for path in (root / "tests").rglob("test_*.py")}
    for path in sorted(discovered - grouped - MANUAL_TESTS.keys()):
        problems.append(f"test needs an explicit group or manual role: {path}")
    for path, groups in SOURCE_GROUPS.items():
        if not _safe_file(path, root) or not groups or any(group not in GROUPS for group in groups):
            problems.append(f"invalid source route: {path}")
    return problems


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"cannot determine changed paths: {os.fsdecode(result.stderr).strip()}")
    return result.stdout


def changed_paths(base: str, root: Path = ROOT) -> list[str]:
    """Include branch commits, staged, unstaged, and untracked changes.

    Resolve the base locally and compare branch commits to its merge base.
    Disable rename collapsing to retain both old and new paths. Separate index
    and worktree diffs also retain changes that cancel each other out.
    """
    commit = os.fsdecode(_git(root, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}")).strip()
    ancestor = os.fsdecode(_git(root, "merge-base", commit, "HEAD")).strip()
    commands = (
        ("diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames", "-z", ancestor, "HEAD", "--"),
        ("diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames", "-z", "--cached", "HEAD", "--"),
        ("diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames", "-z", "--"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
    )
    return sorted({os.fsdecode(path) for args in commands for path in _git(root, *args).split(b"\0") if path})


def requirement_tests(paths: list[str], root: Path = ROOT) -> list[str]:
    """Add the full test modules containing applicable requirement guards."""
    import check_specs
    import yaml

    try:
        document = check_specs.load_binding_document(root / "data/requirement-bindings.yaml")
    except yaml.YAMLError as error:
        raise ValueError(f"invalid requirement bindings: {error}") from error
    problems = check_specs.binding_schema_problems(document, root / "schemas/requirement-bindings.schema.yaml")
    if problems:
        raise ValueError("invalid requirement bindings: " + "; ".join(problems))
    bindings = check_specs.parse_bindings(document)
    selected = set()
    for binding in bindings.values():
        if any(not check_specs.safe_binding_pattern(pattern) for pattern in binding.paths):
            raise ValueError(f"unsafe requirement binding pattern: {binding.rid}")
        if any(
            path == pattern or path in check_specs.path_matches(pattern, root)
            for path in paths
            for pattern in binding.paths
        ):
            selected.update(guard.split("::", 1)[0] for guard in binding.guards)
    return sorted(selected)


@dataclass(frozen=True)
class Selection:
    paths: tuple[str, ...]
    reasons: tuple[str, ...]


def select_changed(paths: list[str], root: Path = ROOT) -> Selection:
    """Fail back to the full suite whenever the impact is not bounded."""
    problems = group_problems(root)
    if problems:
        return Selection(("tests/",), ("full suite: group inventory needs review", *problems))
    runtime = [path for path in paths if path.startswith(("scripts/", "hooks/"))]
    if len(runtime) > 1:
        return Selection(
            ("tests/",),
            (
                "full suite: multiple runtime or tooling source files changed: "
                + ", ".join(repr(path) for path in runtime),
            ),
        )
    groups = {"quick"}
    reasons = []
    for path in paths:
        if not _safe_file(path, root):
            return Selection(("tests/",), (f"full suite: deleted, renamed, or unsafe path {path!r}",))
        affected = SOURCE_GROUPS.get(path)
        if affected is None and path.startswith("tests/"):
            affected = tuple(group for group, tests in GROUPS.items() if path in tests)
        if not affected:
            return Selection(("tests/",), (f"full suite: no reviewed source/test route for {path!r}",))
        groups.update(affected)
        reasons.append(f"{path!r} -> {', '.join(affected)}")
    selected = {path for group in groups for path in select_tests(group, root)}
    guards = requirement_tests(paths, root) if paths else []
    inventoried = {path for tests in GROUPS.values() for path in tests}
    for guard in guards:
        if guard not in inventoried or not _safe_file(guard, root):
            return Selection(("tests/",), (f"full suite: missing, unassigned, or unsafe requirement guard {guard!r}",))
    selected.update(guards)
    if guards:
        reasons.append("requirement guard modules: " + ", ".join(guards))
    reasons.append("shared base group: quick" if paths else "no changed paths; shared base group: quick")
    return Selection(tuple(sorted(selected)), tuple(reasons))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print selected paths without running pytest")
    parser.add_argument("--check-groups", action="store_true", help="validate test inventory and source routes")
    parser.add_argument(
        "--changed-against", metavar="REF", help="select from the merge base plus all local changes; no fetch"
    )
    parser.add_argument("group", nargs="?", default="all", choices=["all", *GROUPS])
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER, help="arguments forwarded to pytest")
    args = parser.parse_args(argv)
    if args.changed_against and args.group != "all":
        parser.error("--changed-against cannot be combined with a named group")
    if args.check_groups and (args.changed_against or args.list or args.group != "all" or args.pytest_args):
        parser.error("--check-groups must be used alone")
    try:
        if args.check_groups:
            problems = group_problems()
            if problems:
                print("\n".join(problems), file=sys.stderr)
                return 2
            print("Test inventory and source routes are valid.")
            return 0
        if args.changed_against:
            selection = select_changed(changed_paths(args.changed_against))
            paths = list(selection.paths)
            print("\n".join(selection.reasons), file=sys.stderr)
        else:
            paths = select_tests(args.group)
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 2
    if args.list:
        print("\n".join(paths))
        return 0
    return subprocess.run([sys.executable, "-m", "pytest", *paths, *args.pytest_args], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
