"""Run reviewed maintainer test groups and conservative Git-based selections.

Exact membership detects additions and renames. Source routes name measured
producer and consumer modules directly; requirement bindings retain their exact
pytest selectors. Unknown paths and shared inputs require the full suite.
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
    "prose-formatting": _tests("""
        apply_prose_fixes
        apply_prose_fixes_coverage
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov3
        e2e_pipeline
        inline_code_formatter
        qa_checks_cov_band3
        walkthrough_renderer
    """),
    "report": _tests("""
        actor_attribution
        actor_presentation
        annotate_architecture
        annotate_sequences
        architect_structural_checks
        compose_depth_scoped_crossrefs
        compose_services
        deployment_inventory
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
        figure_deployment
        figure_details
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
        handler_resolver
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
        lens_coverage
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
        report_plugin_issue
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
        schema_canonicalize
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
        business_relevance
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
        reconcile_privileged_roles
        reconcile_role_access
        sanitize_perimeter_claims
        security_relevance_filter
        security_score
        severity_rollup
        severity_policy
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
        baseline_modular
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
        embedded_store_access
        extract_data_relations
        finalize_component_inventory
        flow_route_auth
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
        audit_test_routes
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

# Each route lists every test module that executes the file, uses its
# module-level constants or classes, or reads it; `make audit-test-routes`
# measures this and rejects a route that misses one. Do not replace them with
# group names: groups are convenient maintainer suites, not dependency boundaries.
# Resource routes also cover tests that execute their loaders and renderers in
# subprocesses, where the audit records execution but not file reads.
# Repository documents (guidance, changelog, docs, specs, requirement bindings)
# are not runtime input: their routes name the tests that read them, including
# the tracked-file content scan. Shipped Markdown under agents/ and skills/
# remains runtime input and falls back to all unless explicitly routed below. threat_fixture replays
# build_threat_model_yaml and compose_threat_model, so modules they import
# route to it.
SOURCE_TESTS = {
    "agents/appsec-ms-renderer.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        agent_logger
        aggregate_run_issues
        check_target_specificity
        completion_contract
        dispatch_manifest
        fragment_invariant_parity
        prompt_token_bounds
        requirements_verification
        stride_outputs
    """),
    "agents/appsec-secarch-renderer.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        agent_logger
        check_target_specificity
        completion_contract
        fragment_invariant_parity
        prompt_token_bounds
        requirements_verification
        stride_outputs
    """),
    "agents/appsec-threat-renderer.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        agent_logger
        agent_logger_cov
        check_target_specificity
        completion_contract
        dispatch_manifest
        fragment_authoring_fidelity
        fragment_invariant_parity
        phase_group_prompts
        requirements_resolution
        requirements_verification
        schema_drift
        stride_outputs
        validate_ms_compactness
    """),
    "scripts/dispatch_window.py": _tests("""
        check_target_specificity
        context_routing
        gate_preconditions
        orchestration_controller
        record_stage_stats
        requirements_verification
        run_path_guard
        stride_outputs
        wait_agent_calls
    """),
    "agents/appsec-evidence-verifier.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        agent_logger
        check_target_specificity
        completion_contract
        fragment_invariant_parity
        requirements_verification
        run_diagnostics_recovery_2026_07_20
        stride_outputs
    """),
    "agents/appsec-stride-analyzer-v2.md": _tests("""
        active_tool_calls
        agent_definitions
        agent_doc_shell_snippets
        agent_logger
        aggregate_run_issues
        budget_watchdog
        check_target_specificity
        completion_contract
        context_prompt_budgets
        dispatch_prompt_cache_order
        fragment_invariant_parity
        hook_payload_contract
        prompt_token_bounds
        requirements_verification
        run_issues_pipeline
        schema_integrity
        stage1_context_edge_inventory
        stage1_coverage_recovery_2026_07_20
        stage1_coverage_recovery_2026_08_02
        stride_outputs
    """),
    "schemas/evidence-verifier-context.schema.json": _tests("""
        build_post_stride_contexts
        check_target_specificity
        new_schemas
        orchestration_controller
        requirements_verification
        schema_integrity
        schemas
    """),
    "schemas/stride.schema.yaml": _tests("""
        agent_definitions
        check_target_specificity
        intermediate_json
        merge_threats
        new_schemas
        orchestration_controller
        requirements_verification
        schema_drift
        schema_integrity
        schemas
        stage1_coverage_recovery_2026_07_20
        stride_dispatch_waves
        validate_intermediate
    """),
    "schemas/threat-model.output.schema.yaml": _tests("""
        actor_presentation
        build_threat_model_yaml
        check_target_specificity
        config_iac_checks
        detect_open_registration
        emit_clean_finding_titles
        emit_verdict_to_model
        enrichment_pass
        figure1_security
        incremental_two_run_e2e
        load_related_repos
        merge_threats
        new_schemas
        prepare_trust_boundary_context
        promote_verified_abuse_cases
        qa_checks
        requirements_verification
        schema_drift
        schema_integrity
        schemas
        severity_policy
        team_questions
        validate_evidence_lines
        validate_fragment
        validate_intermediate
        weakness_class_config_consistency
    """),
    "schemas/threats-merged.schema.yaml": _tests("""
        actor_attribution
        arch_coverage_bridge
        build_post_stride_contexts
        check_target_specificity
        merge_threats
        new_schemas
        promote_verified_abuse_cases
        requirements_verification
        schema_drift
        schema_integrity
        schemas
        severity_policy
        threats_merged_schema
        validate_intermediate
        weakness_class_config_consistency
    """),
    "scripts/build_post_stride_contexts.py": _tests("""
        build_post_stride_contexts
        check_target_specificity
        gate_preconditions
        orchestration_controller
        requirements_verification
        run_path_guard
        stride_outputs
    """),
    "scripts/schema_canonicalize.py": _tests("""
        check_stride_dispatch
        check_target_specificity
        gate_preconditions
        orchestration_controller
        requirements_verification
        run_path_guard
        schema_canonicalize
        stage1_coverage_recovery_2026_07_20
        stride_dispatch_waves
        stride_outputs
        validate_fragment
    """),
    "scripts/stride_dispatch_waves.py": _tests("""
        check_stride_dispatch
        check_target_specificity
        gate_preconditions
        lens_coverage
        log_shape_contract
        orchestration_controller
        requirements_verification
        run_diagnostics_recovery_2026_07_20
        run_path_guard
        stage1_coverage_recovery_2026_07_20
        stage1_coverage_recovery_2026_08_02
        stride_dispatch_waves
        stride_outputs
        stride_serial_dispatch_detection
        wait_stride_progress
    """),
    "scripts/validate_intermediate.py": _tests("""
        actor_attribution
        actor_presentation
        agent_definitions
        arch_coverage_bridge
        architect_structural_checks
        authz_confirm
        build_post_stride_contexts
        build_threat_model_yaml
        build_threat_modeling_context
        build_trust_boundary_assessment_input
        check_stride_dispatch
        check_target_specificity
        config_scanner_wireup
        credential_lifecycle_checks
        cvss_eligibility
        database_privilege_separation
        e2e_pipeline
        figure1_dfd
        fragment_invariant_parity
        gate_preconditions
        incremental_two_run_e2e
        intermediate_json
        lens_coverage
        match_abuse_cases
        merge_threats
        new_schemas
        orchestration_controller
        pentest_tasks
        reclassify_components
        recon_signals_schema
        reconcile_role_access
        render_abuse_cases
        requirements_catalog_predicate
        requirements_trace
        requirements_verification
        resolve_actors
        review_threat_model
        run_diagnostics_recovery_2026_07_20
        run_path_guard
        schema_integrity
        severity_policy
        source_auth_scanner
        stage1_coverage_recovery_2026_07_20
        stage1_coverage_recovery_2026_08_02
        stride_dispatch_waves
        stride_outputs
        threat_fixture
        threats_merged_schema
        triage_compute_ranking
        validate_intermediate
        wait_stride_progress
    """),
    "AGENTS.md": _tests("""
        context_prompt_budgets
        decision_register
        lazy_phase_group_loading
        orchestration_controller
        requirements_verification
        run_tests
    """),
    "CONTRIBUTING.md": _tests("""
        requirements_verification
        run_tests
    """),
    "CHANGELOG.md": _tests("requirements_verification"),
    "README.md": _tests("""
        marketplace_manifest
        orchestration_controller
        requirements_verification
    """),
    "agents/shared/logging-standard.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        budget_watchdog
        check_target_specificity
        requirements_verification
        stride_outputs
    """),
    "data/requirement-bindings.yaml": _tests("""
        check_specs
        check_target_specificity
        requirements_hook
        requirements_verification
        run_tests
        weakness_class_config_consistency
    """),
    "docs/harvester.md": _tests("requirements_verification"),
    "docs/headless-mode.md": _tests("requirements_verification"),
    "docs/images/figure1-example.svg": _tests("requirements_verification"),
    "docs/internal/contracts/orchestration-actions.md": _tests("requirements_verification"),
    "docs/internal/contracts/schema-invariants.md": _tests("""
        report_plugin_issue
        requirements_verification
    """),
    "docs/internal/cost-model.md": _tests("requirements_verification"),
    "docs/internal/decisions.md": _tests("""
        check_specs
        decision_register
        dispatch_prompt_cache_order
        requirements_verification
    """),
    "docs/org-profiles.md": _tests("requirements_verification"),
    "docs/threat-modeler.md": _tests("requirements_verification"),
    "specs/requirements.md": _tests("""
        check_specs
        requirements_hook
        requirements_verification
    """),
    "scripts/apply_prose_fixes.py": _tests("""
        actor_presentation
        analysis_version_upgrade
        apply_prose_fixes
        apply_prose_fixes_coverage
        attack_step_quality
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov2
        compose_threat_model_cov3
        e2e_pipeline
        enforcement_mutations
        gate_preconditions
        p1_renderer_correctness
        qa_checks
        qa_checks_cov_band2
        qa_checks_cov_band4
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
        walkthrough_renderer
    """),
    "scripts/actor_attribution.py": _tests("""
        actor_attribution
        check_target_specificity
        emit_threat_vektors
        gate_preconditions
        merge_threats
        reclassify_components
        requirements_verification
        run_path_guard
        severity_policy
        stride_outputs
        weakness_signals
    """),
    "data/actor-attribution-rules.yaml": _tests("""
        actor_attribution
        check_target_specificity
        emit_threat_vektors
        requirements_verification
        weakness_class_config_consistency
    """),
    "scripts/reconcile_privileged_roles.py": _tests("""
        check_target_specificity
        discover_identity_providers
        embedded_store_access
        flow_route_auth
        fragment_invariant_parity
        gate_preconditions
        orchestration_controller
        reconcile_privileged_roles
        reconcile_role_access
        requirements_verification
        run_path_guard
        stride_outputs
    """),
    "scripts/reconcile_role_access.py": _tests("""
        check_target_specificity
        discover_identity_providers
        embedded_store_access
        figure1_dfd
        flow_route_auth
        fragment_invariant_parity
        gate_preconditions
        orchestration_controller
        reconcile_privileged_roles
        reconcile_role_access
        requirements_verification
        run_path_guard
        stride_outputs
    """),
    "scripts/actor_presentation.py": _tests("""
        actor_attribution
        actor_presentation
        analysis_version_upgrade
        build_threat_model_yaml
        check_target_specificity
        compose_depth_scoped_crossrefs
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        detect_public_repo
        e2e_pipeline
        emit_threat_vektors
        emit_verdict_to_model
        enforcement_mutations
        export_html
        export_pdf
        figure1_detail
        figure1_dfd
        figure1_layout_harness
        figure1_svg
        figure2_svg
        fragment_authoring_fidelity
        gate_preconditions
        p1_renderer_correctness
        p3_behavior_tuning
        p4_cross_reference_coverage
        qa_checks
        qa_checks_cov_band1
        qa_checks_cov_band2
        qa_checks_cov_band4
        reconcile_privileged_roles
        reference_format
        render_abuse_cases
        render_integrity
        render_properties
        requirements_mapping
        requirements_trace
        requirements_verification
        run_path_guard
        run_statistics_appendix
        runtime_doc_cli_contract
        safe_cond
        severity_rollup
        stride_outputs
        taxonomy_coverage
        team_questions
        threat_fixture
    """),
    "scripts/export_sarif.py": _tests("""
        check_target_specificity
        e2e_pipeline
        export_sarif
        export_threat_model_skill
        gate_preconditions
        requirements_verification
        run_path_guard
        runtime_doc_cli_contract
        severity_policy
        stride_outputs
        threat_fixture
    """),
    "scripts/export_html.py": _tests("""
        check_target_specificity
        e2e_pipeline
        export_html
        export_threat_model_skill
        gate_preconditions
        requirements_verification
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
    """),
    "scripts/export_pdf.py": _tests("""
        check_target_specificity
        e2e_pipeline
        export_html
        export_pdf
        export_threat_model_skill
        gate_preconditions
        requirements_verification
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
    """),
    "scripts/export_threat_dragon.py": _tests("""
        check_target_specificity
        export_threat_dragon
        export_threat_model_skill
        gate_preconditions
        orchestration_controller
        render_completion_summary
        requirements_verification
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
    """),
    "scripts/figure1_dfd.py": _tests("""
        actor_presentation
        analysis_version_upgrade
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        detect_public_repo
        discover_identity_providers
        e2e_pipeline
        enforcement_mutations
        export_html
        export_pdf
        figure1_detail
        figure1_dfd
        figure2_svg
        figure_deployment
        figure_details
        gate_preconditions
        p1_renderer_correctness
        p2_structural_determinism
        pregenerate_fragments
        pregenerate_fragments_coverage
        qa_checks
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
    """),
    "scripts/figure2_svg.py": _tests("""
        actor_presentation
        analysis_version_upgrade
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        figure2_svg
        gate_preconditions
        p1_renderer_correctness
        qa_checks
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
    """),
    "scripts/finalize_component_inventory.py": _tests("""
        build_trust_boundary_assessment_input
        check_target_specificity
        discover_identity_providers
        finalize_component_inventory
        fragment_invariant_parity
        gate_preconditions
        requirements_verification
        run_path_guard
        stride_outputs
    """),
    "scripts/inline_code_formatter.py": _tests("""
        analysis_version_upgrade
        apply_prose_fixes
        apply_prose_fixes_coverage
        attack_step_quality
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        e2e_pipeline
        enforcement_mutations
        gate_preconditions
        inline_code_formatter
        p1_renderer_correctness
        qa_checks
        qa_checks_cov_band2
        qa_checks_cov_band3
        qa_checks_cov_band4
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
        walkthrough_renderer
    """),
    "scripts/run_tests.py": _tests("""
        audit_test_routes
        check_target_specificity
        gate_preconditions
        requirements_verification
        run_path_guard
        run_tests
        stride_outputs
    """),
    "scripts/audit_test_routes.py": _tests("""
        audit_test_routes
        check_target_specificity
        gate_preconditions
        requirements_verification
        run_path_guard
        stride_outputs
    """),
    "scripts/walkthrough_renderer.py": _tests("""
        architect_structural_checks
        attack_step_quality
        check_target_specificity
        compose_threat_model
        e2e_pipeline
        gate_preconditions
        p1_renderer_correctness
        pregenerate_fragments
        pregenerate_fragments_coverage
        qa_checks
        qa_checks_cov_band3
        render_integrity
        requirements_verification
        run_path_guard
        severity_rollup
        stride_outputs
        walkthrough_renderer
    """),
    "scripts/repo_scan.py": _tests("""
        check_target_specificity
        gate_preconditions
        repo_scan
        requirements_verification
        run_path_guard
        scanner_review_regressions
        stride_outputs
    """),
    "scripts/config_iac_scanner.py": _tests("""
        agent_config_checks
        check_target_specificity
        config_iac_scanner
        config_scanner_wireup
        gate_preconditions
        repo_scan
        requirements_verification
        run_path_guard
        security_score
        stride_outputs
        validate_intermediate
    """),
    "scripts/deployment_inventory.py": _tests("""
        check_permissions
        check_target_specificity
        deployment_inventory
        e2e_pipeline
        figure_deployment
        figure_details
        gate_preconditions
        requirements_verification
        run_path_guard
        runtime_cleanup
        stride_outputs
        threat_fixture
    """),
    "scripts/figure_deployment.py": _tests("""
        analysis_version_upgrade
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        figure_deployment
        figure_details
        gate_preconditions
        p1_renderer_correctness
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
    """),
    "scripts/figure_details.py": _tests("""
        analysis_version_upgrade
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        figure_deployment
        figure_details
        gate_preconditions
        p1_renderer_correctness
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
    """),
    "scripts/compose_services.py": _tests("""
        analysis_version_upgrade
        check_target_specificity
        compose_services
        compose_threat_model
        compose_threat_model_cov2
        deployment_inventory
        e2e_pipeline
        enforcement_mutations
        figure_deployment
        figure_details
        gate_preconditions
        p1_renderer_correctness
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
    """),
    "data/deployment-technology.yaml": _tests("""
        check_target_specificity
        deployment_inventory
        e2e_pipeline
        figure_deployment
        figure_details
        requirements_verification
        threat_fixture
        weakness_class_config_consistency
    """),
    "schemas/deployment-inventory.schema.json": _tests("""
        check_target_specificity
        deployment_inventory
        e2e_pipeline
        figure_deployment
        figure_details
        requirements_verification
        schemas
        threat_fixture
    """),
    "scripts/mass_assignment_scanner.py": _tests("""
        check_target_specificity
        gate_preconditions
        mass_assignment_scanner
        repo_scan
        requirements_verification
        run_path_guard
        scanner_review_regressions
        stride_outputs
    """),
    "scripts/handler_resolver.py": _tests("""
        actor_attribution
        arch_coverage_bridge
        architecture_coverage_checks
        authz_confirm
        check_target_specificity
        flow_route_auth
        gate_preconditions
        handler_resolver
        orchestration_controller
        repo_scan
        requirements_verification
        route_inventory
        run_path_guard
        security_score
        stride_outputs
        threat_fixture
    """),
    "scripts/flow_route_auth.py": _tests("""
        check_target_specificity
        discover_identity_providers
        embedded_store_access
        flow_route_auth
        fragment_invariant_parity
        gate_preconditions
        orchestration_controller
        reconcile_role_access
        requirements_verification
        run_path_guard
        stride_outputs
        validate_fragment
    """),
    "scripts/source_auth_scanner.py": _tests("""
        authz_confirm
        build_architecture_analysis_context
        build_trust_boundary_assessment_input
        check_target_specificity
        credential_lifecycle_checks
        crypto_path_xxe_checks
        detect_impl_strategy
        finalize_component_inventory
        fragment_invariant_parity
        gate_preconditions
        handler_resolver
        orchestration_controller
        reclassify_components
        repo_scan
        requirements_verification
        run_path_guard
        runtime_doc_cli_contract
        scanner_review_regressions
        security_score
        source_auth_scanner
        stride_outputs
        threat_fixture
        validate_fragment
        weakness_signals
    """),
    "scripts/aggregate_run_issues.py": _tests("""
        actor_attribution
        aggregate_run_issues
        check_target_specificity
        dispatch_model_and_diagnostics
        gate_preconditions
        log_shape_contract
        orchestration_controller
        recommend_fixes
        render_integrity
        requirements_verification
        run_diagnostics_recovery_2026_07_20
        run_headless_completion
        run_issues_pipeline
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
        terminate_run
        thin_runtime_regressions_2026_07_20
    """),
    "scripts/harvest_requirements.py": _tests("""
        check_target_specificity
        gate_preconditions
        harvest_requirements
        requirements_verification
        run_path_guard
        stride_outputs
    """),
    "scripts/pregenerate_fragments.py": _tests("""
        actor_presentation
        analysis_version_upgrade
        assert_completeness
        build_threat_model_yaml
        check_target_specificity
        compose_depth_scoped_crossrefs
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        dispatch_manifest
        e2e_pipeline
        emit_verdict_to_model
        enforcement_mutations
        figure1_dfd
        figure1_layout_harness
        figure2_svg
        figure_details
        fragment_authoring_fidelity
        gate_preconditions
        p1_renderer_correctness
        p2_structural_determinism
        p3_behavior_tuning
        p4_cross_reference_coverage
        pregenerate_fragments
        pregenerate_fragments_coverage
        qa_checks
        qa_checks_cov_band1
        qa_checks_cov_band2
        qa_checks_cov_band4
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_trace
        requirements_verification
        run_path_guard
        run_statistics_appendix
        runtime_doc_cli_contract
        safe_cond
        severity_rollup
        skill_auto_retry
        stride_outputs
        taxonomy_coverage
        team_questions
        threat_fixture
    """),
    "scripts/recommend_fixes.py": _tests("""
        aggregate_run_issues
        check_target_specificity
        gate_preconditions
        orchestration_controller
        recommend_fixes
        report_plugin_issue
        requirements_verification
        run_diagnostics_recovery_2026_07_20
        run_headless_completion
        run_issues_pipeline
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
        terminate_run
    """),
    "scripts/render_completion_summary.py": _tests("""
        actor_presentation
        check_target_specificity
        completion_relay
        compose_threat_model
        gate_preconditions
        p1_renderer_correctness
        render_completion_summary
        render_completion_summary_config
        render_completion_summary_verdict
        render_integrity
        report_plugin_issue
        requirements_verification
        run_headless_completion
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
        team_questions
    """),
    "scripts/verify_run_costs.py": _tests("""
        aggregate_run_issues
        check_target_specificity
        context_window_report
        cost_running_total
        gate_preconditions
        measure_run
        model_release_pricing
        orchestration_controller
        persist_run_baseline
        recommend_fixes
        render_completion_summary
        requirements_verification
        run_diagnostics_recovery_2026_07_20
        run_headless_completion
        run_issues_pipeline
        run_path_guard
        runtime_doc_cli_contract
        skill_watchdog
        stride_outputs
        terminate_run
        verify_run_costs
    """),
    "scripts/render_progress.py": _tests("""
        check_target_specificity
        gate_preconditions
        render_progress
        requirements_verification
        run_headless_completion
        run_path_guard
        stride_outputs
    """),
    "scripts/security_score.py": _tests("""
        check_target_specificity
        gate_preconditions
        repo_scan
        requirements_verification
        run_path_guard
        runtime_doc_cli_contract
        security_score
        stride_outputs
    """),
    "scripts/version_status.py": _tests("""
        appsec_status
        check_target_specificity
        gate_preconditions
        requirements_verification
        run_path_guard
        stride_outputs
        version_status
    """),
    "scripts/load_business_context.py": _tests("""
        build_threat_model_yaml
        build_threat_modeling_context
        check_target_specificity
        compose_threat_model
        figure1_layout_harness
        gate_preconditions
        load_business_context
        orchestration_controller
        pregenerate_fragments
        qa_checks
        requirements_verification
        resolve_config
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
        threat_fixture
        validate_intermediate
    """),
    "scripts/team_questions.py": _tests("""
        analysis_version_upgrade
        build_threat_model_yaml
        check_target_specificity
        completion_relay
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        gate_preconditions
        p1_renderer_correctness
        p2_structural_determinism
        p4_cross_reference_coverage
        qa_checks
        qa_checks_cov_band1
        qa_checks_cov_band2
        qa_checks_cov_band4
        reference_format
        render_completion_summary
        render_completion_summary_config
        render_completion_summary_verdict
        render_integrity
        render_properties
        report_plugin_issue
        requirements_mapping
        requirements_verification
        run_headless_completion
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
        team_questions
        threat_fixture
    """),
    "scripts/build_threat_model_yaml.py": _tests("""
        actor_presentation
        build_threat_model_yaml
        check_target_specificity
        config_iac_checks
        dispatch_manifest
        gate_preconditions
        incremental_two_run_e2e
        merge_threats
        orchestration_controller
        prepare_trust_boundary_context
        promote_verified_abuse_cases
        requirements_catalog_predicate
        requirements_trace
        requirements_verification
        run_path_guard
        run_tests
        severity_policy
        stride_outputs
        threat_fixture
        validate_evidence_lines
    """),
    "scripts/orchestration_controller.py": _tests("""
        agent_config_checks
        agent_logger_cov
        auto_emitter_pass
        check_target_specificity
        config_scanner_wireup
        context_routing
        database_privilege_separation
        discover_identity_providers
        dispatch_manifest
        dispatch_model_and_diagnostics
        dispatch_values_stage
        embedded_store_access
        flow_route_auth
        fragment_invariant_parity
        gate_preconditions
        orchestration_controller
        phase_group_prompts
        reasoning_model_resolution
        reconcile_role_access
        render_completion_summary
        render_completion_summary_config
        report_plugin_issue
        requirements_verification
        run_diagnostics_recovery_2026_07_20
        run_headless_completion
        run_ownership
        run_path_guard
        runtime_doc_cli_contract
        source_auth_scanner
        stage1_context_edge_inventory
        stage1_coverage_recovery_2026_07_20
        stride_outputs
        telemetry_consistency
        thin_runtime_regressions_2026_07_20
    """),
    "scripts/_business_relevance.py": _tests("""
        analysis_version_upgrade
        business_relevance
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        gate_preconditions
        p1_renderer_correctness
        reference_format
        render_completion_summary
        render_completion_summary_config
        render_completion_summary_verdict
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        run_path_guard
        stride_outputs
        threat_fixture
    """),
    "schemas/orchestration-action.schema.json": _tests("""
        check_target_specificity
        context_routing
        dispatch_model_and_diagnostics
        orchestration_controller
        requirements_verification
        schema_integrity
        schemas
    """),
    "agents/appsec-control-analyst.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        agent_logger
        check_target_specificity
        context_prompt_budgets
        fragment_invariant_parity
        prompt_token_bounds
        requirements_verification
        stage1_context_edge_inventory
        stride_outputs
    """),
    "agents/appsec-recon-scanner.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        agent_logger
        agent_logger_branches
        budget_watchdog
        check_target_specificity
        completion_contract
        fragment_invariant_parity
        hook_payload_contract
        match_abuse_cases
        orchestration_controller
        recon_dispatch_contract
        requirements_verification
        stage1_context_edge_inventory
        stride_outputs
    """),
    "agents/shared/ms-template.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        check_target_specificity
        requirements_verification
        stride_outputs
    """),
    "agents/shared/prose-samples.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        check_target_specificity
        requirements_verification
        stride_outputs
    """),
    "agents/shared/qa-ms-checks.md": _tests("""
        agent_definitions
        agent_doc_shell_snippets
        check_target_specificity
        requirements_verification
        stride_outputs
    """),
    "data/context-routing-bindings.json": _tests("""
        build_abuse_case_contexts
        build_architecture_analysis_context
        build_post_stride_contexts
        check_target_specificity
        context_routing
        orchestration_controller
        requirements_verification
    """),
    "data/context-routing-catalog.yaml": _tests("""
        check_target_specificity
        context_routing
        orchestration_controller
        requirements_verification
        weakness_class_config_consistency
    """),
    "data/required-permissions.yaml": _tests("""
        check_permissions
        check_permissions_coverage
        check_target_specificity
        context_routing
        orchestration_controller
        requirements_verification
        weakness_class_config_consistency
    """),
    "data/weakness-classes.yaml": _tests("""
        actor_attribution
        actor_presentation
        analysis_version_upgrade
        arch_coverage_bridge
        build_posture_verdict
        build_threat_model_yaml
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        crypto_path_xxe_checks
        detect_impl_strategy
        discover_identity_providers
        e2e_pipeline
        enforcement_mutations
        export_html
        export_pdf
        figure1_detail
        figure1_dfd
        merge_threats
        p1_renderer_correctness
        qa_checks_cov_band1
        qa_checks_cov_band3
        qa_checks_cov_band4
        reference_format
        render_completion_summary
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        security_score
        severity_policy
        source_auth_scanner
        team_questions
        threat_fixture
        weakness_class_config_consistency
        weakness_signals
    """),
    "docs/internal/contracts/cleanup-whitelist.md": _tests("""
        requirements_verification
        runtime_cleanup
    """),
    "schemas/fragments/verdict.schema.json": _tests("""
        analysis_version_upgrade
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        p1_renderer_correctness
        pregenerate_fragments
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        schema_integrity
        threat_fixture
        validate_fragment
        validate_ms_compactness
    """),
    "schemas/stride-analyst-context.schema.json": _tests("""
        agent_config_checks
        agent_logger_cov
        build_threat_model_yaml
        check_target_specificity
        orchestration_controller
        requirements_verification
        schemas
        team_questions
        validate_intermediate
    """),
    "scripts/_severity_rollup.py": _tests("""
        actor_presentation
        analysis_version_upgrade
        architect_structural_checks
        assert_completeness
        build_threat_model_yaml
        business_relevance
        check_target_specificity
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        discover_identity_providers
        e2e_pipeline
        emit_verdict_to_model
        enforcement_mutations
        export_html
        export_pdf
        figure1_detail
        figure1_dfd
        figure1_svg
        figure2_svg
        figure_details
        gate_preconditions
        p1_renderer_correctness
        p4_cross_reference_coverage
        pregenerate_fragments
        pregenerate_fragments_coverage
        qa_checks
        qa_checks_cov_band1
        reference_format
        render_completion_summary
        render_completion_summary_config
        render_completion_summary_verdict
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        review_threat_model
        run_path_guard
        runtime_doc_cli_contract
        severity_policy
        severity_rollup
        stride_outputs
        summarize_threat_model
        team_questions
        threat_fixture
        validate_fragment
        walkthrough_renderer
    """),
    "scripts/compose_threat_model.py": _tests("""
        actor_presentation
        analysis_version_upgrade
        build_threat_model_yaml
        check_fragment_registry
        check_target_specificity
        compose_depth_scoped_crossrefs
        compose_threat_model
        compose_threat_model_cov
        compose_threat_model_cov2
        compose_threat_model_cov3
        contract_integrity
        e2e_pipeline
        emit_verdict_to_model
        enforcement_mutations
        figure1_dfd
        figure1_layout_harness
        figure1_svg
        figure2_svg
        figure_details
        fragment_authoring_fidelity
        fragment_registry
        gate_preconditions
        manifest_readers
        p1_renderer_correctness
        p3_behavior_tuning
        p4_cross_reference_coverage
        qa_checks
        qa_checks_cov_band1
        qa_checks_cov_band2
        qa_checks_cov_band4
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_trace
        requirements_verification
        run_path_guard
        run_statistics_appendix
        run_tests
        runtime_doc_cli_contract
        safe_cond
        section_condition_wiring
        severity_rollup
        stride_outputs
        team_questions
        threat_fixture
    """),
    "scripts/runtime_cleanup.py": _tests("""
        check_target_specificity
        context_routing
        gate_preconditions
        report_plugin_issue
        requirements_verification
        run_path_guard
        runtime_cleanup
        runtime_doc_cli_contract
        skill_auto_retry
        stride_outputs
        threat_model_health
    """),
    "scripts/summarize_threat_model.py": _tests("""
        check_target_specificity
        gate_preconditions
        render_completion_summary
        render_completion_summary_config
        render_completion_summary_verdict
        requirements_verification
        review_threat_model
        run_path_guard
        runtime_doc_cli_contract
        stride_outputs
        summarize_threat_model
    """),
    "scripts/triage_compute_ranking.py": _tests("""
        actor_presentation
        build_threat_model_yaml
        check_target_specificity
        gate_preconditions
        incremental_two_run_e2e
        orchestration_controller
        requirements_verification
        run_path_guard
        severity_policy
        stride_outputs
        threat_fixture
        triage_compute_ranking
        triage_validate_ratings
    """),
    "scripts/validate_fragment.py": _tests("""
        actor_presentation
        build_threat_model_yaml
        build_trust_boundary_assessment_input
        check_fragment_registry
        check_target_specificity
        detect_open_registration
        discover_identity_providers
        embedded_store_access
        figure1_dfd
        figure1_security
        finalize_component_inventory
        flow_route_auth
        fragment_invariant_parity
        fragment_registry
        gate_preconditions
        incremental_two_run_e2e
        new_schemas
        orchestration_controller
        pregenerate_fragments
        prepare_trust_boundary_context
        recon_signals_schema
        reconcile_privileged_roles
        reconcile_role_access
        render_abuse_cases
        requirements_verification
        resolve_actors
        run_path_guard
        severity_policy
        stride_dispatch_waves
        stride_outputs
        threat_fixture
        validate_fragment
        validate_intermediate
        validate_ms_compactness
    """),
    "skills/create-threat-model/SKILL-full-runtime.md": _tests("""
        check_target_specificity
        context_prompt_budgets
        dispatch_values_stage
        integration
        lazy_phase_group_loading
        orchestration_controller
        qa_depth_profile
        reasoning_model_resolution
        requirements_resolution
        requirements_verification
        runtime_cleanup
        runtime_doc_cli_contract
    """),
    "skills/create-threat-model/SKILL-thin-stage1-v2.md": _tests("""
        agent_definitions
        check_target_specificity
        config_scanner_wireup
        context_prompt_budgets
        dispatch_prompt_cache_order
        integration
        orchestration_controller
        recon_dispatch_contract
        requirements_verification
        runtime_doc_cli_contract
        stride_serial_dispatch_detection
        thin_runtime_regressions_2026_07_20
        wait_agent_calls
    """),
    "skills/create-threat-model/SKILL.md": _tests("""
        check_target_specificity
        context_prompt_budgets
        help_file
        integration
        lazy_phase_group_loading
        package_internal_plugin
        reasoning_model_resolution
        requirements_verification
        runtime_cleanup
        runtime_doc_cli_contract
        skill_definitions
    """),
    "templates/fragments/mitigations.md.j2": _tests("""
        analysis_version_upgrade
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        p1_renderer_correctness
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        threat_fixture
    """),
    "templates/fragments/verdict.md.j2": _tests("""
        analysis_version_upgrade
        compose_threat_model
        compose_threat_model_cov2
        e2e_pipeline
        enforcement_mutations
        p1_renderer_correctness
        reference_format
        render_integrity
        render_properties
        requirements_mapping
        requirements_verification
        threat_fixture
    """),
    "tests/fixtures/e2e/golden/threat-model.md": _tests("""
        e2e_pipeline
        requirements_verification
    """),
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
    for path, tests in SOURCE_TESTS.items():
        if (
            not _safe_file(path, root)
            or not tests
            or len(tests) != len(set(tests))
            or any(test not in grouped or not _safe_file(test, root) for test in tests)
        ):
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
    """Return the exact pytest selectors for applicable requirement guards."""
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
            selected.update(binding.guards)
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
    selected: set[str] = set()
    inventoried = {path for tests in GROUPS.values() for path in tests}
    reasons = []
    fallbacks = []
    for path in paths:
        if not _safe_file(path, root):
            fallbacks.append(f"full suite: deleted, renamed, or unsafe path {path!r}")
            continue
        affected = SOURCE_TESTS.get(path)
        if affected is None and path.startswith("tests/"):
            if path in inventoried:
                selected.add(path)
                reasons.append(f"{path!r} -> changed test module")
                continue
        if not affected:
            fallbacks.append(f"full suite: no reviewed source/test route for {path!r}")
            continue
        selected.update(affected)
        reasons.append(f"{path!r} -> {len(affected)} reviewed test module(s)")
    if fallbacks:
        return Selection(("tests/",), tuple(fallbacks + reasons))
    guards = requirement_tests(paths, root) if paths else []
    added_guards = 0
    for guard in guards:
        test_path = guard.split("::", 1)[0]
        if test_path not in inventoried or not _safe_file(test_path, root):
            return Selection(("tests/",), (f"full suite: missing, unassigned, or unsafe requirement guard {guard!r}",))
        if test_path not in selected:
            selected.add(guard)
            added_guards += 1
    if guards:
        covered_guards = len(guards) - added_guards
        reasons.append(
            f"requirement guards: {added_guards} exact pytest selector(s) added; "
            f"{covered_guards} covered by selected modules"
        )
    if not paths:
        reasons.append("no changed paths; no tests selected")
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
    if not paths:
        return 0
    return subprocess.run([sys.executable, "-m", "pytest", *paths, *args.pytest_args], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
