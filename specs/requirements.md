# Plugin requirements

What the plugin must do. Not every rule the code follows — the short list
development may not deviate from.

Each requirement names the files it governs, where the rule is written, and the
test that fails when it breaks. A requirement without a test is advisory: it is
shown at the point of change and held by nothing.

## What this is

### REQ-PUR-001 — The model is derived from the repository and stays current

The threat model comes from code and configuration, not from a workshop.
Re-running a scan updates it instead of letting it drift away from the code.

**Applies to:** `skills/create-threat-model/**`, `agents/appsec-recon-scanner.md`
**Source:** `README.md` → Why appsec-advisor?
**Guard:** — (guard not located)

### REQ-PUR-002 — The subject is the design, not only the code

The analysis asks what an attacker could do to this system, not only where a
line of code is wrong: missing boundary controls, implicit trust between
services, unauthenticated internal paths, and design weaknesses with no
vulnerable line to point at. It sits next to code scanners rather than replacing
them, and the report is review input, never a release verdict.

**Applies to:** `agents/appsec-stride-analyzer-v2.md`, `docs/threat-modeler.md`
**Source:** `README.md` → Why this isn't a SAST tool, Threat Modeler
**Guard:** — (no guard written)

### REQ-PUR-003 — A developer team and an AppSec team can both run it

A team scanning its own repository gets the report in `docs/security/`. An
engineer scanning a repository they do not own points `--repo` and `--output`
where they need them, and the run behaves the same.

**Applies to:** `scripts/resolve_config.py`
**Source:** `AGENTS.md` → Sources and merge behavior
**Guard:** `test_repo_flag_resolves_path`, `test_repo_flag_honours_explicit_subdir_not_git_root`

## The finding model

### REQ-MOD-001 — A finding is one instance, backed by evidence

A finding says that something concrete is wrong in this repository, and points
at the place. Findings for the same mechanism stay separate unless a stated
reason merges them.

**Applies to:** `scripts/merge_threats.py`, `scripts/validate_intermediate.py`
**Source:** `AGENTS.md`, decisions `WK-6`, `FE-1`
**Guard:** `test_known_vuln_becomes_vulnerability_management_weakness`

### REQ-MOD-002 — A weakness is the class above the findings

A weakness names the pattern that the findings are instances of. It may exist
in the design rather than in a line of code, and then it carries no CVSS —
severity comes from the design risk, not from a score.

**Applies to:** `scripts/detect_impl_strategy.py`, `data/weakness-classes.yaml`
**Source:** decisions `WK-1`, `WK-2`, `WK-4`
**Guard:** `test_schema_enums_match_cluster_ids`, `test_vetted_lib_no_bespoke_is_standard_vetted`,
`test_bespoke_no_lib_is_home_grown`

### REQ-MOD-003 — A trust boundary is an assumption that can fail

A boundary is the one place a crossing is controlled, and whether its assumption
still holds decides how exposed everything behind it is. A finding refutes the
assumption; if findings sit in the protected components but none examines the
crossing, the boundary is unconfirmed, and it is never shown as intact merely
because evidence is absent.

**Applies to:** `scripts/prepare_trust_boundary_context.py`, `data/cwe-boundary-legs.yaml`,
`scripts/build_trust_boundary_assessment_input.py`, `scripts/_boundary_adjacency.py`
**Source:** decisions `TB-1`, `TB-3`, `TB-4`, `TB-5`
**Guard:** `test_context_carries_the_assumption_legs_to_the_analyzer`,
`test_boundary_assumption_state_refuted_requires_clean_evidence_check`

### REQ-MOD-006 — The boundary catalogue is derived, and a declaration only clarifies it

Crossings come from the repository's code and configuration, one row per
enforcement point. A team may declare a crossing the code does not show, but a
declaration never suppresses a detected one and never asserts that its control
works.

**Applies to:** `scripts/prepare_trust_boundary_context.py`, `schemas/trust-boundaries-repo.schema.yaml`
**Source:** `docs/threat-modeler.md` → Trust-boundary declarations, decisions `TB-1`, `TB-8`
**Guard:** `test_repository_declaration_is_additive_and_cannot_self_confirm`,
`test_partial_leg_declaration_adds_a_condition_but_never_removes_a_leg`

### REQ-MOD-004 — An abuse case is a hypothesis until a probe confirms it

An abuse case says how someone would misuse the system and what they gain, so
the report can be read from the attacker's goal rather than only from the code.
One becomes a finding only when a probe confirms it in the code, and then it is
an ordinary finding, not a category of its own.

**Applies to:** `scripts/promote_verified_abuse_cases.py`, `data/abuse-cases/**`,
`scripts/match_abuse_cases.py`, `scripts/verify_abuse_cases.py`, `scripts/abuse_case_gate.py`
**Source:** decisions `AC-1`, `AC-2`, `AC-3`
**Guard:** `test_unconfirmed_or_unclassified_probe_is_never_promoted`,
`test_confirmed_source_probe_becomes_normal_bound_finding`,
`test_promotion_is_idempotent_when_next_scan_rediscovers_same_source_probe`

### REQ-MOD-007 — Abuse cases come from a library the operator controls

Cases come from the plugin's standard library, an organization's additions, the
repository's own cases, and a per-run selection, and each source can be turned
off. A case decides what is checked; it never decides how the run behaves.

**Applies to:** `scripts/resolve_abuse_cases.py`, `data/abuse-cases/**`,
`schemas/abuse-cases.schema.yaml`
**Source:** `docs/org-profiles.md` → Abuse cases, principle `P-4`
**Guard:** `test_library_loads_mandatory_cases`, `test_repo_local_honours_disable`,
`test_explicit_case_file_cannot_escape_repo`

### REQ-MOD-005 — Findings require evidence from the target repository

A finding is supported by the scanned repository's source, configuration, git
history, or target-owned declarations. Context the repository points at — an
upstream threat model, a linked design document — may raise a possible threat,
which the report carries as requiring validation and never scores; only target
evidence turns it into a finding. A walkthrough, solution guide, or bundled
vulnerability write-up never seeds a finding.

**Applies to:** `scripts/merge_threats.py`, `agents/appsec-stride-analyzer-v2.md`,
`schemas/related-repos.schema.yaml`, `scripts/slice_cross_repo_for_component.py`
**Source:** `AGENTS.md`, decision `FE-4`
**Guard:** `test_cross_repo_mismatch_requires_target_evidence`

### REQ-MOD-008 — Reference documentation the operator supplies is analyzed and cited

A design specification, roadmap, or architecture document handed to the run is
analyzed like any other declared input, and a weakness it reveals is reported
with that document cited as its source. It stays data: a claim it makes about a
control is not proof the control exists.

**Applies to:** `scripts/load_business_context.py`, `scripts/build_threat_modeling_context.py`
**Source:** operator request
**Guard:** `test_supplied_reference_document_is_admitted_as_fenced_and_named_data`

## Security architecture

### REQ-ARC-001 — The architecture verdict rates what exists and says so when there is nothing

Each control domain is rated from what the pipeline actually invokes, not from a
tool name in a config file. A system with no such surface is marked not
applicable rather than rated badly, and a wrong check stays distinguishable from
a missing one.

**Applies to:** `data/architecture-coverage-rules.yaml`, `data/architectural-controls.yaml`,
`scripts/normalize_security_architecture.py`, `scripts/architecture_coverage_checks.py`
**Source:** decisions `SA-1`, `SA-2`, `SA-3`, `FE-2`
**Guard:** `test_cookie_no_signal_is_not_applicable`, `test_empty_repo_all_rules_not_applicable`,
`test_normalizer_makes_all_three_gates_pass`

## Who does what

### REQ-ROL-001 — Agents analyze, Python decides

Agents read the repository, judge security meaning, and write prose. Everything
that can be wrong in a checkable way — artifact shape, validation, rendering,
exports, gates — belongs to Python. Dispatch belongs to the controller. Only the
two repair roles receive the `Edit` tool; producer roles may create only their
assigned contracted artifacts.

**Applies to:** `scripts/orchestration_controller.py`, `agents/**`
**Source:** `README.md` → Project structure, principle `P-2`, decisions `OR-1`, `OR-2`
**Guard:** `test_single_runtime_forbids_recursive_agents_and_pins_edit_owners`

### REQ-ROL-002 — What can be derived is not written by a model

A value a computation can produce is computed, in one place. A model is asked
only where judgement is needed, and a deterministic emitter takes a category
whenever it can own it.

**Applies to:** `scripts/compose_threat_model.py`, `scripts/auto_emitter_pass.sh`
**Source:** principles `P-3`, `P-6`, decision `TB-2`
**Guard:** `test_emitter_sequence_preserved_in_order`

### REQ-ROL-003 — Review and QA fix the report, never the findings

The architect review reads the report and may demand repairs; it does not
rewrite it. QA normalizes only where a contract gives it that job — anything
else is fixed at the producer. A repair may not weaken the gate it had to pass.

**Applies to:** `scripts/qa_checks.py`, `scripts/apply_prose_fixes.py`,
`agents/appsec-architect-reviewer.md`, `agents/appsec-qa-reviewer.md`
**Source:** `AGENTS.md` → Validation and repair, decisions `RN-1`, `RN-2`
**Guard:** `test_apply_fixes_is_idempotent_for_core_rewrites`, `test_autofix_is_idempotent_on_paths`

## How a run flows

### REQ-FLW-001 — STRIDE runs in parallel, per component

Components are analyzed side by side. A run that dispatches them one after
another is a defect, not a slower variant, and is reported as one.

**Applies to:** `scripts/check_stride_dispatch.py`, `agents/phases/phase-group-threats.md`
**Source:** `AGENTS.md` → Orchestration, decision `OR-5`
**Guard:** `test_real_serial_wave_is_detected`, `test_real_parallel_wave_is_not_flagged`

### REQ-FLW-002 — Every component is checked against all six STRIDE categories

A component that is analyzed is analyzed against all six categories, at every
depth and in every mode. Cheaper tiers change how much time a component gets,
never how many categories it sees.

**Applies to:** `scripts/build_stride_dispatch_manifest.py`, `scripts/check_stride_dispatch.py`
**Source:** `AGENTS.md` → Model and depth configuration, decision `DT-1`
**Guard:** `test_profile_does_not_skip_stride_categories`

### REQ-FLW-003 — A stage refuses to build on something it cannot check

Every required artifact handed from one stage to the next has a defined shape
and is validated on arrival. A missing or malformed required input stops the
stage. Optional enrichments may degrade only where their contract states the
fail-open behavior explicitly.

**Applies to:** `scripts/orchestration_controller.py`, `scripts/validate_intermediate.py`, `schemas/**`
**Source:** `AGENTS.md` → Fix the source, not the symptom, decisions `OR-3`, `RA-1`
**Guard:** `test_post_stage1_fails_closed_on_missing_artifact`

### REQ-FLW-004 — Producer retries are bounded by their contract

An invalid LLM-written recon-signals artifact is dispatched once more with the
validator errors, then fails terminally. STRIDE uses its separate persisted
two-attempt component budget. Other producers follow their documented boundary
behavior, and an invalid deterministic artifact is never retried.

**Applies to:** `scripts/orchestration_controller.py`
**Source:** `docs/internal/contracts/orchestration-actions.md`, decision `OR-12`
**Guard:** `test_a_rejected_artifact_is_redispatched_with_its_errors`, `test_the_second_failure_aborts`

## Depth and rescans

### REQ-DEP-001 — Cheap STRIDE decides pace, and decides it in one place

Which components get the screened tier is decided in one function, from
exposure and role. A component whose exposure is unknown gets full depth rather
than the cheap tier.

**Applies to:** `scripts/build_stride_dispatch_manifest.py`
**Source:** `AGENTS.md` → Model and depth configuration, decisions `DT-2`, `DT-3`
**Guard:** `test_builder_cheap_stride_spares_auth_and_core_backend`,
`test_builder_cheap_stride_never_screens_exposure_unknown`

### REQ-INC-001 — A rescan reuses only what it can prove is unchanged

Reuse needs a fingerprint match against an unchanged tree; a cache is validated,
never assumed fresh. A deeper rescan starts over instead of extending a
shallower model, and a shallower rescan may not drop what the deeper run found.

**Applies to:** `scripts/check_state.py`, `scripts/resolve_config.py`
**Source:** decisions `IN-1`, `DP-1`, `DP-2`
**Guard:** `test_check_fingerprint_matches_unchanged_repo`,
`test_depth_increase_quick_to_standard_forces_full`, `test_shallower_depth_stays_incremental`

### REQ-INC-002 — A finding lifecycle is never silently discarded

A shallower rescan carries forward a prior finding it cannot reverify. At equal
or deeper depth, a non-reproduced finding is recorded as resolved with its prior
identity and reason, so it never disappears without an audit trail.

**Applies to:** `scripts/build_threat_model_yaml.py`, `scripts/runtime_cleanup.py`
**Source:** decision `IN-2`
**Guard:** `test_reconcile_carries_dropped_prior_threat_at_shallower_depth`,
`test_reconcile_no_carry_at_equal_depth`

## Context

### REQ-CTX-001 — Nothing reaches an agent implicitly

Every piece of context an agent receives is assigned to it on purpose, or
declared forbidden. Context declared forbidden for a focused agent does not
reach it through a shared route, and an assignment never widens the scope the
agent was given.

**Applies to:** `scripts/context_routing.py`, `data/context-routing/**`
**Source:** `docs/internal/contracts/context-routing.md`, decisions `CR-2`, `CR-3`, `CR-5`
**Guard:** `test_every_context_has_a_visible_assignment_or_explicit_forbidden_policy`,
`test_forbidden_shared_context_cannot_enter_focused_agent_inputs`,
`test_semantics_reject_target_that_broadens_component_or_candidate_context`

### REQ-CTX-002 — A prompt that is too long gets shorter

Every prompt surface has a byte budget. Exceeding it is fixed by cutting the
prompt, never by raising the budget.

**Applies to:** `data/context-budgets.yaml`, `skills/create-threat-model/**`
**Source:** `AGENTS.md` → Orchestration and context, decision `CE-1`
**Guard:** `test_each_live_prompt_surface_stays_within_budget`

### REQ-CTX-003 — Prompts are built so the stable part can be cached

Phase groups are loaded when they are reached, never inlined ahead of time.
Dispatch prompts run from stable to component-specific to volatile, so the
provider can cache the part that does not change.

**Applies to:** `agents/phases/phase-group-threats.md`, `skills/create-threat-model/SKILL-impl.md`
**Source:** `AGENTS.md` → Prompt caching contract, decisions `CE-4`, `CE-5`
**Guard:** `test_groups_are_in_order_a_b_c`, `test_group_c_uses_paths_not_inline_json_contract`,
`test_phase_boundary_has_lazy_load_instruction`

## Requirements-based analysis

### REQ-REQ-001 — Only a linked finding reaches the requirements mapping

The mapping keys off the configured catalog, never off a requirement-ID prefix.
A threat with no link to a requirement stays out of it, and without a catalog no
remediation reference is invented.

**Applies to:** `scripts/compose_threat_model.py`, `schemas/requirements-catalog.schema.yaml`
**Source:** `docs/internal/contracts/schema-invariants.md`, decisions `RQ-1`, `RQ-3`, `RQ-4`
**Guard:** `test_mapping_is_prefix_agnostic_for_requirement_ids`,
`test_legacy_requirement_id_is_honoured_and_unlinked_threats_excluded`,
`test_remediation_reference_ignored_without_requirements_yaml`

## Business context

### REQ-BIZ-001 — What the repository declares is checked, then read as data

Known threats, requirements, and related repositories that the target declares
are schema-validated before they enter the analysis, and they enter fenced: the
analysis reads them, it does not follow them.

**Applies to:** `scripts/build_threat_modeling_context.py`, `schemas/known-threats.schema.yaml`
**Source:** principle `P-4`, decisions `RC-1`, `RC-2`
**Guard:** `test_rejects_invalid_known_threats_before_context_publication`,
`test_preserves_schema_valid_known_threats_as_fenced_input`

### REQ-BIZ-002 — Actors carry the business view, and only the repository persists them

Actors and abuse cases say who would attack the system and what they gain, and
they steer which findings matter. An actor turned off in conversation is not
written back — only the target's own `.appsec/actors.yaml` persists that.

**Applies to:** `scripts/resolve_actors.py`, `data/actors/**`
**Source:** `docs/threat-modeler.md` → actor layer, decision `RC-3`
**Guard:** `test_resolver_never_writes_actor_choices_back_to_repo`

### REQ-BIZ-003 — Business context says what is worth protecting

A repository may state purpose, sensitive assets, compromise impact, and
obligations in `docs/business-context.md`, or supply the same for a single run,
and the analysis weights findings with it instead of rating every component
alike. It is read as data, never followed, and it neither suppresses a finding
the repository supports nor creates one on its own. A run names the context
file it read, and refuses a supplied source it cannot apply.

**Applies to:** `scripts/load_business_context.py`, `scripts/build_threat_modeling_context.py`,
`scripts/resolve_config.py`, `scripts/build_threat_model_yaml.py`,
`scripts/build_stride_dispatch_manifest.py`, `scripts/triage_validate_ratings.py`,
`agents/appsec-control-analyst.md`, `schemas/stride-component-business-context.schema.json`
**Source:** `docs/threat-modeler.md` → Business context, principle `P-4`, decision `RC-1`
**Guard:** `test_external_context_is_policy_validated_and_fenced`,
`test_run_only_business_context_replaces_the_repository_file`,
`test_header_names_the_business_context_file_that_was_read`,
`test_context_is_refused_when_the_producer_cannot_read_it`,
`test_a_gone_run_only_source_is_not_reported_as_an_edit`,
`test_build_meta_records_which_file_the_context_digest_came_from`,
`test_declared_business_assets_make_a_component_crown_jewel`,
`test_step5b_flags_low_impact_where_context_declares_assets`

## What a run may cost

### REQ-CST-001 — Model routing has one owner per runtime layer

The session model controls the orchestrator and remains the primary cost lever.
The pipeline centrally routes subagents and may apply explicit stage overrides;
an agent never selects its own model, and an economy mode never moves the STRIDE
pass onto something weaker than Sonnet.

**Applies to:** `scripts/resolve_config.py`, `agents/appsec-*.md`
**Source:** `docs/model-selection.md`, decisions `MD-3`, `MD-4`
**Guard:** `test_haiku_economy_keeps_stride_on_sonnet`

### REQ-CST-002 — A turn ceiling paces work, it never caps coverage

Ceilings are computed per component when it is dispatched. Hitting one is
visible: a lift or a dropped overflow is reported as a run issue rather than
absorbed quietly.

**Applies to:** `scripts/build_stride_dispatch_manifest.py`, `scripts/aggregate_run_issues.py`
**Source:** `AGENTS.md` → Model and depth configuration, decisions `DT-5`, `DT-6`
**Guard:** `test_stride_ceiling_lift_is_surfaced`, `test_stride_ceiling_overflow_dropped_is_surfaced`

## The report

### REQ-RPT-001 — Severity is earned, not asserted

A rating follows the evidence and the caps. Nothing is raised to draw attention
to it, and a finding without evidence for a score does not get one.

**Applies to:** `data/severity-caps.yaml`, `data/critical-criteria.yaml`,
`scripts/validate_intermediate.py`, `scripts/emit_severity_rationale.py`,
`scripts/_severity_rollup.py`
**Source:** `AGENTS.md` → Protect trust and compatibility, decision `FE-1`
**Guard:** `test_cvss_forbidden`, `test_missing_cvss_for_required_source`,
`test_stride_eligible_cwe_with_line_passes`

### REQ-RPT-002 — Finding numbers survive a rescan

A finding that is still there after an incremental rescan keeps its number, so
links into an earlier report still work. Mitigation IDs may be renumbered,
weakness IDs follow display order. `--rebuild` deliberately clears the
stable-ID anchor and may assign finding numbers again.

**Applies to:** `scripts/merge_threats.py`, `scripts/build_threat_model_yaml.py`
**Source:** `AGENTS.md` → Protect trust and compatibility, decision `RA-3`
**Guard:** — (guard not located)

### REQ-RPT-003 — The report reads like an engineer wrote it

Prose is specific, falsifiable, and short. References follow one fixed format
per context, and a locator that does not exist is never invented to fill a gap.

**Applies to:** `agents/shared/prose-style.md`, `scripts/qa_checks.py`
**Source:** `AGENTS.md` → Keep the repository maintainable, decision `RA-4`
**Guard:** `test_strip_trailing_locator_all_forms`, `test_linkify_full_form_basename_and_backticked`

### REQ-RPT-004 — The report is addressed to the developer who has to fix it

The reader is the engineer who owns the code, so a finding names where it is,
why the attack works, and what to change, in the repository's own vocabulary
rather than a framework's. A sentence a developer cannot act on is not a
finding.

**Applies to:** `agents/shared/prose-style.md`, `agents/shared/prose-samples.md`
**Source:** `agents/shared/prose-style.md`, `AGENTS.md` → Keep the repository maintainable
**Guard:** `test_prose_style_file_exists`, `test_prose_authoring_files_reference_anchor`

### REQ-RPT-005 — A fix is prioritized, concrete, and checkable

Every finding carries a mitigation with a priority, and an urgent fix states its
steps and how to verify it. A code example is anchored to a real source
location, never invented to look concrete.

**Applies to:** `scripts/validate_mitigation_quality.py`, `scripts/emit_finding_fix_mitigations.py`,
`scripts/hydrate_mitigation_details.py`
**Source:** `docs/threat-modeler.md` → What you get, decision `RQ-5`
**Guard:** `test_urgent_fix_requires_steps_and_verification`,
`test_urgent_code_example_needs_a_source_location`,
`test_remediation_string_fallback_and_priority_rules`

## After the run

### REQ-USE-001 — The model is worked, not filed

After a run the model can be asked questions and triaged finding by finding,
with decisions kept next to the model instead of in a chat. Ranking follows
mitigation priority, and a stale decision is shown as stale rather than silently
applied.

**Applies to:** `skills/ask-threat-model/**`, `skills/review-threat-model/**`,
`scripts/query_threat_model.py`, `scripts/review_threat_model.py`
**Source:** `docs/threat-modeler.md` → Threat model lifecycle
**Guard:** `test_display_id_maps_t_to_f`, `test_reconcile_ranks_and_marks_untriaged`,
`test_reconcile_merges_sidecar_decisions`, `test_reconcile_flags_stale_entries`

## Trust

### REQ-TRU-001 — A scanned repository cannot steer the run

Repositories are untrusted unless the operator says otherwise. Before Claude
starts, a run rejects Claude Code hooks, settings, and memory files the
repository brings along, and symlinks that point out of it. Such a finding ends
the run; it is never softened into a warning.

**Applies to:** `scripts/preflight_untrusted.py`, `scripts/_path_guard.py`, `scripts/_url_guard.py`
**Source:** `README.md` → Security notes, decisions `TR-1`, `TR-2`, `TR-3`
**Guard:** `test_repo_owned_claude_settings_flagged`, `test_repo_root_claude_memory_is_flagged`,
`test_escaping_symlink_flagged`, `test_preflight_abort_names_the_trust_mode_escape_hatch`

### REQ-TRU-002 — A leaked secret stops the run

If a run artifact contains an unmasked secret, the run fails instead of
publishing.

**Applies to:** `scripts/postscan_secret_check.py`, `scripts/secret_scan.py`,
`scripts/redact_known_secrets.py`
**Source:** `README.md` → Output safety, decision `TR-8`
**Guard:** `test_run_uses_real_secret_scan_for_clean_masked_and_leaky_artifacts`,
`test_main_text_output_reports_hits_and_returns_2`

## Configuration

### REQ-CFG-001 — An organization configures the plugin, it does not fork it

Presets, branding, baseline, requirements, added skills, hooks, and MCP servers
come from the org profile and the package policy. Agents stay core-owned,
`create-threat-model` cannot be removed from a build, and every build records
what it kept and what it dropped.

**Applies to:** `schemas/org-profile.schema.yaml`, `scripts/package_internal_plugin.py`
**Source:** `AGENTS.md` → What an organization can package, decisions `EX-1`, `EX-2`, `EX-3`, `EX-4`
**Guard:** `test_valid_org_profile_fixture_passes`, `test_policy_surface_explicit_block`,
`test_the_package_policy_can_exclude_an_added_skill`, `test_blocks_a_disabled_skill_invoked_by_claude`

### REQ-CFG-002 — A repository configures its own analysis in declared files

Actors, abuse cases, trust boundaries, business context, known threats, and a
requirements catalog are configured in the target repository's own files, each
against its schema. None of them suppresses a finding the repository's evidence
supports.

**Applies to:** `scripts/resolve_actors.py`, `scripts/resolve_abuse_cases.py`,
`scripts/build_threat_modeling_context.py`, `schemas/known-threats.schema.yaml`
**Source:** `docs/threat-modeler.md` → Repo-local context, decisions `RC-1`, `RC-3`
**Guard:** `test_resolver_never_writes_actor_choices_back_to_repo`,
`test_rejects_invalid_known_threats_before_context_publication`

## How the plugin changes

### REQ-EVO-001 — The catalog binds a change before the code does

Work that would contradict a requirement changes the requirement first, and only
the operator approves that change; until then the sentence that is written
holds. The requirements governing a file are put in front of whoever edits it,
at the moment of the edit.

**Applies to:** `specs/requirements.md`, `scripts/check_specs.py`, `scripts/requirements_hook.py`
**Source:** `specs/README.md` → Who writes what, What is enforced
**Guard:** `test_held_files_require_user_approval`, `test_governed_file_carries_its_requirements`,
`test_project_settings_wire_every_write_surface_to_the_hook`

### REQ-EVO-002 — New behavior works for any repository and declares what it touches

Behavior added to the pipeline works for arbitrary repositories; a name that
exists only in a test target stays in fixtures and tests. A new command, shell
prefix, or read and write target is declared in the permission catalog before it
runs.

**Applies to:** `data/test-target-vocabulary.yaml`, `data/required-permissions.yaml`
**Source:** `AGENTS.md` → Protect trust and compatibility, decisions `TA-1`, `TA-2`
**Guard:** `test_name_in_python_string_literal_is_reported`, `test_name_in_help_text_is_reported`

### REQ-EVO-003 — A contract someone else consumes changes only with a migration

Report anchors, exported artifacts, and the org-profile API are read outside
this repository, so their shape changes through a declared version and a
migration rather than in place. A migration never turns an absence into a
positive claim.

**Applies to:** `schemas/threat-model.output.schema.yaml`, `schemas/org-profile.schema.yaml`
**Source:** `AGENTS.md` → Protect trust and compatibility, decisions `RA-3`, `TB-7`, `EX-1`
**Guard:** `test_normalize_migrates_legacy_without_promoting_absence`,
`test_analysis_v5_declares_prior_read_compatibility`,
`test_main_invalid_analysis_compatibility_fails`
