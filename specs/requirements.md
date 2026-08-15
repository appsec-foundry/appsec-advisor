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

### REQ-PUR-002 — The subject is the architecture, and the report is review input

The analysis looks at what sits between components: missing boundary controls,
implicit trust between services, unauthenticated internal paths. It sits next to
code scanners rather than replacing them, and the report is a starting point for
review, never a release verdict.

**Applies to:** `agents/appsec-stride-analyzer.md`, `docs/threat-modeler.md`
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

A boundary states an assumption the system relies on, and a finding refutes it.
A boundary nobody examined is reported as not examined. It is never shown as
intact because nothing was found.

**Applies to:** `scripts/prepare_trust_boundary_context.py`, `data/cwe-boundary-legs.yaml`
**Source:** decisions `TB-1`, `TB-3`, `TB-4`, `TB-5`
**Guard:** `test_context_carries_the_assumption_legs_to_the_analyzer`,
`test_boundary_assumption_state_refuted_requires_clean_evidence_check`

### REQ-MOD-004 — An abuse case is a hypothesis until a probe confirms it

Abuse cases describe how someone would misuse the system. One becomes a finding
only when a probe confirms it in the code, and then it is an ordinary finding,
not a category of its own.

**Applies to:** `scripts/promote_verified_abuse_cases.py`, `data/abuse-cases/**`
**Source:** decisions `AC-1`, `AC-2`, `AC-3`
**Guard:** `test_unconfirmed_or_unclassified_probe_is_never_promoted`,
`test_confirmed_source_probe_becomes_normal_bound_finding`,
`test_promotion_is_idempotent_when_next_scan_rediscovers_same_source_probe`

### REQ-MOD-005 — Findings come from the target's own code

A finding comes from the scanned repository's source, configuration, and git
history. Never from a walkthrough, a solution guide, or a vulnerability
write-up that happens to lie in the repository.

**Applies to:** `scripts/merge_threats.py`, `agents/appsec-stride-analyzer.md`
**Source:** `AGENTS.md`, decision `FE-4`
**Guard:** — (no guard written)

## Who does what

### REQ-ROL-001 — Agents analyze, Python decides

Agents read the repository, judge security meaning, and write prose. Everything
that can be wrong in a checkable way — artifact shape, validation, rendering,
exports, gates — belongs to Python. Dispatch belongs to the controller, and only
the two repair roles may edit files.

**Applies to:** `scripts/orchestration_controller.py`, `agents/**`
**Source:** `README.md` → Project structure, principle `P-2`, decisions `OR-1`, `OR-2`
**Guard:** `test_generation_coexistence_pins_recursive_and_edit_tool_owners`

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
**Source:** `AGENTS.md` → Validation and repair, decisions `RN-1`, `RN-2`, `RN-3`
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
**Guard:** — (guard not located)

### REQ-FLW-003 — A stage refuses to build on something it cannot check

Everything handed from one stage to the next has a defined shape and is
validated on arrival. A missing or malformed input stops the stage; it is never
worked around.

**Applies to:** `scripts/orchestration_controller.py`, `scripts/validate_intermediate.py`, `schemas/**`
**Source:** `AGENTS.md` → Fix the source, not the symptom, decisions `OR-3`, `RA-1`
**Guard:** `test_post_stage1_fails_closed_on_missing_artifact`

### REQ-FLW-004 — A bad artifact costs one retry, not a loop

An LLM-written artifact that fails its contract is dispatched once more with the
validator errors. A second identical failure, or a failure from a deterministic
producer, ends the stage.

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

### REQ-INC-002 — A finding that is gone goes dormant, not away

A finding that is no longer reachable is marked dormant. Deleting it would lose
its number and its history.

**Applies to:** `scripts/merge_threats.py`
**Source:** decision `IN-2`
**Guard:** — (no guard written)

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
**Source:** `AGENTS.md` → Orchestration and context, decisions `CE-1`, `CE-6`
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
**Guard:** — (guard not located)

## What a run may cost

### REQ-CST-001 — The session model is the cost lever

Cost is steered by the model the session runs on, not by pins inside the
pipeline. No agent chooses its own model, and an economy mode never moves the
STRIDE pass onto something weaker than Sonnet.

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
`scripts/validate_intermediate.py`
**Source:** `AGENTS.md` → Protect trust and compatibility, decision `FE-1`
**Guard:** `test_cvss_forbidden`, `test_missing_cvss_for_required_source`,
`test_stride_eligible_cwe_with_line_passes`

### REQ-RPT-002 — Finding numbers survive a rescan

A finding that is still there after a rescan keeps its number, so links into an
earlier report still work. Mitigation IDs may be renumbered, weakness IDs follow
display order.

**Applies to:** `scripts/merge_threats.py`, `scripts/build_threat_model_yaml.py`
**Source:** `AGENTS.md` → Protect trust and compatibility, decision `RA-3`
**Guard:** — (guard not located)

### REQ-RPT-003 — The report reads like an engineer wrote it

Prose is specific, falsifiable, and short. References follow one fixed format
per context, and a locator that does not exist is never invented to fill a gap.

**Applies to:** `agents/shared/prose-style.md`, `scripts/qa_checks.py`
**Source:** `AGENTS.md` → Keep the repository maintainable, decision `RA-4`
**Guard:** `test_strip_trailing_locator_all_forms`, `test_linkify_full_form_basename_and_backticked`

## Trust

### REQ-TRU-001 — A scanned repository cannot steer the run

Repositories are untrusted unless the operator says otherwise. Before Claude
starts, a run rejects Claude Code hooks, settings, and memory files the
repository brings along, and symlinks that point out of it. Such a finding ends
the run; it is never softened into a warning.

**Applies to:** `scripts/preflight_untrusted.py`
**Source:** `README.md` → Security notes, decisions `TR-1`, `TR-2`, `TR-3`
**Guard:** `test_repo_owned_claude_settings_flagged`, `test_repo_root_claude_memory_is_flagged`,
`test_escaping_symlink_flagged`, `test_preflight_abort_names_the_trust_mode_escape_hatch`

### REQ-TRU-002 — A leaked secret stops the run

If a run artifact contains an unmasked secret, the run fails instead of
publishing.

**Applies to:** `scripts/postscan_secret_check.py`, `scripts/secret_scan.py`
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
