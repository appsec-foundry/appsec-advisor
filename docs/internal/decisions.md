# Decision register

Standing decisions and what enforces each one. Values, limits and vocabularies stay in
their own files — this names the decision, points at its guard, and links the reasoning.

**Changing a decision:** ask the operator first. Loosening an entry, widening a guard or
raising a pinned value is not a judgement call you make on your own, and it is a change to
this file before it is a change to the code. If a guard fails and the fix looks like editing
the guard, you are changing a decision — stop and ask.

**Finding the entry you need:** grep this file for the file, constant or test you are about
to touch — each row names them. One row is one decision and carries everything about it.

- **Guard** — the test that fails when the decision is broken. `— (guard not located)`
  means one may exist and was not found; `— (no guard written)` means none exists.
- **Rationale** — where the reasoning lives. A dated document under
  `docs/internal/analysis/` explains how the decision was reached; it does not govern. This
  register does. Prefer an `analysis-`, `design-` or `proposal-` document over an
  `implplan-`: a plan describes a sequence of work packages and stops matching the code
  once they land. Link a plan only where the reasoning exists nowhere else, and move that
  reasoning somewhere durable when the plan closes.
- A decision that only holds while both runtime generations ship is marked
  *(generation-scoped)* with the work package that must revisit it.

**Retired IDs:** `DT-4`, `RN-3`. A retired number is never reused, because a guard,
commit or requirement may still cite it and would then point at a different decision.
Removing an entry means listing it here in the same change.

## Context routing

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| CR-1 | The catalog holds human decisions only; runtime paths, schemas, projectors and limits live in plugin-owned bindings | `test_human_catalog_contains_only_human_decisions`, `test_runtime_parameters_are_isolated_in_plugin_owned_bindings` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |
| CR-2 | Every context has a visible assignment or an explicit forbidden policy — nothing is delivered implicitly | `test_every_context_has_a_visible_assignment_or_explicit_forbidden_policy` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |
| CR-3 | Forbidden shared context never reaches a focused agent's inputs | `test_forbidden_shared_context_cannot_enter_focused_agent_inputs` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |
| CR-4 | The context dependency graph is acyclic | `test_semantics_reject_invalid_importance_and_dependency_cycle` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |
| CR-5 | An assignment may not broaden component or candidate scope | `test_semantics_reject_target_that_broadens_component_or_candidate_context` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |
| CR-6 | Declared paths cannot escape the plugin root or the output root, symlinks included | `test_semantics_reject_plugin_symlink_escape`, `test_shadow_plan_rejects_output_symlink_escape` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |
| CR-7 | Projections are size-limited and the plan itself is capped | `test_shadow_plan_enforces_internal_size_limit` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |

## Shared state

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| ST-1 | Every artifact crossing a boundary carries a versioned receipt whose hash is verified before dispatch, in `verify_receipt_hashes` | `test_exact_byte_plan_receipt_detects_mutation` | `docs/internal/analysis/implplan-threat-analysis-context-and-turn-reduction-2026-08-05.md`, Contract A |
| ST-2 | A stale receipt is refused, never repaired | `test_shadow_plan_rejects_stale_action_receipt` | `docs/internal/analysis/implplan-threat-analysis-context-and-turn-reduction-2026-08-05.md`, Contract A |
| ST-3 | Every new run uses the context-v2 artifact generation; a missing or pre-cutover generation is refused rather than migrated or resumed | `test_runtime_generation_has_no_legacy_selection`, `test_context_v2_action_refuses_a_run_without_a_persisted_generation` | `docs/internal/analysis/analysis-repository-legacy-and-pipeline-ballast-2026-08-19.md` |
| ST-4 | An authoritative abort blocks further producer dispatch for that run; recovery starts a fresh full or rebuild invocation | `test_after_an_abort_only_a_producer_dispatch_is_denied` | `CHANGELOG.md` (context-v2) |

## Orchestration

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| OR-1 | Level-0 dispatch belongs to the deterministic controller acting through compact runtimes; no agent may recurse through `Agent`, pinned by `AGENT_TOOL_OWNERS` | `tests/test_agent_definitions.py` | `docs/internal/analysis/analysis-repository-legacy-and-pipeline-ballast-2026-08-19.md` |
| OR-2 | `Edit` stays limited to the two repair roles, pinned by `EDIT_TOOL_OWNERS` | `tests/test_agent_definitions.py` | comment at the constant |
| OR-3 | A stage refuses to proceed on a missing required upstream artifact; optional enrichment degrades only where its contract names the fail-open behavior | `test_post_stage1_fails_closed_on_missing_artifact` | `docs/internal/contracts/orchestration-actions.md` |
| OR-4 | Rebuild archives before it clears, and fails closed if archiving fails | `test_rebuild_archive_failure_aborts_before_deletion` | `docs/internal/contracts/audit-artifacts.md` |
| OR-5 | Serial STRIDE dispatch is detected and reported as a defect; parallel is the intended shape | `tests/test_stride_serial_dispatch_detection.py` *(guards the detector, not the prohibition)* | `scripts/check_stride_dispatch.py` |
| OR-6 | Only the call-scoped hook lifecycle terminalizes a call; a semantic event such as `SCAN_END` publishes output and is never presented as an outcome | `test_postfix6_recon_sequence_renders_one_start_and_one_terminal_outcome` | `agents/shared/logging-standard.md` |
| OR-7 | Call telemetry stays observational: a disagreement between accepted output, lifecycle, budget, and stage stats is reported, and blocks only under `APPSEC_TELEMETRY_STRICT` | `test_boundary_reports_by_default_and_aborts_only_under_strict` | `docs/internal/contracts/orchestration-actions.md` |
| OR-8 | Every non-clean exit converges on one terminal state through a single terminator, which releases only a lock its own run holds | `test_interrupt_converges_every_terminal_surface`, `test_a_live_foreign_lock_is_left_alone` | `docs/internal/contracts/orchestration-actions.md` |
| OR-9 | Host hook payloads are read through one adapter that fails open and names a missing key, and host sequences are replayed against pinned per-version payload fixtures | `tests/test_hook_payload.py`, `tests/test_hook_payload_contract.py` | `agents/shared/logging-standard.md` |
| OR-10 | An undeterminable stop reason defers the call outcome instead of recording a failure; the Agent return then terminalizes the call and supplies its usage | `test_a_stop_without_a_transcript_defers_the_outcome` | `agents/shared/logging-standard.md` |
| OR-11 | Every dispatching action names its successor boundary in `next_boundary`; the caller invokes that name and never derives the sequence, which branches by depth | `tests/test_orchestration_controller.py::TestContextV2NextBoundary` | `docs/internal/contracts/orchestration-actions.md` |
| OR-12 | A contract violation in LLM-written recon signals buys one redispatch carrying the validator errors; STRIDE keeps its separate persisted two-attempt component budget, and other producers follow their boundary contract | `tests/test_orchestration_controller.py::TestProducerContractRetry` | `docs/internal/contracts/orchestration-actions.md` |
| OR-13 | An artifact a boundary regenerates and then receipts keeps its timestamp while its remaining content is unchanged, so the boundary can repeat the dispatch it already issued | `tests/test_merge_threats.py::TestBoundaryRepeatability`, `test_builder_carries_generated_at_while_the_manifest_is_unchanged` | `scripts/_artifact_stamp.py` |
| OR-14 | A command that rejects its own arguments ends the call and not the run — `reject`, exit code 3, no `RUN_ABORTED`, and the caller repeats it corrected; what a command learns from disk stays a terminal abort | `test_a_malformed_call_ends_the_call_and_a_bad_artifact_ends_the_run` | `docs/internal/contracts/orchestration-actions.md` |
| OR-15 | Lock liveness is read from the heartbeat alone — the stored PID is the acquiring helper's and is dead for a healthy run too, so it is never reported as holder liveness. A lock is reaped early only where `heartbeat == acquired` proves it never heartbeated once; a single heartbeat disarms that rule permanently | `test_a_lock_that_never_heartbeated_is_reaped_once_past_its_grace`, `test_a_lock_that_heartbeated_even_once_is_never_judged_abandoned`, `test_the_blocked_message_never_presents_the_stored_pid_as_holder_liveness` | `scripts/acquire_lock.py` module docstring |
| OR-16 | A STRIDE component is lost to a schema defect only in its CORE evidence. Optional branches that fail the schema are dropped before the gate — never truncated, because a shortened path or identifier validates and points nowhere — and what counts as optional is confirmed by the schema itself: a prune applies only when it strictly shrinks the error set, so removing a required branch raises a fresh `required` error and rolls back. `threats[i]` elements are never candidates. Every prune is logged, since a dropped `discovery_escapes` entry is the analyzer's own record of unresolved evidence | `test_optional_metadata_defect_never_costs_the_component`, `test_core_evidence_defect_stays_fatal`, `test_pruning_an_optional_branch_does_not_mask_a_core_defect`, `test_a_clean_component_is_left_byte_identical` | `scripts/validate_intermediate.py::prune_optional_schema_violations` — four runs died on one unlisted optional field (2026-07-20, 2026-07-31, 2026-08-02, 2026-08-20), each repaired field by field afterwards; this is that repair as a rule, so the next unlisted field cannot repeat it |

| OR-18 | Every interactive decision the runtime may take is resolved by the controller and carried in the action; the runtime never conditions on the environment, which it cannot read. A blocked lock therefore ships `lock_prompt_needed`, and `false` means the run is headless and stops on its exit code | `test_a_blocked_lock_invites_the_question_when_an_operator_can_answer`, `test_a_headless_run_is_never_asked`, `test_the_runtime_reads_the_field_instead_of_the_environment` | `scripts/orchestration_controller.py::_headless_session` — a headless run printed the whole `Held lock` menu into its log and then died at the gate (2026-09-05), because §1a gated on `APPSEC_HEADLESS=1` while the runtime only ever sees the action |

| OR-19 | Once the lock has been refused, everything that runs after the session treats the output directory as the holder's: no compose backstop, no artifact gate, no run-issue aggregation, no recovery hint. `acquire_lock.lock_held_by_live_other_run` is the single predicate, extending OR-8 from the terminator to the post-run surfaces. The dispatch capture is opened before the refusal can be known and is the one file a blocked run still overwrites | `test_a_blocked_run_touches_nothing_in_the_holders_directory` | `scripts/run-headless.sh` — a blocked run composed into the holder's mid-flight directory, reported the holder's not-yet-composed report as its own fail-closed failure and printed a fresh-run command that would collide again (2026-09-05) |
| OR-17 | The STRIDE wave-join deadline is derived from the widest `max_turns` in the wave, never a constant — depth raises the per-component turn budget and retries escalate it further, so a fixed timeout is a function of nothing and expires on exactly the deep runs it should allow. Bounded on both sides: never below the 15 minutes it replaces, never above the 60-minute ceiling that still frees a hung wave, and an unusable `max_turns` falls back to the floor | `test_deadline_covers_the_turn_budget_every_depth_can_hand_out`, `test_deadline_covers_an_escalated_budget`, `test_deadline_grows_with_the_turn_budget`, `test_deadline_never_drops_below_the_historical_floor`, `test_deadline_stays_bounded_so_a_hung_wave_is_still_freed`, `test_an_unusable_turn_budget_falls_back_to_the_floor` | `scripts/stride_dispatch_waves.py::wave_deadline_seconds` — 2026-08-20: the slowest component finished at 895.8 s against the fixed 900 s deadline, a 4.2 s margin, and the same repository at `--thorough` would have exceeded it outright. Staleness stays with `skill_watchdog.py`; this bound only frees a wave that never lands |

## Repair

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| RP-1 | A repair is accepted only when a test fails before the fix and passes after; an always-green test or one that collects nothing proves nothing | `test_a_genuine_fix_is_proven`, `test_an_always_green_test_proves_nothing`, `test_a_test_file_that_collects_nothing_is_rejected` | `tests/test_repair_proof_gate.py` |
| RP-2 | Repair scope is a binding whitelist with a deterministic-only hard ban — `.github/` and `.claude/` are outside it, and the gate itself is never in scope | `test_repair_scope_is_a_binding_whitelist`, `test_repair_scope_preserves_the_deterministic_only_hard_ban` | `tests/test_pre_render_repair_scope.py` |

## Context economy

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| CE-1 | Every listed prompt surface stays within its byte budget; exceeding it is fixed by shortening the prompt, not by raising the number | `test_each_live_prompt_surface_stays_within_budget` | `data/context-budgets.yaml` |
| CE-2 | Everything loaded resident is a listed surface | — *(no guard written)* | `data/context-budgets.yaml` |
| CE-3 | Stage 2 context stays cumulatively bounded | `test_thin_full_cumulative_stage2_context_is_bounded` | `data/context-budgets.yaml`; see `docs/internal/analysis/analysis-context-compaction-thorough-runs-2026-07-16.md` |
| CE-4 | Phase groups load at their boundary, never inline | `tests/test_lazy_phase_group_loading.py` | `docs/internal/contracts/orchestration-actions.md` |
| CE-5 | Dispatch prompts run stable → specific → volatile | `tests/test_dispatch_prompt_cache_order.py` | `skills/create-threat-model/SKILL-thin-stage1-v2.md` |

## Depth and turn budgets

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| DT-1 | All six STRIDE categories stay mandatory for every dispatched component at every depth tier and in every depth mode — cheap-stride and quick mode are pacing levers, never coverage cuts | `test_profile_does_not_skip_stride_categories` | `docs/internal/analysis/analysis-cheap-stride-vs-standard-2026-07-25.md` |
| DT-2 | `_cheap_stride_target` is the only place that decides which components are screened | `test_builder_cheap_stride_spares_auth_and_core_backend`, `test_builder_cheap_stride_spares_untrusted_input_entry_points`, `test_builder_cheap_stride_spares_datastores_not_crown_jewels` | `docs/internal/analysis/design-cheap-stride-layer-2026-07-23.md` |
| DT-3 | Exposure steers component selection, and unknown exposure fails safe to full depth — an off-vocabulary zone becomes exposure-unknown, never internal | `test_builder_cheap_stride_never_screens_exposure_unknown` | `docs/internal/analysis/proposal-stride-depth-tiering-2026-07-23.md` |
| DT-5 | Turn ceilings are computed per component at dispatch time, never declared in agent frontmatter; a ceiling paces work and never caps coverage | — *(no guard written)* | `scripts/build_stride_dispatch_manifest.py` |
| DT-6 | A ceiling lift or a dropped overflow is surfaced as a run issue, never silently absorbed | `test_stride_ceiling_lift_is_surfaced`, `test_stride_ceiling_overflow_dropped_is_surfaced` | `scripts/aggregate_run_issues.py` |

## Depth modes and rescans

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| DP-1 | A depth increase forces a full scan; the prior shallower model is not extended in place | `test_depth_increase_quick_to_standard_forces_full`, `test_depth_increase_standard_to_thorough_forces_full` | `scripts/resolve_config.py` |
| DP-2 | The resolver may classify a shallower rescan as incremental, but the compact runtime rejects it before dispatch or mutation | `test_shallower_depth_stays_incremental`, `test_unsupported_modes_fail_before_output_mutation` | Authorized single-runtime compatibility migration; use `--full` |
| DP-3 | An explicit `--incremental` is parsed only to produce a fail-closed rejection; it cannot bypass the compact runtime | `test_unsupported_modes_fail_before_output_mutation` | Authorized single-runtime compatibility migration |
| DP-4 | A depth increase makes recon reuse eligible only when the tree is git-provably clean | `test_depth_increase_sets_reuse_recon_eligible` | `scripts/resolve_config.py` |

## Model routing

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| MD-1 | Reasoning modes are a fixed canonical set; aliases resolve to a canonical value and never fork into a second vocabulary | `test_canonical_normaliser_maps_alias`, `test_cli_flag_alias_resolves_to_canonical`, `test_extended_models_alias_matches_canonical`, `test_stride_profile_alias_matches_canonical` | `docs/model-selection.md`; see `docs/internal/analysis/plan-model-routing-transparency-2026-07-04.md` |
| MD-2 | Every mode fills all three slots — a mode is a complete routing triple, not a partial override | `test_every_mode_has_three_slots` | `docs/model-selection.md` |
| MD-3 | Economy modes never move the STRIDE pass below sonnet; cost is saved elsewhere | `test_haiku_economy_keeps_stride_on_sonnet` | `docs/model-selection.md` |
| MD-4 | The session model controls the orchestrator and is the primary cost lever; the pipeline centrally routes subagents, while no agent selects its own model | — *(no guard written)* | `docs/model-selection.md` |
| MD-5 | Session-model detection is advisory and fails open; routing resolves with no session model present | `test_effective_routing_empty_session_model` | `scripts/resolve_config.py` |
| MD-6 | An organization may cap Opus org-wide; absent policy defaults to permitted | `test_policy_disable_opus_absent_defaults_false` | `schemas/org-profile.schema.yaml` → `policy.disable_opus` |

## Trust boundaries

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| TB-1 | A boundary is a falsifiable assumption decomposed into legs; a finding's CWE names the leg it refutes | `test_context_carries_the_assumption_legs_to_the_analyzer` | `data/cwe-boundary-legs.yaml`; see `docs/internal/analysis/fixplan-trust-boundary-assumption-legs-2026-08-01.md` |
| TB-2 | `assumption_verdict` is derived, never authored, and derived in one place — the deterministic scoring reads the same states, and two copies would argue with each other's severities | `tests/test_compose_threat_model.py` *(state table for `_boundary_assumption_verdict`)* | docstring of `_boundary_assumption_verdict`; see `docs/internal/analysis/proposal-boundary-scoring-impact-2026-08-01.md` |
| TB-3 | `refuted` requires a clean evidence check; a boundary is not declared broken on unverified evidence | `test_boundary_assumption_state_refuted_requires_clean_evidence_check` | `scripts/prepare_trust_boundary_context.py` |
| TB-4 | A boundary is unconfirmed when adjacent findings do not examine its crossing, not-examined when it protects no known component, and never rendered as clean merely because evidence is absent | — *(guard not located)* | `scripts/prepare_trust_boundary_context.py`; see `docs/internal/analysis/analysis-trust-boundary-documentation-gaps-2026-07-27.md` |
| TB-5 | `confidence` (does it exist), `resolution_status` (is the declaration coherent) and `assumption_verdict` (did the assumption survive) are three axes and are never collapsed | — *(guard not located)* | `schemas/threat-model.output.schema.yaml`; see `docs/internal/analysis/analysis-trust-boundary-data-model-f1-f5-2026-07-30.md` |
| TB-6 | Assumption shape violations are reported, never silently repaired | `test_assumption_shape_violations_are_reported_not_repaired` | `schemas/threat-model.output.schema.yaml` |
| TB-7 | A legacy migration never promotes absence into a positive claim | `test_normalize_migrates_legacy_without_promoting_absence` | `schemas/threat-model.output.schema.yaml` |
| TB-8 | The same crossing collapses unless a stated reason distinguishes it | `test_same_crossing_without_a_stated_reason_collapses` | `schemas/threat-model.output.schema.yaml` |
| TB-9 | Boundary identity survives renumbering; external IDs are translated at delivery | `test_external_boundary_ids_are_translated_through_the_delivery_renumber` | `scripts/emit_severity_rationale.py` |

## Findings and evidence

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| FE-1 | CVSS is assigned only to evidence-backed dependency and known-vulnerability findings and to eligible STRIDE CWEs with file-and-line evidence | `tests/test_cvss_eligibility.py` | `data/cvss-eligible-cwes.yaml` |
| FE-2 | A control is rated only from what the pipeline actually invokes — never from a tool name in a comment, a step label, or string data | `tests/test_assess_supply_chain_controls.py` *(name-level check open)* | `CHANGELOG.md` |
| FE-3 | Client-side code is not modelled as a trust zone | `tests/test_prepare_trust_boundary_context.py` *(name-level check open)* | `CHANGELOG.md` |
| FE-4 | Findings require target evidence from source, configuration, git history or target-owned declarations; validated external context may seed only an unverified hypothesis, and walkthroughs, solution guides or bundled vulnerability prose seed nothing | `test_cross_repo_mismatch_requires_target_evidence` | `docs/internal/analysis/analysis-external-threat-model-ingestion.md` |
| FE-5 | Supply-chain analysis is passive: files and git history only, no package manager, no network CVE scanner | — *(no guard written)* | `docs/internal/analysis/analysis-supply-chain-coverage-improvement.md` |
| FE-6 | Every remote fetch goes through a URL allow-list and an SSRF guard | `tests/test_url_guard.py`, see TR-4 | `schemas/org-profile.schema.yaml` → `policy.url_allowlist` |
| FE-7 | Declared business context weights and flags; it never sets or raises a severity. It may mark a component crown-jewel and it may raise a triage flag, and the severity caps stay authoritative | `test_step5b_flags_low_impact_where_context_declares_assets`, `test_declared_business_assets_make_a_component_crown_jewel` | `scripts/triage_validate_ratings.py`; `scripts/build_stride_dispatch_manifest.py`; `data/severity-caps.yaml` |
| FE-8 | An organization's LLM policy answers what code cannot: without a declared list the permitted-data and approval questions stay unanswered rather than guessed | `test_llm_policy_reaches_the_effective_profile`, `test_llm_policy_absent_stays_none` | `schemas/org-profile.schema.yaml` → `llm_policy`; `agents/shared/owasp-llm-top10.md` |

## Weaknesses

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| WK-1 | The weakness-class vocabulary has one source; schema enums equal the cluster IDs and every consumer references a known class | `test_schema_enums_match_cluster_ids`, `test_posture_rubric_themes_reference_known_classes`, `test_security_library_domains_reference_known_classes` | `data/weakness-classes.yaml`; see `docs/internal/analysis/implplan-weakness-class-evidence-model.md` |
| WK-2 | `implementation_strategy` is derived from evidence: vetted library without bespoke code is standard-vetted, bespoke without a library is home-grown, both together is standard-misused | `test_vetted_lib_no_bespoke_is_standard_vetted`, `test_bespoke_no_lib_is_home_grown`, `test_lib_plus_bespoke_is_standard_misused` | `scripts/detect_impl_strategy.py`; see `docs/internal/analysis/proposal-weakness-class-evidence-model.md` |
| WK-3 | An existing control may soften a design-risk weakness, never a confirmed one | `tests/test_detect_impl_strategy.py` *(name-level check open)* | `scripts/detect_impl_strategy.py` |
| WK-4 | A design-risk weakness is `kind: design` and carries no CVSS | `tests/test_detect_impl_strategy.py` | see FE-1 |
| WK-5 | Known vulnerabilities roll up into a vulnerability-management weakness instead of staying loose findings | `test_known_vuln_becomes_vulnerability_management_weakness` | `scripts/merge_threats.py` |
| WK-6 | Per-instance findings stay separate by default; consolidation by mechanism is the exception you justify | — *(guard not located)* | `data/consolidation-groups.yaml`; see `docs/internal/analysis/analysis-finding-consolidation-improvements-2026-06-26.md` |

## Security architecture

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| SA-1 | Absence of signal yields `not_applicable`, never a negative rating — a system with no such surface says so | `test_cookie_no_signal_is_not_applicable`, `test_authz_hypothesis_not_applicable_without_authenticated_routes`, `test_empty_repo_all_rules_not_applicable` | `data/architecture-coverage-rules.yaml` |
| SA-2 | Effectiveness is never reduced to a boolean; a wrong check and a missing check stay distinguishable, because they are different remediation problems | — *(no guard written)* | `data/architectural-controls.yaml` → `effectiveness_scale` |
| SA-3 | The rendered section passes its gates because the normalizer makes it, not because an author remembered | `test_defective_fixture_fails_all_three_gates`, `test_normalizer_makes_all_three_gates_pass` | `scripts/normalize_security_architecture.py` |
| SA-4 | Control domains and weakness classes are separate taxonomies and are never joined at class level; they meet at the finding | — *(no guard written)* | recurring proposal, rejected |

## Rendering and normalization

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| RN-1 | The render path is a mutation sequence and its order is load-bearing: `compose_threat_model.py --strict`, then `apply_prose_fixes.py`, then `qa_checks.py autofix` | — *(guard not located)* | `docs/internal/contracts/orchestration-actions.md` |
| RN-2 | A normalization pass is idempotent; running it twice changes nothing, or a re-render invents differences | `test_apply_fixes_is_idempotent_for_core_rewrites`, `test_autofix_is_idempotent_on_paths`, `test_r7_full_pipeline_is_idempotent` | `scripts/apply_prose_fixes.py`, `scripts/qa_checks.py` |
| RN-4 | The deterministic emitters run in a fixed sequence | `test_emitter_sequence_preserved_in_order` | `scripts/auto_emitter_pass.sh` |
| RN-5 | One source-preserving recognizer owns inline-code token boundaries for composition, walkthroughs, normalization, autofix, and QA; it formats a complete balanced expression or leaves it unchanged | `tests/test_inline_code_formatter.py`, `tests/test_qa_checks_cov_band3.py::test_inline_code_format_scans_table_and_blockquote_but_skips_opaque_markdown` | `scripts/inline_code_formatter.py` |

## Report and artifacts

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| RA-1 | Every artifact crossing a stage boundary has a schema and a validation path | `tests/test_schema_integrity.py`, `scripts/validate_intermediate.py` | `docs/internal/contracts/schema-invariants.md` |
| RA-2 | A document never duplicates a schema; it points at the authoritative file | `tests/test_schema_drift.py` | `docs/internal/contracts/schema-invariants.md` |
| RA-3 | `T`/`F` identity stays consistent across artifacts derived from one model; compatibility helpers preserve it when reading prior incremental artifacts, while `M` may be regenerated, `W` follows display order, and deliberate `--rebuild` may reassign all IDs | — *(guard not located)* | `docs/internal/contracts/schema-invariants.md`; see `docs/internal/analysis/backlog-numbering-native-contiguous-2026-07-05.md` |
| RA-4 | Reference formats are fixed per context; locators are stripped, never invented | `tests/test_reference_format.py` | `schema-invariants.md` §4a, `qa-crossref-rules.md` |
| RA-5 | Structure and integrity gates after the review stages are read-only | — *(guard not located)* | `docs/internal/contracts/orchestration-actions.md` |
| RA-6 | Audit artifacts and `.appsec-cache/baseline.json` survive normal cleanup; `--rebuild` is the only exception | `tests/test_runtime_cleanup.py` | `docs/internal/contracts/cleanup-whitelist.md` |
| RA-7 | Every surface that shows a reader an aggregate finding tally takes it from `_severity_rollup`; a surface never counts `threats[]` itself. Triage surfaces that tally the finding list they operate on are a different basis and say so | `TestSeverityBasisMatchesTheReport`, `tests/test_severity_rollup.py` | `scripts/_severity_rollup.py` module docstring |

## Abuse cases

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| AC-1 | Only a confirmed probe is promoted; unconfirmed or unclassified never becomes a finding | `test_unconfirmed_or_unclassified_probe_is_never_promoted` | `scripts/promote_verified_abuse_cases.py` |
| AC-2 | A promoted probe becomes an ordinary bound finding, not a separate class of thing | `test_confirmed_source_probe_becomes_normal_bound_finding` | `scripts/promote_verified_abuse_cases.py` |
| AC-3 | Promotion is idempotent — a rediscovered probe does not produce a second finding | `test_promotion_is_idempotent_when_next_scan_rediscovers_same_source_probe` | `scripts/promote_verified_abuse_cases.py` |
| AC-4 | A promoted component resolves against the component registry, never a hardcoded name; overlapping globs resolve to the most specific owner | `test_promoted_component_resolves_against_the_registry_not_a_hardcoded_name`, `test_overlapping_globs_resolve_to_the_most_specific_owner` | see TA-1 |
| AC-5 | Source-probe evidence wins when the verifier omits a file — an omission is not a refutation | `test_source_probe_evidence_wins_when_verifier_omits_a_file` | `scripts/promote_verified_abuse_cases.py` |

## Requirements mapping

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| RQ-1 | Mapping never branches on a requirement-ID prefix; it keys off the catalog | `test_mapping_is_prefix_agnostic_for_requirement_ids` | `docs/internal/contracts/schema-invariants.md` |
| RQ-2 | Rows group by requirement and take the maximum severity | `test_rows_group_by_requirement_and_take_max_severity` | `docs/internal/contracts/schema-invariants.md` |
| RQ-3 | A threat not linked to a requirement is excluded from the mapping, never guessed into it | `test_legacy_requirement_id_is_honoured_and_unlinked_threats_excluded` | `docs/internal/contracts/schema-invariants.md` |
| RQ-4 | Without a requirements source, no remediation reference is invented | `test_remediation_reference_ignored_without_requirements_yaml` | `docs/internal/contracts/schema-invariants.md` |
| RQ-5 | The trace runs both ways — mitigations declare what they fulfil | `test_reverse_fulfills_requirements_adds_measure` | `docs/internal/contracts/schema-invariants.md` |
| RQ-6 | The report's requirement list is a filtered view of the model's, never a different set — one derivation in `requirements_trace`, the §7b status filter applied only at render | `test_the_yaml_derivation_covers_every_threat_side_source`, `test_sidecar_authored_requirements_are_extended_not_replaced` | `scripts/requirements_trace.py`; `scripts/emit_requirement_trace_to_model.py` |
| RQ-7 | A blueprint is selected by fit to the mitigation, and a selection with no shared wording is marked ungrounded rather than presented as governing | `test_the_chosen_blueprint_scores_at_least_as_high_as_every_alternative`, `test_a_selection_with_no_shared_wording_reports_itself_ungrounded` | `scripts/requirements_trace.py::select_blueprint` |
| RQ-8 | Blueprint guidance reaches the STRIDE analyst that writes the remediation steps, not only the renderer that prints them | `test_each_requirement_carries_the_section_that_prescribes_it` | `scripts/build_requirements_contexts.py`; `agents/appsec-stride-analyzer-v2.md` |

## Incremental runs

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| IN-1 | Reuse is authorised by a fingerprint match on an unchanged tree; a cache is validated, never assumed fresh | `test_check_fingerprint_match`, `test_cmd_validate_valid` | `scripts/baseline_state.py` |
| IN-2 | A shallower rescan carries an unverified prior finding; an equal-or-deeper rescan records a non-reproduced finding as resolved with its prior identity and reason instead of dropping its history | `test_reconcile_carries_dropped_prior_threat_at_shallower_depth`, `test_reconcile_no_carry_at_equal_depth` | `scripts/build_threat_model_yaml.py`; see `docs/internal/analysis/proposal-depth-downgrade-incremental-preservation.md` |
| IN-3 | Changed business context recommends a full run, it never forces one — unlike a requirements toggle, because re-rating every finding on every context edit costs more than the drift | `test_changed_context_is_flagged_on_an_incremental_run`, `test_unchanged_context_is_not_flagged` | `scripts/resolve_config.py::resolve_business_context`; `meta.business_context_sha256` |

## Exports

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| EXP-1 | The Threat Dragon export stays alpha and opt-in, and is never part of the `--formats all` expansion | `test_threat_dragon_is_alpha_and_opt_in`, `test_summary_description_marks_the_export_alpha` | `docs/threat-dragon-export.md` |
| EXP-2 | Emitted values stay inside Threat Dragon's own vocabulary; the envelope is v2 | `test_envelope_is_threat_dragon_v2` | `docs/threat-dragon-export.md`; see `docs/internal/analysis/analysis-threatatlas-export-format-2026-07-30.md` |
| EXP-3 | Component tiers map to fixed DFD shapes rather than to whatever the renderer prefers | `test_tier_maps_to_dfd_shape` | `docs/threat-dragon-export.md` |
| EXP-4 | `threat-model.md` stays authoritative and SARIF stays the scanner export; a deliberately lossy export never becomes the source of truth | — *(no guard written)* | `docs/threat-dragon-export.md` |
| EXP-5 | Canonical YAML retains abuse-case, business-context, and requirements traceability; narrower exports use their native fields or bounded text instead of inventing duplicate findings | `test_main_persists_canonical_analysis_to_yaml`, `test_traceability_is_folded_into_bounded_text` | `docs/threat-dragon-export.md`; `docs/internal/contracts/schema-invariants.md` |

## Repository trust

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| TR-1 | The default posture is `untrusted`; `--trust-mode trusted` is an explicit opt-in for a repository whose committed agent configuration someone has read | — *(guard not located)* | `HELP.txt` → TRUST MODE, `SECURITY.md` → Known issues |
| TR-2 | An untrusted run rejects repo-owned Claude Code hooks, settings and memory files, and out-of-repo symlinks, before Claude starts | `test_repo_owned_claude_settings_flagged`, `test_repo_root_claude_memory_is_flagged`, `test_escaping_symlink_flagged` | `scripts/preflight_untrusted.py` |
| TR-3 | A preflight finding aborts the run; it is never downgraded to a warning | `test_clean_repo_passes` *(negative case; abort path name-level check open)* | `scripts/preflight_untrusted.py` |
| TR-4 | An untrusted run requires a URL allow-list for every remote fetch | `tests/test_url_guard.py` *(the `--strict-urls` implication is not separately guarded)* | `--strict-urls` |
| TR-5 | An untrusted run redacts sensitive paths from the run log, so a shared log cannot leak filesystem layout | — *(no guard written)* | `APPSEC_LOG_REDACT_PATHS` |
| TR-6 | A blocked run names the escape hatch, so the operator learns what to review instead of what to disable | `test_preflight_abort_names_the_trust_mode_escape_hatch` | `tests/test_run_headless_completion.py` |
| TR-7 | A file read cannot escape the repository through a symlink | `tests/test_path_guard.py` | `scripts/_path_guard.py` |
| TR-8 | A leaked secret value in a run artifact fails the run | `tests/test_postscan_secret_check.py` | `scripts/postscan_secret_check.py` |
| TR-9 | The pattern masker rewrites a serialized artifact only through its decoded document, never over its text, and an assignment it matches never spans a line break. `mask_file` decides this on the suffix so no caller can reach for the wrong twin, and a document it cannot decode is left untouched: an undetected leak still fails at the unmasked_secrets gate, whereas a blind text rewrite corrupts the artifact instead | `test_mask_file_keeps_yaml_parseable`, `test_mask_file_keeps_json_parseable`, `test_mask_file_leaves_an_undecodable_document_alone`, `test_operator_at_end_of_line_does_not_claim_the_next_line`, `test_single_line_assignments_are_still_masked` | `scripts/secret_scan.py::mask_file` — `mask_structure` had carried the rule as a docstring while `auto_emitter_pass.sh` text-masked threat-model.yaml anyway; a credential keyword ending a line (`?token=`) then let the pattern claim the next line's mapping key, and the unparseable model aborted the run at the controller gate after 1h11m (2026-09-05) |

## Related repositories

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| RR-1 | `docs/related-repos.yaml` is the only source for cross-repository finding deep-reads; a filesystem sibling may annotate a C4 diagram and nothing else | — *(guard not located)* | `docs/threat-modeler.md` |
| RR-2 | A remote related-repo fetch requires the URL allow-list; an untrusted run enforces it | `tests/test_url_guard.py` | see TR-4, FE-6 |
| RR-3 | A stale or unresolvable repository path is rejected before it reaches component analysis, never carried as an unverified claim | `tests/test_build_cross_repo_register.py` *(name-level check open)* | `CHANGELOG.md` |

## Repository-declared context

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| RC-1 | Threat input declared by the target repository is schema-validated before it can enter the analysis context | `test_rejects_invalid_known_threats_before_context_publication` | `schemas/known-threats.schema.yaml`; see `docs/internal/analysis/analysis-external-threat-model-ingestion.md` |
| RC-2 | Valid repo-declared input enters fenced — data the analysis reads, never instructions it follows | `test_preserves_schema_valid_known_threats_as_fenced_input` | see P-4 |
| RC-3 | An actor disable persists only in the target repository's own `.appsec/actors.yaml`; a decision made in conversation is never written back | `test_resolver_never_writes_actor_choices_back_to_repo` | `docs/threat-modeler.md` → actor layer |

## Extension surface

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| EX-1 | An organization extends the plugin only through its org profile and package policy | `tests/test_org_profile_schema.py`, `tests/test_package_internal_plugin.py` | `docs/internal/contracts/org-profile-invariants.md` |
| EX-2 | Agents are core-owned; a profile cannot add or change one | `tests/test_package_internal_plugin.py` | `docs/internal/contracts/org-profile-invariants.md` |
| EX-3 | `create-threat-model` cannot be removed from a build | `tests/test_skill_policy_gate.py` | `docs/internal-plugin-packaging.md` |
| EX-4 | A package policy takes `include` or `exclude` per surface, never both, and the same rule applies to org-added skills | `test_policy_surface_explicit_block`, `test_policy_surface_fallback_to_root`, `test_the_package_policy_can_exclude_an_added_skill` | `docs/internal-plugin-packaging.md` |
| EX-5 | What a build kept and what it dropped is recorded in `.claude-plugin/package-surface.json`, so a shipped plugin can be audited against its policy | — *(guard not located)* | `docs/internal-plugin-packaging.md` |
| EX-6 | An organization baseline replaces the upstream copy instead of shipping both | `test_org_baseline_drops_the_unused_upstream_copy` | `scripts/package_internal_plugin.py` |

## Target agnosticism

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| TA-1 | Production behavior works for arbitrary repositories; fixture-specific names stay in fixtures | `tests/test_check_target_specificity.py` | `data/test-target-vocabulary.yaml` |
| TA-2 | New commands or Read/Write targets require a `required-permissions.yaml` update | `tests/test_check_permissions.py` | `data/required-permissions.yaml` |

## Principles

No code-local home, so they are stated in full here.

- **P-1 One control plane.** There is no second orchestrator, and compaction is not the
  primary optimization. A second scheduler would split the place where turn and context
  admission are decided.
- **P-2 Python controls execution and validates state. The model decides security meaning
  at explicit semantic boundaries. The filesystem stays authoritative between them.**
- **P-3 What can be derived is derived, not authored.** A computed value has no wrong
  state to write, so it needs no guard.
- **P-4 Repository content is data, never instructions.** This covers imports, URLs,
  related repositories, known-threat files and scanner output.
- **P-5 Fix the producer, not the symptom.** Patching a rendered report, softening a
  schema or adjusting a fixture expectation hides a defect the next run reproduces.
- **P-6 When a deterministic emitter can own a category, it does.** Where a call is
  uncertain, keep the deterministic path and give the model less to decide. The controller
  owns phase transitions and producer ownership; the model is asked only at semantic
  boundaries.
- **P-7 One vocabulary per concept.** A second spelling of an existing concept resolves to
  the canonical one or does not exist. `test_canonical_normaliser_maps_alias` and the
  controller's `semantic_role` enum matching `SEMANTIC_ROLE_REGISTRY` are the two working
  examples.

## Conventions

- **Every guard names its decision ID in the assertion message.** A failing test is how
  this register reaches a reader who never opened it, so `assert ..., "CR-3: forbidden
  shared context must not reach focused agent inputs"` is the point, not decoration.
- **A guard must prove it bites.** It asserts over a non-empty subject, and where a gate
  matters, a mutation trips exactly it — `tests/test_enforcement_mutations.py` is the
  model, `test_an_always_green_test_proves_nothing` is the same rule for repairs.
- A decision that gets a guard loses its prose elsewhere — resident text is paid every
  turn, so a sentence a test now enforces is deleted rather than kept.
- Where a decision has a code-local home, the reasoning lives next to the guard and this
  register only indexes it. `AGENT_TOOL_OWNERS` is the model: claim, reason, and the work
  package that must revisit it, written where someone changing it will read it.
- A `gen`-scoped entry names the work package that retires it. Removing the legacy
  generation without revisiting these entries is a defect.
- One row is one decision on one line. Multi-line rows break grep, which is how both
  readers find things here.
- An entry earns its place when breaking it is costly and non-obvious, and when it
  constrains future changes rather than describing current behavior.
