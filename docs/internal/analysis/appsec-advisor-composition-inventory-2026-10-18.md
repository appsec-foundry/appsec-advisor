# AppSec Advisor composition inventory

Status: P1 inventory recorded on 2026-10-18. The operator subsequently approved offline P2–P4 implementation before A7; release, public cutover, and removal remain gated. The first [P3 staging primitives](../contracts/plugin-composition.md) implement explicit artifact assembly and offline runtime bootstrap. This inventory is not a qualification record or a replacement product contract. No public command has switched engines and no existing implementation is deleted.

## Inspected inputs and gate

Inspection used committed files for component comparisons. Working-tree changes in Analyzer were excluded. References to Analyzer paths below mean the recorded revision, not its mutable working tree.

| Component | Committed revision | Selection status |
| --- | --- | --- |
| Advisor | `85c3ea0fbd61b06e45a565d8df5d83890d3ff7e0` on `dev` | Clean starting tree; existing implementation remains the runtime. |
| Analyzer | `ffd6643af1bcc23431715eb17fa219c29da7e927` | Committed inspection candidate after module restructuring; not a qualified release input. Local changes include startup scope work and are excluded. |
| AppSec Skills | `db437fa31b80832ef32216329d9003b1b396af31` | Clean checkout; only `create-threat-model` is currently distributed. |

Analyzer's `appsec_analyzer/cli.py:390–441` declares interface 1, deterministic `scan-sources`, scoring version 2, and available assessment/focused-analysis operations. All declared assessment providers, focused threat analysis, AuthN/AuthZ review, and requirements audit remain `qualified: false`. In particular, `scan` now uses models (`cli.py:394`); deterministic integrations must select `scan-sources`, not infer behavior from an older command name.

Analyzer's `docs/internal/extraction/phase-a-record.md:264–267` records A3–A5 as offline implementation with live model/route qualification open and A7 as local release preparation. This does not satisfy the composition plan's qualified standalone release gate. No inspected record establishes complete Claude, direct API, and gateway qualification. Existing offline evidence is reported by that record; it was not rerun during this documentation change.

P1's workflow inventory is available below. A qualified immutable release, approved artifact digests, supported Python/OS/architecture matrix, and the unresolved fix reconciliation remain release prerequisites. Their absence no longer blocks the approved offline P2–P4 work. None can be filled with the alpha version label or inferred from a successful local package build. Publication and paid qualification runs require separate authorization under the plan.

## Skill ownership and replacement ledger

All existing skills currently belong to Advisor. The destination column assigns future ownership of the user workflow; implementation, schemas, analysis contracts, validation, and result mutation remain engine responsibilities. Every row remains installed from its existing producer until its replacement prerequisite is met. A listed test is a coverage entry point to inspect when implementing the transfer, not an assertion of installed compatibility or a request to run the whole module.

| Skill | Destination and public replacement | Compatibility gap and deletion prerequisite | Existing coverage entry point |
| --- | --- | --- | --- |
| `appsec-analyzer` | Analyzer-owned entry distributed by Advisor; `assess`, `preflight`, `status`, `progress`, `stop`, `results` | Map current phased launch, early business context, retained decisions, imports, source grants, budgets, depth, exports, and storage. The skill currently invokes the controller and shell launcher. Require qualified Claude installed assessment and all downstream rows before deleting dependencies. | `tests/test_skill_definitions.py`, `tests/test_assessment_console.py`, `tests/test_multi_repo_controller.py` |
| `security-score` | AppSec Skills; `score` | Map `--repo` to the positional repository; default it explicitly. Preserve JSON/YAML, cancellation, incomplete and undetermined outcomes; expose scoring version 2 and comparability limits. Require installed execution without models and option tests before removing the legacy producer. | `tests/test_security_score.py`; Analyzer `tests/test_public_score_cli.py` |
| `authnz-review` | AppSec Skills; `authnz-review` | Missing legacy `--with-threat-model` and `--slug` mappings; organization export defaults and `--no-pentest-tasks` need explicit handling. Saved result names/shapes and incomplete exit behavior differ. Require parity or confirmed replacement of each affected option. | `tests/test_authnz_review_skill.py`, `tests/test_authnz_report.py`; Analyzer `tests/test_authnz_review_cli.py` |
| `analyze-threats` | AppSec Skills entry; Analyzer `analyze-threats` and `analyst` | Separate `references/analysis-contract.md` from portable instructions. Map saved answers/forget, resume, question packages, exploration, required context, preview, bounded calls, and cancellation. `analyze-threats` parser alone does not prove all lifecycle operations are exposed. | `tests/test_analyst_skill.py`, `tests/test_analyst_questions.py`, `tests/test_analyst_cli.py`; Analyzer `tests/test_threat_analysis_cli.py` |
| `audit-security-requirements` | AppSec Skills when compatible; `audit-requirements` | Local catalog support does not replace remote catalog resolution, organization source precedence, resume, saved reports, or all exports. Retain source resolver, fetcher, audit contracts, and skill until mapped. | `tests/test_requirements_source_resolution.py`, `tests/test_fetch_requirements.py`, `tests/test_requirements_state.py`; Analyzer `tests/test_requirements_audit_cli.py` |
| `verify-requirements` | AppSec Skills workflow with Analyzer verification operation still needed | Existing differential verification uses `repairs/build_verify_diff.py`, reviewer behavior, and gate semantics. An independent local-catalog audit is insufficient. Retain until a supported verification operation preserves source evidence, catalog identity, and gate. | `tests/test_requirements_verification.py`, `tests/test_requirements_gate.py` |
| `abuse-cases` | AppSec Skills listing workflow; Analyzer-owned catalog resolution | Existing `model/resolve_abuse_cases.py` has no declared catalog-list replacement in the public parser. Preserve technical/business cases and organization selections before transfer. | `tests/test_abuse_case_gate.py` |
| `ask-security-assessment` | AppSec Skills; supported result query still needed | `results` lists validated deliverables; it does not replace `query_threat_model.py`, summaries, health checks, or evidence-based answers. | `tests/test_ask_threat_model_skill.py` |
| `show-security-assessment` | AppSec Skills presentation; Analyzer-owned summary/health operation needed | Preserve version compatibility, summary, baseline context, legacy import, and output lookup instead of parsing private state in the skill. | `tests/test_session_banner.py`, `tests/test_skill_definitions.py` |
| `triage-security-assessment` | AppSec Skills workflow; Analyzer-owned review/triage boundary needed | Preserve `.appsec-triage/`, explicit source-edit consent, accept-risk promotion, team-authored known threats, and rerender semantics. `results` cannot mutate or promote decisions. | `tests/test_triage_compute_ranking.py`, `tests/test_triage_validate_ratings.py` |
| `export-security-assessment` | AppSec Skills entry; Analyzer export operations needed for existing results | Assessment-time export switches do not establish post-run PDF/HTML/SARIF/Threat Dragon/pentest re-export. Preserve validation, explicit destination, optional-tool errors, and format contracts. | `tests/test_export_threat_model_skill.py`, `tests/test_export_pdf.py`, `tests/test_export_html.py`, `tests/test_export_sarif.py`, `tests/test_export_threat_dragon.py` |
| `security-assessment-health` | AppSec Skills entry; Analyzer health/cleanup operation needed | Existing `model/threat_model_health.py` and cleanup behavior are not covered by listing result hashes. | `tests/test_skill_definitions.py`, `tests/test_runtime_cleanup.py` |
| `eval-security-assessment` | Retain Advisor workflow pending Analyzer evaluation API | Existing judge/validation and `.eval-out/` consumers have no declared public replacement. Retired Analyzer evaluation drivers do not authorize removal here. | `tests/test_skill_definitions.py` |
| `diagnose-run` | AppSec Skills entry; Analyzer diagnosis operation needed | Preserve issue/bug records, diagnosis, and supported recovery evidence; never reconstruct private state in portable instructions. | `tests/test_render_run_diagnosis.py`, `tests/test_run_diagnostics_recovery_2026_07_20.py` |
| `diagnose-bundle` | AppSec Skills entry; Analyzer redacted bundle operation needed | Preserve selected audit inputs, exclusions, size/path limits, and explicit destination. `results` does not create a diagnostic bundle. | `tests/test_diagnostic_bundle.py` |
| `fix-run-issues` | AppSec Skills entry; Analyzer recommendation/repair boundary needed | Current recommendation workflow uses `runtime/recommend_fixes.py`. Preserve diagnosis binding and manual-guidance behavior; do not grant model-selected engine edits. | `tests/test_run_diagnostics_recovery_2026_07_20.py` |
| `clean-run-state` | Advisor entry with Analyzer-owned cleanup operation needed | Preserve lock ownership, dry-run, stale-state checks, and the exact retained artifacts. `stop` is cancellation, not stale cleanup. | `tests/test_skill_definitions.py`, `tests/test_runtime_cleanup.py` |
| `status` | Advisor display using Analyzer `status`/`progress` | Current `runtime/appsec_status.py` locates output and reads legacy state. Public commands require `--output`; repository-to-run lookup and legacy-state routing remain unresolved. | `tests/test_appsec_status.py`, `tests/test_appsec_status_live.py` |
| `repo-profile` | AppSec Skills entry; Analyzer-owned repository-profile operation needed | Existing `analyzers/repo_profile.py` is not a declared public CLI operation. Keep until structured output and installed invocation are supported. | `tests/test_repo_profile.py` |
| `help` | Advisor | Generate help from the selected command surface and qualified capabilities; preserve status hints without private-state imports. | `tests/test_skill_definitions.py`, `tests/test_appsec_status.py` |
| `check-permissions` | Advisor | Replace checkout paths only when installed launcher/setup/host bindings exist; preserve prompt-suppression semantics without claiming sandboxing. | `tests/test_check_permissions.py`, `tests/test_check_permissions_coverage.py` |
| `setup-target` | Advisor | Preserve explicit permission setup and repository selection. Separate component runtime setup from target permissions. | `tests/test_check_permissions.py`, `tests/test_skill_definitions.py` |
| `report-error` | Advisor host workflow with Analyzer diagnosis/bundle API needed | Preserve local preview, redaction, exact-draft approval, and submission receipts. No engine cutover may imply permission to publish an issue. | `tests/test_diagnostic_bundle.py`, `tests/test_skill_definitions.py` |
| `install-baseline` | Advisor adapter to AISCB | Keep existing signature/digest verification and scope until supported AISCB lifecycle operations replace it. | `tests/test_install_baseline.py`, `tests/test_baseline_modular.py` |
| `update-baseline` | Advisor adapter to AISCB | Preserve trusted release verification and installed scope; unrelated to Analyzer packaging. | `tests/test_update_baseline.py`, `tests/test_baseline_release.py` |
| `verify-baseline` | Advisor adapter to AISCB | Preserve baseline state, drift checks, and supported installation modes. | `tests/test_baseline_check.py`, `tests/test_baseline_state_coverage.py` |
| `remove-baseline` | Advisor adapter to AISCB | Preserve ownership and scope of removal. | `tests/test_remove_baseline.py` |
| `internal-threat-analysis-kernel` | Analyzer internal contract; no portable public command | Keep semantic analysis instructions with the engine and classify the internal skill separately from user workflows. Remove the Advisor copy only after all calling agents use packaged engine resources. | `tests/test_skill_definitions.py`, `tests/test_agent_definitions.py` |
| `create-threat-model` (additional distribution) | AppSec Skills, already independent | Preserve its design-oriented `threat-model.md` workflow and complete references. It must remain usable without Analyzer; it cannot substitute for the assessment entry. | AppSec Skills installed-distribution coverage still to establish for composition. |

The 28 existing skill directories are all represented above; the additional design-modeling skill is a separate input. Source commands and references remain authoritative in each current `skills/<name>/SKILL.md` and its adjacent help/references. No private-script dependency in those instructions has been declared compatible merely because its implementation was imported into Analyzer.

## Initial transfer compatibility

The first three portable transfers need explicit invocation bindings and per-skill capability declarations, even with interface version 1. Bind plugin invocations to the completed isolated environment; a standalone installation can use an explicitly selected compatible Analyzer. Do not resolve the plugin engine from `PATH` or rewrite engine prompts by substitution.

| Transfer | Required declaration and mapping | Acceptance evidence still needed |
| --- | --- | --- |
| Score | `score`, interface 1, scoring version 2, no model; `--repo X` becomes `score X`, JSON/YAML pass through. Existing plugin accepts a local directory; current Analyzer documents a top-level Git checkout, so non-Git and subdirectory behavior needs an explicit compatibility decision. | Installed text/JSON/YAML, local and authorized remote input, incomplete/undetermined/cancelled outcomes, no credentials or model transport. Legacy scores must not be presented as numerically comparable. |
| AuthN/AuthZ | `authnz-review`, interface 1, Claude CLI/authentication and bounded budget; explicit save/output/export selection. The public parser lacks `--with-threat-model`, `--slug`, and `--no-pentest-tasks`. | Resolve each missing option, org defaults, artifacts, cross-component evidence and incomplete gates; installed success/failure/cancellation and optional export cases. |
| Focused analysis | `analyze-threats` plus supported `analyst` lifecycle operations, interface 1, Claude CLI and actual per-call/job limits; preserve question-first behavior. | Exercise answer/save/forget/cancel and preview in an installed host. Map every current help option; retain engine ownership of `references/analysis-contract.md`. The new CLI warns of a per-call ceiling without a total-job budget guarantee, so do not invent one in skill prose. |

AppSec Skills' current README says all skills need neither Advisor nor Analyzer. Update that statement to per-skill dependencies when transfers land there; preserve the independent design-modeling claim for `create-threat-model`.

## Hook and host consumer ledger

The [hook registry](../../../hooks/hooks.json) contains these commands and the progress module. Existing source files mix display and lifecycle responsibilities; whole-file deletion is not a transfer strategy.

| Event / consumer | Current producer and responsibility | Destination, gap, and removal condition | Coverage entry point |
| --- | --- | --- | --- |
| `SessionStart` / startup | `runtime/session_banner.py`: identity, baseline state, assessment lookup, compatibility and running-state hints (`_model_location`, `_threat_model_line`) | Advisor display and baseline adapter remain. Engine supplies public repository/run lookup, summary and status. Do not infer the output location from new private state. | `tests/test_session_banner.py` |
| `UserPromptSubmit` | `analyzers/security_steering.py`: configured security topics, requirements and baseline coaching | Advisor host event remains; classify policy/data consumed by engine independently. Preserve organization topic selections. | `tests/test_security_steering_units.py` |
| `PreToolUse`, `PostToolUse`, `Stop`, `SubagentStart`, `SubagentStop` | `runtime/agent_logger.py`: tool/agent telemetry, transcript usage, budget counters, terminal lifecycle, checkpoint aborts and live marker cleanup | Advisor translates host events; Analyzer owns any run accounting, budgets, cancellation and cleanup on the direct CLI path. `clear_terminal_active_tool_calls` and `mark_checkpoint_aborted_if_dirty` cannot disappear with logging. | `tests/test_agent_logger.py`, `tests/test_agent_logger_checkpoint_abort.py`, `tests/test_agent_logger_run_scope.py` |
| `PreToolUse` / Skill and `UserPromptExpansion` | `runtime/skill_policy_gate.py` calls `check_skill_enabled`: organization skill policy for invoked/typed commands | Advisor host business policy remains; engine restrictions need their own enforcement. Skill disabling is not a substitute for engine authorization. | `tests/test_skill_policy_gate.py`, `tests/test_check_skill_enabled.py` |
| `PreToolUse` / Read, Grep, Glob | `runtime/plugin_read_gate.py`: prevent runtime-internal reads during analysis | Advisor host guard needs paths for immutable installed resources and explicit maintainer behavior. It is documented as a workflow guard, not a security boundary. | `tests/test_plugin_read_gate.py` |
| `PreToolUse` / Edit, Write, NotebookEdit | `runtime/plugin_write_gate.py`: protect plugin-owned implementation against runtime edits | Advisor host protection remains; add completed runtime environment paths when implemented. Organization namespace rewriting must not change pinned engine code. | `tests/test_plugin_write_gate.py` |
| Progress pane | `hooks/progress.tsx:179–196` reads `.assessment-state.json` and `.assessment-work/host-events` | Advisor UI must consume versioned public progress/status; replace private event parsing only after equivalent structured events are exposed. | `hooks/progress.test.ts` |
| Interactive terminal | `runtime/assessment_console.py` plus primary skill launch and monitor | Advisor handles Claude terminal display; engine supplies liveness and bounded stop. Preserve monitor termination without stopping the owner run. | `tests/test_assessment_console.py` |

## Configuration dispatch ledger

The [profile invariants](../contracts/org-profile-invariants.md) govern current defaults, profile-level values, build-time surface policy, and consumer paths. Analyzer's `appsec_analyzer/organization.py:87–90` explicitly rejects `hooks`, `mcp`, `skills`, `skill_toggles`, `banner`, `baseline`, `security_coach`, and `llm_policy` in its organization distribution. Forwarding the whole Advisor profile cannot work.

All current top-level runtime configuration blocks are assigned here; child fields stay together unless the row explicitly splits them.

| `config.json` block | Destination and compatibility work |
| --- | --- |
| `_comment` | Documentation metadata; not runtime policy. |
| `banner` (`enabled`, `headline`, `url`) | Advisor display. |
| `baseline` (`enabled`, `id`, `mode`, `bundle_dir`, `name`, `release.repository`, `release.allowed_signers`, `fallback_file`, `install_filename`, `enforce`) | Existing Advisor/AISCB adapter, including signed lifecycle verification and enforcement. |
| `external_context` (`enabled`, `rest_url`) | Engine context admission and destination controls; require explicit mapping before switch. |
| `pricing` (`input_per_1m`, `output_per_1m`, `cache_write_per_1m`, `cache_read_per_1m`) | Host telemetry remains Advisor; enforceable per-provider spend accounting belongs to Analyzer and cannot use display prices implicitly. |
| `logging` (`max_log_bytes`, `verbose`) | Split host log controls from engine logs with separate validated settings. |
| `organization_profile` (`enabled`, `path`, `default_preset`) | Explicit trusted dispatch into host settings and engine policy/defaults; preserve source precedence and missing/invalid-profile errors. |

Every [organization profile schema](../../../schemas/org-profile.schema.yaml) top-level field is assigned below. Assignment is a migration destination, not proof that Analyzer implements its current semantics.

| Profile fields | Owner and required handling |
| --- | --- |
| `api_version`, `organization.{id,name,profile_version,owner}`, `compatibility.core` | Validate composition/profile compatibility and identify both host and engine; do not substitute the plugin version for engine compatibility. |
| `policy.{disable_opus,url_allowlist}` | Engine mandatory model/egress policy; demonstrate enforcement in direct CLI use. |
| `branding.{report_title,contact_name,contact_email,logo}` | Engine report metadata with approved resources; Advisor package branding remains host-owned. |
| `banner.{enabled,headline,url}` | Advisor. |
| `skills.add`, `skill_toggles` | Advisor surface assembly and host invocation policy; portable command collisions must fail. |
| `baseline.{enabled,enforce,id,name,url,git,file,install_filename}` | Advisor/AISCB adapter. |
| `default_preset`, `presets` | Split selection/defaults from mandatory restrictions; retain CLI override behavior only for overridable defaults. |
| `requirements.{source,create_threat_model,standalone_audit}` | Engine catalog resolution and workflow configuration; legacy key spelling does not authorize report/workflow renaming. |
| `llm_context.documents` | Engine admitted organization documents and provenance. |
| `llm_policy.{permitted_data_classes,approval_required_actions}` | Currently agent-consumed through effective config; Analyzer distribution rejects this block. Define engine policy enforcement before transfer; never silently drop it. |
| `security_coach.{enabled_by_default,max_requirements_per_topic,baseline,inherit_default_topics,topics}` | Advisor prompt coaching and data. |
| `analyst.{required_packages,default_packages,allow_exploration}` | Analyzer focused-analysis policy; preserve required package enforcement and exploration prohibition. |
| `actors.{inherit_defaults,disable,enable,add}` | Engine actor catalog and terminal organization exclusions. |
| `abuse_cases.{inherit_defaults,disable,add}` | Engine technical/business catalog and schema validation. |
| `mcp.servers` | Advisor host packaging; no new MCP integration is implied. |
| `hooks` | Advisor host packaging and existing explicit profile ownership rules. |

Preset fields also require explicit dispatch; none is assumed compatible solely because a similarly named CLI switch exists.

| Preset field set | Owner / required mapping |
| --- | --- |
| `base_mode` | Engine depth with resolved model/profile identity. |
| `target.{repo,repo_path,output_dir}` | Trusted operator source/output selection; preserve source admission and external storage defaults. |
| `outputs.{yaml,sarif,pdf,pentest_tasks,pentest_format,pentest_target}` | Engine export selection; host handles optional prerequisite guidance. |
| `scan.{incremental,scan_manifest}` | Engine scanning and retained-state compatibility; public gap remains until verified. |
| `requirements.{enabled,gate.{mode,gate_on,priority_floor}}` | Engine requirement workflow and gate; preserve explicit CLI precedence. |
| `context.document_ids` | Engine admitted document selection. |
| `quality.{qa_review,architecture_enrichment,architect_review,attack_walkthroughs}` | Engine analysis/QA controls; preserve disabled/auto/enabled distinctions. |
| `verification.{evidence_recheck,generate_pentest_verification_tasks}` | Engine evidence and export controls. |
| `guardrails.{max_wall_time,soft_budget_usd,max_cost_usd,max_resumes,tracing,verbose_report,fail_on}` | Engine resource/completion/release behavior; preserve deprecated-price-key precedence and distinguish soft guidance from enforceable hard budgets. |

### P4.1 admitted staging configuration

P4.1 now separates the current composed score package's Advisor settings from a versioned, engine-only projection. Host banner, surface assembly, hooks and MCP declarations remain on the existing packaging path. The selected host configuration retains display pricing, host logging and compatible default-preset precedence; unsupported global blocks fail. `compatibility.core` checks the selected original Advisor core, while the engine envelope independently pins its exact engine version. CLI/environment preset selection cannot overwrite profile-wide policy.

The new public Analyzer `organization-config` API validates and inspects base-mode presets and the two `policy` fields, and executes only its declared score workflow. A nonempty URL allowlist restricts remote Git targets before Git or credentials. Score has no model calls or assessment depth; the Opus restriction cannot authorize models, and base mode remains an inspectable assessment default. Every other ledger field still requires its explicit consumer mapping and is rejected on the composed path. External runtime profile overrides are also rejected until host validation/splitting exists. The legacy `--source` workflow remains available. The [offline evidence](composition-offline-evidence-2026-10-18.md#organization-configuration-dispatch-follow-up) records exact local pins, checks and limits; this is not complete configuration or P4 migration.

## Permissions, artifacts, and cleanup

The [permission catalog](../../../data/required-permissions.yaml) records prompt suppression, not containment. The migration retains existing source/URL guards and engine validation; installed invocation coverage must be checked separately.

| Existing permission surface | Consumer / destination and replacement prerequisite |
| --- | --- |
| `Read(REPO_ROOT/**)` | Source and evidence consumers; engine admits source outside the model. |
| `Write(REPO_ROOT/docs/security/business-context.md)` | Early context persistence; retain explicit validated save behavior and run-only imported context. |
| `Read(PLUGIN_ROOT/**)`, `Edit(PLUGIN_ROOT/**)` | Host resources and explicit maintainer edits; installed engine environment needs separate protection and must not become a model-selected write target. |
| `Read(HOME/.claude/projects/**)` | Host session/model discovery; keep host transcript handling in Advisor rather than an undeclared engine prerequisite. |
| `Read/Write(OUTPUT_DIR/**)` and `Read/Write(OUTPUT_DIR/.*)` | Result and sidecar consumers; public operations replace private reads. Direct dotfile coverage is distinct from recursive coverage. |
| `Read/Write(REPO_ROOT/.eval-out/**)` | Existing evaluation workflow remains until public replacement. |
| `Write(REPO_ROOT/.appsec-triage/**)` | Retained user triage outside generated results; never include in engine cleanup. |
| `Write(REPO_ROOT/docs/known-threats.yaml)` | Explicit accepted-risk promotion only; preserve existing entries and schema validation. |
| `Edit(REPO_ROOT/**)` | Explicit remediation requested by the operator, scoped to selected findings. Listing a result never grants this action. |
| `Bash(*)` | Existing host prompt-suppression rule; new launcher uses structured arguments and exact pinned interpreter. This inventory neither widens execution authority nor treats shell coverage as publication/setup consent. |

| Artifact or state consumer | Contract and destination | Gap / deletion prerequisite |
| --- | --- | --- |
| Canonical YAML, Markdown, figures, SARIF, Threat Dragon, pentest outputs | Engine owns validation/render/export; host presents verified artifacts | `results` verifies existing deliverables but does not provide every historical query, repair or re-export operation. Map kinds, versions, names, provenance and optional export tools. |
| Assessment storage and legacy import | `shared/assessment_location.py`, `runtime/legacy_import.py`; engine-owned location/import API with host presentation | Advisor and Analyzer storage namespaces differ. Resolve explicitly before cutover; do not change defaults implicitly or reinterpret state. |
| Private lifecycle and accepted receipts | `.assessment-state.json`, `.assessment-work/`, output locks | Analyzer public lifecycle only; finish/cancel old runs before switch and keep rollback state compatible or use a fresh output. |
| Successful-run cleanup | [Cleanup whitelist](../contracts/cleanup-whitelist.md), `runtime/runtime_cleanup.py` | Preserve exact scope, opt-outs and failure-time diagnostic retention. Require public cleanup and native Windows lock/cancellation evidence. |
| Retained audit, cache and decisions | [Audit artifacts](../contracts/audit-artifacts.md), `.appsec-cache/`, `.architect-review.json`, support receipts | Never infer deletability from a directory being private; preserve accepted corrections, provenance, incremental IDs and user decisions. |
| Stale-state cleanup | `runtime/check_state.py`, `clean-run-state` | Different operation from cancellation; preserve ownership and refusal while a live owner holds the lock. |
| Terminal live markers | `agent_logger.clear_terminal_active_tool_calls`, `.active-tool-calls/` | Settle lifecycle and budget counters before deletion; nested stops must not clear parent state. |
| Rebuild and changelog history | Controller and cleanup contract | Archive changelogs before deletion; archive failure must abort rebuild. |
| Support bundle / publication receipts | `runtime/diagnostic_bundle.py`, `runtime/report_plugin_issue.py` | Keep local preparation separate from explicit reviewed publication; preserve redaction and receipts. |

## Reconciliation since the extraction source

The Analyzer extraction record freezes Advisor at `d21eaac102cea6b8878ba0837e40c7a8fd47358d`. Inspect changes through the Advisor revision above, including release merges, rather than importing history again. The table groups duplicated hotfix commits by outcome.

| Advisor change | Producing path / invariant | Comparison and remaining action |
| --- | --- | --- |
| `e8646e62` configurable component concurrency | `runtime/assessment_jobs.py`, controller parser/budget/pool, `run-headless.sh`; bounded explicit component concurrency | Analyzer implements the same operator control through `--max-parallel`, `AssessmentBudget.max_parallel`, and `ThreadPoolExecutor(max_workers=jobs.budget.max_parallel)`, with profile/budget/pool tests. Defaults and range differ (Advisor 3 and 1–4; Analyzer 2 and 1–16). Map the existing operator setting deliberately and verify installed resume compatibility; absence of the old symbol name is not missing functionality. |
| `bde4f4d6` monitor termination | `runtime/assessment_console.py`, primary skill; monitor ends with run without stopping its owner | Advisor-only integration remains relevant. Preserve it when the new entry skill binds to public progress/status and verify independent monitor/owner termination. |
| `d6334f07` release checks and assessment output names | `renderers/render_completion_summary.py`, primary skill, report-anatomy proposal and affected tests | Analyzer's committed summary contains current `security-assessment` export names but also legacy plugin guidance in another code path. Names alone do not prove the active standalone/plugin completion behavior. Compare relevant paths and installed outcomes; keep affected regressions with their owner. |
| `7b78f05e` / `4caa84dc`, `ffb331d9` / `4e548c81` clone-test hotfixes, plus initial related correction in `d6334f07` | `tests/test_security_score.py`; fake clone handlers must intercept only clone operations | All three committed Analyzer fake handlers contain `if "clone" not in argv`; this specific correction is present by static comparison. No scanner algorithm change is implied. |
| `9f1854f4`, `c007ece5` examples and release documentation | User guides/changelog; current assessment identity | Advisor documentation remains authoritative for current users. Update composed installation guidance only after packaging and workflow compatibility exist. |
| `7a72d646`, release/merge commits, `85c3ea0f` plan | Release metadata, ancestry and planning | Not engine producer fixes. Do not import Advisor version/tag identity into Analyzer or treat a plan commit as qualification evidence. |

This is a reconciliation ledger, not closure of A7. A later inspection of clean Analyzer revision `7602a7fb3d5dd0717746ed235762cbea206306ab` confirmed component concurrency through `--max-parallel`, `AssessmentBudget.max_parallel` and the component thread pool, with existing profile/pool tests. Advisor defaults to 3 and allows 1–4; Analyzer defaults to 2 and allows 1–16, so migration must map the settings explicitly. Completion guidance still needs installed consumer evidence. The original inventory did not execute the listed engine tests.

## Bounded implementation backlog

Each item names the owner and evidence needed to release its dependency. The approved offline sequence permits P2–P4 work before A7; qualification remains required for release, public cutover, and deletion.

| Item | Owner / work | Evidence and dependency |
| --- | --- | --- |
| G1 | Analyzer: finish provider qualification and relevant Advisor fix reconciliation | Complete authorized Claude/direct API/fixed gateway assessments, declared quality thresholds, route/spend evidence, installed consumer compatibility, qualified immutable release. Blocks release, public cutover, and removal. |
| P2.1 | AppSec Skills: score transfer | Source workflow and dependency metadata are committed in AppSec Skills `557f16fa07beead21267a3b220f7e4d608e11b2c`. The opt-in Advisor binding passed an installed real-engine Linux replay for text/JSON/YAML, scored/undetermined/source-error outcomes, schema validation and source preservation. Claude Code 2.1.302 discovers the single skill; setup and session-only loading are documented in the staging runbook. Complete legacy option/input parity, live Claude invocation and native platform acceptance remain open. |
| P2.2 | Analyzer and AppSec Skills: AuthN/AuthZ and focused-analysis gaps | Portable source workflows are committed in AppSec Skills at the revision above. Missing legacy options and lifecycle/contract gaps remain explicitly recorded; installed host binding and compatibility acceptance are open. Do not switch public entry instructions yet. |
| P2.3 | Analyzer: requirements and result-consumer APIs | Remote catalogs, verification, resume, query/health, triage, diagnosis, repair, cleanup and re-export mapped individually. Unresolved rows block only their own replacement/deletion after G1. |
| P3.1 | Advisor: composition schema, selected lock and explicit inclusion manifest | Schema and staging builder are committed in Advisor `3cd82cd4`; synthetic and real-engine offline evidence is recorded. A complete reviewed production lock, exact release artifacts, and build-tool/dependency qualification remain open. |
| P3.2 | Advisor: deterministic assembler and organization packaging | Deterministic staging assembly is implemented in `3cd82cd4`. The organization packager now accepts the assembled tree, preserves pinned engine/bootstrap and retained portable resources, applies host branding and surface selection, retains original metadata and regenerates the delivered inventory. Unmapped runtime policy is refused pending P4 dispatch. Focused evidence is recorded in the [offline evidence](composition-offline-evidence-2026-10-18.md#organization-packaging-follow-up). |
| P3.3 | Advisor: setup, preflight and launcher | Explicit offline setup, read-only preflight, and pinned launcher are implemented in `3cd82cd4` and checked with synthetic and real wheels on Linux. An opt-in score binding now preserves portable workflow provenance and rejects incompatible score capabilities. Other public host bindings, native macOS/Windows verification and upgrade/rollback remain open. |
| P3.4 | Component owners and Advisor: supported runtime matrix | Choose Python versions and OS/version/architecture combinations from wheel and native execution evidence; Linux, macOS and native Windows remain required. Installed read-only/path-with-spaces, tamper/mismatch, rollback, locks, cancellation, cleanup and shadow-PATH cases are pending. |
| P4.1 | Advisor/Analyzer: explicit organization configuration dispatch | The current score staging surface now separates host settings and the engine projection, validates the pinned public interface, preserves supported selection/default semantics and enforces applicable remote-target restrictions. Missing support remains an explicit error; full assessments, external runtime profiles and remaining ledger fields are not migrated. See the [configuration evidence](composition-offline-evidence-2026-10-18.md#organization-configuration-dispatch-follow-up). |
| P4 | Analyzer public operations and Advisor host adapters | Replace every private hook/UI consumer, split all settings, demonstrate direct-CLI enforcement of mandatory restrictions, update installed permissions. Keep baseline adapter. |
| P5 | Advisor and component owners: qualification | Exact-archive install/upgrade/rollback on each supported platform, controlled canonical replays, primary Claude entry, preserved settings/results/decisions and state limits. No model prose equality requirement. |
| P6 | Advisor release and scoped cleanup | Recheck marketplace ZIP/digest syntax and host minimum against official documentation when implementing; publish qualified bytes only with authorization, switch catalog separately, then remove only covered producers in separate commits. |

P1 establishes no Python/OS support, live qualification, publication, or cutover. Offline P2 source preparation and P3 staging primitives are implemented as described above; their installed integration and phase acceptance criteria remain open. P4.1 configuration dispatch is implemented only for the declared score staging surface; remaining configuration and public hook/result migrations are open. The broad route audit was stopped with operator approval at 442 of 444 measured test modules; three completed modules recorded failures with unestablished causes and baseline status. This is incomplete audit evidence, not a passing full-suite result. A7 evidence still gates the release boundary.
