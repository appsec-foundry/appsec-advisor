# Schemas

JSONSchema (Draft 2020-12) contracts for every structured artifact the plugin
produces or consumes. The schemas are the **single source of truth** for the
data contracts; `scripts/validators/validate_intermediate.py` loads them at runtime
and enforces runtime artifacts via `jsonschema`; plugin-shipped config/data
catalogs are checked by dedicated validators such as `scripts/validators/validate_config.py`.
The numbered Markdown API in `.recon-summary.md` is defined by
`agents/shared/recon-output-template.md` and validated by the producer and
controller through `scripts/validators/validate_recon_summary.py`. The ordered Markdown
API in `.threat-modeling-context.md` is defined by the legacy resolver's output
template, emitted deterministically on context-v2, and validated through
`scripts/validators/validate_threat_modeling_context.py`; neither contract is JSONSchema.

| Schema | Artifact | Written by | Read by |
|--------|----------|------------|---------|
| `agent-call-lifecycle.schema.json` | `$OUTPUT_DIR/.active-tool-calls/agent-lifecycle.json` | `scripts/runtime/agent_logger.py` through `scripts/runtime/agent_lifecycle.py` | lifecycle, budget, deterministic join, and progress telemetry |
| `agent-call-budget-state.schema.json` | `$OUTPUT_DIR/.budget-state.json` | `scripts/runtime/budget_watchdog.py` | call-scoped threshold emission and current-claim consumers |
| `agent-call-budget-marker.schema.json` | `$OUTPUT_DIR/.budget-warning`, `$OUTPUT_DIR/.budget-critical` | `scripts/runtime/budget_watchdog.py` | actionable call and controller-claim identity for transient budget signals |
| `stride-progress.schema.json` | `$OUTPUT_DIR/.progress/<component-id>.json` | `scripts/runtime/write_stride_progress.py` | current claim-bound STRIDE progress and status rendering |
| `stride.schema.yaml` | `$OUTPUT_DIR/.stride-attempts/<component-id>.attempt-<n>.json`, promoted to `$OUTPUT_DIR/.stride-<component-id>.json` | `appsec-stride-analyzer-v2` | `scripts/orchestrator/stride_dispatch_waves.py`, then controller merge |
| `stride-evidence-bundle.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/evidence-bundle.json` | `scripts/contexts/build_stride_evidence_bundles.py` | context-v2 manifest validator and STRIDE analyzer |
| `stride-component-business-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/business-context.json` | `scripts/contexts/build_stride_evidence_bundles.py` | context-v2 manifest and context-plan validators and STRIDE analyzer when selected |
| `stride-component-architecture-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/architecture-context.json` | `scripts/contexts/build_stride_evidence_bundles.py` | context-v2 manifest and context-plan validators and STRIDE analyzer when selected |
| `stride-component-security-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/*-context.json` for controls, actors, boundaries, requirements, prior findings, and known threats | `scripts/contexts/build_stride_evidence_bundles.py` | context-v2 manifest and context-plan validators and STRIDE analyzer when selected |
| `stride-component-context-plan.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/context-plan.json` | `scripts/orchestrator/orchestration_controller.py` | context-v2 action validator and STRIDE analyzer |
| `stride-component-repository-roots.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/repository-roots.json` | `scripts/orchestrator/orchestration_controller.py` | context-v2 action validator and STRIDE analyzer |
| `stride-analyst-context.schema.json` | `$OUTPUT_DIR/.stride-analyst-context.json` | `appsec-control-analyst` | `scripts/validators/validate_intermediate.py` checks routing hints against finalized component ownership before `scripts/orchestrator/build_stride_dispatch_manifest.py`; carries only bounded human-facing business attributes per component |
| `recon-signals.schema.json` | `$OUTPUT_DIR/.recon-signals.json` | `appsec-recon-scanner` | actor resolution, trust-boundary input, and STRIDE bundle construction; v2 carries structured, repository-validated evidence locations |
| `trust-boundary-selection.schema.json` | `$OUTPUT_DIR/.dispatch-context/trust-boundary-selection.json` | `scripts/contexts/prepare_trust_boundary_context.py` | STRIDE context dispatch and `scripts/model/build_threat_model_yaml.py` |
| `stride-repository-registry.schema.json` | `$OUTPUT_DIR/.stride-repository-registry.json` | context-v2 controller via `contexts/build_stride_evidence_bundles.py` | evidence-bundle builder, manifest validator, and component repository projector |
| `stride-dispatch-manifest.schema.yaml` | `$OUTPUT_DIR/.stride-dispatch-manifest.json` | `scripts/orchestrator/build_stride_dispatch_manifest.py` | Level-0 dispatcher and `scripts/validators/validate_dispatch_manifest.py` |
| `stride-dispatch-waves.schema.json` | `$OUTPUT_DIR/.dispatch-waves.json` | `scripts/orchestrator/stride_dispatch_waves.py` | context-v2 controller and bounded STRIDE join waiter |
| `orchestration-action.schema.json` | ephemeral controller stdout | `scripts/orchestrator/orchestration_controller.py` | thin skill runtimes |
| `merge-candidates.schema.json` | `$OUTPUT_DIR/.merge-candidates.json` | `scripts/model/merge_threats.py collect` | threat merger and `scripts/model/merge_threats.py finalize` |
| `merge-review-context.schema.json` | `$OUTPUT_DIR/.merge-context/candidates.json` | context-v2 controller | focused threat merger |
| `threats-merged.schema.yaml` | `$OUTPUT_DIR/.threats-merged.json` | orchestrator Phase 9 | diagram annotator, YAML/SARIF exporters, changelog writer, triage validator |
| `evidence-verification.schema.json` | `$OUTPUT_DIR/.evidence-verification.json` | `appsec-evidence-verifier` | evidence guard and Phase 10b triage |
| `evidence-verifier-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/post-stride/evidence-sample.json` | `scripts/contexts/build_post_stride_contexts.py` | evidence verifier and controller-owned canonical annotation |
| `post-stride-generated-threats.schema.json` | `$OUTPUT_DIR/.dispatch-context/post-stride/generated-threats.json` | `scripts/contexts/build_post_stride_contexts.py` | post-STRIDE synthesizer |
| `post-stride-proposed-mitigations.schema.json` | `$OUTPUT_DIR/.dispatch-context/post-stride/proposed-mitigations.json` | `scripts/contexts/build_post_stride_contexts.py` | post-STRIDE synthesizer |
| `abuse-case-deriver-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/abuse-cases/deriver.json` | `scripts/model/derive_abuse_cases.py` | the abuse-case deriver job (thorough depth) |
| `abuse-case-verifier-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/abuse-cases/<candidate-id>.json` | `scripts/contexts/build_abuse_case_contexts.py` | one abuse-case verifier job |
| `merge-decisions.schema.json` | `$OUTPUT_DIR/.merge-decisions.json` | `appsec-threat-merger` (Phase 9) | `scripts/model/merge_threats.py finalize` |
| `triage-flags.schema.yaml` | `$OUTPUT_DIR/.triage-flags.json` | `appsec-triage-validator` (Phase 10b) | Phase 11 rendering, QA reviewer |
| `threat-model.output.schema.yaml` | `$OUTPUT_DIR/threat-model.yaml` | orchestrator Phase 10/11 | CI/CD, DefectDojo, SonarQube, cross-repo discovery |
| `known-threats.schema.yaml` | `docs/known-threats.yaml` (user-supplied input) | analyzed team | `contexts/build_threat_modeling_context.py`, then the focused STRIDE analyzer |
| `related-repos.schema.yaml` | `docs/related-repos.yaml` (user-supplied input) | analyzed team | `scripts/contexts/load_related_repos.py` |
| `cross-repo-register.schema.json` | `$OUTPUT_DIR/.cross-repo-register.json` | `scripts/contexts/build_cross_repo_register.py` | STRIDE dispatcher, Phase 11 §5/§7 renderer |
| `actors-repo.schema.yaml` | `<repo>/.appsec/actors.yaml` | analyzed team | `scripts/model/resolve_actors.py` |
| `actors-discovered.schema.yaml` | `$OUTPUT_DIR/.actors-discovered.json` | `appsec-actor-discoverer` | `scripts/model/resolve_actors.py` |
| `actors-merged-static.schema.yaml` | `$OUTPUT_DIR/.actors-merged-static.json` | `scripts/model/resolve_actors.py` | `appsec-actor-discoverer` |
| `actors-resolved.schema.yaml` | `$OUTPUT_DIR/.actors-resolved.json` | `scripts/model/resolve_actors.py` | actor slicer, report composer, architect review |
| `context-routing-catalog.schema.json` | `data/context-routing-catalog.yaml` | plugin maintainers | semantic validator and context-v2 resolver |
| `context-routing-bindings.schema.json` | `data/context-routing-bindings.json` | plugin maintainers | semantic validator and context-v2 resolver |
| `context-effective-plan.schema.json` | `$OUTPUT_DIR/.context-routing-plan.json` | `scripts/contexts/context_routing.py` | local audit, active delivery binding, and migration diagnostics |
| `context-effective-plan-receipt.schema.json` | `$OUTPUT_DIR/.context-routing-plan.receipt.json` | `scripts/contexts/context_routing.py` | exact-byte plan freshness validation |
| `recon-patterns.schema.json` | `$OUTPUT_DIR/.recon-patterns.json` | `scripts/analyzers/recon_patterns.py` | receipted recon-scanner input |
| `recon-summary-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/architecture/recon-summary-context.json` | `scripts/contexts/build_architecture_analysis_context.py` | actor, architecture, and exceptional triage roles |
| `architecture-route-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/architecture/route-context.json` | `scripts/contexts/build_architecture_analysis_context.py` | architecture analyst |
| `threat-summary.schema.json` | `<OUTPUT_DIR>/threat-summary.json` (when `--format json` or `both`) | `scripts/model/aggregate_threat_summary.py` | External dashboards / internal reporting jobs |
| `analyst-request.schema.json` | `request.json` in an on-demand threat analysis job root | on-demand threat analysis controller | `scripts/validators/validate_analyst.py` |
| `analyst-state.schema.json` | `state.json` in an on-demand threat analysis job root | on-demand threat analysis controller | `scripts/validators/validate_analyst.py` |
| `analyst-snapshot.schema.json` | `snapshot.json` in an on-demand threat analysis job root | on-demand threat analysis snapshot capture | `scripts/validators/validate_analyst.py` |
| `analyst-context.schema.json` | `context.json` in an on-demand threat analysis job root | `scripts/contexts/build_analyst_context.py` | analyst controller and prompt builder |
| `analyst-response.schema.json` | untrusted model reply of one analysis pass | model session via `scripts/runtime/analyst_host.py` | `scripts/validators/validate_analyst.py` before any use |
| `analyst-result.schema.json` | `result.json` in the job root and `analyst-result.json` in the chosen output | `scripts/orchestrator/analyst_controller.py` | `scripts/renderers/render_analyst_report.py`, CI consumers |
| `analyst-feature.schema.json` | developer-chosen feature-context file | `scripts/contexts/analyst_questions.py` on explicit save | analyst controller (`--feature`) |
| `analyst-catalog.schema.json` | `data/analyst-questions.yaml` and custom question packages | plugin maintainers, organizations | `scripts/contexts/resolve_analyst_catalog.py` |
| `analyst-methodology.schema.json` | `data/analyst-methods/*.yaml` and custom methodology profiles | plugin maintainers, organizations | `scripts/contexts/resolve_analyst_catalog.py` |
| `analyst-limits.schema.json` | `data/analyst-limits.yaml` | plugin maintainers | `scripts/contexts/resolve_analyst_catalog.py` |

## Design notes

- Schemas capture **structural** invariants (required fields, enum values,
  field types, regex patterns). They are enforced on every write by the
  producing agent (`validators/validate_intermediate.py <type> <path>`).
- Rules that JSONSchema cannot express in Draft 2020-12 remain as Python
  post-checks inside `validators/validate_intermediate.py`:
  - Sequential `T-NNN` numbering in `threats-merged` (`T-001`, `T-002`, …)
  - Uniqueness of `t_id` across the merged list
  - Redaction rule on `hardcoded_secrets[].snippet` (must contain `****`,
    may not expose more than 4 chars of the original secret)
  - `scenario` in stride findings must be ≥ 10 non-whitespace chars
  - Sequential `TF-NNN` numbering and uniqueness in `triage-flags`
  - `summary.total_flags` / `warnings` / `info` counters consistent with
    the actual `flags[]` array in `triage-flags`
  - Uniqueness of `id` across the user-supplied `known-threats.yaml`
- Error stubs (objects with `parse_error`) bypass the full schema; they are
  a known failure-state contract between a sub-agent and the orchestrator.

## Versioning

Each schema carries a `$id` of the form
`https://appsec-advisor/schemas/<name>.schema.yaml` and the
`https://json-schema.org/draft/2020-12/schema` meta-schema. Breaking changes
require a version bump in the schema `$id` path (e.g. `/v2/<name>.schema.yaml`)
and a coordinated update across the producing agent, the validator, and any
downstream consumer.
