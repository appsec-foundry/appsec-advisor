# Schemas

JSONSchema (Draft 2020-12) contracts for every structured artifact the plugin
produces or consumes. The schemas are the **single source of truth** for the
data contracts; `scripts/validate_intermediate.py` loads them at runtime
and enforces runtime artifacts via `jsonschema`; plugin-shipped config/data
catalogs are checked by dedicated validators such as `scripts/validate_config.py`.
The numbered Markdown API in `.recon-summary.md` is defined by
`agents/shared/recon-output-template.md` and validated by the producer and
controller through `scripts/validate_recon_summary.py`. The ordered Markdown
API in `.threat-modeling-context.md` is defined by the context resolver's
output template and validated at the same two boundaries through
`scripts/validate_threat_modeling_context.py`; neither contract is JSONSchema.

| Schema | Artifact | Written by | Read by |
|--------|----------|------------|---------|
| `stride.schema.yaml` | `$OUTPUT_DIR/.stride-<component-id>.json` | `appsec-stride-analyzer` | orchestrator Phase 9 merge |
| `stride-evidence-bundle.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/evidence-bundle.json` | `scripts/build_stride_evidence_bundles.py` | context-v2 manifest validator and STRIDE analyzer |
| `stride-component-business-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/business-context.json` | `scripts/build_stride_evidence_bundles.py` | context-v2 manifest and context-plan validators and STRIDE analyzer when selected |
| `stride-component-architecture-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/architecture-context.json` | `scripts/build_stride_evidence_bundles.py` | context-v2 manifest and context-plan validators and STRIDE analyzer when selected |
| `stride-component-security-context.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/*-context.json` for controls, actors, boundaries, requirements, prior findings, and known threats | `scripts/build_stride_evidence_bundles.py` | context-v2 manifest and context-plan validators and STRIDE analyzer when selected |
| `stride-component-context-plan.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/context-plan.json` | `scripts/orchestration_controller.py` | context-v2 action validator and STRIDE analyzer |
| `stride-component-repository-roots.schema.json` | `$OUTPUT_DIR/.dispatch-context/<component-id>/repository-roots.json` | `scripts/orchestration_controller.py` | context-v2 action validator and STRIDE analyzer |
| `stride-analyst-context.schema.json` | `$OUTPUT_DIR/.stride-analyst-context.json` | `appsec-control-analyst` on context-v2; legacy threat analyst otherwise | `scripts/build_stride_dispatch_manifest.py`; carries only bounded human-facing business attributes per component |
| `recon-signals.schema.json` | `$OUTPUT_DIR/.recon-signals.json` | `appsec-recon-scanner` | actor resolution, trust-boundary input, and STRIDE bundle construction; v2 carries structured, repository-validated evidence locations |
| `trust-boundary-selection.schema.json` | `$OUTPUT_DIR/.dispatch-context/trust-boundary-selection.json` | `scripts/prepare_trust_boundary_context.py` | STRIDE context dispatch and `scripts/build_threat_model_yaml.py` |
| `stride-repository-registry.schema.json` | `$OUTPUT_DIR/.stride-repository-registry.json` | context-v2 controller via `build_stride_evidence_bundles.py` | evidence-bundle builder, manifest validator, and component repository projector |
| `stride-dispatch-manifest.schema.yaml` | `$OUTPUT_DIR/.stride-dispatch-manifest.json` | `scripts/build_stride_dispatch_manifest.py` | Level-0 dispatcher and `scripts/validate_dispatch_manifest.py` |
| `orchestration-action.schema.json` | ephemeral controller stdout | `scripts/orchestration_controller.py` | thin skill runtimes |
| `merge-candidates.schema.json` | `$OUTPUT_DIR/.merge-candidates.json` | `scripts/merge_threats.py collect` | threat merger and `scripts/merge_threats.py finalize` |
| `merge-review-context.schema.json` | `$OUTPUT_DIR/.merge-context/candidates.json` | context-v2 controller | focused threat merger |
| `threats-merged.schema.yaml` | `$OUTPUT_DIR/.threats-merged.json` | orchestrator Phase 9 | diagram annotator, YAML/SARIF exporters, changelog writer, triage validator |
| `evidence-verification.schema.json` | `$OUTPUT_DIR/.evidence-verification.json` | `appsec-evidence-verifier` | evidence guard and Phase 10b triage |
| `merge-decisions.schema.json` | `$OUTPUT_DIR/.merge-decisions.json` | `appsec-threat-merger` (Phase 9) | `scripts/merge_threats.py finalize` |
| `triage-flags.schema.yaml` | `$OUTPUT_DIR/.triage-flags.json` | `appsec-triage-validator` (Phase 10b) | Phase 11 rendering, QA reviewer |
| `threat-model.output.schema.yaml` | `$OUTPUT_DIR/threat-model.yaml` | orchestrator Phase 10/11 | CI/CD, DefectDojo, SonarQube, cross-repo discovery |
| `known-threats.schema.yaml` | `docs/known-threats.yaml` (user-supplied input) | analyzed team | `appsec-context-resolver` (Phase 1), STRIDE analyzer |
| `related-repos.schema.yaml` | `docs/related-repos.yaml` (user-supplied input) | analyzed team | `scripts/load_related_repos.py` |
| `cross-repo-register.schema.json` | `$OUTPUT_DIR/.cross-repo-register.json` | `scripts/build_cross_repo_register.py` | STRIDE dispatcher, `coverage_checks.check_cross_repo`, Phase 11 §5/§7 renderer |
| `actors-repo.schema.yaml` | `<repo>/.appsec/actors.yaml` | analyzed team | `scripts/resolve_actors.py` |
| `actors-discovered.schema.yaml` | `$OUTPUT_DIR/.actors-discovered.json` | `appsec-actor-discoverer` | `scripts/resolve_actors.py` |
| `actors-resolved.schema.yaml` | `$OUTPUT_DIR/.actors-resolved.json` | `scripts/resolve_actors.py` | actor slicer, report composer, architect review |
| `context-routing-catalog.schema.json` | `data/context-routing-catalog.yaml` | plugin maintainers | semantic validator and context-v2 resolver |
| `context-routing-bindings.schema.json` | `data/context-routing-bindings.json` | plugin maintainers | semantic validator and context-v2 resolver |
| `context-effective-plan.schema.json` | `$OUTPUT_DIR/.context-routing-plan.json` | `scripts/context_routing.py` | local audit, active delivery binding, and migration diagnostics |
| `context-effective-plan-receipt.schema.json` | `$OUTPUT_DIR/.context-routing-plan.receipt.json` | `scripts/context_routing.py` | exact-byte plan freshness validation |
| `threat-summary.schema.json` | `<OUTPUT_DIR>/threat-summary.json` (when `--format json` or `both`) | `scripts/aggregate_threat_summary.py` | External dashboards / internal reporting jobs |

## Design notes

- Schemas capture **structural** invariants (required fields, enum values,
  field types, regex patterns). They are enforced on every write by the
  producing agent (`validate_intermediate.py <type> <path>`).
- Rules that JSONSchema cannot express in Draft 2020-12 remain as Python
  post-checks inside `validate_intermediate.py`:
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
