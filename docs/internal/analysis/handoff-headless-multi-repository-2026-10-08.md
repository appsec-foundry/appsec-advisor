# Headless multi-repository implementation handoff

This document accompanies the multi-repository development checkpoint on `dev` and records the implementation state on 2026-10-08 for later continuation and failure analysis. It supplements the [implementation plan](implplan-headless-multi-repository-2026-10-07.md) and [approved proposal](../../../specs/changes/headless-multi-repository/proposal.md).

## Current status

The combined headless assessment is not implemented completely and is not available through the public runner. `scripts/run-headless.sh` and `scripts/runtime/resolve_config.py` reject a repeated `--repo` until the combined route exists. No completed combined assessment or user report has been produced. Controlled unit inputs now exercise canonical YAML assembly, standalone Figure 1 and both machine-readable exporters. The remaining work includes implementation, not just verification.

The intended result is one fresh assessment of all explicitly selected local checkouts, with reviewed connections, repository-qualified findings, one combined Figure 1 and consistent exports. There is no primary repository in the new internal scope. Repository membership does not establish a trust boundary.

On 2026-10-08 the operator said not to run end-to-end tests in this session and requested this documentation for later analysis. No full host-driven assessment or end-to-end rendering/export run was executed here. Keep that distinction when reporting readiness.

## Changed implementation

The existing [orchestration controller](../../../scripts/orchestrator/orchestration_controller.py) remains the sole phase and semantic-role authority. The new helpers execute or validate scoped work; they do not select their own pipeline or publish a completed report.

| Area | Files and entry points | Behavior implemented |
| --- | --- | --- |
| Admitted source view | `scripts/runtime/multi_repo_scope.py`; `schemas/multi-repo-scope.schema.json` | Admits 2–16 explicit top-level Git checkouts, rejects duplicate/overlapping roots and output inside sources, captures bounded contained files, supplies redacted slices, and rechecks source state. Root IDs and inventory ordering do not depend on argument order. |
| Model exchanges | `scripts/runtime/assessment_host.py` | Accepts only structured read/complete exchanges. Reads require an allowed repository/file pair and a bounded positive line range. Models receive no filesystem, shell, network-fetch or delegation tools through this exchange. |
| Accepted jobs | `scripts/runtime/assessment_jobs.py`; `schemas/assessment-job-receipt.schema.json` | Binds cached artifacts to role, selector, scope, instructions, schema, context and allowed sources. Revalidates hashes, retrieval ranges and semantic checks before reuse. Reserves calls and cost before creating a transport. |
| Owned session | `scripts/runtime/assessment_state.py`; `schemas/multi-repo-state.schema.json` | Persists run identity, cumulative accounting, original deadline and delivered-file hashes. Resume requires unchanged scope, effective settings and runtime fingerprint. Unknown cost reservations block further resumed dispatch. |
| Shared output lock | `scripts/runtime/acquire_lock.py` | CLI lock writers use a persistent `.appsec-lock.guard` with a nonblocking process lock. A multi-repository session holds it for its lifetime. Linked guards and linked liveness files are rejected on the new session path. Existing liveness classification remains authoritative. |
| Configuration | `scripts/runtime/resolve_config.py::resolve_assessment` | Resolves configuration from each frozen source snapshot and requires compatible effective settings. Uses captured source counts instead of invoking Git in snapshots. Preserves explicit model pins and the Opus ceiling. This does not yet deliver every resolved optional feature to analysis. |
| Discovery | `scripts/runtime/multi_repo_discovery.py` | Retrieves and validates observations for every selected repository, records retrieved ranges and unread paths, shares accounting and supports accepted-job reuse. |
| Connection matching | `scripts/contexts/reconcile_multi_repo_architecture.py` | Namespaces local identities and builds source-backed HTTP/RPC and messaging candidates. Matching names alone do not establish a deployed connection. |
| Connection review | `scripts/contexts/review_multi_repo_connections.py` | Gives the architecture analyst only candidate participants. Validates retrieved evidence before promotion. Resolved messaging retains broker nodes and separate hops; unresolved/rejected candidates remain outside canonical flows. |
| Final components | `scripts/model/finalize_component_inventory.py::finalize_assessment` | Reuses existing per-root finalization and trusted scanners on private frozen snapshots, then namespaces components and qualifies paths/evidence. Literal captured filenames are preferred over glob interpretation. |
| Architecture validation | `scripts/validators/validate_assessment_architecture.py` | Validates scope, finalization fingerprints, owners, nested source hashes and references. Retains existing source and identity-provider authentication checks through per-root projections. |
| Semantic contracts | `scripts/contexts/multi_repo_analysis.py` | Compiles only known local schemas, builds source selections and incident neighborhoods, and validates controls, six-category STRIDE coverage, evidence reviews and boundary candidates. A broker does not grant access to every other consumer. |
| Crossing input | `scripts/contexts/build_trust_boundary_assessment_input.py::build_assessment`, `project_assessment_signal` | Builds qualified crossing inputs from finalized topology and caller-supplied validated source context. Each model job receives one signal and its endpoints. A reviewed cross-repository flow triggers review; it does not establish a trust boundary. Missing source context is rejected. |
| Boundary normalization | `scripts/contexts/prepare_trust_boundary_context.py::promote_assessment_boundaries` | Reuses normalization, enforcement-point consolidation, ID allocation and signal coverage reconciliation. Preserves source owners and explicit unresolved/same-trust dispositions. Equal control names in separate owners do not by themselves merge boundaries. Candidate consolidation now retains both owners when equal relative files and line numbers support the same crossing. |
| Controller stages | `_assessment_session`, `_assessment_architecture`, `_assessment_boundary_candidates`, `_assessment_controls`, `_assessment_stride` | Joins configuration and owned jobs, sequences fresh architecture and scoped semantic stages, independently reviews findings and invokes the existing merger. These are internal functions, not a completed CLI action. |
| Merged findings | `scripts/model/merge_threats.py::merge_assessment` | Reuses intake, deduplication and severity policy with qualified comparison locations, then restores raw relative files and their repository/hash fields. Distinct roots with the same filename remain distinct. A controller-supplied `started_at` keeps merged timestamps stable on resume. |
| Portable output adapter | `scripts/shared/assessment_sources.py`; `scripts/validators/validate_intermediate.py` | Validates the v2 output shape and inventory binding and creates a read-only namespaced presentation view for legacy semantic checks. The canonical assembler, standalone Figure 1 and exporters use its qualified validation. The composer and full rendering pipeline still need migration. |
| Canonical model assembly | `scripts/model/build_threat_model_yaml.py::build_assessment_model`; `tests/test_multi_repo_builder.py` | Rechecks finalized scope, topology, source hashes and finding/control owners. Reuses finding filters, severity policy, mitigation synthesis, weakness pruning, boundary renumbering and secret masking. Builds native v2 metadata without a primary Git checkout or raw invocation. Returns an un-enriched in-memory model; it does not publish or mark completion. Unintegrated configured business context and requirements are rejected. |
| Standalone Figure 1 | `scripts/renderers/figure1_dfd.py`; `tests/test_multi_repo_figures.py` | Validates native v2 inputs before drawing, uses a qualified presentation view and adds repository codes to component cards with a complete source legend. Repository membership creates no boundary line. Existing geometry checks remain active. Full composition, runtime/build projection and large-view integration are still pending. |
| Qualified exports | `scripts/exporters/export_sarif.py`, `scripts/exporters/export_threat_dragon.py`; `tests/test_multi_repo_exports.py` | SARIF uses distinct portable repository URI bases, encoded relative paths and source hashes. Threat Dragon retains repository labels in evidence text and node descriptions and reports its loss of structured source mappings. Both reject invalid v2 models; legacy export behavior remains supported. |
| Fragment admission | `scripts/validators/validate_fragment.py`; `scripts/validators/check_fragment_registry.py` | Registers versioned component, flow and boundary fragments. Qualified fragment validation requires an actual admitted scope; a serialized public inventory cannot grant source access. |
| Qualified build placement | `scripts/model/build_plane.py`; `tests/test_build_plane.py` | Recognizes captured v2 CI paths and owner-qualified presentation locators while preserving literal whitespace and owner-like source directories. Mixed application/build source remains runtime. Unrelated legacy prefixes are not stripped. |
| Maintenance | `scripts/run_tests.py`; `data/required-permissions.yaml`; `docs/internal/contracts/audit-artifacts.md`; permission/cleanup tests | Registers new tests and some source routes, documents existing output permissions and preserves session/receipt state and the lock guard. Dependency-route maintenance is still incomplete. |

The existing `scripts/runtime/analyst_host.py` transport is reused. Its earlier implementation came from separate analyst work; it was not replaced by a second host or pipeline here.

## Artifact versions and ownership

The qualified component and flow sidecars retain their canonical roles `.components.json` and `.data-flows.json` with schema version 2. The component finalization receipt is version 2. Provisional trust-boundary candidates and their assessment input are version 2; normalized boundaries are version 3. Qualified coverage is version 2. The merged document uses `version: 2`, while the proposed canonical YAML uses `meta.schema_version: 2` and a public `source_inventory`. The in-memory canonical assembler now exists; controller publication, enrichment and the complete delivery path remain unimplemented.

New schema files include `schemas/multi-repo-*.schema.json`, `schemas/assessment-job-receipt.schema.json`, `schemas/component-inventory-finalization-v2.schema.json`, `schemas/fragments/components-v2.schema.json`, `schemas/fragments/data-flows-v2.schema.json`, `schemas/fragments/trust-boundary-candidates-v2.schema.json`, `schemas/fragments/trust-boundaries-v3.schema.json`, `schemas/trust-boundary-assessment-input-v2.schema.json`, `schemas/trust-boundary-coverage-v2.schema.json`, `schemas/threats-merged-v2.schema.json` and `schemas/threat-model.output-v2.schema.yaml`.

Private `.assessment-state.json` and `.assessment-work/` belong to the explicitly admitted output directory. `.assessment-work/jobs/` holds accepted model artifacts and receipts. `.appsec-lock.guard` must persist across ordinary liveness-file removal and must never be removed while held. Cleanup tests cover preservation of these names. Source snapshots are private temporary directories containing regular non-executable files; they are not synthetic super-repositories and are never a model working directory.

## Validation evidence

Targeted tests use controlled structured model replies, real scoped exchanges and, where applicable, fresh artificial Git checkouts. Those tests prove the tested admission and stage behavior, not the actual model's analytical quality or full feature availability.

| Check | Recorded result and scope |
| --- | --- |
| Earlier multi-repository stage selection | 160 tests passed before the later configuration, session and crossing additions. This is historical evidence, not a final count for the current tree. |
| Session/controller/cleanup/permission selection | 282 tests passed after session integration. Later state and boundary changes were checked separately. |
| Session state | 24 tests passed after adding non-finite accounting and deadline/schema rejection. Two later hard-link rejection cases passed separately. |
| Ordinary lock compatibility | 62 existing `test_acquire_lock_heartbeat.py` cases passed after serialization was introduced. |
| Boundary normalization and semantic adapters | 144 tests passed across `test_prepare_trust_boundary_context.py`, `test_multi_repo_boundaries.py` and `test_multi_repo_analysis.py` after extracting shared coverage reconciliation. |
| Controller crossing jobs | Five new cases passed for neutral/renamed inputs, unresolved/same-trust dispositions and foreign endpoints. Four promotion/coverage cases then passed after promotion checks were added. |
| Shared validation | `make validate` passed after the assembler, qualified exporters and source-guard additions. |
| Python lint | `make lint` passed after the assembler, qualified exporters and source-guard additions. |
| Canonical builder and standalone figures | 1,223 tests passed across the new builder/figure cases and existing YAML builder, Figure 1 and paged-detail modules. This covers controlled inputs and legacy compatibility, not the public runner or a live combined assessment. |
| Export compatibility | 151 tests passed across new qualified export cases and existing SARIF/Threat Dragon modules before adding the final owner/reference guard. |
| Final qualified source selection | 54 tests passed across source validation, builder, exports, standalone figures and internal controller after adding cross-owner and endpoint checks. |
| Build placement and consumer checks | 64 tests passed across build placement, canonical builder, qualified figures, existing build-view composition and supply-chain view cases after correcting the resolved business-context configuration keys. Later literal-path cases were checked separately. |
| Boundary evidence consolidation | 125 tests passed across existing normalization and qualified-boundary cases, including renamed inputs with the same file and line in both repositories. |
| Complete dependency-route audit | Not completed. Its complete measurement includes end-to-end modules, whose execution the operator deferred. Earlier focused/cached measurements do not replace this audit. |
| End-to-end assessment, rendering and exports | Not executed; explicitly deferred by the operator for this session. |

An earlier live discovery-only probe with Claude Code 2.1.292 and Haiku returned two components and one connection candidate from two artificial checkouts in four calls at USD 0.067055. An earlier host probe advertised/emitted only `StructuredOutput`. Neither probe produced a complete threat model, Figure 1 or export, and neither establishes retention behavior. Do not promote this evidence into full acceptance.

## Review corrections

A review of this checkpoint found defects in the existing stages. The following corrections carry regression tests that fail on the checkpoint and pass after the change.

| Area | Corrected behavior |
| --- | --- |
| Admission | `git status` runs with every repository-configured filter driver disabled and submodules ignored, so admission and `verify_unchanged()` never execute a selected repository's filter commands. A driver name that cannot be overridden stops admission. |
| Source slices | Lines end only at LF, as in Git and grep. A masked multi-line secret keeps its redacted text on its first line and empty lines after it, so later evidence lines keep their source line numbers. |
| Broker grants | A shared broker remains one node. A job about a producer or consumer receives only the broker paths of its own incident connections; `project_assessment_signal` now requires the canonical flow list for that projection. The broker's own job still sees every topic it carries. |
| Messaging crossings | The cross-repository review signal compares a connection's outer sender and receiver repositories, not each hop's endpoints. Both broker hops of a cross-repository connection therefore require boundary review. |
| Merged findings | Deduplication runs separately per review verdict. A refuted or unproven duplicate can no longer absorb a verified finding at the same location. |
| STRIDE contract | `cwe` is a required CWE string in `multi-repo-stride.schema.json`, matching the merged contract, so a missing CWE fails at job acceptance instead of aborting the merge. |

Review findings that remain open: whole-scope admission still fails on a tracked symlink, a submodule or an untracked nested repository; overlap and output containment checks are lexical and miss case-insensitive or alias mounts; untracked credential files with unlisted names can be captured and are protected only by masking; SARIF absence evidence assigns the anchor's hash to every searched file; `.assessment-state.json` accounting is not bound to receipts. The implementation plan items for a per-root repository trust preflight, per-source secret scanning, decision entries, context-routing budgets and `related-repos.yaml` semantics are also not yet covered by the list below.

## Remaining implementation

Continue in the existing controller and retain all production schema, QA and completion gates. Do not replace them with placeholder prose or write `meta.enrichment_pass` directly.

1. Wire the public repeated-`--repo` route and structured argument transport only with the complete assessment path. Preserve single-repository behavior and reject unsupported combinations before dispatch.
2. Integrate remaining per-root deterministic scans, qualified source context, deployment facts, actors, workload/zone identity and target-owned declarations. Complete namespace/reference rewriting before receipts. Boundary jobs currently require a caller-supplied context; there is no production combined-context loader.
3. Deliver local business context, known threats, organization configuration and configured requirements under explicit ownership. Finish synthesis, triage, actor attribution, abuse-case and architectural-review integration. Do not silently ignore settings that the resolver accepts.
4. Wire the in-memory canonical v2 assembler into controller staging and publication. Integrate qualified attack-surface/context producers, then run the real deterministic emitter pass, enrichment receipt, mitigation quality and completeness gates. The assembler deliberately carries no enrichment receipt and records abuse verification as not_run until its producer completes.
5. Connect the read-only presentation adapter to the composer, pregeneration and runtime/build projections. Standalone native-v2 Figure 1 supports qualified cards and legends, but that alone does not establish complete rendering. Preserve repository annotations, all topology, contextual encoding and existing geometry/QA gates. Do not turn repositories into trust zones.
6. Wire the implemented qualified SARIF/Threat Dragon exporters into publication and finish follow-on readers. SARIF URI bases use appsec-repository://<repository-id>/ and require a consumer-supplied checkout mapping; they are not local filesystem roots. Keep machine-local source mappings separate from portable identifiers. Unsupported v2 readers must fail clearly instead of treating a qualified location as a single-root path.
7. Complete normalization/ID persistence for unchanged-state resume, terminal/status handling and publication. A session helper and accepted model jobs alone are not a complete resume path.
8. Finish source-to-test routes and exact requirement bindings, rerun applicable shared checks and the required route audit, and update user documentation and normative promises when behavior is delivered. End-to-end validation remains deferred as requested.

Both branch and worktree test plans were inspected. They include unrelated work and end-to-end modules; the checks executed here used direct task-specific selections instead. No full suite or complete route measurement was run.

Route follow-up includes the new tests' existing producers and resources, original schemas loaded by the contract compiler, source guards and role instruction files. Existing cached route measurements cover earlier trees only. Add a focused finalizer regression for literal filenames containing glob characters; the literal-preference change currently lacks its own dedicated finalizer case.

## Investigation notes

If repeated `--repo` is rejected, that is the interim guard in `scripts/run-headless.sh` and `resolve_config.py`; the multi-root route has not been added. Do not diagnose this as a model failure.

If resume fails, inspect the bounded local `.assessment-state.json` identity and accounting fields and the matching job receipt. Changed sources/settings/runtime, an expired original deadline, unknown cost or altered delivered bytes deliberately stop reuse. Do not clear reservations, extend deadlines or rewrite receipt hashes to force continuation.

If boundary review fails, inspect the immutable input fingerprint, component fingerprint, signal endpoint/flow IDs, covered signal IDs and qualified evidence. Each claimed source line must have been retrieved by that job. Shared candidate keys are namespaced during combination. A normalized boundary and its coverage audit must agree; unresolved signals remain explicit.

If identical relative files appear to merge, trace `source_key`, component ownership and the merger's qualified comparison projection before changing report output. Check the final owner/reference checks in validate_portable_model as well as stage checks. The assembler, standalone Figure 1 and exporters have scoped adapters; full composer, emitter and publication migration remains unfinished.

Review the checkpoint's committed file list and subsequent working-tree changes before continuing. The working tree contains unrelated changes, including other implementation plans; preserve them. During implementation several feature files were untracked, so an ordinary working-tree diff alone did not show the full change. Temporary `/tmp` probes and logs are optional diagnostics and may disappear; this document and repository tests are the durable handoff.

## Next session starting point

The internal canonical assembler is `build_assessment_model(scope, skill_cfg=..., architecture=..., controls=..., boundaries=..., merged=..., plugin_root=..., project=...)`. It returns `(document, warnings)` and performs no output write. Supply the actual resolved `business_context_source` and `skip_business_context` keys; invented `context_source` or `skip_context` keys do not represent runtime policy. It rejects configured requirements and unapplied business context until their qualified producers are integrated. Do not treat its `abuse_case_analysis.status: not_run` as a completed verifier outcome.

Standalone Figure 1 accepts a complete native-v2 model through `check_diagram` or `build_figure1_dfd_svg`. Whole-model validation happens before the qualified presentation projection. Full composer/runtime/build projections still need an explicit validated-view handoff; passing a filtered v2 model through whole-inventory validation will correctly reject omitted owners. Keep canonical source references separate from display locators.

The public CLI remains the final integration step after deterministic scans, source context, synthesis, real enrichment, composition and completion gates are connected. Repeated `--repo` is rejected; replace that rejection only together with the complete route. Do not document the proposed combined invocation as an available command yet.
