# Headless multi-repository implementation handoff

This document accompanies the multi-repository development checkpoint on `dev` and records the implementation state on 2026-10-08 for later continuation and failure analysis. It supplements the [implementation plan](implplan-headless-multi-repository-2026-10-07.md) and [approved proposal](../../../specs/changes/headless-multi-repository/proposal.md).

## Current status

Updated on 2026-10-10. The combined assessment is wired end to end and available through the public runner: a repeated `--repo` in `scripts/run-headless.sh` hands the unchanged argv to `orchestration_controller.py assess`. Single-repository runs are unchanged. The sections below "Integration on 2026-10-10" record the 2026-10-08 checkpoint; their "remaining" statements are superseded where this section says so.

The result is one fresh assessment of all explicitly selected local checkouts, with reviewed connections, repository-qualified findings, one combined report and Figure 1, and consistent exports. There is no primary repository. Repository membership does not establish a trust boundary.

## Integration on 2026-10-10

`assess_repositories` in the controller owns the sequence. Every model role runs as a tool-less exchange through `runtime/assessment_jobs.py`; deterministic producers run on private masked snapshots.

| Step | Implementation |
| --- | --- |
| Admission | `_assessment_argument_parser`, `_assessment_budget` (a soft or hard budget is required), per-root `validators/preflight_untrusted.py`, `multi_repo_scope.admit`. Unsupported lifecycle modes stop before admission. |
| Host | `_assessment_cli_host_factory` launches `ClaudeCliTransport` in a fresh private directory per exchange. `assessment_host.host_schema` sends the host a structural projection of each contract, because the CLI rejects draft-2019 keywords such as `dependentSchemas`; the controller validates the full contract. A complete result that a deterministic check or the full contract rejects gets at most two correction turns with the controller's reason. Repeated reads are not served twice, oversized ranges are narrowed and ranges past the end of a file are reported back. |
| Context | `orchestrator/assessment_context.py` captures per-repository business context and known threats and a run-wide requirements catalog; STRIDE and evidence jobs receive a bounded per-component slice. |
| Declarations | `orchestrator/assessment_declarations.py` qualifies `.appsec/trust-boundaries.yaml`, `.appsec/actors.yaml` and `docs/related-repos.yaml` per repository. An import naming a selected repository yields to the current scan. |
| Semantic stages | Discovery, connection review, local architecture (now also applying the single-root evidence guards inside the job), trust-boundary crossings with declarations, controls, STRIDE with deterministic scanner findings (`model/assessment_scanner_findings.py`, including config/IaC absence findings) and independent evidence review, merge. |
| Workspace | `orchestrator/assessment_workspace.py` projects the qualified artifacts into a private legacy-shaped workspace whose locations are `<label>/<path>` over a masked combined copy. Component names carry a repository annotation such as `Order API [backend]`. |
| Deterministic tail | Route inventory, `model/assessment_posture.py` (coverage checks, config/IaC, deployment inventory, SCA and known-bad-library sidecars, actors), architect review and abuse cases (`orchestrator/assessment_review.py`), triage, synthesis, the legacy YAML builder, enrichment and its gates. |
| Report | `orchestrator/assessment_stage2.py` authors the Management Summary, §6 prose and, with a catalog, the requirements compliance through tool-less jobs with deterministic fragment gates; then the existing compose and QA gates. |
| Publication | `assessment_workspace.canonical_model` converts the enriched model back into the qualified version-2 contract; every location must resolve to a captured file. The report, figures and requested exports (SARIF, Threat Dragon, pentest tasks, PDF, HTML) are delivered; the private workspace is removed. |
| Readers | Follow-on tools understand version-2 models through `shared/assessment_sources.py` or refuse them clearly where they would act on one checkout (`tests/test_portable_model_readers.py`). |

Repository-local abuse-case files and per-scan abuse-case files stop a combined run with a clear message. Git-history-based dependency activity is recorded as unknown. Config/IaC absences that searched no captured file stay in the config sidecar.

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
| Crossing input | `scripts/contexts/build_trust_boundary_assessment_input.py::build_assessment`, `project_assessment_signal`, `assessment_source_context` | Builds qualified crossing inputs from finalized topology and validated source context. `assessment_source_context` measures that context: the route inventory runs on every frozen snapshot, route IDs are renumbered across repositories, and the route cap interleaves repositories. Recon signals come only from route and CI evidence; a signal without supporting evidence is `null`, never `false`. A repository with `.appsec/trust-boundaries.yaml` or `docs/related-repos.yaml` stops the assessment until those inputs have per-repository ownership. Each model job receives one signal and its endpoints. A reviewed cross-repository flow triggers review; it does not establish a trust boundary. Missing source context is rejected. |
| Boundary normalization | `scripts/contexts/prepare_trust_boundary_context.py::promote_assessment_boundaries` | Reuses normalization, enforcement-point consolidation, ID allocation and signal coverage reconciliation. Preserves source owners and explicit unresolved/same-trust dispositions. Equal control names in separate owners do not by themselves merge boundaries. Candidate consolidation now retains both owners when equal relative files and line numbers support the same crossing. |
| Controller stages | `_assessment_session`, `_assessment_architecture`, `_assessment_boundary_candidates`, `_assessment_controls`, `_assessment_stride` | Joins configuration and owned jobs, sequences fresh architecture and scoped semantic stages, independently reviews findings and invokes the existing merger. These are internal functions, not a completed CLI action. |
| Deterministic scanner findings | `scripts/model/assessment_scanner_findings.py::scan`; `_assessment_stride` | Runs `source_auth_scanner`, `authz_confirm` and `mass_assignment_scanner` on every frozen snapshot. Each finding keeps its repository and file hash. Its owner is the most specific component of its own repository, else that repository's primary component. The component's evidence review decides scanner findings together with its STRIDE findings and may read their anchors. A failed scanner or an error stub stops the assessment. |
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
| In-process pipeline (2026-10-10) | `tests/test_multi_repo_assessment.py` drives admission through publication with scripted replies: standard and thorough depth, renamed labels, declared context with a run-wide catalog, resume after an interrupted render, selection-order invariance, a source change before publication, unsupported modes and the per-root preflight. |
| Routed selection (2026-10-11) | `make test-for` over the changed sources: 9,679 passed. The remaining failures predate this work: `test_threat_fixture` fails identically at HEAD with the same git-ignored `_last-run` data (missing `ms-verdict.json`), and `test_finding_state` counts a state literal committed in `575a142b`. |
| Live runs over `tests/fixtures/multi_repo_system/` (2026-10-10/11) | Each run exposed one defect that no scripted test could; each is fixed with a regression test: the host rejected draft-2019 schema keywords; a model cited a comment as authentication evidence after the job had ended; repeated reads and ranges past a file's end aborted the job; unbounded reasoning exhausted a call budget without a result; a textual control statement broke the publication owner check; the Management Summary request carried a volatile model hash; endpoint matching required literal equality, so no cross-repository candidate arose; a diagram placeholder rejection named no format. The ninth run published the complete model with the AMQP chain through one broker node; the HTTP request needed the deterministic Kubernetes Service binding added afterwards. |

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

The five review findings listed as open on 2026-10-08 are fixed with regression tests: omitted links, submodules and nested repositories are recorded instead of failing admission; overlap and output containment also compare device and inode identities; scanner snapshots hold masked text; SARIF absence evidence carries a hash only for its anchor file; resume checks state accounting against the job receipts. Every selected root passes the untrusted-repository preflight before admission.

## Remaining implementation

The 2026-10-08 list is superseded by the integration above. Open items:

1. A live run after the Kubernetes Service binding (2026-10-11) to confirm that the connection review resolves the storefront → orders-api request; the binding itself is replayed against the ninth run's discovery data, which now yields both candidates.
2. A renamed and reordered live variant per the runbook, and the complete route audit (`make audit-test-routes`).
3. Compose service names and other deployment wiring beyond a repository's single Kubernetes Service still rely on the discovered interface identity.

## Investigation notes

If a combined run stops before admission, read the controller's message: a missing budget, an unsupported lifecycle flag, a failed per-root preflight or an overlapping selection is reported there and is not a model failure.

If resume fails, inspect the bounded local `.assessment-state.json` identity and accounting fields and the matching job receipt. Changed sources/settings/runtime, an expired original deadline, unknown cost or altered delivered bytes deliberately stop reuse. Do not clear reservations, extend deadlines or rewrite receipt hashes to force continuation.

If boundary review fails, inspect the immutable input fingerprint, component fingerprint, signal endpoint/flow IDs, covered signal IDs and qualified evidence. Each claimed source line must have been retrieved by that job. Shared candidate keys are namespaced during combination. A normalized boundary and its coverage audit must agree; unresolved signals remain explicit.

If identical relative files appear to merge, trace `source_key`, component ownership and the merger's qualified comparison projection before changing report output. Check the final owner/reference checks in validate_portable_model as well as stage checks. The assembler, standalone Figure 1 and exporters have scoped adapters; full composer, emitter and publication migration remains unfinished.

Review the checkpoint's committed file list and subsequent working-tree changes before continuing. The working tree contains unrelated changes, including other implementation plans; preserve them. During implementation several feature files were untracked, so an ordinary working-tree diff alone did not show the full change. Temporary `/tmp` probes and logs are optional diagnostics and may disappear; this document and repository tests are the durable handoff.

## Next session starting point

Run the in-process pipeline with `tests/test_multi_repo_assessment.py`; it drives every stage with scripted host replies. For a live run, follow the runbook from a snapshot copy of the plugin (`rsync` into a temporary directory and run `scripts/run-headless.sh` from there), because the run binds the plugin runtime fingerprint and aborts when plugin files change while it runs. A failed live exchange names the rejected reason; `TransportError` messages carry the host's error subtype.
