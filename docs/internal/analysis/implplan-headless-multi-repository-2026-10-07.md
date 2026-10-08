# Headless multi repository threat modeling implementation plan

Status: Reviewed and corrected on 2026-10-07; implementation authorized by the operator and started on `dev`. Updated on 2026-10-08: internal controller functions now cover architecture, scoped trust-boundary review, controls, STRIDE, evidence review, merging and an owned resumable session; only unit tests call them, and no controller subcommand or pipeline step reaches them. The public headless assessment feature remains incomplete and unavailable. See the [implementation handoff](handoff-headless-multi-repository-2026-10-08.md) for changed files, validation evidence and remaining integration. The approved product delta is recorded in [the specification proposal](../../../specs/changes/headless-multi-repository/proposal.md); normative requirements remain unchanged until the product behavior is delivered.

## Outcome and scope

A headless assessment accepts several explicitly selected local Git checkouts, scans every selected repository, and produces one threat model of the combined system. The architecture analyst identifies supported connections across repositories before STRIDE analysis. Figure 1, findings, data-flow descriptions, and exports consume the same validated architecture and source identities.

The first delivery supports a fresh full assessment, local checkouts, one explicitly selected output directory, and resume of the same admitted input state. It requires no pre-existing threat models. Incremental assessment across changed repositories, remote cloning, interactive multi-repository selection, and separate per-repository reports are later work. Unsupported mode combinations fail before model dispatch; they never silently fall back to one repository.

Proposed invocation, where each path is an operator-selected checkout or output location:

```bash
./scripts/run-headless.sh \
  --repo /repos/frontend \
  --repo /repos/backend \
  --repo /repos/worker \
  --output /reports/order-system \
  --full
```

One `--repo` retains its existing behavior, including supported subdirectory selection. With multiple repositories, the first argument has no special analysis authority. Reordering the same selection does not change component ownership, admitted scope, or connection decisions. Independent services may remain disconnected in the resulting model; selection alone does not establish integration.

## Existing behavior and constraints

Before 2258f00a the parser in [`scripts/run-headless.sh`](../../../scripts/run-headless.sh) assigned each `--repo` value to one `REPO_PATH`, so a repeated argument replaced the previous selection. It now rejects a repeated `--repo`, as does `resolve_config.py`. Fixing only this parser would still leave discovery, output placement, completion handling, and source validation tied to one root.

[`schemas/related-repos.schema.yaml`](../../../schemas/related-repos.schema.yaml) describes dependency threat-model imports. [`scripts/contexts/build_threat_modeling_context.py`](../../../scripts/contexts/build_threat_modeling_context.py) builds their context through the related-repository loader and register. These imports do not provide fresh full assessments of every dependency.

[`scripts/contexts/build_stride_evidence_bundles.py`](../../../scripts/contexts/build_stride_evidence_bundles.py) already gives source slices repository identities and verifies contained paths, state, and content. Its registry is derived from local `docs/related-repos.yaml` declarations, retains an implicit `primary` root, and is not a general multi-target admission mechanism. Extend these guarantees through a versioned adapter instead of treating additional targets as imported threat models.

[`docs/internal/runbooks/e2e-cross-repo-fixture.md`](../runbooks/e2e-cross-repo-fixture.md) explicitly scans one consumer and supplies pre-generated producer models. Preserve that compatibility test and add a separate fresh multi-repository fixture.

[`docs/internal/contracts/schema-invariants.md`](../contracts/schema-invariants.md) and decisions RA-15, RA-26 through RA-31 govern overview/detail rendering, legibility, ordering, and the runtime/build split. Figure 1 is the overview. With build evidence it becomes Figure 1a and Figure 1b shows the supply chain. Repository ownership must fit this presentation without creating a competing layout or boundary model.

The failure class to prevent is silent omission or misattribution: a requested repository, source location, service, or connection must never disappear because a consumer still assumes one root. The producing locations are CLI admission, discovery, architecture reconciliation, and source resolution. Renderers cannot repair missing architecture by guessing connections.

The current headless command grants general `Read`, `Write`, `Glob`, `Grep`, `Bash`, and `Agent` tools and selects `bypassPermissions`. The header of [`data/required-permissions.yaml`](../../../data/required-permissions.yaml) explicitly states that its interactive allow-list is not containment. Existing preflight and deterministic path checks must not be described as a filesystem sandbox for model tool calls. Enforced read-only source scope is new work and a prerequisite for the proposed multi-repository mode.

## Product and contract preparation

The operator approved the specification change proposal through the implementation request. Extend target-scope language in REQ-PUR-001, REQ-PUR-003, REQ-MOD-001, REQ-MOD-005, and REQ-TRU-001 to cover an operator-selected set when delivering the behavior. State fresh discovery, incomplete-run behavior, and supported modes. Preserve REQ-FLW-002 and REQ-FLW-003 coverage and validation promises, REQ-RPT-002 anchor consistency, REQ-RPT-006 export traceability, REQ-RPT-007 legibility, REQ-RPT-008 build separation, and REQ-EVO-003 compatibility handling.

Update [`data/requirement-bindings.yaml`](../../../data/requirement-bindings.yaml) with exact guards when implementation establishes them. Record only non-obvious decisions in [`docs/internal/decisions.md`](../decisions.md). Keep shapes in schemas, matching rules in deterministic code or catalogs, and workflow sequencing in the orchestration contract. Update section contracts and templates only where report structure actually changes.

## Admission and source identity

Add a schema-validated assessment manifest owned by the controller. Separate the private mapping of repository IDs to canonical local roots from the portable repository inventory delivered in reports. Suggested artifact names and fields below are proposals to finalize in the schema change.

| Record | Required meaning | Owner and consumers |
| --- | --- | --- |
| Private assessment manifest | Schema version, assessment identity, exact selected roots, stable repository IDs, source-state fingerprints, output scope, effective configuration fingerprint | CLI admission and controller; never imported from repository prose |
| Portable repository inventory | Repository ID, readable label, revision and dirty-state qualification, coverage status | Canonical model, report, exports, status |
| Source reference | Repository ID, relative path, line range, content fingerprint where required | Discovery, architecture, STRIDE, validators, exports |
| Connection candidate | Endpoint observations, repository-qualified evidence, environment qualification, disposition and reason | Deterministic producer, analyst, reconciliation gate |
| Canonical connection | Existing flow identity and endpoints, protocol, purpose, evidence, resolution state, per-hop controls | Architecture model, boundary analysis, Figure 1, findings |

Canonicalize selections before creating model jobs. Reject missing roots, duplicate canonical roots, ambiguous overlaps, and aliases that would scan the same tree twice. Require top-level Git checkouts for the initial multi-repository mode; preserve existing single-repository subdirectory semantics. Do not descend into nested repositories or submodules. Selecting a nested checkout together with its containing repository is rejected as an overlap in this first version; supporting both requires an explicit exclusion and ownership contract in a later change.

Allocate opaque IDs outside the model, persist their mapping, and disambiguate identical repository basenames. Do not derive public IDs from credential-bearing remotes or expose absolute workstation paths. IDs survive argument reordering and resume of the same assessment. A moved checkout requires an explicit validated remap or a new assessment; it must not accidentally reuse a different source root. Single-repository adapters retain existing IDs and artifact behavior.

All selected sources are read-only for assessment work. Require an explicit output directory outside selected trees in multi-repository mode. Own the lock, runtime files, history, and cleanup at that output location. A fresh invocation must not overwrite an incompatible assessment already there. No temporary synthetic super-repository, broad parent-directory grant, or source-tree symlink farm is needed.

Use structured argument transport from the wrapper into the controller. Paths containing spaces or shell metacharacters stay data. Repository IDs never select arbitrary files, commands, or permissions. Apply existing repository-trust preflight to every selected root before any source reaches an agent, including instruction files, hooks, settings, links, and dirty-state handling.

Introduce a controller-owned host boundary before enabling this mode. Prefer a narrow source-read broker that resolves repository-qualified paths and executes allow-listed deterministic helpers outside the model; do not expose an unrestricted shell or general filesystem tools beside it. If the existing host requires those tools, an independently enforced sandbox must provide equivalent read/write and process restrictions, including all descendants. A manifest, prompt instruction, `--add-dir`, or interactive permission entry alone does not meet this gate. Prove the selected approach with the actual headless host before building the remaining feature on it; unsupported hosts fail admission.

Launch from a controlled working directory with explicit trusted configuration sources. The operator's current directory and parent directories must not load repository-owned instructions or hooks before preflight. Selected sources are readable only within admitted scope, plugin resources are read-only, and writes are limited to owned output and scratch space. Keep host authentication outside model-readable files. Validate any required network access separately; discovering a URL in source does not authorize fetching it. The first multi-repository delivery does not support a trust-mode option that bypasses these controls.

## Configuration and imported context

Resolve run-wide policy, model/depth settings, budgets, and organization configuration once from operator-authorized inputs. Multiple repository defaults must not compete by argument order or silently relax policy. Conflicting run-wide settings produce an actionable preflight error unless an explicit supported override resolves them.

Keep repository-local business context, known-threat declarations, requirement catalogs, and interface hints attached to their owning repository. Define requirement catalog namespaces before joining traces so identical local requirement IDs do not collide. A supplied run-wide context may describe the combined system; it does not rewrite local documents. Headless runs never wait for questions or persist dialog answers.

Maintain the existing single-repository `related-repos.yaml` behavior. In multi-repository mode, distinguish selected source targets from imported context. A related model cannot silently add a source root or count as fresh coverage. If an import names an already selected repository, use the current source assessment as authoritative and retain imported claims only as qualified context. Do not rewrite or generate `related-repos.yaml` in input repositories.

## Discovery and connection reconciliation

Run deterministic scanners and bounded recon for every admitted repository into separate namespaces. Aggregate component, actor, deployment, asset, route, and integration observations after their local validation. Add a deterministic global identity reconciliation stage before component finalization and architecture dispatch, retaining the mapping from repository-qualified local observations to global presentation IDs. `scripts/model/reserve_ids.py` does not currently allocate component or data-flow IDs; reusing its counters alone cannot establish this mapping. Integrate reconciliation with `scripts/model/finalize_component_inventory.py` and the component-inventory fingerprint. A shared library is not automatically a running service.

Namespace workload names, deployment zones, actors, external entities, assets, and local flow IDs as well as component IDs. Keep deployment identity separate from repository identity: two `default` namespaces are not automatically the same cluster, and one service identity may be implemented by more than one repository. Rewrite references atomically before producing receipts. Late component injection must pass through the same reconciliation and invalidate dependent handoffs rather than introducing colliding IDs after the graph is built.

Build candidate connections before the architecture handoff. Deterministic matching narrows the analyst's work. The analyst explains semantics and proposes ambiguous links in structured output; the controller validates evidence, scope, identities, and allowed dispositions before promoting any result.

| Mechanism | Useful evidence | Exclusions and unresolved cases |
| --- | --- | --- |
| HTTP or RPC | Client operation, server route or service contract, and deployment binding linking the target to that server | A shared route name, unused URL, or unresolved target variable alone cannot select a peer |
| Messaging | Producer and consumer operations, topic or queue, broker identity, namespace or virtual host, payload contract | Identical topic names on separate brokers or environments remain separate |
| Shared storage | Read/write operations and evidence that both workloads address the same deployed resource | Equal engine names, table names, or example connection strings cannot merge stores |
| Deployment wiring | Compose service references, Kubernetes service selection, workload identity, deployment overlays | Equal service or namespace names from independent deployments cannot be merged without a common deployment binding |
| In-process dependencies | Import or package usage plus evidence that it executes inside the owning runtime | A package declaration does not create a network edge or trust boundary |

The initial supported matching vocabulary covers evidenced HTTP/RPC and messaging chains, with shared-storage and deployment bindings where static source proves identity. Unsupported mechanisms remain visible as unresolved observations. Publish detection coverage and omissions; never imply complete discovery of dynamic production topology.

Separate endpoint identity from evidence strength and deployment activation. Proposed candidate dispositions are `resolved`, `unresolved`, and `rejected`, with reasons. These do not reuse finding confirmation status or invent a scalar confidence score. A resolved source-supported link still says whether production activation is unknown. Competing plausible peer matches remain unresolved; only contradicted candidates are rejected. Never choose a peer by lexical order.

Distinguish three claims: communication exists, a particular payload moves across it, and an identity or security property survives the handoff. Prove each independently. A backend-to-broker-to-worker route does not prove end-to-end tenant authorization. Retain the broker as a node and authentication at each receiving interface. Do not infer encryption, authentication, authorization, or trust from protocol labels, repository ownership, or an upstream check.

Deduplicate shared infrastructure only with resource-identity evidence, retaining all source references and consumer relationships. Preserve different deployment environments and conflicting declarations. Report unresolved external dependencies without creating invented internal peers. Selected but disconnected repositories remain in the architecture and coverage inventory.

## Analysis and canonical artifacts

Use one validated architecture handoff, based on the existing component inventory and `.data-flows.json`, before trust-boundary assessment and STRIDE dispatch. Extend that canonical representation rather than maintaining a second graph whose topology can disagree with the report. Candidate matching receipts are supporting audit artifacts, not another topology authority.

Every selected component receives all six STRIDE categories under existing depth rules. Cross-repository analysis packets contain the relevant connected neighborhood, boundary evidence, and source slices from admitted roots. They do not contain all repositories indiscriminately. Review the context-routing catalog, bindings, budget profiles, and dispatch receipts together.

A cross-repository finding identifies its affected components, exact source locations, and remediation ownership across the chain. A single shared control defect may have multiple repository-qualified references. Similar findings in different repositories remain distinct unless evidence establishes the existing consolidation rule. Preserve weakness links, scenario numbers, severity evidence, and unproven status.

Add repository-qualified references through fragments, merge, boundary catalogs, canonical YAML, query tools, SARIF, HTML, PDF, and rerender. SARIF uses explicit repository base mappings rather than ambiguous relative paths. An export that cannot represent multiple source roots must use a documented compatible representation or fail clearly; it must not drop ownership. Avoid absolute local paths in portable output.

Version incompatible schema changes and provide a legacy single-repository adapter. Old consumers must reject unsupported versions clearly. Existing saved single-repository models still render without access to unrelated roots. Follow-on tools resolve qualified references through the delivered inventory and explicit local mappings, never by guessing from the current directory.

Inventory embedded evidence shapes before changing them. Repository qualification must also reach authentication evidence, sensitive-data and capability evidence, deployment facts, absence evidence and its searched-file list, weakness provenance, repair inputs, and preserved architect-review transactions. Updating only top-level finding locations leaves ambiguous references in these consumers. `schemas/fragments/data-flows.schema.json` currently carries schema version 1 and closed objects; update its producers and validators together with the canonical YAML shape. `scripts/exporters/export_sarif.py` currently assigns evidence locations to one `%SRCROOT%`; replace this assumption and test distinct files with identical relative paths in different repositories. Keep portable repository identities separate from machine-local SARIF base resolution, and verify the selected representation against actual consuming tools before claiming compatibility.

## Figure 1 presentation

Keep the Architecture and Threat Overview as the system-level view. Use deployment and security zones for layout; repository membership is a distinct short annotation such as `Order API [backend]`. A repository is neither automatically a trust zone nor automatically one component. Components implemented in several repositories and shared infrastructure retain multiple ownership references where supported.

The expected acceptance topology is a browser client, an API, a broker, a worker, and a database. The client, API, and worker belong to separate selected repositories. The broker and database appear once only when shared identity is established. The overview shows the API request, publish operation, delivery, and storage access with their individual directions and payload labels.

Use existing trust-boundary evidence and crossing checks. Do not draw extra security perimeter lines around repository groups. Keep authentication at the appropriate receiving interface. Preserve Figure 2 scenario alignment, actor codes, finding anchors, component IDs, and the runtime/build distinction. Extend Figure 1b source attribution without linking unrelated build pipelines merely because their repositories are selected together.

Only resolved connections enter canonical data flows and the normal Figure 1 topology. Unresolved peer candidates stay in the connection diagnostics, even when both candidate participants are known. An observed outbound operation with an unknown peer may retain its evidenced external endpoint; do not create an endpoint solely to visualize a hypothesis. A resolved connection whose deployment activation is unknown may carry a short textual qualification with a legend, distinct from trust-boundary dashes and attack-path styling. Unsupported connections never become highlighted confirmed attack routes.

Extend the existing overview aggregation and paged detail mechanism. Repository annotations must not squeeze out payload labels or make text illegible at supported report widths. Grouped nodes expose their repository membership and member counts; detail views and catalogues retain every component, flow, and source identity. No independent figure per repository replaces the combined overview.

Geometry and semantic gates verify endpoint validity, directions, label retention, collisions, clipping, readable text, boundary crossings, and detail coverage. Exercise SVG plus the actual HTML/PDF embedding. Repository annotations need a compact display form and full accessible text. A failed figure gate follows the existing contracted behavior; this feature must not silently hide nodes or introduce an unapproved fallback.

## State and security boundaries

The aiscb baseline requires the controller to enforce the selected source scope outside the model. Protected assets here are source confidentiality, artifact integrity, and the operator's filesystem. The initiating local operator selects readable roots; repository authors, imported models, and analyst outputs cannot expand those rights. Source observations cross into model context as untrusted data, and model proposals cross back through schema, evidence, and authorization gates.

Apply containment and current-state checks at read and dispatch boundaries, not only at initial parsing. Test links replaced after admission, forged repository IDs, tampered manifests, and stale source slices. Audit configuration propagation so settings or instructions from any selected checkout cannot enable tools or hooks. A source root that fails trust admission stops the combined assessment before dispatch.

Per-root fingerprints do not create an atomic snapshot across independently changing repositories. The first implementation must either capture admitted content into controlled immutable snapshots or validate every consumed input against its admitted fingerprint and revalidate the complete selected set before publication. Record revisions and dirty-state qualification without claiming that those revisions were deployed together. A mismatch fails the current assessment instead of silently refreshing one repository and mixing states. Snapshot retention, exclusion of sensitive files, and cleanup belong to the same source-handling contract.

Bind cache and resume state to the entire selected set, per-root HEAD and dirty content, effective configuration, and graph inputs. Track dependencies for packets that cite more than one root. A source change during a run invalidates dependent observations and blocks stale publication. Initial resume supports unchanged admitted inputs only; changed membership or state requires a fresh full assessment. Add incremental reuse only after dependency invalidation is independently proven.

Retain existing per-dispatch limits and introduce measured aggregate accounting for the run. Schedule bounded work and record omitted optional discovery explicitly. Do not raise model budgets merely because there are more repositories, and do not silently skip required components when a limit is reached. Cancellation stops all jobs owned by the assessment; cleanup only removes owned output state.

Classify each new artifact in the cleanup and audit contracts. Preserve portable source inventory, graph evidence dispositions, coverage, and fingerprints needed for rerender and diagnosis. Treat absolute-root mappings as private runtime state with a defined resume lifetime. Apply secret scanning to every selected source contribution and final combined artifacts before publication. Diagnostic records contain bounded reasons and safe references rather than credentials or source dumps.

Review this design and its negative tests against the [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/) and [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), focusing on prompt injection, excessive tool authority, poisoned retrieved context, and uncontrolled work. These references supplement the repository's concrete trust and validation contracts.

## Delivery sequence and ownership

Each slice includes producer, consumer, schema, permission, and test changes. Intermediate slices remain inaccessible as a supported multi-repository feature until their publication gates are complete.

| Step | Change surface | Exit evidence |
| --- | --- | --- |
| 1. Approve scope | Specification proposal, requirement bindings, orchestration and compatibility decisions | Approved product delta, explicit modes and failure behavior, consumer inventory |
| 2. Admit selected roots | `scripts/run-headless.sh`, `scripts/runtime/resolve_config.py`, controller entry, manifest schema, trust preflight, permissions | Repeated arguments reach one validated scope; no overwrite, broadened reads, or first-repository policy precedence |
| 2a. Enforce host scope | Headless host launch, source-read broker or equivalent sandbox, controlled configuration, helper execution | Actual model tools and descendant processes cannot read an unselected sentinel, modify a selected source, load a hostile parent configuration, or escape output scope; unsupported enforcement blocks startup |
| 3. Discover every target | Recon/scanner dispatch, output namespaces, context builders, ID allocation | All repositories have coverage receipts; duplicate names and local IDs remain distinct |
| 4. Resolve integrations | Candidate producer/schema, architecture context and analyst, deterministic reconciler, data-flow validators | Supported HTTP and messaging chains join from evidence; ambiguity and environment conflicts stay explicit |
| 5. Analyze the combined system | `scripts/orchestrator/orchestration_controller.py`, STRIDE bundles, source registry, trust-boundary and merge consumers | Full per-component STRIDE coverage and qualified cross-repository findings |
| 6. Publish one model | YAML builder, composer, `figure1_dfd.py`, `figure1_detail.py`, `figure1_svg.py`, Figure 1b consumers, exporters and follow-on tools | Matching topology and references across artifacts; legible overview and complete detail views |
| 7. Complete lifecycle | Fingerprints, resume, status, logging, completion checks, locks, cleanup, redaction | Mid-run changes cannot publish stale evidence; cancellation and recovery preserve only owned state; finish and test this gate before live discovery acceptance |
| 8. Enable and document | Headless/help documentation, neutral fixture driver and runbook, reviewed routes, user-facing changelog if completed | Live fresh-scan acceptance, deterministic replay, single-repository compatibility, no undocumented partial mode |

Review affected [`data/required-permissions.yaml`](../../../data/required-permissions.yaml) entries for new commands or read/write targets. Every new Python script gets a matching test module and a reviewed route in `scripts/run_tests.py`. New runtime context artifacts also require catalog, binding, budget, validation, and cleanup ownership.

## Verification and acceptance

The operator explicitly excluded end-to-end tests from the current session on 2026-10-08 and requested documentation for later analysis. The acceptance cases below describe deferred verification; they are not evidence that those runs occurred. Runtime validation and publication gates remain required in the implementation.

Use neutral local fixtures without pre-generated threat models. Establish a reproduction that the pre-change implementation cannot satisfy, a variant with changed repository names, paths, service names, and declaration order, and a negative topology that must remain disconnected. Preserve the existing imported-model fixture as a separate compatibility case. Do not alter its expectations to disguise missing fresh-scan coverage.

| Area | Required cases and observable result |
| --- | --- |
| CLI and scope | Three roots are scanned; argument reordering is equivalent; same basenames remain distinct; one-repository behavior is unchanged; duplicates, overlaps, missing values and unsupported modes fail before dispatch; spaces and shell metacharacters remain literal |
| Connection evidence | Client/API/broker/worker chain resolves with source references from all participating roots; identical route/topic names in separate deployments do not join; missing target bindings remain unresolved; supported payload continuity is distinguished from assumed identity propagation |
| Source boundaries | Through the actual headless tools and child processes, traversal, escaping links, post-admission link replacement, forged repository IDs, model-selected extra roots, shell-based reads/writes, and repository-owned or parent instructions cannot access an unselected sentinel, alter selected sources, or add authority; denied source never enters context |
| Canonical identity | Repeated component, workload, zone, actor, flow and asset names and `src/main` paths never collide; global IDs map to correct roots; shared stores merge only with positive identity evidence; imported stale models cannot override current scans; late component injection preserves all references |
| Findings | An evidenced cross-repository authorization defect is attributed to its actual control and sources; a variant with the control present is not reported as missing; unresolved connectivity does not yield a confirmed attack chain |
| Figure 1 | All selected runtime components are represented directly or through documented aggregation; repository labels survive scaling; directions, payloads and per-hop authentication remain distinct; no repository-only boundary is drawn; dense and cyclic layouts pass existing gates or fail publication as contracted |
| Build and detail views | Independent builds remain independent; Figure 1a/1b actor and scenario IDs agree; oversized models retain complete navigable detail coverage; HTML/PDF output is inspected at supported widths |
| Lifecycle | Changes in any cited root invalidate affected work; changed selection cannot resume; source failure or budget exhaustion cannot report overall success; concurrent output locks prevent mixed results; cleanup never writes to selected source trees |
| Compatibility | Saved single-repository models still rerender; related-model imports retain their contract; qualified YAML/SARIF references resolve correctly; unsupported old readers fail explicitly; post-run query and triage keep ownership |

Begin each implementation slice with `scripts/check_specs.py --for` for its paths. Inspect `make test-plan BASE=origin/dev`; use the worktree-only plan and direct task routes when unrelated changes are present. Run the smallest sufficient routed producer/consumer selection with shared validation, and `make lint` for Python changes. If new source routes are introduced, run the required route audit. Use `make check` at the integrated feature gate if the cross-cutting runtime consumers cannot yet be bounded by reviewed routes; state that reason before running it. Investigate failing selected tests at the merge base according to CONTRIBUTING.md.

Replay a frozen combined model with `scripts/threat_fixture.py` after scanner or deterministic-tail changes, then run a fresh headless assessment over the neutral multi-repository fixture. Record commands, source revisions, coverage, candidate dispositions, figure checks, and observed token/time use. The deterministic replay proves downstream consistency; only the fresh run proves that discovery actually finds the connections. No implementation, render, or E2E success is claimed by this plan.

The feature is complete when every selected repository is freshly covered, supported connections have qualified evidence, the combined model preserves uncertainty, Figure 1 and exports agree on topology and identity, source boundaries remain enforced, and existing single-repository behavior remains compatible. Incremental multi-repository runs and interactive selection remain separately scoped follow-ups.

## Plan verification result

The review traced the CLI parser and host launch, registry construction, component finalization and ID reservation, data-flow schema, SARIF location construction, Figure 1 contracts, and cleanup ownership. It corrected the missing host-enforcement prerequisite, the assumption that existing counters allocate component identities, nested-checkout scope ambiguity, candidate disposition semantics, speculative figure edges, incomplete embedded-evidence migration, and source-state consistency requirements.

The design is sufficiently specified to prepare the product change proposal and the host-boundary feasibility slice. Implementation feasibility remains conditional on proving actual host isolation and selecting a portable export representation supported by consumers. These are explicit implementation gates, not claims that the existing plugin already satisfies them. No product code or normative requirements were changed during this review.

## Implementation progress

The current implementation contains internal modules and tests, not an assessment entry point. `scripts/run-headless.sh` keeps single-repository behavior and rejects a repeated `--repo`. Controlled unit inputs now exercise an in-memory canonical v2 assembler, the Figure 1 overview data in `figure1_dfd.py` and qualified exporters; the Figure 1 SVG, detail, and composition paths are unchanged. No completed multi-repository assessment or user report has been produced.

| Area | Implemented | Remaining before delivery |
| --- | --- | --- |
| Source admission | `scripts/runtime/multi_repo_scope.py` validates selected top-level checkouts and a separate output location, captures bounded source bytes, disambiguates repository identities and labels, serves redacted slices, and detects changed admitted input | Public CLI admission, complete source-coverage reporting and per-root trust preflight |
| Model boundary | `scripts/runtime/assessment_host.py` validates tool-less model exchanges. `scripts/runtime/assessment_jobs.py` persists accepted artifacts and retrieval receipts and revalidates them before reuse. Shared budgets reserve calls before dispatch | Public transport qualification and complete lifecycle integration |
| Discovery and architecture | The existing controller sequences per-root discovery, component finalization, candidate review and local/external architecture. Only resolved reviewed connections enter canonical flows; messaging retains brokers | Remaining deterministic scanner, deployment, actor, context and namespace integration |
| Trust boundaries | Versioned input and candidate adapters support controller-selected crossing jobs. Existing normalization and coverage reconciliation preserve qualified evidence and unresolved dispositions | Production source-context and declaration loading, stable normalization on resume and publication of validated sidecars |
| Controls and findings | The existing controller scopes controls to each component, supplies incident peers to STRIDE, requires all six categories and independently reviews findings. The existing merger preserves qualified locations, policy and distinct instances | Remaining synthesis, triage, actor attribution, configured requirements and architectural review integration |
| Configuration and session state | `resolve_assessment` compares effective per-root configuration. `AssessmentState` binds resume to scope, settings and plugin bytes, retains accounting, checks delivered hashes and owns output through the shared serialization guard | Public routing, status, terminal handling and the complete gated completion path |
| Contracts and consumers | Versioned sidecars, merged findings and output schemas exist. The in-memory canonical builder reuses existing policy, mitigation and pruning helpers. Standalone Figure 1 annotates source owners. Qualified SARIF/Threat Dragon exports retain distinct locations. Targeted tests cover source ownership, neutral variants, malformed inputs and resume | Controller publication, emitter pass, full composition, runtime/build projections and follow-on tools; reviewed route completion and deferred end-to-end acceptance |

A live tool-less Claude host probe advertised only `StructuredOutput` and emitted only that tool call. It advertised no file, shell, network-fetch, or delegation tool. Model self-reports of whether a file was read were inconsistent across probes and are not treated as evidence. The probe establishes the observed tool surface only; it does not establish host-side retention behavior or a completed assessment.

The live discovery probe exposed two host schema incompatibilities: duplicate resource IDs and unsupported root-level combinators. The exchange producer now defines the artifact schema once and sends a structural host envelope. The controller retains the complete conditional validator, including mutual exclusion of read requests and final artifacts. Negative tests verify that an ambiguous response still stops processing.

A fresh discovery probe with Claude Code 2.1.292 and Haiku completed against two artificial local Git checkouts without imported threat models. It returned two owned components and one connection candidate requiring architecture review. Four model calls cost USD 0.067055 in that run. Both fixture files in each repository were retrieved. This is discovery-stage evidence, not an end-to-end threat-model or Figure 1 acceptance result.

The next integration milestone is the complete production path through scanners, semantic analysis, canonical YAML construction and the existing publication gates. Full Figure 1 composition, publication and the public repeated-argument route are still missing; standalone figure and export adapters are implemented. End-to-end acceptance is deferred at the operator's request; this deferral does not establish feature availability or permit fabricated completion receipts.
