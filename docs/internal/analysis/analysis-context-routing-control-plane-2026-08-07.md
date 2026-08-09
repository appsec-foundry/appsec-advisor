# Analysis — context routing control plane

- Date: 2026-08-07
- Status: Stage-1 edge inventory and human-readable catalog implemented; component-root, business-context, and architecture-context STRIDE migrations active
- Parent plan:
  `docs/internal/analysis/implplan-threat-analysis-context-and-turn-reduction-2026-08-05.md`

## Decision

Add one schema-validated context catalog and routing control plane to the
existing orchestration controller. It becomes the authoritative description of
which semantic or deterministic consumer receives which bounded context
projection for which application component.

Do not add a second orchestrator. Do not turn the routing configuration into a
prompt extension surface. The controller remains responsible for resolving
trusted core policy, validated organization extensions, repository-provided
data, and the finalized application-component inventory into immutable dispatch
inputs.

Implement the control plane after the current Stage-1 path completes one live
full/rebuild invocation, but before WP6 reduces Stage 2-4, before incremental or
resume migration, and before the paid A/B cohort. Otherwise those later paths
would add more distributed context decisions that must be migrated again.

## Problem

Context selection is currently distributed across controller role metadata,
manifest and evidence-bundle builders, taxonomy and lens selection, phase
instructions, and agent prompts. A field may therefore exist in a producer
schema without reaching its intended consumer. The current
`focus_paths`/`exclude_paths` gap is one example: the control-analysis contract
can emit the values and the dispatch manifest can retain them, but the v2
STRIDE delivery path does not consume them as analyzer inputs.

This distribution makes four questions unnecessarily difficult to answer:

1. What context exists and who owns it?
2. Why did one consumer receive or not receive a specific context slice?
3. Which limit, projection, trust rule, or fallback applied?
4. Can an organization add domain context without adding instructions or
   bypassing mandatory security context?

## Frozen current Stage-1 edge inventory

This inventory freezes the context-v2 full/rebuild path at commit `6473fe17`.
It records current behavior before a catalog resolver changes admission. The
declared action inputs are not treated as a complete inventory: several roles
also read repository evidence, plugin policy, or output sidecars named only in
their prompts.

The delivery labels below have fixed meanings:

- `declared` means the path is present in `dispatch_jobs[].input_artifacts`;
- `implicit` means the consumer reads it under current prompt or script rules
  but the action does not declare it;
- `direct-source` means bounded or broad reads under `REPO_ROOT`;
- `plugin-owned` means a fixed plugin path selected by code or agent contract;
- `scalar` means a bounded value copied from resolved configuration; and
- `projected` means a deterministic component- or decision-scoped artifact.

### Semantic consumer deliveries

| Consumer | Phase and current producer | Current deliveries | Contract, limit, and freshness behavior |
|---|---|---|---|
| `consumer:context_resolver` | Phase 1; `appsec-context-resolver` | declared `.skill-config.json`; implicit `.requirements.yaml`, plugin/org configuration, external context, repository policy/architecture/business files, `docs/known-threats.yaml`, and `docs/related-repos.yaml`; direct-source repository metadata | Markdown validator caps and fences `.threat-modeling-context.md`; related-repository helpers validate their JSON outputs. The action has no exact-byte receipts for these inputs or outputs. External failure is optional; requested requirements failure blocks. |
| `consumer:recon_scanner` | Phase 2; `appsec-recon-scanner` | declared `.skill-config.json`; implicit `.recon-patterns.json` and optional `.scan-manifest.txt`; direct-source repository docs, manifests, deployment/configuration files, and security patterns; plugin-owned scan exclusions and recon template | Recon Markdown and `recon-signals` validators run at producer and controller boundaries. Per-category examples and discovery calls are capped, but the action does not receipt the pre-pass, source reads, or template bytes. |
| `consumer:config_scanner` | Phase 2.5; `appsec-config-scanner` or deterministic empty stub | declared `.skill-config.json`; direct-source selected IaC/configuration files; plugin-owned `data/config-iac-checks.yaml`; scalar assessment depth | `config-scan-findings` schema validation is best-effort enrichment. Quick depth caps files per category. The check catalog and selected source bytes are not action-receipted. |
| `consumer:actor_discoverer` | Phase 2.7; `appsec-actor-discoverer` | declared `.actors-merged-static.json` and `.recon-summary.md`; implicit `.recon-signals.json` and discovery cache key; scalar depth | Discovery schema validation degrades to the static set on failure. Cache freshness binds plugin defaults, org/repository actor inputs, recon signals, and prompt version outside the action receipt model. |
| `consumer:architecture_analyst` | Phases 3-6; `appsec-architecture-analyst` | declared `.recon-summary.md`, projected `.route-inventory.json`, and projected `.actors-resolved.json`; direct-source targeted Grep; plugin-owned ID reservation | Route and actor inputs have exact-byte receipts. Recon Markdown and direct source do not. Four output schemas, inventory finalization, data-flow fingerprint binding, coverage gates, and boundary-input construction block on failure. |
| `consumer:trust_boundary_analyst` | Phase 7; `appsec-trust-boundary-analyst` | declared projected `.trust-boundary-assessment-input.json`; scalar run paths | The assessment input has a schema, size limits, component coverage, and an exact-byte receipt. The role forbids recon/context Markdown and arbitrary source discovery. Candidate validation and deterministic promotion block. |
| `consumer:control_analyst` | Phase 8; `appsec-control-analyst` | declared `.components.json`, `.trust-boundaries.json`, and `.architecture-coverage.json`; implicit requirements-violation evidence referenced by the prompt; direct-source targeted Grep | Canonical boundaries have an exact-byte receipt; the other declared inputs do not. Both outputs are schema-gated. Unknown components, oversized overlays, reserved profile values, and unsafe focus/exclude paths block later bundle construction. |
| `consumer:stride_analyzer` | Phase 9 per selected component; `appsec-stride-analyzer-v2` | declared manifest, projected evidence bundle, projected taxonomy slice, and optional repository registry; plugin-owned fixed lenses; direct-source receipted ranges plus optional component-local discovery; scalar depth, budgets, sampling, lens IDs, and profile | Manifest, bundle, registry, and taxonomy bytes are checked immediately before dispatch. Bundle limits are 65,536 bytes, 16,384 estimated tokens, 400 source lines, 24 slices, and 32 values per evidence class. Lens bytes and optional discovery results are not exact-byte action receipts. |
| `consumer:threat_merger` | Phase 9 merge; `appsec-threat-merger` | declared projected `.merge-context/candidates.json`; scalar unresolved group IDs; optional component map exists only on the legacy prompt surface | The projection is capped at 64 groups and 262,144 bytes, carries the full-source hash, and has an exact-byte receipt. Source code and full `.merge-candidates.json` are forbidden. Decisions are schema-checked and rebound to unchanged source candidates. |
| `consumer:evidence_verifier` | Phase 10a; `appsec-evidence-verifier` | declared `.threats-merged.json`; direct-source sampled evidence windows selected from finding citations; scalar depth and sample cap | Merged threats have an exact-byte receipt before dispatch. Source windows are not preprojected or receipted. The verifier writes incremental in-place annotations plus an optional sidecar; invalid side-channel data is ignored while canonical annotations remain guarded. |
| `consumer:triage_validator` | Exceptional Phase 10b fallback; `appsec-triage-validator` | declared `.threats-merged.json` and optional `.triage-flags.json`; implicit optional `.recon-summary.md`; plugin-owned breach-distance, compound-chain, and critical-criteria data; direct-source access through deterministic ranking helpers | Dispatch occurs only after deterministic ranking fails. Merged threats are receipted; triage flags, optional recon context, plugin policy bytes, and helper source reads are not all represented by the action. Both mutated artifacts are revalidated before synthesis. |
| `consumer:post_stride_synthesizer` | Phase 10b; `appsec-post-stride-synthesizer` | declared `.threats-merged.json` and `.triage-flags.json`; scalar unresolved synthesis keys | Both inputs have exact-byte receipts. The current controller requests only tier-root-cause synthesis; the role contract also permits mitigation overrides when a future controller key requests them. Accepted outputs are schema-validated and receipted before YAML consumption. |
| `consumer:abuse_case_verifier` | Stage 1d; `appsec-abuse-case-verifier` outside the semantic-role registry | implicit projected `.abuse-case-matches.json`; scalar abuse-case ID and model; direct-source entry, sink, and control reads; plugin/org/repository abuse-case catalogs feed the matcher | The action carries candidate IDs and titles, not `dispatch_jobs`, input artifacts, or artifact receipts. Candidate count is capped at 64. Per-case verdict schemas, deterministic merge/finalize, the release gate, and YAML rebuild own the handoff. |

### Deterministic producer and projection edges

| Edge | Producer and source | Current consumer and delivery | Validation, failure, and lifecycle behavior |
|---|---|---|---|
| `edge:preflight_run_config` | `resolve_config.py`, persisted `.skill-config.json`, invocation and org profile | every controller action and scalar prompt alias | Action schema allow-lists dispatch keys. Runtime generation and artifact-version mismatches block. The file is not separately receipted per dispatch. |
| `edge:preflight_repository_signals` | `route_inventory.py`, `architecture_coverage_checks.py`, optional database checks, and `source_auth_scanner.py` read repository source | recon, architecture, control, bundle construction, merge, and YAML builders through sidecars | Individual schemas and downstream gates vary. Best-effort prepasses may leave absent optional sidecars; source-auth and route evidence later enter bundles when present. |
| `edge:requirements_resolution` | `fetch_requirements.py` resolves invocation, org, URL, cache, or skipped stub into `.requirements.yaml` | context resolver, requirement checks, component violation slices, and final model | Requested missing input blocks preflight. The resolved file is not currently an action receipt, and context-v2 does not explicitly prove creation of every later per-component violation slice. |
| `edge:recon_projection` | deterministic recon patterns plus recon agent source inspection | `.recon-summary.md` and `.recon-signals.json` consumed by actor resolution, architecture, matching, and later deterministic checks | Producer and controller validation block malformed canonical headings/signals. Markdown freshness is cache/fingerprint based rather than exact-byte action-receipted. |
| `edge:related_repository_projection` | `load_related_repos.py`, `build_cross_repo_register.py`, declarations, and registered local Git roots | context Markdown, architecture annotations, and intended per-component cross-repository bundle evidence | Declarations and JSON outputs are schema-validated; URL/path policy applies. The current context-v2 controller rebuilds the register but does not explicitly invoke the component slicer before manifest construction. |
| `edge:actor_resolution` | default, organization, repository, optional discovered actors, and recon signals through `resolve_actors.py` | projected `.actors-resolved.json`, `.actors-for-<component>.json`, architecture, bundles, and final model | Resolver schema and fingerprint/cache checks apply. Architecture receives a receipt for the resolved set; per-component slices are file-presence driven in the manifest. |
| `edge:architecture_finalization` | four analyst fragments plus route, coverage, config, source-auth, and data-relation signals | finalized components/data flows/assets/attack surface and `.trust-boundary-assessment-input.json` | Fragment schemas, component finalization, inventory fingerprint, completeness, and exact assessment-input receipt block. |
| `edge:boundary_promotion` | assessment input, boundary candidates, optional prior model, and organization/repository boundary declarations | canonical `.trust-boundaries.json`, coverage/diagnostics, and per-component boundary slices | Promotion and schema checks block. Canonical boundaries are receipted for control analysis; component slices are later admitted by file presence. |
| `edge:stride_dispatch_projection` | finalized components, control overlay, component selection, actor/boundary/index slices, deterministic signal sidecars, repository registry, taxonomy, and plugin lens selection | manifest, evidence bundles, taxonomy slices, and STRIDE jobs | Selection, schemas, containment, size limits, repository fingerprints, exact-byte receipts, and pre-dispatch rehashing block. Prior, known-threat, cross-repository, and requirements projections currently depend on pre-existing component slice files. |
| `edge:stride_merge_projection` | selected `.stride-<component>.json` outputs plus deterministic findings | `.merge-candidates.json`, bounded merge review context, decisions, and `.threats-merged.json` | Wave verification and STRIDE schemas block. Empty candidates skip the semantic merger. Full candidates are rebound by hash after review. |
| `edge:evidence_and_posture` | merged threats plus repository evidence and passive posture emitters | evidence verifier, guarded merged annotations, and triage inputs | Verifier selection is depth/cap bounded. Optional invalid summary degrades explicitly; canonical merged validation remains blocking. |
| `edge:triage_and_synthesis` | merged threats, evidence verdicts, plugin severity/CVSS policy, deterministic ranking, and optional semantic repair | triage flags, tier root causes, mitigation overrides, and canonical YAML inputs | Rating validation blocks. Semantic fallback is exceptional. Accepted synthesis artifacts are schema-validated and consumed through exact-byte receipts. |
| `edge:stage1_yaml_handoff` | all validated Phase 3-10b sidecars through `build_threat_model_yaml.py` and deterministic emitters | canonical `threat-model.yaml`, Stage 2, and later Stage 1d rebuild | YAML schema, mitigation quality, completeness, and checkpoint generation block. Stable IDs and report mutation remain deterministic. |
| `edge:abuse_case_projection` | plugin, organization, and repository catalogs plus recon signals and canonical findings through `match_abuse_cases.py` | projected matches, per-case verifiers, verdict merge, finding promotion, ranking, and YAML rebuild | Match failures may retain partial candidates; fan-out overflow and configured release gates block. The current candidate action has no structured delivery receipts. |

### Pinned gaps before shadow catalog work

The inventory exposes these current contracts without repairing them in this
slice:

1. Action `input_artifacts` do not describe all semantic inputs for context,
   recon, config, actors, controls, triage, or abuse-case verification.
2. Context and recon Markdown are validated but not represented by exact-byte
   dispatch receipts. Plugin lenses and several fixed policy files are also
   selected without per-delivery hashes.
3. Direct source reads by recon, config, architecture, controls, evidence,
   triage helpers, and abuse verification are bounded by role-specific rules,
   not one routing plan.
4. Component prior-finding, known-threat, related-repository, and requirements
   bundle inputs are admitted only when their legacy slice files already
   exist. The context-v2 controller does not yet own every slice producer.
5. Stage 1d uses candidate IDs and prompt aliases instead of the structured
   semantic-role and artifact-receipt path used by context-v2 Stage 1a-1c.
6. Runtime cleanup knows `.dispatch-context/`, `.taxonomy-slices/`, and
   `.merge-context/`, but the future effective-plan artifact still needs an
   explicit full/rebuild, diagnostic, packaging, checkpoint, and resume
   contract.

These gaps are migration inputs. None authorizes weakening an existing gate or
changing delivery behavior while the catalog first runs in shadow mode.

## Implemented migrations after the frozen inventory

The frozen rows above retain their commit-specific state. The current
context-v2 path additionally admits project context and preset-selected
organization documents to the control analyst through exact-byte receipts.
That producer emits at most five human-readable business attributes per final
component. The bundle builder projects them into a separate bounded component
artifact, and the STRIDE context plan either selects that artifact or omits it
physically. It is never folded into the mandatory Evidence Bundle, never grants
repository access, and never supplies evidence, controls, actors, boundaries,
likelihood, or severity.

This establishes the required routing granularity for later migrations:
security architecture and assumptions, actors and abuse cases, trust
boundaries, existing controls and mitigations, threats, and proposed
mitigations need independent artifacts and plan rows when their consumers can
receive or omit them independently. A field nested inside mandatory evidence
does not count as a selectable context element.

## Model

Keep three separate concepts:

1. A **context element** is a versioned, bounded unit of data with a producer,
   schema, scope, trust class, and deterministic projection policy.
2. A **consumer** is a plugin-owned semantic role or deterministic component
   that reads context for one defined purpose.
3. A **route** binds a context element to a consumer under validated run and
   application-component selectors.

The routing dimension is:

```text
plugin consumer x application component x context element -> bounded delivery
```

Do not create a configurable entry for every Python function or every schema
field. A context element is independently routable only when it can be
projected, limited, omitted, audited, or assigned differently from its parent
artifact. Closely coupled scalar fields remain one contracted element.

## Context catalog

The initial inventory must cover existing context before adding new producer
behavior. The identifiers below describe the intended granularity; the schema
migration may consolidate elements that cannot be routed independently.

### Run and target context

- repository identity, canonical root, output location, and revision;
- branch, dirty-worktree state, and changed-file scope;
- run mode, assessment depth, runtime generation, feature flags, and formats;
- full, rebuild, incremental, rerender, and resume state;
- selected repository registries and validated operator inputs; and
- bounded user scan notes represented as data, never instructions.

### Discovery context

- bounded repository tree and coverage record;
- languages, frameworks, build systems, and package manifests;
- entry points, API and UI routes, CLI surfaces, and background jobs;
- database, queue, realtime, file-upload, authentication, and authorization
  surfaces;
- configuration, IaC, container, Kubernetes, deployment, and CI/CD surfaces;
- dependency, secret, supply-chain, and git-history signals;
- recon findings, uncertainty, omissions, and coverage limits; and
- validated recon signal sidecars distinct from the Markdown summary.

### Architecture context

- component inventory, canonical component IDs, types, paths, and technologies;
- interfaces, protocols, relationships, and data flows;
- assets, data classifications, and sensitive-data handling;
- external systems, deployment zones, reachability, and exposure;
- canonical trust boundaries, adjacent boundaries, and crossed boundaries;
- actors, roles, privileges, and component interactions;
- authentication, authorization, and tenancy models;
- trust assumptions, architecture decisions, and unresolved uncertainty; and
- component fingerprints and source-to-component attribution.

### External and organization context

- organization profile and security baseline;
- organization policies and requirements;
- external business and architecture documents;
- user- and organization-defined actors;
- user-declared trust boundaries and external systems;
- user- and organization-defined abuse cases;
- known threats and known-vulnerability inputs;
- accepted risks, documented exceptions, and suppressions when their contracts
  authorize them;
- related-repository metadata and component relationships;
- bounded cross-repository evidence; and
- imported scanner evidence.

### Component security evidence

- component source slices and evidence locations;
- focus paths and exclude paths;
- interfaces and attack-surface facts;
- claimed, evidenced, missing, and compensating controls;
- known secrets, vulnerabilities, dependencies, and supply-chain findings;
- LLM and agentic-system patterns;
- input validation, output encoding, session, cryptography, audit, error,
  isolation, and rate-limit evidence;
- applicable requirements and baseline clauses;
- component-relevant known threats and prior findings;
- related-repository evidence matched to the component; and
- evidence gaps, truncation, staleness, and escape-read reasons.

### Threat-analysis context

- applicable STRIDE taxonomy slices;
- plugin-owned component and technology lenses;
- applicable abuse cases and attacker goals;
- adjacent actors, assets, trust boundaries, and data flows;
- attack prerequisites and candidate paths;
- control gaps and compensating controls;
- deterministic and semantic threat candidates;
- estimated threat count and full/light depth label;
- merge groups, bounded candidate projections, and merge decisions;
- consolidation policy and duplicate relationships; and
- analysis coverage and unsupported hypotheses.

### Rating and verification context

- severity caps, critical criteria, and CVSS eligibility decisions;
- CWE mappings and evidence requirements;
- abuse-case verification requests and verdicts;
- evidence-verification samples and results;
- confirmed, rejected, and unresolved hypotheses;
- false-positive exclusions;
- mitigation candidates, existing controls, and residual risk; and
- triage decisions and ranking inputs.

### Prior-run and identity context

- prior canonical model and structured findings;
- baseline and carry-forward candidates;
- stable T/F identity anchors;
- new, changed, resolved, accepted, and suppressed findings;
- audit changelog and prior checkpoints;
- prior component identities, paths, and fingerprints; and
- persisted runtime generation and artifact schema versions.

### Rendering and quality context

- validated threats, findings, mitigations, components, and boundaries;
- report fragments and section contract;
- branding and output configuration;
- prose and cross-reference rules;
- SARIF, structured export, and Threat Dragon projections;
- QA results, architect review, and repair plan; and
- completion-summary inputs.

Not every item above is agent-visible. Stable-ID allocation, severity and CVSS
enforcement, cleanup, schema validation, report mutation ordering, and similar
fixed policy should remain deterministic. Where a semantic consumer needs the
result, deliver the bounded decision and reason rather than the complete policy
file.

## Core configuration

Keep the human decision surface separate from runtime implementation bindings.
`data/context-routing-catalog.yaml` names categories, contexts, agents, and
assignments in language an AppSec or engineering owner can review without
reading controller code:

```yaml
schema_version: 1

categories:
  - id: actors_and_abuse_cases
    name: Actors and abuse cases
    description: Human and system actors, privileges, attacker goals, abuse-case candidates, and verification evidence.

agents:
  - id: stride_analyzer
    name: STRIDE component analyst
    purpose: Analyze one selected component from bounded evidence, taxonomy, and fixed lenses.
    scope: one_component
    stage: Threat analysis

contexts:
  - id: controls.component_evidence
    name: Component security evidence
    category: security_controls_and_evidence
    description: Bounded controls, gaps, deterministic signals, and source slices relevant to one component.
    scope: one_component

assignments:
  - id: stride-component-evidence
    context: controls.component_evidence
    agents: [stride_analyzer]
    delivery: required
    importance: essential
    applies_to: current_component
    reason: Each component analyst receives only its bounded and receipted security evidence.
```

The human file deliberately has no schemas, paths, producers, projectors,
models, commands, byte limits, token limits, or write targets. Those values
live in `data/context-routing-bindings.json`, which is plugin-owned and binds
the same IDs to closed registries and hard safety caps. The semantic validator
requires the human and internal context and agent sets to match exactly, binds
all context-v2 agents to the current semantic-role registry, and permits only
the already inventoried abuse-case verifier on the Stage-1d legacy binding.

## Future selectors and extension layers

The first human catalog deliberately exposes no component-type, capability, or
path selectors. A later trusted extension may add bounded selectors only after
the resolver validates and enforces them over canonical data:

- canonical component ID;
- component type and tier;
- technology and capability enums;
- deployment zone and exposure;
- interface and protocol class;
- adjacent actor, asset, data class, or trust-boundary ID;
- related-repository relationship type; and
- resolved run mode and assessment depth.

Exact component IDs are target-specific and may change after architecture
updates. The resolver must report unmatched and ambiguous selectors. Prefer
stable semantic selectors when a project does not control component identity.

The human target field remains limited to `whole_run`, `current_component`, and
`current_candidate`. Runtime migration state and technical selection details
remain outside the human catalog.

Configuration has four trust layers:

1. **Core plugin policy** defines mandatory and forbidden human assignments;
   its separate internal bindings define projectors, limits, and failure
   behavior.
2. **Packaged organization policy** may add schema-backed context sources,
   catalogs, assignments, and stricter limits.
3. **Repository declarations** may contribute facts such as known threats,
   related repositories, boundaries, actors, requirements, and abuse cases.
4. **Invocation overrides** may select documented bounded options for one run.

Repository declarations are untrusted data. They may not select agents,
instructions, tools, commands, projectors, schemas, arbitrary paths, or write
targets. They may not remove a mandatory context, relax an internal limit,
downgrade a failure rule, or make imported prose executable. A new
organization-defined context shape requires a trusted packaged schema and
internal producer binding; those technical settings never become parameters
in the human assignment file.

## Effective routing plan

Resolve the layered configuration only after the application-component
inventory required by a route is final. Persist one schema-validated effective
plan under the runtime output, with cleanup and preservation behavior assigned
explicitly by contract.

For every delivery, record:

- run, action, named agent, dispatch-job, and application-component identity;
- human category, context name, assignment, importance, and reason;
- context-element ID and internal contract version;
- producer and source artifact receipt;
- deterministic projector and selector match reason;
- trust and sensitivity class;
- required, optional, and forbidden status;
- priority and failure behavior;
- source and delivered byte, token, item, and line counts;
- truncation, omission, staleness, and escape-read disclosures; and
- exact-byte hash and freshness inputs.

The action schema should reference effective-plan entries and artifact receipts
instead of repeating large context descriptions. The controller revalidates the
plan entry, artifact containment, schema, and exact bytes immediately before
dispatch. Diagnostics must expose the effective plan in a human-readable form
without printing sensitive source content.

An inspection should be able to explain a decision such as:

```text
stride_component_analyst / auth-service
  + boundaries.adjacent: TB-002 and TB-004 touch the component
  + threats.known.component_relevant: 6 of 83 entries matched identity/session
  + repositories.related.component_evidence: 9 bounded slices from one declared relationship
  - abuse_cases.file_upload: no matching interface or capability
  - recon.complete_markdown: forbidden for this consumer
```

## Validation and failure rules

- Define schemas for the core configuration, trusted extension shape, effective
  plan, and every new structured projection.
- Reject unknown context IDs, consumers, projectors, selectors, schemas, and
  failure modes.
- Reject duplicate routes, contradictory required/forbidden assignments,
  dependency cycles, and unresolved mandatory inputs.
- Enforce per-element and per-consumer byte, token, item, line, and path limits.
- Canonicalize and contain every local path; bind remote context to existing URL
  and related-repository policy.
- Bind each delivery to an exact-byte receipt and reject stale inputs.
- Fail closed for missing or invalid mandatory security context.
- Continue only with an explicit diagnostic where the core contract marks an
  element optional.
- Preserve mandatory core routes when an organization or repository extends the
  configuration.
- Keep sensitive content out of diagnostic summaries and event logs.

## Migration sequence

1. Complete one live context-v2 full/rebuild invocation and close any producer
   or schema blocker it exposes.
2. Fix the existing focus/exclude-path delivery gap under its current contract.
3. Inventory every current producer-consumer edge and pin it with tests.
4. Add the core configuration schema, semantic validator, resolver, and
   effective-plan schema without changing dispatch behavior.
5. Migrate existing Stage-1 role metadata, evidence bundles, taxonomy, lenses,
   and receipts to the resolved plan.
6. Migrate known threats, related repositories, external context, trust
   boundaries, actors, requirements, prior findings, and abuse cases one source
   at a time.
7. Add trusted organization extensions and bounded repository declarations.
8. Use the same control plane for WP6 Stage 2-4 context reduction.
9. Migrate incremental and resume only after full/rebuild parity.
10. Run the controlled A/B cohort and consider default rollout only after the
    acceptance matrix passes.

Steps 1-4, the first bounded part of step 5, and the related-repository,
business, architecture, known-threat, prior-finding, actor, boundary,
requirement, and control parts of step 6 are implemented. Each STRIDE job
now receives one receipted component context plan instead of the shared
dispatch manifest. The plan binds the evidence bundle, taxonomy slice, fixed
lens IDs, and controller-owned analysis policy to active effective-plan
delivery IDs. The shared effective plan remains controller-only and is
revalidated immediately before dispatch.

The complete related-repository registry is now controller-only. A component
bundle fingerprints only related roots named by its admitted source slices,
and a STRIDE job receives an exact-byte-receipted root projection containing
only those repository IDs. Jobs without related source evidence receive no
projection. The projection is bound to the component plan and source-registry
hash; extra, missing, unknown, stale, or cross-component entries block.

Generated threats, proposed mitigations, and abuse cases remain on their
inventoried paths. The Stage-1d abuse-case verifier remains legacy.

## Exit gates

- Every context consumed in Stage 1 has one catalog entry, producer, schema or
  explicitly documented scalar contract, route, limit, and validation path.
- The effective plan reconstructs every Stage-1 dispatch input and explains
  every conditional inclusion, exclusion, and truncation.
- Existing Stage-1 fixtures produce equivalent selected components, evidence,
  lenses, findings, and gates before new extension behavior is enabled.
- Repository content cannot select or alter execution surfaces or remove
  mandatory context.
- Focus paths, exclude paths, known threats, related-repository evidence, trust
  boundaries, actors, requirements, external context, prior findings, and abuse
  cases have explicit component projections or explicit global-only ownership.
- No complete shared analysis artifact enters a focused consumer when a bounded
  projection exists.
- Cleanup, diagnostics, permissions, packaging, resume, and checkpoint behavior
  cover the new configuration and effective-plan artifacts.
- WP6 and the paid A/B cohort remain blocked until these gates pass.
