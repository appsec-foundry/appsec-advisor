# Analysis — context routing control plane

- Date: 2026-08-07
- Status: proposed prerequisite for WP6
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

Use one plugin-owned configuration as the source of truth for context elements,
consumers, and routes. The exact filenames are an implementation decision, but
the logical shape is:

```yaml
version: 1

context_elements:
  threats.known.component_relevant:
    producer: known_threat_resolver
    artifact_schema: known-threat-projection-v1
    scope: per_component
    projector: known_threats_by_component_v1
    trust: repository_untrusted
    delivery: agent
    limits:
      max_items: 40
      max_tokens: 3000

  boundaries.adjacent:
    producer: trust_boundary_resolver
    artifact_schema: trust-boundary-projection-v1
    scope: per_component
    projector: adjacent_boundaries_v1
    trust: generated_validated
    delivery: both

consumers:
  stride_component_analyst:
    phase: threat_analysis
    scope: per_component
    required:
      - evidence.component
      - boundaries.adjacent
      - actors.interacting
    forbidden:
      - recon.complete_markdown
      - architecture.complete_model

routes:
  - id: stride-related-repository-evidence
    consumer: stride_component_analyst
    context: repositories.related.component_evidence
    when:
      component.related_repository_links: present
    required: false
    priority: high
    on_missing: continue_with_diagnostic
    on_invalid: abort
```

Projectors, producers, consumer IDs, instruction files, tools, commands, and
write targets resolve only through plugin-owned allow-listed registries. The
configuration must not duplicate the current semantic-role registry. Migrate
that registry into the same authoritative model or generate one representation
from the other.

## Selectors and extension layers

Routes may use bounded selectors over validated data:

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

Configuration has four trust layers:

1. **Core plugin policy** defines mandatory contexts, consumers, projectors,
   limits, forbidden deliveries, and failure behavior.
2. **Packaged organization policy** may add schema-backed context sources,
   catalogs, assignments, and stricter limits.
3. **Repository declarations** may contribute facts such as known threats,
   related repositories, boundaries, actors, requirements, and abuse cases.
4. **Invocation overrides** may select documented bounded options for one run.

Repository declarations are untrusted data. They may not select agents,
instructions, tools, commands, projectors, schemas, arbitrary paths, or write
targets. They may not remove a mandatory context, relax a limit, downgrade a
failure rule, or make imported prose executable. A new organization-defined
context shape requires a trusted packaged schema and producer registration.

## Effective routing plan

Resolve the layered configuration only after the application-component
inventory required by a route is final. Persist one schema-validated effective
plan under the runtime output, with cleanup and preservation behavior assigned
explicitly by contract.

For every delivery, record:

- run, action, consumer, dispatch-job, and application-component identity;
- context-element ID and schema version;
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
