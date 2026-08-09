# Implementation plan — threat-analysis context and turn reduction

- Date: 2026-08-05
- Base: `d9f6bdef0c2ca64f409e6b789c977f9ece159772`
- Primary replay target: OWASP Juice Shop run
  `003c27f7-83e6-4b01-b46a-cadb493c69e1`
- Related:

  - `docs/internal/analysis/analysis-threat-analyst-context-cost-2026-08-05.md`
  - `docs/internal/contracts/orchestration-actions.md`
  - `docs/internal/contracts/schema-invariants.md`
  - `agents/shared/completion-contract.md`
  - `docs/internal/analysis/implplan-dedicated-trust-boundary-assessment-stage-2026-07-27.md`
  - `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md`

## Status and decision

Implement the cost reduction as an extension of the existing deterministic
control plane. Do not introduce a second orchestrator and do not treat
compaction as the primary optimization.

The execution rule is:

```text
Python controls execution and validates state.
The model decides security meaning at explicit semantic boundaries.
The filesystem remains authoritative between boundaries.
```

The migration has two independent but complementary admission gates:

1. context admission limits what enters a semantic session and what later tool
   results remain useful;
2. turn admission prevents status, fixed routing, successful validation, and
   mechanical normalization from entering a model loop at all.

These are standing rules, not plan-local decisions. Their durable ownership,
generation coexistence, admission, semantic-producer, and context-routing
contracts live in `docs/internal/contracts/orchestration-actions.md` and
`docs/internal/contracts/context-routing.md`; this plan records migration and
acceptance status only.

The first release target is a p50 reduction from 928 to at most 700 usage turns
on the fixed thorough benchmark, together with at least 20% reconstructed cost
reduction. A later 650-turn target is a stretch goal, not a release gate for the
first migration.

## Verified starting point

The measured thorough run used 30 sessions, 928 usage turns, 67.26M cache-read
tokens, 2.90M cache-write tokens, and USD 40.69 at list price. The role split
was:

| Role | Sessions | Turns | Reconstructed cost |
|---|---:|---:|---:|
| Thin top-level | 1 | 178 | USD 8.40 |
| Threat analyst | 3 | 134 | USD 6.80 |
| STRIDE analyzers | 10 | 187 | USD 14.29 |
| Other subagents | 16 | 429 | USD 11.20 |

The current architecture already provides the foundation for this plan:

- `scripts/orchestration_controller.py` validates every action against
  `schemas/orchestration-action.schema.json` and already owns many post-stage
  gates.
- `skills/create-threat-model/SKILL-thin-stage1.md` already dispatches Stage 1a,
  Stage 1b, Analyst A, bounded STRIDE waves, and Analyst B as separate contexts.
- `scripts/build_stride_dispatch_manifest.py` already builds a schema-validated
  component manifest and references per-component `.dispatch-context/` files.
- `scripts/stride_dispatch_waves.py` already owns bounded scheduling and retry
  state.
- `merge_threats.py`, `triage_validate_ratings.py`,
  `triage_compute_ranking.py`, and `build_threat_model_yaml.py` already own much
  of the post-STRIDE deterministic progression.
- `agents/shared/completion-contract.md` already prevents artifact prose from
  being copied into the parent conversation.

The remaining defect is ownership. The 152,034-byte threat-analyst definition
still carries multiple phase algorithms, and Analyst B still acts as a workflow
engine around deterministic scripts and focused specialists. STRIDE agents
still discover and reread evidence that the pipeline can project before
dispatch.

## Goals

1. Keep plugin-selected startup payload at or below 10k tokens per new threat
   semantic role and initial resident context at or below 30k when the runtime
   floor permits it.
2. Reduce the target thorough run to at most 700 p50 usage turns without model,
   depth, selected-component, or quality-gate changes.
3. Make successful deterministic validation and its fixed successor one
   controller operation, without a validation-only model re-entry.
4. Make status and logging consume zero dedicated model turns.
5. Give each semantic role only its current contract, bounded state manifest,
   necessary tools, and targeted evidence.
6. Keep all six STRIDE categories and existing evidence requirements mandatory.
7. Preserve existing artifact formats, T/F identity, severity rules, resume
   behavior, and renderer/QA ownership.
8. Keep the current Agent runtime, hooks, permission model, cancellation, and
   telemetry surfaces.
9. Make every context delivery explainable through one schema-validated catalog
   and effective routing plan before extending context reduction to Stage 2-4.

## Non-goals

- Do not reduce assessment depth, selected components, evidence standards, or
  verification merely to meet a token target.
- Do not switch Opus work to Sonnet or Sonnet work to Haiku as part of this
  migration.
- Do not put the complete shared state into `CLAUDE.md`, agent definitions, or
  dispatch prompts.
- Do not make an LLM-authored summary or completion message authoritative.
- Do not add a vector store or direct Messages API runtime.
- Do not depend on undocumented Claude Code context-management flags.
- Do not lower autocompaction thresholds until the new session peaks are
  measured.
- Do not rewrite deterministic merge, ranking, or stable-ID algorithms in
  prompts.

## Target execution model

```mermaid
flowchart TD
    A[Controller advance] --> B{Next boundary}
    B -->|Deterministic work| A
    B -->|Semantic work| C[Schema-validated dispatch action]
    C --> D[Small focused agent]
    D --> E[Contracted artifact on disk]
    E --> F[Controller post-agent gate]
    F -->|Valid| A
    F -->|Mechanical defect| G[Deterministic normalization]
    G --> F
    F -->|Semantic conflict| H[Focused repair action]
    H --> D
    B -->|Complete| I[Read-only final gates]
```

The skill remains the Agent-call execution shim because the Python controller
cannot invoke Claude Agent tools. The controller owns every fixed decision up
to that call: which plugin-owned role is allowed, which bounded inputs it
receives, which artifacts must appear, which validators run, and which fixed
stage follows success.

One controller action may request a bounded parallel wave. The skill issues all
Agent tool blocks in one assistant message, as it already does for STRIDE. The
action must never contain repository-selected agent names, commands,
instruction files, tools, or write paths.

## Turn-admission contract

Every measured model turn receives one primary diagnostic category:

| Category | Owner after migration | Admission rule |
|---|---|---|
| `semantic_decision` | Focused agent | Admit only when evidence requires qualitative security judgment |
| `evidence_request` | Focused agent | Use the bounded bundle first and batch independent slices |
| `agent_dispatch` | Thin skill | At most one parent turn per semantic boundary or parallel wave |
| `artifact_write` | Focused agent | One contracted write phase per semantic output where practical |
| `validation` | Controller | No validation-only model turn on success |
| `repair` | Deterministic normalizer or focused repair agent | Dispatch a model only for semantic conflicts |
| `status_or_logging` | Python event writers | Zero dedicated model turns |
| `workflow_routing` | Controller | At most one parent turn per semantic boundary |

Extend `scripts/context_window_report.py` rather than adding a production
sidecar. Before classification, aggregate every JSONL content block with the
same assistant `message.id`; deduplicating by retaining only the first block can
drop a later `tool_use` block from the same model response. Its optional JSON
diagnostic output should assign one primary category with a documented
precedence rule, retain secondary category candidates, and report confidence.
Mixed and low-confidence turns remain visible and require manual adjudication
before a release gate may claim zero turns in a category. This is benchmark
telemetry, not authoritative runtime state.

The classifier must distinguish a batched turn from its number of tool uses.
One response that dispatches eight STRIDE agents is one parent
`agent_dispatch` turn, not eight turns. Subagent turns remain counted in their
own transcripts.

Transcript usage cannot attribute the first resident context to the runtime,
agent definition, task, tool schemas, and preloaded skills. Measure static
plugin-owned layers with the provider token-counting path when available, or
with controlled one-variable startup A/B sessions otherwise. Use transcript
usage only for the assembled first-resident measurement. Record the measurement
method, Claude Code version, model, tool allow-list, task hash, and agent
definition hash with every startup-layer result.

## Context-admission contract

Create `skills/internal-threat-analysis-kernel/SKILL.md` as one concise,
plugin-owned shared threat-analysis kernel containing only:

- untrusted-input and evidence rules;
- stable-ID and artifact-authority rules;
- phase-independent severity and CVSS boundaries;
- validation, failure, logging, and completion semantics; and
- shared prose rules used by every threat semantic role.

Keep phase algorithms, renderer rules, repair instructions, mode branches,
large examples, and future-phase work outside the kernel. The initial budgets
are:

| Surface | Maximum |
|---|---:|
| Shared kernel | 4k tokens |
| One role contract | 3k tokens |
| Dispatch task | 1.5k tokens |
| State manifest | 0.5k tokens |
| Total plugin-selected startup payload, including tools and preloaded skills | 10k tokens |
| Initial resident context, including measured runtime floor | 30k tokens |

Preload the kernel through the documented custom-agent `skills` frontmatter so
it is present before the first model turn. A semantic role must not spend a
runtime `Read` turn loading it. Packaging and agent-definition tests must prove
that only the intended roles preload it and that repository content cannot
select another skill.

Treat the kernel as a non-user-configurable transitive dependency of the
focused core agents. Internal packaging must retain it whenever those agents are
shipped, regardless of organization skill include/exclude policy or runtime
skill toggles. Update the packaging contract and tests rather than allowing an
internal build to ship an agent whose required kernel was filtered out.

Add separate kernel and role surfaces to `data/context-budgets.yaml`. Retain the
existing `threat_analyst` allowance while any legacy path can still select that
agent; remove it only with the legacy agent or its final runtime reference.
Byte limits remain fast drift guards, while static token measurements and
transcript resident measurements own release acceptance. WP0 must measure the
tool and preloaded-skill surface before the 10k total becomes an enforced gate:
the four initial allocations already consume 9k and must be rebalanced if the
required tool schemas do not fit in the remaining 1k.

## Contract changes

### Contract A — orchestration action receipts and dispatch jobs

Extend, do not replace:

```text
scripts/orchestration_controller.py
schemas/orchestration-action.schema.json
docs/internal/contracts/orchestration-actions.md
```

Add bounded, controller-authored fields for:

- plugin-owned semantic role enum;
- bounded parallel dispatch jobs;
- artifact path, schema identity, SHA-256, record count, and validation status;
- unresolved semantic decision keys; and
- fixed resume action.

Keep the current human-readable `receipts: string[]` field for compatibility and
add structured `artifact_receipts`; do not change the element type of the
existing field in place. Version the new dispatch-job and receipt shapes. The
schema must cap arrays, strings, and total jobs, and reject unknown properties.
It can reject syntactic traversal and absolute paths, but it cannot prove total
serialized size, filesystem containment, provenance, symlink safety, or
uniqueness by object key.

The controller-side semantic validator must therefore:

- map the semantic role enum to plugin-owned agent, instruction, tool, and
  output-contract constants; an action never carries a repository-selected
  agent or instruction path;
- resolve the canonical output root once and reject traversal, absolute paths,
  and symlink escapes for every artifact path;
- reject duplicate job and component IDs independently of JSON Schema;
- reject an action whose canonical serialized form exceeds the documented byte
  cap;
- fail closed when the structural validator is unavailable;
- derive receipts from the exact validated bytes, not agent prose; and
- re-read and re-hash an artifact immediately before consumption so a receipt
  cannot authorize bytes changed after validation.

Subprocess stdout and stderr included in an action must be reduced to bounded
status fields; full diagnostic output stays on disk. Agent prose cannot populate
receipts.

The action remains ephemeral. Do not add a persisted stage-receipt sidecar
unless resume testing proves that current checkpoints and contracted artifacts
cannot reconstruct the action.

Before adding `fixed_resume_action`, define and test the reconstruction function
from `.skill-config.json`, the runtime-generation marker, checkpoints, artifact
schema versions, and validated artifact fingerprints. If two valid successor
actions can be reconstructed from the same durable state, the state contract is
insufficient and must be fixed before rollout rather than resolved by model
judgment.

### Contract B — per-component STRIDE evidence bundle

Add:

```text
schemas/stride-evidence-bundle.schema.json
scripts/build_stride_evidence_bundles.py
$OUTPUT_DIR/.dispatch-context/<component-id>/evidence-bundle.json
```

The producer consumes only validated current artifacts and emits bounded
component-local data:

- component identity and selected paths;
- interfaces and trust-boundary crossings;
- relevant actors and security controls;
- known-threat, prior-finding, requirements, and cross-repository references;
- deterministic recon signals; and
- source-slice references with repository-relative file, start line, end line,
  signal kind, and content hash.

It must not copy complete source files, choose findings, assign severity, or
turn imported strings into commands or instruction paths. Slice ranges and
array sizes need explicit caps with deterministic risk ordering and disclosure
when truncation occurs.

The bundle contract must also cap total serialized bytes, estimated tokens,
total referenced source lines, and values per signal class. Its ordering may use
only documented deterministic signal fields; it must not infer qualitative
security importance. Truncation metadata records the original count, retained
count, omitted count, cap, and ordering key for every affected class.

Every source slice records a repository ID from a controller-owned registry,
repository-relative path, range, and content hash. The primary repository entry
is bound to the analyzed commit plus a dirty-worktree fingerprint. A related
repository entry is allowed only when it was resolved from
`docs/related-repos.yaml` through the existing canonical source-resolution
contract. The validator re-resolves every path under its registered repository
root and re-hashes every slice before dispatch. A mismatch makes the bundle
stale and requires deterministic regeneration; it never degrades to an
unverified Agent read.

Extend `schemas/stride-dispatch-manifest.schema.yaml` and
`build_stride_dispatch_manifest.py` with the bundle path and fingerprint. Keep
the existing individual index paths during the migration for compatibility.
`validate_dispatch_manifest.py` must validate the bundle and its component ID
before dispatch.

On the context-v2 path, the validator must also apply the same canonical
containment checks to the retained legacy `index_paths`. Compatibility means
retaining those fields during migration, not retaining acceptance of arbitrary
absolute paths. Missing `jsonschema`, malformed source artifacts, a stale
fingerprint, duplicate component IDs, or a bundle outside `.dispatch-context/`
is fatal before Agent dispatch.

The existing `.dispatch-context/` cleanup entry already covers the new file.
Update permission rationale, cleanup tests, and diagnostic inventory only where
the new producer or artifact changes their actual contract.

### Contract C — semantic role outputs

Add focused definitions for these responsibilities:

```text
agents/appsec-architecture-analyst.md
agents/appsec-control-analyst.md
agents/appsec-post-stride-synthesizer.md
```

- The architecture analyst consumes completed recon and contracted topology
  inputs. It writes the existing architecture-stage artifacts and does not
  dispatch other agents or run downstream gates.
- The control analyst consumes validated architecture, boundary, and control
  inputs. It writes the existing Phase-8 control and STRIDE-context artifacts
  and does not dispatch STRIDE.
- The post-STRIDE synthesizer runs only for qualitative mitigation overrides,
  cross-finding root-cause synthesis, or other explicitly contracted outputs
  that deterministic producers cannot derive. It does not run merge, ranking,
  YAML build, validators, workflow logging, or stage routing; it still emits its
  own agent lifecycle and semantic step events.

Keep `agents/appsec-threat-analyst.md` as the legacy path until full/rebuild,
incremental, and resume parity are complete. Do not let new and legacy agents
write the same artifact in one run.

### Contract C1 — complete phase and producer ownership

The migration is not activated from role names alone. Land and test this
producer map before a focused agent is selectable:

| Boundary | Semantic producer | Deterministic owner and required handoff |
|---|---|---|
| Phases 1 and 2 | Existing context resolver and recon scanner, dispatched as one bounded Level-0 wave | Controller resolves cache/fingerprint decisions and validates `.threat-modeling-context.md`, `.recon-summary.md`, and contracted recon sidecars |
| Phase 2.5 | Legacy config agent only when the deterministic IaC-surface check selects it; Context-v2 uses the deterministic catalog producer directly | Controller owns the surface check and validates complete `.config-scan-findings.json` semantics |
| Phase 2.6 | None unless an existing coverage contract explicitly selects a specialist | Existing route, database-separation, and architecture-coverage scripts own their sidecars and exit semantics |
| Phase 2.7 | Existing actor discoverer only when the cache/depth contract selects it | Existing actor resolvers own the canonical actor artifacts and validation |
| Phases 3–6 | Architecture analyst | Controller validates `.components.json`, `.data-flows.json`, `.assets.json`, attack-surface sidecars, architecture-stage fragments, and the Phase-6 checkpoint, then runs component finalization |
| Phase 7 / Stage 1b | Existing trust-boundary analyst | Existing assessment-input builder, promotion, normalization, coverage gate, and checkpoint remain authoritative |
| Phases 8 and 8b | Control analyst | Controller validates `.security-controls.json`, requirements violations, STRIDE-context inputs, early structural artifacts, and the Phase-8 checkpoint |
| Phase 9 dispatch | Per-component STRIDE analyzers | Controller builds and validates bundles and the manifest; skill issues the bounded Agent wave; wave controller owns attempts and completion |
| Phase 9 merge | Existing threat merger only for ambiguous candidate groups | `merge_threats.py` owns collect/finalize, ordering, and IDs |
| Phase 10 | None | Existing deterministic posture emitters own their outputs |
| Phase 10a | Existing evidence verifier only when its sampling contract selects findings | Controller validates the verification artifact and applies existing failure semantics |
| Phase 10b | Existing triage validator only for unresolved semantic flags; post-STRIDE synthesizer only for contracted qualitative outputs | Existing rating validation and ranking scripts remain authoritative; controller validates `.mitigation-overrides.json` and `.tier-root-causes.json` |
| YAML handoff | None | `build_threat_model_yaml.py`, `validate_intermediate.py`, completeness gates, and the Phase-10b checkpoint own the Stage-2 handoff |

For every row, the implementation patch must name exact input and output schema
versions, allowed writers, validator commands, exit-code classes, checkpoint
transition, retry budget, and next action in the orchestration contract. The
controller must preserve the existing parallel recon behavior, cache decisions,
failure fallbacks, budget-critical handling, and trust-boundary substage; moving
the Agent call to Level 0 must not silently simplify those contracts.

The controller and skill own `AGENT_INVOKE`/`AGENT_DONE`, phase transitions, and
fixed presentation. Focused agents own only their `AGENT_START`/`AGENT_END`,
semantic step events, artifact writes, and semantic failure details. Update
`agents/shared/logging-standard.md` and its tests with that ownership change.
Logging remains batched with useful work, and no controller-authored proxy event
may claim to be an agent-authored semantic event.

### Contract D — post-STRIDE progression

Move fixed progression from Analyst B into controller commands backed by the
existing scripts:

```text
STRIDE verify
  -> merge_threats.py collect
  -> focused merger only when ambiguous groups exist
  -> merge_threats.py finalize
  -> deterministic Phase-10 posture emitters
  -> evidence-verifier dispatch only when its sampling contract selects work
  -> triage_validate_ratings.py
  -> focused triage validator
  -> triage_compute_ranking.py
  -> focused post-STRIDE synthesis only when required
  -> build_threat_model_yaml.py
  -> validate_intermediate.py and completeness gates
```

Each controller command runs until the next semantic dispatch or a blocker. A
successful empty candidate set skips its specialist. A validator success never
returns a repair action. A mechanical defect is normalized only where the
relevant contract already permits normalization. An ambiguous merge, evidence
conflict, or unsupported qualitative synthesis may return a focused semantic
action.

The deterministic ordering, stable-ID allocation, severity caps, CVSS
eligibility, and current failure semantics remain authoritative. Remove any
inline LLM fallback that would reimplement a deterministic script.

Contract D is not production-selectable until the post-STRIDE synthesizer and
all required semantic branches exist. WP3 may exercise controller transitions
in unit, fixture, and shadow comparison modes, but the live runtime continues
through the legacy Analyst-B boundary until WP4 activates the complete producer
set atomically.

### Contract E — context catalog and effective routing plan

Add one plugin-owned, schema-validated catalog for context elements, consumers,
and routing policy. It must describe the existing producer-consumer edges before
it changes their behavior. Do not create a second orchestrator or a second
semantic-role registry.

The catalog separates plugin consumers from analyzed application components. A
route binds one versioned context element to one plugin-owned semantic or
deterministic consumer under validated run and component selectors:

```text
plugin consumer x application component x context element -> bounded delivery
```

Each independently routable context element defines its producer, schema or
bounded scalar contract, scope, deterministic projector, trust class, delivery
audience, limits, requiredness, priority, freshness inputs, and failure
behavior. Core policy owns the allow-listed consumers, projectors, instruction
files, tools, commands, paths, mandatory contexts, and maximum limits.
Repository content may contribute validated facts, but it cannot select or
alter those execution surfaces or remove a mandatory context.

The controller resolves core policy, trusted organization extensions, bounded
repository declarations, invocation settings, and the finalized component
inventory into one schema-validated effective routing plan. Each plan entry
records the dispatch job, application component, context ID, selection reason,
source receipt, projector, trust class, requiredness, source and delivered size,
truncation or omission, and exact-byte freshness binding. Orchestration actions
reference the effective plan and artifact receipts instead of repeating large
context descriptions.

The catalog covers run state; discovery and recon; components, interfaces, data
flows, actors, assets, trust boundaries, and external systems; known threats,
prior findings, related repositories, cross-repository evidence, requirements,
organization and external context, user-defined abuse cases, controls, source
slices, focus and exclude paths, secrets, dependencies, supply-chain and LLM
signals; taxonomy and lenses; merge, verification, rating, and mitigation
inputs; stable identity and carry-forward state; and rendering and QA inputs.
Not every element is agent-visible: deterministic consumers retain ownership of
stable IDs, severity and CVSS enforcement, cleanup, schema validation, and
report mutation order, and semantic roles receive only the bounded decision or
projection they require.

The detailed inventory, trust layers, selector model, example configuration,
validation rules, and migration sequence are defined in
`docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md`.
That analysis is subordinate to this plan; it is not a separate rollout plan.

## Work packages

### WP0 — freeze measurement and add turn telemetry

Change:

- `scripts/context_window_report.py`;
- `tests/test_context_window_report.py`;
- `scripts/verify_run_costs.py` and `tests/test_verify_run_costs.py` for the
  separately identified Haiku 4.5 pricing correction; and
- the benchmark command in the related analysis.

Add startup-layer reporting, role totals, turn-purpose classification,
compaction duration, and unclassified/mixed-turn disclosure. Reproduce the
existing totals before changing runtime behavior.

Aggregate all content blocks by assistant `message.id` before inspecting tool
uses. Add controlled startup measurements for the empty runtime floor, each
tool allow-list, the shared kernel, each role definition, the dispatch task, and
the state manifest. Do not label a counter-derived residual as a measured
layer. Pin the Claude Code version, model ID, pricing table version, and input
hashes in the diagnostic result.

Exit gate: the report reconstructs 928 turns and USD 40.69 from the fixed run,
batched tool-use turns retain every content block, and all existing output
remains backward compatible unless a new flag is used. A reviewed measurement
record either proves that the required tool surface fits the 10k plugin-owned
startup budget or amends the individual allocations before WP1 enforces them.

### WP1 — land schemas, admission budgets, and security constraints

Change:

- `data/context-budgets.yaml`;
- `tests/test_prompt_token_bounds.py`;
- `tests/test_agent_definitions.py`;
- `tests/test_skill_definitions.py`;
- `schemas/orchestration-action.schema.json`;
- `docs/internal/contracts/orchestration-actions.md`;
- `scripts/package_internal_plugin.py`, its packaging contract, and packaging
  tests for the mandatory internal kernel;
- `data/required-permissions.yaml`; and
- permission coverage tests.

Add the internal preloaded kernel, role surfaces, bounded and versioned
dispatch-job shape, separate artifact-receipt shape, action-size cap, and
evidence-bundle schema. Retain the legacy threat-analyst budget. No runtime
selects the new path yet.

Exit gate: schema and semantic-validation tests reject traversal, absolute
paths, symlink escapes, unknown roles, repository-selected instruction paths,
oversized arrays/actions, duplicate component IDs, missing validation
dependencies, and unbounded strings. Tests prove that role enums resolve only
through the plugin-owned registry and that an artifact changed after receipt
creation is rejected at consumption.

### WP2 — build and validate evidence bundles

Implement `build_stride_evidence_bundles.py` with its mandatory
`tests/test_build_stride_evidence_bundles.py`. Wire it into manifest production
and validation behind a temporary internal rollout switch. In Slice B this is a
shadow/fixture path only: it may build and compare receipts, but it must not
change the live Agent dispatch or artifact producer.

Update:

- `scripts/build_stride_dispatch_manifest.py`;
- `scripts/validate_dispatch_manifest.py`;
- `schemas/stride-dispatch-manifest.schema.yaml`;
- `tests/test_dispatch_manifest.py`;
- `tests/test_validate_dispatch_manifest.py`; and
- cleanup, diagnostic, and permission tests when their contracts require it.

Exit gate: the same selected component set is produced, every selected
component has a valid bundle, imported data cannot alter paths or execution,
and bundle omission fails before Agent dispatch on the new path. Total bytes,
estimated tokens, source-line budgets, per-class truncation disclosure,
primary-repository dirty-worktree changes, related-repository registry checks,
stale slice hashes, legacy index-path containment, and cross-repository escape
attempts have explicit success and failure tests.

### WP3 — extend the controller to run to semantic boundaries

Add controller actions for the Phase-1/2 bounded wave, conditional Phase 2.5,
Phase-2.6 deterministic work, Phase-2.7 actor resolution, architecture and
control handoffs, STRIDE preparation, post-wave verification, conditional merge
review, post-merge progression, conditional triage, and post-triage
finalization. Reuse the current action schema and controller; do not add a
parallel state machine.

Change:

- `scripts/orchestration_controller.py`;
- `skills/create-threat-model/SKILL-thin-stage1.md`;
- `docs/internal/contracts/orchestration-actions.md`;
- `agents/shared/logging-standard.md`;
- `tests/test_orchestration_controller.py`;
- `tests/test_stage1_dispatch_contract.py`;
- `tests/test_dispatch_prompt_cache_order.py`; and
- the existing merge, triage, and checkpoint tests touched by ownership changes.

At each boundary, the thin skill should perform only fixed presentation, one
controller call, and the returned Agent wave. Logging and stats commands should
be part of the controller operation where their updated contract assigns
ownership. Preserve the current one-message parallel recon and STRIDE dispatch
semantics.

Exit gate: on a success-only fixture, post-STRIDE deterministic progression
does not enter the threat analyst. Candidate-free merge and triage branches
skip their specialists. Every semantic dispatch is allow-listed and bounded.
The full producer map has transition tests, but live context-v2 activation is
still disabled until WP4 supplies every semantic role.

### WP4 — split threat semantic roles atomically

Add the three focused agent definitions and switch only thin full/rebuild runs
to them behind the rollout switch. Move specialist fan-out and gates to the
controller/skill boundary before removing those instructions from the legacy
definition.

Change:

- the new agent files;
- `skills/create-threat-model/SKILL-thin-stage1.md`;
- relevant phase-group files so each algorithm has one owner;
- `data/context-budgets.yaml`;
- `tests/test_agent_definitions.py`;
- `tests/test_skill_definitions.py` and packaging tests for the preloaded kernel;
- `tests/test_prompt_token_bounds.py`; and
- stage artifact and checkpoint tests.

This package activates only together with WP1-WP3. A small prompt without its
validated projection is not a shippable intermediate state.

Exit gate: each new role starts at or below the admission budgets, has no unused
tool or preloaded skill, cannot execute future phases, and produces the same
contracted artifacts and checkpoints as the legacy full/rebuild path. Context,
recon, config, actor, boundary, merge, evidence, and triage specialists are
dispatched only at the Level-0 boundaries in Contract C1; no focused semantic
role retains the `Agent` tool unless a separately documented contract requires
it.

### WP5 — modularize the STRIDE agent

Reduce `agents/appsec-stride-analyzer.md` to the mandatory six-category
workflow, evidence rules, output contract, and failure semantics. Put optional
component lenses in plugin-owned bounded files selected only from validated
feature enums. Repository content may select data values but never a lens path.
Preload the same internal kernel and remove duplicated shared invariants from
the analyzer; do not add a runtime kernel-read turn.

The analyzer must:

1. read its evidence bundle once;
2. batch independent source slices;
3. record a bounded escape reason before broader discovery;
4. keep all six categories mandatory; and
5. leave schema validation and mechanical repair to the post-agent gate.

Update agent, manifest, caching-order, token-bound, dispatch, and STRIDE golden
tests. Preserve cheap-STRIDE pacing and full-depth exclusions exactly.

Exit gate: first resident STRIDE context falls by at least 16k tokens against
the fixed run, selected-component and six-category coverage are unchanged, and
broader-search escapes are measurable.

### WP5a — centralize context catalog and routing

Begin only after the context-v2 Stage-1 path completes one live full/rebuild
invocation and its producer or schema blockers are closed. Fix the existing
`focus_paths`/`exclude_paths` delivery gap first, then inventory and pin every
current Stage-1 producer-consumer edge before changing admission behavior.

The first implementation slice is fixed and must complete before catalog
scaffolding begins:

1. Trace and test the existing path from the control-analyst producer and
   `stride-analyst-context` schema through the STRIDE dispatch manifest to the
   evidence-bundle builder, bundle schema, thin runtime, and v2 STRIDE
   consumer. The current loss occurs after manifest construction: live
   component `focus_paths` survive into the manifest but do not enter the
   evidence bundle or v2 consumer admission.
2. Define one normalized, bounded, repository-relative representation for both
   fields. Compatibility input may remain string-or-list during migration, but
   the deterministic boundary must reject empty values, absolute paths,
   traversal, repository or symlink escape, invalid component references, and
   over-limit path collections before dispatch.
3. Treat focus paths as component-scoped prioritization inputs, not additional
   read permission. Admit their bounded source projections before optional
   broad discovery, record every admitted or omitted path in the bundle
   receipt, and retain the existing component, repository-registry, freshness,
   and byte limits.
4. Treat exclude paths only as component-local suppression of optional broad
   discovery. They must not suppress a focus path, a mandatory deterministic
   signal, an already selected or cited evidence file, a contracted receipt,
   or any other component's inputs. A conflict fails validation instead of
   silently hiding evidence.
5. Carry the normalized routing decision through the evidence-bundle schema
   and exact-byte receipt. Do not inline source files or complete shared
   artifacts into the dispatch prompt; the v2 consumer continues to read only
   its bounded bundle and plugin-owned references.
6. Add producer, schema, manifest, bundle, dispatch, path-containment, limit,
   conflict, stale-input, and negative security tests. Use neutral fixtures and
   cover absolute paths, traversal, symlink escape, unknown components,
   oversized lists, focus/exclude overlap, and attempts to exclude mandatory
   evidence.

This slice exits only when a valid focus path measurably changes bounded bundle
admission, a valid exclude path affects only optional discovery, all decisions
are reconstructable from receipts, and neither field can widen repository
access or hide mandatory evidence. It is a contract repair, not the context
catalog migration itself. After it passes, inventory the current Stage-1 edges
and pin their behavior before introducing the catalog resolver in shadow form.

Add:

- the plugin-owned context catalog and its schema;
- semantic validation for consumers, projectors, selectors, dependencies,
  limits, trust layers, and failure behavior;
- a deterministic resolver and schema-validated effective routing plan;
- human-readable diagnostics that explain inclusion, exclusion, projection,
  truncation, and missing optional context without exposing sensitive content;
- exact-byte receipts and pre-dispatch freshness checks for each delivery; and
- cleanup, permission, packaging, checkpoint, and resume contracts for the new
  configuration and runtime artifacts.

Migrate existing Stage-1 role metadata, evidence bundles, taxonomy slices,
lenses, known threats, related-repository evidence, external and organization
context, trust boundaries, actors, requirements, prior findings, controls,
source slices, focus and exclude paths, and abuse cases one source at a time.
Preserve selected components, cheap/full depth, six-category coverage, evidence,
findings, and failure gates while the current behavior moves under the catalog.

Repository declarations remain untrusted data. Trusted organization packages
may add schema-backed context sources, catalogs, assignments, and stricter
limits, but neither layer may select instructions, agents, tools, commands,
projectors, arbitrary paths, or write targets. Neither layer may remove a
mandatory core route, relax a maximum, or downgrade a failure rule.

Exit gate: every Stage-1 context delivery has one catalog entry and validation
path; the effective plan reconstructs and explains every dispatch input; all
mandatory and forbidden deliveries are enforced; the existing Stage-1 fixtures
remain behaviorally equivalent; and no complete shared artifact enters a
focused role when a bounded projection exists.

### WP6 — reduce top-level and remaining fixed-prefix throughput

After WP0-WP5a pass the controlled A/B, apply the same action-receipt and
catalog-resolved admission inventory to Stage 2-4 and then to other roles ranked
by:

```text
first resident tokens * observed turns
```

Extend `orchestration_controller.py` only where deterministic work currently
returns to the parent before another semantic boundary. Do not merge renderer,
QA, or architect-review semantics into the controller.

Exit gate: no status-only or successful-validation turn remains in the thin
top-level trace, and renderer/QA mutation order is unchanged.

### WP7 — incremental, resume, and default rollout

Keep incremental and resume on the legacy threat analyst until full/rebuild
parity is established. Then migrate one mode at a time with checkpoint,
preserved-state, stable-ID, retry-budget, and cleanup tests.

Resolve the temporary context-v2 selection in `resolve_config.py`, persist a
`runtime_generation` value and relevant artifact schema versions in durable run
state, and include them in controller reconstruction. Repository content cannot
select the generation. Resume must continue the persisted generation or abort
with an explicit incompatible-state result; it must never switch producers
because the current environment variable changed. Rollback selects the prior
runtime for a new invocation, not midway through an existing context-v2 run.

Retain `APPSEC_THIN_ORCHESTRATOR=0` as the documented legacy escape hatch. The
temporary context-v2 switch may become the default only after the acceptance
matrix passes; remove it once both paths no longer need side-by-side A/B.

## Rollout slices

| Slice | Default behavior | Purpose |
|---|---|---|
| A | Existing runtime | WP0 telemetry only |
| B | Existing runtime; context-v2 shadow/fixture evaluation only | WP1-WP3 contracts, bundles, and controller actions without changing the live producer path |
| C | Context-v2 opt-in for full/rebuild | WP4 focused threat roles |
| D | Context-v2 opt-in for full/rebuild | WP5 STRIDE modularization |
| D2 | Context-v2 opt-in for full/rebuild | WP5a context catalog, effective routing plan, and Stage-1 migration |
| E | Context-v2 default for full/rebuild | WP6 top-level changes after A/B |
| F | Context-v2 default for all supported modes | WP7 incremental and resume parity |

Each slice must be revertible by selection of the prior runtime. Do not keep
two producers active for the same artifact within one invocation.

## Implementation status

Status as of 2026-08-09:

| Work package | Status | Remaining gate |
|---|---|---|
| WP0 | Implemented, repository-tested, and captured in one complete live run | Reconfirm the measurements in the fixed comparison cohort |
| WP1 | Implemented, repository-tested, and captured in one complete live run | Evaluate the admission targets in the fixed comparison cohort |
| WP2 | Implemented, repository-tested, and exercised in one live context-v2 run | Collect the bounded-context acceptance measurements |
| WP3 | Implemented, repository-tested, and exercised through final rendering in one complete live invocation | Establish behavior and finding parity against the legacy runtime |
| WP4 | Implemented for opt-in full/rebuild | Establish artifact and finding parity against the legacy runtime |
| WP5 | Implemented for opt-in full/rebuild | Establish the resident-context and escape-rate targets |
| WP5a | Repository implementation complete through the post-R9 projection, contract, lifecycle, summary, and telemetry fixes | Pass the R10 live acceptance checkpoint, then establish parity in the controlled A/B cohort |
| WP6 | Not implemented | WP0-WP5a must pass the controlled A/B before Stage 2-4 changes begin |
| WP7 | Partially implemented | Incremental and resume migration, default rollout, and legacy-switch removal remain |

The first WP5a slice now normalizes bounded literal repository-relative focus
and exclude paths at the deterministic manifest-to-bundle boundary. Focus
paths admit receipted source projections before optional discovery; exclude
paths affect only component-local optional discovery and fail on overlap with
focus, deterministic, selected, or cited evidence. The exact-byte bundle
receipt carries the normalized decision, and the v2 consumer reads it only
from the bundle. Path containment, symlink escape, unknown component, list
limit, overlap, mandatory-evidence, dispatch, and freshness cases are covered.
The frozen Stage-1 inventory now covers all context-v2 semantic roles, the
separate Stage-1d abuse verifier, deterministic projections, implicit prompt
inputs, direct source reads, plugin-owned references, receipts, failure modes,
and lifecycle effects. Drift tests bind the inventory to the current role
registry and consumer contracts.

The WP5a catalog slice adds a human-readable catalog, separate plugin-owned
bindings, schema and semantic validation, and a schema-validated effective plan
with an exact-byte receipt. Human assignments name the
threat-modeling category, agent, required, optional, or forbidden delivery,
optional-context importance, whole-run, current-component, or current-candidate
target, and reason. Paths, schemas, models, commands, projectors, trust labels,
and limits remain internal. The review removed unused component selectors and
runtime migration status from the human surface.

The first active migration gives every STRIDE analyzer one receipted component
context plan instead of the full dispatch manifest. It binds the component
evidence bundle, taxonomy slice, fixed lens IDs, depth and sampling policy,
turn and estimate values, resolved STRIDE profile, and the optional
related-repository, business-context, architecture-context, and six
security-category projections to fourteen active effective-plan delivery
decisions. An omitted optional projection remains an audited omission and is
physically absent from the component plan and Agent inputs. The full effective
plan stays in the controller
audit path and is revalidated by exact bytes immediately before dispatch; it is
never an Agent input.

The business and organization-context migration resolves only the organization
documents selected by the active preset and loads them once as bounded
untrusted control-analysis input. An optional document-level
`applies_to_components` list is validated against final component IDs and acts
as a hard projection bound. The control analyst may emit only business purpose,
compromise impact, sensitive assets, security obligations, and declared
security assumptions for a matching component. The deterministic builder
normalizes those values into a separate bounded
`.dispatch-context/<component-id>/business-context.json`; it removes the raw
object from the manifest, validates the component and content fingerprints,
and dispatches the artifact only when the component plan selects it. The
Evidence Bundle remains mandatory and contains no business projection, so one
context can be withheld without hiding evidence or changing repository access.
Security architecture and analytically derived assumptions remain separate
from the business object. Actors, abuse cases, trust boundaries, existing
controls and mitigations, threats, and proposed mitigations remain separate
source migrations.

The architecture-context migration now projects security role, exposed
interfaces, security dependencies, deployment constraints, and analytical
architecture assumptions into a separate optional component artifact. The
projection is physically absent when the control analyst has no
security-relevant architecture fact beyond the component registry. It cannot
carry actors, boundary decisions, controls, mitigations, threats, findings,
severity, or path-selection instructions, and the complete architecture model
remains forbidden to STRIDE agents.

The complete related-repository registry is now controller-only. Each bundle
fingerprints only the primary root and related roots cited by its admitted
source slices. When those slices exist, the controller writes one bounded,
receipted component projection containing exactly their repository IDs and
validated roots, binds it to the component plan and source-registry hash, and
rejects extra, missing, unknown, stale, cross-component, or non-STRIDE use. A
job with no related source evidence receives no root projection. STRIDE wave
concurrency is capped at five so worst-case projection receipts remain within
the unchanged 64-artifact immediate verification gate.

Known threats, canonical boundaries, resolved actors, requirement violations,
prior findings, and existing controls now use separate bounded component
projections. Each projection carries a source fingerprint, normalized records,
limits, an exact-byte receipt, and its own component-plan row; an empty source
is physically absent. The required Evidence Bundle no longer duplicates those
categories. Generated threats and proposed mitigations now use separate
receipted post-STRIDE projections. Evidence verification receives only its
deterministically selected sample with exact-source-bound code windows, and the
controller owns canonical annotations. Stage 1d receives one receipted abuse-
case candidate projection per job; the complete match set remains controller-
owned.

The 2026-08-08 contract review traced these projections through source index,
producer, schema, manifest, component plan, action, exact-byte receipt,
consumer reconstruction, permission, cleanup, and resume-version surfaces. It
also covers shared-budget reconstruction, wrapper-shaped known-threat input,
empty and truncated projections, stale sources and hashes, duplicate and
cross-role admission, and symlinked output paths. `context_routing.py validate`,
`make lint`, `make test`, and `make check` pass. The final test runs each report
11,783 passed and 95 skipped; `make test` reports 91.68% coverage.

The first post-projection WP5a smoke reached the architecture, boundary, and
control stages, then stopped before STRIDE bundle construction. Recon had
invented conventional source names, the architecture producer copied them
into component paths and data-flow evidence, and the control producer reused
one as a focus path. The bundle gate correctly rejected the missing path, but
the defect had already crossed two stage boundaries. Recon now permits source
claims only from observed tool output; architecture treats recon paths as
unverified leads; and the producer plus controller gates resolve every
component glob, data-flow evidence file and line, and recon `Key files`
reference against the contained target repository. Deterministic component
reconciliation no longer emits existence-independent fallback paths.

The next preserved-runtime smoke, run
`88129c09-c950-4121-9580-880765a82eff`, proved that the new post-recon gate
blocked the defect before architecture, but also exposed a producer/contract
format gap: the recon role emitted line ranges, bare files, directories, and
invented conventional names in `Key files`, then skipped its required local
validator. The producer and template now require one exact observed
regular-file and single-line reference per entry. The shared deterministic
normalizer is a fail-safe at both the producer command and controller boundary;
it can only delete unverifiable entries or write `none detected`, never create
path evidence. Exact-entry parsing now rejects ranges and trailing annotations
instead of accidentally accepting their numeric prefix.

At that point, the next checkpoint was a fresh opt-in full Juice Shop run at
quick depth with runtime files preserved. The later R4 run superseded that
checkpoint and exposed the remaining projection work described below.

The implemented WP0-WP5 scope includes:

- controller actions from `context-v2-begin` through `context-v2-finalize`,
  including the Phase-1/2 pre-passes, conditional Phase 2.5, Phase 2.6, and
  Phase-2.7 actor resolution;
- focused semantic roles, modular STRIDE lenses, bounded evidence bundles, and
  the internal shared kernel;
- exact-byte, versioned artifact receipts with pre-dispatch hash verification;
- a controller-owned local repository registry with path, symlink, repository
  identity, duplicate-root, and stale-slice enforcement;
- a bounded merge-review projection instead of admitting the complete merge
  candidate artifact, with one or more disjoint decisions per admitted group;
- a shared deterministic auto-emitter handoff before mitigation-quality and
  completeness validation in both legacy and context-v2 finalization; and
- fail-closed authoritative gates plus persisted artifact-schema compatibility
  checks.

Slices C and D are available only by opt-in. `APPSEC_CONTEXT_V2=1` selects the
context-v2 `runtime_generation` for compact-runtime full and rebuild runs.
Deadline, cost-limited, live-phase, and compact-runtime opt-out invocations stay
on `legacy`. `resolve_config.py` persists that generation and its artifact
schema versions; the controller reads them from durable state, refuses a
cross-generation continuation, and hands the skill
`SKILL-thin-stage1-v2.md` instead of the legacy Stage-1 runtime.

The implemented part of WP7 is limited to generation selection, persistence,
schema-version persistence, and incompatible-generation rejection. Incremental
and resume still use the legacy threat analyst. Context-v2 is not the default.

Local verification on 2026-08-07 passed `git diff --check`, `make lint`,
`make test`, and `make check`. The final `make test` and `make check` runs each
reported 11,655 passed and 95 skipped; `make test` reported 91.92% coverage.

The implementation plan is not complete. The first smoke attempt on 2026-08-06
combined `APPSEC_CONTEXT_V2=1` with `--max-wall-time`, which selected the legacy
top-level runtime while incorrectly persisting `context-v2`. Monitoring caught
the legacy threat analyst after 54 turns and the run was aborted. The producer
selection now derives from the same compact-runtime eligibility as routing and
rejects an inconsistent combination. A second smoke attempt entered context-v2
and dispatched the three-role recon wave, but exposed that concurrent Agent
registrations could replace one another and that the hook counted all parallel
tool calls against one 25-turn budget. It set `.budget-critical` at an aggregate
25 turns and was aborted before STRIDE. Session registration is now serialized;
shared-session budgeting is disabled after a second Agent dispatch, and nested
`Stop` events cannot emit an assessment summary while the run lock remains
owned. A third smoke attempt completed the parallel recon wave and the focused
architecture Agent, then exposed a missing controller-owned component
finalization, an overlong data-flow classification from the architecture
producer, and a missing controller-owned Phase-6 checkpoint. The parent model
manually repaired those runtime artifacts and reached the trust-boundary Agent
before the run was aborted. The controller now validates architecture
fragments, finalizes components, binds the derived inventory fingerprint into
the data-flow sidecar, builds the boundary input, and writes the checkpoint in
that order. The producer uses the bounded classification vocabulary, and the
compact runtime treats an abort as terminal instead of entering a legacy repair
loop. The same smoke also showed that shared-session telemetry attributed
cumulative usage to the most recently recognized legacy role; plugin-owned
roles are now registered generically and multi-Agent hook telemetry is labeled
`shared-session` with `scope=session-cumulative`. Live status now suppresses a
prior-run cutoff warning when the current v2 lock has a fresh heartbeat even if
its short-lived launcher PID has exited. No successful live context-v2
invocation or paid A/B cohort has run.

A fourth smoke attempt, run
`50badedf-90aa-4065-ac6a-6090d59148f2`, exercised the corrected path through
parallel recon, architecture, trust-boundary analysis, control analysis,
context-v2 manifest and evidence-bundle production, and the first six-component
STRIDE wave. Architecture finalization produced one identical component
fingerprint in the finalization receipt, data flows, and boundary input. The
Phase-6 and Phase-7 controller gates passed without manual artifact edits, all
six selected components received bounded bundles, all six analyzers wrote six
categories with `partial=false`, and no shared-session budget marker fired.
The first STRIDE wave reached approximately USD 3.72 in cumulative session
telemetry. Its post-wave gate accepted only `frontend-spa`: the other five
outputs carried malformed optional `boundary_refs` shapes, and two used
unmapped CWE values with the forbidden `TH-UNCLASSIFIED` sentinel. The bounded
retry controller therefore dispatched five second attempts, and the run was
aborted before they completed. The producer now carries the exact boundary-ref
shape, valid last-resort TH mappings, the literal progress command, and absolute
bundle-path resolution. The merge-owned pre-gate normalizer drops malformed
optional boundary links without changing findings or evidence, and the CWE map
now covers CWE-620 and CWE-799. Replaying the six captured outputs through that
gate validates all six without a retry. Post-abort live status now requires
merged threats plus a late checkpoint before claiming budget exhaustion, and
directs an incomplete context-v2 run to a fresh restart instead of unsupported
resume. The post-STRIDE merge, evidence, triage, synthesis, YAML handoff, and
rendering boundaries remained unexercised at that point.

A fifth smoke attempt, run
`6aa53070-5542-4b3d-afcf-3a5d618e1a08`, exercised the corrected path through
seven-component STRIDE analysis and every remaining Stage-1 semantic boundary.
All seven analyzers produced six-category outputs with `partial=false`, and the
post-wave gate accepted them without retries. The controller merged 48 raw
threats, admitted eight bounded merge decisions, verified a 16-threat sample,
ran deterministic triage and post-STRIDE synthesis, and built a structurally
valid canonical model with 42 threats and 42 mitigations. Finalization then
failed mitigation-quality validation because context-v2 had omitted the shared
deterministic auto-emitter pass that hydrates mitigation detail from threat
remediation. The controller now calls the same auto-emitter helper in both
legacy and context-v2 finalization, after initial structure validation and
before mitigation-quality and completeness gates. A full
`context-v2-finalize` replay against a preserved copy of the live runtime passed
those gates and produced the Stage-1c render checkpoint without modifying the
target runtime. Monitoring now excludes seed-only STRIDE placeholders from the
completed count and describes interrupted runs without falsely claiming that
merge was never reached. The smoke was aborted before live Stage-2 rendering,
so no successful complete live context-v2 invocation or paid A/B cohort exists.

A sixth smoke attempt, run
`566f85ee-e2b3-4309-b866-fc433445c805`, completed recon, architecture, and the
trust-boundary handoff. It produced six components, 15 data flows, 13 assets,
10 boundary candidates, and 21 boundary dispositions before the Phase-8 gate
rejected `.stride-analyst-context.json`. The control analyst had placed a
397-character repository summary in the reserved `_stride_profile` field,
whose compatibility schema permits only a string of at most 200 characters or
a bounded scalar object. The context-v2 producer contract now forbids that
field, the controller removes it as an ownership backstop before schema
validation, and manifest construction derives the profile exclusively from the
resolved run configuration. Replaying `context-v2-prepare-stride` against a
copy of the captured runtime passed in three seconds, validated seven evidence
bundles, and returned the seven-component STRIDE dispatch wave. The smoke also
showed that live status could report an interrupted run after the short-lived
launcher heartbeat expired despite recent tool or Agent activity, and that the
trust-boundary producer could resolve `shared/logging-standard.md` under the
wrong plugin directory. Live cutoff suppression now considers bounded recent
activity, and the producer names the absolute plugin-owned logging contract.
The run ended before STRIDE dispatch, so the corrected final Stage-1 gate and
Stage 2-4 still have not passed in one live invocation.

A seventh smoke attempt, run
`c55b8503-375d-471a-8004-de1c7f228dd9`, passed the corrected Phase-8 contract,
produced ten component contexts without the reserved `_stride_profile` field,
and dispatched seven full-depth STRIDE analyzers. All seven wrote six-category
outputs with `partial=false`; the post-wave gate accepted them without retries.
The selected components were all authentication, frontend, LLM, real-time, or
internet-exposed surfaces, so cheap-stride correctly screened none of them.
Context-v2 had nevertheless dropped the user-visible full/light label from its
dispatch-job contract; jobs now carry a required `analysis_depth` and the thin
runtime uses it in Agent descriptions and progress prompts. The merger reviewed
eight admitted groups and wrote nine decisions because one genuine partial
cluster required disjoint `merge [0,2]` and `keep [1]` decisions. The controller
incorrectly rejected the repeated group ID even though the v2 schema, producer
contract, and deterministic merge consumer all support partial-cluster
decisions. It now requires at least one decision per admitted group and validates
index bounds, survivor membership, and disjoint subsets instead. Replaying the
captured `context-v2-post-merge` boundary on a runtime copy accepted the exact
artifact, produced 50 merged threats, and returned the evidence-verifier job.
Live status now treats recent completed phase events as activity and lets an
in-window `RUN_ABORTED` override stale tool markers with the explicit
`controller_abort` cause. The thin runtime now also forbids legacy-style claims
that `--full` resumes retained context-v2 artifacts at only the failed boundary;
a later full run starts Stage 1 again. The live run ended at the merge gate, so
a corrected complete Stage 1 and Stage 2-4 invocation still has not passed.

A pre-A/B contract audit on 2026-08-06 then traced each changed Stage-1
artifact through its producer, schema, controller gate, consumer, cleanup, and
permission surface. It closed stale-output and duplicate-output ownership in
semantic actions, declared the evidence and triage mutations of
`.threats-merged.json` as in-place outputs, restored the resolved STRIDE profile
and bounded taxonomy slice to every v2 analyzer dispatch, and corrected the
client/server/data tier keys in post-STRIDE synthesis. Recon signals and
evidence verification now have explicit schemas plus controller-owned semantic
checks; the evidence summary's total is bound to the canonical merged threat
count, and an invalid optional summary supplies no evidence-guard signal.

The same audit bounded and validated the Markdown context and recon contracts,
removed empty analyst-context placeholders, rejected unknown component IDs,
and made recon reuse require both a valid summary and valid signal sidecar. It
also found that the recon producer had mixed `6.x` and `7.x` references while
the canonical template's Security-Relevant Code block and its consumers use
Sections 7.1–7.32. The template, producer self-check, and controller gate now
agree on 7.1–7.32; the cross-repository parser still accepts the previously
emitted 6.25 form as a compatibility input. The 200-line recon size is an
observable optimization target, not a blocking contract; the controller owns
the 1,000-line and 262,144-byte safety limits. The interrupted Juice Shop
runtime contains the superseded 6.x recon form and must not be resumed as a v2
continuation; a fresh full run will replace it. The post-audit focused suite
reported 1,228 passing tests. The subsequent repository-wide `make lint`,
`make test`, and `make check` gates passed. `make test` reported 11,617 passed,
95 skipped, and 91.92% coverage; the final `make check` run reported the same
test counts and passed its format, configuration, fragment-registry, and
target-specificity drift gates. No further contract defect was found by those
gates.

An eighth smoke attempt on 2026-08-07 aborted at the post-recon gate. The
artifact was complete through Sections 8–10, so the reported truncation
explanation was false: the recon producer had emitted the historical Cat-28
mapping as `7.28 AI Coding Assistant` and omitted canonical Sections 7.28–7.32.
The session transcript showed the structural cause. The role consumed exactly
all 25 allowed tool calls; calls 23 and 24 wrote the two artifacts, and call 25
printed completion statistics without running the required heading check.

The correction does not rely on repository size or an optimistic turn-ceiling
increase. The recon role now admits at most 22 discovery tool calls, reserves
at least ten publication and validation calls, and retains four calls as
failure headroom. Deterministic scans, finding lists, tree output, and source
reads remain bounded, so a larger repository may extend deterministic scan
runtime but cannot consume the model-turn publication reserve. The producer
must run `validate_recon_summary.py` immediately after the summary write and
before the signal write. That validator and the controller share the exact
template-heading contract, including titles and order; the prompt and template
also disambiguate Cat 28 from canonical Section 7.32 and require explicit
no-surface bodies instead of conditional heading omission. The initial focused
regression suite reported 418 passing tests; the broader contract suite reported
776 passing tests. The subsequent `make lint`, `make test`, and `make check`
gates passed. `make test` and `make check` each reported 11,624 passed and 95
skipped; `make test` reported 91.93% coverage.

An earlier smoke attempt, run `7073e7bf-f627-4a4e-8996-3df9f39829fc`, completed
an opt-in context-v2 full invocation at quick depth without manual runtime
artifact edits. Recon, architecture, trust-boundary analysis, control analysis,
six component-specific STRIDE jobs, bounded merge review, evidence verification,
deterministic triage, post-STRIDE synthesis, canonical YAML construction, Stage
2 rendering, and the deterministic Stage-3 gate all completed. The controller
merged 40 threats and the quick severity floor delivered 37 findings: six
Critical, 20 High, and 11 Medium. The run produced `threat-model.yaml` and
`threat-model.md`, cleared its checkpoint and lock, and ended after 58 minutes
33 seconds. Cumulative shared-session telemetry reported 119,437 output tokens,
368,939 cache-write tokens, 15,284,414 cache-read tokens, and USD 7.7612 under
subscription accounting. These are cumulative session-throughput figures, not
a measurement of simultaneously resident context, but they keep the remaining
top-level reduction work visible.

Monitoring found two nonterminal defects. The context resolver wrote and
sourced a shell environment file containing repository-derived paths; its
producer contract now keeps repository values out of executable shell text.
An independent full-QA replay also found that anchor enrichment could expand a
compact finding link with the YAML storage form `Title — file:line`; the
consumer now converts the locator to the required backticked parenthesized form
before enrichment.
The exact completed output passes the full QA replay after that correction, and
both fixes are covered by the repository-wide gates above. They have not been
re-exercised in another paid live invocation.

A later preserved-runtime rebuild smoke at
`/tmp/appsec-context-v2-wp5a-smoke-20260808-r4` confirmed that rebuild cleanup
retained the resolved context-v2 generation. It completed recon, architecture,
boundary and control analysis, five independently planned STRIDE jobs, bounded
merge review, evidence verification, deterministic triage, and post-STRIDE
synthesis. Final YAML construction then exposed a producer/contract mismatch:
the runtime-only `rebuild` cleanup mode was copied into the public `meta.mode`
and changelog mode, whose delivery schema permits only `full` and
`incremental`. The YAML producer now maps every non-incremental run to `full`
while retaining the explicit rebuild invocation and audit note. Replaying the
exact captured artifacts produces a schema-valid model with 37 threats, 37
mitigations, 108 attack-surface entries, and seven components. Recovery
classification now also treats an in-window controller `RUN_ABORTED` as
terminal even when a partial YAML exists, so the headless wrapper cannot
recommend unsupported context-v2 resume.

The aborted smoke reported 274,170 output tokens, 17,771,358 cache-read tokens,
1,076,818 cache-write tokens, and USD 12.13. The preceding legacy run reported
USD 24.07, but the context-v2 run never entered Stage 2, so the apparent 49.6%
reduction is not an end-to-end comparison. Receipts also exposed remaining
WP5a pressure: recon emitted 521 lines against its 200-line target,
architecture received the full 247-route inventory, and the evidence and root-
cause roles still received full merged-threat artifacts. These projections
must be bounded before the controlled A/B gate.

The first R4 pressure fix bounds deterministic recon patterns to 12 findings
per category and 96 across the run, with category-diverse risk ordering and
explicit pre-cap and omission counts. Actor discovery and architecture now
consume an exact-source-bound recon projection capped at 200 retained heading
and body lines. Architecture also receives at most 96 risk-shaped and
framework-diverse routes while the complete inventory remains available to
deterministic consumers. Against the preserved R4 artifacts, those projections
reduce recon patterns from 151,318 to 31,807 bytes, recon Markdown from 521
source lines to 197 retained lines, and routes from 247 to 96 records. All
three inputs have schemas, active catalog routes, exact-byte action receipts,
source-hash freshness checks, cleanup under `.dispatch-context/`, and existing
output-tree permissions.

The remaining R4 pressure fix moves evidence sampling into the deterministic
controller and embeds one exact 11-line source window per selected finding.
The verifier writes only its verdict sidecar; the controller stages, validates,
and atomically applies accepted annotations. Post-STRIDE synthesis receives
separate generated-threat and proposed-mitigation projections instead of the
complete merged set and triage flags. Stage 1d similarly receives one bounded
candidate projection per verifier job instead of the complete abuse-case match
set. Against the preserved R4 artifacts, the 146,456-byte merged input becomes
a 38,208-byte, 17-finding evidence sample plus 27,102-byte threat and
26,551-byte mitigation projections for 41 pre-render threats. An offline match
of the same artifacts produced five abuse candidates whose individual inputs
range from 2,670 to 6,153 bytes, compared with the 29,119-byte complete match
set. The four schemas, deterministic producers, controller reconstruction,
focused consumers, cleanup ownership, artifact-version registry, catalog
routes, permissions, and regression tests move together.

The R5 checkpoint at
`/tmp/appsec-context-v2-wp5a-smoke-20260809-r5` stopped at the authoritative
Stage-1 context gate. The context resolver spent all 25 tool calls and about
51k tokens on discovery, returned without `.threat-modeling-context.md`, and
prevented recon output from advancing. The same producer had emitted the
plugin repository rather than the requested target as `Repo Root` in R4, so a
larger publication reserve would not address the complete correctness defect.
Context-v2 now replaces that model session with a deterministic producer that
uses the controller's canonical repository root, caps source counts and bytes,
rejects escaping symlinks, validates URLs and redirects, fences imported data,
fails closed on invalid or oversized `known-threats.yaml`, writes the existing
related-repository sidecars, and validates the final Markdown contract before
recon dispatch. An offline Juice Shop replay produced a valid 9,344-byte
context artifact with `Repo Root` set to `/home/mrohr/juice-shop`.

R5 also exposed a JSON Schema overlap: integer recon line numbers matched both
the `integer` and `number` branches of a `oneOf`, so a valid 96-record capped
artifact failed validation. The scalar contract now uses one bounded `number`
branch. The captured producer output retained 96 of 1,134 patterns, omitted
1,038, and occupied 41,584 bytes versus 151,318 bytes in R4, a 72.5% reduction.
Invalid optional recon output is removed before routing, and invalid optional
config output is replaced by its schema-valid no-surface stub.

The receipt audit found a broader enforcement defect: an active output binding
could fall back to `shadow_hashed` when its action carried no validated
producer receipt. Active delivery now requires an exact artifact, hash, and
contract receipt. Applying that rule exposed previously unreceipted per-
component taxonomy slices; the controller now validates and receipts each
slice before STRIDE dispatch. Required architecture, boundary, control, and
post-STRIDE producers also reserve fixed publication turns so repository size
cannot consume their write and validation allowance. A schema-structure audit
found no other `integer`/`number` union overlap.

The headless wrapper creates an empty `.headless-result.json` before the run
lock exists. Live status interpreted that bounded startup interval as a
completed run without a report and displayed a false incomplete-run warning.
A recent empty capture is now a 120-second startup marker unless an explicit
abort exists; old empty captures remain terminal evidence. R5 reported 44,170
output tokens, 4,691,069 cache-read tokens, 285,359 cache-write tokens, and USD
2.04, but it did not reach architecture or STRIDE and is not an end-to-end
cost sample.

The R6 checkpoint at
`/tmp/appsec-context-v2-wp5a-smoke-20260809-r6` confirmed the deterministic
context producer, bounded recon-pattern projection, and startup-status fix. It
then stopped before architecture because the routing profile compared 525
physical pretty-printed JSON lines with the recon schema's 200 retained
semantic source lines. The producer and routing unit tests had covered those
limits separately and therefore missed the incompatible boundary. Routing
`max_lines` now means physical serialized lines, while retained source lines
and evidence windows remain schema-owned semantic limits. A maximal
schema-valid producer test now crosses the receipt-counting and routing limit
code for recon, routes, evidence samples, mitigation projections, and the
default abuse-case library.

The same audit found two latent instances of the unit mismatch. A maximal
256-record evidence sample with 11-line source windows can exceed 2,816
physical JSON lines, and a 512-record mitigation projection with 20 steps per
record can exceed 10,000. Their serialized line profiles now admit the complete
schema-valid shape while retaining the existing 524,288-byte caps. The unused
`max_paths` binding field was removed because no routing code enforced it;
path-bearing collections remain bounded by their artifact schemas, and a drift
test now requires every declared profile field to map to an enforced counter.
The remaining specialized profiles were replayed or exercised at their bounded
producer shapes without another incompatibility.

An R6 side effect exposed a separate config-producer contract drift. The
context-v2 runtime omitted the Config Scanner's required `ASSESSMENT_DEPTH`
alias, and its inventory instructions did not require repository operations to
resolve beneath `REPO_ROOT`. The agent first wrote a 25-finding scan of the
plugin worktree outside `OUTPUT_DIR`, then produced a 70-finding target artifact
while its completion log retained the first scan's counts. Context-v2 now
passes the depth alias, the producer contract confines every scan target to the
canonical repository root and every output to the declared directory, and
completion counts must be derived from the validated final bytes. Contract
tests pin all three requirements.

Replaying `context-v2-post-recon` against an isolated copy of the exact R6
artifacts passed with the final bindings. The effective plan admitted the
recon projection as `action_validated` with 44 records, 525 physical lines,
18,253 bytes, and 4,564 estimated tokens. It admitted the route projection as
`action_validated` with 96 records, 1,756 physical lines, 49,204 bytes, and
12,301 estimated tokens, then emitted the architecture action. R6 reported
32,800 output tokens, 2,767,407 cache-read tokens, 216,731 cache-write tokens,
and USD 1.27, but it did not reach architecture analysis and remains unsuitable
as an end-to-end cost or quality sample.

The R7 checkpoint at
`/tmp/appsec-context-v2-wp5a-smoke-20260809-r7` passed the context publication,
recon, config, architecture, boundary, control, and first STRIDE-wave gates.
The raw 485-line recon summary projected to 199 retained semantic lines, 524
serialized lines, 17,906 bytes, and 4,477 estimated tokens with 181 body lines
omitted. The 247-route inventory projected to 96 routes, 1,756 serialized
lines, 49,204 bytes, and 12,301 estimated tokens with 151 routes omitted. Both
deliveries were `action_validated`. The Config Scanner received quick depth,
reported the same 24 checks and 27 findings as its validated artifact, cited
only Juice Shop paths, and wrote no artifact in the plugin or target root.

R7 selected six STRIDE components and dispatched five in the first wave. Four
completed with one threat in each of the six categories. The API component
authored six complete categories on both attempts, but each output used the
old discovery-escape field names `unresolved_decision` and `selected_lens`.
The version-1 STRIDE schema requires `decision_key` and `lens`, so the wave gate
correctly rejected both outputs and exhausted the two-attempt budget before
the second-wave Web3 component or any post-STRIDE work ran. The agent contract
had described the values without naming their exact JSON fields, while tests
covered schema acceptance and prompt presence separately instead of replaying
the known producer alias shape through wave completion.

The producer now names every discovery-escape field exactly. The wave gate
also owns a lossless backstop that renames only those two aliases when the
canonical field is absent; conflicting fields remain fatal. An isolated replay
of the exact final R7 API artifact passes wave completion and persists the
canonical names. Retry claims now carry their validation reasons into the
controller log, and retry-budget errors include the component-specific reason
instead of diagnosing every schema failure as an oversized component.

R7 reported 270,901 output tokens, 14,211,199 cache-read tokens, 1,068,913
cache-write tokens, 47 top-level turns, about 50.6 minutes wall time, and USD
11.66. The long Control call and STRIDE wave each crossed the five-minute cache
TTL, and the invalid API shape paid for a complete second dispatch. R7 is a
useful failure-cost and bounded-context sample but is not an end-to-end cost or
quality sample.

The R8 checkpoint at
`/tmp/appsec-context-v2-wp5a-smoke-20260809-r8` passed deterministic context
publication, recon, architecture, boundary, and control gates. The raw
493-line recon summary projected to 200 retained semantic lines, 525 serialized
lines, 20,226 bytes, and 5,057 estimated tokens with 182 body lines omitted.
The 247-route inventory again projected to 96 routes, 1,756 serialized lines,
49,204 bytes, and 12,301 estimated tokens with 151 routes omitted. Both
deliveries were `action_validated`; the full route inventory remained forbidden
to the architecture role.

R8 stopped while preparing STRIDE because the API component declared
`routes/**/*.ts` while its bounded analyst routing selected the literal
directory `routes`. Evidence-bundle containment tested that directory by
inventing `routes/x`; the suffix-constrained file glob could never match that
probe, and Python `fnmatch` also treated `**/` as requiring a nested directory.
The bundle producer and validator now use the same component-glob semantics as
the canonical reclassifier, where `**/` admits zero or more directory levels.
A literal focus directory must equal or descend from the static prefix of a
component glob; a broader parent remains invalid, and every projected file is
still checked against the complete glob. Replaying the exact R8 artifacts now
builds and validates all six component manifests and evidence bundles and
returns the five-job first STRIDE wave. The API `routes` projection admitted 11
of 61 candidate files and recorded 50 source-budget omissions.

The same checkpoint exposed an independent producer gap before it became a
blocking gate: the Config Scanner reported only 12 of 24 catalog checks and two
findings. Context-v2 now skips that model dispatch and invokes a deterministic
catalog executor after recon. The producer canonicalizes every selected file,
rejects symlink escapes, evaluates every catalog entry, writes atomically, and
uses the run epoch for a stable timestamp. Semantic validation binds
`checks_run`, `violations`, local-ID sequence, check IDs, and finding metadata
to the canonical catalog. The catalog inventory now shares category-wide
patterns for recursive Dockerfiles, both YAML extensions, Compose aliases, and
Dependabot alternatives, closing a gap where the surface selector started a
scan for files the producer could not enumerate. An exact Juice Shop replay
evaluates all 24 checks and emits 30 findings: unlike R7, it does not flag the
fully SHA-pinned lint-fixer workflow, reports the absent npm lockfile, and
evaluates the nested smoke-test Dockerfile. A failed fresh producer cannot
reuse stale config bytes, and config enrichment remains non-blocking.

The designated R9 checkpoint at
`/tmp/appsec-context-v2-wp5a-smoke-20260809-r9` completed successfully through
final rendering and deterministic gates. It produced 42 findings: six
Critical, 21 High, and 15 Medium. The headless result recorded 157 total turns,
5,114,602 milliseconds, 29,589,045 cache-read tokens, 1,496,506 cache-write
tokens, 369,404 output tokens, and USD 19.66941455. Six components were selected
for STRIDE while the final model retained eight components. Active effective-
plan deliveries carried physical line, byte, and estimated-token counts and no
active delivery used `shadow_hashed`.

R9 also exposed measurement and lifecycle defects that did not fail the run.
Only abuse verification and rendering reached `.stage-stats.jsonl`, so the run
cannot support an exact phase-by-phase cost claim. The preserved output retained
19 `.active-tool-calls` entries after termination. The Completion Summary called
all eight modeled components analyzed even though the selection contained six.
The abuse-verifier row reported 212,533 tokens, 101 tool calls, and 185,975
milliseconds and was the largest recorded role cost driver, but its priced token
classes and turns are unavailable. Do not allocate the exact run cost to roles
proportionally; that would create unsupported precision.

Two committed follow-ups after R9 reduce and protect the next run. Commit
`022bf115` bounds abuse verification with exact source windows and a turn limit,
removes redundant reads and writes, excludes scan and code-fix artifacts from
recon, removes refuted threats from abuse inputs, and routes known
vulnerabilities as `threats.known_threats`. Commit `7961c132` sorts the Findings
Index by Critical, High, Medium, Low, and Info with deterministic tie-breaking.
Neither change has been exercised in another live run.

The pre-R10 repository follow-up closes the remaining generic false-pass and
measurement paths. Projection gates now reconstruct recon, route, evidence,
generated-threat, proposed-mitigation, and abuse-case inputs and compare every
deterministic field except the self-referential serialized-byte field. The
context catalog rejects missing schema paths, corrects the requirements route
to `requirements-catalog.schema.yaml`, and gives the active taxonomy slice a
schema plus category-reference validation. The terminal outer hook clears live
tool markers even when other runtime diagnostics are preserved, without
following a symlinked marker directory. Completion output distinguishes the
STRIDE-selected count from the modeled inventory, combines its report reading
path, exposes read-only threat-model Q&A as a numbered action, and no longer
recommends a requirements rerun without user intent. Stage 1 records one
aggregated usage row per semantic role, Stage 1d binds its row to the verifier
dispatch window, and `measure_run.py` preserves stage variants, reports
role-record coverage, and imports exact headless totals.

The line-limit audit found no remaining semantic-versus-physical unit mismatch
in the active large projections. Semantic producer caps remain separate from
routing limits, which count serialized physical lines. R9 examples fit both
dimensions: recon retained at most 200 semantic lines while serializing to 524
physical lines; its route projection serialized to 1,756 physical lines; the
largest evidence and synthesis projections remained below their physical line,
byte, and token profiles. Regression tests construct projections whose physical
line counts exceed their semantic window counts so either unit cannot silently
stand in for the other.

The next required live checkpoint is R10. It uses the same target and quick
model cohort as R9 and forces Stage 1d:

```bash
APPSEC_CONTEXT_V2=1 ./scripts/run-headless.sh \
  --repo /home/mrohr/juice-shop \
  --output /tmp/appsec-context-v2-wp5a-smoke-20260809-r10 \
  --model claude-sonnet-4-6 \
  --reasoning-model sonnet-economy \
  --assessment-depth quick \
  --abuse-cases \
  --keep-runtime-files \
  --rebuild
```

R10 passes only when all of these conditions hold:

- the invocation exits successfully through final rendering with no context,
  schema, contract, projection, or reconstruction abort;
- `runtime_generation=context-v2` is authoritative, the repository root is
  `/home/mrohr/juice-shop`, all selected components cover all six STRIDE
  categories, and the final status, lock, checkpoint, and Completion Summary
  agree;
- every intended active context route is delivered through a current
  `action_validated` receipt, no active delivery uses `shadow_hashed`, and
  focused evidence, synthesis, and abuse jobs do not receive their complete
  shared source artifacts or another candidate's projection;
- every major projection reports source, retained and omitted records,
  serialized physical lines, bytes, and estimated tokens; recon remains at or
  below 200 semantic retained lines and 1,024 physical lines, routes remain at
  or below 96 records, and every routing profile passes in its declared unit;
- `.stage-stats.jsonl` has a usage row for every dispatched semantic role and
  reports each role's aggregate tokens, tool calls, and duration; the headless
  result reports exact total turns and per-model priced token classes and cost;
  per-role turns and cost remain explicitly unavailable unless the runtime
  starts emitting the required fields;
- the abuse-verifier row is compared with R9's 212,533 tokens, 101 tool calls,
  and 185,975 milliseconds, together with its candidate count and source-window
  sizes, so the limiter's effect is measured rather than inferred;
- total findings and the severity distribution are recorded and mapped against
  both R9 and
  `examples/threat-modeler/threat-model-juice-shop-quick-v0.5.2.yaml`; any real
  loss is explained, and DOM-based XSS plus supported OAuth-derived credential
  and JWT role/claim findings are restored where the source evidence remains;
- no refuted finding or run, scan, code-fix, or generated output artifact is
  reintroduced as a candidate, and targeted repository escape reads remain
  receipted and bounded;
- the Findings Index is ordered Critical, High, Medium, Low, Info with stable
  within-severity order; `.active-tool-calls` is absent after terminal Stop even
  with `--keep-runtime-files`; and the Completion Summary reports six
  STRIDE-analyzed and eight modeled components when the R9 selection repeats;
- deterministic Config/IaC evaluates all 24 checks and preserves its known
  pinned-tree expectations, startup does not report a false incomplete run, and
  every routing, retry, producer-gate, and compaction warning is retained for
  review.

R10 is a live smoke checkpoint, not the controlled three-pair A/B acceptance
cohort. It cannot close WP6, the controlled A/B evidence, WP7 incremental and
resume parity, default rollout, or the acceptance matrix.

A subsequent governance audit moved standing orchestration and admission rules
into the durable contracts, pinned the legacy/context-v2 tool topology, added a
review ratchet for every prompt surface, registered the repository-local
Claude contributor instructions as development resident context, and bound the
duplicated context-v2 schema vocabularies with cross-schema drift tests. The
startup aggregate remains measurement-only until WP5a produces reviewed stable
startup records. GitHub `main` currently has neither required status checks nor
a ruleset, so merge enforcement remains an external rollout gate rather than a
repository-tested guarantee.

The acceptance matrix, runtime parity, 700-turn target, resident-context
targets, and cost-reduction gates remain unverified. WP5a live acceptance,
WP6, incremental/resume migration, and rollout slices E and F must not be
reported as complete.

## Verification matrix

Use the same target commit, Claude Code version, exact model IDs, versioned
pricing table, depth, concurrency, formats, and clean-session conditions. Run at
least three baselines and three variants before evaluating p50 cost or turns.
Alternate baseline and variant runs where practical, record median and range,
and pair runs by time block so service-load drift is visible. A run on a
different Claude Code version is a new benchmark cohort, not another sample in
the fixed cohort.

Required behavior coverage:

| Dimension | Cases |
|---|---|
| Mode | full, rebuild, incremental, resume |
| Depth | quick, standard, thorough |
| STRIDE execution | parallel, serial fallback, bounded retry, blocked component |
| Merge | no candidates, ambiguous candidates, failed specialist, invalid decision artifact |
| Triage | no flags, semantic flags, missing specialist output, invalid output |
| State | fresh output, preserved baseline, stale checkpoint, corrupted sidecar, incompatible runtime generation |
| Evidence bundle | clean tree, dirty tree, stale slice hash, truncation, related repository, path and symlink escape |
| Context routing | required, optional, forbidden, conditional, unmatched, ambiguous, duplicate, and contradictory routes |
| Context selectors | component ID, type, technology, capability, zone, exposure, boundary, actor, related repository, mode, and depth |
| Context extensions | stricter organization policy, repository data addition, attempted mandatory-route removal, attempted projector or instruction selection |
| Context sources | known threats, prior findings, related repositories, external context, boundaries, actors, requirements, controls, focus/exclude paths, and abuse cases |
| Runtime dependency | schema validator present, structural validator unavailable |
| Report path | normal Stage 2, rerender, Stage 3 skipped, Stage 4 repair plan |

Compare findings by stable mechanism, evidence location, component, and public
identity rather than generated title wording. Before running the A/B, freeze the
matching keys and adjudication procedure. Every apparent loss, addition,
unsupported item, duplicate, severity change, and component-selection delta is
classified as expected variance, explained improvement/regression, or
unresolved. Any unresolved quality delta blocks rollout; aggregate counts alone
cannot waive a lost evidence-backed finding.

## Acceptance criteria

Quality and compatibility:

- identical finalized component inventory and STRIDE selection;
- all six STRIDE categories completed for every selected component;
- no unexplained loss of schema-valid evidence-backed findings;
- no weakening of severity caps, CVSS eligibility, T/F identity, cross-links,
  cleanup, permission, renderer, QA, or architect-review gates;
- no increase in unsupported, rejected, ambiguous, or duplicate findings;
- no increase in incomplete exits or semantic repair frequency;
- a required GitHub status check enforces the repository test gate before
  context-v2 becomes the default;
- full/rebuild parity before incremental/resume activation;
- no unresolved finding, severity, evidence, or component-selection delta; and
- runtime generation, schema versions, checkpoints, and artifact fingerprints
  reconstruct exactly one valid successor action on resume.

Context and turns:

- shared kernel at or below 4k tokens;
- each focused role contract at or below 3k tokens;
- total plugin-selected startup payload at or below 10k tokens;
- initial resident context at or below 30k for each focused threat role unless
  a controlled A/B proves a higher immutable runtime floor;
- `admission.enforce_startup_totals` enabled after reviewed startup-layer
  measurements stabilize the WP5a cohort;
- peak threat-role context below 120k with no automatic compaction on the target
  fixture;
- p50 total usage turns at or below 700 from the 928-turn baseline;
- zero dedicated `status_or_logging` turns;
- no validation-only model re-entry after successful deterministic validation;
- at most one `workflow_routing` turn per semantic boundary;
- no complete shared analysis artifact in a common prompt or initial dispatch;
- every Stage-1 delivery represented by one validated effective-plan entry with
  its selection reason, limit, trust class, source receipt, and delivered size;
- mandatory routes cannot be removed or weakened by organization or repository
  configuration, and forbidden routes cannot be added;
- effective-plan diagnostics disclose omission, truncation, staleness, and
  unmatched selectors without disclosing sensitive source content;
- every usage turn aggregated from all of its JSONL content blocks before
  classification; and
- no unadjudicated mixed, low-confidence, or unclassified turn in a zero-turn
  release claim.

Cost and latency:

- p50 reconstructed cost reduction of at least 15% at quick and 20% at
  thorough;
- no compaction latency in focused threat sessions on the target fixture; and
- no regression in p50 wall time after controlling for model variance and
  concurrency, with the cohort range reported beside the median.

Repository gates:

- targeted schema, controller, dispatch, permissions, cleanup, checkpoint,
  resume, and golden-fixture tests pass;
- path containment, symlink escape, stale-fingerprint, runtime-generation, and
  fail-closed validator tests pass;
- every new `scripts/` module has a matching `tests/test_*.py` covering success
  and failure paths;
- `make lint` passes;
- `make test` passes; and
- `make check` passes before default rollout.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A projection hides cross-cutting evidence | Preserve bounded escape reads, record the reason, and compare escape and finding rates in A/B |
| Session splitting increases cold starts | Use three coherent semantic roles, not one agent per mechanical phase |
| A new receipt duplicates state | Extend ephemeral orchestration actions first; add no persisted receipt without a resume gap |
| Controller normalization changes security meaning | Limit it to contract-owned mechanical fields and route semantic conflicts to focused agents |
| Agent and controller both own a stage | Activate producers atomically and forbid dual writes in tests |
| Turn classifier overstates precision | Publish precedence, mixed classifications, and confidence; keep it diagnostic |
| Prompt reduction causes broad rereads | Measure full-artifact reads and bundle escapes; fail the A/B if they erase savings |
| One cheaper run reflects model variance | Require three baseline and three variant runs and compare p50 plus finding identity |
| New sidecars break cleanup or resume | Reuse `.dispatch-context/`, trace cleanup and diagnostics, and test every preserved-state mode |
| The catalog becomes a second semantic-role registry | Keep one authoritative registry or generate one representation from the other; reject drift in tests |
| A routing extension becomes a prompt or execution channel | Permit schema-backed data and bounded selectors only; keep consumers, projectors, tools, commands, instructions, and paths core-owned |
| Over-granular entries make policy unmaintainable | Create a separate element only when it can be independently projected, limited, omitted, audited, or assigned |
| Component changes silently stop a user assignment from matching | Prefer semantic selectors and report every unmatched or ambiguous rule in the effective-plan diagnostics |
| Transcript deduplication hides a tool call | Aggregate all blocks by `message.id` before turn classification |
| Startup layers are inferred from an aggregate counter | Use provider token counting or one-variable startup A/B; record residuals only as residuals |
| A validated file changes before consumption | Bind receipts to exact bytes and re-hash immediately before use |
| Absolute or symlinked compatibility paths escape output | Apply canonical containment to bundles and retained legacy index paths on context-v2 |
| Environment changes the runtime during resume | Persist `runtime_generation` and refuse incompatible continuation |
| The required tool surface cannot fit the 10k startup target | Measure it in WP0 and amend allocations before enforcing WP1; do not hide tools from the accounting |
| Controller proxy logging obscures the acting agent | Assign event ownership in the shared logging contract and keep semantic events agent-authored |

## Stop conditions

Do not make context-v2 the default if any of these occur:

- unexplained finding loss or weaker evidence;
- a role repeatedly reads complete shared artifacts instead of projections;
- the 700-turn gate is reached by skipping verification or semantic work;
- initial resident context remains near 66k after the agent split, indicating
  the assumed avoidable startup producer was wrong;
- repair or incomplete-exit frequency increases materially;
- incremental or resume changes T/F identity;
- cost falls by less than 20% at thorough after WP0-WP6 while quality remains
  constant;
- any release metric depends on unadjudicated mixed or low-confidence turns;
- bundle freshness cannot be reconstructed from repository and artifact
  fingerprints; or
- durable state permits more than one valid runtime generation or successor
  action on resume.

If startup remains high, remeasure runtime, task, tools, preloaded skills, and
agent-definition layers independently before changing the architecture. If
turns remain high, inspect the turn-purpose report and move only the largest
non-semantic category to its existing deterministic owner.
