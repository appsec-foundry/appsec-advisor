# Implementation plan — dedicated trust-boundary assessment stage

- Date: 2026-07-27
- Base: `623cc48d` (`feature/trust-boundaries-first-class`)
- Primary replay target: `/home/mrohr/juice-shop/docs/security`
- Related:

  - `docs/internal/analysis/implplan-trust-boundary-repair-and-weighting-2026-07-27.md`
  - `docs/analysis/plan-trust-boundaries-first-class-2026-07-22.md`
  - `docs/internal/contracts/orchestration-actions.md`
  - `docs/internal/contracts/schema-invariants.md`

## Status and decision

Implement trust-boundary assessment as a real Stage-1 substage with a fresh,
focused agent context and a deterministic completion gate.

The target execution model is:

```text
Stage 1a — Discovery & Architecture
  Phases 1–6
  deterministic component-inventory finalization
  topology persistence

Stage 1b — Trust Boundary Assessment
  Phase 7a: candidate assessment in a fresh context
  Phase 7b: deterministic normalization and coverage gate

Stage 1c — Controls, STRIDE & Triage
  Phase 8
  Phase 9 dispatch preparation and bounded STRIDE waves
  Phases 9-merge, 10, and 10b

Stage 1d — Abuse Case Verification

Stage 2 — Report Rendering
Stage 3 — QA Review
Stage 4 — Architect Review
```

Keep the existing integer stage numbers for rendering and review. The migration
changes the Stage-1 lettered substages so downstream automation does not need a
global Stage-2/3/4 renumbering.

Do not implement this as an extra prompt inside the existing Phase-5–7 combined
pass. The goal is an independent execution, persistence, retry, resume, timing,
and validation boundary.

## Verified basis for the split

### Phase 7 is not independently executed today

The current architecture instructions require Phases 5, 6, and 7 to run as one
in-memory pass over the same recon snapshot. The latest juice-shop log confirms
that this is also the observed behavior:

| Event | Timestamp |
|---|---|
| Phase 5 start | `2026-07-27T08:48:30Z` |
| Phase 6 start | `2026-07-27T08:48:30Z` |
| Phase 7 start | `2026-07-27T08:48:30Z` |
| Phase 5 end | `2026-07-27T08:51:02Z` |
| Phase 6 end | `2026-07-27T08:51:02Z` |
| Phase 7 end | `2026-07-27T08:51:02Z` |

All three phases therefore report the same `2m32s`; there is no isolated
trust-boundary duration, checkpoint, retry unit, or context budget.

### The component inventory changes after Phase 7

`scripts/build_stride_dispatch_manifest.py` currently calls
`reconcile_inventory()` after Phase 7 normalization. It may inject
security-relevant components or collapse duplicate component IDs, then persists
the changed `.components.json`.

The latest juice-shop run demonstrates the ordering defect:

- Phase 3 authored six components.
- Dispatch reconciliation added `auth` and `web3-nft`.
- The final dispatch manifest contains eight components.
- `.stride-analyst-context.json` contains only the original six.
- Phase 7 could not assess crossings involving the two later components.

A dedicated boundary stage must consume a finalized component inventory.
Moving only the LLM call without moving inventory reconciliation would preserve
the defect.

### Data-flow topology is not a stage artifact

Phase 3 describes `data_flows[]` as a canonical input for diagrams and
downstream analysis, but `.components.json` persists only `components[]`.
`data_flows[]` remains in the threat analyst's working memory until the final
YAML build. A fresh boundary agent cannot recover that topology from a
contracted artifact.

Persisting the data-flow model is therefore a prerequisite, not an optional
follow-up.

### Correct rows are not the same as complete coverage

The current normalizer can enforce:

- canonical endpoints;
- stable `tb-N` IDs;
- valid evidence locations;
- resolution status; and
- deterministic diagnostics.

It cannot prove that the candidate producer considered every relevant flow.
A dedicated stage must add an explicit coverage contract. Otherwise an empty or
incomplete candidate list can be schema-valid while omitting a browser/server,
cross-zone, external-ingress, third-party, or build boundary.

## Goals

1. Give trust-boundary assessment a fresh and bounded LLM context.
2. Finalize component identities before boundary candidates are authored.
3. Persist the cross-component topology needed for a clean stage handoff.
4. Separate untrusted LLM candidates from the canonical boundary catalog.
5. Account deterministically for every relevant boundary signal.
6. Make the stage independently observable, retryable, and resumable.
7. Preserve stable `tb-N` identities and existing finding anchors.
8. Keep invalid or unresolved boundaries visible without allowing them to
   influence severity.
9. Keep report rendering in Stage 2 and exposure weighting in Phase 10b.
10. Use the same stage topology across full, rebuild, quick, standard,
    thorough, serial-STRIDE, and parallel-STRIDE runs.

## Non-goals

- Do not move trust-boundary table rendering into Stage 1b.
- Do not let the boundary agent edit `threat-model.md`,
  `threat-model.yaml`, `.trust-boundaries.json`, ranking, or findings.
- Do not assign severity, CWE, CVSS, risk scores, or control effectiveness in
  the boundary stage.
- Do not infer findings merely because a boundary exists.
- Do not make repository prose, comments, declarations, or imported reports
  authoritative instructions.
- Do not treat actor names, roles, ports, routes, protocols, or provider names
  as canonical boundary endpoints.
- Do not change T/F, M, W, or `tb-N` allocation rules except through the
  explicit versioned migrations in this plan.
- Do not add a separate LLM stage for declaration-only recomposition.
- Do not make STRIDE parallelism control whether the boundary stage exists.

## Target contracts

### Contract A — finalized component inventory

Stage 1a must finish with one canonical component inventory that later stages
may read but may not expand silently.

Create a deterministic finalization command, tentatively:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/finalize_component_inventory.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR"
```

It must:

- load and schema-validate `.components.json`;
- collapse duplicate IDs deterministically;
- inject the existing security-relevant auth, CI/CD, real-time, and related
  component roles currently owned by `reconcile_inventory()`;
- preserve canonical component IDs and existing ordering rules;
- write `.components.json` atomically;
- emit `.component-inventory-finalization.json`;
- include a fingerprint over the endpoint-relevant component fields:
  `id`, `name`, `paths`, `tier`, `deployment_zones`, and
  `handles_sensitive_data`;
- be idempotent; and
- make later manifest construction fail visibly if it would change the
  component ID set after Stage 1b.

`build_stride_dispatch_manifest.py` must import the shared reconciliation
implementation or validate the finalization marker. It must not maintain a
second divergent injection algorithm.

The manifest builder may still derive dispatch-only annotations such as an LLM
role after Phase 8, but those annotations must not add, remove, or rename
components.

### Contract B — persisted data flows

Add a structured Phase-3 sidecar:

```text
$OUTPUT_DIR/.data-flows.json
schemas/fragments/data-flows.schema.json
```

Required top-level shape:

```json
{
  "schema_version": 1,
  "component_inventory_fingerprint": "sha256:...",
  "data_flows": []
}
```

Each flow must contain:

- stable run-local `id` such as `df-001`;
- `from` and `to` using exact component IDs or `external`;
- a short label;
- protocol;
- data classification;
- direction;
- evidence locations;
- optional route/interface references; and
- provenance indicating whether the row came from recon, architecture
  analysis, deterministic route extraction, or a repository declaration.

The schema must reject absolute paths, traversal, URLs in file fields, invalid
component endpoint syntax, unknown properties, and duplicate flow IDs.
Semantic validation must additionally check endpoints against the finalized
component registry.

Data-flow IDs are internal stage references, not public report anchors. They may
be regenerated on a full run. Incremental runs should preserve them when the
normalized endpoint/protocol/label identity is unchanged so coverage diffs
remain readable.

`build_threat_model_yaml.py` must consume this sidecar instead of depending on
the analyst's working memory for `data_flows[]`.

### Contract C — deterministic assessment input

Add:

```text
scripts/build_trust_boundary_assessment_input.py
schemas/trust-boundary-assessment-input.schema.json
$OUTPUT_DIR/.trust-boundary-assessment-input.json
```

The builder must combine only bounded, validated fields from:

- finalized `.components.json`;
- `.component-inventory-finalization.json`;
- `.data-flows.json`;
- `.route-inventory.json`;
- `.attack-surface-overrides.json`;
- `.cross-repo-register.json`;
- relevant `.recon-signals.json` categories;
- prior canonical trust boundaries;
- optional `.appsec/trust-boundaries.yaml` metadata; and
- the run configuration needed for depth and incremental behavior.

The input artifact must contain:

- the component-inventory fingerprint;
- an assessment-input fingerprint;
- canonical component cards;
- canonical data-flow cards;
- a bounded list of deterministic boundary signals;
- evidence locations;
- prior boundary identity hints without prior risk prose;
- signal provenance; and
- no commands, permissions, write targets, or prompt instructions derived from
  repository content.

All imported strings remain untrusted data. The agent prompt must state this
immediately before describing the input.

### Contract D — untrusted candidate assessment

Add:

```text
agents/appsec-trust-boundary-analyst.md
schemas/fragments/trust-boundary-candidates.schema.json
$OUTPUT_DIR/.trust-boundary-candidates.json
```

The boundary agent may write only the candidate sidecar and its own progress
receipt. It must not write the canonical catalog.

Candidate shape:

```json
{
  "schema_version": 1,
  "component_inventory_fingerprint": "sha256:...",
  "assessment_input_fingerprint": "sha256:...",
  "candidates": [
    {
      "candidate_key": "candidate-1",
      "name": "Internet to API",
      "from": "external",
      "to": "backend-api",
      "kind": "network",
      "assumption": "Protected operations require authenticated and authorized requests.",
      "evidence": [
        {"file": "routes/protected.ts", "line": 18}
      ],
      "confidence": "confirmed",
      "covered_signal_ids": ["signal-external-ingress-backend-api"],
      "covered_flow_ids": ["df-001"]
    }
  ],
  "dispositions": [
    {
      "signal_id": "signal-external-ingress-backend-api",
      "disposition": "boundary",
      "candidate_keys": ["candidate-1"],
      "rationale": "Requests cross from an untrusted network into the API process."
    }
  ]
}
```

The agent must not author:

- public `tb-N` IDs;
- `resolution_status`;
- `sources`;
- exposure labels;
- severity or risk;
- finding references;
- commands or paths outside the declared output; or
- component IDs not present in the input registry.

Candidate keys are local foreign keys only. They have no stability guarantee
outside the candidate artifact.

### Contract E — canonical catalog and coverage result

Extend `prepare_trust_boundary_context.py` or add a narrow orchestration wrapper
so Phase 7b consumes the candidate sidecar and writes:

- `.trust-boundaries.json`;
- `.trust-boundary-diagnostics.json`; and
- `.trust-boundary-coverage.json`.

The canonical catalog remains the only semantic input for STRIDE, YAML,
rendering, and severity weighting.

Coverage output must record, for every deterministic signal:

- whether it maps to a canonical boundary;
- whether the agent explicitly classified it as same-trust or not applicable;
- whether it remains unresolved;
- the candidate and canonical IDs involved;
- the evidence basis; and
- deterministic validation issues.

The gate must require:

1. matching component and assessment fingerprints;
2. schema-valid candidate and disposition arrays;
3. unique candidate keys;
4. every mandatory signal accounted for exactly once at the disposition level;
5. all `boundary` dispositions referencing existing candidate keys;
6. every candidate covering at least one signal or flow;
7. canonical normalization and stable-ID reconciliation succeeding;
8. final endpoint validity against the finalized component registry; and
9. schema-valid canonical, diagnostics, and coverage artifacts.

Unresolved candidates are allowed. Missing artifacts, stale fingerprints,
unaccounted mandatory signals, or malformed dispositions are stage failures.

An explicit empty canonical list is valid only when the coverage artifact shows
that there were no mandatory crossing signals or that every signal received an
accepted non-boundary disposition with a concrete rationale.

## Deterministic boundary signals

The assessment-input builder must state the inspected signal, trigger,
false-positive exclusions, evidence, and expected disposition requirement.
It does not emit findings, so CWE, CVSS, and severity mappings are not
applicable.

| Signal class | Trigger | Required exclusions | Evidence |
|---|---|---|---|
| External ingress | Internet/DMZ component placement plus a runtime route or listener | Test fixtures, documentation-only routes, development-only listeners | Route/listener file and component mapping |
| Browser to server | Client-tier component with a runtime flow to an application-tier component, or a confirmed SPA/browser recon signal | SSR-only rendering with no client runtime; static asset copies without application messages | Flow plus client/server source locations |
| Cross-zone flow | Data flow whose resolved endpoint zones differ materially | Runtime-only labels that do not express trust; duplicate protocol views of the same crossing | Flow, component zones, protocol |
| Application to data tier | Application component reaches a datastore, cache, file store, queue, or search index | In-memory collections and test databases used only by tests | ORM/client configuration or flow evidence |
| Third-party or cross-repository | Cross-repo register entry or runtime SaaS/provider call | Development tooling and build-only dependencies unless the boundary kind is `build` | Register entry and runtime client/config evidence |
| Identity or privilege transition | Explicit authentication, authorization, admin, service identity, tenant, or impersonation transition | Display-only roles and documentation claims without enforcement code | Auth/control evidence and enforcing component |
| In-process isolation | Sandbox, plugin, template, parser, worker, child process, file-origin, or deserialization transition | Ordinary function calls with no trust or privilege change | Call site and isolation/parser configuration |
| Build and deployment | CI/CD, build, artifact publication, dependency registry, deployment, or contribution crossing | Local scripts not used by automation; docs-only workflow examples | Workflow/config evidence and component mapping |

The builder may merge duplicate raw signals, but it must preserve all evidence
and provenance. It must not invent the trust assumption; that remains an
assessment judgment.

## Stage completion and failure semantics

### Stage 1a completion

Required artifacts:

- `.recon-summary.md`;
- `.threat-modeling-context.md` when required by the selected mode;
- `.components.json`;
- `.component-inventory-finalization.json`;
- `.data-flows.json`;
- `.assets.json`;
- `.route-inventory.json` or an explicit validated empty/fallback state;
- `.attack-surface-overrides.json`; and
- `.trust-boundary-assessment-input.json`.

Write:

```text
phase=6 status=completed need_boundary_assessment=true
```

Do not create `.trust-boundaries.json` in Stage 1a on a normal analysis path.

### Stage 1b completion

Dispatch the dedicated boundary agent in a fresh session, validate its candidate
artifact, and run the deterministic gate.

On malformed or missing candidate output:

1. retry the boundary agent once with the same immutable input path;
2. do not broaden repository read scope on retry;
3. if the retry still fails, mark the checkpoint aborted and stop before
   Phase 8/STRIDE.

On valid output containing unresolved rows, continue and surface diagnostics.

Required completion artifacts:

- `.trust-boundary-candidates.json`;
- `.trust-boundaries.json`;
- `.trust-boundary-diagnostics.json`;
- `.trust-boundary-coverage.json`; and
- a passing Stage-1b gate receipt.

Write:

```text
phase=7 status=completed need_threat_analysis=true
```

### Stage 1c completion

Resume the threat analyst at Phase 8. It must:

1. produce `.security-controls.json`;
2. perform Phase-9 dispatch preparation;
3. build and validate the manifest;
4. create component-scoped trust-boundary contexts only after component
   selection;
5. run serial or bounded-parallel STRIDE according to the existing setting;
6. merge findings;
7. run deterministic emitters and triage;
8. build and validate `threat-model.yaml`; and
9. write the existing `phase=10b status=completed need_render=true`
   checkpoint.

The manifest gate must compare the current component fingerprint to the
Stage-1b fingerprint. A changed component ID set is a blocking producer defect,
not a reason to silently regenerate boundary contexts.

## Mode behavior

| Mode | Stage 1a | Stage 1b | Stage 1c |
|---|---|---|---|
| First full run | Run | Run | Run |
| Full refresh | Run | Run with prior `tb-N` identity | Run |
| Rebuild | Run after deliberate wipe | Run with new IDs allowed | Run |
| Quick | Run | Run with smaller agent budget and input caps | Run |
| Standard | Run | Run | Run |
| Thorough | Run | Run with larger evidence-read allowance | Run |
| Incremental with relevant source changes | Run/update contracted inputs | Re-run when input fingerprint changes; otherwise validate reuse | Run dirty STRIDE scope |
| Declaration-only boundary change | Skip LLM discovery | Deterministic normalize/coverage refresh only | Skip STRIDE |
| Rerender | Skip | Skip | Skip |
| Dry run | Plan and validate configuration only | No agent dispatch | No agent dispatch |
| Serial STRIDE opt-out | Run | Run | Run with serial STRIDE |
| Parallel STRIDE | Run | Run | Run with bounded waves |

`APPSEC_PARALLEL_STRIDE=0` changes only Phase-9 dispatch. It must not collapse
Stages 1a–1c back into one analyst session.

Use one stage topology at every assessment depth. Quick may reduce the model
turn budget and evidence sample counts, but it must not use a different
checkpoint graph.

## Incremental and stable-identity rules

The Stage-1b input fingerprint must cover:

- endpoint-relevant component fields;
- normalized data flows;
- external-ingress signals;
- relevant cross-repo entries;
- repository boundary-declaration fingerprint;
- assessment depth only when depth changes candidate coverage requirements;
- prior boundary identity inputs; and
- trust-boundary analysis schema version.

Re-run Stage 1b when any covered field changes.

For a declaration-only change:

- retain the existing fast path;
- rebuild the deterministic assessment input from existing canonical
  components and topology;
- merge declarations through the normalizer;
- refresh coverage and diagnostics;
- preserve stable IDs by declaration key and canonical identity;
- carry findings unchanged;
- rerender and run QA; and
- do not dispatch the boundary agent or STRIDE.

For ordinary incremental source changes, do not reuse a Stage-1b result merely
because component IDs are unchanged. Route, protocol, zone, integration,
identity, or build-surface changes may alter boundaries without changing the
component set.

## Work packages

## WP-0 — Freeze regression fixtures and decisions

Add neutral fixtures reproducing:

- a six-component architecture later expanded to eight by reconciliation;
- a browser/API/data-store topology;
- an internet ingress;
- one external SaaS flow;
- one build/deployment flow;
- one same-trust flow that should not become a boundary;
- an unresolved component endpoint;
- duplicate component IDs;
- stale fingerprints; and
- an explicit empty-boundary application with no relevant crossing signal.

Capture the latest juice-shop artifacts only as sanitized structural fixtures.
Do not include fixture-specific application names or known solution details in
production code.

Tests must demonstrate the current failure before the migration:

- Phase-7 candidates cannot see components injected later;
- no persisted `data_flows[]` handoff exists;
- an empty candidate list can currently pass shape validation; and
- combined Phase-5–7 logging cannot provide an isolated Phase-7 duration.

## WP-1 — Persist the topology contract

Files:

- add `schemas/fragments/data-flows.schema.json`;
- update `agents/phases/phase-group-architecture.md`;
- update `scripts/build_threat_model_yaml.py`;
- update fragment registration and schema-drift guards;
- update `docs/internal/contracts/schema-invariants.md`; and
- add producer, schema, builder, and two-run tests.

Implementation requirements:

- author data flows once in Phase 3;
- write `.data-flows.json` before the Phase-3 end marker;
- validate endpoint membership dynamically;
- preserve valid flow IDs during an incremental run;
- reject stale component fingerprints;
- remove the current working-memory-only YAML path; and
- ensure renderer behavior is unchanged for an equivalent flow set.

## WP-2 — Finalize components before trust assessment

Files:

- add `scripts/finalize_component_inventory.py`;
- add `tests/test_finalize_component_inventory.py`;
- refactor `scripts/build_stride_dispatch_manifest.py`;
- update `.components.json` producer tests;
- add the finalization audit schema; and
- update cleanup/audit contracts.

Implementation requirements:

- one shared reconciliation implementation;
- atomic component write;
- deterministic fingerprint;
- no late component-ID mutation;
- explicit failure when the manifest detects drift; and
- golden tests covering auth, CI/CD, real-time, duplicate-ID, and no-op cases.

Run the finalizer after Phase 6 on every Stage-1a path, including incremental
and serial-STRIDE runs.

## WP-3 — Build the bounded assessment input

Files:

- add `scripts/build_trust_boundary_assessment_input.py`;
- add `tests/test_build_trust_boundary_assessment_input.py`;
- add `schemas/trust-boundary-assessment-input.schema.json`;
- update `data/required-permissions.yaml`; and
- document the artifact in `docs/internal/contracts/audit-artifacts.md`.

Test:

- canonical path handling;
- untrusted strings retained only as data;
- signal detection and exclusions;
- deterministic ordering;
- deduplication without evidence loss;
- input fingerprint stability;
- missing optional sources;
- malformed input rejection;
- bounded route/evidence samples; and
- no repository-specific names in production output.

The builder must be deterministic and must not call the network or package
managers.

## WP-4 — Add the dedicated boundary agent

Files:

- add `agents/appsec-trust-boundary-analyst.md`;
- add `schemas/fragments/trust-boundary-candidates.schema.json`;
- update `tests/test_agent_definitions.py`;
- update model-selection and reasoning-model tests only if a new routed model
  role is introduced;
- update `data/context-budgets.yaml`; and
- update permissions.

Agent constraints:

- read the assessment input exactly once;
- read only evidence files referenced by the input, with bounded targeted
  slices;
- treat all repository and imported content as untrusted;
- write exactly one candidate artifact;
- never author public IDs or status;
- never run arbitrary repository commands;
- never write canonical/report artifacts;
- return only a completion receipt; and
- distinguish `confirmed`, `inferred`, and `unknown` conservatively.

Use the resolved orchestrator model initially unless measurements justify a
separate user-configurable role. Avoid adding a new public model option merely
for naming symmetry.

## WP-5 — Add coverage validation and canonical promotion

Files:

- extend `scripts/prepare_trust_boundary_context.py`;
- add `schemas/trust-boundary-coverage.schema.json`;
- update `schemas/trust-boundary-diagnostics.schema.json`;
- update `scripts/aggregate_run_issues.py`;
- update `scripts/validate_fragment.py`;
- update trust-boundary tests; and
- add coverage-gate tests.

Test:

- every mandatory signal accounted for;
- duplicate and missing dispositions;
- candidate-to-disposition referential integrity;
- candidate-to-flow referential integrity;
- stale fingerprints;
- valid unresolved rows;
- invalid canonical endpoints;
- empty candidate acceptance and rejection;
- stable `tb-N` assignment across two runs;
- declaration merge behavior;
- evidence path and line validation;
- semantically irrelevant evidence remaining non-confirmed when the agent did
  not verify it;
- diagnostics aggregation; and
- idempotent normalization.

The normalizer remains the sole owner of public IDs, sources, status, and final
endpoint canonicalization.

## WP-6 — Split the Stage-1 runtime

Files:

- update `skills/create-threat-model/SKILL-thin-stage1.md`;
- update the authoritative full runtime;
- update `skills/create-threat-model/SKILL-impl.md` compatibility prose;
- update `agents/appsec-threat-analyst.md`;
- update `agents/phases/phase-group-architecture.md`;
- update `agents/phases/phase-group-threats.md`;
- update `scripts/orchestration_controller.py`; and
- add runtime composition tests.

Add:

- `STAGE1_PHASE_LIMIT=6` discovery branch;
- a Stage-1b boundary dispatch owned by the skill/controller;
- `RESUME_FROM_PHASE=8` for the Stage-1c coordinator;
- explicit pre- and post-stage gates;
- separate Task lifecycle transitions; and
- separate stage-stat variants.

Remove:

- Phase 7 from the combined Phase-5–7 pass;
- provisional canonical-boundary writes from Stage 1a;
- the assumption that Analyst-A always runs Phases 1–8 in one context; and
- current Task rows that claim triage is independently live when it is not.

Proposed Task subjects:

```text
Stage 1a - Discovery & Architecture
Stage 1b - Trust Boundary Assessment
Stage 1c - Controls, STRIDE & Triage
Stage 1d - Abuse Case Verification
Stage 2 - Report Rendering
Stage 3 - QA Review
Stage 4 - Architect Review
```

The exact strings become contracts and require corresponding tests.

## WP-7 — Migrate checkpoints, resume, liveness, and statistics

Files likely affected:

- `scripts/check_state.py`;
- `scripts/acquire_lock.py`;
- `scripts/skill_watchdog.py`;
- `scripts/watch_run.py`;
- `scripts/appsec_status.py`;
- `scripts/render_progress.py`;
- `scripts/estimate_duration.py`;
- `scripts/record_stage_stats.py`;
- `scripts/render_completion_summary.py`;
- orchestration action contracts; and
- their tests.

Required resume transitions:

| Durable state | Resume action |
|---|---|
| Phase 6 completed, boundary needed | Dispatch Stage 1b only |
| Phase 7 started/aborted | Re-run Stage 1b against immutable input |
| Phase 7 completed, threat analysis needed | Start Stage 1c at Phase 8 |
| Phase 8 completed, STRIDE dispatch needed | Reuse existing manifest/wave recovery |
| Phase 10b completed, render needed | Existing Stage-2-only path |
| Phase 11 completed | No-op/clean completion |

Resume guards must verify the artifacts required by the claimed checkpoint.
A phase-7 checkpoint without matching candidate, canonical, coverage, and
fingerprint artifacts is stale and must not skip the boundary stage.

Stage statistics must record separate Stage-1 variants rather than accumulating
all work into one opaque `Threat Analysis & Triage` row. Net agent compute and
observed wall time must retain their current semantics.

Duration estimates must be recalibrated only after measured runs. Before real
measurements, label the boundary-stage estimate as parametric; do not derive an
isolated historical Phase-7 duration from the combined Phase-5–7 timestamps.

## WP-8 — Preserve mode-specific behavior

Update and test:

- full;
- rebuild;
- first run;
- incremental dirty;
- incremental ambiguous/new-component;
- declaration-only boundary recomposition;
- rerender;
- dry run;
- quick/standard/thorough;
- serial STRIDE;
- parallel STRIDE;
- budget-critical wrap-up; and
- requirements-enabled runs.

Budget-critical handling before Stage 1b may produce an incomplete assessment,
but it must not fabricate an empty successful coverage artifact. Mark the model
partial and surface the omitted boundary stage explicitly.

If budget-critical is reached during Stage 1b, allow the single normal retry
only when the failure was malformed output rather than budget exhaustion.
Otherwise stop before STRIDE and preserve the Stage-1a inputs for resume.

## WP-9 — Keep consumers on their correct stages

Do not move downstream ownership:

- component-scoped boundary context remains dispatch preparation;
- `boundary_refs[]` remain STRIDE/finding output;
- merge validation remains in `merge_threats.py`;
- effective severity and reconciliation remain Phase 10b;
- rationale remains downstream of persisted ranking;
- canonical YAML remains the source for Stage-2 rendering;
- the trust-boundary table remains composer-owned; and
- QA remains read-only after the final allowed mutations.

Add integration tests proving:

1. only canonical Stage-1b rows reach STRIDE contexts;
2. unresolved or unaccounted rows cannot elevate severity;
3. a valid confirmed external boundary still requires a finding-owned
   `boundary_ref`;
4. table rendering is unchanged for equivalent canonical input; and
5. no Stage-1b artifact can directly alter a finding.

## WP-10 — Versioning, permissions, cleanup, and documentation

Because the stage split changes analysis coverage and intermediate contracts:

- bump `analysis_version`;
- keep the prior repaired version readable;
- recommend a full refresh for older compatible baselines;
- document why incremental cannot reconstruct missing historical topology;
- register all new schemas and artifacts;
- preserve durable assessment/diagnostic artifacts through normal cleanup;
- remove transient candidate/input artifacts only according to the explicit
  cleanup contract;
- add new agent Read/Write and script command targets to
  `data/required-permissions.yaml`;
- update `docs/threat-modeler.md`;
- update internal orchestration, schema, cleanup, audit, and status contracts;
- update packaging tests; and
- add one concise user-visible `CHANGELOG.md` bullet.

Do not hardcode local replay paths in production files or user documentation.

## Implementation sequence

Implement in this order:

1. WP-0 fixtures and failing contract tests.
2. WP-1 data-flow persistence.
3. WP-2 early component finalization.
4. WP-3 deterministic assessment input.
5. WP-4 dedicated boundary agent and candidate schema.
6. WP-5 coverage and canonical gate.
7. WP-6 Stage-1 runtime split.
8. WP-7 checkpoint, resume, status, and statistics migration.
9. WP-8 mode-specific paths.
10. WP-9 downstream integration.
11. WP-10 versioning, permissions, cleanup, docs, and changelog.
12. Targeted tests, full repository gates, and real-run replay.

Do not merge the Stage split before WP-1, WP-2, and WP-5 are complete. Those
work packages are the safety prerequisites that make the fresh context an
improvement rather than a context-loss regression.

## Suggested commit slices

1. `Persist architecture data flows and finalize component inventory`
2. `Add trust boundary assessment input and candidate contracts`
3. `Add deterministic trust boundary coverage gate`
4. `Split trust boundary assessment into a dedicated stage`
5. `Migrate resume status and stage statistics`
6. `Complete mode compatibility and documentation`

Each slice must leave schemas, producers, consumers, and tests internally
consistent. Do not commit a producer that writes a shape no checked-in consumer
can validate.

## Verification plan

### Targeted unit and contract tests

At minimum run:

```bash
pytest -q \
  tests/test_finalize_component_inventory.py \
  tests/test_build_trust_boundary_assessment_input.py \
  tests/test_prepare_trust_boundary_context.py \
  tests/test_agent_definitions.py \
  tests/test_dispatch_manifest.py \
  tests/test_analysis_version_upgrade.py \
  tests/test_check_state.py \
  tests/test_appsec_status_live.py \
  tests/test_record_stage_stats.py \
  tests/test_render_completion_summary.py \
  tests/test_incremental_mode.py \
  tests/test_runtime_cleanup.py \
  tests/test_check_permissions.py
```

Also run all compose, YAML-builder, merge, ranking, rationale, and QA tests
affected by the canonical boundary consumer path.

### Runtime contract tests

Add tests for:

- Stage-1a completion and artifact gate;
- Stage-1b first attempt success;
- Stage-1b malformed output then successful retry;
- Stage-1b two-attempt failure;
- Stage-1b unresolved-but-valid completion;
- Stage-1b empty valid coverage;
- Stage-1b empty invalid coverage;
- component fingerprint drift before manifest construction;
- resume from Phase 6;
- resume during Phase 7;
- resume after Phase 7;
- declaration-only deterministic path;
- serial and parallel STRIDE after the same Stage-1b output;
- quick using the same checkpoint graph;
- budget-critical before and during Stage 1b; and
- Stage-2 rerender not dispatching the boundary agent.

### Golden fixture replay

Use `scripts/threat_fixture.py` with an application-neutral fixture that
contains:

- browser client;
- API;
- datastore;
- external identity provider;
- CI/CD workflow;
- internal same-trust helper;
- confirmed, inferred, and unresolved evidence.

Acceptance:

- finalized component ID set is identical before and after Stage 1b;
- every mandatory signal has one disposition;
- every canonical boundary has a candidate and evidence lineage;
- unresolved rows remain visible;
- only valid canonical rows reach component contexts;
- findings without `boundary_refs[]` receive no boundary elevation;
- two identical runs preserve `tb-N`;
- rebuild may reassign `tb-N` only under the existing rebuild contract; and
- Markdown/YAML/SARIF validation remains green.

### Juice-shop replay

Do not mutate `/home/mrohr/juice-shop/docs/security` during development.
Copy the run or execute against a disposable output directory.

Verify:

- `auth` and `web3-nft` are present before Stage 1b starts;
- the boundary agent receives the final component registry;
- browser/API, API/data, external ingress, external LLM/OAuth, WebSocket,
  CI/CD, and relevant in-process crossings are each dispositioned;
- unsupported or weakly evidenced candidates remain inferred/unresolved;
- Stage 1b has distinct start/end timestamps and a separate stage-stat row;
- STRIDE manifest construction does not mutate component IDs;
- trust-boundary table QA checks are clean;
- no exposure elevation occurs without new finding-owned boundary references;
  and
- the report is not claimed fully assessed if Stage 1b failed or was skipped by
  budget wrap-up.

The replay establishes correctness and stage observability. It must not be used
to add juice-shop-specific signals or exclusions.

### Repository gates

After targeted tests:

```bash
make lint
make test
make check
```

If the repository is already red because of unrelated working-tree changes,
record the baseline first and distinguish it from regressions. Run Ruff and
format checks directly on every touched Python file, and run
`git diff --check`.

## Acceptance criteria

The migration is complete only when all of the following hold:

- Stage 1a, 1b, 1c, and 1d have truthful independent task lifecycles.
- Stage 1b runs in a fresh agent context.
- The final component ID set exists before Stage 1b.
- The manifest cannot silently change that ID set.
- Data flows cross the Stage-1a/1b boundary through a validated schema.
- The agent writes candidates, never the canonical catalog.
- Every mandatory signal is dispositioned and coverage-validated.
- Missing or stale Stage-1b artifacts block STRIDE.
- Unresolved rows remain non-blocking and visible.
- Full, rebuild, incremental, quick, serial, parallel, declaration-only,
  rerender, resume, and budget-critical paths have tests.
- Existing `tb-N` identity is stable across compatible incremental/full
  refreshes.
- Severity still requires finding-owned validated boundary references.
- Stage 2 remains the sole normal report-rendering stage.
- The latest juice-shop replay has an independently measured Stage-1b and no
  post-boundary component-ID mutation.
- Relevant targeted tests, `make lint`, `make test`, and `make check` pass or
  have only documented unrelated baseline failures.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Extra agent handoffs increase cost | Keep the boundary prompt and input compact; measure before adding a separate public model option |
| Fresh context loses topology | Persist flows and finalize components before the split |
| Schema-valid but incomplete assessment | Require deterministic signal dispositions and coverage |
| Late component injection invalidates endpoints | Move reconciliation to Stage 1a and fingerprint the registry |
| Candidate agent invents public identity | Candidate-only schema; deterministic `tb-N` allocation |
| Repository content prompt-injects the agent | Explicit untrusted-data boundary, bounded input, restricted writes |
| Resume skips a partial stage | Artifact and fingerprint gate for every Phase-7 checkpoint |
| Quick and serial paths drift | One checkpoint graph across depth and dispatch modes |
| Declaration-only changes become expensive | Preserve deterministic no-LLM/no-STRIDE recomposition |
| New stage appears successful with no boundaries | Empty result requires complete accepted dispositions |
| Stage statistics double-count multi-dispatch work | Record explicit Stage-1 variants and test accumulation semantics |
| Current consumers start reading candidate data | Keep `.trust-boundaries.json` as the only canonical consumer input |

## Final recommendation

Proceed with the dedicated Stage-1b design, but land the topology persistence,
early component finalization, and coverage gate first. The fresh context is a
quality improvement; those deterministic contracts are what make the split
safe.
