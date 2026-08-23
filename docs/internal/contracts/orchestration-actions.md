# Orchestration Action Contract

`scripts/orchestration_controller.py` is the deterministic control plane for
the single full/rebuild and rerender runtimes. Its stdout is validated against
`schemas/orchestration-action.schema.json` before the skill consumes it.

## Control-plane invariants

Python controls execution and validates state. Models decide security meaning
only at explicit semantic boundaries, and contracted filesystem artifacts are
authoritative between boundaries. Extend the existing controller; never add a
second orchestrator, semantic-role registry, or concurrent producer for one
artifact.

Every semantic dispatch passes two independent admissions. Context admission
limits and receipts the instructions, state, and evidence delivered to the
role. Turn admission keeps deterministic routing, status, validation, and
normalization out of model loops. The action contract and artifact receipts
own the first gate; controller commands and fixed successor classification own
the second.

### Agent call lifecycle and budget telemetry

Every Agent tool invocation uses the host `tool_use_id` as its immutable
`agent_call_id`. `scripts/agent_lifecycle.py` persists the schema-v1 lifecycle
under `.active-tool-calls/agent-lifecycle.json` and permits only
`AGENT_SPAWN -> AGENT_RUNNING -> AGENT_DONE | AGENT_FAILED`. Replayed terminal
events are no-ops; missing, reordered, or conflicting transitions emit
`AGENT_LIFECYCLE_REJECTED`. The host `agent_id` binds SubagentStart and
SubagentStop usage to the call. SubagentStop reads the child-specific
`agent_transcript_path` and retires the budget; a missing or later Agent
PostToolUse cannot reopen the call. The common `transcript_path` belongs to the
parent session. A headless session persists neither transcript: SubagentStop
then defers the outcome instead of recording a failure, and the Agent
PostToolUse terminalizes the call and supplies its usage. A run or session ID
alone never assigns a role, usage record, or turn counter.

Context-v2 semantic prompts carry the controller action and job IDs. STRIDE
calls also carry their component and attempt-qualified job, while depth and
turn policy are re-read from the schema-valid current component plan. The
context-routing ledger, persisted dispatch-wave active claim, and promoted
attempt remain authoritative. Lifecycle state, `.active-tool-calls`, hook
events, and status output are observational.

`scripts/budget_watchdog.py` opens one schema-v2 counter at call admission and
retires it with the terminal call. Budget markers retain the compatible JSON
list envelope but each new entry must validate against
`schemas/agent-call-budget-marker.schema.json`. Entries without a current
`agent_call_id + action_id + job_id + component_id + attempt` identity are
inert. Consumers use `budget_watchdog.py active-critical`; they never branch on
marker-file existence. Terminal cleanup first emits `AGENT_FAILED` for any
remaining calls, retires their counters and markers, then removes
`.active-tool-calls/`.

A run that does not finish cleanly still reaches one terminal state.
`scripts/terminate_run.py` is that single terminator: it records `RUN_ABORTED`
unless a controller verdict already stands, closes the checkpoint, terminalizes
remaining calls, removes live markers, aggregates run issues, and releases the
lock when the run owns it. A lock whose holder is alive under a different run
ID is never released. The headless wrapper calls it on operator interrupt and
on a failed exit.

Each context-v2 boundary that runs after a producer returned first cross-checks
the surfaces describing the calls of the most recent dispatch action: accepted
output, lifecycle terminal state, child usage attribution, budget retirement,
and stage-stats tokens. A disagreement emits `TELEMETRY_MISMATCH` and the run
continues, because these surfaces stay observational. `APPSEC_TELEMETRY_STRICT=1`
aborts the boundary instead, so an acceptance run cannot pass on telemetry its
own producers contradict.

Context-v2 STRIDE progress uses schema version 2 in
`schemas/stride-progress.schema.json`. Its producer resolves the one running
component call and persists `action_id`, attempt-qualified `job_id`, `attempt`,
and the validated context-plan depth. A stale attempt or non-current active
claim fails at the producer gate. Status accepts schema-v1 progress only as
legacy observational input; current v2 records are schema- and claim-checked.

The standing contract surfaces are:

- action and dispatch receipts in this document and
  `schemas/orchestration-action.schema.json`;
- component STRIDE admission in this document and the evidence-bundle,
  component-plan, and dispatch-manifest schemas;
- semantic producers and post-STRIDE progression in the boundary map below;
  and
- context catalog and effective-plan policy in
  `docs/internal/contracts/context-routing.md`.

Dispatch and mutation ownership is global: Level-0 dispatch belongs to the
compact runtime acting on controller actions, and no agent recurses through
`Agent`. One controller boundary owns each state mutation and producer output.

## Ownership

- `resolve_config.py` remains the source of truth for flags, paths, modes,
  models, depth, and output settings.
- `orchestration_controller.py` owns thin-runtime selection, full/rebuild
  preflight mutations, Stage-1a topology/finalization gate, Stage-1b candidate
  promotion and coverage gate, Stage-1c post-analysis gates and checkpoint
  freshness, abuse-case match/finalize, Stage-2 structural preparation,
  rerender artifact preconditions, fixed next-action classification, and
  compact dispatch values.
- `prepare-stage2` returns an explicit renderer profile. Default Quick uses only
  the Management Summary specialist, enriched architecture uses both
  specialists, and the full renderer remains the bounded recovery profile.
  Every profile converges on the same controller-owned fragment validation,
  strict compose, prose-fix, and QA-autofix tail before Stage 3.
- `SKILL-full-runtime.md`, `SKILL-thin-stage1-v2.md`,
  `SKILL-thin-stage1d.md`, `SKILL-thin-stage2.md`, and
  `SKILL-rerender-runtime.md` own user-visible output, Task lifecycle, and
  Level-0 producer calls for their modes. `SKILL-thin-stage3.md`,
  `SKILL-thin-stage4.md`, and `SKILL-thin-completion.md` own the bounded review,
  repair, release-gate, export, and cleanup calls selected by the controller.
- `stride_dispatch_waves.py` owns deterministic bounded-wave scheduling,
  persisted two-attempt counters, resume selection, and the selected-component
  completion gate. It never changes component selection or analyzer prompts.
- Registered agents own semantic analysis and prose. The controller and its
  deterministic validators, renderer, QA gates, and cleanup own every state
  transition and release decision.

The action itself is not a persisted runtime sidecar. Rehydration reads
existing `.skill-config.json`, checkpoints, validated phase artifacts, and
status files.

## Context routing plan

`data/context-routing-catalog.yaml` is the human-readable Stage-1 context
configuration. It groups context into target and run, business and
requirements, repository discovery, architecture, assets, and data flows,
actors and abuse cases, trust boundaries, security controls and evidence,
threat analysis, verification and risk, and prior-run identity. Each assignment
names the context, the receiving agents, whether delivery is required,
optional, or forbidden, its optional-context importance, its whole-run,
current-component, or current-candidate target, and the reason. It deliberately
contains no paths, schemas, producers, projectors, models, commands, byte
limits, token limits, runtime migration switches, or unresolved selectors.

`data/context-routing-bindings.json` is the plugin-owned implementation
contract. It binds the human names to closed semantic roles, artifact
contracts, paths, projectors, trust and sensitivity classes, and hard limits.
Repository content cannot select or modify either execution surfaces or core
required and forbidden assignments.

For every emitted context-v2 semantic action, `scripts/context_routing.py`
validates both files, binds them to the controller role registry, and appends a
decision to `.context-routing-plan.json`. The exact-byte
`.context-routing-plan.receipt.json` detects plan mutation. Unmigrated entries
remain `shadow-only`; existing implicit artifacts are `observed_implicit`, and
direct reads and unresolved plugin registries are `legacy_unreceipted`.

The first active migration covers the STRIDE component plan, evidence bundle,
taxonomy slice, fixed lens IDs, and bounded analysis policy. Those deliveries
are marked `plan-enforced`, referenced by delivery ID from the owning job, and
revalidated before dispatch. The shared effective plan remains a controller
audit artifact and never enters an Agent input or prompt.

Both plan files are local audit artifacts. Successful runtime cleanup preserves
them, while the next full or rebuild preflight removes them before a fresh plan
is created. Incremental and resume invocations are refused before dispatch or
run-state mutation; stale catalog,
binding, run, plan, or receipt bytes block rather than being carried forward.
Diagnostic bundles include only their filename, byte count, and hash through
the existing metadata inventory and never copy their contents.

## Context-v2 STRIDE admission

`scripts/build_stride_evidence_bundles.py` projects each selected component
into `.dispatch-context/<component-id>/evidence-bundle.json`, validated by
`schemas/stride-evidence-bundle.schema.json`. The bundle is capped at 65,536
serialized bytes, 16,384 estimated tokens, 400 referenced source lines, 24
source slices, and 32 values per evidence class. Deterministic lexical ordering
and explicit truncation receipts replace qualitative selection by the builder.
Known threats, prior findings, actors, trust boundaries, requirement
violations, and existing controls are not duplicated in that required bundle.
Each non-empty category has its own bounded
`.dispatch-context/<component-id>/*-context.json` projection under
`schemas/stride-component-security-context.schema.json`; an inapplicable or
empty category is physically absent. All six projections together retain the
former 65,536-byte and 16,384-token aggregate admission budget.

The builder normalizes compatibility string-or-list focus and exclude inputs
to at most 16 literal repository-relative paths per component. Focus paths
admit bounded source projections before optional discovery. Exclude paths
suppress only optional component discovery and conflict with focus paths,
deterministic signals, or cited evidence. The bundle's `path_routing` records
each focus admission or omission and each applied exclusion; the bundle receipt
binds that decision to the exact validated bytes.

Each source slice names a controller-registered repository, relative path,
line range, signal kind, and exact content hash. The primary repository state
binds HEAD and the dirty worktree while excluding generated output. Related
roots require an exact local declaration in `docs/related-repos.yaml` and a
controller-owned `.stride-repository-registry.json` record validated by
`schemas/stride-repository-registry.schema.json`. Remote and non-Git local
declarations do not become source roots; a declaration that reuses an already
registered Git root fails admission. A component bundle fingerprints only the
primary root and related roots named by its admitted source slices. The
controller projects those related roots into
`.dispatch-context/<component-id>/repository-roots.json`, validated by
`schemas/stride-component-repository-roots.schema.json`; the complete registry
never enters a STRIDE job. The validator re-resolves containment, repository
state, the source-registry binding, and every slice hash immediately before
dispatch.

`context_version: 2` in `.stride-dispatch-manifest.json` requires the canonical
bundle path, exact file SHA-256, and token estimate for every selected
component. It also applies containment to retained legacy `index_paths` and
fails closed without `jsonschema`. `--context-v2` on the manifest builder is an
internal producer switch; the live path reaches it only through an eligible
context-v2 full/rebuild generation.

Optional STRIDE lenses are fixed manifest enums. The role registry maps them to
plugin-owned files; no bundle or repository value can select a lens path.
The controller also builds one component-scoped
`.taxonomy-slices/<component-id>/threat-category-taxonomy.yaml`, carries its
path and SHA-256 in the STRIDE job, and writes a receipted
`.dispatch-context/<component-id>/context-plan.json`. This bounded projection
binds the evidence and taxonomy hashes, any selected component business,
architecture, repository-root, or security-category projection, fixed lens
IDs, component analysis depth, sampling and turn policy, estimates, and
resolved STRIDE profile. The
thin runtime re-hashes the component plan, taxonomy, effective-plan receipt,
and structured receipts immediately before dispatch. The STRIDE consumer reads
the component plan instead of the complete dispatch manifest. A wave contains
at most five components so the worst-case eleven receipts per component plus
the effective-plan receipt stay within the fixed 64-artifact verification cap.

## Context-v2 semantic boundary map

Every boundary below has a landed controller command, and each executes its real
deterministic owners. The commands run the boundary chain in order:
`context-v2-begin`, `context-v2-post-recon`, `context-v2-post-actors`,
`context-v2-post-architecture`, `context-v2-post-boundary`,
`context-v2-prepare-stride`, then the `context-v2-post-*` post-STRIDE chain.

When the LLM-written recon-signals artifact fails its contract, the recon
boundary returns one redispatch of the producing role instead of aborting. The
retry carries the validator errors as an input artifact, uses an
attempt-qualified job id, and is budgeted once for that artifact; the second
violation aborts. STRIDE uses its separate persisted two-attempt component
budget described below. Other producer failures follow the boundary-specific
behavior in the table, and a deterministic producer's invalid output is never
retried.

Every dispatching action carries `next_boundary`, the command the caller must
invoke once those jobs return. The caller invokes it verbatim and never derives
the successor from the run's shape: quick depth skips actor discovery, so the
boundary after recon differs by depth. Re-invoking a boundary whose semantic
dispatch already ran repeats that dispatch without preparing its outputs a
second time; only a changed action under the same job identity is rejected as a
replay and aborts the run.

The generation is the default for eligible full/rebuild runs. `prepare` returns
the plugin-owned `SKILL-thin-stage1-v2.md` instruction path, and the compact
parent runtime loads that returned path rather than choosing a Stage-1 producer
itself. The table is the producer contract for that path.

| Boundary | Validated inputs | Writer and output contract | Gate and exit class | Checkpoint, retry, and next action |
|---|---|---|---|---|
| Phase 1/2 recon wave | `.skill-config.json`; current repository fingerprint and cache decision; bounded contained project documents; optional schema-valid `known-threats.schema.yaml`; optional receipted `recon-patterns.schema.json` v1 | `build_threat_modeling_context.py` writes bounded `threat-modeling-context-markdown-v1` and the declared related-repository sidecars before dispatch; `recon_scanner` writes the `recon-summary-markdown-v1` numbered security sections plus `recon-signals.schema.json` v2; the controller invokes `config_iac_scanner.py` to write `config-scan-findings.schema.yaml` when an IaC surface exists | Context-v2 performs no model dispatch for project-context selection, rendering, or Config/IaC catalog evaluation. The builder caps admitted files and bytes, rejects escaping symlinks, fences repository and endpoint text, validates configured URLs and redirects, rejects malformed or oversized known-threat inputs, and validates the completed Markdown before the recon wave. The deterministic pattern producer retains at most 12 findings per category and 96 across the run with pre-cap counts and omission metadata. The recon role admits at most 22 discovery tool calls and reserves at least ten calls for one-shot template loading, publication, shared validation, bounded correction, and completion; repository size may extend deterministic pre-passes but not the model discovery allowance. `validate_recon_summary.py` runs at the producer and controller boundaries. A `Key files` entry is one observed contained regular-file and single-line reference; its deterministic normalizer may only delete malformed, missing, directory, range, or out-of-range entries and replace an empty list with `none detected`. Recon signal evidence is structured and every location must resolve to a contained regular file and existing line at both producer and controller gates; malformed evidence is never parsed or repaired. The Config/IaC producer evaluates every canonical catalog entry, contains resolved files beneath the repository, and binds counters and finding metadata to that catalog. Context headings, non-nested fences, recon safety limits, bounded recon-signal schema, unique hint IDs, and config completeness are validated before the next boundary; config enrichment failure is non-fatal | No checkpoint; one bounded recon wave plus deterministic Config/IaC enrichment; then deterministic Phase-2.6 projection and actor selection |
| Phase 2.7 actors | Receipted `recon-summary-context.schema.json` v1 capped at 200 retained lines, `recon-signals.schema.json` v2, `actors-merged-static.schema.yaml` v1, and the actor-input fingerprint | `resolve_actors.py` exclusively writes and validates the static actor catalog; `actor_discoverer` may write `actors-discovered.schema.yaml`; the resolver then exclusively writes `actors-resolved.schema.yaml` | Projection source hashes, schema, omission counts, and receipts block; discovery is skipped at quick depth or on a valid cache hit; resolver validation is authoritative; discovery failure degrades to the static actor set | No implicit redispatch after an Agent returns; then `architecture_analyst` |
| Phases 3–6 architecture | Receipted recon projection, `architecture-route-context.schema.json` v1 capped at 96 risk-shaped and framework-diverse routes, and resolved actors | `architecture_analyst` writes version-1 components, data-flows, assets, and attack-surface-overrides fragments; every non-route attack-surface addition carries a boolean authentication verdict; the data-flow inventory fingerprint is provisional | Projection source hashes, schemas, omission counts, `validate_fragment.py`, controller-owned component finalization, deterministic data-flow fingerprint binding, receipt validation, and assessment-input construction block; the complete route inventory remains with deterministic consumers; null authentication or structural failure blocks | The controller writes `phase=6 status=completed need_boundary_assessment=true` only after every gate passes; failure blocks without implicit redispatch; then `trust_boundary_analyst` |
| Phase 7 boundary | `trust-boundary-assessment-input` contract v1 and its exact receipt | `trust_boundary_analyst` writes `trust-boundary-candidates.schema.json` v1 | `prepare_trust_boundary_context.py promote` owns normalization and coverage; non-zero is blocking | `phase=7 status=completed need_threat_analysis=true`; persisted Stage-1b retry behavior; then `control_analyst` |
| Phase 8 controls | Controller-bounded path list for final components, boundaries, and architecture-control signals | `control_analyst` writes `security-controls.schema.json` v1 and the bounded semantic overlays needed by known component IDs in `stride-analyst-context.schema.json` v1; it omits empty component placeholders and never owns the reserved `_stride_profile` routing value | The producer gate and controller both validate routing hints against repository existence and finalized component ownership. The controller also drops a producer-authored `_stride_profile`, rejects unknown component IDs or an overlay above the byte cap, derives the manifest profile from resolved run configuration, and runs `validate_fragment.py security-controls`; bundle construction independently repeats normalization and containment checks before dispatch, and every non-zero gate remains blocking | Phase-8 checkpoint; failure blocks without implicit redispatch; then bundle and manifest construction |
| Phase 9 STRIDE | One receipted component context plan binding a fresh `stride-evidence-bundle` v1, hashed taxonomy slice, lens IDs, analysis policy, independently selected security-category projections, and only the related roots cited by that component's admitted source slices | `stride_analyzer` writes `stride.schema.yaml`; no other writer may write the same component file | Manifest, bundle, component-plan, security-context, and repository-projection schema and source-hash validation, active effective-plan binding, immediate receipt re-hash, merge-owned mechanical normalization, per-file `validate_intermediate.py stride`, and `stride_dispatch_waves.py verify`; optional branches that fail the schema are pruned before validation and remaining invalid output is fatal | Persisted two-attempt component budget in background waves of at most five; each job carries its controller-owned attempt identity; the deterministic waiter joins exactly the persisted active claim and retains one cumulative deadline across bounded host-Bash slices before `context-v2-post-stride` — derived from the widest `max_turns` in the wave, floored at 15 minutes and capped at 60; an unjoined claim cannot be claimed again |
| Phase 9 merge | Valid STRIDE outputs and bounded `merge-review-context` v1 projected from `merge-candidates` v1 | `merge_threats.py collect/finalize` owns ordering and T-IDs; `threat_merger` writes `merge-decisions.schema.json` v2 only when candidate groups exist | Candidate-free collect immediately finalizes; context-v2 binds the projection to the full source hash, requires at least one decision per admitted group, validates disjoint partial-cluster subsets, and re-hashes decisions before finalize | No checkpoint; one merger dispatch for at most 64 groups within the 262,144-byte projection cap; then passive posture emitters |
| Phase 10/10a evidence | Receipted `evidence-verifier-context.schema.json` v1 with at most 256 deterministically selected findings, a 524,288-byte cap, and exact-source-bound 11-line citation windows | Passive posture scripts own their existing sidecars; `evidence_verifier` writes only `evidence-verification.schema.json` v1; the controller exclusively applies accepted verdicts to the canonical merged threats | The controller reconstructs sampling from depth and cap, re-hashes merged threats and every source file, compares every projected window, validates counts and selected T-IDs, applies only evidence verdict fields, and revalidates the canonical artifact; invalid enrichment supplies no semantic signal; the guard retains its degenerate-verdict fallback | No model retry for a deterministic emitter; the complete merged artifact and direct repository reads are forbidden to the verifier; semantic source-window bounds and serialized-artifact line bounds remain separate; then deterministic triage |
| Phase 10b triage | `threats-merged.schema.yaml` v1 and optional evidence verdicts | `triage_validate_ratings.py` and `triage_compute_ranking.py --force --bootstrap-yaml` write `triage-flags.schema.yaml` v2 | Rating validation is blocking; a ranking failure selects the focused triage fallback, while every path revalidates both the mutated merged artifact and triage flags before synthesis | No specialist on deterministic success; then optional post-STRIDE synthesis |
| Phase 10b synthesis | Separate receipted generated-threat and proposed-mitigation projections, each capped at 512 records and 524,288 bytes and bound to exact merged-threat and component hashes | `post_stride_synthesizer` writes only the requested version-1 mitigation-overrides or tier-root-causes fragment | The controller reconstructs both projections before dispatch; complete merged threats and triage flags are forbidden; `validate_fragment.py` gates each output, which is receipted and re-hashed before YAML consumption | Failure blocks without implicit redispatch; then `context-v2-finalize` |
| YAML handoff | Validated Phase-3 through Phase-10b sidecars | `build_threat_model_yaml.py` writes canonical `threat-model.yaml`; the shared deterministic auto-emitter pass then backfills scanner remediation and hydrates mitigation details | Initial `validate_intermediate.py threat_model_output`, mitigation-quality validation after enrichment, and build completeness are blocking | `phase=10b status=completed need_render=true runtime_generation=context-v2`; then Stage 2 |

`context-v2-prepare-stride` validates the Phase-8 outputs, builds and validates
the v2 manifest and bundles, and returns one bounded job per selected component.
The compact runtime issues every job of the wave as an Agent call in one
assistant message, which is what runs them concurrently; the Agent tool exposes
no per-call background flag, so dispatch shape is not gated at PreToolUse.
`check_stride_dispatch.py` remains the enforcement point — it fails the run on
an inline-shortcut bypass and reports a serially dispatched wave as DEGRADED.
The blocking waiter applies wave completion validation, so a write-first seed
remains pending.
`context-v2-post-stride` runs wave verification and merge collection until it
either returns a bounded merger job or reaches the next boundary.
The merger reads `.merge-context/candidates.json`; the full
`.merge-candidates.json` remains a deterministic-finalizer input and is rejected
if it changes after projection.
`context-v2-post-merge`, `context-v2-post-evidence`, and
`context-v2-post-triage` continue from the corresponding focused output;
`context-v2-finalize` consumes the optional synthesis output. An empty merge
candidate set skips the merger. The deterministic ranking success path skips
the triage agent; its focused fallback is selected only when deterministic
ranking fails. A run with no threats reaches the YAML handoff without a
post-STRIDE Agent dispatch.

Stage 1d context-v2 matching projects each of at most 64 eligible candidates
to `abuse-case-verifier-context` v1 under `.dispatch-context/abuse-cases/`.
Every verifier job carries its candidate ID, one declared projection, one exact-
byte receipt, and one verdict output. The thin runtime verifies all projection
receipts immediately before launching every verifier in the background. The
PreToolUse gate rejects foreground context-v2 verifier calls. One deterministic
waiter requires every declared verdict to have all steps decided; a write-first
pending verdict does not release the boundary. The complete match set stays
controller-owned; merge, chain finalization, finding promotion, YAML rebuild,
release gates, and ranking remain deterministic. The controller also selects
the stage: while the Stage-1 checkpoint still needs rendering, abuse
verification is enabled, and no matcher sidecar is newer than that checkpoint,
the `next` and `prepare-stage2` transitions return the Stage-1d runtime instead
of Stage 2 — each at most once, so an ignored redirect cannot loop.

Every semantic role is classified as producer-gated or controller-recovered
before it can be dispatched. Producer-gated roles run the same deterministic
schema or Markdown validator before returning that the controller repeats at
the boundary. STRIDE is the only controller-recovered role: its existing
bounded retry validates and redispatches only the affected component. Adding a
semantic role without one of these enforcement paths is a controller contract
error.

## Security and schema rules

- Action names and stage names are fixed enums.
- Abuse verifier candidates are bounded data-only identifiers; repository text
  cannot add commands, tools, paths, or instruction files to an action.
- `dispatch_values` has an allow-listed key set and bounded scalar/profile
  values; arbitrary command fields are rejected.
- `instruction_file` is selected only from plugin-owned constants. Repository
  content never supplies an action, command, write target, or instruction path.
- `task_rows` is a fixed controller-owned label set covering every task row of
  the run, already reduced to the rows this invocation has. The session creates
  rows only from it and authors no label of its own, so the subjects a later
  update matches on cannot drift.
- `semantic_role` and every role in `dispatch_jobs` resolve through the
  controller's closed registry to a plugin-owned agent definition, tool set,
  model route, and output contract. Jobs carry the controller-derived
  `agent_type` and bare model alias plus bounded identifiers, relative artifact
  paths, and unresolved semantic decision keys; semantic validation rejects a
  mismatch with the role registry.
- Every STRIDE job carries one bounded component context plan and its exact
  receipt. The plan binds resolved depth and sampling policy, lens IDs, the
  controller-resolved profile, bundle and taxonomy hashes, and any receipted
  component repository-root projection; repository data cannot select or
  relabel the tier, profile, lens path, taxonomy, or additional repository.
- Dispatch-job, component, and output-artifact ownership are independently
  unique within one action. Parallel jobs cannot read an artifact another job
  writes. The canonical JSON form of an action is capped at 65,536 bytes.
- A semantic action identity is single-use within one run. The effective plan
  is append-only, so a boundary that recomputes the recorded action byte for
  byte is answered with it and skips dispatch preparation, which would remove a
  producer's existing output; a differing action under that identity is
  rejected before preparation runs. A controller-owned STRIDE retry uses a new
  attempt-qualified job identity and records the bounded attempt in the action.
- Artifact paths resolve under `dispatch_values.output_dir`. Absolute paths,
  traversal, backslashes, and symlink escapes fail before dispatch.
- `artifact_receipts` are versioned separately from human-readable `receipts`.
  A structured receipt records the relative path, schema identity, SHA-256,
  record count, and successful validation status from the exact validated
  bytes.
- A command that rejects its own arguments answers `reject` with exit code 3,
  writes no `RUN_ABORTED`, and leaves the run untouched; the caller corrects the
  call and repeats it. Everything a command learns from disk — a changed
  artifact, an invalid contract, a stale receipt — answers `abort`, ends the
  run, and is never repeated.
- Receipt creation validates and hashes one exact byte snapshot. Immediately
  before Agent dispatch, the thin runtime calls `verify-receipts` once for the
  complete action and its STRIDE taxonomy slices; the effective-plan receipt is
  one of the action's receipts, and naming it a second time with the same
  fingerprint verifies it once rather than failing. A missing validator,
  unreadable artifact, byte change, or one path carrying two fingerprints fails
  closed.
- Before returning a semantic dispatch, the controller removes prior bytes for
  every output not also used as an in-place repair input. Fresh context-v2 entry
  also removes optional evidence and synthesis outputs that may have no producer
  in the new run, so retained runtime files cannot satisfy a later gate.
- A parallel join is scoped to the dispatch jobs in the current action, never
  to undispatched members of a future wave. A waiter slice returns `75` before
  the host's Bash ceiling and is repeated without resetting the persisted wave
  deadline; `0` and deadline exit `1` return ownership to the controller.
- Full/rebuild cleanup matches the controller-owned exact filename globs;
  prefix lookalikes and symlink targets must not be deleted.
- A context-v2 terminal abort has no continuation action. A later `--full`
  starts Stage 1 again; retained runtime artifacts are diagnostic evidence, not
  a merge-only recovery checkpoint.
- A current-run `RUN_ABORTED` is enforced both by context-v2 controller entry
  points and the PreToolUse hook. Abort aggregation removes live-only
  `.active-tool-calls` state, while headless runs export their resolved output
  directory to every hook process so terminal state and telemetry share one
  run-local location.
- Rebuild archives the live changelog audit before deletion and fails closed if
  archiving fails.
- All new event lines use `event_log.py`.

## Runtime generation

Every new run is prepared as `context-v2`, and `resolve_config.py` persists that
generation in `.skill-config.json` together with the artifact schema versions
used to reconstruct successor actions. Environment variables cannot select a
different generation. A boundary refuses a missing, pre-cutover, or
schema-incompatible generation and requires a new full or rebuild run.

## Supported modes

Full and rebuild use `SKILL-full-runtime.md`; rerender uses
`SKILL-rerender-runtime.md`. Incremental, resume, dry-run, `--max-wall-time`,
`--max-cost`, and `APPSEC_LIVE_PHASE=1` are unsupported until they have bounded
controller implementations. The router resolves these invocations without
creating their output directory, then aborts before dispatch or run-state
mutation with the supported alternatives.
