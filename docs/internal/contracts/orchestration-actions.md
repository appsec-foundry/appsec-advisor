# Orchestration Action Contract

`scripts/orchestration_controller.py` is the deterministic control plane for
the thin full/rebuild and rerender runtimes (the defaults; opt out with
`APPSEC_THIN_ORCHESTRATOR=0`). Its stdout is validated against
`schemas/orchestration-action.schema.json` before the skill consumes it.

## Ownership

- `resolve_config.py` remains the source of truth for flags, paths, modes,
  models, depth, and output settings.
- `orchestration_controller.py` owns thin-runtime selection, full/rebuild
  preflight mutations, Stage-1a topology/finalization gate, Stage-1b candidate
  promotion and coverage gate, Stage-1c post-analysis gates and checkpoint
  freshness, abuse-case match/finalize, Stage-2 structural preparation,
  rerender artifact preconditions, fixed next-action classification, and
  compact dispatch values.
- `SKILL-full-runtime.md`, `SKILL-thin-stage1.md`,
  `SKILL-thin-stage1b.md`, `SKILL-thin-stage1d.md`, `SKILL-thin-stage2.md`, and
  `SKILL-rerender-runtime.md` own user-visible output, Task lifecycle, and
  Level-0 Agent calls for their modes.
- `stride_dispatch_waves.py` owns deterministic bounded-wave scheduling,
  persisted two-attempt counters, resume selection, and the selected-component
  completion gate. It never changes component selection or analyzer prompts.
- Existing agents, phase groups, deterministic gates, renderer, QA, and
  cleanup remain authoritative for analysis and report quality.

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
is created. Context-v2 still has no incremental or resume path; stale catalog,
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
internal producer switch; the live path can reach it only through the explicit
full/rebuild `APPSEC_CONTEXT_V2=1` opt-in.

Optional STRIDE lenses are fixed manifest enums. The role registry maps them to
plugin-owned files; no bundle or repository value can select a lens path.
The controller also builds one component-scoped
`.taxonomy-slices/<component-id>/threat-category-taxonomy.yaml`, carries its
path and SHA-256 in the STRIDE job, and writes a receipted
`.dispatch-context/<component-id>/context-plan.json`. This bounded projection
binds the evidence and taxonomy hashes, any component repository-root
projection, fixed lens IDs, component analysis depth, sampling and turn policy,
estimates, and resolved STRIDE profile. The
thin runtime re-hashes the component plan, taxonomy, effective-plan receipt,
and structured receipts immediately before dispatch. The STRIDE consumer reads
the component plan instead of the complete dispatch manifest. A wave contains
at most 15 components so the worst-case four hashes per component plus the
effective-plan receipt stay within the fixed 64-artifact verification cap.

## Context-v2 semantic boundary map

Every boundary below has a landed controller command, and each executes its real
deterministic owners. The commands run the boundary chain in order:
`context-v2-begin`, `context-v2-post-recon`, `context-v2-post-actors`,
`context-v2-post-architecture`, `context-v2-post-boundary`,
`context-v2-prepare-stride`, then the `context-v2-post-*` post-STRIDE chain.

The generation is reachable only through the explicit full/rebuild
`APPSEC_CONTEXT_V2=1` A/B opt-in. `prepare` returns the plugin-owned
`SKILL-thin-stage1-v2.md` instruction path, and the compact parent runtime loads
that returned path rather than choosing a Stage-1 producer itself. The table is
the producer contract for that opt-in path.

| Boundary | Validated inputs | Writer and output contract | Gate and exit class | Checkpoint, retry, and next action |
|---|---|---|---|---|
| Phase 1/2 recon wave | `.skill-config.json`; current repository fingerprint and cache decision | `context_resolver` writes bounded `threat-modeling-context-markdown-v1` with controller-validated untrusted-data fences and its declared related-repository sidecars; `recon_scanner` writes the `recon-summary-markdown-v1` numbered security sections plus `recon-signals.schema.json` v1; the conditional `config_scanner` writes `config-scan-findings.schema.yaml` | The recon role admits at most 22 discovery tool calls and reserves at least ten calls for one-shot template loading, publication, shared validation, bounded correction, and completion; repository size may extend the deterministic pre-pass but not the model discovery allowance. `validate_recon_summary.py` and `validate_threat_modeling_context.py` run at their producers and again at the controller boundary. The context contract may insert an omitted level-2 heading with neutral text in canonical order; it never repairs a missing root, reordered authored sections, size violations, or malformed fences. Context headings, non-nested fences, recon safety limits, bounded recon-signal schema, and unique hint IDs are blocking; the tighter recon line target is observable but compatibility-safe; config enrichment failure is non-fatal | No checkpoint; one bounded parallel wave; then deterministic Phase-2.6 work and actor selection |
| Phase 2.7 actors | Validated recon sidecars, default/org/repository actor catalogs, actor-input fingerprint | `actor_discoverer` may write `actors-discovered.schema.yaml`; `resolve_actors.py` exclusively writes `actors-resolved.schema.yaml` | Discovery is skipped at quick depth or on a valid cache hit; resolver validation is authoritative; discovery failure degrades to the static actor set | No implicit redispatch after an Agent returns; then `architecture_analyst` |
| Phases 3–6 architecture | Controller-bounded path list for validated recon, route inventory, and resolved actors | `architecture_analyst` writes version-1 components, data-flows, assets, and attack-surface-overrides fragments; the data-flow inventory fingerprint is provisional | `validate_fragment.py`, controller-owned component finalization, deterministic data-flow fingerprint binding, receipt validation, and assessment-input construction; structural failure blocks | The controller writes `phase=6 status=completed need_boundary_assessment=true` only after every gate passes; failure blocks without implicit redispatch; then `trust_boundary_analyst` |
| Phase 7 boundary | `trust-boundary-assessment-input` contract v1 and its exact receipt | `trust_boundary_analyst` writes `trust-boundary-candidates.schema.json` v1 | `prepare_trust_boundary_context.py promote` owns normalization and coverage; non-zero is blocking | `phase=7 status=completed need_threat_analysis=true`; persisted Stage-1b retry behavior; then `control_analyst` |
| Phase 8 controls | Controller-bounded path list for final components, boundaries, and architecture-control signals | `control_analyst` writes `security-controls.schema.json` v1 and the bounded semantic overlays needed by known component IDs in `stride-analyst-context.schema.json` v1; it omits empty component placeholders and never owns the reserved `_stride_profile` routing value | The controller drops a producer-authored `_stride_profile`, rejects unknown component IDs or an overlay above the byte cap, derives the manifest profile from resolved run configuration, then runs `validate_fragment.py security-controls` and JSON Schema validation; bundle construction normalizes and containment-checks component-local focus/exclude inputs before dispatch; non-zero is blocking | Phase-8 checkpoint; failure blocks without implicit redispatch; then bundle and manifest construction |
| Phase 9 STRIDE | One receipted component context plan binding a fresh `stride-evidence-bundle` v1, hashed taxonomy slice, lens IDs, analysis policy, and only the related roots cited by that component's admitted source slices | `stride_analyzer` writes `stride.schema.yaml`; no other writer may write the same component file | Manifest and bundle validation, component-plan and repository-projection schema and source-hash validation, active effective-plan binding, immediate receipt re-hash, merge-owned mechanical normalization, per-file `validate_intermediate.py stride`, and `stride_dispatch_waves.py verify`; malformed optional boundary links are dropped before schema validation and remaining invalid output is fatal | Persisted two-attempt component budget; then `context-v2-post-stride` |
| Phase 9 merge | Valid STRIDE outputs and bounded `merge-review-context` v1 projected from `merge-candidates` v1 | `merge_threats.py collect/finalize` owns ordering and T-IDs; `threat_merger` writes `merge-decisions.schema.json` v2 only when candidate groups exist | Candidate-free collect immediately finalizes; context-v2 binds the projection to the full source hash, requires at least one decision per admitted group, validates disjoint partial-cluster subsets, and re-hashes decisions before finalize | No checkpoint; one merger dispatch for at most 64 groups within the 262,144-byte projection cap; then passive posture emitters |
| Phase 10/10a evidence | `threats-merged.schema.yaml` v1 and repository evidence | Passive posture scripts own their existing sidecars; `evidence_verifier` writes `evidence-verification.schema.json` v1 and annotates the admitted merged-threat artifact in place only when the sampling cap and threat set select work | The mutated merged artifact is structurally revalidated and every valid sidechannel flag must match its merged-threat annotation; an invalid summary supplies no semantic signal but retains non-fatal enrichment semantics; the guard neutralizes degenerate verdicts in the canonical merged artifact before rendering | No model retry for a deterministic emitter; existing evidence-verifier budget; then deterministic triage |
| Phase 10b triage | `threats-merged.schema.yaml` v1 and optional evidence verdicts | `triage_validate_ratings.py` and `triage_compute_ranking.py --force --bootstrap-yaml` write `triage-flags.schema.yaml` v2 | Rating validation is blocking; a ranking failure selects the focused triage fallback, while every path revalidates both the mutated merged artifact and triage flags before synthesis | No specialist on deterministic success; then optional post-STRIDE synthesis |
| Phase 10b synthesis | Receipted merged threats and triage flags | `post_stride_synthesizer` writes only the requested version-1 mitigation-overrides or tier-root-causes fragment | `validate_fragment.py`; each accepted file is receipted and re-hashed before YAML consumption | Failure blocks without implicit redispatch; then `context-v2-finalize` |
| YAML handoff | Validated Phase-3 through Phase-10b sidecars | `build_threat_model_yaml.py` writes canonical `threat-model.yaml`; the shared deterministic auto-emitter pass then backfills scanner remediation and hydrates mitigation details | Initial `validate_intermediate.py threat_model_output`, mitigation-quality validation after enrichment, and build completeness are blocking | `phase=10b status=completed need_render=true runtime_generation=context-v2`; then Stage 2 |

`context-v2-prepare-stride` validates the Phase-8 outputs, builds and validates
the v2 manifest and bundles, and returns one bounded job per selected component.
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
- Artifact paths resolve under `dispatch_values.output_dir`. Absolute paths,
  traversal, backslashes, and symlink escapes fail before dispatch.
- `artifact_receipts` are versioned separately from human-readable `receipts`.
  A structured receipt records the relative path, schema identity, SHA-256,
  record count, and successful validation status from the exact validated
  bytes.
- Receipt creation validates and hashes one exact byte snapshot. Immediately
  before Agent dispatch, the thin runtime calls `verify-receipts` once for the
  complete action, STRIDE taxonomy slices, and the effective-plan receipt; a
  missing validator, unreadable artifact, or byte change fails closed.
- Before returning a semantic dispatch, the controller removes prior bytes for
  every output not also used as an in-place repair input. Fresh context-v2 entry
  also removes optional evidence and synthesis outputs that may have no producer
  in the new run, so retained runtime files cannot satisfy a later gate.
- Full/rebuild cleanup matches the exact filename globs in the legacy runtime;
  prefix lookalikes and symlink targets must not be deleted.
- A context-v2 terminal abort has no continuation action. A later `--full`
  starts Stage 1 again; retained runtime artifacts are diagnostic evidence, not
  a merge-only recovery checkpoint.
- Rebuild archives the live changelog audit before deletion and fails closed if
  archiving fails.
- All new event lines use `event_log.py`.

## Runtime generation

A run is prepared as exactly one producer generation, `legacy` or `context-v2`,
and `resolve_config.py` persists it as `runtime_generation` in
`.skill-config.json` together with the artifact schema versions a context-v2
successor action is reconstructed from. Only `APPSEC_CONTEXT_V2=1` selects
context-v2, and only for full and rebuild invocations eligible for the compact
top-level runtime. Deadline, cost-limited, live-phase, dry-run, resume, and
explicit compact-runtime opt-out paths persist `legacy`; repository content
never reaches the decision. The runtime router rejects any state that combines
`context-v2` with an ineligible top-level runtime.

The controller reads the generation from that persisted state, never from the
current environment. A context-v2 action refuses a run prepared as legacy, and a
legacy Stage-1 gate refuses a run prepared as context-v2, so one invocation
never gets two producers for the same artifact. Clearing `APPSEC_CONTEXT_V2`
mid-run does not switch producers: the run continues on its persisted generation
and records `RUNTIME_GENERATION_ENV_IGNORED`. A context-v2 successor also
requires the persisted artifact-version map to match the current producer
generation; a mismatch requires a new run. Rollback selects the prior runtime
for a new invocation.

## Rollout

The thin path is the default for full/rebuild and rerender;
`APPSEC_THIN_ORCHESTRATOR=0` is the permanent escape hatch back to
`SKILL-impl.md`. Incremental, resume, dry-run, deadline/cost, and live-phase
paths remain on `SKILL-impl.md` regardless. The full/rebuild thin path became
the default after the juice-shop standard
parity A/B held (2026-07-04): Critical severity identical at base (11=11) and
effective (21=21), remaining deltas attributable to STRIDE-analyzer run
variance rather than the orchestrator runtime.

The context-v2 role registry, structured dispatch jobs, and artifact receipts
remain opt-in migration contracts. They select the focused-agent runtime only
for a new full/rebuild invocation with `APPSEC_CONTEXT_V2=1`; parity and rollout
gates still prevent default selection.

Legacy mode also uses bounded post-Stage-1 reads: normal Stage 2, conditional
recovery, Stage 3, optional Stage 4, completion, and error handling are loaded
at their own boundaries rather than as one tail. The normal thin path instead
uses compact dedicated Stage-1a/1b/1c/1d/2 runtimes and never reads those legacy
bodies. Both runtimes omit Stage 1d when abuse-case verification is disabled.
