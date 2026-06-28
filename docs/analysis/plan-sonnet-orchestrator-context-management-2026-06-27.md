# Plan: Sonnet Orchestrator Context Management

**Date:** 2026-06-27
**Status:** Implemented behind an opt-in full/rebuild rollout gate; runtime parity benchmarks pending
**Scope:** `create-threat-model` main-session orchestration under Sonnet
**Supersedes:** the implementation recommendation in
`docs/analysis/analysis-orchestrator-context-budget-2026-06-23.md` where it conflicts
with the verified findings below

## Implementation state

Implemented in this change:

- `scripts/context_window_report.py` measures resident context and authoritative
  `compact_boundary` events while separating main and subagent sessions;
- `data/context-budgets.yaml` and regression tests cap every live prompt surface;
- `scripts/orchestration_controller.py` owns full/rebuild config, cleanup, lock,
  prepass, requirements, and filesystem-rehydrated next-action decisions;
- `schemas/orchestration-action.schema.json` rejects arbitrary action/command fields;
- `skills/create-threat-model/SKILL-full-runtime.md` keeps Agent/Task calls at
  Level 0 while loading only the Stage-1 slice and the later tail;
- `skills/create-threat-model/SKILL.md` selects that compact runtime for
  ordinary full/rebuild scans when `APPSEC_THIN_ORCHESTRATOR=1`.

The deterministic byte budget is 212,355 bytes for the current legacy initial
slice versus 78,235 bytes for router + compact runtime + Stage-1 slice (63.2%
smaller).
This is a static prompt-size result, not yet a claim of zero runtime compactions.
The latter still requires fresh quick/standard/thorough benchmark runs and
`context_window_report.py` verification.

Incremental, rerender, resume, dry-run, wall-time/cost-limited, and live-phase
invocations deliberately remain on `SKILL-impl.md` until the dedicated parity
matrix in §8.4 passes. This is the rollout gate from §10, not an implicit claim
that those paths are already migrated.

The legacy path also remains the default while the environment opt-in is
unset. Default-on activation is intentionally deferred until the same-commit
quick/standard/thorough A/B runs satisfy §8.2 and §8.3.

### Post-implementation contract audit — 2026-06-28

The follow-up audit corrected these parity/security gaps before rollout:

- cleanup now uses the exact legacy filename globs instead of broader prefixes;
- runtime-directory symlinks are unlinked without following their targets;
- rebuild changelog archiving fails closed before deletion;
- Stage-1 dispatch configuration is resident before the first Agent call;
- route/source-auth, session-context, validator, cleanup, and duration signals
  retain their deterministic audit/user surfaces;
- the action schema requires action-specific fields and allow-lists every
  dispatch key.

Contract ownership is documented in
`docs/internal/contracts/orchestration-actions.md`; rebuild audit behavior is
also recorded in `docs/internal/contracts/audit-artifacts.md`.

Verification result: 740 focused runtime/config/schema/packaging tests passed;
the complete suite passed 8,699 tests with 93 skipped. The one test requiring a
local TCP listener was rerun outside the socket-restricted sandbox and passed.
No live Claude quick/standard/thorough A/B assessment was executed, so
`APPSEC_THIN_ORCHESTRATOR=1` remains opt-in.

## 1. Decision

The context problem is real, but “free old context sooner” is not directly available:
Claude Code does not expose selective eviction of earlier turns from a running agent
session. A loaded prompt or tool result remains resident until whole-session compaction
or session replacement.

The recommended fix is therefore:

1. make the main-session skill a thin dispatch loop;
2. move deterministic preflight, state transitions, cleanup decisions, and gates from
   `SKILL-impl.md` into tested Python entry points;
3. keep all qualitative security judgement in the existing specialized agents;
4. keep Agent/Task calls in the main session because scripts cannot call Claude tools
   and nested agents cannot perform the required Level-0 fan-outs;
5. pass state through validated on-disk artifacts and compact action manifests, never
   through lossy LLM summaries.

Further lazy loading and mode extraction are useful interim reductions, but they do not
release content already loaded into the same session and are insufficient as the final
solution.

## 2. Verification method

### 2.1 Context occupancy

For each non-synthetic assistant turn in a Claude Code JSONL transcript:

```text
resident_context =
    input_tokens
  + cache_read_input_tokens
  + cache_creation_input_tokens
```

This is the same method used by the earlier context-budget analysis. Main-session JSONL
files and `subagents/agent-*.jsonl` were measured separately.

A compaction is counted only when the transcript contains:

- a `system` entry with `subtype: compact_boundary`; and
- its associated `isCompactSummary` continuation.

`SESSION_ABORTED_MIDRUN`, `SESSION_STOP`, or a high cumulative `cache_read` value are
not substitutes for this signal.

### 2.2 Important limitation

The inspected transcripts identify the model as `claude-sonnet-4-6`, but do not record
the model's configured nominal context-window size. The observed compaction points
therefore establish the effective threshold for those runs, not whether the nominal
window was 200k, 300k, or another value.

Implementation and acceptance tests must measure the effective runtime threshold. They
must not hardcode a percentage derived from an assumed model window.

## 3. Verified findings

### 3.1 The main session still compacts after the existing lazy-load fix

Representative post-fix runs:

| Run | Depth | Compaction point(s) | Context after compaction | Location in pipeline |
|---|---:|---:|---:|---|
| `5784e6b7` (2026-06-26) | standard | 161,957 | 62,636 | Level-0 STRIDE fan-out |
| `0f056e49` (2026-06-25) | thorough | 152,324; 166,681 | 54,116; 60,097 | first fan-out; QA/repair tail |
| `9846eb5b` (2026-06-25) | standard | 166,216; 166,302 | 70,733; 61,897 | later stage handoffs |
| `cf030a8e` (2026-06-27) | quick | 168,423 | 58,202 | Stage-2 tail load/handoff |

The existing `LAZY-LOAD BOUNDARY` prevents the Stage-2/3/4 tail from loading before
Stage 1, but it does not remove the already-loaded Stage-1 prefix. It postponed
compaction; it did not reliably eliminate it.

### 3.2 The first skill slice is still large

Current size:

```text
SKILL-impl.md through LAZY-LOAD BOUNDARY:
  2,601 lines
  213,167 bytes
  approximately 50–54k tokens in observed Read results
```

In the fresh `cf030a8e` quick run:

```text
first measured turn:       40,316 tokens
after initial skill reads: 88,108 tokens
before later handoffs:    134–168k tokens
```

The live prefix before the boundary contains:

| Section | Bytes | Assessment |
|---|---:|---|
| Prerequisites and session checks | 35.5k | partly deterministic; much can move to scripts |
| Argument parsing | 13.3k | already owned semantically by `resolve_config.py` |
| Configuration resolution | 14.8k | extraction boilerplate is deterministic |
| Incremental/precheck/fast-path cluster | about 25k | dead weight in full/rebuild runs |
| Configuration summary and operational setup | 40.4k | largest pre-Stage-1 consolidation target |
| Resume | 5.0k | conditional |
| Stage 1 dispatch | 50.6k | required flow mixed with rationale and recovery detail |
| Stage 1c abuse verification | 12.1k | needed only after Stage 1 |

### 3.3 Specialized agents are not the primary compaction source

Representative standard-run peaks:

| Agent/session | Peak resident context | Compactions |
|---|---:|---:|
| Analyst-A | 149,197 | 0 |
| Analyst-B | 155,156 | 0 |
| Renderer `secarch` | 102,032 | 0 |
| Renderer `ms` | 55,998 | 0 |
| STRIDE analyzers | 47–96k | 0 |
| QA reviewer | 78,795 | 0 |

The Phase 3–8 work already runs inside Analyst-A. Creating another
`architecture-author` agent would not fix the measured main-session problem and would
add another contract boundary.

Splitting Analyst-A and Analyst-B definitions may reduce their cost later, because both
currently receive the full `appsec-threat-analyst.md` prompt. It is a secondary
optimization, not the primary context fix.

### 3.4 Current context warnings do not measure occupancy

The current `8 M cache_read` check is useful as a correlation signal for:

- a reused/non-empty session;
- repeated prefix reads;
- likely latency and cost growth.

It is not current context occupancy. `cache_read` is cumulative throughput and grows
with the number of turns even when the resident window is stable or has already been
compacted.

The current prose in `SKILL-impl.md` also overstates the evidence when it describes
multiple `SESSION_ABORTED_MIDRUN` events as a “compaction storm.” In the inspected quick
run, several abort-like log entries coexist with exactly one transcript
`compact_boundary`. Logging attribution must be corrected before it is used for policy.

### 3.5 Nominally larger context is a fallback, not a fix

A model with a larger effective window can avoid or delay compaction, but:

- it still re-reads a large prefix on every turn;
- it can cost more;
- it hides prompt growth instead of removing it;
- window availability varies by model, account, and Claude Code version.

Sonnet remains a valid target if the main-session control plane is made materially
smaller. A larger-window model should remain an explicit fallback for an already-used
interactive session or an unusually large run, not the default recommendation.

## 4. Feasibility constraints

### 4.1 What a deterministic controller can do

A Python controller can safely own:

- argument/config resolution;
- baseline and checkpoint classification;
- mode-specific preflight decisions;
- safe cleanup plans;
- artifact precondition checks;
- schema validation and deterministic gates;
- construction of compact per-stage action manifests;
- transition validation after a dispatched agent returns;
- final completion-state calculation.

This follows the repository rule that deterministic Python owns validation, rendering,
export, and gates.

### 4.2 What it cannot do

A Python controller cannot call Claude Code's:

- `Agent`;
- `TaskCreate`, `TaskUpdate`, or `TaskStop`;
- interactive user-input tools.

Those calls must remain in a small main-session loop.

A single new coordinator subagent also cannot replace the main session: the full/rebuild
path requires Level-0 parallel STRIDE and abuse-case fan-outs, while nested Agent
dispatch is unavailable to Level-1 agents.

### 4.3 Interactive versus headless behavior

The controller must return a decision request rather than read from stdin when user
choice is required. The main skill asks interactively; headless mode applies the
existing deterministic default.

No new prompt may block:

- `claude -p`;
- `APPSEC_CI_MODE=1`;
- `APPSEC_NO_CONFIRM=1`.

`scripts/run-headless.sh` already owns outer path resolution, trust-mode preflight,
restore, and some fast paths. New controller work must not duplicate or contradict
those checks.

The externally injected `context-mode` helper reduced large raw tool returns in the
measured environment, but it is not a repository-owned runtime prerequisite. The
pipeline and its context budget must remain correct when that helper is absent.

### 4.4 State and recovery

The controller must rehydrate solely from existing trusted runtime state:

- `.skill-config.json`;
- `.appsec-checkpoint`;
- `.appsec-cache/baseline.json`;
- schema-valid phase sidecars;
- stage status/repair-plan files.

No transition may depend only on facts remembered by the main LLM session.

Background watchdog/task identifiers are a special case. If a future transition needs
them after compaction or resume, either:

- persist the minimum identifier/PID state in an intentional runtime sidecar; or
- make watchdog cleanup discoverable and idempotent without remembered identifiers.

A new runtime sidecar requires cleanup-whitelist, audit-artifact, diagnostic-bundle,
and test review.

### 4.5 Security boundary

The controller must treat repository-derived text as data:

- accept paths as separate arguments, never shell fragments;
- canonicalize repo/output paths;
- never copy target-repo strings into commands or action types;
- emit fixed action enums;
- keep action manifests free of arbitrary executable strings.

## 5. Target architecture

The main session should execute only this bounded loop:

1. call deterministic `prepare/next-action`;
2. inspect a compact, schema-valid action;
3. ask the user only when the action explicitly requires a decision;
4. dispatch one agent or one parallel agent batch when requested;
5. call deterministic `record-result/next-action`;
6. repeat until `complete` or `abort`.

Suggested action vocabulary:

| Action | Main-session responsibility |
|---|---|
| `abort` | print fixed reason and stop |
| `decision_required` | ask one bounded question; persist answer |
| `dispatch_agent` | invoke one named allow-listed agent |
| `dispatch_parallel` | invoke the complete manifest batch in one turn |
| `start_watchdog` | start the fixed allow-listed watchdog command |
| `stop_watchdog` | stop/discover the matching watchdog safely |
| `run_gate` | invoke one fixed deterministic gate |
| `complete` | render the deterministic completion summary |

The manifest should carry paths and short scalars, not large JSON blobs. Agent-specific
volatile context remains in `.dispatch-context/`, preserving the existing Group
A → B → C prompt-cache contract.

## 6. Options assessed

| Option | Context actually released? | Expected value | Risk | Decision |
|---|---|---|---|---|
| More lazy-load markers in the same session | No | delays peaks | low | interim only |
| Extract full/incremental/resume branches | Avoids dead mode context | small/medium | low | do early |
| Remove runtime historical rationale | Avoids dead prompt context | medium | low if local MUST rules remain | do early |
| Deterministic transition controller | Avoids most orchestration prompt context | high | medium implementation risk, low quality risk with parity gates | recommended |
| New all-in-one coordinator subagent | Fresh context, but cannot nested-dispatch | incomplete | high | reject |
| New architecture-author subagent | Phases already isolated | negligible for main | medium | reject for this goal |
| Split Analyst-A/B definitions | Smaller subagent contexts | cost/latency benefit | medium drift risk | defer |
| Depend on auto-compact | Whole-history lossy summary | unpredictable | high | reject |
| Require a 1M-context model | No reduction | masks limit | cost/policy risk | fallback only |

## 7. Implementation plan

### Phase 0 — Correct measurement and establish a baseline

1. Add a reproducible context-measurement helper or extend existing telemetry to report,
   separately for main and subagent sessions:
   - peak resident context;
   - every `compact_boundary`;
   - stage immediately before each boundary;
   - prompt/tool-result source totals;
   - model ID and Claude Code version;
   - nominal context window only when the runtime actually exposes it.
2. Label cumulative `cache_read` explicitly as throughput, not occupancy.
3. Stop deriving “mid-run abort” counts from generic subagent Stop hooks.
4. Capture baseline runs for quick, standard, and thorough from fresh `/clear` sessions.

No optimization claim is accepted without this baseline.

### Phase 1 — Low-risk prompt de-accretion

1. Move the full incremental/precheck/fast-path cluster into one gated mode file.
2. Move resume-only instructions into one gated mode file.
3. Keep exactly one pointer per mode and extend
   `tests/test_lazy_phase_group_loading.py`.
4. Move historical incident narratives and long rationale out of the live skill into
   this analysis document or internal contracts.
5. Keep safety-critical `MUST` rules local to their execution point.
6. Add prompt-size regression tests for:
   - initial `SKILL-impl` slice;
   - post-boundary tail;
   - `appsec-threat-analyst.md`;
   - each phase group.

This phase must be behavior-preserving. Mode bodies move verbatim before any semantic
cleanup.

### Phase 2 — Deterministic preflight and transition plan

1. Introduce a tested script module for:
   - config extraction;
   - baseline/checkpoint classification;
   - mode decision;
   - cleanup plan;
   - stage preconditions;
   - next-action generation.
2. Define and schema-validate the action-manifest shape.
3. Replace shell snippets in the live skill with fixed script invocations.
4. Keep interactive choice rendering in the thin skill; persist the chosen result.
5. Make every transition idempotent and safe to replay after a compact/resume.
6. Route every new log event through `scripts/event_log.py`; do not introduce
   controller-specific log formatting.

Every new `scripts/` module requires a matching `tests/test_*.py`. Any new command or
read/write path requires updates to:

- `data/required-permissions.yaml`;
- `tests/test_check_permissions.py`.

### Phase 3 — Thin main-session dispatch loop

1. Replace the detailed Stage-1/1c/2/3/4 control prose with the bounded action loop.
2. Preserve all existing parallelism:
   - Analyst-A;
   - Level-0 STRIDE batch;
   - Analyst-B;
   - abuse-case verifier batch;
   - optional parallel renderer;
   - QA/repair;
   - architect review.
3. Preserve explicit runtime model fields on every dispatch.
4. Preserve the STRIDE Group A → B → C prompt order.
5. Ensure agent returns remain receipt-sized; canonical content stays on disk.

### Phase 4 — Optional subagent prompt split

Only after the main session no longer compacts:

1. measure Analyst-A and Analyst-B prompt-source totals;
2. split their definitions only if the measured saving justifies another contract
   boundary;
3. extract shared security/logging/sidecar rules into a drift-guarded common source;
4. keep `appsec-threat-analyst` as a compatibility path until full/incremental/resume
   parity is proven.

This phase targets cost and latency, not the primary main-session failure.

### Phase 5 — Remove obsolete warnings and finalize rollout

1. Recalibrate non-empty-session guidance against measured occupancy and throughput.
2. Keep `/clear` as the cheapest recommendation for a reused interactive session.
3. Recommend a larger-window model only when:
   - the session cannot be cleared; or
   - measured headroom is insufficient for the selected depth/repo.
4. Remove claims that warnings are the “only lever.”
5. Document the final design in `AGENTS.md` without copying the implementation contract.

## 8. Quality and regression gates

### 8.1 Functional invariants

All must remain unchanged:

- final reports are rendered only by deterministic composition;
- T-ID stability and baseline counters;
- required Phase 3–10b sidecars;
- YAML/schema validation;
- severity/CVSS policy;
- Stage-4 advisory-only behavior;
- runtime cleanup and must-preserve audit artifacts;
- full/rebuild/incremental/rerender/resume semantics;
- headless non-interactive behavior;
- explicit per-agent model routing.

### 8.2 Context acceptance criteria

On fresh-session benchmark runs:

1. zero main-session `compact_boundary` entries through completion for quick and
   standard;
2. zero for thorough on the reference repo, or a documented bounded exception on a
   deliberately larger fixture;
3. pre-STRIDE main-session peak at least 20% below the lowest baseline compaction point;
4. no stage ends with less than 15% measured effective headroom;
5. no subagent context regression above 10% without an explicit explanation;
6. initial live skill slice materially smaller than the current 213,167 bytes.

Using the current local evidence, criterion 3 implies a reference target below about
122k tokens. This is a benchmark target, not a hardcoded production threshold.

### 8.3 Quality acceptance criteria

Compare baseline versus candidate runs using deterministic and semantic gates:

- all fragment/intermediate schemas pass;
- `qa_checks.py all` passes where required;
- component inventory and selected STRIDE roles are unchanged;
- no loss of threats attributable to missing phase context;
- every prior finding and known threat retains coverage;
- all required mitigations and cross-references resolve;
- report section presence follows `sections-contract.yaml`;
- incremental rerun preserves unchanged T-IDs;
- resume produces the same canonical outputs as uninterrupted execution.

LLM-authored prose is nondeterministic, so byte-identical report comparison is not a
valid gate. Structural and evidence-semantic invariants are.

### 8.4 Test matrix

Minimum before default-on rollout:

| Scenario | Required proof |
|---|---|
| quick full | clean completion; no compaction |
| standard rebuild | full fan-out; no compaction; QA clean |
| thorough rebuild | extended path and repair budget; sufficient headroom |
| incremental no-op | no unnecessary mode/stage loads |
| incremental dirty component | T-ID carry-forward and selective STRIDE |
| full over existing model | changelog preservation and stale-work wipe |
| rerender | no Stage-1 dispatch |
| interrupted + resume | action replay and watchdog cleanup |
| headless/CI | no interactive wait; same exit codes |
| requirements enabled | Phase 8b and traceability retained |

## 9. Side effects and mitigations

| Side effect | Mitigation |
|---|---|
| One-time prompt-cache invalidation after prompt restructuring | expected rollout cost; measure only after cache stabilizes |
| Cross-file instruction drift | one pointer, one owner, bidirectional drift tests |
| LLM misses an extracted rule | retain local MUST blocks; move rationale, not enforcement |
| Controller becomes another monolith | small pure modules; typed action enums; per-module tests |
| Script stdout re-enters context | compact JSON/one-line receipts; details written to runtime files |
| New runtime state leaks findings | review diagnostic-bundle exclusions and cleanup contracts |
| Headless path diverges | characterize current exit codes and defaults before moving logic |
| Watchdog survives lost task ID | idempotent PID/state discovery and tested cleanup |
| Prompt order harms caching | do not alter STRIDE Group A/B/C ordering |
| Repo text influences control flow | fixed enums, canonical paths, no shell interpolation |
| Larger model hides regression | acceptance based on measured occupancy, not successful completion alone |

## 10. Rollout order

1. telemetry correction and baseline;
2. mode extraction and prompt-size guards;
3. deterministic preflight/transition controller behind an opt-in flag;
4. A/B runs on the same commit and repository;
5. default-on for full/rebuild after parity;
6. incremental/resume default-on only after their dedicated matrix passes;
7. optional Analyst-A/B prompt split;
8. remove the legacy orchestration body only after one release of fallback coverage.

## 11. Expected outcome

The primary expected gain is not merely fewer warnings. It is a smaller, stable
main-session prefix that:

- keeps Sonnet viable as the cost-efficient orchestrator;
- avoids involuntary lossy compaction on normal repositories;
- reduces repeated cache-read cost and cold re-prefills;
- makes resume behavior deterministic;
- moves control-flow correctness from prose into testable code;
- preserves security-analysis depth and report quality.

The plan deliberately does not weaken analysis scope, STRIDE depth, evidence checks,
QA, or rendering contracts to save context.
