# Analysis — R10 postfix6 lifecycle failure and systemic reliability

- Date: 2026-08-15
- Run: `postfix6`
- Run ID: `4753cd20-b08c-4dd3-953f-717bbf9824ea`
- Target: OWASP Juice Shop
- Runtime: context-v2, quick rebuild, abuse verification enabled, retained runtime files
- Outcome: operator-interrupted after the first lifecycle defect was confirmed

## Scope

This analysis separates the immediate lifecycle defect from other run signals
and identifies why successive live checkpoints continue to expose failures
after broad repository gates pass. It does not accept postfix6 as R10, change a
standing control-plane decision, or authorize another live scan.

Artifact paths below are relative to the postfix6 output directory.

## Observed sequence

| UTC | Local time | Event | Interpretation |
|---|---|---|---|
| `04:43:42Z` | `06:43:42 CEST` | Recon `AGENT_SPAWN` and `AGENT_RUNNING` | One concrete call opened under `toolu_01TkvNUF1iKrgk6L5basHv3Y` |
| `04:47:02Z` | `06:47:02 CEST` | `BUDGET_WARN`, 27/36 turns | Current-call warning; no critical or maximum marker |
| `04:47:28Z` | `06:47:28 CEST` | Recon `SCAN_END` | Semantic producer reported valid output |
| `04:47:36Z` | `06:47:36 CEST` | Hook `AGENT_FAILED`, `subagent_stop:unknown` | Incorrect lifecycle classification |
| `04:48:50Z` | `06:48:50 CEST` | Architecture `AGENT_SPAWN` | Controller had accepted the recon artifacts and advanced |
| `04:51:15Z` | `06:51:15 CEST` | Architecture `AGENT_FAILED`, `outer_session_terminal` | Expected result of the operator interrupt |

The recon identity stayed consistent across spawn, running, budget, and
terminal records:

```text
action_id=stage1c:b078fb4269a6b5c5
agent_call_id=toolu_01TkvNUF1iKrgk6L5basHv3Y
job_id=phase2-recon
agent_type=appsec-advisor:appsec-recon-scanner
```

The call had no claim, attempt, or component identity because it was not a
STRIDE or abuse-verifier job.

## Immediate root cause

Claude Code supplies two transcript paths on `SubagentStop`:

- `transcript_path` is the parent session transcript;
- `agent_transcript_path` is the stopped subagent's transcript.

The distinction is explicit in the
[Claude Code hooks reference](https://code.claude.com/docs/en/hooks#subagentstop).

`scripts/agent_logger.py::handle_stop` read `transcript_path` for stop reason,
usage, and distinct tool-use count regardless of event type. On postfix6 it
therefore found no usable child terminal record or child usage and fell back to
`stop_reason=unknown`, `in=0`, and `out=0`. The lifecycle consumer accepts only
`end_turn` and `stop_sequence` as clean. It passed the fallback to
`agent_lifecycle.fail_call` as `subagent_stop:unknown`, persisted the call as
failed, and emitted the false `AGENT_FAILED` event.

The producer-to-consumer chain was:

```text
Claude Code SubagentStop payload
  -> agent_logger.handle_stop
  -> wrong parent transcript selection
  -> stop_reason=unknown and no child usage
  -> agent_lifecycle.fail_call
  -> persisted failed state and AGENT_FAILED
  -> render_progress displays a failed recon agent
```

This was not a failed recon dispatch. `.agent-run.log` records `SCAN_END`, both
recon artifacts existed, `.stage-stats.jsonl` recorded one dispatch with 31
tool uses and 105,755 tokens, routing advanced to revision 2, and the controller
started architecture. The controller's artifact gate and the hook lifecycle
disagreed.

The current narrow correction selects `agent_transcript_path` for
`SubagentStop` and retains `transcript_path` for the outer `Stop` event. It does
not change lifecycle states, budget thresholds, call identity, or retry rules.

## Relationship to the active implementation plan

The governing migration and acceptance scope is
[`implplan-threat-analysis-context-and-turn-reduction-2026-08-05.md`](implplan-threat-analysis-context-and-turn-reduction-2026-08-05.md),
specifically these sections:

- **Active completion scope** limits current implementation acceptance to one
  complete quick rebuild R10 followed by the fixed three-baseline and
  three-context-v2 thorough cohort.
- **Postfix5 lifecycle, budget, and depth telemetry correction** defines the
  concrete call-scoped implementation exercised by postfix6.
- **Remaining verification** requires one correctly invoked R10 to prove the
  full lifecycle, concurrency, claim, post-STRIDE, rendering, and cleanup path.
- **Completion criteria** keep the controlled cohort, 700-turn median, and 20%
  reconstructed-cost reduction open after a successful R10.

The postfix5 implementation in force before postfix6 was:

| Implemented plan contract | Current implementation owner | Postfix6 result |
|---|---|---|
| Host `tool_use_id` is the immutable call identity | `scripts/agent_logger.py`, `scripts/agent_lifecycle.py` | Passed: recon used one call ID across spawn, running, budget, and terminal records |
| `agent_id` binds SubagentStart and SubagentStop to that call | `scripts/agent_logger.py`, lifecycle schema v1 | Passed: the recon runtime agent ID resolved to the correct call |
| SubagentStop reconciles usage, terminalizes the call, and retires its budget | `scripts/agent_logger.py`, `scripts/budget_watchdog.py` | Partially failed: the correct call was closed, but usage and outcome came from the parent transcript |
| Parent tools cannot charge a completed child | call-scoped budget schema v2 | Passed: recon disappeared from budget state before architecture started |
| A delayed PostToolUse cannot reopen or create another start | lifecycle terminal idempotency | Passed: no second `AGENT_SPAWN` or `AGENT_INVOKE` was emitted |
| The renderer emits one start and one terminal state per call | `scripts/render_progress.py` | Failed at presentation scope: `SCAN_END` was rendered as an additional apparent terminal completion |
| Terminal cleanup closes remaining calls and removes live markers | outer Stop hook and wrapper cleanup | Passed for live markers after the operator interrupt |

The immediate code correction completes the intended postfix5
producer-to-contract chain rather than introducing a new lifecycle design:

```text
SubagentStop.agent_transcript_path
  -> child stop reason, usage, and distinct tool uses
  -> existing call-scoped lifecycle transition
  -> existing call-scoped budget retirement
  -> delayed PostToolUse remains idempotent
```

The regression in `tests/test_agent_lifecycle.py` deliberately gives the parent
and child transcripts conflicting stop reasons and usage. It proves that the
current implementation selects the child values, persists `state=done`, closes
the call-specific budget, and emits no `AGENT_FAILED`.

Postfix6 does not satisfy the plan's R10 gate. The lifecycle outcome was wrong
before the correction, the operator interrupted architecture, and no STRIDE,
post-STRIDE, abuse, rendering, final-gate, or deliverable acceptance evidence
exists. The fixed thorough cohort, finding adjudication, 700-turn gate, and 20%
cost gate remain open exactly as stated in the active plan.

## Separate postfix6 findings

### Duplicate terminal presentation

`scripts/render_progress.py` renders semantic `SCAN_END` as
`recon-scanner done`. It separately renders hook `AGENT_DONE` or
`AGENT_FAILED` as a terminal lifecycle line. The transcript correction would
turn the second line into a successful `AGENT_DONE`, but the operator would
still see two apparent completions.

`SCAN_END` is a semantic publication milestone, not the lifecycle terminal
authority. The renderer should label it as output readiness or another
nonterminal milestone. Only call-scoped `AGENT_DONE` or `AGENT_FAILED` should
render a terminal agent outcome. A timeline regression must cover
`AGENT_SPAWN -> SCAN_END -> SubagentStop -> delayed PostToolUse` and assert one
visible start and one visible terminal outcome.

### Raw recon size

The recon producer wrote 673 physical Markdown lines against its 200-line
optimization target. This is a real cost and prompt-compliance deviation, but
it did not cause the lifecycle failure and is not currently a blocking
contract.

The deterministic consumer boundary remained bounded:

| Measure | Value |
|---|---:|
| Raw source lines | 673 |
| Retained semantic lines | 200 |
| Omitted body lines | 281 |
| Serialized projection lines | 525 |
| Projection bytes | 18,699 |
| Estimated projection tokens | 4,675 |
| Routing validation | `action_validated` |

The projection protected architecture from the complete recon artifact. It did
not recover the model time and tokens already spent authoring 673 lines.

### Usage undercount

The abnormal wrapper summary reported zero tokens because the completed recon
`SubagentStop` used the wrong transcript and the interrupted architecture call
did not return a normal child usage record. Selecting the child transcript
restores exact usage for completed subagents. A hard-interrupted active child
must remain disclosed as unavailable rather than estimated from unrelated
session totals.

### Operator interrupt and terminal convergence

The architecture failure with `reason=outer_session_terminal` and wrapper exit
130 were correct consequences of the operator interrupt. Live-call cleanup
removed `.active-tool-calls`.

The wrapper deliberately skipped post-run parsing, leaving an empty
`.headless-result.json`, a retained lock, and no authoritative `RUN_ABORTED`
record. `appsec_status.py --live` continued to show an unknown phase until the
heartbeat aged out. This is not the cause of the recon failure, but it leaves
operator-interrupted runs without one immediately consistent terminal outcome.

## Systemic causes

### 1. External host contracts are consumed as untyped dictionaries

Hook payload fields are accessed independently at each consumer. There is no
event-specific adapter that validates required fields, selects the correct
transcript owner, and exposes one normalized internal object. Synthetic tests
used `stop_reason` and `transcript_path` shapes that the real
`SubagentStop` boundary does not use for child completion.

This class of defect survives broad unit coverage because the tests repeat the
implementation's mistaken assumption.

### 2. Event ownership is correct in prose but blurred in presentation

Semantic agents own `SCAN_END`, hook lifecycle owns `AGENT_DONE` and
`AGENT_FAILED`, and the controller owns artifact acceptance. The live renderer
collapses the semantic and lifecycle events into the same word, `done`.

The result can show success and failure for one real call even when each
producer emitted exactly one event in its own scope.

### 3. Prompt-only invariants remain on expensive producer paths

The recon line target is advisory. The downstream projector enforces context
admission, but no deterministic publication boundary prevents the producer
from spending turns and tokens on an oversized artifact. Similar historical
failures used prompt text to constrain field names, validation order, parallel
dispatch, component ownership, and depth labels before deterministic guards
were added.

Prompt instructions are necessary for semantic work but are not a reliable
owner for mechanical limits or vocabulary.

### 4. Contracts are repeated across too many surfaces

One lifecycle or routing fact can appear in an agent prompt, hook payload,
plain-text event, persisted state, JSON Schema, controller action, waiter,
status reader, renderer, and test fixture. Repeated vocabularies have produced
alias drift, stale IDs, wrong schemas, wrong component paths, wrong depth
labels, replayed actions, and incorrect terminal state.

The number of tests does not offset duplicated ownership. A locally correct
producer and a locally correct consumer can still disagree at their shared
boundary.

### 5. Tests stop at module boundaries instead of replaying time

The repository has strong unit and schema coverage. The missing layer is a
deterministic replay of a real run sequence, including delayed, missing, and
reordered hooks. The postfix6 failure required all of these facts at once:

- one parent session;
- one Agent tool-use ID;
- one runtime agent ID;
- separate parent and child transcripts;
- a semantic completion before `SubagentStop`;
- a delayed parent `PostToolUse`;
- budget closure before later parent tools.

No existing test represented that complete sequence with a real host payload
shape.

### 6. Expensive full scans are the first host-integration test

Repository gates validate code and deterministic fixtures. They cannot prove
the installed Claude Code version's hook payload, background scheduling,
provider behavior, or signal propagation. The current process discovers that
gap only after a full Juice Shop scan has paid for recon and later roles.

## Reliability programme

### P0 — required before another R10

All five items are implemented; see "Verification state at handoff" below.

1. **Done.** The child-transcript correction landed with a red-before /
   green-after lifecycle regression.
2. **Done.** `render_progress.py` renders `SCAN_END` as
   `<owner> output ready`; only `AGENT_DONE` and `AGENT_FAILED` render a
   terminal outcome. `test_render_progress.py` replays the postfix6 order
   (`AGENT_SPAWN -> SCAN_END -> SubagentStop -> delayed PostToolUse`) and
   asserts one visible start and one visible terminal outcome.
3. **Done.** `tests/fixtures/hook-payloads/claude-code-2.1.233.json` holds
   sanitized `PreToolUse`, `SubagentStart`, `SubagentStop`, and `PostToolUse`
   payloads whose keys and types come from the pinned host version's hook input
   schema. `tests/test_hook_payload_contract.py` drives the full sequence and
   pins parent/child transcript ownership, usage attribution, and delayed
   `PostToolUse` idempotency.
4. **Done.** `scripts/telemetry_consistency.py` cross-checks accepted output,
   lifecycle terminal state, child usage attribution, budget retirement, and
   stage-stats tokens for the calls of the most recent dispatch action. Every
   context-v2 boundary that runs after a producer returned calls it. It emits
   `TELEMETRY_MISMATCH` and continues; `APPSEC_TELEMETRY_STRICT=1` aborts the
   boundary instead. Export it in the environment that launches the acceptance
   run, so the skill's Bash — and therefore the controller — sees it. The
   stage-stats rule is deliberately ordering-free: a record that is not written
   yet is not a finding, a record that reports zero tokens for a charged call
   is. This keeps the check off the prompt, which is the failure mode named in
   systemic cause 3.
5. **Done.** Focused suites, `make lint`, `make test`, and `make check` were
   re-run.

### P1 — host compatibility and replay

1. Introduce one event-specific hook adapter. It validates the external payload
   and produces a bounded internal record before lifecycle, usage, or status
   code can read fields.
2. Keep anonymized fixtures for every supported Claude Code payload version and
   record the tested host version with acceptance evidence.
3. Build one deterministic lifecycle replay harness covering sequential roles,
   parallel roles, provider wait, retry, interrupt, missing PostToolUse,
   repeated hooks, current and stale claims, and terminal cleanup.
4. Add a low-cost live canary before a paid acceptance scan. It should prove one
   foreground child completion, one bounded parallel pair, nonzero completed
   child usage, call-specific budget retirement, and live-marker cleanup.
5. Generate the acceptance invocation from one immutable cohort manifest and
   verify its resolved config hash before the first model dispatch. This removes
   repeated path, depth, rebuild, and runtime-preservation mistakes from the
   paid test loop.

### P2 — reduce semantic surface area

1. Split recon into deterministic inventory and bounded semantic synthesis.
   Mechanical tables, counts, paths, timestamps, and truncation belong to a
   deterministic producer. The model should author only the bounded security
   interpretation that cannot be derived mechanically.
2. Replace repeated prompt-authored envelopes and aliases with deterministic
   builders that accept a smaller semantic payload and write the contracted
   artifact.
3. Make every exit class converge on one small terminal result: success,
   controller abort, provider failure, or operator interrupt. Lock, checkpoint,
   headless result, run issues, lifecycle, and live-marker cleanup should agree
   immediately.
4. Track live defects by failed boundary rather than by postfix number. A fix
   closes only when one replay covers producer, contract, consumer, status, and
   cleanup for that boundary.

## Decision boundaries

The child-transcript correction and nonterminal `SCAN_END` presentation enforce
the existing lifecycle contract and do not change a standing decision.

Making telemetry mismatch block normal production would change the current
rule that lifecycle and hook state are observational. A strict acceptance-only
gate can be added without changing production behavior. A general blocking
gate requires operator approval and a corresponding decision-register entry.

Turning the raw recon target into a blocking limit or replacing the recon
producer changes producer ownership and failure behavior. It requires an
explicit contract migration across the producer, projection, controller,
context routing, tests, and cost acceptance evidence.

## Verification state at handoff

- Both lifecycle regressions failed before the code change by selecting the
  parent transcript, persisting `state=failed` and the parent's usage — the
  exact postfix6 signature — and pass after selecting `agent_transcript_path`.
- The focused lifecycle, hook-payload, budget, progress, stage-stat,
  agent-definition, and prompt-budget suites pass.
- `make lint`, `make test`, and `make check` pass on the current tree.
- No replacement scan was started. P1 and P2 are untouched.

The patch touches:

```text
CHANGELOG.md
agents/shared/logging-standard.md
docs/internal/contracts/orchestration-actions.md
docs/internal/decisions.md
docs/internal/analysis/analysis-r10-postfix6-lifecycle-and-systemic-reliability-2026-08-15.md
scripts/agent_logger.py
scripts/orchestration_controller.py
scripts/render_progress.py
scripts/telemetry_consistency.py
tests/fixtures/hook-payloads/claude-code-2.1.233.json
tests/test_agent_lifecycle.py
tests/test_hook_payload_contract.py
tests/test_render_progress.py
tests/test_telemetry_consistency.py
```
