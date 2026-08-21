# STRIDE waiter exit 75 renders as a console error

Status: analysis and options. No code change made. Options O1 and O2 need
operator approval before implementation; O2 additionally changes a documented
orchestration contract.

## Symptom

During a running analysis the console shows a red Bash entry followed by
orchestrator narration along the lines of `Exit 75 — repeating waiter
unchanged.` The run is healthy and continues.

## What actually happens

`scripts/wait_stride_progress.py` joins the STRIDE analyzers of the current
dispatch action. It polls in slices that stay below the host's Bash execution
ceiling instead of blocking for the full wave:

- `--interval 20 --rounds 24` — one slice covers ~8 minutes
  (`skills/create-threat-model/SKILL-thin-stage1-v2.md:52-56`).
- The persisted wave deadline is 15 minutes and is *not* reset per slice.
- A slice that ends with the wave still pending returns
  `PENDING_EXIT_CODE = 75` (`scripts/wait_stride_progress.py:18,105`).

The exit code is a four-way branch signal for the orchestrator, documented in
`skills/create-threat-model/SKILL-thin-stage1-v2.md:58` and
`docs/internal/contracts/orchestration-actions.md:369-371`:

| Exit | Meaning | Orchestrator action |
|---|---|---|
| `0` | wave complete | call `context-v2-post-stride` |
| `1` | wave deadline reached | call `context-v2-post-stride` (retry classification) |
| `2` | invalid wave state | abort |
| `75` | another slice required | repeat the identical waiter call |

A 15-minute wave therefore produces at least one `75` by design. It is not a
failure.

## Why it looks like an error

Two independent layers:

1. **Host rendering.** `75` is non-zero, so the Claude Code TUI marks the Bash
   call as failed and renders it red. The TUI has no knowledge of the plugin's
   exit-code vocabulary. Exits `1` and `2` render identically.
2. **Orchestrator narration.** The wording `Exit 75 — repeating waiter
   unchanged` exists nowhere in the repository. The model paraphrases the
   contract sentence at `SKILL-thin-stage1-v2.md:58` into user-facing prose.
   Same class of console noise as the precedent recorded for commit `0cd22b60`.

## What it is not

Measured on the live `insecure-large-spring-app` run
(`docs/security/.agent-run.log`, ~48 min elapsed, Stage 1c in progress):
zero `TOOL_ERROR` and zero `BASH_WARN` entries. The pending exit does not reach
the run-issue aggregation, so it does not surface in the report's Run Issues
section. Evidence is one run, not a guard test.

The waiter's own stderr line on the pending path starts with the literal token
`BASH_WARN` (`scripts/wait_stride_progress.py:100-103`). That token is *not*
what `agent_logger.py` keys on — its Bash detection matches anchored CLI
diagnostics and a fixed keyword list (`scripts/agent_logger.py:3155-3210`),
none of which the message contains. The prefix is misleading to a human reading
the red box and buys nothing.

## Options

### O0 — leave as is

Cost: one red console entry per waiter slice on slow waves, plus one narration
line. Benefit: zero risk. The stderr text already explains the condition.

### O1 — make the pending path read as progress (recommended)

Two prose changes, no contract change, no behavior change:

1. `scripts/wait_stride_progress.py:100-103` — drop the `BASH_WARN` prefix and
   state the condition plainly, e.g. `STRIDE wave still running after <elapsed>
   — expected. Exit 75 means: repeat the identical waiter call.`
2. `skills/create-threat-model/SKILL-thin-stage1-v2.md:58` — pin the narration
   so the model reports the slice as progress rather than as an exit code.

Change surface: the waiter script, one skill sentence, and
`tests/test_wait_stride_progress.py:193-205` if it asserts the message text.
After any skill prose edit run `tests/test_context_prompt_budgets.py` — that
file is a budgeted prompt.

Residual: the Bash entry stays red. Only the host can change that.

### O2 — exit 0 for non-terminal outcomes, status on stdout

This is the variant that removes the red rendering.

Design:

- The waiter always prints a machine-readable final line,
  `STRIDE_WAIT_STATUS=complete|pending|expired`.
- Exit `0` for all three. Exit `2` stays for invalid wave state and for a
  missing progress script, so the fail-closed path is unchanged.
- `SKILL-thin-stage1-v2.md` branches on the status token instead of the exit
  code.
- `docs/internal/contracts/orchestration-actions.md:369-371` is rewritten: the
  waiter slice no longer carries its outcome in the exit status.

Change surface: `scripts/wait_stride_progress.py`,
`skills/create-threat-model/SKILL-thin-stage1-v2.md`,
`docs/internal/contracts/orchestration-actions.md`,
`tests/test_wait_stride_progress.py` (six exit-code assertions),
`tests/test_stride_serial_dispatch_detection.py:205`,
`tests/test_context_prompt_budgets.py:222`. A decision entry in
`docs/internal/decisions.md` is warranted because the current tri-state is a
deliberate choice, not an accident.

Risk — this is the reason O2 is not the recommendation:

- An exit code is a hard branch. A status token is text the model must read and
  classify. The failure mode is not symmetric: mistaking `pending` for
  `complete` calls `context-v2-post-stride` while analyzers are still running.
- The contract states that a persisted active claim prevents a premature
  boundary call from re-claiming a running component
  (`scripts/stride_dispatch_waves.py:590-630`). Whether
  `context-v2-post-stride` itself *fails closed* on an incomplete wave is not
  established here and is the decisive question for O2. If it does, O2 is
  cheap; if it does not, O2 trades a cosmetic annoyance for a run-corruption
  path.
- `1` (deadline) must move to `0` as well, otherwise the red entry merely
  becomes rarer instead of disappearing — which is what makes O2 a contract
  change rather than a tweak.

### O2a — larger slices

Raising `--rounds` so one slice approaches the 600-second host ceiling does not
help: the wave deadline is 15 minutes, so a slow wave still needs a second
slice. Rejected.

## Recommendation

O1. The condition is benign, correctly designed, and already bounded; the only
real defect is that its user-facing wording reads like a failure.

Take O2 only after establishing that `context-v2-post-stride` rejects an
incomplete wave deterministically. Without that guard the exit code is the
safety mechanism, and removing it to silence a console color is a bad trade.
