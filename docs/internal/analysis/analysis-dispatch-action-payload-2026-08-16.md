# How big is a dispatch action, and is item C worth doing

`session-handoff-2026-08-16.md` leaves item C open — "do not send large payloads
through the model" — and records that the one number the decision needs was
never obtained: "Never verified: the byte size of the returned payload. Every
attempt to reproduce the call failed on the non-idempotency itself." With A and
B landed the call reproduces, so it was measured.

## Method

Measured against the completed 2026-08-16 juice-shop run's own artifacts, on a
copy, never the original.

1. `cp -a docs/security <scratch>/out`, and repoint `output_dir` in the copy's
   `.skill-config.json` at the copy.
2. Remove what the completed run had already produced, so the boundary has work
   to issue: `.stride-<component>.json` for the seven components, `.progress/`,
   `.dispatch-waves.json`, `.stride-attempts/`.
3. Remove the routing ledger and its projections — `.context-routing-plan.json`,
   its receipt, `.dispatch-context/` — so the replay guard does not reject a
   reconstruction whose content differs from the recorded action.
4. `orchestration_controller.py context-v2-prepare-stride --output-dir <copy>`,
   and measure stdout.

`dispatch_jobs` rebuild from the untouched `.stride-dispatch-manifest.json`, so
they are the production values. `context_plan` carries a fresh revision and
differs from the original by a few bytes at 335 total.

Two attempts failed first and both were informative. Clearing state without
clearing the ledger hit `context-v2 dispatch replay rejected: … already issued
with different content`, which is fix B holding. An earlier attempt wrote a
`RUN_ABORTED` line into the copy's log and then refused to continue against it,
which is why every measurement starts from a fresh copy.

## Result

Wave 1, five components, `action=dispatch_parallel`:

| Field | Bytes | Share |
|---|---|---|
| `dispatch_jobs` | 17,813 | 50% |
| `artifact_receipts` | 12,717 | 36% |
| `dispatch_values` | 2,733 | 8% |
| `context_plan` | 335 | 1% |
| everything else | ~230 | — |
| **total, as printed** | **35,796** | **≈8,950 tokens** |

Re-serialized with compact separators the same action is 29,410 bytes, 17.8%
smaller.

## What follows

**C is real and smaller than assumed.** Roughly nine thousand tokens for the
largest action in the run. Even assuming every one of the eleven boundary calls
were comparable, the whole run's action payloads land in the tens of thousands
of tokens.

**C is not what forced the compactions.** In the 20:35–20:53 window the session
added 92,806 output tokens and 15,204,420 cache reads for nineteen seconds of
productive work, at a cost of $7.04. What it did in that window was read
`walkthrough_renderer.py` at three offsets, grep it twice, and run four ad-hoc
`python3 -c` probes against `scripts/`. That file is ~1,900 lines: one full read
is larger than the largest action of the entire run, and it was read three
times. The cause was reading implementation, not returning payloads.

**`context_plan` was already built correctly.** The shared plan reached 341 KB
over the run and none of it goes through the model — only a 335-byte reference,
exactly as `bind_action_to_plan` documents.

**`artifact_receipts` is the part of C worth taking.** Checksums and paths the
model forwards and never reads, at 36% of the payload. Moving them to disk is
what C means by "keep receipts on disk", and it removes a third of the action
with nothing lost. It changes
`docs/internal/contracts/orchestration-actions.md`, so it is a contract change
with a measured benefit rather than an assumed one.

**Compact separators are not worth it.** 17.8%, about 1,600 tokens per dispatch,
paid for with a printed action a human can no longer read during a failure
investigation — which is how this codebase is debugged. `sort_keys=True` would
have to stay regardless: `d87c297d` and `2a0921ac` rest on a repeated boundary
call answering with identical bytes.

## Landed instead

`scripts/plugin_read_gate.py` — a PreToolUse hook denying `Read`/`Grep`/`Glob`
against `$CLAUDE_PLUGIN_ROOT/scripts/**`, lifted by `APPSEC_PLUGIN_DEV=1`. Only
`scripts/` is closed; `agents/`, `skills/`, `data/` and `schemas/` stay open
because the pipeline lazy-loads them at phase boundaries and agents are pointed
at contracts there. No prompt in this repository asks anyone to read a file
under `scripts/` — they invoke them, and invocation is untouched.

A shell command can still read a script. Gating Bash would mean parsing
arbitrary command lines, which fails open more often than it holds, so the block
covers the tool-level vector that carried the cost.

## Not measured

The whole run's action payload total, and the size of the other ten boundary
actions. Wave 1 is the largest fan-out in the run, so it is an upper bound per
action rather than a typical one.
