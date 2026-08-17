# Task-list rows from the controller's boundary chain

Standalone work item. It changes what the session task list shows during a run
and touches no runtime artifact, no schema, and no report output.

## What is wrong

`Stage 1c - Control & Threat Analysis` is one row for roughly 90 minutes. On the
2026-08-16 juice-shop run it went `in_progress` at 18:57 and stayed there until
about 20:25. Everything the user learns in that window comes from the spinner
line above the list, which the orchestrator writes freely.

The list itself is not the problem. Row granularity is decided once, in
`SKILL-impl.md` → Stage Task List Bootstrap, and has nothing to do with how the
pipeline is staged.

## The lever

Two mechanisms exist, and they are not interchangeable.

Rows are created in exactly one place. `SKILL-impl.md` permits `TaskCreate`
nowhere else, because every later `TaskUpdate` matches by subject and silently
no-ops on drift, which hangs the spinner.

`activeForm` on the row that is `in_progress` may be rewritten mid-stage. Stage
1c already does this at three dispatch seams — `Phase 9 — STRIDE (<N>
components, …)` and `Phases 9–10b — merge → triage`.

Rows carry the sequence. `activeForm` carries movement inside one row. A change
that needs both needs both mechanisms.

## Row set

The controller already publishes the sequence. `orchestration_controller.py`
drives eleven boundaries, and the orchestrator receives the next one as
`next_boundary` and invokes it verbatim:

```
begin · post-recon · post-actors · post-architecture · post-boundary
prepare-stride · post-stride · post-merge · post-evidence · post-triage · finalize
```

Map boundary to row label through a fixed table in the skill. The orchestrator
must not name rows per run — a freely authored label drifts between runs the
same way agent-authored run facts do (see
`analysis-agent-authored-artifact-facts-2026-08-16.md`).

`prepare-stride` and `post-stride` share one row. Stage 1d is not a controller
boundary and keeps its own row. Work with no boundary of its own — the
config/IaC scan, the post-STRIDE synthesis — stays inside the row that contains
it and gets no line.

## Path split

Boundary rows apply to the context-v2 path only, which is the default.

The legacy path keeps the eight-row stage list. There the orchestrator sits
inside a blocking Agent call for the whole of Stage 1c, so eleven rows would
flip together when the call returns — worse than one row, because it reads as
stalled and then lies. This is the same constraint that makes the LIVE_PHASE
Monitor (`SKILL-impl.md` → live-phase variant) serial-only.

Two lists is the cost of not lying on one path.

## What this cannot do

**No durations in a row.** The subject is the matching key. A row that gains
`22m04s` on completion has a different subject than the one that was created.
Durations stay in the completion summary.

**No counts fixed at bootstrap.** The STRIDE component count is decided after
recon, and bootstrap is the only `TaskCreate` site. A count belongs in
`activeForm`.

**No live counter without a seam.** A counter is only honest where the
orchestrator regains control during the work: the STRIDE waiter, which returns
`75` repeatedly and is re-invoked unchanged, and the Stage-1d fan-out, which
returns per candidate. The evidence verifier is one blocking call at a
boundary, so its row shows a static label and no fraction.

## What the user sees

Constructed from the 2026-08-16 juice-shop run's timings. Today, at 19:45:

```
✻ Analyzing controls and threats… (47m 12s · ↓ 88.3k tokens)
✔ Preparing workspace
✔ Stage 1a - Discovery & Architecture Modeling
✔ Stage 1b - Trust Boundary Analysis
◼ Stage 1c - Control & Threat Analysis
◻ Stage 1d - Abuse Case Verification
◻ Stage 2 - Report Rendering
◻ Stage 3 - QA Review
◻ Final summary + cleanup
```

The same moment with boundary rows:

```
✻ STRIDE wave 2/3 - 4/7 components… (12m 51s · ↓ 88.3k tokens)
✔ Preparing workspace
✔ Recon scan
✔ Actor discovery
✔ Architecture modeling
✔ Trust boundaries
◼ STRIDE analysis
◻ Threat merge
◻ Evidence verification
◻ Triage
◻ Abuse case verification
◻ Stage 2 - Report rendering
◻ Stage 3 - QA review
◻ Final summary + cleanup
```

At 20:06, with the verifier's static label:

```
✻ Verifying cited evidence… (1m 34s · ↓ 96.1k tokens)
…
✔ Threat merge
◼ Evidence verification
◻ Triage
```

The blocks that remain, measured on that run: recon 8 min, actors 2 min,
architecture through controls 20 min across three rows, STRIDE 26 min, merge
5 min, evidence 6 min. STRIDE is the only one long enough to need the counter.

## Blocked on prompt budget

The session-side half does not fit. `SKILL-thin-stage1-v2.md` sits at 5716 of
6400 bytes, and `test_thin_runtimes_have_headroom_for_operational_detail` holds
every `thin_stage` surface under 90 percent — 5760 bytes. The rule that ticks a
row costs several hundred; the surface has 44.

There is no other surface. `thin_full_runtime` has 142 bytes to its ceiling and
its aggregate has 30, and the full runtime hands all of Stage 1 to the Stage-1
runtime, so it cannot tick per job even with room.

Making room means cutting rules that exist because runs failed without them —
one dispatch message, no `run_in_background`, no re-dispatch, the abort text.
The guard's own rationale is that budgets must leave room for exact commands
rather than prose. Trading an instruction for a progress label is a decision
about that guard, not a detail of this change.

Everything below describes the code as written. It is not committed.

## What was built

The row labels live in `orchestration_controller.py` as
`STAGE1_TASK_ROWS_CONTEXT_V2` / `_LEGACY`, and the prepare action carries the
right set as `stage1_task_rows`. The session creates one row per entry and
never authors a label.

That placement was forced rather than chosen. Spelling the ten labels out in
`SKILL-full-runtime.md` put the surface 395 bytes over its budget, and
REQ-CTX-002 fixes that by cutting the prompt, not by raising the ceiling.
Moving the list into Python costs the prompt one line and makes the labels
testable, so the constraint produced the better design.

`SKILL-thin-stage1-v2.md` owns the lifecycle: a row goes `in_progress` before
its job dispatches and `completed` on return, and any earlier row still open
completes with it. While joining STRIDE it lifts `<ready>/<expected>` out of the
waiter's `[stride]` line into that row's active form.

`SKILL-impl.md` and `SKILL-rerender-runtime.md` are untouched. Context-v2
requires the compact runtime (`resolve_config.resolve_runtime_generation`), so
`SKILL-impl.md` never bootstraps this row set, and the rerender runtime creates
no Stage-1 rows at all.

Every label is ASCII, pinned by a test. The stage subjects were moved from
em-dash to hyphen-minus because the TUI renderer mis-measures the em-dash's
width on partial redraws and bleeds adjacent labels together
(`CHANGELOG-dev-history.md`); whether that reaches an active form is untested,
and a label that now rewrites often is the wrong place to find out.

## Left out

The Stage-1d counter. `thin_stage1d_runtime` sits inside the pre-Stage-2
aggregate, which had 30 bytes of headroom — not enough for the rule, and not
worth cutting an instruction for. The row still opens and closes; only the
per-candidate fraction is missing.

The handoff banner still reads `▶ Stage 1a/<TOTAL_STAGES> — Discovery &
Architecture Modeling starting` on both paths. `tests/test_context_prompt_budgets.py`
pins that string, so a context-v2 run names a stage that is no longer one of its
rows. Changing it is a separate decision about a pinned user-visible string.

## Verifying

- `TestStage1TaskRows` in `tests/test_orchestration_controller.py` covers the
  two row sets, the ASCII and uniqueness invariants, the schema bound, and that
  both runtimes still read the rows from the action.
- `tests/test_context_prompt_budgets.py` guards every surface this touched.
- A real run is the only place the subject-match invariant is observable. A row
  whose subject drifted still renders — it just never completes.
