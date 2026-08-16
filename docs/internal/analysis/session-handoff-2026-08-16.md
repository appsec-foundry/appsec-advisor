# Session handoff — context-v2 run integrity, 2026-08-16

Three full scans of a juice-shop checkout, three aborts at three different
places. This note is enough to continue without the original session.

Findings F1–F11 are written up in
`analysis-context-v2-stale-bundle-2026-08-16.md`. F12 onward are recorded here.

## Landed on dev

```
f6183f85  fix: stop log_event trusting its caller                    (F1, F4)
dfa5cebe  fix: bind an evidence bundle to the files it cites         (F2, F3)
5c3be57c  fix: take run facts from the controller, not from the agent (F6, F8, F9-part)
30b2b7af  fix: read back every event name the log writer emits       (F10)
c60fb04b  test: pin log consumers against real production shapes
1c317aa0  fix: make the title cleaner satisfy the constraints it owns (F13)
114c304d  fix: compare dispatch order within a wave, not across waves (F8 follow-up)
bee261c3  fix: give the evidence verifier its run paths              (F12)
3cf7d048  fix: name the failure in the abort event, on one line      (F14)
0cd22b60  fix: keep internal boundary names out of the console
d87c297d  fix: rebuild the dispatch manifest to the same bytes       (A)
2a0921ac  fix: let a re-read of a dispatch boundary answer twice     (B)
```

`make lint` is red only on `tests/test_context_routing.py`, at a line no fix
here touched. It was already failing.

## The three runs

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| reached | phase 9, wave 2 gate | phase 10, yaml build | phase 9, dispatch |
| abort | evidence bundle stale | `@` in a threat title | dispatch replay rejected |
| cost | ~$5.04 | ~$6.20 | ~$2.31 |
| status | fixed and re-verified | fixed and re-verified | fixed and re-verified |

## The dispatch-replay abort

`context-v2-prepare-stride` aborted run 3 with:

```
context-v2 dispatch replay rejected: semantic dispatch was already issued for
job(s) stride:angular-spa:attempt-1, … ; invoke the successor boundary instead
```

The orchestrator called the boundary a second time because it could not consume
the first response in one pass (its own report).

The missing property: **an operation that changes state must be able to repeat
its answer. A guard may refuse the effect; it must not refuse the answer.**

Replaying the boundary twice on a copy of run 3's output directory found one
non-deterministic byte range, and it was not the one this note first named:
`generated_at`, a wall-clock stamp. It feeds `manifest_sha256`, which feeds
every `context-plan.json`, which feeds each job's `context_plan_sha256`; and it
feeds `stride_dispatch_waves._fingerprint`. A second call therefore discarded
the wave plan, reset attempt accounting, re-claimed the same `attempt-1` job
ids, and hit the replay guard.

The `build_all` pops were real but not the cause: `build_stride_dispatch_manifest.build()`
rebuilds the manifest from `.stride-analyst-context.json` on every call, so the
popped fields come back. What the pops did break is the builder's own CLI —
running it twice deleted the two projections it had just written.

What landed, in `d87c297d` and `2a0921ac`:

- **A1** — `build_all` keeps `business_context` and `architecture_context`.
  Manifest growth is safe: the schema defines both under
  `additionalProperties: true`, `validate_dispatch_manifest` takes the sources
  from `.stride-analyst-context.json` rather than the manifest, `build_bundle`
  reads only named keys so bundle bytes do not move, and there is no manifest
  byte cap. This also unblocks a per-wave evidence-bundle rebuild, rejected
  earlier for exactly this reason.
- **A2** — the builder carries `generated_at` forward while the manifest is
  otherwise unchanged.
- **B** — `assert_action_not_replayed` became `action_already_issued` and
  returns the recorded action when `action_sha256` matches; a differing
  checksum still aborts. `resolve_action` needed the same rule — it re-raised
  at the next line otherwise — and returns the existing plan rather than
  appending a second copy of its rows. All three call sites gate
  `_prepare_context_v2_dispatch_outputs` on the result.
- **The wave claim** — A2 exposed a second abort behind the first. With the
  wave plan surviving, `claim` correctly reports `in_flight`, which the
  controller rejected as an unsupported status. It now repeats the wave already
  issued without touching attempt accounting.

Verified on a copy of run 3's own artifacts, through the path `_emit` takes:
two calls, identical action, manifest and `.dispatch-context/` byte-identical,
ledger unchanged at one action row and 95 deliveries, and the first dispatch's
attempt artifact intact. Each fix was reverted in place and its tests re-run.

**C — do not send large payloads through the model.** Still open, still its own
decision. Return only what dispatch needs (component, model, turn limit,
context-plan path) and keep receipts on disk. It changes the
`orchestration-actions` contract. With A and B in place a second call is now
harmless, so C only lowers how often one happens.

Never verified: the byte size of the returned payload. Every attempt to
reproduce the call failed on the non-idempotency itself. The claim rests on the
orchestrator's own report and on the plan file being 217 KB with 118 deliveries
at that revision.

## Open findings

| ID | Finding | Status |
|---|---|---|
| F5 | Lifecycle events are agent-authored and unverified | impact removed, ownership question open |
| F7 | Duplicate `AGENT_COMPLETE` per dispatch | open; needs per-dispatch identity, see OR-6 |
| F9 | context-v2 emits `PHASE_START <label>`, consumers expect `[Phase N/M]` | guards fixed, vocabulary open |
| F11 | An agent wrote raw JSON into `.agent-run.log` | did not recur in runs 2–3; model variance |
| F15 | ~10% of log lines violate the event-name contract | open |
| F16 | Component IDs drift between runs; canonicalization never runs | open |

**F15.** 20 of 195 lines in run 2 were unreadable by `event_log.parse_line`,
from three distinct hand-rolled shapes: hyphenated lowercase event names
(`components-written`), lowercase names (`agent_start`), and a single instead of
double field separator (`AGENT_START stride-analyzer-v2 …`). Invisible to every
consumer.

**F16.** Three runs produced three naming schemes for the same repository —
`web-frontend` / `frontend-spa` / `angular-spa`, and `api-server` /
`backend-api` / `express-api`. Only `auth-service` was stable. The catalog
would have normalised two of the three (`angular-spa → frontend-spa`,
`express-api → backend-api`), but nothing calls `canonicalize_component_id`:
the instruction lives in `phase-group-architecture.md` and
`appsec-threat-analyst.md`, and `appsec-architecture-analyst.md` — the agent
context-v2 dispatches — has no mention of it. Component *count* is stable at 7
because `finalize_component_inventory.finalize()` injects the missing two
deterministically, which is also the natural place to canonicalise. Matters for
`--incremental`: T-IDs are keyed on component identity.

Also standing: `RECON_SUMMARY_TARGET_EXCEEDED` fired in all three runs at 477,
530 and 500 lines against a target of 200.

## How to work on this

**Fixtures in this area have lied repeatedly.** Three separate suites were green
while production was broken: an upper-case `COMPONENT_ID=` nobody emits, a
staleness test using a file its bundle did not cite, and a long-event-name test
that checked the name was written but never that it parsed back. Two habits
follow.

- Revert the fix in place and re-run the new test. If it still passes, it proves
  nothing.
- Replay against the aborted runs' own artifacts wherever they exist, not
  against a fixture. That is how F9 surfaced and how an inert F6 fix was caught.

`tests/test_log_shape_contract.py` makes this permanent for log consumers, with
a corpus of real lines in `tests/fixtures/logs/context-v2-run.log`.

## Practical notes

- Never edit plugin files while a scan runs; the runtime reads them live.
- Evidence bundles built before `dfa5cebe` are incompatible with the current
  fingerprint semantics. Use a fresh `--full` or `--rebuild`, never a resume.
- After an authoritative `RUN_ABORTED` the runtime refuses to continue. Deleting
  the marker to resume is not safe: `.dispatch-waves.json` already records the
  attempt as issued while no analyzer ran.
- `SKILL-thin-stage1-v2.md` sits at ~90% of its 6400-byte budget. Anything added
  there has to be paid for by cutting something else, which is part of why rules
  stayed behind in the legacy files.
