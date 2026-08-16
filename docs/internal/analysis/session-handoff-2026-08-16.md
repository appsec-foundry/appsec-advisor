# Session handoff — context-v2 run integrity, 2026-08-16

Three full scans of a juice-shop checkout, three aborts at three different
places. Ten commits landed on `dev`; the working tree is clean. This note is
enough to continue without the original session.

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
```

Full suite green (12902 passed, 28 skipped). `make lint` is red only on
`tests/test_context_routing.py`, which is unmodified and was already failing.

## The three runs

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| reached | phase 9, wave 2 gate | phase 10, yaml build | phase 9, dispatch |
| abort | evidence bundle stale | `@` in a threat title | dispatch replay rejected |
| cost | ~$5.04 | ~$6.20 | ~$2.31 |
| status | fixed and re-verified | fixed and re-verified | **open — see below** |

Runs 1 and 2 passed the point where run 3 died, so the current blocker is
model variance under a large payload, not a deterministic failure. Empirically
about one in three.

## The open blocker

`context-v2-prepare-stride` aborted the run with:

```
context-v2 dispatch replay rejected: semantic dispatch was already issued for
job(s) stride:angular-spa:attempt-1, … ; invoke the successor boundary instead
```

The orchestrator called the boundary a second time because it could not consume
the first response in one pass (its own report). Verified chain:

1. **The boundary destroys its own inputs.** `build_stride_evidence_bundles.build_all`
   does `component.pop("business_context")` and `component.pop("architecture_context")`.
   Confirmed against the live manifest: both fields are absent after the run.
2. **So it can never recompute the same thing.** A second call derives a
   different context plan from the emptied manifest and fails on
   `orchestration_controller.py:2811` — "component context plan hash is stale".
   Reproduced on a clean copy of the output directory with the ledger emptied,
   so this is independent of the replay guard.
3. **The replay guard cannot tell a re-read from a second dispatch.**
   `context_routing.assert_action_not_replayed` derives `action_id` from the
   sorted job ids; any second call with the same job set aborts the run.
4. **The contract offers no alternative.** `SKILL-thin-stage1-v2.md` says never
   to re-invoke a boundary whose dispatch already ran, but not what to do
   instead when the response cannot be consumed.

Not verified: the actual byte size of the returned payload. Every attempt to
reproduce the call fails on exactly the non-idempotency under investigation.
The size claim rests on the orchestrator's own report and on the plan file
being 217 KB with 118 deliveries at that revision.

## Recommended next step

The property that is missing: **an operation that changes state must be able to
repeat its answer. A guard may refuse the effect; it must not refuse the
answer.**

**A — stop consuming the inputs.** Make `build_all` non-destructive: write the
projections without removing the source fields from the manifest. Check first
what the manifest growth affects — it is validated and hashed in several
places. This also unblocks a per-wave evidence-bundle rebuild, which was
rejected earlier in the day for exactly this reason.

**B — let the guard answer twice.** With A in place the boundary is
deterministic, so `assert_action_not_replayed` can recompute, compare
`action_sha256` against the recorded row, and return the action when they
match; a differing checksum stays a real conflict and still aborts. The ledger
already carries both fields — only `action_id` is used today. Without A this
needs a persisted copy of the action instead, because recomputation is
impossible; the plan schema cannot hold it (`$defs.action` is
`additionalProperties: false`), so it would mean a sidecar artifact plus schema,
cleanup-whitelist entry and tests.

**C — do not send large payloads through the model.** Return only what dispatch
needs (component, model, turn limit, context-plan path) and keep receipts on
disk. Lowers the probability rather than removing the cause, and it changes the
`orchestration-actions` contract, so it belongs in its own decision.

Order matters: A makes B cheap.

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

## Implementation prompt for A and B

Paste this into a fresh session.

> Read `docs/internal/analysis/session-handoff-2026-08-16.md` first, then
> implement fixes A and B from it. Goal: a context-v2 boundary that changes
> state must be able to repeat its answer without ending the run.
>
> **A — make dispatch preparation non-destructive.**
> `scripts/build_stride_evidence_bundles.py:1745-1746` removes
> `business_context` and `architecture_context` from each manifest component
> after projecting them. Because of that, a second
> `context-v2-prepare-stride` derives a different context plan and dies on
> `orchestration_controller.py:2811` ("component context plan hash is stale").
> Keep the source fields and make `build_all` produce byte-identical output when
> run twice on the same inputs.
> Before changing it, trace what the manifest growth affects: it is validated
> against `schemas/stride-dispatch-manifest.schema.yaml`, hashed, and read by
> `validate_dispatch_manifest.py` and `orchestration_controller.py`. If keeping
> the fields is not viable, say so with the evidence rather than working around
> it.
> Verify by running `context-v2-prepare-stride` twice on a copy of a completed
> output directory and asserting the second call returns the same action.
>
> **B — let the replay guard answer a re-read.**
> `scripts/context_routing.py:686 assert_action_not_replayed` derives
> `action_id` from the sorted job ids and aborts whenever a row already exists,
> so a re-read and a duplicate dispatch are indistinguishable. With A in place
> the action is recomputable, so: when `action_id` matches an existing row **and**
> the recomputed `action_sha256` equals the recorded one, return that action
> instead of raising; when the checksum differs, keep aborting — that is a real
> conflict.
> The caller must then skip the side effect: all three sites call
> `_prepare_context_v2_dispatch_outputs(output_dir, jobs)` right after the guard
> (`orchestration_controller.py:2972/3419`, `:3479/3480`, `:4270/4273`), and
> re-running it would delete artifacts the first dispatch already produced —
> that is the risk the guard's own docstring names. Cover all three, not just
> the STRIDE one.
>
> **Tests.** Both fixes need a test that fails without them; revert each in
> place and re-run to prove it. Cover: prepare-stride twice returns the same
> action and leaves `.dispatch-context/` untouched; a genuinely different job
> set still aborts; a checksum mismatch still aborts.
>
> **Do not** shrink the returned payload in this change — that is fix C, it
> touches `docs/internal/contracts/orchestration-actions.md`, and it belongs in
> its own decision.
>
> Run `make lint` and the full suite when done. `tests/test_context_routing.py`
> already fails formatting before your change; leave it.

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
