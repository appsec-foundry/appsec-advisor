# Agent-authored run facts reach structured artifacts

Standalone work item. Independent of the context-v2 run-integrity work in
`session-handoff-2026-08-16.md`, where this appears as F5 and is scoped to log
lines only. It is not confined to logs.

## What is wrong

An agent writes a JSON artifact and fills in fields it cannot know: the wall
clock and the model it ran as. Both come out wrong, and both pass validation.

Measured across one full run's output directory. Eleven artifacts carry
`generated_at`. Three of them are agent-authored, and two of those three carry
midnight:

```
.actors-discovered.json        generated_at = 2026-08-16T00:00:00Z
.evidence-verification.json    generated_at = 2026-08-16T00:00:00Z
                               model_id     = claude-sonnet-4-6
```

The same run's log carries the midnight stamp too, in the actor-discoverer's
own JSON step events: `"ts":"2026-08-16T00:00:00Z"`. It is off by up to a full
day, in an artifact that is consumed downstream and preserved.

The third agent-authored stamp got it right:

```
.merge-decisions.json          generated_at = 2026-08-16T20:02:07Z   model = sonnet
```

`agents/appsec-threat-merger.md` templates both fields, `merge_threats.py` only
reads the file, and the merger has `Bash` — so it ran a clock. A wrong stamp is
therefore not a reliable signature of agent authorship, and the two failing
producers are not failing for want of a clock they cannot reach. Nothing tells
them to read one, and nothing notices when they do not.

`model_id` is a different failure. It reads `claude-sonnet-4-6` while the
controller logged `model=sonnet` for that job. The value was handed to the
agent: `SKILL-thin-stage1-v2.md` fixes `MODEL_ID` to the bare alias passed as
the Agent model, and `agents/appsec-evidence-verifier.md` tells the verifier to
use that value for its output metadata. The agent ignored an input, rather than
guessing at something it was never given.

The same disagreement shows up in the run log, where the recon-scanner claimed
`model=haiku` for a job the controller's `AGENT_SPAWN` recorded as `sonnet`.

## Why it passes validation

`schemas/evidence-verification.schema.json` requires the field and constrains
it to a non-empty string of at most 64 characters:

```json
"generated_at": { "type": "string", "minLength": 1, "maxLength": 64 }
```

Nothing checks that the value is a timestamp, and nothing checks that it is
plausible for this run.

**Tightening the schema does not fix this.** `2026-08-16T00:00:00Z` is a valid
RFC 3339 date-time, so adding `format: date-time` leaves it passing. A bound
against the run's start epoch would catch it, but that only converts a silent
wrong value into a late abort. The value still has to come from somewhere that
cannot invent it.

## Field naming is inconsistent

`.evidence-verification.json` uses `model_id`, `.merge-decisions.json` uses
`model`. Both are agent-authored, and a consumer joining the two has to know
both names. Worth settling in the same change.

## Direction

`model_id` is a compliance gap, not a producer gap: the verifier already
receives the controller's alias and is instructed to use it. Say so in the
agent's output contract, and check the written value against the dispatched
alias where the controller accepts the artifact.

`generated_at` needs a different producer. The two candidates:

- The controller stamps it when it accepts the artifact, the way it already
  owns run facts elsewhere. This needs no agent cooperation.
- A deterministic wrapper writes the envelope and the agent supplies only its
  payload.

Either way, remove the field from what the agent is asked to produce. Telling
the two failing agents to run `date` the way the merger does would work today
and break again on the next prompt that forgets to.

Removing it is not a one-line change. Both schemas list `generated_at` as
required, and the verifier runs `validate_intermediate.py` as its own producer
gate before the controller ever sees the file — so dropping the field from the
prompt fails the agent's gate. The field has to become optional at the source
and required only after the stamping step, the enrich-then-gate order the
mitigation-verification backfill already uses.

## Scope

Two artifacts are known affected. The scan covered one run's output directory
and matched on the field names `generated_at`, `model_id`, `model`, `ts`,
`timestamp`, `created_at`. Artifacts written only on other depths or on failure
paths were not exercised, so treat the list as a floor.

## Verifying a fix

The two habits from the handoff apply here, for the reason given there —
fixtures in this area have been green while production was broken.

- Revert the fix in place and re-run the new test. If it still passes, it
  proves nothing.
- Assert against a real run's artifacts, not a fixture. The bug is that a
  producer writes a plausible value; a fixture that supplies the value cannot
  observe that.

A regression test should compare the artifact's stamp against the run's own
start epoch rather than against a literal, and should cover both affected
producers.
