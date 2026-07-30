# Spike — how much instruction does a Copilot stage need?

- Date: 2026-07-30
- Status: Procedure only — not yet run.
- Belongs to: `implplan-copilot-mvp-2026-07-30.md`, Phase 0.
- Verified against: GitHub Copilot CLI 1.0.76.

## What this decides

The Copilot MVP rests on one unmeasured assumption: that a stage's analytical
instruction can be delivered to a Copilot custom agent at all. The profile size
limit is not the binding constraint — the per-turn context is, and the Claude
side solves it by reading phase bodies in bounded slices.

A single run would only answer "does it work". Running the same stage at three
instruction sizes answers the question the go/no-go actually needs: how much of
the guidance is load-bearing. That number decides whether porting the control
plane is cheap, expensive, or not worth doing.

## Why architecture modeling

Phase 3 is about 66,000 characters and is the largest body of genuine analysis
guidance in the pipeline. Phase 9 STRIDE and Phase 11 finalization are larger
on paper — about 124,000 and 138,000 characters — but most of that is dispatch
and logging protocol that the deterministic controller absorbs in the Copilot
design. Phase 3 is therefore the honest worst case for an agent profile.

## Inputs

| Role | Artifact |
|---|---|
| Target repository | `tests/fixtures/e2e/synthetic-repo` — 36 files: `server.js`, `middleware/`, `models/`, `routes/`, `config/`, `Dockerfile` |
| Oracle | `tests/fixtures/e2e/_last-run/.components.json` — the Claude result: three components (`backend-api`, `partner-api`, `ci-cd-pipeline`), each with `tier` and `paths` |
| Hard gate | `python3 scripts/validate_fragment.py components <out>/.components.json` |
| Contract | `schemas/fragments/components.schema.json`; every component carries `tier` (`client`/`application`/`data`), `id`, `name`, `description`, `paths` |

Nothing new has to be built to judge the result. The fixture is small, so the
whole spike is cheap to repeat.

## The three instruction tiers

| Tier | Prompt content | Size |
|---|---|---|
| A | Contract only: schema fields, the `tier` enum, the zone vocabulary, path rules, where to write | 2.8k |
| B | A plus the two production sections that bear on this stage, verbatim: `### Architecture modeling` and `### Phase 3 sidecar` | 14.4k |
| C | A plus an instruction to read the whole Phase 3 body from the checkout first | 3.3k prompt, 66k read at run time |

Phase 3 is 66,000 characters, but only about 11,000 of it concerns component
enumeration; the rest specifies C4 diagrams, layer heatmap tables, the §2.4
themes and section numbering. In the MVP design that rendering belongs to the
render stage, not to this agent. Tier B is therefore what a careful port would
produce, and tier C is what a wholesale port would produce — C measures whether
an agent still writes a clean sidecar when most of its instruction is about
something else.

Read the outcome like this:

- **A already lands near the oracle** — the capacity concern is void and the
  port is far cheaper than the plan assumes.
- **B is the first tier that holds** — the plan's per-stage profiles are
  workable at their documented limit.
- **Only C holds** — every stage needs runtime slicing, and Phase 3 of the plan
  has to design that mechanism before any profile is written.
- **C does not hold either** — the MVP is not buildable in its planned shape.

The gap between B and C is the number the stop threshold is set from.

## Procedure

The harness is `spike/`: one prompt per tier, `run.sh`, and `compare.py`. Each
run works on a throwaway copy of the fixture and never writes into the
repository.

```bash
./spike/run.sh A     # then B, then C
```

`run.sh` copies the fixture, runs the tier, gates the result with
`validate_fragment.py`, compares it against the oracle, and prints the tail of
the JSONL for the usage numbers. Set `SPIKE_DIR` to keep all three tiers in one
directory, `MAX_AI_CREDITS` to change the cap.

The `--allow-tool` form it uses is deliberate. Copilot's help calls `--allow-all-tools`
required for non-interactive mode; this run establishes whether a scripted run
can instead be scoped to named tools. If it fails, that is a recorded finding —
the MVP's minimal-allowlist mitigation would then be unreachable on the
scripted path, which is a security answer, not a setback.

## What to record

Per tier: gate passed, component count against three, `tier` agreement, path
coverage, AI credits from the JSONL, wall-clock, and whether tool scoping held.
Eighteen numbers in total, which is enough to set a stop threshold from
evidence instead of inventing one.

Record the results in the Phase 0 compatibility note, together with the
threshold and the named owner the plan requires.

## Constraints

Copilot needs authentication and network access, so the spike runs outside a
restricted sandbox. `spike/` is experiment scaffolding, not product code:
nothing in `scripts/` may import from it, and it is deleted with the rest of
the Copilot surface if the MVP is stopped.

The fixture is 36 files and about 96,000 characters. What this costs says
nothing about a production run, which is orders of magnitude larger. The spike
measures feasibility and quality; operating cost belongs to the decision gate
in the MVP plan, measured against a real repository.
