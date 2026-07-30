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

| Tier | Profile content | Size |
|---|---|---|
| A | Contract only: schema fields, the `tier` enum, path rules, where to write | ~4k |
| B | A plus the Phase 3 enumeration heuristics — what counts as a component, when components are merged | ~18k |
| C | A plus the full Phase 3 body, loaded at run time | 66k |

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

Run against a copy, never against the repository itself.

```bash
SPIKE=$(mktemp -d)
cp -r tests/fixtures/e2e/synthetic-repo "$SPIKE/repo"
mkdir -p "$SPIKE/out-A"

copilot -p "$(cat spike/prompt-A.md)" \
  -C "$SPIKE/repo" \
  --add-dir "$SPIKE/out-A" \
  --allow-tool shell --allow-tool write \
  --output-format json --no-ask-user \
  --max-ai-credits 30 > "$SPIKE/log-A.jsonl"

python3 scripts/validate_fragment.py components "$SPIKE/out-A/.components.json"
python3 spike/compare.py "$SPIKE/out-A/.components.json" \
  tests/fixtures/e2e/_last-run/.components.json
```

Repeat for tiers B and C.

The `--allow-tool` form is deliberate. Copilot's help calls `--allow-all-tools`
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
restricted sandbox. Keep the harness under an untracked `spike/` directory: it
is throwaway scaffolding, not product code, and nothing in it may be imported
by `scripts/`.
