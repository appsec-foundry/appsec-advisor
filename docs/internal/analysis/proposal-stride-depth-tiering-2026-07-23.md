# Proposal — security-priority STRIDE depth tiering (standard depth, large inventories)

**Status:** design **blocked** by the 2026-07-23 baseline measurement below — the Light tier has
no population at `standard`. Author decision needed before proceeding (supersedes the three open
parameters).
**Goal:** cover repos with many components (30–50+) at `standard` depth without linear
cost blow-up, by spending analysis effort proportional to a component's security value —
**same Sonnet model throughout, no model downgrade.**

---

## Measurement result (2026-07-23) — the Light tier has no population at `standard`

A baseline `standard` run was started against `insecure-large-spring-app` (88 Java files) to size
the tail, then **aborted at the STRIDE-selection checkpoint** (cheap, pre-dispatch) because the
selection already refutes the design's core assumption:

- Recon yields **5 components total** (`.components.json`), not 30–50; `excluded=0`, `ceiling` (10)
  not reached, `lifted=false`. This repo is not a large-inventory case at all.
- All 5 selected are **priority 0–3** (1 auth · 1 frontend · 3 crown-jewel), footprint-floored to
  24–48 turns. **Zero priority 4–5** (ci-cd / internal-only) — the exact set the Light tier
  targets is empty.

This is not a quirk of the repo. At `standard` depth the internal / transitively-reachable tail
(priority 5) is **by design never selected**: `_selection_reasons` adds "transitively reachable"
only when `depth == "thorough"`. Therefore:

> **The two gates do not overlap on the population that matters.** The Light tier's named
> population (internal-only / transitive, priority 5) exists **only at `thorough`**, but the tier
> is gated to `standard`. At `standard` the tier can touch at most **ci-cd (priority 4)** — never
> the internal tail — because standard-depth selection is already a security filter that drops the
> tail.

**Consequence for the thesis.** At `standard`, a 30–50-component inventory is 30–50
*positively-selected* components (auth/frontend/exposed/llm/crown-jewel/upload/realtime/ci-cd) —
all Deep or Standard tier, none Light. Turn-tiering saves little there; the lever that scales with
such an inventory is the **fixed per-dispatch overhead × N** (≥18-turn reserve —
`_MANDATORY_CONTEXT_READS=8` + `_WRITE_AND_LOGGING_RESERVE=10` — plus system/context per agent),
which only **batching** (explicitly out-of-scope here) reduces.

**Author decision now required (supersedes open params 1–3):**
- **(a)** Move the Light gate to `thorough`, where the tail exists — contradicts "thorough keeps
  everything Deep"; resolve that contradiction first.
- **(b)** Redefine the standard-depth Light population to what is actually selectable (ci-cd,
  and/or large-but-lower-value attack surface) — accepting the risk of under-budgeting attack
  surface.
- **(c)** Reframe the proposal around **batching / fixed-overhead** as the primary economic lever
  for standard-depth large inventories, with turn-tiering as a secondary refinement.

A real large-inventory measurement (turns_used vs. budget) still needs either a genuinely larger
repo or a `thorough` run — `insecure-large-spring-app` at `standard` cannot exercise it.

### Follow-up run (2026-07-23, same repo re-segmented to 8 components)

The repo was re-shaped to yield more deployable units. Recon then produced **8** components
including a `data-tier` (data-zone) and a `ci-cd-pipeline` (build-zone) — natural Light-tier
candidates. The actual selection was still:

```
selected=8  excluded=0  lifted=False  ceiling=10
priority tally: {0: 1, 3: 7}      Light-tier candidates (prio 4/5): 0
```

**Root cause — the Light tier is structurally near-empty regardless of depth or component count.**
`_is_crown_jewel(c) = bool(c["handles_sensitive_data"])`, and recon tags sensitive data broadly
(here 8/8). In `_priority`, **crown-jewel (3) is evaluated *before* ci-cd (4) and internal (5)**, so
any component touching secrets/PII — *including the ci-cd pipeline (holds secrets) and the data
tier* — resolves to priority 3, never 4/5. For the Light tier to have a population a component must
be **both** low-value **and** `handles_sensitive_data=False`, which the ci-cd/data/internal tail
rarely is. This is a second, independent reason (on top of the standard-vs-thorough gate above) that
turn-tiering the "light tail" has almost nothing to act on in real repos — reinforcing option **(c)**:
the standard-depth economic lever is fixed-overhead / batching, not per-component turn-tiering.

> Aside — a real bug surfaced while verifying this run: the analyst emitted off-vocabulary
> `deployment_zones` (`application-zone`/`data-zone`/`build-zone`) that matched no zone set, so the
> zonal exposure/ci-cd classification was silently inert (a Spring web API was not flagged
> `internet`-exposed; ci-cd was only caught by a text-hint). Fixed separately in
> `build_stride_dispatch_manifest.py` (off-vocab zones now fail-safe to exposure-unknown + a
> `ZONE_DRIFT` warning) and the recon prompt (canonical-zone enumeration). Not part of this proposal.

---

## Why not the obvious levers

- **Cheaper model (Haiku) — rejected.** A weaker model needs more turns, more retries, more
  QA repair, and fails more often, so it frequently costs *more* end-to-end while losing
  discovery recall. `docs/model-selection.md` already encodes the principle "reasoning is
  never downgraded to Haiku"; STRIDE is the tool's primary value contribution. The knob
  exists (`APPSEC_STRIDE_MODEL` / `--stride-model`) but blanket-cheapening STRIDE is the
  wrong trade. (Note: the `gotcha_pipeline_tier_locked` memory claiming "no tier knob" is
  stale — the knob exists; it is deliberately parked on Sonnet.)
- **Prompt caching — not a plugin lever.** The plugin sets no `cache_control`; sub-agent
  prompt caching is harness-managed. Nothing to build here.
- **Effort/depth per component — this proposal.** Vary `max_turns` (reading/analysis budget)
  by security priority. Keeps the model, cuts cost on the low-value tail.

## Current state (verified)

- **Component count is capped but lifts.** `resolve_config.STRIDE_COMPONENT_CEILING = 10`
  (`resolve_config.py:266`), depth-independent; it *lifts* rather than drops exposed /
  crown-jewel components, so a broadly-exposed repo can dispatch 30–50 STRIDE agents. Waves
  bound concurrency (`STRIDE_DISPATCH_CONCURRENCY = 8`), **not** total token cost — cost
  scales linearly with component count today.
- **Security priority is known at manifest time.** `build_stride_dispatch_manifest.py`:
  `_is_crown_jewel:311` (`handles_sensitive_data`), `_is_exposed`, `_is_internal_only:315`,
  `_priority:335` (0 auth · 1 frontend · 2 llm/exposed · 3 crown-jewel/upload/realtime ·
  4 ci-cd · 5 internal-only). These land in `.stride-selection.json` (`priority`, `reasons`).
- **But the turn budget is priority-blind.** `classify_component.classify:206` computes
  `max_turns` from complexity tier (`TURN_BUDGETS:67` — standard: simple 8 / moderate 22 /
  complex 31) plus the file-footprint floor (`_footprint_turn_floor:186`, cap
  `_FOOTPRINT_TURN_CAP = 48`). It never sees crown-jewel / exposed / internal. **This is the
  plumbing gap:** thread the security tier from the manifest builder into the budget.

## Design

**Three depth tiers** (mapped to existing predicates):

| Tier | Components | Budget (standard) |
|---|---|---|
| **Deep** | crown-jewel (`_is_crown_jewel`) | ≥ complex (31) — never under-analysed |
| **Standard** | attack surface: auth, frontend, exposed, llm, upload, realtime | current complexity-based budget (unchanged) |
| **Light** | internal tail: internal-only, ci-cd, transitively-reachable (`_priority` 4–5) | new light budget (~12–15), footprint-floored |

**Gating — when the Light tier activates:**
- `depth == "standard"` only. `thorough` keeps everything Deep (premium tier, cost accepted);
  `quick` is already minimal.
- Only when the selected component count exceeds a threshold **N** (see open param 1). Below
  N: today's uniform behaviour, no tiering.

**Safety net (directly answers "cheap → more failures/cost"):** the Light tier lowers only
the *base* budget. The **footprint floor (`_footprint_turn_floor`, the D5 fix) stays a hard
lower bound**, so a wide internal component still gets enough turns and does not fail →
no retry waste. Savings materialise only for components that are *both* low-priority *and*
small-footprint — precisely the long tail of a 30–50-component inventory.

**Out of scope (deliberately):**
- STRIDE category count stays 6 — dropping categories loses threats.
- The model. No Haiku, no per-component model pinning.
- Batching multiple components per dispatch — a separate lever (cuts fixed per-dispatch
  overhead) that could compound later; not part of this change.

## Open parameters (author decision)

1. **Activation threshold N.** `> 8` (the concurrency / "there is a second wave") vs coupling
   to the ceiling lift (`> 10` / `lifted == true`).
2. **Light budget start value.** ~12–15 turns (between simple 8 and moderate 22), footprint-floored.
3. **Exposed placement.** Own middle "Standard" tier (as above) vs folded into "Deep" with
   crown-jewel. Author leaning: crown-jewel most detail, exposed "a bit more weight" than the
   tail → keep exposed as the middle Standard tier.

## Implementation sketch (bidirectional)

1. **Producer — `build_stride_dispatch_manifest.py`:** compute a `depth_tier`
   (`deep` / `standard` / `light`) per component from the existing predicates + the gating
   (depth, component count); pass it into `classify_component.classify(...)`.
2. **Budget — `classify_component.py`:** accept the tier; apply it to the base `TURN_BUDGETS`
   lookup *before* the footprint floor (floor still wins upward). Surface the tier in the
   returned `reason` for observability, like `_footprint_turn_floor` already does.
3. **Manifest / dispatch:** carry `depth_tier` through to `.stride-dispatch-manifest.json`
   so a run is auditable ("which components got the light layer, and why").
4. **Config surfacing:** reflect the active tiering in the run's model/depth label /
   `.skill-config.json`, and a `log_event` line so the operator sees it (mirrors
   `EXPOSURE_CAP_LIFT`).
5. **Tests:** (a) tier assignment per predicate; (b) gating — no light tier at `thorough`,
   none below N, active above N at `standard`; (c) footprint floor still overrides a light
   component that is wide (no under-budget failure); (d) crown-jewel never dips below the
   Deep floor. Run against the real component inventory like the D5 verification table.

## Verification target

Reproduce the effect on a large-inventory repo: at `standard` with > N components, the tail
components show reduced `max_turns` in `.stride-dispatch-manifest.json` while crown-jewel and
exposed components are unchanged, and no light-tier component fails for lack of turns.
