# Design + evaluation — a "cheap STRIDE layer" for large inventories

**Status:** design/evaluation. Supersedes the turn-tiering framing in
`proposal-stride-depth-tiering-2026-07-23.md`, which the 2026-07-23 measurements refuted.
**Goal:** bound STRIDE cost growth for repos with many components **without losing security
coverage** — same Sonnet model throughout.

---

## 1. Cost model (what "cheap" can actually move)

Per dispatched component the cost is:

```
cost_i  ≈  F  +  V_i
```

- **F — fixed per-dispatch overhead.** Skill/agent system prompt + injected context
  (`prior-findings`, `known-threats`, `cross-repo`, `requirements-violations`, `relevant-actors`,
  `trust_boundaries`, taxonomy slice) + the reserve baked into the budget floor
  (`_MANDATORY_CONTEXT_READS = 8` + `_WRITE_AND_LOGGING_RESERVE = 10`). Paid **once per dispatch**,
  independent of depth.
- **V_i — variable analysis.** Turns actually *used*, bounded above by `max_turns`. `max_turns` is a
  **ceiling, not a consumption figure**: a component that finishes early spends less than its budget.

Total ≈ `Σ (F + V_i)`. Three distinct knobs fall out — and they are **not** interchangeable:

| Knob | Attacks | Helps when |
|---|---|---|
| Lower `max_turns` (turn-tiering) | V | the component is *turn-bound* (hits its ceiling) |
| Fewer F-payments (batching K comps/dispatch) | F × N | N is large |
| Leaner context/prompt for low-value comps | F | a low-value population exists |

## 2. Measured constraints (2026-07-23, `insecure-large-spring-app`)

These kill the obvious levers before any code is written:

1. **The priority-4/5 "light tail" is structurally near-empty.** `_is_crown_jewel =
   handles_sensitive_data` (recon tags it broadly — 8/8 components), and `_priority` checks
   crown-jewel (3) **before** ci-cd (4) / internal (5). Even a `ci-cd-pipeline` (holds secrets) and a
   `data-tier` resolve to priority 3. Measured selection over 8 components: `{0:1, 3:7}`, **zero**
   priority 4/5. A priority-keyed cheap tier has **no population**.
2. **`max_turns` is a ceiling.** Small/low-value components finish well under budget, so lowering
   their ceiling saves ≈ 0. Turn-tiering only bites turn-bound (large-footprint) components — which
   the footprint floor deliberately keeps high.
3. **Standard-depth selection already excludes the internal tail.** `_selection_reasons` adds
   "transitively reachable" only at `thorough`. So at `standard` the inventory is *already* a
   security-filtered set of positively-selected units; recon's coarse segmentation caps it
   (~10 units typical). Cost at standard is already bounded by the ceiling (10) + waves (8).
4. **A lean-pacing tier already exists.** `appsec-stride-analyzer.md` keys on
   `ESTIMATED_THREAT_COUNT=low` → "skip optional verification greps; skip LLM/Supply-Chain
   sub-blocks; finish 6 STRIDE letters in ≤6 turns." Variable cost for thin components is *already*
   trimmed.

**Where a genuinely large, genuinely low-value population actually exists:** at **`thorough`** (the
internal/transitive tail is selected) and in true **microservice estates** (many small deployable
units). Not in standard-depth monoliths.

## 3. Options and evaluation

| Option | Lever | Cost impact | Coverage risk | Effort | Applies where | Verdict |
|---|---|---|---|---|---|---|
| **1. Turn-tiering by priority** (original proposal) | V | ~0 (empty population; ceiling not consumption) | low | med | nowhere real | **Reject** |
| **2. Batch the proven-internal tail** (K comps/dispatch, shared budget) | F × N | high at large N | med (isolation loss, stall) | high | thorough / microservice estates | **Primary** |
| **3. Leaner F for low-value comps** (drop cross-repo / reqs / partial taxonomy; lean prompt) | F | modest per comp | med (less context → weaker) | med | thorough tail | **Secondary** |
| **4. Do nothing at standard** | — | — | none | none | standard monoliths | **Accept as-is** |

**Option 2 detail + caution.** Batching amortises F: one agent analyses K low-value components,
paying F once instead of K times — the only lever that scales against the dominant term at large N.
But it is a controlled version of exactly the failure mode in `bug_stride_inline_shortcut`: collapsing
components into one context created a ~182k-token serial turn that stalled the whole phase. So a batch
must be **bounded** (small K), **budgeted** (combined `max_turns` ≥ Σ footprint floors), **isolated in
output** (per-component `.stride-<id>.json`), and **restricted to `_is_internal_only` components**
(the only genuinely low-value, sheddable set — never crown-jewel/exposed/auth/frontend).

**Do NOT reorder crown-jewel-before-cicd to manufacture a cheap population.** A ci-cd pipeline or
data tier that handles secrets genuinely deserves depth; demoting it to save turns trades security
for cost. The empty light-tail is a *correct* consequence of a conservative ordering, not a bug.

## 4. Recommendation

1. **Drop turn-tiering as the lever.** It targets an empty population and a ceiling, not spend.
2. **Re-aim the cheap layer at `thorough` (and large microservice inventories):** batch
   `_is_internal_only` components into bounded, combined-budget dispatches (Option 2), keeping every
   positively-selected unit (crown-jewel/exposed/auth/frontend/llm/ci-cd) in its own deep dispatch.
   This is the lever the original proposal explicitly deferred — and the evidence says it is the
   *only* one with real leverage.
3. **Lean-F (Option 3) as a cheap add-on** once batching exists; reuse the existing
   `ESTIMATED_THREAT_COUNT=low` pacing rather than inventing a new tier.
4. **Leave standard-depth monoliths alone** — recon coarse-segmentation + ceiling + waves already
   bound their cost.

## 5. The measurement still missing

Choosing batching over turn-tiering is directionally settled by the cost model + the empty-population
finding. The **magnitude** (how large is F relative to V?) is still unmeasured — both 2026-07-23 runs
were aborted before STRIDE completed, so there is no `turns_used`-vs-budget data. Before building
Option 2, capture it from **one completed `thorough` run** on a multi-component repo:
per-component `turns_used` (from `.agent-run.log` STEP_END counts) vs `max_turns` (manifest), plus the
per-dispatch fixed token count. If F ≫ V on the tail → batching wins decisively; if V dominates → even
batching's headroom is small and the honest answer is option 4 everywhere.
