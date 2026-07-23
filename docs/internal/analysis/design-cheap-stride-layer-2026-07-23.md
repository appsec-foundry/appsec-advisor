# Design + evaluation — a "cheap STRIDE layer" for large inventories

**Status:** design/evaluation. Supersedes the turn-tiering framing in
`proposal-stride-depth-tiering-2026-07-23.md`, which the 2026-07-23 measurements refuted.
**Goal:** bound STRIDE cost growth for repos with many components **without losing security
coverage** — same Sonnet model throughout.

---

## 1. Cost model (what "cheap" can actually move)

The total cost is:

```
Total  ≈  D  +  Σ (F + V_i)
```

- **D — dispatch-orchestration overhead.** The single large Stage-1 analyst turn that carries the
  Phase 1–8 context (~180k tokens) and composes/dispatches the STRIDE fan-out. Paid **once per run**
  (per wave), independent of component count. At standard tier this turn is **latency-heavy and
  cache-cold-prone** — see constraint 5. Not a per-component cost at all.
- **F — fixed per-dispatch overhead.** Skill/agent system prompt + injected context
  (`prior-findings`, `known-threats`, `cross-repo`, `requirements-violations`, `relevant-actors`,
  `trust_boundaries`, taxonomy slice) + the reserve baked into the budget floor
  (`_MANDATORY_CONTEXT_READS = 8` + `_WRITE_AND_LOGGING_RESERVE = 10`). Paid **once per dispatched
  component**, independent of depth.
- **V_i — variable analysis.** Turns actually *used*, bounded above by `max_turns`. `max_turns` is a
  **ceiling, not a consumption figure**: a component that finishes early spends less than its budget.

Four distinct knobs fall out — and they are **not** interchangeable:

| Knob | Attacks | Helps when |
|---|---|---|
| Shrink / chunk the Stage-1 dispatch context | D | dispatch stalls / cold re-prefill dominate (see #5) |
| Fewer F-payments (batching K comps/dispatch) | F × N | N is large |
| Leaner context/prompt for low-value comps | F | a low-value population exists |
| Lower `max_turns` (turn-tiering) | V | the component is *turn-bound* (hits its ceiling) |

## 2. Measured / observed constraints (2026-07-23, Spring-app runs)

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
5. **The STRIDE-dispatch turn (D) is itself a large, recurring cost — observed 3× (`observed`).**
   Every full-run attempt (once on `insecure-large-spring-app`, twice on `insecure-spring-app`)
   **stalled 9–11+ min at the Phase 8→9 boundary** — the single Stage-1 analyst turn that composes
   the fan-out — *before any component was analysed*. The watchdog attributes it to standard-tier
   API latency, and warns explicitly: **a wait past the 5-min cache TTL forces the recovered turn to
   re-prefill the whole ~180k-token context COLD** — a token spike on top of the wall-clock loss. So
   a meaningful slice of "cost per run" lives in the monolithic dispatch turn, **not** in the
   analysis. (This is also why the quantitative F/V measurement in §5 could not be completed — the
   blocker is itself the finding.)

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
| **5. Shrink / chunk the Stage-1 dispatch context** | D | high (cuts stall + cold re-prefill) | low–med | med | every depth, every repo | **Co-primary** |

**Option 5 detail.** The one cost that showed up empirically (constraint 5) is the monolithic Stage-1
dispatch turn, not per-component analysis. Reducing what that turn must carry when it composes the
fan-out — e.g. hand the dispatcher a compact manifest/index instead of the full Phase 1–8 narrative,
or split the fan-out compose into smaller turns so no single turn holds ~180k tokens — attacks D
directly and shrinks the >5-min-stall / cold-re-prefill exposure. It applies at **every** depth and
repo shape (unlike batching, whose population only exists at thorough/microservices), which makes it
the broadest-reach lever we have evidence for.

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
2. **Attack the dispatch turn D first (Option 5)** — it is the only cost the runs actually
   *demonstrated* (three 9–11-min stalls + cold re-prefill), and it applies at every depth and repo
   shape, including the standard-depth monolith where batching has no population. Shrink/chunk what
   the Stage-1 fan-out turn carries. Broadest reach for the evidence we have.
3. **Batching (Option 2) as the large-inventory lever** at `thorough` / microservice estates: batch
   `_is_internal_only` components into bounded, combined-budget dispatches, keeping every
   positively-selected unit (crown-jewel/exposed/auth/frontend/llm/ci-cd) in its own deep dispatch.
   The original proposal deferred this; it is the lever that scales with N — but only where the tail
   exists.
4. **Lean-F (Option 3) as a cheap add-on** once batching exists; reuse the existing
   `ESTIMATED_THREAT_COUNT=low` pacing rather than inventing a new tier.
5. **Leave standard-depth monoliths' analysis alone** — recon coarse-segmentation + ceiling + waves
   already bound the *analysis* cost; the win there is D (Option 5), not the fan-out.

## 5. The measurement still missing

Choosing batching over turn-tiering is directionally settled by the cost model + the empty-population
finding. The **magnitude** (how large is F relative to V?) is still unmeasured. It was **attempted
four times on 2026-07-23** and never reached a completed STRIDE fan-out — blocked in turn by a mode
mixup (incremental reused a prior baseline; fixed with `--full`), a hit account session limit, and
finally — twice — the **dispatch stall of constraint 5** (the run sat 11+ min at Phase 8→9 and never
dispatched). That the F/V probe keeps dying at the dispatch turn is itself corroboration that D, not
per-component analysis, is where the time goes.

To capture F/V when a run does complete: per-component `turns_used` (pair `.agent-run.log`
STEP_START/STEP_END by `[<component-id>]`, or count tool-call events per `AGENT_SPAWN`→`COMPONENT_ID`
session) vs `max_turns` (manifest), plus the per-dispatch fixed token count and the Stage-1 dispatch
turn's tokens. If F ≫ V on the tail → batching wins; if V dominates → even batching's headroom is
small. Either way, D (Option 5) is already justified by the observed stalls independent of this probe.

> En route, verifying the selection surfaced and fixed a real bug (`ea623c4`): off-vocabulary
> `deployment_zones` (`application-zone`/`data-zone`/`build-zone`) matched no zone set, so the zonal
> exposure/ci-cd signal was silently inert and off-vocab components were mis-read as proven-internal.
> Not a cheap-STRIDE lever, but it was corrupting the very selection this analysis reads.
