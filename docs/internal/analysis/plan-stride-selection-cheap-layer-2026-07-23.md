# Planning — STRIDE component selection, risk tiers & the cheap/thin layer

**Status:** planning. Consolidates and supersedes the framing in
`proposal-stride-depth-tiering-2026-07-23.md` (measurement record) and
`design-cheap-stride-layer-2026-07-23.md` (cost analysis) — both remain as inputs.
**Goal:** make STRIDE cost scale gracefully on large inventories **without losing security
coverage**, and make the internal-component handling **risk-based rather than all-or-nothing** —
same Sonnet model throughout.

---

## 1. Current-state selection *is* the risk model (verified)

Selection is **not** all-or-nothing. Two deterministic functions in
`scripts/build_stride_dispatch_manifest.py` already encode a risk model:

### 1a. `_in_scope(c, depth)` — who is analysed, per depth

| Risk signal (predicate) | `quick` | `standard` | `thorough` |
|---|:--:|:--:|:--:|
| auth / frontend / llm (role floor) | ✓ | ✓ | ✓ |
| **exposed** (`_is_exposed`, internet/edge zones) | ✓ | ✓ | ✓ |
| exposure-**unknown** (no reachability zone / runtime-only tag) — fail-safe | ✓ | ✓ | ✓ |
| **crown-jewel** (`handles_sensitive_data`) | ✗ | ✓ | ✓ |
| **ci-cd** (`_is_cicd`) | ✗ | ✓ | ✓ |
| file-upload / realtime | ✗ | ✓ | ✓ |
| **internal-only** (`_is_internal_only`: has zone, none of the above) | ✗ | ✗ | ✓ |

Key consequence: a component is dropped as "internal" **only when it carries no risk signal at
all**. CI/CD, sensitive SQL databases, auth, exposed services are each kept at `standard` by their
own predicate — they are never in the dropped set.

### 1b. `_priority(c)` — ceiling-shedding order (lower = kept first)

`0` auth · `1` frontend · `2` llm / **exposed** · `3` **crown-jewel** / upload / realtime ·
`4` ci-cd · `5` **internal-only**. Only priority 5 is ever shed.

### 1c. Ceiling & waves

`STRIDE_COMPONENT_CEILING = 10` is an operational guard, **not** a selection cap: it may shed
**only** `_is_internal_only` components; anything earned lifts the ceiling (logged `EXPOSURE_CAP_LIFT`)
and is dispatched. `STRIDE_DISPATCH_CONCURRENCY = 8` bounds concurrent execution, not total cost.

---

## 2. Cost model — what "cheap" can move

```
Total  ≈  D  +  Σ (F + V_i)
```

- **D — dispatch-orchestration overhead.** The single large Stage-1 analyst turn (~180k-token
  Phase 1–8 context) that composes the fan-out. **Once per run**, depth-independent.
- **F — fixed per-dispatch overhead.** System prompt + injected context + the reserve baked into the
  budget floor (`_MANDATORY_CONTEXT_READS = 8` + `_WRITE_AND_LOGGING_RESERVE = 10`). Once per
  dispatched component.
- **V_i — variable analysis.** Turns actually *used*; `max_turns` is a **ceiling, not consumption**.

Levers, by what they attack: **D** (shrink/chunk the dispatch turn) · **F×N** (batch components) ·
**F** (leaner context for low-value) · **V** (turn-tiering — *rejected*, see §3).

---

## 3. Findings (2026-07-23)

1. **The priority-4/5 "light tail" is structurally near-empty** *(measured).* `_is_crown_jewel =
   handles_sensitive_data` is broadly tagged and checked **before** ci-cd/internal in `_priority`, so
   even ci-cd/data components resolve to crown-jewel. An 8-component run selected `{0:1, 3:7}` — zero
   priority 4/5. A priority-keyed cheap tier has no population.
2. **The dispatch turn D is the real, recurring cost** *(observed 3×).* Every full-run attempt
   stalled **9–11+ min at Phase 8→9** *before any component ran*; a >5-min stall forces a **cold
   context re-prefill** (token spike). The F/V probe never completed — it kept dying at the dispatch
   turn (incremental / session-limit / stall×2), which itself corroborates D as the cost centre.
3. **`max_turns` is a ceiling, not spend** *(structural).* Small components finish under budget →
   turn-tiering them saves ≈ 0. → **turn-tiering rejected as a lever.**
4. **Zone-drift bug — fixed** (`ea623c4`). The analyst emitted off-vocabulary `deployment_zones`
   (`application-zone`/`data-zone`/`build-zone`) matching no zone set, so the zonal exposure/ci-cd
   signal was silently inert and off-vocab components were mis-read as proven-internal. Now
   `_reachability_zones` is intersective vs `_REACHABILITY_VOCAB`; off-vocab → exposure-unknown
   fail-safe + `ZONE_DRIFT` warning; recon prompt enumerates canonical zones. **The exposed tier only
   functions correctly because of this fix.**

---

## 4. Component tiers (target model)

| Tier | `_priority` | Components | Treatment | Ever cheapened? |
|---|:--:|---|---|:--:|
| **Deep / protected** | 0–3 | auth, frontend, **exposed**, llm, **crown-jewel**, **data-store\***, upload, realtime | own dispatch, full budget, all sub-blocks; optional floor ≥ `complex` | **Never** |
| **Standard** | 4 | ci-cd | complexity budget, own dispatch | Never |
| **Cheap / thin** | 5 | internal-only / transitive | batched dispatch, lean pacing, combined budget | **Yes** (gated) |

`*` data-store is **not** a predicate today — see decision **D1**. exposed + crown-jewel are excluded
from the thin tier structurally, via `_is_internal_only`’s `not(...)` guard: they can never land in
the cheap tail regardless of inventory size.

---

## 5. Activation logic (target)

**Two gates, both must pass** for the thin (batching) layer to touch a component:

- **Gate 1 — run-level:** (`depth == thorough` **or** microservice estate) **and** `N > ~10`
  **and** `count(_is_internal_only) ≥ ~4`. Otherwise the thin layer is off for the run.
- **Gate 2 — component-level:** only `_is_internal_only` (priority 5). Everything priority 0–4 keeps
  its normal dispatch.

**D (dispatch-context reduction)** is *not* part of this gate — it applies to **every** run and is
the only saving available when the thin layer is off (e.g. standard monoliths).

---

## 6. Decisions to make

### D1 — Data-store / infrastructure type-anchor  · **recommended**
**Problem:** in-scope-ness of a data tier rests solely on `_is_crown_jewel` (the `handles_sensitive_data`
flag) or `_is_exposed`. There is **no `_is_datastore` predicate**. If recon under-tags a SQL DB as
non-sensitive *and* it sits internal, it is **dropped at `standard`** — yet SQL-injection, tampering
and info-disclosure are STRIDE-relevant regardless of the sensitive flag.
**Fix (bidirectional):** add `_is_datastore(c)` (component_type ∈ {data-store, database,
data-persistence, message-queue, secrets-store, cache} or a DB token in `tech_stack`), a type-based
risk anchor exactly like the existing `_is_file_upload` (CWE-434) anchor.
- `_in_scope`: include at `standard`+ (`… or _is_datastore(c) …`).
- `_priority`: place at 3 (crown-jewel-class).
- `_selection_reasons`: add a reason string.
- `_is_internal_only`: add `_is_datastore` to the `not(...)` exclusion list.
- Tests: an internal, non-sensitive-tagged `data-store` is selected at `standard`; a plain internal
  util still drops.

### D2 — Count-dependent internal handling (threshold N)  · **decide**
**Today:** internal-only is dropped at `standard` **unconditionally** — 5 components or 40, the 2
internal ones are skipped. At small N the saving is ~zero and it only creates blind spots.
**Option:** below a small threshold (e.g. `N ≤ 10`) include the internal tail even at `standard`
(cheap, better coverage); above it, keep the drop (or thin-batch at thorough). Implement as a
post-selection pass in `select_stride_components` (it already sees the full set), not in the
per-component `_in_scope`.
**Trade-off:** coverage vs. a small cost bump at small inventories — err toward coverage, since the
cost there is trivial. This is the "activation threshold N" the original proposal left open.

### D3 — Batch the internal tail (thin layer)  · **large-inventory only**
Where Gate 1 passes (thorough / microservice estates with ≥ ~4 internal): batch `_is_internal_only`
components, K small, combined `max_turns ≥ Σ footprint floors`, per-component `.stride-<id>.json`
output. **Caution:** batching is the controlled form of `bug_stride_inline_shortcut` (collapsed
context → stall) — bound K, isolate output, never batch the earned/deep set.

### D4 — Reduce dispatch overhead D  · **broadest reach**
Shrink/chunk what the Stage-1 fan-out turn carries (compact manifest/index instead of the full
Phase 1–8 narrative; or split the compose into smaller turns so no single turn holds ~180k tokens).
Applies at every depth/repo, including the standard monolith where D3 has no population. Justified
independently by the three observed stalls.

### Rejected — turn-tiering by priority
Empty population (finding 1) + ceiling ≠ spend (finding 3). Do not build. Do **not** reorder
crown-jewel-before-cicd to manufacture a cheap population — a secrets-holding ci-cd/data component
deserves depth.

---

## 7. Worked examples

- **5 components, 3 exposed + 2 internal, `standard` (today):** the 3 exposed get full STRIDE; the 2
  internal are **skipped** (not thinned — dropped). Depth decides, not count. With **D2**, at N=5 the
  2 internal would be included (cheap). To cover them today: run `thorough`.
- **40 components, `standard`, all earned:** the ceiling **lifts**, all 40 dispatch **deep** —
  inherently expensive, and the thin layer **cannot** help (no low-value tail; they are all
  high-value). Only **D4** reduces cost here. Genuinely-internal ones among the 40 are dropped
  (or, with **D1/D2**, kept if they are data-stores / the inventory is small).
- **µ-service estate, `thorough`, 15 internal services:** Gate 1 passes → the internal tail is
  **batched** (D3); earned services stay deep.

---

## 8. Implementation plan (phased, measurement-gated)

| Phase | Work | Verify |
|---|---|---|
| **0** | **D1 — data-store type-anchor** (self-contained, high value, no measurement needed) | test: internal non-sensitive `data-store` selected at `standard`; plain internal util still dropped; `make test` |
| **1** | **Measure D vs F vs V** on one *completed* run (per-component `turns_used` via `.agent-run.log` STEP_START/STEP_END by `[<cid>]`, or tool-calls per `AGENT_SPAWN`→`COMPONENT_ID`; plus the Stage-1 dispatch-turn tokens) | data captured; decision gate below |
| **2** | **D4 — dispatch-context reduction** (justified by the stalls regardless of Phase 1) | stall/cold-reprefill reduced on a real run |
| **3** | **D2 — count-threshold** for internal inclusion at small N | test: N≤thresh includes internal at standard; N>thresh drops/thins |
| **4** | **D3 — thin batching** of the internal tail (only if Phase 1 shows F ≫ V on the tail) | batched dispatch, isolated per-component output, `check_stride_dispatch` green, no STRIDE_STALE |

**Gate after Phase 1:** if V dominates (agents are task-bound, not F-heavy), skip D3 — batching buys
little. D1/D2/D4 stand regardless.

Every code phase is bidirectional (producer predicate + `_priority` + `_selection_reasons` +
`_is_internal_only` + schema/validator + tests) per AGENTS.md §4.

---

## 9. Not doing / open

- **Not doing:** turn-tiering by priority; cheaper model (Haiku) for the tail; reordering
  crown-jewel-first.
- **Open:** the quantitative F-vs-V split (Phase 1 — blocked 4× on 2026-07-23 by the dispatch stall,
  which is itself finding 2); exact thresholds (N for D2, K for D3) — set from Phase 1 data.
