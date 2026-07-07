# Implementation Plan — clean up SKILL-impl.md for Sonnet orchestration

**File:** `appsec-advisor/skills/create-threat-model/SKILL-impl.md`
**Branch:** `feature/skill-impl-sonnet-cleanup` · **As of:** 2026-06-20

## Goal

The skill should run **reliably on Sonnet** (rather than only Opus) as the orchestrator.
Primary goal = **followability for a weaker model**; token/cost savings are a
welcome side effect, not the driver. The dominant cost lever (~5× via
Sonnet session) is **already banked and live-validated** — what's open only chases
a remainder (~$1/run prompt trimming) or internal cleanliness.

Core hypothesis: Sonnet doesn't fail on size, but on **scattered/buried
contracts** and **prose-instead-of-table branching**.

## Status — what's implemented + validated

Primary goal **achieved and proven live multiple times** (orchestrator = Sonnet):
- Standard run (`455206c32`, ~66 min): all three fan-outs parallel, QA gate `pass`, **0 errors**.
- **Re-validation 2026-06-20** (`--verbose --quick --abuse-cases`, `/tmp/tm-phase-d-quick`) after the
  whole bundle: **STRIDE 5/38 s + abuse 6/17 s parallel**, verbose marker ok after P4 dedup (appendix present,
  **0** format_line/LOG_ERR), clean finish (0 errors). De-accretion did not break followability.

Full suite green, each workstream its own commit.

| Workstream | Status |
|---|---|
| **P1** Abuse-Verifier-MUST block | **DONE** `cf7c13a` — buried "ONE message" contract into a local HARD-CONSTRAINT block; the STRIDE block was already ideal (no churn) |
| **P5** Mode-routing table | **DONE** `6bcf2bd` — additive navigation table, per-section conditions stay authoritative |
| **format_line bug** (surfaced by the live run) | **DONE** `007f4be` — step logging mandated onto `log_event.py`, inline `format_line` forbidden; guard test |
| **P8** Lazy-load (pattern) | **PARTIAL** `d3a1d4f` — re-render branch → `modes/rerender.md`, JIT load; guard test |
| **P3** Shell→`.sh` (largest block) | **PARTIAL** `df36584` — auto-emitter (139 lines) → `scripts/auto_emitter_pass.sh`, characterization tests |
| **P4** Marker-lifecycle dedup | **DONE** `e8fd2c1` — divergent early `$VERBOSE_REPORT` duplicate (verbose+tracing) removed, authoritative `RESOLVED_JSON` section + EXIT trap stays; guard test; live re-validated |

## Completed (strand variant b: review-scan → fix → re-validation)

- **Phase B (DONE):** P4 marker dedup (`e8fd2c1`, above). **Recon-inline = NO fix** — the
  `--verbose` run had `.route-inventory.json` (50 KB), no fallback → it was transient API latency in the
  standard run, not a structural bug.
- **Phase D (GREEN):** the re-validation run confirms the whole bundle (see status above).

## Open — deliberately deferred

**Phase C — P6 (132 markers) + meta-narration consolidation: NOT done, recommended to drop.**
Close inspection showed: the "real" redundancies/contradictions (duplicate sections, format_line) are
already fixed in B/format_line. What would remain in P6/meta-narration is **diffuse historical noise**
— most of the 28 `narrat/suppress` hits are unrelated (`--no-yaml`, `SUPPRESS_INCOMPLETE_BANNER`,
`NARRATIVE_PLACEHOLDER`), real "do not narrate" repetition ≈ only the top block. Cosmetic, highest
followability risk (R2), lowest correctness value → effort/risk not justified for
"clean + performant under Sonnet" (= already achieved).

### Gated / low priority (own live run needed or low value)

- **P8 remainder** (incremental cluster 298+119 lines, resume 79 lines, dry-run 12 lines): largest remaining token gain,
  but **entangled** — resume contains the always-run **requirements fail-closed gate** (extracting it blindly
  = bug), incremental is control-flow- and test-entangled, dry-run purely descriptive. Needs a
  per-mode golden run (`--incremental`). End state = SKILL-impl.md as a thin backbone + JIT-load table;
  the file does **not** disappear (always-run core: config resolution, stages, gates).
- **P3 remainder** (deadline watchdog/wipes/completion persistence …): fully verifiable (characterization tests),
  low risk, but diminishing marginal benefit per block. Only if file size is a goal in its own right.
- **P2** (branching → tables): the live run navigated **all** branches correctly — addresses
  a non-manifesting problem. Lowest priority.

### Deliberately NOT implemented (with rationale)

- **P7** (verbatim-subjects copy block): subjects already live in a backticked "source of truth" table;
  a copy block would create a competing second source (violates guardrail 3).
- **P4 pregenerate dedup**: no real duplication — 3 execution sites, 2nd call divergent
  (`+_chain-skeleton.md`); dedup to a canonical reference violates R3.

## Guardrails (apply to every open change)

1. **Byte-identical runtime behavior.** The diff shows only reformatting, no changed command/exit code.
2. **The deterministic substrate is the per-phase gate.** Update the `SKILL-impl`-pinning tests
   (`test_skill_composition_split`, `test_incremental_mode`, `test_skill_auto_retry`, …) + the gates
   (`check_stride_dispatch`, `validate_dispatch_manifest`, `check_inline_shortcut`, `requirements_gate`)
   in lockstep. Golden run only as the final smoke, not per phase.
3. **Local rather than global reinforcement.** Contracts ONCE at the execution point as a "MUST" block.
4. **Chesterton's Fence.** Co-locate protective rationale (script docstring) or keep it briefly inline,
   never delete wholesale.
5. **Incremental, no big-bang.** One reviewable commit + test per workstream.
6. **Respect the cache-stable prefix.** Insertions near the start of the file invalidate the prefix
   (AGENTS.md:186). Static edits re-stabilize after a one-time re-cache.

## Risks & countermeasures

| Risk | Countermeasure |
|---|---|
| **R2** Redundancy reduction (P6/meta-narration) weakens LLM adherence | Local reinforcement instead of global repetition; **Phase-D re-run as proof** |
| **R3** Cross-file refs not loaded under context pressure | Only for **dispatch-point contracts** (INLINE). Mode bodies/rationale extractable (phase group proves it) |
| **R4** Chesterton — lost protective rationale | Pointer in place; rationale in the script docstring |
| **R5** Extraction drift (exit codes/quoting) | Verbatim Bash→`.sh`, no Python rewrite; characterization test old==new |
| **R7** Divergent duplicates merged incorrectly | Establish authority via run evidence before dedup (P4 markers) |

## Non-goals

- No functional change to the pipeline, gates, or output schema.
- No removal of security gates or recovery paths.
- No big-bang rewrite; no splitting of **operational dispatch-point contracts** across file boundaries
  (P8 only extracts mode-conditional bodies — see R3).
- No model-routing change for the analysis sub-agents (already auto-routed).
