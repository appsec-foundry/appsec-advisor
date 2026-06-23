# Orchestrator Context Budget — Measurement & Fix Plan

**Date:** 2026-06-23
**Status:** Analysis CORRECTED after deeper verification — see §8. The original
attribution (§4–§6, "Phases 3–8 inline") was WRONG; the real bloat source is the
orchestrator reading the full `SKILL-impl.md` into its own context. Fix in progress.
**Trigger:** Observation that the Sonnet orchestrator's context window sits at ~79% at
end of a juice-shop standard-mode run; concern that larger repos won't scan.

> ⚠ **Read §8 first.** Sections 4–6 below reflect a wrong premise (that the measured
> session ran Phases 3–8 inline). The measured session is the **main session**, which
> *dispatches* `appsec-threat-analyst` for Stage 1 — Phases 3–8 run in that sub-agent,
> not in the measured context. The corrected root cause and fix are in §8.

---

## 1. Question

Does the orchestrator's context window fill up enough to block large-repo scans, and
can it be "cleaned up" periodically mid-run?

**Hard constraint up front:** In Claude Code an agent **cannot selectively evict** its
own earlier turns. Context is append-only per agent session. It only shrinks via
(a) `/compact` / auto-compact (lossy, whole-history summarisation — you don't choose
what survives), (b) a fresh agent/session (state handed over via disk), or
(c) sub-agent isolation (already used heavily). There is no "drop turns 40–80 because
obsolete" primitive. Any "cleanup" must take one of those three forms.

---

## 2. Method

Measured the **main-session** transcript (the orchestrator; sub-agents live in separate
`agent-*.jsonl` files and are excluded). Per assistant turn, context occupancy =
`input_tokens + cache_read_input_tokens + cache_creation_input_tokens` from
`message.usage`. Joined the token curve to phase boundaries via `.agent-run.log`
`PHASE_START/PHASE_END` timestamps.

- Transcript: `~/.claude/projects/-home-mrohr-j-juice-shop/f038d924-…jsonl`
  (Sonnet-4-6, 273 turns, end ctx = 158,287 = **79% of 200K** — matches the observation).
- Run dir: `/home/mrohr/j/juice-shop/docs/security/` (standard mode).
- Scripts: `scratchpad/ctxmeasure.py`, `ctxdetail.py`, `ctxphase.py`.

---

## 3. Measured facts

```
t0   34k   Fixed floor: SKILL-impl instructions + system prompt
t12  65k   Phase 1–2  (recon / config-scan output ingested into orchestrator)
t18 118k   steepest jump: +53k in 6 turns
t24 141k   Phase 3–8 INLINE (architecture, assets, surface, boundaries, controls)
t42 163k
t59 166k = 83%  → AUTO-COMPACT fires (confirmed compact_boundary marker)
t60  52k   compaction lands right after Phase-9-prep (STRIDE dispatch)
 …         remainder (STRIDE merge, 10a/b, 11, render, QA, architect) climbs GENTLY
t272 158k = 79% (end)
```

Two hard findings:

1. **The orchestrator already auto-compacts — involuntarily.** A `compact_boundary`
   system marker + `isCompactSummary` user message are present. At 83% (166k) Claude
   Code's auto-compact fires and collapses to 52k. This is **lossy Option C already
   running, ungoverned.** The "79% at end" is the post-final-climb of a sawtooth, not a
   first approach to the limit.

2. **Essentially the entire climb (34k→166k) is Stage 1 before STRIDE** — recon/config
   output ingestion + Phases 3–8 inline. The dispatch-heavy back half climbs only gently
   (52k→158k over 210 turns), exactly as the disk-handoff design intends.

---

## 4. Diagnosis

- **Context is a binding constraint, not hypothetical.** Standard mode on a *medium*
  repo already triggers one compaction and ends one cycle short of a second. Thorough
  mode or a real monorepo (80+ components) → multiple compaction cycles guaranteed.
- **The dominant filler is the inline Stage-1 architecture work (Phases 1–8).** Not the
  threat data — that never enters orchestrator context (sub-agents return `<usage>`
  metadata only; `.stride-*.json` / `threat-model.yaml` stay on disk; verified
  separately).
- **Why the compaction is non-fatal today (and why that's deceptive):** it fires *after*
  Phase-9-prep, i.e. after the architecture sidecars are already written to disk. The
  disk-handoff discipline saves the run — the orchestrator loses its *narrative* memory
  of the architecture but every structured artifact survives on disk, and all downstream
  steps read from disk. On a **larger repo the compaction fires earlier** (possibly
  mid-Phase-8, before all sidecars are persisted) → the summary can drop not-yet-written
  state. That is the real scaling risk. Plus every compaction breaks the prompt-cache
  prefix that the parallel STRIDE dispatch relies on (cost + latency).

### Disk-handoff is complete (verified)

Pre-condition for any restart/compaction safety. All Phase 3–8 decisions persist to
disk; nothing lives only in orchestrator memory:

| Phase 3–8 output | Sidecar |
|---|---|
| Components (C4 input) | `.components.json` |
| Assets | `.assets.json` |
| Trust boundaries | `.trust-boundaries.json` |
| Security controls (13 domains) | `.security-controls.json` |
| Attack surface | `.attack-surface-overrides.json` |
| C4 diagrams | not inline — regenerated in Stage 2 from `threat-model.yaml` by `pregenerate_fragments.py` |

`build_threat_model_yaml.py`, the Phase-9 dispatch-prep, and `compose_threat_model.py`
all read **only disk files**. A fresh process given only the sidecars continues
correctly from the Stage-1→Stage-2 boundary (single edge: if yaml AND prior-yaml AND a
required sidecar are all missing → `exit 4`; recover by re-running the producing phase).

---

## 5. Recommendation

**Fix = move Phases 3–8 (plus recon/config output ingestion) out of the inline
orchestrator into a dispatched `architecture-author` sub-agent.**

~130k of the 166k accumulates there. The sub-agent reads recon output from disk, authors
the architecture sidecars (which are **already written to disk today**) and returns only
`<usage>`. Orchestrator Stage-1 footprint drops from ~166k to ~40–50k → auto-compaction
stops on medium repos, large repos gain headroom.

Clean because (verified): Phases 3–8 persist losslessly to disk, everything downstream
reads from disk, and these phases **do not dispatch** themselves — so a level-1
sub-agent running them does not hit the no-nested-dispatch constraint.

### Why not the alternatives

- **Auto-compact (C):** already firing; lossy, ungoverned, breaks prompt cache. It is the
  symptom, not a fix.
- **Stage-boundary restart (B):** the compaction fires *within* Stage 1, before any stage
  boundary — B only touches the already-gentle back half. Keep as a secondary lever if a
  very large repo later reveals a second limit in the back half; not the primary fix.

---

## 6. Implementation sketch (Option A)

1. New sub-agent `appsec-architecture-author` (level-1; no Agent tool needed).
   Inputs (paths only): recon summary, config-scan findings, `.components.json` seed,
   route inventory, org-profile. Outputs to `$OUTPUT_DIR`: `.components.json`,
   `.assets.json`, `.trust-boundaries.json`, `.security-controls.json`,
   `.attack-surface-overrides.json` (+ any Phase-3 diagram-input metadata). Returns
   `<usage>` only.
2. Orchestrator (SKILL-impl) replaces the inline Phase 3–8 block with a single dispatch +
   `<usage>` capture, mirroring the existing STRIDE/QA dispatch pattern.
3. Contract/drift: update the phase-group spec(s), `data/required-permissions.yaml`
   (new sub-agent dispatch), agent registry, and any phase-map drift guards in tests.
   Bidirectional per AGENTS.md §4.
4. Verify: a fresh standard juice-shop run should show the Stage-1 climb capped well
   below the compaction threshold and **zero** `compact_boundary` markers. Re-run the
   measurement scripts to confirm.

### Open feasibility question (resolve before building)

Phase 4 ("Attack Walkthroughs — rendering Section 9") runs in the log *between* Phase 3
and 5 but renders from STRIDE output (Phase 9). This ordering anomaly means Phase 4 is
likely **not** part of the architecture-author sub-agent. The clean candidates are the
pure architecture phases **3, 5, 6, 7, 8**. Confirm Phase 4's true data dependency and
placement before drawing the sub-agent boundary.

---

## 7. Bottom line (original — superseded by §8)

The user's premise is correct: context is binding and the orchestrator is already
auto-compacting in standard/medium. The disk-handoff architecture is what keeps that
non-fatal today. ~~The targeted fix is to stop the Stage-1 inline climb at its source
(Phases 3–8 → sub-agent)~~ — **wrong attribution, see §8.**

---

## 8. CORRECTION — real root cause (verified 2026-06-23)

The measured transcript `f038d924` is the **main session** invoked as
`/appsec-advisor:create-threat-model --slug juice-shop-standard --reasoning-model
sonnet-economy --stride-cap 2`. It does **not** run Phases 3–8 inline — it *dispatches*
`appsec-threat-analyst` (Agent tool) for Stage 1, then does the Level-0 STRIDE fan-out,
Analyst-B, abuse verifiers, renderer, QA. Phases 3–8 run inside the analyst sub-agent,
in its own isolated context. So §4–§6 attribute the bloat to the wrong place.

### What actually fills the main session (per-tool char totals, whole run)

| Source | chars | ~tokens |
|---|---|---|
| **`SKILL-impl.md` — 10 Reads, whole file (offset 0→3790)** | **350k** | **~90k** |
| context-mode MCP returns (42 calls) | 64k | ~16k |
| `threat-model.md` reads (QA/render) | 26k | ~7k |
| **Agent returns (21 dispatches total)** | **17k** | **~4k** |
| Bash (25 calls) | 12k | ~3k |

Two corrected findings:

1. **Sub-agent isolation is excellent** — 21 dispatches return only 17k chars *combined*.
   Threat data never enters the orchestrator. The disk-handoff design works as intended.
   Option A (move Phases 3–8 out) would do nothing for the measured context — those
   phases are already out, in the analyst sub-agent.
2. **The real bloat = the orchestrator reading its own 4210-line `SKILL-impl.md`
   (~82–90k tokens) in full, early** (turns 9–25, sequential offset 0/598/1198/1797/
   2396/2995/3392/3790). `SKILL.md:45` explicitly says "read `SKILL-impl.md` **in
   full**"; `SKILL.md:19` already notes it is "~86k tokens." That read *is* the
   34k→152k climb that triggers the pre-STRIDE auto-compaction.

### Corrected fix

Reduce `SKILL-impl.md`'s **resident** footprint in the main session by extending the
already-established, test-guarded lazy-load pattern (`modes/rerender.md`,
`tests/test_lazy_phase_group_loading.py`, `tests/test_skill_composition_split.py`):

- **Primary, low-risk:** extract the mode-conditional branches that never execute in a
  standard/full scan (Full-Scan Recommendation Prompt, Incremental Pre-Check / Fast-Path /
  Dirty-Set, Rebuild Pre-flight Wipe, Resume from Checkpoint, Dry-Run) into lazy-loaded
  `modes/*.md`, each replaced by a single gated pointer. Removes ~8–11k tokens of dead
  weight from every standard run's resident context. Each extraction: verbatim move +
  gated pointer + drift test mirroring `test_rerender_mode_lazy_loaded_not_inline` +
  AGENTS.md note. `modes/*.md` reads are already permitted (rerender.md works today).
- **Secondary, higher-effort:** lazy-load the Stage-3/4/Completion tail (lines ~3106–4210,
  ~21k tokens) at its stage boundary. Deferred because ~10 tests (`test_qa_depth_profile`
  and others) grep that tail's content in `SKILL-impl.md`; each would need a bidirectional
  update to read the extracted file. Bigger win, but do it after the cheap mode extractions
  land and are measured.
- **Not a fix:** auto-compact (lossy, already firing) and Option A (Phases 3–8 already
  isolated).

### Verify
After extractions, re-run the measurement scripts (`scratchpad/ctxmeasure.py`,
`reads.py`) against a fresh standard run: `SKILL-impl.md` resident chars should drop and
the pre-STRIDE peak should fall below the auto-compact threshold (no `compact_boundary`
marker before the STRIDE dispatch).

---

## 9. Phase 2 — the mode extractions were insufficient; the real fix (implemented 2026-06-23)

Measuring a fresh full run (`7e4cd879`, juice-shop, 153 turns) confirmed the mode
extractions (Phase 1, §8) barely moved the needle:

```
turn 16 130k (65%)   } 9 Reads of SKILL-impl.md = ~80k tokens (321k chars) — read IN FULL
turn 27 153k (77%)   ← pre-flight first renders HERE  (the user's "instantly at 77%")
turn 57 166k (83%)   ← PEAK → AUTO-COMPACT fires (2 compact markers, drop to 55k)
```

Root cause confirmed: `SKILL.md:45` said "read `SKILL-impl.md` **in full**", so the whole
~80k-token file loads before pre-flight regardless of the mode extractions (which only
shrank the file ~4k). The dominant cost is the full upfront read, not the mode branches.

**Fix shipped (read-schedule change, content-preserving — chosen over §8's "extract stage
tail to files", which would churn ~10 tests):** a `<!-- LAZY-LOAD BOUNDARY` marker sits
just before `## Stage 2 - Report Rendering`. `SKILL.md` now instructs the orchestrator to
read only down to that marker during initial load (Stage 1 core, ~48k), and a resume
instruction just above the marker tells it to read from the boundary to EOF at the Stage-2
handoff. The Stage 2/3/4/Completion/Error-Handling tail (~30k) is deferred. The
Incremental-Mode and Dry-Run-Mode sections in the tail are descriptive reference only
(operative logic runs earlier), so deferring is behavior-neutral.

Because the content stays in `SKILL-impl.md`, every test that greps it still passes (no
churn), and correctness is unaffected even if the orchestrator ignores the stop and reads
ahead — worst case is no saving, never a wrong run. Drift guard:
`tests/test_lazy_phase_group_loading.py::test_skill_impl_stage2_tail_lazy_loaded`.

Expected: pre-flight ~77% → ~62%; pre-STRIDE peak ~83% → ~68% (below the auto-compact
threshold). To verify, re-run `scratchpad/run_profile.py` against the next full-scan
transcript: the `compact_boundary` marker before STRIDE should be gone. Further reduction
(toward ~40%) would require a second boundary deferring the Stage-1-dispatch detail past
pre-flight — a follow-up, not done here.
