# Thin-runtime regressions — e2e run 2026-07-20 (juice-shop)

First real end-to-end exercise of six commits that all landed **2026-07-20**:

| Commit | Subject |
|---|---|
| `ff6e0d9` | Lazy-load post-analysis skill stages |
| `86c2b55` | Fix lazy-loaded release gate routing |
| `71eeb70` | Reduce thin orchestrator context usage |
| `2150b13` | Scale STRIDE dispatch for large component inventories |
| `331538a` | Optimize deterministic QA gating |
| `88d5208` | docs: streamline contributor agent guidance |

Run outcome: Stage 1 completed (56 threats, 8 Critical / 40 High), then the run was
hard-aborted by `post-stage1` exit 4. No report produced. One session reached
**$11.70** and **21.6M cache_read**.

`pytest tests/test_context_prompt_budgets.py tests/test_lazy_phase_group_loading.py
tests/test_stride_dispatch_waves.py tests/test_check_stride_dispatch.py
tests/test_prompt_token_bounds.py` → **72 passed**. Every defect below is green in CI.

---

## D1 — Gate deadlock: `post_stage1` demands what the wave gate forbids (BLOCKER)

`scripts/orchestration_controller.py:1122-1125` requires `.threats-merged.json`,
`.triage-flags.json`, `threat-model.yaml` — all **Analyst-B outputs**:

```python
required = (".recon-summary.md", ".threats-merged.json", ".triage-flags.json", "threat-model.yaml")
missing = [name for name in required if not (output_dir / name).is_file()]
if missing:
    raise ControllerError(f"Stage 1 did not produce required artifacts: ...")
```

`scripts/orchestration_controller.py:1131` then runs the coverage gate:

```python
_run_script("check_stride_dispatch.py", [str(output_dir)])   # exit 4 on incomplete coverage
```

Meanwhile `SKILL-thin-stage1.md:68` and `:85-86` instruct the orchestrator: *"status=blocked
… stop before Analyst-B"* / *"any non-zero result is fatal and Analyst-B must not run."*

**Both branches abort:**
- Obey the wave gate (skip Analyst-B) → line 1125: *"Stage 1 did not produce required artifacts"*
- Run Analyst-B anyway → line 1131: exit 4, *"ASSESSMENT BLOCKED — selected STRIDE coverage incomplete"*

Observed exactly this: stopped before Analyst-B → missing-artifacts abort → followed the
documented cut-off recovery → merge+triage ran (~20 min, $5.75) → killed by exit 4.

`post_stage1` **never reads the wave-plan state**. `.dispatch-waves.json` appears in
`orchestration_controller.py` only at lines 70 and 106 — cleanup name lists. The two gates
are mutually blind, so the controller cannot report "legitimately blocked" instead of
"you failed to produce artifacts".

The `check_stride_dispatch.py` call site at :1131 pre-dates `2150b13`; what `2150b13` added
(+38 lines) is the new exit-4 condition that now fires there. The cheap pre-merge gate is
**LLM-prose only, never code-enforced** — the only deterministic coverage gate sits strictly
*after* the expensive stage it exists to prevent.

**Fix:** have `post_stage1` read `.dispatch-waves.json` first and return a distinct
`blocked` action (with the blocked component list) before the artifact precondition.

---

## D2 — Pre-seed placeholder is indistinguishable from a genuine partial result (BLOCKER)

`agents/appsec-stride-analyzer.md:237-246` mandates a write-first pre-seed:
`partial: true`, all six `skipped_categories`, `threats: []`. Category overwrites happen
only *as each category completes* (`:244`) — granularity is per-category, not continuous.

`scripts/stride_dispatch_waves.py:138-159`:

```python
if data.get("partial") is not False:
    return "partial is not false"
if data.get("skipped_categories") != []:
    return "skipped_categories is not empty"
```

An agent that dies **before its first completed category** leaves a file byte-identical to a
genuine zero-coverage partial. The gate cannot tell "never started" from "honestly reported".
No `seed_only` sentinel, no turn-stamp, no freshness field.

Retry budget is hardcoded `>= 2` at `stride_dispatch_waves.py:225` and again at `:115-116`.
No env var, no flag, no force mode (`--manifest` / `--concurrency` are the only CLI options).
Attempts **persist across parent-session resume**, so restarting does not help.

Live evidence: `.stride-data-persistence.json` = `partial:true, skipped_categories:6,
threats:0` after 2/2 attempts, neither of which logged a single STRIDE category.

**No documented recovery exists.** Repo-wide grep for `blocked_components` /
`retry budget exhausted` / `coverage is incomplete` in `docs/`, `skills/`, `AGENTS.md`
returns no operator guidance. `clean-run-state` doesn't mention `.dispatch-waves.json`.
The only path that clears it is `modes/rebuild-wipe.md:62` — a full `--rebuild` that discards
the merge+triage work already paid for.

**Fix:** stamp a `seed_only: true` (cleared on first real overwrite) so the gate can
distinguish, and expose a targeted attempt-counter reset.

---

## D3 — Compaction deleted executable CLI contracts (root cause of the day's friction)

`data/context-budgets.yaml`, in `71eeb70` alone:

```
-  thin_full_pre_stage2_max_bytes: 92000
+  thin_full_pre_stage2_max_bytes: 31000     # −66% in one commit
```

Stage-1 instructions went from ~57KB of literal, runnable commands to a 6800-byte ceiling —
**~8× compression**. Current occupancy leaves no headroom to restore anything:

| Surface | Size | Budget | |
|---|---|---|---|
| `SKILL-thin-stage1.md` | 6468 | 6800 | 95% |
| `SKILL-thin-stage1c.md` | 2429 | 2600 | 93% |
| `SKILL-thin-stage2.md` | 2519 | 2700 | 93% |
| `SKILL-full-runtime.md` | 12768 | 13250 | 96% |
| `SKILL.md` | 8152 | 8500 | 95% |

What was lost is **syntax**, while **intent** was kept:

**`log_event.py`** — real contract: kinds are `phase-start|phase-end|step-start|step-end|info`
(`log_event.py:61-67`); `info` needs 5 positionals `<dir> info <event> <detail>` (`:222-228`).
`SKILL-thin-stage1.md:17-18` says only *"Log `PARALLEL_STRIDE_RESOLVED` via
`scripts/log_event.py`"* — names a payload, never the kind. Took 3 attempts to get right.
`SKILL-impl.md:2158-2161` **still contains the correct runnable command.**

**`record_stage_stats.py`** — `output_dir` is positional (`:264-269`), there is no
`--output-dir`. `--subagent-type`/`--since-iso` must be passed together (`:409-413`) or
dispatch derivation is silently skipped — this warned on *every* accumulate call in the run.
`--model` defaults to `"—"` (`:281`), which the deterministic heuristic (`:377-389`) reads as
an explicit deterministic marker, producing the bogus *"claims deterministic, but tokens=…
indicate an LLM dispatch"* warning on every row.
`SKILL-impl.md:2276-2314` had all three calls verbatim, using
`${STAGE1_START_ISO:+--subagent-type … --since-iso "$STAGE1_START_ISO"}` — a bash idiom that
made the pairing violation **structurally impossible**. That guard rail is gone.

**The information still exists but is contractually unreachable:** `SKILL-thin-stage1.md:4`
states *"do not read Stage 1 from `SKILL-impl.md`"* — the file holding the correct commands.

**Why CI is green:** `tests/test_context_prompt_budgets.py:11-100` asserts byte sizes;
`:103-136` does literal substring checks for a hand-picked phrase list — none referencing
`log_event.py`'s kinds or `record_stage_stats.py`'s flags. `tests/test_log_event.py` and
`tests/test_record_stage_stats.py` test the scripts in isolation and contain **zero**
references to any `.md`. Nothing validates that instruction files remain *executable*.
A compaction pass optimized against a byte-budget test has no signal that it is deleting
the only copy of a working command line.

### Predicted next failures (same class, not yet fired)

1. `SKILL-thin-stage1c.md:52-55` and `SKILL-thin-stage2.md:38-41` **never name
   `record_stage_stats.py` at all** — the script is unguessable from the prose.
2. `SKILL-thin-stage2.md:38-41` says *"pass both specialist subagent types"*. `--subagent-type`
   takes **one comma-separated value** (`record_stage_stats.py:143`). Repeating the flag makes
   argparse keep only the last → Stage-2 dispatch count and wall-time silently under-report.
   **Silent wrong data, not a loud error** — worse than the two failures already observed.
3. `SKILL-thin-stage1.md:126` references `stall_notice.py` with no output_dir and no `--stage`
   value; only `output_dir` is positional (`stall_notice.py:92-96`).

---

## D4 — False `SESSION_ABORTED_MIDRUN` alarms (7× in one run)

`scripts/agent_logger.py:1921`: `reason = data.get("stop_reason", "unknown")` — `unknown` is
the **absent-key default**, not an abort signal.

`scripts/aggregate_run_issues.py:710-713` already documents this:
> *"the Claude Code Agent tool returns `stop_reason=unknown` for every successful sub-agent
> dispatch in Subscription mode … a transport limitation, not a problem"*

But `agent_logger.py:210` `_CLEAN_STOP_REASONS = {"end_turn", "stop_sequence"}` omits
`unknown`, so `_mark_checkpoint_aborted_if_dirty` (`:213-270`) rewrites the checkpoint to
`status=aborted` and `handle_stop` (`:2002-2018`) emits the WARN. **Two modules disagree on
what `unknown` means.**

The Stop hook fires **per checkpoint, not once per session** (`agent_logger.py:728-730`);
one session logged 13 `SESSION_STOP` lines with monotonically growing cumulative usage.

Proof it was a false alarm: `SESSION_ABORTED_MIDRUN phase=11` fired at 16:24:12, yet the same
session wrote `threat-model.yaml` (16:25:40), logged `PHASE_END [Phase 11/11]` and
`ASSESSMENT_END … threats=56` (16:26:29). Final checkpoint: **`phase=10b status=completed
need_render=true`**.

Operational cost: mid-run I read the transient `status=aborted` checkpoint and reported to the
user that the agent had died. It had not. This mislabel actively misleads operators.

---

## D5 — `MAX_TURNS` (22) and `maxTurns` (40) are different units

- `agents/appsec-stride-analyzer.md:6` frontmatter `maxTurns: 40` — hard harness ceiling.
- `:116` `MAX_TURNS` from the manifest (22 for moderate) — soft in-prompt pacing target only.
- `scripts/budget_watchdog.py:43` keys thresholds off the **frontmatter 40**, not the manifest 22.

`data-persistence` (manifest `max_turns: 22`) burned both attempts against the real 40-turn
ceiling without completing one category. Retries restart from turn 0 with no resumption of
Step-2 reading (`appsec-stride-analyzer.md:246`), so attempt 2 reproduced attempt 1 exactly.

---

## Not supported by evidence: lazy loading did **not** cause the cache blow-up

The 21.6M cache_read / $11.70 session is **not** attributable to today's lazy-load commits.

`tests/test_lazy_phase_group_loading.py:125-134` (`test_phase_boundary_reads_are_unique`)
asserts each phase-group file's `Read()` appears exactly once — that work added enforcement
*against* redundant re-reads. `agents/phases/phase-group-architecture.md:1039-1053` carries
explicit single-read constraints.

The real driver is pre-existing and self-documented at `SKILL-impl.md:648-654`: a long-lived
orchestrator session re-serves a growing prefix on every dispatch, and `_usage_from_transcript`
(`agent_logger.py:1861-1917`) **sums usage across every assistant turn**, so the figure is
cumulative, not per-turn.

**Real gap:** the `SESSION_BLOAT` guard (`SKILL-impl.md:631`, 8M threshold) never fired despite
cache_read crossing 8M at 16:06 — it is only evaluated at *new dispatch boundaries*, and this
was one continuous 70-minute session. The guard cannot see the case it was built for.

---

## Priority

| | Defect | Severity | Blast radius |
|---|---|---|---|
| D1 | Gate deadlock | **Blocker** | Any run with one incomplete component dies after paying for merge+triage |
| D2 | Pre-seed ≡ partial, no escape hatch | **Blocker** | Same trigger; no recovery short of full `--rebuild` |
| D3 | CLI contract drift | High | Fires per run; 3 more latent, one of them silent |
| D4 | False abort alarms | Medium | Misleads operators; corrupts checkpoint mid-flight |
| D5 | Turn-cap unit mismatch | Medium | Under-budgets heavy components into guaranteed 2× failure |

D1 + D2 compound: D2 produces the blocked component, D1 turns it into an unrecoverable run.
Fixing either alone restores forward progress.

**Systemic root cause for D3:** byte-budget tests gate the instruction files, but no test
gates their executability. Recommend a test that extracts every `scripts/*.py` invocation
from `SKILL-thin-*.md` and validates it against the script's argparse contract.

---

## Implemented (2026-07-20) — proof-by-failing-test, then fix

Two new suites encode the defects; each failed against the pre-fix tree.
Full suite after all changes: **10031 passed, 93 skipped, 0 failed.**

`tests/test_thin_runtime_regressions_2026_07_20.py` — 8/9 failed pre-fix:

| Defect | Fix |
|---|---|
| D6 `AGENT_ERROR`/`RENDER_FAILED` dropped despite docstring | `aggregate_run_issues.py:521-556` match tuple + category map |
| D8 `wall_secs=?` on 211/211 | `agent_logger.py` disk-backed dispatch times via the existing `_active_tool_path` sidecar idiom |
| D3 `log_event.py` kind never stated | exact command restored in `SKILL-thin-stage1.md` |
| D3 `record_stage_stats.py` prose-only | exact commands in all three stage runtimes, incl. the `${VAR:+...}` pairing guard |
| D3 `--subagent-type` repeated-flag trap | comma-joined form documented in `SKILL-thin-stage2.md` |
| D3 compaction pressure | budgets raised; a **band** (ceiling + ≥10% headroom floor) replaces the bare ceiling |

`tests/test_stage1_coverage_recovery_2026_07_20.py` — 9 tests:

| Defect | Fix |
|---|---|
| D1 deadlock | `post_stage1` checks wave coverage **before** the artifact precondition and names the blocked components; an orchestrator that correctly stopped is no longer blamed for missing artifacts, and no longer pays for merge+triage before dying |
| D5 turn budget blind to footprint | `classify_component._footprint_turn_floor` — `max(tier budget, files + 8 context reads + 10 write/log reserve)`, capped at 48; wired through `build_stride_dispatch_manifest._component_max_turns` |
| D5 hard ceiling below new floor | analyzer frontmatter `maxTurns: 40 → 56` (48 + 8 buffer); `EXPECTED_MAX_TURNS` updated |
| D2 pre-seed ≡ partial | `seed_only` sentinel in `schemas/stride.schema.yaml`, written/cleared per the analyzer contract, consumed by `stride_dispatch_waves.completion_error` |

Verified against the real repo (`_component_max_turns`, production call path):

| Component | Files | Was | Now |
|---|---|---|---|
| `data-persistence` | 24 | 22 | **42** |
| `realtime-channel` | 2 | 15 | 20 |
| `frontend-spa` | 374 | 22 | 48 (capped) |

**Scope limit, stated honestly.** The floor targets mid-size components (~15–40 files)
where exhaustive reading looks feasible to the analyzer but does not fit the budget —
the `data-persistence` failure mode. Wide components (`frontend-spa`, 374 files) are not
covered by the floor and do not need to be: the analyzer samples them rather than reading
exhaustively, which is why it completed in 40 turns. The 48 cap deliberately prevents
over-provisioning that case.

### Round 2 — remaining items closed

`tests/test_run_diagnostics_recovery_2026_07_20.py` — 13 tests. Full suite: **10044 passed**.

**D6 evidence-verifier.** Three separate causes, all closed:
- *Wrong layer.* `guard_evidence_verification.py` plus an inline content check now run at
  the Phase-10a→10b boundary in `phase-group-threats.md`, where the consumer is — not in the
  Stage-2 emitter pass minutes later. The gate now also forbids compound-chain elevation of
  `effective_severity` when the refutation signal is missing, instead of rating on evidence
  that was never verified.
- *Capacity.* `maxTurns: 40 → 60`. The budget must satisfy `N + 2·ceil(N/5) + 3`; a standard
  38-finding sample needs ~57. A test now pins this arithmetic so a future cap change cannot
  silently outgrow the budget again.
- *Stale guidance.* The ⅔ turn guard said "turn 20 of 30" while the ceiling was 40. Now
  derived from and tested against the frontmatter value.

**D7 aggregator blindness.** Three independent mechanisms had to be fixed, not one:
- *Matcher* — `AGENT_ERROR`/`RENDER_FAILED` added (round 1).
- *Outcome discarded* — `_extract_run_outcome` turns `reconcile_recovered_events` into a real
  `run_incomplete` error instead of a log line no extractor reads.
- *Scoping* — this was the reason the round-1 matcher fix alone changed nothing. The
  90-minute sliding window assumed "the longest thorough run is ~40 min"; the run spanned
  **147 min**, so its own `AGENT_ERROR` (93 min before the last entry) was discarded before
  any extractor ran. Scoping now uses `.scan-start-epoch`, the exact per-invocation boundary
  (`cutoff_cause.py` already read it for this purpose), falling back to the heuristic only
  when the marker is absent.
- *Never invoked on abort* — `_aggregate_issues_on_abort` hooks the single choke point every
  controller abort passes through, so `.run-issues.json` is populated for the runs that need
  it most.

Verified against the real failed run: `run_status: clean, 0 errors` → **`issues`, 2 errors**
(`agent_error`, `run_incomplete`).

**D8 retry budget.** `APPSEC_STRIDE_MAX_ATTEMPTS` (default 2, hard ceiling 5, cannot lower
below the default) replaces the hardcoded `>= 2`; the schema maximum moves 2 → 5. Both the
controller abort and the CLI now name the override *and* state the precondition: fix the
structural cause first — an override is not a licence to retry the same thing harder.

### Round 3 — causal fixes

**D5 complexity drift → evidence floor.** The first attempt at this was symptomatic: it
replaced the `auth-*` enumeration in `classify_component._to_canonical` with a prefix rule.
Tracing further showed `classify_component` **is not called on this path at all** —
`build_stride_dispatch_manifest.py:1032` reads the complexity straight out of
`.components.json`:

```python
complexity = (c.get("complexity") or "moderate").lower()
```

So the risk tier is an LLM judgement, not a measurement, which is why the same commit
classified the same auth code `complex`/31 in one run and `moderate`/22 in the next. No
naming rule can fix that — the next inventory may say `identity-provider`.

The causal fix uses evidence that already exists before classification runs:
`.source-auth-findings.json`, written by a deterministic pre-flight scanner (48 findings
across 17 files on juice-shop). `_evidence_complexity_floor` raises any component that owns
auth-carrying files to `complex`, matched via `_path_owns` so glob forms work. Against live
data: `auth-service` moderate → complex (`lib/insecurity.ts`), no other component moved.
The prefix rule is retained only as defence in depth for callers with no scanner artifact.

**D2a follow-up — the footprint count was blind to `**`.** `Path.glob("routes/**")` yields
directories, not the files inside, and `_glob_files` keeps only `is_file()` hits. Component
inventories use exactly that form, so the floor counted 2 files for backend-api (actually
324) and 0 for frontend-spa (actually 637) — it was blind to precisely the widest
components. `_expand_recursive` fixes the count; `sqlite-db` now resolves to 42 turns, the
value the original failing component needed.

### Diagnosed, not fixed: per-dispatch timing has the wrong key

`wall_secs` cannot be repaired by persistence alone. `agent_logger.py` keys dispatch times
by `sid[:8]`, but **every dispatch in a run shares one sid** — verified on both runs
(`9617b066`, `6f373f38`: 23 dispatches, 1 distinct sid; 211 completes, 1 distinct sid). The
key is per-session while the measurement is per-dispatch, so a parallel wave of eight STRIDE
analyzers overwrites one slot, and the first `AGENT_COMPLETE` pops it while the remaining
210 report `?`.

The same root cause explains the 211-vs-23 mismatch: `AGENT_COMPLETE` is emitted from
`handle_stop`, and the Stop hook fires per checkpoint, not per dispatch
(`agent_logger.py:728-730`).

Both would be fixed by emitting `AGENT_COMPLETE` from `PostToolUse(Agent)` keyed on
`tool_use_id` — the correlation idiom the codebase already uses for
`_active_tool_path`. It was **not** done here: `agent_logger.py:39-49` documents that
PostToolUse does not propagate through nested agent sessions, which is why both hooks exist,
and restructuring that while a scan was running was the wrong risk to take.

Note the pop is deliberately kept. Removing it would make every checkpoint report
"time since the most recent dispatch" under the name `wall_secs` — a plausible-looking
number nobody would recognise as wrong. `?` is the honest answer until the key is fixed.

### Still open

- **Thorough-depth verifier sampling.** At `--thorough` the cap is 100 non-Criticals plus
  uncapped Criticals (~108), needing ~155 turns against 60. This is accepted rather than
  fixed: the ⅔ guard flushes in Critical→High→Medium order, so the outcome is honest partial
  coverage of the highest-severity findings, with the remainder reported as `unchecked`. It
  is a real limitation, not a silent one — but a joint (Critical-inclusive) cap would be the
  principled fix.
- **`aggregate_run_issues.py` docstring** still claims `.appsec-trace.log` is an input; it
  has never been read (0 references). The trace log is where the 23-dispatch / 211-complete
  mismatch and the `wall_secs` data live, so wiring it in would add real signal.

---

## Follow-up e2e run 2026-07-23 (juice-shop) — coverage recovered, QA-blocked

This run completed Stage-1 and produced a report where the 2026-07-20 dead end did not: the
`APPSEC_STRIDE_MAX_ATTEMPTS` escalation (D8) let it self-heal and cover all 9 selected
components. But two producer defects surfaced, and the delivered report was QA-blocked as
non-releasable. Both root-caused and fixed.

### R1 — STRIDE `TH-UNCLASSIFIED` aborts a run the pipeline can already repair (fixed `8925c38`)

`express-backend-008` (CWE-601, Open Redirect) was written with
`threat_category_id: "TH-UNCLASSIFIED"`. The per-component gate
`stride_dispatch_waves.completion_error` → `validate_intermediate.validate_stride` rejects
that sentinel (`^TH-[0-9]{2}$` required for `source=stride`), so the component burned its
whole retry budget and hard-aborted the run — **even though CWE-601 → TH-18 is in
`data/threat-category-taxonomy.yaml` and `merge_threats._threat_category_id_for` returns it
deterministically.** The repair existed; it just ran *after* the gate (in merge), which the
gate blocks the run from ever reaching.

**Fix:** extracted `merge_threats.backfill_threat_category_id`; `completion_error` now
applies it before `validate_stride` and persists the canonical id. Genuinely unmappable CWEs
keep the sentinel and still fail. Not a taxonomy gap — an ordering defect
(validation-before-backfill). Cost this run: express-backend dispatched 3× (~44% STRIDE
retry waste) on a defect the pipeline already knew how to fix.

### R2 — §6 SecArch renderer emits id-in-link-text references (fixed `5de7021`)

The §6 Security Architecture narrative cites findings as `[F-NNN — Title](#f-nnn)`, pulling
the title into the link text. `check_reference_format._ID_IN_LINK` (tightened in `27a0d9f`)
forbids exactly that shape → 53 violations → QA `repair_required`, non-releasable. No pass
converted it (`_bulletize_relevant_findings` only handles the bare `[F-NNN](#f-nnn)` form).

**Fix:** deterministic `compose._delink_id_in_link_text` (inverse of the linter regex)
rewrites to canonical `[F-NNN](#f-nnn) — Title` in the final reference pass, before locator
normalisation. Verified on the run's report: 53 → 0. Link syntax is normalised
deterministically, never trusted to the LLM.

### `web3-nft: missing output` — a wave-gating artifact, not a failure (covered by R1)

The abort listed `web3-nft: missing output` and hypothesised "turn budget too small for its
file footprint". Both misleading. `.dispatch-waves.json`: 9 components at concurrency 8 →
wave 1 = 8, **wave 2 = `[web3-nft]` alone**. `status()` only advances `next_wave` past a wave
with zero incomplete (`stride_dispatch_waves.py:245`), so wave 2 never dispatched while wave 1
was blocked by express-backend's `TH-UNCLASSIFIED` (R1). `all_incomplete` collects across
*all* waves (`:237`), so a never-dispatched wave-2 component reads as "missing output",
indistinguishable from a real failure. Proof: `attempts.web3-nft == 1` — one dispatch,
immediately successful (7 threats) once R1 unblocked wave 1. R1 removes this run's trigger; a
4-file / 22-turn component was never budget-starved.

**Diagnosed, not fixed — the abort conflates not-reached with failed.** D1's fix names blocked
components but does not distinguish "dispatched & failed" (express-backend) from "never
reached, gated behind an earlier wave" (web3-nft), and appends a generic turn-budget
hypothesis that is wrong for wave-gated components. This misdirects operators — it misdirected
this investigation. A fix would label wave-gated incompletes "not reached — blocked by wave N".
Deferred: cosmetic, touches the `status()` payload + abort builder + tests, low urgency.

### Not a defect — `toc_closure` SAF anchors

The QA plan flagged 4 unresolved `#saf-016/025/027/001` anchors. **The final report has
`check_toc_closure == 0`.** The secarch fragment uses `SAF-NNN` as plain-text labels (zero
`](#saf` links). The QA plan (`.qa-repair-plan.json`, 06:05Z) linted a render superseded by
the fragment + md rewrite 7 min later (06:12Z). No broken anchor ships.

**Adjacent observation (not chased):** the QA verdict mixed a real issue still in the final md
(R2 reference_format) with one already gone (SAF). QA may lint a non-final render — a
freshness / ordering question worth a separate look if it recurs.
