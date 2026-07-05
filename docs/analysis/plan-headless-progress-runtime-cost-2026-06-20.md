# Plan: headless progress + runtime + cost (analysis, NOT implemented)

Status: Element 1+2 **IMPLEMENTED** 2026-06-20 (branch feature/skill-impl-sonnet-cleanup),
Element 3 still **deferred** (dry token pipe). Three display elements in a
periodic headless liner + end summary: (1) rough percent progress, (2) net
runtime (total − standby), (3) cost (actual + API-equivalent).

IMPLEMENTATION Element 1+2 (`scripts/skill_watchdog.py`): new `RUN_PROGRESS` event in the
60s watchdog loop (section 7d). Weights from `estimate_duration._PHASE_DURATION`
(guarded import), depth from `.skill-config.json`, phase from `.appsec-checkpoint`,
wall from `.scan-start-epoch`, standby = cumulative RUN_RESUMED peaks (`idle_total`).
Percent clamped monotonically, lower-bound (completed phases), `status=completed`→100.
Only for timeable runs (scan-start-epoch present). 6 new tests, suite 56 green,
ruff clean. Cost deliberately NOT in the liner.

Guiding principle: **small solution**. No new infrastructure where existing infrastructure is reusable.
All deterministic Python in the existing 60s watchdog loop + end summary.

---

## Element 1 — rough percent progress  (effort: SMALL, all building blocks present)

The building blocks exist:
- The current phase is durably on disk: `.appsec-checkpoint` (`phase=<N>`),
  parsed in `acquire_lock.py:181-230` (`_current_phase_label`).
- A periodic emitter exists: `skill_watchdog.py:593-647`, 60s loop, knows the phase,
  calls `event_log.format_line()`. New line is additive, no schema constraint.
- Weighting: TWO independent phase-weight tables exist (not one!) —
  choose, don't mix:
  - `data/phase-budgets.yaml` — wall-time budget per phase × depth; maintained for
    watchdog stall classification. Only 1/2/3/9/10b/11 explicit, 4–8 = fallback.
  - `scripts/estimate_duration.py:164` `_PHASE_DURATION` — its own hardcoded
    minutes table per depth, WITH fractional weights (line 451-457: ×0.5/×0.3 for
    phases 3–6). The sum-over-phases pattern already exists there (resume remaining time).
  - Recommendation: `_PHASE_DURATION` is the finer basis (covers 4–8), but for
    consistency with the stall logic possibly `phase-budgets.yaml` + fallback. Pick one source.

Calculation: `pct = Σ(weight[completed phases]) / Σ(weight[all phases])`.

Honest limits (why "approximate"):
- Checkpoint granularity = whole phases → the value stands still for minutes in long phases (esp. phase 9
  STRIDE).
- Phase list hardcoded + SCATTERED (no central enum): `[Phase N/11]` echoes
  live in `appsec-threat-analyst.md` AND 4 phase-group docs (phase-group-recon/
  -architecture/-threats/-finalization.md, ~67 hits total). (Corrected: NOT
  at `appsec-threat-analyst.md:1154-1319` — that line reference was wrong.)
  `phase-budgets.yaml` lists only 1/2/3/9/10b/11 explicitly; 4–8 share
  `unlisted_phase_fallback_seconds` (180s) → with this table the curve stutters there
  (not with `_PHASE_DURATION`, since 4–8 have their own values there).
- Phase 2.5 conditional (`HAS_IAC_SURFACE`), incremental skips phases →
  the denominator is run-dependent, not constant.
- **Clamp monotonically** (never jump back on resume/incremental).

Optional refinement (NOT for the small solution): sub-progress only where it
exists — phase 2 recon `[k/26]`, phase 9 `.appsec-progress.json` (`step/step_total`).
More effort per phase, low added value for "just an impression". Omit.

---

## Element 2 — net runtime (total − standby)  (effort: SMALL-MEDIUM)

The building blocks exist:
- Run start durable: `.scan-start-epoch` (written `SKILL-impl.md:1866`,
  read `run_timing.py:226`). Wall = `now − scan-start-epoch`, trivial.
- **The end summary already computes net**: `render_completion_summary.py:918` →
  `run_timing.compute_timing(output_dir)` returns `net_compute_secs`, `wall_secs`,
  `standby_secs`; standby from event gaps (`_standby_from_event_gaps`). Renders
  "Net agent compute" + "Idle / standby". → **Nothing to build for the end.**

Mid-run gap (the only real piece of work):
- The watchdog tracks only the peak of the *current* stall (`run_idle_peak`), resets on
  `RUN_RESUMED`. There is NO running cumulative idle sum.
- Two ways:
  - (A, preferred) call `run_timing.compute_timing()` mid-run — reads the same
    logs/event gaps as at the end, authoritative, one source. O(N) log scan per tick
    (every 60s, cheap).
  - (B) grep `.agent-run.log` once for all `RUN_RESUMED` peaks and sum them.
    Less authoritative than (A); only choose if (A) doesn't run cleanly mid-run.
- Display: `elapsed 45m23s | net 38m11s (idle 7m12s)`.

Recommendation: way (A) — avoids a double definition of "standby" (watchdog peak vs
event gap). Same number mid-run as at the end = consistent.

---

## HARD REQUIREMENT (user, 2026-06-20)
Cost MAY only be displayed when it is CERTAIN — `/cost`-accurate, never
estimated. Estimated values (tokens × a hand-maintained table on broken inputs)
have always been wrong in the past. Better NO number at all than a wrong one.

Correcting an assumption: `/cost` is NOT an exact number billed by the backend. It
reads the same transcript `usage` blocks (API-reported, authoritative TOKEN counts)
× Claude Code's pricing table. There is NO cost number more authoritative than
tokens×price — not even `/cost`. Mid-run there is no accessible server `total_cost_usd`
(only at session end in the headless JSON, unreachable for a running skill).

→ "`/cost`-accurate" = read the same source as `/cost` CORRECTLY: authoritative usage across
the main + ALL sub-agent transcripts, with the correct price per model. Then by
construction = `/cost`. Earlier wrong values came from broken inputs (dry
SESSION_STOP pipe → undercounted; model flat-set to sonnet → wrong price; sub-agent
transcripts separate → aggregated with gaps), not from the tokens×price concept.

THREE-TIER DISPLAY POLICY (refined 2026-06-20): not binary. Uncertainty is
measurable — derive the tier from the signal, don't guess.

Uncertainty signal (from existing logs):
- `coverage` = agents-with-captured-usage / dispatched agents
  (SESSION_STOP-with-usage vs. AGENT_SPAWN in `.hook-events.log`).
- `model_known` = model per agent resolvable from AGENT_SPAWN `model=`.
- `price_current` = `PRICING_MODELS` keys checked against actually used model IDs
  (stale `opus-4-6` vs. Opus 4.8 = not current).

Tiers:
1. CERTAIN (coverage ~complete + model_known + price_current) → display normally,
   honest label "= /cost method". This is the parity-with-`/cost` tier.
2. SOMEWHAT UNCERTAIN (one condition wobbles: pricing table possibly outdated, occasional
   agents without usage) → display WITH a warning: `~$X (estimated, may deviate)`.
3. VERY UNCERTAIN (no/barely any usage captured — currently 0 SESSION_STOP; models
   unknown) → do NOT display at all. Better nothing than wrong.

Hard additional rule — MID-RUN always tier 3: still-running agents contribute 0, any
subtotal is a moving undercount → NEVER cost in the periodic liner,
regardless of the signal. Only element 1 (percent) + 2 (runtime). Cost exclusively
in the end summary, there tier 1/2/3 per the signal above.

## Element 3 — cost: ONLY at the end, ONLY /cost-accurate  (effort: MEDIUM — blocked by the source)

### What already exists AND is wired
- Pricing table: `config.json:7-11` + `verify_run_costs.py:49-68` `PRICING_MODELS`
  (sonnet/opus/haiku, input/output/cache_write/cache_read).
- Calculation + banner: `cost_running_total.py` (`aggregate_running_total`,
  `format_banner` → "↳ running total: 45k tokens, $0.18").
- Already called: `appsec-threat-analyst.md:356` (after phase 8, non-fatal),
  `SKILL-impl.md:1742` (budget check). **So the banner is already in the pipeline flow.**
- Model attribution: each `agents/*.md` frontmatter `model:`; dispatch override
  logged in AGENT_SPAWN (`agent_logger.py:_agent_model`).

### The real blocker (empirically verified 2026-06-20)
Token source = `SESSION_STOP` lines that the `Stop`/`SubagentStop` hook
(`agent_logger.py:handle_stop`, parses `transcript_path` usage) is supposed to write.
Hooks are registered (`hooks/hooks.json:33-48`).

**BUT: 0 SESSION_STOP in 3 real run logs** (`/tmp/tm-sonnet-standard`,
`/tmp/tm-phase-d-quick`, `/tmp/tm-verbose-quick`). Existing events only:
HEARTBEAT (watchdog), AGENT_SPAWN (PreToolUse), PHASE_*/SCAN_START (bash echoes).
No SESSION_STOP, no PostToolUse SCAN_COMPLETE, no BUDGET_*.

→ Stop/SubagentStop/PostToolUse hooks don't fire in these headless runs (or
deliver no usage). **Currently any cost display would be $0 / n/a.** The cost pipe
is wired, but dry.

To clarify before a cost display (root cause, separate investigation):
- Does `SubagentStop` fire at all in the `claude -p` headless path?
- Does the headless transcript deliver usage blocks to the hook?
- Is the plugin (and thus `hooks/hooks.json`) loaded in the juice-shop session?
  (Memory `gotcha_env_var_reaches_skill_bash`: cross-project settings don't always
  take effect — an analogous suspicion for plugin hooks.)

### Subscription vs. "what it would have cost"
The user runs on a subscription → marginal real cost ≈ $0. What's wanted is the
**API-equivalent hypothetical total** = tokens × list price. That's exactly the
number `format_banner` already produces. No subscription-markup logic needed —
just a label: "API-equivalent (hypothetical)". The `~$` convention for subscriptions is
already provided in QA/docs (`appsec-qa-reviewer.md`), calculation identical.

→ "Actual" and "API-equivalent" coincide for subscription users; the sensible thing
is ONE number with the label "hypothetical API cost ~$X (subscription: real $0)".

---

## Effort / order summary

| Element | Building blocks present? | Real work | Risk |
|---|---|---|---|
| 1 percent | phase+loop+weighting | helper: budget-sum/checkpoint→pct + 1 emitter line; budget phases 4–8 for a smooth curve | low |
| 2 net runtime | end summary already computes | call `compute_timing` mid-run + into liner | low-medium |
| 3 cost | pricing+calc+banner wired, but source dry | ONLY at end; authoritative transcript usage (main+all sub-agents) × price per model; guarantee parity with `/cost`, otherwise nothing | high — blocked, MID-RUN excluded |

Recommended sequence if implemented:
1. Element 1 + 2 together — both live in the same watchdog tick, share the one new
   liner format, zero external dependency, NO cost dependency. Immediately shippable.
2. Element 3 ONLY as an end-summary field, separately, AFTER:
   (a) root cause why SESSION_STOP/transcript usage isn't aggregated headless,
   (b) correct price-per-model attribution (not flat sonnet). WATCH OUT for price
       drift: `PRICING_MODELS` (verify_run_costs.py:49-68) has keys `opus-4-6`/
       `sonnet-4-6`/`haiku-4-5` — `opus-4-6` is outdated vs. the current Opus 4.8;
       such stale keys are exactly the cause of earlier wrong values → the table must
       be checked against the actually used model IDs,
   (c) proof of parity with `/cost` (same inputs → same number).
   Until (a)–(c) are proven: NO cost display. Better nothing than wrong.

Mid-run liner (WITHOUT cost — per the user rule):
```
  ~42%  |  elapsed 45m23s  net 38m11s (idle 7m12s)
```
End summary adds cost per tier (see policy above):
```
  Runtime: 45m23s (net 38m11s, idle 7m12s)
  # Tier 1: Cost (API-equiv, = /cost): $3.10
  # Tier 2: Cost (estimated, may deviate): ~$3.10
  # Tier 3: omit the line entirely
```
The runtime fields at the end already exist (`run_timing.compute_timing`).
