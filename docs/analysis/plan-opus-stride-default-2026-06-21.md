# Implementation plan: Opus as default for STRIDE reasoning (except `quick`)

Status: **PLAN — NOT implemented. Code claims verified 2026-06-21** (file:line +
consumers checked against `scripts/resolve_config.py`; corrections incorporated). Follows
the recommendation from
[`analysis-model-placement-orchestrator-vs-stride-2026-06-21.md`](analysis-model-placement-orchestrator-vs-stride-2026-06-21.md).

Goal: **unified use of Opus for the reasoning phase** (STRIDE/triage/
merge) at `standard`/`thorough`. `quick` stays on Sonnet (deliberately shallow mode). The
size-triggered auto-downgrade to all-Sonnet is dropped.

---

## 0. Decision / scope

- **"Opus for STRIDE" = the full `opus` tier** (stride **+ triage + merger** on Opus).
  Rationale: the calibration gain comes from `triage=opus`, the cost saving from
  `stride=opus` — only together do they produce the measured V3 result (better **and** on
  large repos cheaper). A "stride-only" tier would leave calibration half done
  and introduce a new, unnecessary tier.
- **`quick` untouched:** stays `sonnet-economy` (reduced STRIDE depth, Sonnet
  fits). Sonnet STRIDE is legitimate only there + with explicit opt-out.
- **Unification = flat, not size-adaptive:** default flat `opus` for
  standard/thorough, **no** automatic size switch anymore. Small repos cost somewhat
  more — a deliberate trade-off in favor of uniformity + quality; opt-out via
  `--reasoning-model sonnet-economy` / `--max-cost`. (The size-adaptive *inversion* —
  small→economy, large→opus — is noted as optional Phase 4, not part of the
  core plan.)

---

## 1. Verification gate (Phase 0 — recommended, not mandatory)

The cost inversion is **N=1** (only Juice Shop, large repo). Before the flat flip,
recommended: **Stage-0 matrix** on 1 small + 1 medium repo, each
`sonnet-economy` / `opus-cheap` / `opus`. Delivers:
- the missing `opus-cheap` data point (isolates whether STRIDE-on-Sonnet is the cost driver
  or triage/merger),
- whether the cost inversion flips on small repos (expected: yes → confirms the
  opt-out need, not the direction),
- real Opus standard **wall time** (V3 was idle-contaminated) → input for the
  duration recalibration in Phase 3.

Decision rule: the **direction** (Opus reasoning as default) does **not** depend on the
result — it is carried by quality (calibration/evidence/surface). Stage 0
only calibrates magnitude + duration. Whoever wants to skip the gate can go straight to
Phase 2; then Phase 3 with a conservative estimate instead of a measurement.

---

## 2. Core change (producer: `scripts/resolve_config.py`)

### 2a. Change the default tier
`resolve_reasoning_model` (~line 498-501): `standard`/`thorough` default
`"opus-cheap"` → `"opus"`. `quick` stays `"sonnet-economy"`.

```
elif depth == "quick":
    mode = "sonnet-economy"
else:
    mode = "opus"          # was: "opus-cheap"
```

### 2b. Remove the size downgrade  *(verified 2026-06-21)*
**Remove** `resolve_default_tier_for_capped_repos` (B2d, line 415) + the call site **line 1508**
(`cfg.update(resolve_default_tier_for_capped_repos(cfg, ns))`). With the new
default `opus`, B2d would no-op anyway (guard `!= "opus-cheap"`), but out it goes as a dead path
with the wrong philosophy.

- **Keep** `resolve_repo_size_cap` (line 373), but only as **label-informative**
  (`repo_size_capped`, `repo_size_source_files`, `depth_label` markers). It reduces
  no components anyway (comment line 383-385). **Note:** the B2d docstring line 433
  ("the large-repo cap reduces MAX_STRIDE_COMPONENTS to 3") is **stale** — no code
  reduces this; `max_stride_components` = `STRIDE_COMPONENT_CEILING = 10` (line 209/298),
  depth-independent. Dropped with B2d.
- **Verified: `repo_size_capped` has 3 consumers, ALL display-only** (no
  behavior) → removing B2d is behavior-safe. BUT both display notes say
  "→ economy reasoning tier" and become **wrong** after the change → change the text too:
  - `scripts/resolve_config.py:2196` (config summary note)
  - `scripts/resolve_config.py:2536` (post-summary note) ← *overlooked in the first plan*
  - `skills/create-threat-model/SKILL-impl.md:1171` (label string)
  New wording e.g.: "Large repo (<N> source files) → longer run expected; reasoning
  stays on the default Opus tier (all criteria-selected components analyzed)."
- `reasoning_auto_switched`: no longer set (only in B2d, line 471). The only reader
  is **`scripts/resolve_config.py:2359`** (display-only, `_format_reasoning_summary`) →
  becomes a dead branch → remove along with it.
- **Existing "all→Sonnet" opt-out is preserved:** `--no-opus` / `opus_disabled`
  (resolver ~line 609 "Opus→Sonnet ceiling", display line 2358). After the change this is
  the clean way to force the new Opus default entirely onto Sonnet — alongside
  `--reasoning-model sonnet-economy`.

### 2c. `opus-cheap` from default to pure opt-in
**Keep** `opus-cheap` in `MODEL_MATRIX` (explicit `--reasoning-model opus-cheap`
stays valid for users who want the middle ground), but it is **no longer a default**.
Add a comment on `MODEL_MATRIX["opus-cheap"]`: "explicit opt-in only; not any
depth's default since 2026-06 — see analysis-model-placement". No hard deprecation,
no removal (avoids a breaking change for existing scripts/`--reasoning-model`).

---

## 3. Accompanying contracts (bidirectional, AGENTS.md §4)

### 3a. Tests (mandatory — pins today's defaults/labels)
Affected files with **verified** hit counts (2026-06-21, regex
`opus-cheap|sonnet-economy|repo_size_capped|reasoning_auto_switched|"opus"|reasoning_model`):
- `tests/test_resolve_config.py` — **56 hits** (not ~33) — change the default and
  label assertions; remove/adapt B2d tests. **Largest effort item.**
- `tests/test_reasoning_model_resolution.py` — **31** — default resolution
  standard/thorough (`opus-cheap` → `opus`).
- `tests/test_haiku_routing_per_depth.py` — **24** — extended routing stays unchanged
  (Haiku scanners are tier-independent), but check the default-tier assumptions.
- `tests/test_estimate_duration.py` — **4** — anchors/model factor (Phase 3b).
- `tests/test_render_completion_summary.py` — **5** — reasoning-label display
  (incl. the dead `reasoning_auto_switched` branch, if tested there).

Choose the direction per cluster deliberately (test-vs-code): default flip = code leads, tests
follow; but check whether a test protects an *invariant* (then the test leads).

### 3b. Duration/cost estimation (`scripts/estimate_duration.py`)
- Anchor comments line 63-64 to the new default (`opus` instead of `sonnet-economy`/`opus-cheap`).
- `_MODEL_FACTOR`: leave `opus: 1.40` for **duration** for now (Opus latency is real;
  recalibrate exactly after the Stage-0 wall measurement). Note: the *cost* assumption behind
  1.40 is refuted — if estimate_duration derives a cost component from it,
  decouple that (duration ≠ cost).
- Banner estimate: standard costs rise (Opus reasoning). Update the values once
  Stage-0/a real run is available; until then conservative + marked as an estimate.

### 3c. User-facing surfaces
- `skills/create-threat-model/SKILL.md` + `SKILL-impl.md`: config summary / depth labels /
  possibly advisory notes on the new default; search for default mentions (`opus-cheap`,
  "economy tier").
- `docs/threat-modeler.md`: cost table (standard ~$17.37 etc. rises), default-model
  description; the already-added Opus reasoning TIP becomes consistent with it.
- `scripts/run-headless.sh` + `HELP.txt`: `--reasoning-model` default/help text.
- `scripts/render_completion_summary.py`: reasoning-label choices/display.

### 3d. Permissions
`data/required-permissions.yaml`: **no change** — model routing adds no new
Bash command / write target / sub-agent dispatch. (Double-check briefly during
implementation.)

---

## 4. Optional / later — size-adaptive inversion (NOT in core scope)

If small-repo costs become a problem: **invert** the B2d logic instead of removing it —
small/simple repos → `sonnet-economy` (no thrash to save), large/complex → `opus`.
That is more logic + more tests and contradicts the "unified" goal; therefore
deliberately kept out of the core plan. The prerequisite would be robust Stage-0 evidence
on the crossover point.

---

## 5. Rollout / verification of the implementation

1. (Phase 0) Run the Stage-0 matrix → confirm magnitude + wall.
2. Code changes 2a–2c, then get tests 3a green.
3. `make lint` / `make test` (subset per CONTRIBUTING "Targeted tests"; separate baseline fails
   from new ones).
4. A real `standard --full` run against Juice Shop **from a Sonnet session** →
   confirms: STRIDE runs on Opus (`.agent-run.log` shows Opus dispatches,
   `.skill-config.json` `stride_model=opus`, `reasoning_label` new), cost/duration in the
   expected range, report quality (severity distribution) like V3.
5. Finalize the documentation estimates (3b/3c) with a real run.

## 6. Rollback

Pure config/default change, no schema/data migration. Rollback = default in
`resolve_reasoning_model` back to `"opus-cheap"` + restore B2d + revert tests.
The user opt-out (`--reasoning-model …`) works in both directions the entire time,
hence low risk.

## 7. Risks / open points

- **Small-repo extra cost** (deliberate trade-off; opt-out available). N=1 for the
  inversion → Phase 0 mitigates this.
- **Duration estimate** conservative for now, without a clean Opus wall measurement.
- **Test-pin scope** (**56** in `test_resolve_config.py` + 31 + 24 in the others,
  verified 2026-06-21) is the largest effort item.
- **Config-summary/label strings** possibly duplicated in several places → enumerate before
  editing (grep for `opus-cheap`, `sonnet-economy (auto`, `reasoning_auto_switched`).
