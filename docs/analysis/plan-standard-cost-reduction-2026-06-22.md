# Plan: standard-depth cost reduction — resume avoidance, threat/component cap, QA quick-fix

**Date:** 2026-06-22
**Trigger:** A `standard` run against juice-shop cost ~$44.73 (expected <$30). Diagnosis (two
causes, see cost analysis): (a) **one resume** (`RESUME:1`, heartbeat gap, ~98 min idle) → cold
prompt re-prefill → Sonnet cache-read 59.1m instead of ~26m (~+$10); (b) **genuinely more depth**: 89 STRIDE threats
across 9 components (vs. 77 in the comparison run), b2b as its own component + one additional
QA content-repair round. Both runs actually ran at `assessment_depth: standard`.

Goal of this doc: analyze how **(1) resume avoidance** and **(2) threat/component budget cap**
can be implemented at `standard`, plus **QA repair as a single quick-fix** instead of multiple rounds.

Status: **IMPLEMENTED 2026-06-22** (uncommitted). Done: **QA-A** (depth-aware
`max_repair_iterations`, quick/standard=1, thorough=3) + **2A as opt-in `--stride-cap N`**
(key-gated, Critical-safe, full depth otherwise preserved, meta disclosure). Lever 1 (resume) deliberately
not implemented on its own — addressed indirectly via fewer turns. Full suite green (8434 passed,
55 skipped), lint clean. Original analysis below unchanged as rationale.

---

## Key insight up front: 2 + QA reduce 1 indirectly

A resume arises primarily when the orchestrator exhausts the **turn budget** (`maxTurns: 300`,
`appsec-threat-analyst.md:6`) or an **external limit** (5h session, API stall) hits.
There is **no** default wall-clock SIGTERM that kills mid-phase (the earlier 1800s assumption was an
E2E `run-headless.sh --max-duration` invocation, not a default). So "resume avoidance" is only
directly controllable to a limited extent.

**But:** fewer threats (lever 2) and fewer QA rounds (QA quick-fix) mean **fewer
orchestrator turns** → lower probability of hitting the turn budget → **fewer resumes**.
Lever 2 + QA quick-fix are therefore simultaneously the best *practical* lever for lever 1.

---

## Lever 1 — resume avoidance

**Finding:** Largely external. `skill_watchdog.py` is observe-only (never kills; comment `:62`). RUN_IDLE/
RUN_RESUMED (`skill_watchdog.py:798-845`) only document stalls for reporting (`agent_logger.py:987-1055`),
they trigger no resume. The "real" resume is the cut-off recovery after turn-budget exhaustion
(`SKILL-impl.md` "Handling turn-budget cut-offs"), cap `MAX_STAGE1_RESUMES` default 1 (`SKILL-impl.md:651`).

Directly controllable options:

### 1A — make the turn budget depth-aware *(low benefit, not recommended as a primary lever)*
- Currently flat `maxTurns: 300` (`agents/appsec-threat-analyst.md:6`), `DEFAULT_MAX_TURNS=250`
  (`budget_watchdog.py:41`). standard needs less than thorough.
- **Risk/effort:** AGENTS.md `:143` pins "appsec-threat-analyst — Sonnet, 300 max turns" via regex
  (`tests/test_agent_definitions.py::TestAgentsMdDocDrift`). Change = frontmatter + AGENTS.md line +
  test together.
- **Caveat:** The real limit is the harness session, not `maxTurns` alone. Raising the turn budget only helps
  *if* the cut-off came from `maxTurns` — for an API stall / 5h window it does nothing. **Low expected value.**

### 1B — shrink the resumed prompt *(addresses resume *cost*, not frequency)*
- The expensive resume is the mid-phase-9 `STAGE1_CUTOFF` (re-entry with the full analyst prompt). `STAGE11_CUTOFF`
  is already restricted to the phase-11-only renderer.
- **Risk:** Phase-group lazy-load + cache order A→B→C are explicit non-obvious decisions
  (AGENTS.md `:125-126`), drift guard `tests/test_dispatch_prompt_cache_order.py`. Higher risk, fine-grained.

**Recommendation lever 1:** No standalone change as a primary lever. Lower resume frequency primarily via **lever 2 +
QA quick-fix** (fewer turns). Only pick up 1A if you're touching DEPTH_PARAMS anyway and carry the
turn budget there too. "Don't regress": leave the default with *no* `--max-wall-time` (otherwise self-inflicted resumes).

---

## Lever 2 — threat/component budget cap at standard

**Finding:** The desired mechanism **already exists and is wired end-to-end** — it's just switched off at
standard.

- `max_threats_per_category` (top-N per STRIDE category per component, Critical-safe) lives in the
  `QUICK_STRIDE_PROFILE` (`resolve_config.py:170-190`, value `1`).
- Gating in `resolve_stride_profile` (`resolve_config.py:582-612`): applies **only** when
  `reasoning_mode == "sonnet-economy" AND depth == "quick"`. At standard/thorough → `{"stride_profile_label":
  "full"}` = **no cap**.
- The consumer already reads it: `agents/appsec-stride-analyzer.md:281` (cap table), forwarding
  `phase-group-threats.md:414-426`, plumbing `SKILL-impl.md:840` (`STRIDE_PROFILE_JSON`).
- Banner: `compose_threat_model.py:1903`.

The **component count**, by contrast, is emergent (`select_stride_components`,
`build_stride_dispatch_manifest.py:626-688`); the flat ceiling `STRIDE_COMPONENT_CEILING=10`
(`resolve_config.py:214`) **only sheds `_is_internal_only`** (`:658-670`) and *lifts* acquired
(exposed/crown/cicd) components instead of dropping them (`EXPOSURE_CAP_LIFT`). → A component ceiling
does **not** apply in *this* 9-component run (b2b is exposed, not internal-only).

### 2A — enable `max_threats_per_category` for standard *(CORRECTED after verification: DESIGN REVERSAL, not "just ungate")*

> **Verification 2026-06-22 refutes the original "low risk / mechanism already wired" assessment.**
> Three hard blockers found:
>
> 1. **The consumer is label-gated, not key-gated.** `agents/appsec-stride-analyzer.md:116,276` activates the
>    entire cap table (incl. `max_threats_per_category`) **only** when
>    `stride_profile_label == "quick (depth-reduced via sonnet-economy)"`. A standard profile with a different label
>    does carry the key, but the analyzer **ignores it**. → The analyzer-prompt activation must be co-edited
>    (LLM-prompt contract, non-deterministic enforcement).
> 2. **A test nails down the opposite.** `tests/test_stride_quick_profile.py:80-94`
>    (`test_profile_full_outside_quick_haiku_economy`) checks for **exactly the user config** `("opus","standard")`
>    as well as `("sonnet","standard")`, `("sonnet-economy","standard")` etc.: `stride_profile_label == "full"` **and**
>    `max_threats_per_category NOT in profile`, with the intent message **"must keep full STRIDE depth — opt-in only"**.
>    This is a deliberate, documented design decision: STRIDE depth reduction is **quick-only / opt-in**.
>    2A **reverses this principle** → the test must be rewritten (= design change, not a bugfix).
> 3. **No standard banner path.** The `compose_threat_model.py` banner is hard-gated on `is_quick_depth`
>    (`if not ctx.eval_context.get("is_quick_depth"): return ""`). For transparency at standard a
>    **new** disclosure path would have to be built.

- **Producer:** `resolve_config.py:607-612 resolve_stride_profile` — add a standard branch (only
  `{"max_threats_per_category": 2, "stride_profile_label": "standard (per-category cap 2)"}`; **not** the other
  quick reductions like skip_cvss/skip_greps, since the user run used opus reasoning and full evidence/CVSS should
  stay at standard).
- **Consumer (mandatory, not optional):** `agents/appsec-stride-analyzer.md` — decouple activation of the
  `max_threats_per_category` rule from the quick label (e.g. "apply the cap as soon as the key is present in the
  STRIDE_PROFILE") + adjust the `phase-group-threats.md:207,414` forwarding doc ("full at Standard").
- **Render:** new standard disclosure in `compose_threat_model.py` (the banner is quick-only).
- **Tests:** rewrite `tests/test_stride_quick_profile.py:80-94` (intent reversal), `tests/test_resolve_config.py`,
  `tests/test_p3_behavior_tuning.py`, `tests/test_reasoning_model_resolution.py`.
- **Docs (AGENTS.md §4):** `docs/threat-modeler.md`, AGENTS.md "Assessment depth profiles".
- **Risk:** **MEDIUM** (not low). It's the largest token saving against the 89-threat count, **but** it
  overrides the deliberate product principle "standard = full STRIDE depth, reduction only opt-in". **Needs
  explicit user approval** — this is not a silent ungate. Plus: enforcement hangs on the LLM prompt (softer than
  a Python cap).

### 2B — depth-aware component ceiling *(optional, only for microservice estates)*
- `STRIDE_COMPONENT_CEILING` from flat 10 → a per-depth map (e.g. quick=6/standard=8/thorough=10) in
  `resolve_config.py:214` + `resolve_assessment_depth:303`; mirror in `_FALLBACK_DEPTH_PARAMS`
  (`build_stride_dispatch_manifest.py:37`).
- **Caveat:** changes the documented invariant "depth-independent" (AGENTS.md `:206`) and **does nothing for the
  concrete run** (acquired components are lifted, not shed). Shedding acquired components would reintroduce the
  blind spot removed in the 2026-06-07 redesign → **don't do it.**
- **Tests:** `tests/test_dispatch_manifest.py:261,421,444` among others.
- **Risk:** MEDIUM. Only pick up if microservice estates are an explicit target.

### 2C — recon/authoring granularity *(not recommended)*
- Prose hint `appsec-recon-scanner.md:679` + merge rule "fold siblings except behind a distinct
  trust boundary". Authoring-side pruning is contractually frowned upon (`phase-group-architecture.md:876`
  "Author the COMPLETE inventory ... Do NOT pre-prune"). LLM prose is unreliable — that's exactly what
  failed here (b2b split). **Not as a primary lever.**

**Recommendation lever 2:** implement **2A** (cap=2 for standard). Optionally 2B (=8) only if microservice estates
become relevant.

---

## QA repair as a single quick-fix at standard

**Finding:** `MAX_REPAIR_ITERATIONS = 3` is a **flat literal** (`SKILL-impl.md:3435`), not depth-aware.
Loop tail (`SKILL-impl.md:3498-3534`): on exhaustion **fail-closed `exit 2`** (`:3499-3500`) — no invalid
report is shipped. Two repair plans: structural `.qa-repair-plan.json` (`qa_checks.py:build_repair_plan`,
LLM applier `appsec-fragment-fixer`) and content-side `.qa-content-repair-plan.json` (emitted by the QA reviewer agent,
applied deterministically via `apply_content_repair.py`). No knob limits the rounds today.

### QA-A — `max_repair_iterations` in DEPTH_PARAMS *(RECOMMENDED — verification confirms: low risk)*

> **Verification 2026-06-22 confirms the assessment.** `MAX_REPAIR_ITERATIONS = 3` is a pure literal
> (`SKILL-impl.md:3435`), **no test pins the `3`** (`grep` over `tests/` empty). Loop tail
> `repair_iteration >= MAX_REPAIR_ITERATIONS → exit 2` (`:3499-3500`) verifies fail-closed. Cap=1 yields **exactly
> one** repair pass (mechanical applier *or* one fragment-fixer dispatch), then a re-check, then hard `exit 2`.

- **Producer:** `resolve_config.py:199-204` — add key `max_repair_iterations` to `DEPTH_PARAMS`
  (quick=1, standard=1, thorough=3), emit via `resolve_assessment_depth`; mirror in `_FALLBACK_DEPTH_PARAMS`
  (`build_stride_dispatch_manifest.py:37`, drift guard `tests/test_dispatch_manifest.py:261`).
- **Consumer:** `SKILL-impl.md:3435` literal `3` → `$MAX_REPAIR_ITERATIONS` from RESOLVED_JSON. The loop is
  prose pseudocode (no shell var today) → the skill must read the value into a var once.
- **Correctness:** preserved — "quick-fix" = *one attempt, then fail-closed*, **not** *ship anyway*.
- **VERIFIED side effect:** The loop mechanics are **shared** between Stage-3 QA *and* Stage-4 architect
  (`:3432` "both stages share the same mechanics", `:3622` "Each stage has its own MAX_REPAIR_ITERATIONS budget").
  A depth-derived value therefore caps **both** loops at 1 at standard. Consistent with "single quick-fix",
  but a deliberate decision: if only the QA loop (not architect) should be capped, it needs **two**
  variables (`MAX_QA_REPAIR_ITERATIONS` / `MAX_ARCHITECT_REPAIR_ITERATIONS`). Note: architect review is mostly off
  by default at standard anyway — the side effect is only relevant with `--architect-review`.
- **Tests:** `test_skill_documents_exit_code_2_on_exhaustion` (`tests/test_skill_auto_retry.py:94`, only checks
  the "exit 2" substring) stays green. For the new DEPTH_PARAMS key: extend `tests/test_dispatch_manifest.py` (fallback sync) +
  `tests/test_resolve_config.py` expectation.
- **Docs:** AGENTS.md depth table, `docs/threat-modeler.md`, SKILL flag table (§4 bidirectional).
- **Risk:** LOW (verified).

### Rejected variant *(inadmissible)*
On exhaustion, downgrading `exit 2` to "ship a partially repaired report" → violates AGENTS.md §1/§12
and the SKILL-impl compliance contract (`:147`). **Don't do it.**

**Recommendation QA:** **QA-A** — `max_repair_iterations` standard=1 via DEPTH_PARAMS, replace literal `:3435`,
keep fail-closed `exit 2`.

---

## Overall recommendation & expected impact

| Lever | Measure | Main file | Risk | Impact |
|---|---|---|---|---|
| **2 (threats)** | enable `max_threats_per_category: 2` for standard | `resolve_config.py:582-612` | low | dominant lever on 89→~ threats; ↓ Opus output + ↓ merge/mitigation/QA downstream |
| **QA** | `max_repair_iterations: 1` at standard via DEPTH_PARAMS | `resolve_config.py:199-203` + `SKILL-impl.md:3435` | low | ≤1 repair pass; saves the extra Sonnet repair round |
| **1 (resume)** | indirect via 2+QA (fewer turns); 1A optional | — | — | ↓ resume frequency (fewer turn-budget hits) |
| 2B (optional) | depth-aware ceiling=8 | `resolve_config.py:214` | medium | only microservice estates; does nothing for this run |

**Order (cheap → valuable):** 2A first (largest token lever, lowest risk, no schema), then QA-A.
Both share the same DEPTH_PARAMS/docs/test quartet sync (AGENTS.md §4 bidirectional), so commit them
together. 1A only if you carry the turn budget in DEPTH_PARAMS anyway.

**Bidirectional contract sync (for 2A + QA-A together):** `resolve_config.py` (producer) + consumer
(`SKILL-impl.md` / analyzer prompt) + `tests/test_resolve_config.py` + `tests/test_qa_depth_profile.py` +
`tests/test_dispatch_manifest.py` (`_FALLBACK_DEPTH_PARAMS` sync) + docs (`docs/threat-modeler.md`, AGENTS.md
depth table, SKILL flag table) in the same commit.

## Open decision points (for the user)
1. **Cap value at standard:** `max_threats_per_category = 2` (proposal, severity-sorted, Critical-safe) — or
   stricter `1` like quick? 2 keeps standard distinct from quick.
2. **QA at standard:** strictly 1 pass (proposal) — or 2 (one retry allowed)? 1 = true quick-fix.
3. **2B ceiling** include (=8) or drop? Recommendation: drop until microservice estates are a target.
4. **Lever 1A** (depth-aware maxTurns) include? Recommendation: only if DEPTH_PARAMS is touched anyway.
