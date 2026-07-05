# Plan: Interactive "switch to Sonnet-4.6?" prompt (AskUserQuestion)

Date: 2026-07-04 · Status: proposed, not started · Origin: follow-up to the session-cost
advisory — user wants a real selectable prompt, not only a passive warning.

## Goal

On a **non-Sonnet-4.6 interactive session** (Sonnet-5 or Opus), before any tokens are
spent, show a real Claude Code **`AskUserQuestion`** prompt asking whether to switch to
Sonnet-4.6 — in addition to / instead of the passive advisory that already exists.

## Hard constraint that shapes the design

**The skill cannot switch its own model** — a running Claude Code loop cannot change the
model it runs on. So a "Yes, switch" answer cannot be executed by the skill. The only
realizable outcomes are:

- **Stop & restart on 4.6** → the skill **aborts cleanly before Stage 1** and prints the
  exact restart command (`claude --model claude-sonnet-4-6 <same launch flags> ` then
  re-run `/appsec-advisor:create-threat-model <original args>`).
- **Continue on `<model>`** → proceed as-is.

So it is really a **continue-vs-abort gate**, framed as a model-switch question.

## Proposed prompt

> **Session cost** — This session runs on **`<model>`** (~2× cost). Switch to Sonnet-4.6?
> - ▸ **Stop & restart on Sonnet-4.6** *(recommended)* — aborts before Stage 1, shows the exact restart command
> - ▸ **Continue on `<model>`**

(header ≤12 chars e.g. "Session cost"; 2 options; recommended first.)

## What already exists (build on / reconcile with)

- **Early advisory** in `skills/create-threat-model/SKILL.md` — emitted directly under the
  `🔧 Building …` line via LLM self-report, fires on any non-4.6 (Opus + Sonnet-5), gives the
  exact `claude --model claude-sonnet-4-6` restart command + `/clear` + settings.json. This is
  the current passive surface (exempt from the "only 2 lines" hard rule, SKILL.md:~87).
- **Pre-flight box ⚠ callout** — `resolve_config.py:_render_session_cost_callout` (deterministic,
  session model injected; thin path via `orchestration_controller.py`, legacy via `--run-plan-notes`).
- The prompt would **replace or augment** the passive advisory as the primary interactive gate;
  keep the box callout as the record.

## Design decisions to make

1. **Opt-in vs default-on:**
   - **A — opt-in** (`APPSEC_CONFIRM_SESSION_MODEL=1`): prompt only when set; default stays the
     passive advisory. Non-intrusive. (recommended for a first cut)
   - **B — default-on interactive**: prompt on every non-4.6 interactive session; headless skipped.
     More forceful; risks annoying users who deliberately scan on 5/Opus.
2. **Placement:**
   - (a) In `SKILL.md` right after the early advisory (earliest; LLM-driven; before the router).
   - (b) After the Pre-flight box, before Stage 1 dispatch (both runtimes).
   - (c) **Deterministic decision in `orchestration_controller.py`** (compute a `prompt_model_switch`
     flag from detected session model + headless env), exposed in the ACTION; the runtime files
     (`SKILL-full-runtime.md` thin, `SKILL-impl.md` legacy) instruct "if flag set, call
     AskUserQuestion before Stage 1." Most robust (decision is deterministic; LLM only executes
     the prompt). Preferred if built properly.

## Critical: headless / non-interactive safety

`claude -p` (headless / CI, via `scripts/run-headless.sh`) **cannot answer** an AskUserQuestion —
it would hang or auto-resolve and **break unattended runs**. The prompt MUST be skipped there.

- **Gap:** run-headless.sh does NOT currently export a general non-interactive marker (it sets
  `APPSEC_CI_MODE` only when `--ci`, plus `APPSEC_PR_MODE`, etc.; it always runs `claude -p`).
- **Action:** add an explicit `export APPSEC_HEADLESS=1` (or `APPSEC_NONINTERACTIVE=1`) in
  run-headless.sh, and gate the prompt on its absence. Also honor an opt-out
  (`APPSEC_SKIP_MODEL_PROMPT=1`) for interactive users who don't want the gate.

## Contract touchpoints (if built)

- `skills/create-threat-model/SKILL.md` (+ `SKILL-full-runtime.md` and/or `SKILL-impl.md` depending
  on placement) — the AskUserQuestion instruction + the abort-with-restart-command branch.
- `scripts/orchestration_controller.py` — if design (c): compute + expose `prompt_model_switch`.
- `scripts/run-headless.sh` — export the headless marker.
- `data/required-permissions.yaml` — check whether AskUserQuestion needs a permission entry
  (it is a built-in interactive tool; likely no path/Bash entry, but verify the drift guard).
- Tests: run-headless headless-marker export; controller flag (if design c); an interactivity-gate
  unit where feasible. The AskUserQuestion call itself is LLM-driven (not unit-testable).

## Open questions for the fresh session

- Reliable interactivity detection at the point of the prompt (env marker is the plan; confirm the
  skill Bash sees it — cf. the "env reaches skill Bash only via global settings.json / headless export"
  gotcha).
- Which placement (a/b/c) — (c) is most robust but touches both runtimes + the action schema.
- Does aborting cleanly before Stage 1 leave any partial state to clean up? (Should be none — it's
  pre-dispatch; verify against `orchestration_controller.py` prepare ordering.)
- UX: is a modal gate actually wanted by default, or is the passive advisory + "Ctrl-C now" bullet
  (already present) sufficient? Lean opt-in (A) first.

## Related

- [[project_group_a_routing_transparency_2026-07-04]] — the session-cost advisory + box callout this builds on.
- [[project_model_routing_architecture_and_plan_2026-07-04]] — why session=4.6 is the economy lever.
- [[gotcha_env_var_reaches_skill_bash]] — env-to-skill-Bash propagation caveat (matters for the headless gate).
