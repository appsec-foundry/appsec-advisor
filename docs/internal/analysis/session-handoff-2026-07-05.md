# Session handoff — model-routing economy + session-cost warning (uncommitted)

Date: 2026-07-05 · Branch: `dev` · Status: all work UNCOMMITTED, full test suite GREEN
(9056 passed, 93 skipped, last full run) · `ruff check` clean.

## What was done (ready to commit)

Implemented the model-routing transparency + economy plan
(`docs/internal/analysis/plan-model-routing-transparency-2026-07-04.md`), Groups A–E, plus
a prominent session-cost warning. See
`[[project_group_a_routing_transparency_2026-07-04]]` for the per-group detail.

- **A** session-model transparency: `scripts/detect_session_model.py` (fail-safe) +
  `render_effective_routing` + drift fixes.
- **B** version-id model knobs (dropped `choices=`; fixed architect `else→opus` bug).
- **C** renderer + abuse-verifier pins (`APPSEC_RENDERER_MODEL` / `APPSEC_ABUSE_VERIFIER_MODEL`).
- **D** triage→5 buy-back locking test + merger-inline caveat docs.
- **E** `run-headless.sh` defaults session to `claude-sonnet-4-6`; docs; fixed the `--model`
  phantom baseline (test_help_file).
- **Session-cost warning**: early advisory in `SKILL.md` (under the 🔧 Building line, fires on
  any non-4.6 incl. Opus + Sonnet-5, exact `claude --model claude-sonnet-4-6` restart cmd +
  `/clear` + launch-flags/original-args) + prominent ⚠ callout in the Pre-flight box
  (`resolve_config.py:_render_session_cost_callout`, thin + legacy paths).

## Uncommitted files (git status on `dev`, 2026-07-05)

**Modified (tracked) — 19 files, +661 / −84:**
```
AGENTS.md
README.md
agents/appsec-abuse-case-verifier.md
agents/phases/phase-group-threats.md
data/required-permissions.yaml
docs/headless-mode.md
docs/threat-modeler.md
schemas/required-permissions.schema.yaml
scripts/check_permissions.py
scripts/orchestration_controller.py
scripts/resolve_config.py            (+230/−21 — bulk of the feature)
scripts/run-headless.sh
skills/create-threat-model/HELP.txt
skills/create-threat-model/SKILL-impl.md
skills/create-threat-model/SKILL.md
tests/test_check_permissions.py
tests/test_help_file.py
tests/test_orchestration_controller.py
tests/test_resolve_config.py
```

**New (untracked):**
```
scripts/detect_session_model.py
tests/test_detect_session_model.py
docs/internal/analysis/plan-model-routing-transparency-2026-07-04.md   (original plan)
docs/internal/analysis/plan-ms-abuse-case-surfacing-2026-07-04.md      (open analysis)
docs/internal/analysis/plan-interactive-model-switch-prompt-2026-07-04.md (open plan)
```

## Suggested commit grouping

The routing feature + warning are one cohesive change (the SKILL.md advisory, the box callout
in `resolve_config.py`, and the controller injection are interdependent). Suggested:

1. **feat(model-routing): per-agent version-id knobs + session-model transparency + economy defaults**
   — everything except the 3 analysis docs. One coherent feature commit (code + tests + AGENTS.md +
   docs/threat-modeler.md + docs/headless-mode.md + README.md + HELP.txt + required-permissions +
   schema + run-headless.sh). Include `detect_session_model.py` (+test).
   Optionally split docs into a follow-up `docs:` commit if you prefer smaller commits.
2. **docs(internal): planning/analysis notes** — the 3 `docs/internal/analysis/*.md` (the original
   routing plan is already committed as a separate file? it is untracked here → include it), the MS
   abuse-case analysis, and the interactive-prompt plan. Planning artifacts, no code.

Pre-commit: `make lint` + targeted subset (see CONTRIBUTING.md). **Do NOT `ruff format`
`scripts/resolve_config.py`** — it is in `extend-exclude`; an explicit format collapses its
intentional alignment and breaks the `test_incremental_mode` doc-invariant (bit us this session;
recovery = `git checkout` + re-apply logic in the aligned style).

## Open — NOT built (each waiting on a go)

1. **Interactive "switch to Sonnet-4.6?" prompt** (AskUserQuestion instead of only the advisory)
   → full plan: `docs/internal/analysis/plan-interactive-model-switch-prompt-2026-07-04.md`.
   Key: skill can't self-switch (Yes = clean abort + restart cmd); MUST skip in headless
   (needs a run-headless `APPSEC_HEADLESS=1` export — currently missing).
2. **CLI flags `--renderer-model` / `--abuse-verifier-model`** — so the renderer/abuse buy-back
   works interactively as a flag (today only via env / settings.json `"env"` block, per the
   skill-Bash env gotcha). Small add to `resolve_config.py` (argparse + wire like `--triage-model`)
   + SKILL dispatch + tests + docs.
3. **MS abuse-case surfacing rework** (badge verified chains into the red-box worst-case bullets)
   → analysis: `docs/internal/analysis/plan-ms-abuse-case-surfacing-2026-07-04.md`.

## Verification state

- Full suite GREEN (9056 passed) after the resolve_config restore/re-apply.
- `ruff check scripts/ tests/ hooks/` clean.
- `ruff format --check` clean except the pre-existing baseline `tests/test_compose_threat_model_cov3.py`
  (NOT touched this session).
