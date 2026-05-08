# Changelog

## Unreleased — Documentation: flat stage numbering

The intermediate "Stage 1b" label was a migration artifact from the
M2.12 Phase-11 split — it implied a sub-relationship to Stage 1 that
did not exist operationally (Composition has its own task entry,
turn budget, dispatch, and retry loop). Renamed to a flat sequence:

| old | new |
|-----|-----|
| Stage 1 — Threat Model Orchestrator (Phases 1–10b) | unchanged |
| Stage 1b — Composition (Phase 11) | **Stage 2 — Composition (Phase 11)** |
| Stage 2 — QA Review | **Stage 3 — QA Review** |
| Stage 3 — Architect Review | **Stage 4 — Architect Review** |

The user-facing pipeline is now four numbered stages with no `b`
suffix. Internal env vars (`STAGE1_PHASE_LIMIT`) and state files
(`.stage1-resume-count`) keep their names — they belong to Stage 1,
which did not move. CHANGELOG entries for M2.12 and M2.13 retain
their original "Stage 1b" wording as historical record.

Test file renamed: `tests/test_skill_stage1b.py` →
`tests/test_skill_composition_split.py`.

## Unreleased — User-facing stage labels

The visible stage/task labels were tightened up to read like a pipeline rather
than an implementation detail dump:

| old | new |
|-----|-----|
| Pre-flight intermediate wipe | **Preparing workspace** |
| Stage 1 — Threat Model Orchestrator (Phases 1–10b) | **Stage 1 — Threat Analysis & Triage** |
| Stage 2 — Composition (Phase 11) | **Stage 2 — Report Rendering** |
| Completion summary + cleanup | **Final summary + cleanup** |

This rename is intentionally user-facing only. Internal runtime contracts
remain unchanged: `STAGE1_PHASE_LIMIT=10b`, `phase=10b status=completed
need_render=true`, `Phase-10b precondition gate`, `Phase 10b Triage
Validation`, and `Phase 11 Finalization`.

## Unreleased — Stage-D contract enforcement (M2.9 – M2.13)

The 2026-04-25 juice-shop Run 4 incident exposed that a single Sonnet
orchestrator session, under Phase-11 turn-budget pressure, can quietly
take an "inline-shortcut": skipping the fragment renderer and hand-
authoring `threat-model.md` directly. The result was a 90 KB document
missing the Security Posture at a Glance heatmap, with a broken TOC,
untitled multi-link cells, and inconsistent mitigation grouping. Worse,
the skill body's Bash detector was loose enough that the LLM executor
interpreted the gate trip as a "soft warning" and continued into Stage 2.

Stage-D closes that whole class of failures with five coordinated changes:

### M2.9 — Bump orchestrator `maxTurns` from 75 to 120

`agents/appsec-threat-analyst.md` — same rationale as the QA-reviewer
M2.8 bump: Phase 11 (write 12 fragments + compose + qa_checks +
placeholder-patch) is the dominant turn consumer. 120 turns gives ~50%
headroom, which empirically eliminates the inline-shortcut attempt
under normal load. Test ceiling raised from 80 to 120 in
`tests/test_agent_definitions.py`.

### M2.10 — Hard inline-shortcut gate as standalone script

New `scripts/check_inline_shortcut.py` (218 lines) replaces the old
~50-line inline Bash detector in `SKILL-impl.md`. The script:

- Re-uses `qa_checks.py fragments` as one indicator (REQUIRED_FRAGMENTS
  list stays the source of truth).
- Adds three skill-level indicators (A1: dir missing; A2: dir present
  but `< MIN_FRAGMENTS`; B: `.threats-merged.json` missing while MD
  exists; C: `.triage-flags.json` missing at standard+ depth).
- Prints the canonical inline-shortcut banner to stderr and exits 2.
- Optional `--write-repair-plan` writes
  `.inline-shortcut-repair-plan.json` for the auto-retry consumer.

Skill body now invokes it with `|| { … exit }` — the Bash short-circuit
is impossible to "soft-interpret" away. 14 unit tests pin the exit
codes, banner contents, and repair-plan schema.

### M2.11 — Deterministic pre-generation of structural fragments

New `scripts/pregenerate_fragments.py` (~400 lines) generates 6 of the
8 REQUIRED_FRAGMENTS deterministically from `threat-model.yaml` and the
Phase-3-8 outputs:

- `system-overview.md` (project meta + components prose)
- `architecture-diagrams.md` (4 sub-sections + 3 Mermaid blocks)
- `assets.md` (asset table)
- `attack-surface.md` (5.1 unauthenticated + 5.2 authenticated)
- `security-architecture.md` (all 14 sub-sections, populated from
  `security_controls[]`)
- `out-of-scope.md` (from `meta.scope.out_of_scope` or default)

Idempotent: never overwrites an LLM-authored fragment. Wired into
`SKILL-impl.md` to run before the hard gate. Reduces Phase-11 LLM load
to just 4 qualitative fragments (`ms-verdict.json`,
`ms-architecture-assessment.json`, optionally `attack-walkthroughs.md`
and `security-posture-attack-paths.json`). 37 unit tests cover every
generator + the CLI driver flags (`--force`, `--only`, `--dry-run`).

### M2.12 — Always-on Stage 1b (Phase-11 split)

Phase 11 used to share the orchestrator's turn budget with Phases 1–10.
Now `STAGE1_PHASE_LIMIT=10b` makes Stage 1 stop cleanly after Phase 10b
(`agents/appsec-threat-analyst.md` new branch), and the skill always
dispatches a separate `Stage 1b — Composition` agent with `RENDER_ONLY=true`
and a fresh 120-turn budget. Stage 1b authors only the 2 mandatory LLM
fragments, then runs `compose_threat_model.py --strict` +
`render_completion_summary.py --patch-placeholders` + `qa_checks.py all`.

The Stage 1b task is pre-created in the bootstrap (no longer a
recovery-only conditional). 14 doc-drift tests in
`tests/test_skill_stage1b.py` keep the contract internally consistent
across `SKILL-impl.md` and the orchestrator agent.

### M2.13 — Auto-Retry Loop on hard-gate trip

If `check_inline_shortcut.py` returns exit 2 (despite M2.9–M2.12
reducing the probability), the skill enters a recovery loop with
`MAX_INLINE_RETRIES=2`. Each iteration:

1. Recovery sequence — best-effort reconstruction of any missing
   Phase-9/10b artefacts:
   - `merge_threats.py collect` → `merge_threats.py finalize` if
     `.threats-merged.json` is missing and `.stride-*.json` exist.
   - `triage_validate_ratings.py` if `.triage-flags.json` is missing.
   - `pregenerate_fragments.py` (idempotent) for any structural gaps.
2. Re-dispatch Stage 1b (`RENDER_ONLY=true`) with a fresh 120-turn
   budget.
3. Re-run the hard gate.

Exit conditions: gate passes → break, proceed to Stage 2. Counter
exhausted → exhausted-retries banner + exit 2 (preserves repair plan
on disk for inspection). Counter file (`.inline-shortcut-retry-count`)
is reaped on success via `runtime_cleanup.py POST_QA_FILES_IF_PASS`.
23 tests in `tests/test_skill_auto_retry.py` cover the loop contract,
recovery scripts, and runtime-cleanup integration.

### Cumulative effect

Compliance posture is now: **compliant or at most 2× retry — failing
that, hard exit 2 with the repair plan preserved on disk for manual
inspection**. At normal repo sizes (≤8 components) the expected success
rate without any manual intervention is ~99%. No malformed threat
model is ever persisted to `docs/security/`.

### M2.14 — Composition observability (Sprint 6)

Stage-D guarantees compliance, but a successful run could still hide
non-blocking issues from the user — soft warnings, internal compose
retries, or a single auto-retry-loop firing all collapse into "it
worked" with no trail. Sprint 6 closes that observability gap by
persisting composition health in three coordinated places:

1. **`scripts/compose_threat_model.py` writes `.compose-stats.json`**
   on every successful render. Records soft warnings (categorized via a
   heuristic mapper), per-section compose-retry counts (read from the
   pre-render repair plan before deletion), and a clean/warned status
   flag. Schema-versioned for forward compatibility.

2. **`## Appendix: Composition Notes` is added to threat-model.md** —
   a new conditional section in `data/sections-contract.yaml` between
   Run Statistics and Vektor Taxonomy. Only emitted when the
   `compose_warned` eval-context flag is True (any of: `.compose-stats.json`
   shows non-clean status, or `.inline-shortcut-retry-count > 0`). When
   present, lists soft warnings as a table, section retries as a table,
   and skill-level auto-retry events as bullets. The MD-embedded form is
   the canonical persistence — it survives `runtime_cleanup`, git commits,
   and PR reviews.

3. **`-- Composition Health --` block in the completion summary** —
   `render_completion_summary.py` reads the same sources and emits a
   conditional CLI block between Run Statistics and Next Steps. Shows
   warnings/retries/auto-retries with up to 2 inline warning previews
   plus a pointer to the MD appendix for the full picture.

When the pipeline runs cleanly (default case), all three artefacts are
either absent (`.compose-stats.json`) or omitted (the MD appendix and
the CLI block) — no extra noise on successful runs.

`runtime_cleanup.py` reaps `.compose-stats.json` along with the other
QA bookkeeping at successful completion.

### M2.15 — Run Issues + auto-fix engine (Sprint 7)

Sprint 6 made the composition pipeline transparent. Sprint 7 extends the
same pattern to the **whole run**: errors, warnings, performance
anomalies, and recovery events from `.agent-run.log` and
`.hook-events.log` are now aggregated, classified, paired with
structured fix recommendations, and exposed via three coordinated
surfaces. A new user-facing skill applies auto-eligible fixes
non-interactively after confirmation.

The 2026-04-25 juice-shop runaway (Phase 1 ran 8 hours, cost $51, no
visible alarm) was the canonical motivating incident — Sprint 7 ensures
that class of issue is impossible to miss in any future run.

1. **`scripts/aggregate_run_issues.py`** parses the three log files plus
   `.compose-stats.json` and `.inline-shortcut-retry-count`. Produces
   `.run-issues.json` with categorized issues:
     * `error` (TOOL_ERROR, MAX_TURNS, RENDER_FAILED)
     * `warning` (BASH_WARN, SESSION_STOP with reason=unknown,
       high-token-usage)
     * `perf_anomaly` (phase wall-time exceeds depth-specific limit;
       hard ceiling 30 min flagged regardless of depth)
     * `recovery_event` (auto-retry firings, compose section retries)
   Tolerant against missing PHASE_END events (uses next PHASE_START as
   approximate end timestamp).

2. **`scripts/recommend_fixes.py`** reads `.run-issues.json` and adds a
   structured `fix_recommendation` per issue:
   ```
   category         agent_def | config_tune | yaml_edit | skill_spec
                    | user_action | rerun | investigate | no_fix
   auto_applicable  bool — only True for well-bounded changes
   confidence       high | medium | low
   risk_level       low | medium | high
   summary          one-line description
   rationale        why this fix is recommended
   actions          ordered list of {type, target, find, replace}
   verification     commands to run after applying (e.g. pytest)
   ```
   Per-category recommenders implement the fix logic; unknown categories
   get a default `investigate` recommendation rather than being dropped.

3. **`## Appendix: Run Issues` in threat-model.md** (conditional, only
   when `run_warned` eval-context flag is True) — groups issues by
   severity, lists each with evidence, fix category, summary, rationale,
   actions, and verification commands. Auto-applicable fixes carry a
   `✓ auto-applicable` badge with a pointer to the fix-skill.

4. **`-- Run Issues --` block in completion summary** (conditional) —
   shows counts, top 2 issues, and an "Apply fixes" pointer when at
   least one auto-fix is ready.

5. **New skill `/appsec-advisor:fix-run-issues`** — reads
   `.run-issues.json`, presents each issue interactively (or with
   `--yes` non-interactively), applies auto-eligible `edit_file` actions
   via the Edit tool, runs the `verification` commands, and persists an
   audit trail in `.run-issues-fixes.json`. Hard safety rails:
     * Never applies non-`auto_applicable` or non-`high`-confidence fixes.
     * Never modifies `threat-model.md`, `threat-model.yaml`, or anything
       outside `$CLAUDE_PLUGIN_ROOT`.
     * Rate limits to max 5 auto-fixes per invocation.
     * Verification failure marks fix as `applied_with_verification_failure`.

Initial auto-applicable category: **`agent_def`** (bumping `<agent>.md`
maxTurns by 50% on first MAX_TURNS event, mirroring the M2.8/M2.9
manual fixes). Additional categories are opt-in as patterns prove safe
through repeated production runs.

`runtime_cleanup.py` reaps `.run-issues.json` and `.run-issues-fixes.json`
on successful completion — the canonical persistence is the §Run Issues
appendix in `threat-model.md`.

## 0.9.0-beta — 2026-04-23

First public release. Works well enough for guided use; not yet something
I'd leave unattended in CI overnight.

- New `publish-threat-model` skill so reports don't get committed by accident.
- Multi-repo scanning (`--repo`, `--output`, `generate-threat-summary`).
- `docs/related-repos.yaml` pulls upstream findings into STRIDE at trust boundaries.
- Headless runner for CI (`scripts/run-headless.sh`).
- Incremental mode with a noise-only fast path — docs/IDE-only changes exit immediately.
- Triage validator split: steps 1–5 are plain Python now, only ranking stays on the LLM.
  Cut triage cost by ~10x.
- Architect reviewer (Opus, advisory only) auto-runs at `--assessment-depth thorough`.
- QA reviewer with a bounded repair loop (max 3 iterations).
- SARIF v2.1.0 and pentest-task export.
- Prompt-caching contract for Phase 9 dispatches — stable payload first, volatile last.
- Schema/contract enforcement on every intermediate artefact.
- Default reasoning model is now `opus-cheap` (Opus for triage + merger, Sonnet for the rest).
- Rendering went single-source: agents emit fragments, `compose_threat_model.py` writes the report.

### Known issues

- `appsec-config-scanner` is defined but not wired up yet. Will either land
  as Phase 2.5 or be removed before 1.0.
- On a fresh install, run `/appsec-advisor:check-permissions --update` once.
  Otherwise the first assessment will stop every 30 seconds for a permission prompt.
- No full-pipeline E2E test in CI yet. Unit coverage is fine.
