# Changelog

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
