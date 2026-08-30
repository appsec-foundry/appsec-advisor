# Proposal: Stage 4 becomes a fast editorial pass

Direction decided by the operator on 2026-08-30: Stage 4 stops being an architect review and becomes a short content polish. It tightens and straightens formulations and fixes nothing else — no links, identifiers, numbers or evidence, so it cannot undo the QA reviewer's work — and it must stay cheap in tool calls, so it emits one plan instead of editing files.

Scope decided: the yaml free text, the Management Summary, and the security-architecture section. Gating decided: automatic at `thorough`, and available at `standard` through `--architect-review`.

Every claim was checked against the code or against the measured run in `/home/mrohr/juice-shop2/docs/security`.

## Measured baseline (juice-shop2, 2026-08-30, thorough)

From `.agent-run.log`:

| Step | Window | Duration | Result |
|---|---|---|---|
| Architect round 1, deterministic pre-pass | 08:17:01 → 08:17:33 | 32 s | 14 findings (checks 1, 3, 5, 6, 12, 13, 14, 15) |
| Architect round 1, LLM checks 2, 4, 7–11 + residues | 08:17:33 → 08:29:06 | 11 min 33 s | 29 findings total (13 warning, 16 info), 1 technical defect |
| Fragment fixer | 08:30:04 → 08:31:27 | 1 min 23 s | 3 actions on `.fragments/security-architecture.md`, gate exit 0, converged |
| Architect round 2 (verification) | 08:32:54 → 08:49:06 | 16 min 12 s | 26 findings (15 warning, 11 info), 0 technical defects, pass |
| **Stage 4 total** | 08:16:55 → 08:49:06 | **32 min** | one repaired fragment |

The review does not find nothing. It found 26 items in the final round, including: the Management Summary counting 61 findings against a register of 74 (W-03), no P1 mitigation for any effective-Critical finding (W-02), one fix split across three priority tiers as duplicate mitigations (W-05), a missing client-tier trust boundary (W-08), no finding for the permissive wildcard CORS policy (W-10), plus two plugin defects: the composer demoting three fragment-declared `#### 6.2.N` headings to bold paragraphs (W-14) and a false-positive regex at `architect_structural_checks.py:1261` (W-15). Its verdict was "Recommend rework".

What is true is that none of it changes anything. `technical_defects: 0` means nothing enters the repair loop, `.architect-review.md` has no consumer in any deliverable — `grep` across `scripts/`, `skills/` and `agents/` finds only runtime cleanup, `publish_threat_model.py`, `postscan_secret_check.py`, and one line in the completion summary suggesting the reader open the file (`scripts/render_completion_summary.py:892`). Cost is not readable from the log: the `SESSION_STOP` figures belong to the outer session, not the subagent.

## Three separable problems

**1. Verification is a full re-review.** One technical defect triggered a complete opus pass: 16 minutes to confirm a 3-action fragment rewrite that the fixer had already verified with `gate_exit_code: 0`. That is a runtime-design question in `SKILL-thin-stage4.md`, not a budget question — the file says to repeat the architect review in full after every repair.

**2. The LLM half produces advisory findings that reach no deliverable.** The deterministic pre-pass delivered 14 findings in 32 seconds. The 11.5-minute LLM half added roughly fifteen more, none of which was repairable, and all of which land in a file the report never reads. The one technical defect of the run came from Check 14, whose detection is already deterministic (`sec7_quality_bar`); only the Unsafe-vs-Missing classification was LLM work.

**3. Nobody polishes the language.** `apply_prose_fixes.py` applies seven regex fix classes and explicitly declines paragraph restructuring. `agents/shared/prose-style.md` binds the authoring roles, but each sees only its own slice. Tone consistency across sections, redundancy between the Management Summary and §6, and clumsy sentences are unowned.

## The new Stage 4

Three parts, in the order they run.

**1. Deterministic checks, no agent.** The controller runs `architect_structural_checks.py all --output-dir <dir>` itself; the script has a standalone CLI and needs no agent. It took 32 seconds in the measured run and produced 14 of that round's findings. Its output builds `.architect-repair-plan.json` for the technical-defect types the classifier in `agents/shared/architect-repair-classifier.md` assigns, and `.architect-status.json` with `source=deterministic-pre-pass`. This mirrors the QA fast path, where `qa_checks.py gate` exit 0 releases the stage with no agent.

**2. The editorial pass.** Sonnet, one dispatch, never inside a repair loop. It changes no link, identifier, number, severity or evidence locator — see Scope and Guard — so it cannot undo what the QA reviewer settled.

It does not edit files. It emits one plan, the same shape of handoff as the QA reviewer's `.qa-content-repair-plan.json`, and a deterministic applier performs every write. The QA applier itself is not reused: its action carries a QA `check` id and a QA type enum, and its `fragment` field cannot address a yaml path, so bending it would mean schema surgery on a contract that already has a producer. `schemas/editorial-plan.schema.json` and `scripts/apply_editorial_plan.py` are the sibling. The editor's tool-call budget is then: one startup log, one read of a bounded input, one plan write, one completion log. Roughly five calls, against the 100-turn ceiling the architect reviewer carries today — raised from 40 after two thorough reviews were measured at 81 and 90 turns.

The bounded input matters as much as the plan. The controller prepares a projection of the editable prose only — the §6 narrative blocks, the Management Summary prose, and the free text of findings from High upwards — each block under a stable id. The editor reads that one file instead of the 90 KB report, which is the same shape as the `.dispatch-context/` projections the STRIDE fan-out already uses.

**3. Verification without a second review.** With no LLM reviewer in Stage 4, the repair loop's second full pass disappears by construction. What verifies a repair is the deterministic checks for the repaired action types plus the Stage-3 QA gate — a few seconds of Python where the measured run spent 16 minutes of opus.

The judge/author objection to OR-2 dissolves here: the Stage-4 role no longer judges, so authoring is no longer self-certification.

### What the change costs

Mapping the measured run's 15 warnings against the depth matrix's `Det?` column:

| Survives (deterministic detection) | Lost with checks 2, 4, 7, 8, 10, 11 |
|---|---|
| W-03 MS counts 61, register lists 74 (Check 3) | W-04 Weakness register aggregates 36% (Check 7) |
| W-05 duplicate mitigations across three tiers (Check 12) | W-06, W-07 rating coherence (Check 10) |
| W-12 §6 verdicts understate defeated controls (Check 14) | W-08, W-09 trust-boundary gaps (Check 2) |
| W-13 BFF anti-pattern mandate (Check 15) | W-10, W-11 uncovered CORS and archive extraction (Check 4) |
| W-14, W-15 (Check 14 detection; the composer and false-positive diagnoses were the model's own) | W-02 partly — Check 12 detects the ROI half, Check 8 the chain half |

So roughly half the warnings survive for free, and the coverage-gap and trust-boundary observations are the real loss. Keeping checks 2, 4, 7, 8, 10 and 11 reachable behind an explicit `--architect-review` flag preserves them for a deliberate deep run without paying twelve minutes of opus on every thorough scan.

**Land the deterministic findings.** They are currently invisible: `.architect-review.md` has no consumer in any deliverable. Print the warning titles in the Stage-4 receipt and carry them into `aggregate_run_issues.py`, so a reader sees "MS counts 61, register lists 74" without opening a dotfile. Cheap, and independent of everything else here.

Available immediately, without code: `--no-architect-review`, or `APPSEC_ARCHITECT_MODEL=sonnet` (`scripts/resolve_config.py:1135`). The architect auto-enables at `thorough` and defaults to opus (`resolve_config.py:1108`, `:1134`).

## OR-2 stays untouched

Decision OR-2 limits `Edit` to `appsec-fragment-fixer` and `appsec-qa-reviewer`, pinned by `EDIT_TOOL_OWNERS` in `tests/test_agent_definitions.py:161`. Because the editorial role emits a plan instead of editing files, it needs `Read`, `Write` and `Bash` only. `EDIT_TOOL_OWNERS` keeps its two entries and `decisions.md` needs no amendment.

Convergence is the remaining constraint. A model asked to improve wording finds something to improve on every pass, so the editorial pass runs exactly once per run and never inside the repair loop.

## Where the report's prose actually comes from

1. **Deterministic templates.** Before every compose the controller runs `pregenerate_fragments.py --force --only system-overview.md,architecture-diagrams.md,assets.md,attack-surface.md,out-of-scope.md,attack-walkthroughs.md` (`scripts/orchestration_controller.py:6346`). Editing those six fragments is pointless — the next compose overwrites them. §3 belongs here too: `walkthrough_renderer.py` renders the walkthroughs from the yaml plus per-CWE templates and takes only `title` / `_title_source`, `scenario`, and mitigation titles from the model.
2. **`threat-model.yaml` free text**, rendered into the §8 finding cards: `scenario`, `evidence_summary`, `impact_description` are read in `_build_threat_card` (defined at `scripts/compose_threat_model.py:14538`, fields read at 14771–14921). `mitigations[].steps` and `mitigations[].verification` come from `hydrate_mitigation_details.py`, which states that authored mitigation fields always win — an edit there survives re-hydration.
3. **LLM-authored fragments**: `.fragments/security-architecture.md` (deterministic scaffold from `gen_security_architecture`, narrative expanded by `appsec-secarch-renderer`), `.fragments/ms-verdict.json`, `.fragments/ms-anti-patterns.json`.

The editor's reach is §8 and the mitigation cards through the yaml, plus §6 and the Management Summary through the fragments. §1, §2, §3, §4, §5 and §10 are template-owned and out of scope by construction.

One feasibility check that decides the design: after Stage 2 the yaml is stable. `build_threat_model_yaml.py` is invoked at runtime from exactly one place (`scripts/orchestration_controller.py:6174`) and only when `meta._bootstrap` marks the yaml as a stub. `render_completion_summary.py --write-yaml` is a display flag, not a rebuild (`render_completion_summary.py:1322`).

## Scope of the editorial pass

Editable:

- `threats[].scenario`, `threats[].evidence_summary`, `threats[].impact_description`, `threats[].breach_distance_reason`
- `mitigations[].steps`, `mitigations[].verification`
- the `verdict` block's prose fields
- narrative blocks in `.fragments/security-architecture.md`
- prose fields in `.fragments/ms-verdict.json` and `.fragments/ms-anti-patterns.json`

Not editable, byte-identical afterwards:

- every identifier: `F-`, `T-`, `M-`, `C-`, `TB-`, `AC-`, `CWE-`
- `threats[].title` and `_title_source`. §8 titles are derived by `_canonical_finding_title` from CWE plus the evidence `file:line`; where the raw title survives it feeds `_FNNN_REGISTER_ROW` (`scripts/compose_threat_model.py:1596`), `_MD_THREAT_ROW_RE` (`scripts/qa_checks.py:9908`), the §3 headings, and TOC anchors.
- `severity`, `risk`, `likelihood`, `impact`, `effective_severity`, `breach_distance`, `chain_role`, CVSS vectors and scores
- `evidence[]` entries and every `file:line` locator
- `violated_requirements`, `prior_finding_ref`, `evidence_tier`, and the unproven marking REQ-MOD-009 requires
- every number, every link target, every code span

The editor rephrases and shortens. It never adds a claim and never removes a qualification.

Mitigations carry their own floor. REQ-RPT-005 and `scripts/validate_mitigation_quality.py` require every P1/P2 fix card to have at least two ordered steps and a concrete post-change verification instruction, and every code example to name its source file. The editor may rewrite the wording of a step or of the verification sentence; it may not merge steps, drop one, remove the verification, or strip the source location from a code example. `mitigations[].title` stays out of v1: it is short label text, and `recommend_fixes.py` and the §3 "Primary mitigation" line match on it.

## Guard

`scripts/check_editorial_diff.py` runs before and after the pass and fails closed.

Before the dispatch it snapshots `threat-model.yaml` and the editable fragments and extracts an invariant set: identifiers, severity and score values, `file:line` locators, link targets, code spans, numeric literals, and every key outside the allow-list. After the dispatch it re-extracts and compares. Any difference, any change to a field outside the allow-list, or a schema validation failure restores the snapshot and reports the violation. The run continues with the unedited text: a failed polish is not a release blocker.

Two invariants are specific to mitigations: the step count per card and the presence of a non-empty `verification` must be identical before and after. Catching that in the guard reverts a bad edit; leaving it to `validate_mitigation_quality.py` in the compose tail would abort the run instead, since that gate is blocking.

The existing gates still run afterwards — strict compose with fragment schema validation, `validate_mitigation_quality.py`, `qa_checks.py gate`, `section_integrity.py`.

Test shape: one fixture whose editor output changes a severity value, one that rewrites a `file:line` locator, one that drops an unproven marking, and one clean rewrite. The first three must revert; the fourth must survive compose with every invariant unchanged.

## Built so far

Three scripts and one schema, 42 tests, no wiring — nothing in the pipeline calls them yet.

- `scripts/build_editorial_context.py` — projects the editable blocks to `.dispatch-context/editorial/blocks.json`. Every block carries the address the plan quotes back, and only addresses the guard admits. Selection: the verdict, the Management Summary and the §6 prose always, plus the finding and mitigation prose of the worst `--max-findings` findings at or above `--severity-floor`.
- `scripts/apply_editorial_plan.py` + `schemas/editorial-plan.schema.json` — the only writer. Field addresses must be on the allow-list, `find` is the optimistic lock, a Markdown block must match exactly once, and a rejected action does not stop the others.
- `scripts/check_editorial_diff.py` — `snapshot` before, `verify [--restore]` after.

Measured against the `juice-shop2` run at the defaults: 228 blocks, 51 KB — 153 from the yaml, 63 §6 paragraphs, 12 from the two Management-Summary fragments. The §6 filter skips headings, tables, fences, HTML, list items, the mechanical bold labels (`**Status:**`, `**Implemented controls:**`) and everything inside a `FROZEN` region, and requires a paragraph to carry a sentence of at least 80 characters once its label is stripped.

## Dry run

The pass has no agent definition yet, so the first run is manual. Work on a copy — never in a real output directory:

```bash
cp -r /home/mrohr/juice-shop2/docs/security "$TMPDIR/editorial-dry-run"
python3 scripts/build_editorial_context.py "$TMPDIR/editorial-dry-run"
python3 scripts/check_editorial_diff.py snapshot --output-dir "$TMPDIR/editorial-dry-run"
```

Hand `.dispatch-context/editorial/blocks.json` to a model with these rules, and have it write `.dispatch-context/editorial/plan.json` against `schemas/editorial-plan.schema.json`:

> Rewrite only the prose in each block. Keep every identifier, link, code span, path, `file:line` locator and number exactly as it stands, and keep a leading bold label. Do not add a claim, remove a qualification, merge mitigation steps or drop a verification sentence. Skip a block that is already clear — a short plan is a good plan. For each rewrite emit one action with the block's `file` and `path`, `find` set to the block's text verbatim, and `replace` set to the rewrite; a Markdown block carries no `path`.

Then apply and check:

```bash
python3 scripts/apply_editorial_plan.py "$TMPDIR/editorial-dry-run"
python3 scripts/check_editorial_diff.py verify --output-dir "$TMPDIR/editorial-dry-run"
diff -u <(git -C /home/mrohr/juice-shop2 show :docs/security/threat-model.yaml 2>/dev/null || cat /home/mrohr/juice-shop2/docs/security/threat-model.yaml) "$TMPDIR/editorial-dry-run/threat-model.yaml" | head -200
```

Three numbers decide the rest: how many blocks the pass actually rewrote, how many the guard rejected, and how many turns it needed. The last one is what a turn ceiling may be set from — `tests/test_agent_definitions.py:88` records that every shipped turn-kill was a budget set too small, so the 100-turn ceiling does not come down on an estimate.

## Registration checklist

- the Stage-4 agent definition, taking the existing slot rather than adding a stage; tools `Read`, `Write`, `Bash` only
- `EXPECTED_MAX_TURNS` and `MIN_MAX_TURNS` in `tests/test_agent_definitions.py`; that test fails on an unregistered agent file, and both the 100-turn ceiling and its 90-turn floor come down once the dry run has measured the pass
- the controller step that writes the bounded input projection
- the agent table in `agents/shared/logging-standard.md`
- model routing in `resolve_extended_models` (`scripts/resolve_config.py:851`) and the Stage-4 resolution in `resolve_architect_review` (`resolve_config.py:1108`)
- the controller action and `next_boundary` in `docs/internal/contracts/orchestration-actions.md`, plus `SKILL-thin-stage4.md` for the targeted-verification rule
- the cost model and the Stage-4 label in the run plan
- `tests/test_check_editorial_diff.py`, a targeted-verification test, and a controller routing test

`data/context-budgets.yaml` needs no entry: it budgets prompt-surface bytes and covers only the four kernel-preload roles and the shared assets.

## Follow-ups the measured run surfaced

- W-14: the composer demotes three fragment-declared `#### 6.2.N` headings to bold paragraphs and renumbers OAuth to 6.2.1. The fragment is correct, so regenerating it reproduces the defect. Candidate for `/fix-plugin-defect`; unverified here.
- W-15: `sec7_v2_no_legacy_flows` matches the canonical control name "OAuth 2.0 Authorization Code Flow with PKCE" at `scripts/architect_structural_checks.py:1261`. A false positive that returns on every run; unverified here.

## Open questions

- `--architect-review` now means "run the editorial pass at `standard`", so it can no longer double as the switch that keeps checks 2, 4, 7, 8, 10 and 11 reachable. Recommendation: drop those checks rather than carry a second flag for a path nothing consumes; add a separate switch later if the deep review is missed. The deterministic checks are unaffected.
- Should `architect_structural_checks.py all` run at every depth, independent of Stage 4? It costs 32 seconds, and its §6 quality-bar and verdict-plausibility detection currently never runs at `quick` or `standard`.
- Rename or not. `appsec-architect-reviewer` appears in the agent file, the turn-budget test, the logging table, `resolve_config` keys, the completion-summary regexes at `scripts/render_completion_summary.py:690–719`, and the cost model. Keeping the id for v1 and changing only its contract and its display label avoids a wide rename inside a behavior change.
- May the editor shorten a section, or only rephrase? Shortening interacts with `agents/shared/sec7-quality-bar-rules.md` and the substance verdicts in `section_integrity.py`.
