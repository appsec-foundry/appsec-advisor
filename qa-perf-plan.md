# QA Performance Plan — verified 2026-06-02

Code-level re-verification of the QA subsystem (`qa_checks.py`, `appsec-qa-reviewer.md`,
skill wiring). Two prior-memory claims were **corrected** this pass.

## Verification verdict

| Prior claim | Status |
|---|---|
| `check_invariants` numeric part is dead (regex + composer single-source + enum gate) | **HOLDS.** `SECTION_8_SUB_RE` (`### 8.1 Critical (N)`) never matches composer output (`### 🔴 Criticals (N)` @ compose:9839 / `### {emoji} {label} (N)` @ compose:11450). Risk-Dist sum + STRIDE sum both rendered from one `counts`/`stride_map` over one `threats[]`. Only PHASE_BURST (qa_checks:979-1024) is live. |
| "prose keys kept because consumed by apply_prose_fixes" | **WRONG — corrected.** `apply_prose_fixes.py` takes only `<md>`, re-runs its OWN regex passes (`_wrap_line`, `_apply_ai_padding_fixes`, `_apply_rhetorical_severity`, `_apply_perimeter_claim_strip` + whole-doc post-procs). It reads **no** pre-pass key. So those pre-pass keys reach no actuator via apply_prose_fixes. |
| ~11 prose checks reach no consumer | **HOLDS and is larger** — see Tier 1/2 below. |

## Decisive architectural finding (the real lever)

`GATE_EXIT` = exit code of **`qa_checks.py repair_plan`** only (SKILL:2715).
`qa_checks.py all` (SKILL:2721) runs unconditionally but its exit code is **discarded**
(`> .qa-prepass.json`). `all` serves two roles:
1. **Side-effect (load-bearing):** 5 in-place auto-fixers mutate the md —
   `check_links`, `linkify_anchors`, `check_ms_structure`, `check_cell_format`,
   `strip_heading_attribute_artifacts`.
2. **Detector dump:** ~47 pure checks → `.qa-prepass.json`.

On the **clean fast path** (`GATE_EXIT==0`, common case) the agent is **skipped**, so
`.qa-prepass.json` is **written and never read**. → ~47 detectors run for nobody, every clean run.

Also: `repair_plan` and `all` BOTH run the same 16 structural checks (mermaid, walkthroughs,
compactness, …) → double execution per run.

## Plan (ordered by impact)

### P1 — Split `all` into `autofix` + full detector battery  *(biggest win, fast path)*
- New subcommand `qa_checks.py autofix`: runs ONLY the 5 mutating passes above, writes back, no JSON.
- Skill: on `GATE_EXIT==0` clean path, call `autofix` only; **skip** the full `all` detector dump.
- Run full `all` (the `.qa-prepass.json` producer) **only** in the agent-dispatch branch
  (`QA_DEPTH=extended`, `APPSEC_FORCE_QA_AGENT=1`, `GATE_EXIT==2` fallback, post-loop triage).
- Effect: removes ~47 detector executions from every clean run; makes the prose-check question
  moot on the fast path. No quality loss — nobody consumed that JSON on the clean path.

### P2 — Drop hard-dead checks (consumers=0 anywhere)  *(low risk)*
Verified: referenced nowhere outside `cmd_all` + tests (no agent handoff key, not in
`build_repair_plan`, no apply_prose_fixes/renderer rule). Remove from `cmd_all` (and their fns/tests):
- `summary_bullets`
- `attack_tree_node_id_leak`
- `section_713_no_table`
- `hypothesis_validation_objective`
- `section7_finding_reference_semantic`
- `section7_narrative_placeholders`
- `section7_h4_positive_intro`
- `section7_fence_intro_sentence`
- `section7_finding_link_duplicate`

### P3 — Drop detector-only prose checks secured upstream  *(low-med risk)*
Detection has no QA-side actuator; the rule is already given to the Stage-2 **renderer**
(earlier phase) or only mentioned as a quality-bar in agent prose. Re-detecting in QA is
belt-without-braces:
- `generic_phrases`, `section_opener_restates_heading`, `paragraph_density`,
  `dependency_cross_ref`, `na_against_recon`, `finding_range_homogeneous`, `architectural_prose`
- `rhetorical_severity` (detector's 9 patterns unused; apply_prose_fixes does its own 1-phrase rewrite)
- Keep `inline_code_format` / `label_as_code` detection ONLY if the agent's "already auto-fixed"
  note is the desired audit trail; otherwise drop (apply_prose_fixes fixes independently).

### P4 — `check_invariants` numeric cut  *(securable upstream)*
- Extract PHASE_BURST (qa_checks:979-1024) → own `phase_burst` subcommand, call it from the gate path.
- Remove numeric battery (948-977). Add ONE composer unit test:
  `rendered Risk-Dist sum == STRIDE sum == len(threats)`.

### P5 — De-dup the 16 structural checks across repair_plan/all  *(med risk, defer)*
`repair_plan` runs them pre-mutation; `all` post-mutation → inputs differ, can't naively cache.
Only worth it after P1 (P1 already stops `all` running on the clean path). Low priority.

## Must-keep (do NOT drop)
- 5 auto-fixers (P1 moves them, doesn't remove).
- 16 structural checks in `build_repair_plan` (drive Re-Render Loop).
- Hard gates: `unmasked_secrets`, `evidence_integrity`, `placeholders`, `contract`,
  `yaml_md_consistency` (incremental verbatim-reuse guard @ compose:1316).
- `linkify_anchors` Pass 2 (linkifies T/M refs in LLM-fragment prose — not enum-securable).

## Security side-finding (separate from perf)
`check_unmasked_secrets` is documented as a release-blocking gate, but in the skill flow it runs
**only inside `all`** (exit code discarded). No path invokes the `unmasked_secrets` subcommand as
a gate. → currently toothless on the automated path. Recommend promoting to a real `exit 2` gate.
Independent of this perf work.
