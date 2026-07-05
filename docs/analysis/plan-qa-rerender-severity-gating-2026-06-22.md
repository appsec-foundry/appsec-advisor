# QA re-render: severity gating (blocking vs cosmetic)

**Date:** 2026-06-22
**Status:** IMPLEMENTED 2026-06-22 (qa_checks.py + SKILL-impl.md + tests + CHANGELOG; uncommitted)
**Goal:** Trigger the re-render loop only on genuine defects, not on cosmetic
findings. Cosmetics are still surfaced (warnings), but burn
no loop iterations (fragment-fixer dispatch + recompose, LLM, ~minutes).

---

## 1. Current state (verified in code)

Before each agent dispatch, this runs deterministically:

```bash
python3 scripts/qa_checks.py repair_plan threat-model.md $OUTPUT_DIR
GATE_EXIT=$?
```

`cmd_repair_plan` (qa_checks.py:2413) → the exit code drives the skill flow
(SKILL-impl.md ~3280–3550):

| Exit | `status`        | Skill action |
|------|-----------------|--------------|
| 0    | `pass`          | no re-render |
| 1    | `fail`          | **re-render loop** (apply_repair_plan → fragment-fixer → recompose), max 3 iter. |
| 2    | (tool error)    | QA agent as fallback |
| 3    | `manual_review` | loop skipped, QA agent once (no fragment can fix it) |

**The only threshold** (`_classify_plan_status`, qa_checks.py:2405):

```python
actionable = any(a.get("fragments_to_rewrite") for a in actions)
if not issues:            return "pass", actionable          # exit 0
if actions and not actionable: return "manual_review", actionable  # exit 3
return "fail", actionable                                    # exit 1 → Re-Render
```

**→ There is no severity distinction whatsoever.** As soon as *any* action carries a
non-empty `fragments_to_rewrite`, it's exit 1 → re-render. `thorough`
makes this worse, because `QA_DEPTH=extended` arms *more* of these checks and
additionally activates stage 4 (architect review, its own loop).

---

## 2. All re-render-driving action types + proposal

Only types with a non-empty `fragments_to_rewrite` drive the loop today (exit 1).
Types with an empty `fragments_to_rewrite` (infobox, posture_*, placeholders,
yaml_md_consistency) already go to `manual_review`/exit 3 today — **not
the subject of this change.**

| # | `type` | Check / finding | Today | **Proposal** | Rationale |
|---|--------|----------------|-------|---------------|------------|
| 1 | `mermaid_syntax` | invalid Mermaid block | loop | **blocking** | breaks diagram render |
| 2 | `toc_nested_link` | link in §3 heading | loop | **blocking** | breaks §3 TOC |
| 3 | `auth_method_decomposition` | §7.2 IAM not decomposed by mechanism | loop | **blocking** | §7 contract structure |
| 4 | `validation_approach_first` | §7.6 doesn't open with an approach block | loop | **blocking** | §7 contract structure |
| 5 | `control_subsection_coverage` | §7.x H4 control shape missing | loop | **blocking** | §7 v2 contract |
| 6 | `missing_required_subsection` | required subsection missing | loop | **blocking** | contract |
| 7 | `missing_section` | whole section missing | loop | **blocking** | contract |
| 8 | `forbidden_ms_heading` | disallowed MS `###` | loop | **blocking** | MS structure |
| 9 | `table_schema_drift` | table columns ≠ contract | loop | **blocking** | data rendering wrong |
| 10 | `walkthrough_coverage` | Critical walkthrough missing entirely | loop | **blocking** | genuine content gap |
| 11 | `unclassified` | unknown finding | loop | **blocking** | safe default |
| 12 | `section_order_drift` | section in wrong order | loop | **blocking** | usually pure recompose, cheap |
| 13 | `required_subsection_order_drift` | subsection order | loop | **blocking** | contract order |
| 14 | `relevant_findings_bullet_list` | inline instead of bullet list `**Relevant findings**` | loop | **cosmetic** | purely presentational (user decision) |
| 15 | `chain_tid_consistency` | chain node cites the "wrong" T-NNN (keyword heuristic) | loop | **blocking** | wrong T-ID reference = correctness (user decision) |
| 16 | `walkthrough_depth` | §3.x body shorter than threshold / missing alt/else / 3-node stub | loop | **cosmetic** | content thinness, no correctness |
| 17 | `chain_compactness` | §3.1 chain >6 nodes / layout keyword | loop | **cosmetic** | pure readability |
| 18 | `diagram_compactness` | §2.3/§2.4 diagram >7 nodes | loop | **cosmetic** | pure readability |
| 19 | `recon_iam_bridge` | recon MFA evidence missing in §7 | loop | **cosmetic** | content hint (user decision) |

**Borderline decisions (2026-06-22 final):**
- **#14 `relevant_findings_bullet_list` → cosmetic** (user: "inline vs bullet" trivial).
- **#15 `chain_tid_consistency` → blocking** (user: a wrong T-ID reference is critical).
- **#19 `recon_iam_bridge` → cosmetic** (user).

**`COSMETIC_ACTION_TYPES` (code, qa_checks.py):** `diagram_compactness`,
`chain_compactness`, `walkthrough_depth`, `relevant_findings_bullet_list`,
`recon_iam_bridge`. Everything else = blocking.

---

## 3. Implementation (severity field + loop gate — chosen approach)

### 3a. Producer: `qa_checks.py`

1. **Central map** instead of scattered strings:
   ```python
   COSMETIC_ACTION_TYPES = frozenset({
       "diagram_compactness", "chain_compactness",
       "walkthrough_depth", "chain_tid_consistency", "recon_iam_bridge",
   })  # exact set per your approval of #14/#15/#19
   ```
2. Every `actions.append({...})` gets:
   ```python
   "severity": "cosmetic" if a_type in COSMETIC_ACTION_TYPES else "blocking",
   ```
   (A helper `_severity_for(type)` instead of 19× hand-edit; sets the field
   afterward in the dedup loop at 2351 for all actions.)
3. **Rewrite the gate** (`_classify_plan_status`, 2384):
   ```python
   blocking = any(a.get("fragments_to_rewrite")
                  and a.get("severity") != "cosmetic" for a in actions)
   cosmetic = any(a.get("fragments_to_rewrite")
                  and a.get("severity") == "cosmetic" for a in actions)
   if not issues:                       return "pass", blocking
   if blocking:                         return "fail", blocking          # exit 1
   if cosmetic:                         return "cosmetic_advisory", blocking  # NEW → exit 4
   return "manual_review", blocking                                      # exit 3
   ```
4. **`cmd_repair_plan`** (2413): neuer Branch
   ```python
   if plan["status"] == "cosmetic_advisory":
       plan_path.write_text(...)   # plan PRESERVED for surfacing
       return 4
   ```
   The plan file stays (unlike `pass`, which deletes it) → the completion
   summary can display the cosmetic advisories.

### 3b. Consumer: `SKILL-impl.md` re-render loop (~3280–3330)

New exit branch alongside 0/1/2/3:
```
GATE_EXIT == 4 → cosmetic_advisory:
   - NO re-render, NO fragment-fixer.
   - .qa-status.json: status="pass" + cosmetic_advisories[] from .qa-repair-plan.json.
   - Banner: "N cosmetic QA notices (no re-render)" + list.
   - Loop exit as for pass.
```

### 3c. Opt-out (repo pattern, optional)

`APPSEC_QA_COSMETIC_BLOCKING=1` → `COSMETIC_ACTION_TYPES = frozenset()` at
runtime, i.e. old behavior (everything blocking). Default = new behavior.

### 3d. Contract obligations (AGENTS.md §4 — bidirectional)

- [ ] `qa_checks.py` — severity field + gate + exit 4 (producer)
- [ ] `SKILL-impl.md` — exit-4 branch (consumer)
- [ ] `data/required-permissions.yaml` — check whether a new path/command is needed (probably not)
- [ ] Repair-plan schema (if present) — allow `severity` + `status: cosmetic_advisory`
- [ ] Tests: `_classify_plan_status` (blocking-only→fail, cosmetic-only→cosmetic_advisory,
      mixed→fail, empty-fragments→manual_review), `cmd_repair_plan` exit-4,
      opt-out env. Drift guard for the SKILL-impl exit branch.

---

## 4. Impact & risk

- **Thorough benefits most:** exactly the `extended` checks (#15–#19) are
  the cosmetic ones — re-render will henceforth occur only on render/contract/content
  defects.
- **No silent swallowing:** cosmetics remain visible in the plan + completion summary
  (exit 4, plan file preserved).
- **"Fix the producer" stays intact:** we relax no schema, we patch
  nothing downstream — we only downgrade the loop trigger.
- **Low risk:** purely in the gate classification; default behavior reversible via
  env; borderline cases explicitly presented to you for approval.
- **Not covered:** the stage-4 architect repair loop (`.architect-repair-plan.json`)
  is a separate mechanism. If the same severity gating is wanted there
  → its own follow-up step.

---

## 5. Decisions (2026-06-22, final & implemented)

1. Borderline: #14 cosmetic, #15 blocking, #19 cosmetic.
2. **Exit code 4** (`cosmetic_advisory`) — plan file stays for surfacing.
3. **Opt-out env `APPSEC_QA_COSMETIC_BLOCKING=1`** implemented.

## 6. Verification

- `tests/test_qa_checks_cov_band1.py`: `_action_severity` (cosmetic/blocking/env
  override), `_classify_plan_status` (cosmetic-only→`cosmetic_advisory`+
  actionable False, mixed→fail, no-severity→blocking-default), `cmd_repair_plan`
  cosmetic-only→exit 4 + plan preservation.
- Subset green: `test_qa_checks_cov_band1` / `test_qa_checks` / `test_apply_repair_plan`
  (314 passed, 1 skipped) + regression `test_skill_auto_retry` /
  `test_compose_threat_model_cov2` / `test_check_inline_shortcut` (211 passed).
- ruff clean. Existing `_classify_plan_status` tests unchanged, green
  (backward compatibility: action without `severity` = blocking).
