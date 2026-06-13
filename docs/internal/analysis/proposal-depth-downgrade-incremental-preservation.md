# Proposal: Preserve richer content on depth-downgrade incremental scans

**Status:** Design only — nothing implemented.
**Date:** 2026-06-13
**Scope:** The `standard|thorough → quick --incremental` path on the same repo.
**Author:** design pass (code-verified, file:line cited)

---

## 1. Problem

A user runs `standard`/`thorough`, then later runs `--quick --incremental` on the
same repo. The expected contract (and the one the pipeline *mostly* honours) is:

> Quick **adds/changes only what its own scan actually verified, and preserves
> everything else** carried forward from the richer prior run.

Two places violate that contract:

- **Gap A — §3 Attack Walkthroughs is dropped, not carried.** §7 Security
  Architecture has a deliberate verbatim carry-forward (`_resolve_security_arch_override`);
  §3 has no equivalent and is hard-dropped at quick depth. Asymmetry by omission,
  not by design.
- **Gap B — a changed (DIRTY) component re-scanned at shallower depth can silently
  lose prior threats.** The whole `.stride-<id>.json` is replaced. The analyzer's
  prior-finding re-verification has only a binary disposition (confirm→keep /
  affirmatively-gone→drop) with **no "inconclusive at shallower depth → carry"
  branch**, and the claimed "resolved-list captures it" reconciliation does not
  exist for non-removed components. A quick re-scan that simply doesn't look hard
  enough produces a **false resolution**.

The two gaps are coupled (see §5): Gap B can change the Critical set, which is
exactly what makes a verbatim §3 carry (Gap A's fix) unsafe.

---

## 2. Verified root cause (code-cited)

### Gap A — §3 vs §7 asymmetry

| Concern | §7 (has carry-forward) | §3 (dropped) |
|---|---|---|
| Resolver | `_resolve_security_arch_override` `compose_threat_model.py:1284` | none |
| Extractor | `_extract_section_verbatim(..., top_level_number=7)` `:1353` (already generic — takes any N) | n/a |
| Stability gate | `_verbatim_fnnn_refs_match` `:1539` (F-NNN title-drift guard) | n/a |
| ctx field | `security_arch_override` `:224`, set `:14306` | n/a |
| eval flag | `render_security_architecture` `:14313` | `skip_attack_walkthroughs` `:14292` (set true when depth==quick) |
| consume | body handler `:8559`; TOC respects flag | contract condition `not skip_attack_walkthroughs` `sections-contract.yaml:83,147,179` |

§3 current render path: handler `compose_threat_model.py:8718` → intro injector
`:8778` over fragment `.fragments/attack-walkthroughs.md`. Quick sets
`skip_attack_walkthroughs` → composer drops heading, body, TOC entry, the §8
back-link, and emits the quick-notice bullet `:1828`.

**§3-specific hard constraint that §7 does not have:** §3 is **per-Critical**
(one `### 3.N` block per Critical finding; contract requires *exactly N* H3
blocks, `sections-contract.yaml:~825`). QA `check_walkthrough_coverage`
(`qa_checks.py:~6380`) enforces the 1:1 Critical↔§3.N mapping and **cannot be
bypassed** the way the §7 pattern checks can. So a verbatim §3 carried from a run
whose Critical set differs from the current run is not just stylistically stale —
it **fails QA** (wrong H3 count) and cites T-NNN that may no longer exist.

### Gap B — dirty-component prior-threat loss

- Dispatch decision: `phase-group-threats.md:46-120`. DIRTY component → re-dispatch,
  **"Overwrite `.stride-<component-id>.json`"** (`:50`). Carry-forward (`:51-58`)
  is whole-file reuse, integrity-checked; **no threat-level merge** within a
  component. Dirtiness is whole-component (`:82`).
- Merge: `merge_threats._load_stride_outputs:103`, `_flatten_threats:189`,
  `_assign_t_ids:985` — global re-sort, T-IDs reassigned every run; a prior
  threat absent from the new stride file simply isn't in the merged set.
- **A prior-threat channel already exists** (the agent-claimed "no channel" is
  wrong): `PRIOR_FINDINGS_INDEX_PATH` (`appsec-stride-analyzer.md:80,122`,
  `phase-group-threats.md:209,239`). The analyzer is told (`:117-124`):
  - prior finding `status: open` → **mandatory** verification target;
  - re-read confirms → emit with `evidence_check: "verified-prior"`;
  - **"re-read shows the code changed and the issue is gone → do NOT emit (the
    orchestrator's resolved-threats list captures it instead)."**
- **The two real defects, both verified:**
  1. **Binary disposition, no depth-awareness.** `:124` has only confirm-or-gone.
     There is no "couldn't affirmatively confirm at this (shallower) depth →
     carry forward unchanged" branch. Quick profile weakens verification
     (`skip_verification_greps: true`, `appsec-stride-analyzer.md:246`), so a
     still-present threat that the quick scan doesn't re-confirm falls into the
     "gone" bucket → **false resolution**.
  2. **The reconciliation it relies on doesn't exist for dirty components.**
     `resolved.threats` is only ever populated for **removed components**
     (`phase-group-threats.md:62`); the changelog builder initialises it empty
     (`build_threat_model_yaml.py:968`) and `carried_forward_components` is
     initialised `[]` (`:961`) and never populated by the pipeline (only *read*
     back by `render_completion_summary.py:300,323`). So a prior threat that the
     analyzer "does not emit" for a still-present, changed component is **neither
     kept nor recorded as resolved-with-reason — it silently vanishes.**

---

## 3. Fix A — give §3 the same carry-forward as §7

Mirror the §7 tri-state, with a **stricter** stability gate keyed on the Critical
set (because of the per-Critical 1:1 QA constraint).

### Mechanism (mirrors §7 exactly)
- New resolver `_resolve_attack_walkthroughs_override(output_dir, current_depth,
  current_threats, current_critical_ids)` → tri-state `None | "" | <verbatim>`,
  same semantics as §7.
- Reuse `_extract_section_verbatim(prior_md, top_level_number=3)` — already generic.
- New ctx field `attack_walkthroughs_override` + eval flag
  `render_attack_walkthroughs`, set right after the resolver (mirror `:14306`,
  `:14313`).
- Body handler `:8718` checks the override before fragment load (mirror `:8559`).

### Stability gate (the §3-specific part — stricter than §7)
Carry verbatim **only if** the current Critical set is identical (by stable
identity) to the prior run's Critical set that produced §3:
1. Count `### 3.\d+` blocks in the extracted prior §3; require it equals
   `len(current_critical_ids)`.
2. Every T-NNN cited in the prior §3 still exists in `current_threats` with the
   same title (the T-NNN analog of `_verbatim_fnnn_refs_match`).
3. Each current Critical maps 1:1 to a prior §3.N block.
Any mismatch → return `""` (drop, render the skip placeholder). **Better absent
than QA-failing or mis-referenced.**

### Contract / consumers
- `sections-contract.yaml`: change the three `attack_walkthroughs` conditions
  from `not skip_attack_walkthroughs` to a new `render_attack_walkthroughs`
  (mirror `render_security_architecture`). Keep `skip_attack_walkthroughs` as the
  *authoring*-skip signal so the quick run still doesn't author §3; the new flag
  governs whether the **carried** body renders. (`:83,147,179` and the
  `required_patterns_condition` / `per_critical_subsection_condition` at
  `~815,817,870`.)
- `check_walkthrough_coverage` (`qa_checks.py:~6380`): when §3 is a verbatim
  carry, it must validate against the **current** Critical set — which the gate
  guarantees matches, so the check passes by construction. Add a test asserting
  it does not fire on a stable-Critical carry and *does* drop the carry on a
  changed Critical set.
- Quick-notice (`:1828`) and skipped-sections placeholder (`:1874`, today only
  names §6/§7): add the third state "§3 preserved from prior standard/thorough
  run".
- TOC children for §3 are scanned live from the fragment (`:1985`). A verbatim
  carry must feed the **carried** body to the children scan, not the (stale/empty)
  quick fragment — otherwise TOC child count ≠ body. This is a real divergence
  from §7 (whose children aren't per-fragment-scanned the same way) and **must be
  handled**, else TOC/body mismatch.

---

## 4. Fix B — preserve prior threats of a changed component at shallower depth

Reuse the existing `PRIOR_FINDINGS_INDEX_PATH` channel — **do not invent a new
hypothesis sidecar.** Two targeted changes close both verified defects.

### B1 — depth-aware disposition (closes the false-resolution)
Pass the prior run depth (already on disk: `baseline.json.last_run_depth`) and the
current depth into the dirty-component dispatch context. Extend the analyzer rule
at `appsec-stride-analyzer.md:124` with a third branch:

> When the current scan depth is **shallower** than the depth that produced the
> prior finding, a prior `status: open` finding that you cannot **affirmatively**
> show to be fixed (control added / vulnerable path removed / input now
> validated) must be **carried forward unchanged** with `evidence_check:
> "carried-unverified-shallower-depth"`, **not** dropped. Only an affirmative
> fix observation resolves it. Absence of confirmation at reduced depth is **not**
> evidence of a fix.

This makes "quick can only *remove* a prior threat when it actually verified the
fix" true — exactly the user's mental model.

### B2 — real reconciliation (closes the silent vanish)
Add a deterministic reconciliation in the merge/builder step (NOT the LLM):
for each DIRTY component, diff `prior threats for this component` (from the
baseline yaml) against `threats emitted in the new .stride-<id>.json`:
- emitted & matched (by stable fingerprint: component + CWE + normalized title +
  file) → keep, preserve prior T-ID;
- prior present, **not** emitted, **and** analyzer recorded an affirmative fix →
  `resolved.threats[]` + `reason_by_id` (the path that `:124` *claims* exists);
- prior present, not emitted, **no** affirmative fix → **carry forward** (re-inject
  the prior threat) rather than drop. Belt-and-suspenders behind B1 in case the
  analyzer drops it anyway.
Populate `carried_forward_components` (`build_threat_model_yaml.py:961`) and the
changelog `resolved/changed` buckets so the completion summary
(`render_completion_summary.py:300,323`) stops reading an always-empty field.

### Schema / touchpoints
- `schemas/threats-merged.schema.yaml`: add the `evidence_check` enum value
  `carried-unverified-shallower-depth` (the field already exists/used at
  `appsec-stride-analyzer.md:124`); confirm `resolution_reason` is representable.
- T-ID stability: B2's fingerprint-match must preserve the prior T-ID for a
  confirmed/carried prior threat so refs and traceability don't churn
  (`_assign_t_ids:985` currently reassigns globally — the reconciliation runs
  **after** assignment and rewrites matched IDs back, or pins them before sort).
- `data/required-permissions.yaml`: B1 adds a read of `baseline.json` /
  dispatch-context in a place that may be new → re-check the permission manifest
  + `tests/test_check_permissions.py`.

---

## 5. The coupling (why these are one proposal, not two)

In incremental mode threats are largely carried forward per-component, so on an
**unchanged** repo the Critical set is identical and Fix A's gate trivially
passes — §3 carries safely. The Critical set only diverges when a DIRTY component
re-scan **changes** the threat picture — which is precisely Gap B's domain.
**Fix B keeps the threat/Critical set stable across a depth-downgrade re-scan,
which is what makes Fix A's verbatim §3 carry safe in the common case.** Ship B
first (or together); A on its own is correct but its gate will conservatively
drop §3 more often than necessary whenever B's instability is present.

---

## 6. Side conditions / constraints (the ones that bite)

1. **§3 per-Critical 1:1 + un-bypassable QA** (`check_walkthrough_coverage`) — the
   single hardest §3 constraint. The Critical-set gate is mandatory, not optional.
2. **TOC children for §3 are fragment-scanned** — verbatim carry must redirect the
   children scan to the carried body (divergence from §7).
3. **T-ID reassignment is global every run** (`_assign_t_ids:985`) — any
   carry/confirm path must pin or rewrite IDs back, or traceability (§7 F-NNN gate,
   abuse-case refs, mitigation register) churns.
4. **"Don't emit" ≠ "resolved" today** — the reconciliation B2 adds is genuinely
   missing; without it, B1 alone still loses threats if the analyzer under-emits.
5. **Genuinely-fixed threats must still resolve** — B must not resurrect a threat
   the change actually fixed. That's why resolution requires an **affirmative** fix
   observation, and component-removal keeps its existing resolved path
   (`phase-group-threats.md:62`) untouched.
6. **Requirements-drop hard-abort already guards one downgrade hazard**
   (`resolve_config.py:976`) — these fixes are orthogonal to it; don't disturb it.
7. **Prior MD must exist on disk** for both §3 and §7 carries (incremental keeps
   `threat-model.md`; verify cleanup whitelist `docs/internal/contracts/audit-artifacts.md`
   doesn't reap it).

---

## 7. Test plan

- **Fix A:** mirror the existing §7 tests (`test_compose_threat_model.py:2544,2564`)
  for §3: stable-Critical→verbatim carries; dropped/added/reordered Critical→drop;
  T-NNN title drift→drop. QA: `check_walkthrough_coverage` passes on stable carry,
  drops on changed set (`test_qa_checks.py:~273`). TOC child-count == carried-body
  H3-count. Update incremental drift tests (`test_incremental_mode.py:792,858,888`).
- **Fix B:** unit-test the reconciliation diff (prior−emitted → keep/resolve/carry)
  with depth-shallower vs depth-equal; assert a still-present prior threat is
  carried (not resolved) when quick under-confirms; assert an affirmatively-fixed
  prior threat resolves with reason; assert T-ID preserved on carry; assert
  `carried_forward_components` / changelog buckets populated.
- **Live:** one `thorough` then `--quick --incremental` on juice-shop; assert
  count does not collapse, §3 present, no false resolutions, §7+§3+§9 all carried.

---

## 8. Risks

- **Carrying a stale threat the fix actually removed** (Fix B over-preserves) —
  mitigated by requiring affirmative-fix to resolve, but a shallow scan that
  *should* have resolved will now keep → slightly conservative (over-report) rather
  than under-report. For a security tool, over-report is the safer failure
  direction; acceptable and matches the user's stated preference ("only remove what
  you verified").
- **Verbatim §3 prose referencing changed prose elsewhere** — the Critical-set +
  T-NNN gate covers the structural refs; free-prose mentions of other sections are
  the same residual risk §7 already accepts.
- **Scope creep into the merge/T-ID path** — Fix B touches `_assign_t_ids`
  adjacency, historically a churn-prone area; keep the reconciliation a clearly
  separated post-pass.

---

## 9. Recommendation & sequencing

1. **Fix B first** (B1 depth-aware disposition + B2 reconciliation) — it fixes a
   real correctness/coverage regression (silent threat loss), which matters more
   than §3 cosmetics, and it stabilises the Critical set that Fix A depends on.
2. **Fix A second** — pure parity with §7, low risk once B holds the Critical set
   stable; mostly a mechanical mirror plus the per-Critical gate + TOC-children
   redirect.

Both are bidirectional contract changes (producer + schema + consumer + QA +
tests per AGENTS.md Editing Guidance); none should be a template-only or
prompt-only edit.
