# Implplan — Standalone Weakness Register + bidirectional cross-referencing

**Status:** IMPLEMENTED 2026-07-14 (`dev`, uncommitted). All 6 phases landed;
Hybrid (C) mitigation model. juice-shop deliverable + PDF regenerated; full test
suite green (9375+ passed). See "Implementation record" at the end.

**User chose:** Hybrid (C) mitigation integration (§4) and phased implementation.

**Author context:** Follows the juice-shop thorough v0.4.1 run. Builds on
[implplan-design-weakness-emphasis.md] (systemic_posture MS table, DONE
2026-07-13) and [proposal-weakness-class-evidence-model.md] (the
`build_weakness_register` data model). This plan does **not** re-derive the
weakness data — it re-homes and cross-links it.

---

## 1. Analysis — current state and my opinion

### 1.1 What already works (keep it)

`merge_threats.build_weakness_register()` produces a genuinely good data model.
For the juice-shop run it emitted 9 weaknesses (`W-001..W-009`), each carrying:

- `kind` (`design` | `implementation`), `severity`, `severity_basis`
  (`confirmed` | `design-risk` | `observed-practice`)
- `instances[]` — the **confirmed findings** (`T-NNN`) that prove the gap
- `observable_backing.practice_evidence[]` — folded practice sites (`T-NNN` +
  file:line) for implementation weaknesses
- `observable_backing.absent_control_signal[]` — design-gap evidence
- `affected_components[]`, `implementation_strategy`

**The weakness→finding link already exists in the data** (`instances[].id`,
`practice_evidence[].id`). Nothing new needs to be computed to cross-reference —
it just isn't rendered as links today.

### 1.2 What does not work (the problems)

1. **It is not a register, it is an MS appendix.** `document.order` places
   `systemic_weaknesses` at position 5 — immediately after `management_summary`,
   *before* `system_overview`. It reads as a management-summary spill-over, not a
   first-class artifact peer to the Findings Register (pos 16) and Mitigation
   Register (pos 18).

2. **The prose is thin and templated (near-AI-slop).**
   `_render_systemic_weaknesses` emits statements like *"Route Authentication is
   not consistently enforced."* — a mechanical restatement of the title. There is
   no explanation of *what* the control is, *why* the gap is systemic, or *how*
   the evidence proves it.

3. **The cross-references are absent or one-directional.**
   - Weaknesses do **not** render clickable `F-NNN` links to their instances or
     practice evidence (the ids sit in the data, unused).
   - Findings (§8) carry **no** back-link to the weakness they instantiate.
   - §7 Security Architecture references findings directly rather than the
     weakness that owns the control gap.

4. **The finding/practice-evidence duplication tension** — the root cause of the
   broken links repaired in this run. A practice-tier finding (crypto:
   `T-006/020/027/047`) is folded into a weakness *and* suppressed from §8
   (`compose:_render_threat_register` drops `evidence_tier == "insecure-practice"`
   when `weaknesses` exist). But those same findings are referenced by `F-NNN`
   across §2/§4/§5/§7/§3 — so the suppressed §8 anchor left ~22 dangling links.
   The model cannot decide whether a practice finding is a first-class finding or
   a subordinate evidence row.

5. **Tracking gap.** `systemic_weaknesses` is in `document.order` but missing from
   the composer's `render-integrity.json` manifest (the `section_integrity`
   expected-vs-actual mismatch observed this run). Cosmetic today, but it means the
   section escapes the per-section integrity matrix.

### 1.3 My recommendation

Elevate the weakness concept to a **true peer register** and make the three
registers a coherent triangle:

- **Weakness** = the *root cause* / systemic control gap (the "why").
- **Finding** = the concrete *instance* with code evidence (the "where").
- **Mitigation** = the *remediation* (the "fix").

Concretely: **findings are always first-class** (never suppressed from §8);
weaknesses **aggregate** findings by root cause; every edge is bidirectional and
clickable. This dissolves the §1.2(4) tension — a practice finding is a normal
finding *and* is listed as evidence under its weakness, with links both ways.

---

## 2. Target structure

### 2.1 New standalone `## Weakness Register` (user points 2, 3, 9, 11)

- **Rename** `## Systemic Weaknesses` → `## Weakness Register` (peer to Findings /
  Mitigation registers).
- **Reposition** in `document.order`: move from pos 5 (after MS) to **immediately
  before `threat_register`** (pos 16). New order tail: `… security_architecture,
  requirements_compliance, weakness_register, threat_register, abuse_cases,
  mitigation_register, …`.
- **Per-weakness card** (structured, not prose-only):
  - Heading: `### <emoji> W-NNN — <control name>` with stable anchor `#w-nnn`.
  - **What / Why** (2–4 sentences, deterministic template filled from
    `weakness_class` vocabulary + `severity_basis` + component spread — see §3.2).
    No LLM slop; more explanation than today's one-liner.
  - **Evidence** row: `Instances:` clickable `F-NNN` list (from `instances[]`) +
    `Practice sites:` clickable `F-NNN` list (from `practice_evidence[]`) +
    `Absent controls:` short phrases (from `absent_control_signal[]`).
  - **Affected components:** `C-NN` links.
  - **Remediation:** per the §4 decision.
- Weaknesses get **working internal links** (point 11): the register is the anchor
  home for every `#w-nnn`; all other sections link *to* it.

### 2.2 Findings reference weaknesses (user point 8)

- §8 (Findings Register) story card gains a **`Weakness:`** field: `W-NNN` link
  when the finding is an instance or practice site of a weakness. Derived by
  inverting `instances[]`/`practice_evidence[]` into a `finding_id → weakness_id`
  map at compose time (deterministic, no new data).
- **Stop suppressing practice-tier findings from §8.** They render as normal
  finding cards (this run's manual yaml fix becomes the systematic behaviour) and
  carry the `Weakness:` back-link. Removes the dangling-link class entirely.

### 2.3 §7 Architecture references only weaknesses (user point 4)

- In `security-architecture.md` control subsections, replace direct `F-NNN`
  citations with the owning `W-NNN` link (the weakness is the architectural unit;
  the finding is an implementation instance). Findings remain reachable one hop
  away via the weakness card. Falls back to `F-NNN` only when a control gap has no
  weakness (rare; log it).

### 2.4 MS `### Top Weaknesses` (user point 10)

- New MS sub-section inserted **between `### Architecture Assessment` and
  `### Mitigations`** (i.e., before "top mitigations"), so the enforced MS order
  becomes SIX: `Verdict, Top Findings, Architecture Assessment, Top Weaknesses,
  Mitigations, Operational Strengths`.
- Content: the top N weaknesses by severity (Critical/High first), each with a
  one-line proof (`W-NNN — <name>` + severity + a "proven by F-NNN, F-NNN"
  clause). Table, consistent with Top Findings/Mitigations style.
- Requires updating `agents/shared/ms-template.md` (the "exactly FIVE required
  sub-sections" contract → SIX) and the qa `ms_structure` check.

### 2.5 Weaknesses reference both (user point 9)

Already covered: the weakness card links **down** to findings (§2.1 Evidence) and
is linked **from** §7 architecture (§2.3) and §8 findings (§2.2) — bidirectional.

---

## 3. Implementation phases (each with a verify step)

### Phase 0 — data plumbing (no visible change)
- Add `compose`-time inverse map `finding_id → weakness` from
  `instances[]`/`practice_evidence[]`. **Verify:** unit test asserts every
  `W-NNN.instances[].id` appears in the map.

### Phase 1 — first-class practice findings
- Remove the `evidence_tier == "insecure-practice"` suppression in
  `_render_threat_register`; findings always render. **Verify:** `toc_closure` on
  a repo with practice findings → 0 broken `#f-nnn`; §8 count == `len(threats)`.

### Phase 2 — standalone Weakness Register
- Rename section, add `weakness_register` to `document.order` before
  `threat_register`, register it in `render-integrity.json`, add to
  `sections-contract.yaml` + qa `contract`/`toc_contract`. Rewrite
  `_render_systemic_weaknesses` → `_render_weakness_register` with the §2.1 card.
  **Verify:** `section_integrity` expected==actual (closes the current mismatch);
  `final_structure` passes; new golden-doc test.

### Phase 3 — cross-references
- §8 `Weakness:` field (point 8); §7 F-NNN→W-NNN swap (point 4); weakness Evidence
  links (point 9). **Verify:** link gate 0-broken for all `#w-nnn`/`#f-nnn`; a
  test asserts each §7 control subsection cites a `W-NNN`.

### Phase 4 — MS Top Weaknesses
- New sub-section (point 10); update `ms-template.md` + qa `ms_structure` FIVE→SIX.
  **Verify:** `ms_structure` passes with the six ordered sub-sections; a golden MS
  test asserts `Top Weaknesses` sits between Architecture Assessment and Mitigations.

### Phase 5 — better descriptions
- Extend `data/weakness-classes.yaml` with a `description`/`why_systemic` template
  per cluster; `_render_weakness_register` fills the What/Why from it +
  component-spread facts (point 3). **Verify:** no weakness card emits only the
  title restatement; snapshot test on the 9 juice-shop weaknesses.

---

## 4. Mitigation integration — decision needed (user's open question)

Three models; I recommend **C (hybrid)**.

| Model | How | Pro | Con |
|---|---|---|---|
| **A. Weakness-centric** | Mitigations attach to weaknesses; findings inherit | Clean "fix the root cause" story | Loses per-finding actionability; big rewrite of `M-NNN → finding` links |
| **B. Finding-centric (status quo)** | Mitigations stay on findings; weakness rolls up the union of its findings' mitigations | No data-model change; reuses existing `M-NNN` links | A design weakness's *structural* fix is invisible if no single finding carries it |
| **C. Hybrid (recommended)** | Tactical `M-NNN` stay finding-level; each weakness shows (a) the deduped roll-up of its findings' mitigations **and** (b) an optional weakness-level *structural* mitigation for the root cause | Keeps per-finding fixes shippable **and** surfaces "the real fix is architectural"; mirrors abuse-case "blocking mitigations" roll-up already in the codebase | One new optional field (`weakness.structural_mitigation`) + roll-up render logic |

**Why hybrid:** a design weakness like W-002 "no centralised authorization policy"
is only *truly* closed by a structural change that no single finding-patch
delivers — but the individual IDOR/mass-assignment findings still need their
tactical patches shipped now. Pure-A hides the tactical work; pure-B hides the
architectural message. Hybrid's Weakness Register "Remediation" cell =
`structural_mitigation` (if present) + deduped tactical `M-NNN` set covering the
weakness's findings. This is the **same roll-up shape** already used by
`render_abuse_cases._blocking_mitigations`, so the mental model and code pattern
are consistent.

**If C is chosen:** structural mitigations are authored where design signals are
(the arch-coverage / impl-strategy bridge already knows the control class), so
`build_weakness_register` can attach a `structural_mitigation` id deterministically
for `kind == "design"` weaknesses; the tactical roll-up is pure compose-time
aggregation (no new authoring).

---

## 5. Risks / open questions

- **Section renumber blast radius.** Adding `weakness_register` before
  `threat_register` shifts §8→§9, §9→§10, … The display renumber
  (`renumber_sections_display.py`) and every literal `§N` in qa contracts must be
  swept. (This is exactly the class of bug fixed this run for the `--`
  double-hyphen slugs — budget for it.)
- **MS FIVE→SIX contract** touches the thin-parallel MS renderer contract
  ([implplan-management-summary-thin-parallel-contract-alignment-2026-07-04.md]);
  keep the two in sync.
- **Practice findings now in §8** raises the §8 count (juice-shop: +4). Confirm the
  triage top-N and severity distribution still read correctly.
- **Open:** should a weakness with only `design-risk` backing (no confirmed
  instance, no practice site — currently suppressed unless `has_absent`) ever
  appear in the register, or stay MS-only? Proposed: register-worthy only when it
  has ≥1 clickable finding or practice site; pure design-risk stays in the MS
  systemic_posture table.

---

## 6. Requirement → change traceability (verification of the plan)

| User point | Addressed by | Verify |
|---|---|---|
| 2 standalone register before Findings | §2.1 + Phase 2 | `document.order`; section_integrity |
| 3 better descriptions, no slop | §2.1 + Phase 5 | snapshot: no title-only cards |
| 4 §7 → weaknesses only | §2.3 + Phase 3 | test: each §7 control cites `W-NNN` |
| 8 findings → weaknesses | §2.2 + Phase 3 | §8 `Weakness:` field; link gate |
| 9 weaknesses → both | §2.1/§2.3 + Phase 3 | bidirectional link test |
| 10 MS Top Weaknesses before mitigations | §2.4 + Phase 4 | ms_structure order test |
| 11 working internal links | §2.1 + Phase 3 | `toc_closure` 0-broken for `#w-nnn` |
| 12 plan + verify + mitigation proposal | this doc + §4 | — |

---

## Implementation record (2026-07-14, `dev`, uncommitted)

All six phases landed. Hybrid (C) mitigation model chosen by the user.

- **Phase 0** — `_build_finding_to_weakness_map` / `_get_finding_weakness_map`
  (compose): inverse map from `instances[]` + `practice_evidence[]`, both T-/F-NNN
  forms. +2 unit tests.
- **Phase 1** — removed the `evidence_tier == "insecure-practice"` suppression in
  `_render_threat_register` AND the mirrored exclusion in `qa_checks.yaml_md`
  count check. Practice findings are now first-class §8 cards (fixes the dangling
  `#f-006/020/027/047` link class at the source; the run's manual yaml band-aid
  reverted / made moot).
- **Phase 2** — heading `## Systemic Weaknesses` → `## Weakness Register`, anchor
  `weakness-register`; repositioned in BOTH `document.order` and
  `document_sets.full.order` (the latter previously *lacked* it entirely — the
  section rendered only via the management_summary backward-compat fallback with
  NO render-integrity manifest entry, which was the `section_integrity`
  expected-vs-actual mismatch; now first-class → section_integrity clean).
- **Phase 3** — §8 story card `**Weakness:**` field; weakness card links practice
  sites to F-NNN and components to C-NN; `_rewrite_sec7_table_findings_to_weaknesses`
  swaps F→owning-W in §7 control TABLES only (evidence prose keeps finding cites).
  +2 tests.
- **Phase 4** — MS `### Top Weaknesses` computed subsection injected before
  `### Top Mitigations` (compose special-case; ms-template.md notes it is
  compose-injected, not LLM-authored). Hybrid remediation: weakness card
  `**Remediation:** Structural — … · Tactical — [M-NNN]…` (structural from
  `weakness-classes.yaml class_guidance.structural_fix`; tactical = deduped
  roll-up of the weakness's findings' `mitigation_ids`). +2 tests.
- **Phase 5** — `weakness-classes.yaml class_guidance.{description,structural_fix}`
  per cluster; `build_weakness_register` attaches `description` +
  `structural_recommendation`; renderer prefers `description` over the thin
  statement.

Updated tests: `test_compose_threat_model_cov` + `test_e2e_pipeline` heading/anchor
assertions. Net: rename `Observed practice`→`Practice sites`, `Systemic
Weaknesses`→`Weakness Register`.

**Deferred / follow-ups:** structural mitigation is prose (not a dedicated M-NNN)
— M-NNN aren't assigned at `build_weakness_register` time; a future pass could
mint a design-level M-NNN. §7 evidence PROSE still cites findings (by design —
only the control-overview tables were switched to weaknesses).
