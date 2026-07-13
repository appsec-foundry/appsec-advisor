# Implplan — Emphasise systemic design weaknesses (MS surfacing + evidence-less detectors)

**Status:** IMPLEMENTED 2026-07-13 (uncommitted, `dev`). Both gaps landed; see
"Implementation record" at the bottom. One pre-existing baseline test failure
(`test_compose_matches_golden`) is unrelated (a different uncommitted
formatting workstream backtick-wraps an HTML anchor id) and is called out there.

Extends the shipped weakness-class evidence model
(`implplan-weakness-class-evidence-model.md`, P1–P4) and the P4 design-gap fold
(commit `6b0be3e`). Goal: flag *unsafe SQL handling, weak input/output
validation, missing access control, weak authentication, weak crypto* as
first-class **design weaknesses even when no concrete SQLi/XSS/IDOR instance is
found**, and **emphasise them in the Management Summary** — not only deep in §8.

Two gaps drive this plan (both verified against code, 2026-07-13):

- **Gap B — emphasis.** The systemic posture verdict + weakness register render
  **only in §8** (`_render_security_principles` compose:14713, `_render_weakness_classes`
  compose:14750, both called from `_render_threat_register` compose:15006). The
  Management Summary (`_render_management_summary` compose:9295) never surfaces
  them; a design weakness with no concrete instance reaches the MS *only* as an
  aggregate integer in the verdict "Findings: … · Z design" line
  (`_weakness_basis_breakdown` compose:2580). The live MS Top-Threats table
  (`_compute_top_threats_rows` compose:9054) is attack-path/glyph-keyed and
  **blind to `weaknesses[]`**.
- **Gap A — production.** A `kind:design` weakness needs *observable backing*
  (`has_absent OR has_practice`, `build_weakness_register` merge_threats:1815).
  Crypto has a rich evidence-less pack (`crypto-checks.yaml`; CWE-327/328/330/916
  forced `insecure-practice`). Access-control / auth / SQLi packs exist but emit
  **concrete instances**, not evidence-less design gaps — their design-level
  surfacing depends entirely on the *LLM-soft* arch-coverage absent-control
  bridge (`arch_coverage_to_threats.build_design_signals`:255). **Input/output
  validation and output-encoding have NO dedicated deterministic detector** — if
  the Phase-9 assessment stays silent, no weakness is produced.

Contract rule (AGENTS.md §4): every schema/producer/consumer/test moves
together. `file:line` targets are from the 2026-07-13 fact base; confirm at
implementation time (lines drift).

## Invariants (must hold after every phase)

- **I1** No new user-facing "hypothesis" wording (existing QA grep guard).
- **I2** Nothing emitted without observable backing — a new detector must attach
  an `absent_control_signal[]` or a `practice_evidence[]` site; never a bare
  "might be missing" (reuse the `build_weakness_register:1815` gate).
- **I4** Headline finding count is post-consolidation and must **not rise** from
  surfacing work — Gap B only *moves/echoes* existing weakness rows into the MS;
  it must not mint new `threats[]`/`findings_ranked[]` entries.
- **I5** Determinism preserved — all of Gap B and the Gap-A detectors are Python
  / catalog-driven, no LLM.
- **Golden:** regen the synthetic fixture + juice-shop example each phase; gate
  on `e2e-full-standard`.

---

## Gap B — surface the systemic posture verdict in the Management Summary

Rationale first: the natural MS emphasis surface is the **Security Principles
verdict table** (VIOLATED / WEAK / ADEQUATE per principle), *not* the attack-path
Top-Threats table. The Top-Threats table is keyed on attack-class glyphs (①–⑦,
`#path-<class>` anchors, compose:9085,9120) and joins the attack-paths fragment;
bolting weakness rows onto it fights its structure. The Principles table is
already the P4.3 "systemic posture" surface — hoist it, don't re-invent it.

### B.1 New MS subsection `systemic_posture`

- `data/sections-contract.yaml` (`management_summary.required_subsections`,
  :338): add `systemic_posture` **after `verdict`** and after the optional
  `architectural_anti_patterns` callout (so the reader sees the structural
  posture before the per-flow heatmap), i.e. between `architectural_anti_patterns`
  and `security_posture_at_a_glance`. Mark it optional-conditional
  (`condition: "has_weakness_register"`) so pre-P1 data / a clean repo with no
  register renders nothing → goldens for those cases unchanged.
- `_render_management_summary` (compose:9302): insert a `systemic_posture` branch
  in the explicit subsection loop that calls a new
  `_render_systemic_posture_ms(ctx)` — a thin wrapper that returns the existing
  `_render_security_principles(ctx)` output (the VIOLATED/WEAK/ADEQUATE table)
  **plus a one-line lead** naming the VIOLATED principles ("Access Control and
  Input Validation are systemically violated — see §8"). The table body is the
  already-built `_render_security_principles`; do not duplicate its logic.
- **De-duplicate §8:** `_render_security_principles` currently renders inside
  `_render_threat_register` (compose:15006). Decide **one** home:
  - *Recommended:* keep the full table in the MS (primary emphasis) and replace
    the §8 call with a **back-reference line** ("Systemic posture verdict: see
    Management Summary") so the verdict isn't shown twice. `_render_weakness_classes`
    (the per-class instance detail) **stays in §8** — it is the drill-down, not
    the summary.
- **Placement gate:** the new subsection must obey the MS
  `forbidden_subsection_patterns` (contract:355) — the block is a **bold lead +
  table**, not a `###` heading named like a forbidden pattern
  ("Top Critical Findings" etc.). `_render_security_principles` already emits a
  bold block, not a heading anchor (compose:14719) — keep that.

### B.2 Condition predicate

- Add `has_weakness_register` to whatever evaluates MS `optional_subsections`
  conditions (same mechanism as `has_anti_patterns` / `has_llm_surface`,
  contract:348,352) → true iff `ctx.yaml_data.get("weaknesses")` non-empty.
  Grep the condition evaluator (search `has_anti_patterns`) and add the twin.

### B.3 Verdict lead already carries the breakdown — keep, don't double

- `_render_verdict` already appends "Findings: N — X confirmed · Y implementation
  · Z design" (`_weakness_basis_breakdown` compose:2580) and folds each
  `design-risk` weakness once into the risk-distribution tally
  (`_risk_distribution_counts` compose:2621). Leave these — they are the count,
  the new table is the *named* posture. Verify no double-count (I4).

### B.4 Verify

- Re-render juice-shop fixture: MS shows the **Security Principles** table with
  "Authorization / Access Control = 🔴 VIOLATED" and "Input Validation = 🔴
  VIOLATED" above the heatmap; §8 shows the drill-down once (no duplicated
  verdict table). Headline count unchanged vs. pre-change (I4).
- `make test` + targeted compose/contract subset green; two contract tests that
  pin `management_summary.required_subsections` updated together (search
  `required_subsections` in `tests/`).
- Golden regen for fixture + example; `e2e-full-standard`.

---

## Gap A — evidence-less detectors for input/output validation + access control

Goal: make the design weakness for these domains **deterministic**, not
dependent on the LLM arch-coverage step emitting `weak_or_missing_controls`.
Mirror the crypto pattern: a catalog/heuristic that emits an
`absent_control_signal[]` (→ `kind:design`, `severity_basis:design-risk`) when a
**central control is observably absent** across the request surface.

### A.1 Central-control-absence emitter (new deterministic signal)

- The gate is backing (`build_weakness_register:1815`): a pure strategy verdict
  (`home-grown`/`none` from `detect_impl_strategy`) does **not** by itself create
  a weakness — it needs an absent-control signal or a practice site. So the new
  work is an **emitter**, not just a classifier.
- New deterministic check (extend `detect_impl_strategy.py` or a sibling that
  writes into the design-signals stream `_load_design_signals` consumes,
  merge_threats:1895): for each domain, emit `{weakness_class, statement,
  absent_control_signal[], affected_components[], implementation_strategy}` when:
  - **InputValidation (injection / output_xss_csp):** the repo exposes request
    handlers/routes (from `recon_patterns.py` route inventory) **AND** no vetted
    validation library is detected (`security-libraries.yaml` injection domain:
    zod/joi/express-validator/class-validator, :23) **AND** no central validation
    middleware pattern → `absent_control_signal: ["no central input-validation
    layer across N route handlers"]`, strategy `none`/`home-grown`.
  - **Output encoding (output_xss_csp):** raw-sink patterns present
    (`innerHTML`/`dangerouslySetInnerHTML`, security-libraries output_xss_csp
    domain :50) **AND** no auto-escaping template engine / no `dompurify`/`helmet`
    → `absent_control_signal: ["no central output-encoding / CSP"]`.
  - **Access control (missing_authz):** routes present **AND** no central authz
    middleware (`casl`/`accesscontrol`/policy layer, security-libraries
    missing_authz domain :57) → `absent_control_signal: ["no centralized
    authorization layer"]`.
- **I2 discipline:** each signal MUST name its observable basis (route count,
  sink file:line, "library X absent per manifest") — never a bare "probably
  missing". When unsure, drop (do NOT grant a weakness on ambiguous evidence).
- **Exculpation already handled:** if a vetted lib *is* detected,
  `detect_impl_strategy` returns `standard-vetted` and the reconciler's Fall-B
  (merge_threats:1833) suppresses the pure design gap — so a well-built repo
  stays quiet. No new suppression logic needed.

### A.2 Language coverage caveat (must not silently under-report)

- `detect_impl_strategy` source grep is **JS/TS-only today** (`_SRC_EXTS`
  detect_impl_strategy:45 — no `.py`/`.java`/`.go`). A polyglot repo would get a
  false "library absent" (→ spurious design weakness) OR miss non-JS controls.
  Two-part rule:
  - Gate the absence emitter on the **detected primary language(s)** from recon;
    only assert "no validation library" for a language the detector actually
    inventories. For un-inventoried languages, emit **nothing** (silent, not a
    false positive) and `log()` the coverage gap via `scripts/event_log.py` (no
    silent cap — AGENTS.md).
  - File a follow-up to extend the manifest/lib inventory beyond JS (out of
    scope here; note it in the risk register).

### A.3 Contract / permissions / tests

- If A.1 introduces a new scanner invocation or read target, update
  `data/required-permissions.yaml` + `tests/test_check_permissions.py`
  (AGENTS.md §7).
- Unit tests: (1) route-bearing fixture with no validation lib → exactly one
  `injection` **design** weakness, `design-risk`, `absent_control_signal`
  populated, 0 instances; (2) same fixture + zod added → weakness suppressed
  (Fall B); (3) `innerHTML` sink + no dompurify → `output_xss_csp` design
  weakness; (4) routes + no authz lib → `missing_authz` design weakness;
  (5) polyglot/un-inventoried language → **no** weakness + coverage-gap log line.

### A.4 Verify

- juice-shop re-run: InputValidation and Access Control surface as design
  weaknesses even where no *new* concrete instance exists, and (Gap B) show as
  🔴 VIOLATED in the MS Security Principles table.
- Confirm I4: finding headline count does not rise (design-risk weaknesses are
  counted in the "Z design" bucket, not as confirmed findings / CVSS rows — I3).

---

## Cross-cutting

- **Order of work:** ship **Gap B first** (pure deterministic surfacing, highest
  emphasis-per-effort, partially-existing renderer) so the systemic posture is
  loud in the MS immediately; then Gap A to make the underlying signals robust.
- **Back-reference labeling nuance (from analysis):** `_theme_to_primary_cluster`
  (arch_coverage_to_threats:57, first-wins) folds an *output-encoding* design gap
  under the `injection` cluster (label "Injection") because both `injection` and
  `output_xss_csp` map to `InputValidation`. Harmless for the principle table
  (theme-level) but the §8 weakness label may read "Injection" for an
  encoding gap. Optional: split the fold so an `output_xss_csp`-tagged signal
  keeps its own cluster. Not blocking.

## Risk register

- R1 (Gap B) Double-emphasis / double-count — verdict breakdown + new table +
  §8 must total consistently; keep the table in ONE primary home (MS), §8 gets a
  back-ref. Guard: I4 count test.
- R2 (Gap A) False-positive design weaknesses on polyglot repos — gate on
  detected language; emit nothing for un-inventoried languages; log the gap.
- R3 (Gap A) Over-emitting for micro-repos (a 2-route script flagged "no central
  validation layer") — reuse `SYSTEMIC_SPREAD_MIN` (weakness-classes.yaml
  per-class override) so a design weakness needs spread ≥ threshold before it
  reaches `design`/systemic severity; below threshold stays a low-severity note.
- R4 Golden churn — every phase regens fixture + example; separate pre-existing
  baseline failures per CONTRIBUTING before asserting green.

---

## Implementation record (2026-07-13, uncommitted on `dev`)

**Gap B — DONE (as designed).** The P4 Security-Principles verdict table now
renders as the `### Security Principles` subsection *inside* the Management
Summary (between the anti-patterns callout and the Security-Posture heatmap),
not §8. §8 keeps only a back-reference line. Changes:
- `compose_threat_model.py`: `_render_security_principles` reworked to emit the
  `### Security Principles` MS section (heading + a lead that *names the
  VIOLATED principles* + verdict table); new `systemic_posture` branch in
  `_render_management_summary`; §8 call replaced with a back-ref; new eval-context
  var `has_weakness_register`.
- `data/sections-contract.yaml`: `systemic_posture` added to MS
  `optional_subsections` (`condition: has_weakness_register`) + a
  `sections.systemic_posture` entry (`### Security Principles`, `computed`).
- Test: `test_e2e_pipeline.py::test_weakness_register_renders_and_is_qa_safe`
  strengthened to assert the table is *in the MS* and §8 has the back-ref.

**Gap A — DONE, scoped to the low-FP slice (home-grown/misused sink).** The pure
"no library at all" absence emitter (A.2) was deliberately NOT built — it is
genuinely FP-prone deterministically and the arch-coverage bridge already covers
pure absence. Instead: a `home-grown` / `standard-misused` **central control**
(a bespoke sink with no vetted lib) now surfaces a design-risk weakness *even
with zero confirmed instances*, backed by the sink's own file:line (I2 —
self-gating by language, since the evidence IS JS/TS source). Changes:
- `data/security-libraries.yaml`: `central_control{principle, statement}` on the
  four centralizable domains (injection, output_xss_csp, missing_authz,
  broken_auth). `weak_crypto`/`server_side_exposure` intentionally omitted
  (crypto is covered by `crypto-checks.yaml`; avoids double-surfacing).
- `detect_impl_strategy.py`: `_scan_bespoke` now also returns up to 5
  `{file,line}` sink sites; `build_strategy_map` carries `bespoke_evidence`; new
  `build_impl_design_signals` emits a design signal per home-grown/misused
  central control; `_main` writes `.impl-design-signals.json`.
- `merge_threats.py`: `_load_design_signals` merges `.impl-design-signals.json`
  with the arch-coverage stream (both fold into the same class buckets → one
  weakness per class; component spread = distinct sink dirs, so ≥2 dirs → systemic
  → VIOLATED).
- Skill contract (`SKILL-impl.md`) documents the new sidecar. No permission
  change (dotfile sidecar under `OUTPUT_DIR` already allowed).
- Tests: 7 new in `test_detect_impl_strategy.py` (evidence capture, emit gating,
  vetted→no-signal, no-central-control→skip, no-instance design weakness,
  pervasive→Critical, CLI sidecar). End-to-end verified: a home-grown SQL sink
  across 2 dirs with no confirmed instance → `injection` design weakness
  (Critical) → **Input Validation ⇒ VIOLATED** in the posture verdict → MS table.

**Tests:** targeted sweep 758 passed / 6 skipped. One failure —
`test_compose_matches_golden` — is a **pre-existing baseline failure** from a
separate uncommitted formatting workstream (the final render pass
backtick-wraps an HTML anchor id: `<a id=`"dependency-update-posture"`>`), NOT
from this change (fails identically with these edits stashed; the e2e golden
fixture has no `weaknesses[]`, so neither gap touches it). Flagged for that
workstream to fix — a golden regen here would bake in the broken anchor.

**Still open / deferred:** the pure-absence emitter + polyglot language
inventory (A.2 follow-up); the `output_xss_csp`→`injection` label fold nuance
(Cross-cutting note) — both non-blocking.
