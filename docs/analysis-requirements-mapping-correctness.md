# Requirements Ingestion & Mapping — Correctness Verification

Scope: verify correctness of custom-requirements ingestion (own requirements via
URL) and the mapping of those requirements to findings / measures (Maßnahmen),
especially for blueprints; assess management-summary integration; specify a
dedicated mapping table.

All claims below are verified at file:line against the working tree.

---

## 1. What is correct today

**URL ingestion — OK.** `harvest_requirements.py` crawls URL sources of
`type: requirement` and `type: blueprint` and writes `requirements.yaml`:

- `categories[].requirements[]` → `{id, text, priority, url}` (parsed `1c`, SKILL.md:190–199)
- `blueprints[].sections[]` → `{title, url, content, references[]}`

**Runtime fetch — OK.** SKILL Step 1b (SKILL.md:113–186):
- `--requirements <url>` → direct fetch, **no** cache fallback (hard fail on miss)
- configured `requirements_yaml_url` → fetch → cache → fallback to `.cache/requirements.yaml`
- config validated by `validate_config.py:_validate_requirements_config` (:133–167): URL must be http(s) with host.

**Blueprint→requirement back-reference — OK and deterministic.**
`add_references_to_blueprints` (harvest_requirements.py:901) reverse-scans each
blueprint section's `content` for requirement-ID tokens via `resolve_references`
+ `REF_ID_PATTERN` (:883) and attaches `references: [{id, url}]`. Called from
`run()` (~:1050) only when both `req_categories` **and** `blueprints` are present.
→ The harvest layer produces a deterministic blueprint↔requirement link set.

---

## 2. Correctness gaps (confirmed)

### G1 — The structured linkage exists in threat-model.yaml but compose ignored it
Correcting an earlier draft of this doc: the requirement linkage **is** present
as structured data. Phase 8b turns each FAILed requirement into a threat carrying
`requirement_id`/`violated_requirements` (schema:595) and `mitigation_ids`
(schema:590); mitigations carry `fulfills_requirements` (schema:788). These are
QA-enforced (`Violated:` annotation in §8, `Fulfills Requirements:` line in §9).

The gap is **presentation**, not data: that linkage is scattered across §8
(per-threat `Violated:` notes) and §9 (per-mitigation `Fulfills` lines) with **no
consolidated traceability view**, and `compose_threat_model.py` never read the
requirement fields for any combined table — the §7b/MS subsection
(`_render_requirements_compliance_ms`, :6345) consumed **only** the freehand
markdown fragment. (The separate `audit-security-requirements` skill builds its
own standalone report from the same `violated_requirements`, SKILL.md:225–240.)

### G2 — Management Summary silently drops the mapping (regex bug)
`_render_requirements_compliance_ms` parses the §7b "Architectural Violations"
table with (compose:6396–6399):
```
\|\s*(\[.+?\]\(.+?\)(?:\s*—\s*.+?)?)\s*\|\s*(MUST|SHOULD|MAY)\s*\|(.+?)\|
```
The table is `| Requirement | Priority | Evidence | Risk | Linked |`.
The regex captures group(3) = **Evidence only**; the **Risk** and **Linked
(F-NNN)** columns are discarded (:6401–6404, 6418–6419). → Even the freehand
finding links never reach the Management Summary; MS bullets are link-less.

### G3 — No mapping-integrity validation
`requirements-compliance.md` is registered as a **markdown** fragment
(compose:144; contract `fragment_type: markdown`), so `validate_fragment.py`
only checks heading-prefix, never schema. `validate_fragment.py` has **zero**
requirements-specific logic (grep `requirement` → no match). Nothing verifies
that F-NNN / blueprint IDs in the "Linked" column actually exist. → dangling /
hallucinated links pass undetected.

### G4 — Requirement→measure (Maßnahme / M-NNN) link exists but is not consolidated
Correcting an earlier draft: the link **does** exist — a requirement-sourced
threat carries `mitigation_ids`, and mitigations carry `fulfills_requirements`
(schema:590/788), rendered as the per-mitigation `Fulfills Requirements:` line in
§9. What was missing is a single requirement → Finding **+ Maßnahme** column view;
the §7b compliance table (phase-group-architecture.md:1900–1907) has a `Linked
Threats` column but **no mitigation column**.

### G5 — Blueprint linkage in the report (B) is freehand
Harvest produces `blueprint.references[]` deterministically (§1), and skill (A)
consumes it — but the threat-model report (B) does not. Blueprint citations in
§7b/MS are LLM prose, not anchored to the harvested reference set.

### G6 — No tests / no golden example
No test covers requirements-compliance rendering (only
`test_requirements_resolution.py`, which tests source resolution).
`threatdemo.md` has `check_requirements` off → section absent → no example.

---

## 3. Resolution (implemented)

Decisions: **deterministic mapping + validation**; columns
**Requirement · Risk · Finding · Maßnahme · Blueprint**; placement
**MS compact + §7b full**.

Full verification (§2, G1/G4 corrected) showed the structured linkage already
lives in `threat-model.yaml` (`violated_requirements`, `mitigation_ids`,
`fulfills_requirements`). So the original `.md → .json` fragment cutover below
was **unnecessary** — the deterministic table is built directly from the yaml
the renderer already holds. No new schema, no Phase-8b authoring change, no
fragment-format migration. Implemented:

- **`_build_requirements_mapping_rows(ctx)`** (`compose_threat_model.py`) — groups
  requirement-linked threats by requirement ID → findings (F-NNN), mitigations
  (M-NNN), blueprint, max severity. Reads only `threat-model.yaml`; honours the
  legacy singular `requirement_id`; excludes non-requirement threats.
- **`_render_requirements_mapping_table(...)`** — 5-column table
  (Requirement · Risk · Findings · Maßnahmen · Blueprint); F/M cells link to
  §8/§9; `limit` caps the MS variant with an overflow pointer to §7b.
- **`_render_requirements_compliance` (§7b, hybrid)** — keeps the LLM narrative
  fragment (status/priority/evidence the yaml lacks) and appends a deterministic
  `### Requirements Traceability` table. Wired via the `_render_by_id` dispatcher.
- **`_render_requirements_compliance_ms` (MS)** — G2 fixed: the buggy regex that
  dropped the Linked/Risk columns is gone; the compact table now carries the
  actual F/M links. Baseline + PASS/FAIL summary still read from the fragment
  (the only data the yaml does not carry), preserving the QA count-consistency
  rule between MS and §7b.

Validation is **inherent**: every F-NNN/M-NNN in the table comes from
`threat-model.yaml` itself, so dangling links are structurally impossible — no
separate gate needed.

Tests: `tests/test_requirements_mapping.py` (5 unit tests on the row builder +
table) plus an end-to-end render check (9 assertions) confirming the §7b table,
the MS compact table, dispatcher wiring, and the `check_requirements` conditional.
Full suite: 446 passed, 2 skipped.

Not done (out of scope / unnecessary): the `.md → .json` fragment migration; a
requirement URL in the traceability table (yaml has none — the §7b full table
already links requirement IDs to their source); blueprint enrichment beyond the
threat's `remediation.blueprint` value.

---

### Superseded first-draft plan (kept for reference)

> The structured-fragment redesign below was the initial proposal before §2 was
> fully verified; it is **not** what was implemented.

1. **New structured fragment + schema**
   `schemas/fragments/requirements-compliance.schema.json` — per requirement:
   `{id, priority, status, category, evidence, findings:[F-NNN],
   mitigations:[M-NNN], blueprint:{id,section,url}|null, baseline:{name,url}}`.
   → verify: schema file validates; round-trips a hand example.

2. **Deterministic renderer** in `compose_threat_model.py`
   - `§7b`: full mapping table, all requirements, 5 columns; finding/mitigation
     cells link to `#f-nnn` / `#m-nnn`; blueprint cell links the harvested
     section URL.
   - MS: compact table (FAIL/ANTI-PATTERN rows only) **with** Finding/Maßnahme
     links — replaces the current link-less bullets, removing the G2 regex path.
   → verify: golden render shows links in both places.

3. **Validation gate** — extend `validate_fragment.py` (+ wire into
   `pre-render-gate` and `qa_checks.py`): every `F-NNN`/`M-NNN` must exist in
   `threat-model.yaml`; every `blueprint.{id,section}` must exist in
   `requirements.yaml`. Dangling ref → hard fail.
   → verify: a fragment with a fake F-999 fails the gate.

4. **Authoring phase** — switch the requirements phase to emit the JSON fragment;
   seed findings/mitigations from `violated_requirements[]` + harvested
   `references[]` deterministically, LLM only fills status/evidence/effort.
   → verify: dry-run against a live run dir (per `feedback_dry_run_before_cutover`).

5. **Contract + tests + demo** — update `sections-contract.yaml`
   (`requirements_compliance*` → data fragment); add render + validation tests;
   add a `check_requirements` example to the demo fixture.
   → verify: `run-tests.sh` green; demo shows populated mapping table.

Files touched: `schemas/fragments/requirements-compliance.schema.json` (new),
`compose_threat_model.py`, `validate_fragment.py`, `qa_checks.py`,
`sections-contract.yaml`, requirements authoring phase doc, `tests/*`.
