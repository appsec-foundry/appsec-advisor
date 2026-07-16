# QA Management Summary format — residual semantic rules

Referenced by `appsec-qa-reviewer` Check 7b. The deterministic helper `qa_checks.py check_ms_structure` is the authoritative validator for MS layout (numeric-prefix stripping, legacy renames, forbidden-heading detection, sub-section presence + order). This file documents only the residual semantic rules the helper cannot decide.

## 1. Presence (critical defect)

If `## Management Summary` is **entirely missing**, `check_ms_structure` will surface it as an issue. The QA reviewer must **generate** a complete MS from §8 Threat Register and §9 Mitigation Register following the template in `phase-group-threats.md` → "Build Management Summary". Use F-NNN IDs in Top Findings. Include all five sub-sections with the templates below.

## 2. Five required sub-sections (helper-enforced)

1. `### Verdict` — severity cue 🟢/🟡/🔴 + one-sentence verdict, then a **red HTML `<blockquote>`** styled `border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;` containing 2–5 bold-name worst-case-scenario bullets (`- **<Name>** — <sentence>. *([F-NNN](#f-NNN))*`), then 1–2 closing sentences.
2. `### Top Findings` — 7-col table: `# | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations`. 🔴 rows before 🟠. Legend line follows: `> 🔴 = Critical · 🟠 = High. **Vektor** values link to full definitions in [Appendix A — Vektor Taxonomy](#appendix-a-vektor-taxonomy).`
3. `### Architecture Assessment` — 3-col table: `Defect | Description | Key Findings`. Bold short defect phrase. `Key Findings` cells carry `[F-NNN](#f-NNN) — <short label>` (multiple `<br/>`-separated). Closes with reference to `[§6 Security Architecture](#6-security-architecture)`. Preceded by 🔴/🟡/🟢 severity cue sentence + short framing.
4. `### Mitigations` — two sub-tables under `#### Prioritized Mitigations` and `#### Follow-up Mitigations`. Both 5-col: `ID | Mitigation | Component | Addresses | Effort`. Sorted by effort asc, then findings-addressed desc. Every Critical finding from Top Findings appears at least once in Prioritized.
5. `### Operational Strengths` — 3-col cluster table (`Strength | What's in Place | Effectiveness`). Closes with `**Bottom line:**` sentence. Truncation footnote `_+N additional controls — see [Section 7](#6-security-architecture)._` when > 8 rows qualify. Verdict 🟡/🔴 requires an intro framing sentence before the table. Detailed cluster validation belongs to `qa_checks.py check_strengths_row_quality` — this file only checks the column header.

When `CHECK_REQUIREMENTS=true`, `### Requirements Compliance` sits between Mitigations and Operational Strengths.

## 3. Forbidden sub-sections (helper-enforced)

`check_ms_structure` auto-rewrites or strips: `### Risk Distribution`, `### STRIDE Coverage`, `### ⚠ Worst Case Scenarios` (any variant — bullets migrate into the Verdict blockquote), `### Top Threats` / `### Top Critical Findings` / `### Critical Findings` (→ `### Top Findings`), `### Key Strengths` (→ `### Operational Strengths`), `### Follow-up Actions` (→ `### Mitigations`), `### Recommended Priority Actions` / `### Immediate Actions` (→ `### Mitigations`), `### Overall Security Rating` (the Verdict carries it). Legacy `## Critical Attack Chain` is renamed to `## Critical Attack Tree`.

## 4. Worst Case Scenarios migration (semantic)

If a standalone `### ⚠ Worst Case Scenarios` heading still exists after the helper's strip pass, merge its bullets into the Verdict blockquote:
- Extract bold scenario names + F-NNN/T-NNN references.
- Convert to single-line bullets (`- **<Name>** — <sentence>. *([F-NNN](#f-NNN))*`) if needed.
- Append to Verdict blockquote bullets; deduplicate by scenario name.
- Drop any trailing "See [Critical Attack Chain]" / "See [Critical Attack Tree]" link.

If a Markdown blockquote (`> `) wraps the Verdict bullets instead of the canonical HTML form, auto-convert to the HTML blockquote with the red style above.

## 5. Prose purity (semantic)

The Verdict opening/closing prose sentences (outside the red blockquote) and the Architecture Assessment intro prose must contain **no** `[T-` / `[M-` / `vscode://` / file path references. F-NNN/T-NNN/M-NNN links are allowed in: Verdict blockquote bullets, Top Findings, Architecture Assessment table cells, Mitigations sub-tables, Requirements Compliance. Annotate violations with `<!-- QA: MS prose carries a code/finding reference — keep prose purity, move to a table cell or blockquote -->`.

## 6. Legacy column schemas (warn-only)

When `check_ms_structure` flags a legacy column schema (Top Findings 6-col, Architecture Assessment 5-col, Mitigations 4-col, Operational Strengths 5-col), the reviewer does NOT auto-rewrite — the rewrite is too destructive (sub-cell semantics differ across schemas). Surface via repair plan so the renderer regenerates the table from canonical source.
