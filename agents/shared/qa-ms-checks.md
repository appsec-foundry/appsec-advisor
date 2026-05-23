# QA Management Summary format checks

Used by `appsec-qa-reviewer` Check 7b. Validates the five required Management Summary sub-sections (`### Verdict`, `### Top Findings`, `### Architecture Assessment`, `### Mitigations`, `### Operational Strengths`) plus prose-purity rules and report-wide CWE / inline-code formatting. The detailed Operational Strengths cluster validation lives in Check 3i; this file only covers the MS-local format contract.

## 1. Presence

**Management Summary presence check (critical):** Find `## Management Summary`. If the heading is entirely absent, **this is a critical defect** — the Management Summary is mandatory at all assessment depths. Generate a complete Management Summary by reading the Threat Register (Section 8) and Mitigation Register (Section 9) from the document, then insert it between the Table of Contents (or Changelog if present) and Section 1. The generated summary must include all five required sub-sections (Verdict with integrated worst-case-scenarios blockquote, Top Findings, Architecture Assessment, Mitigations with Prioritized and Follow-up sub-tables, Operational Strengths). Follow the template in `phase-group-threats.md` → "Build Management Summary". Use F-NNN IDs in the Top Findings table. Print: `[qa-reviewer]   ↳ Management Summary: <present|GENERATED — was missing>`

## 2. Verdict

**Management Summary verdict check:** The first sub-section MUST be `### Verdict`. The verdict MUST follow this structure: (1) opening sentence beginning with 🟢/🟡/🔴 severity cue + one-sentence verdict (Critical/High counts are permitted in the opening sentence), (2) a **red HTML `<blockquote>` with bullet points** — each bullet names one critical attack path in bold followed by a plain-language explanation and a parenthesised italic F-NNN citation (e.g. `*([F-009](#f-009))*`), (3) 1–2 closing sentences with overall assessment. The blockquote style MUST include `border-left: 3px solid #dc2626; background: #fef2f2`. If the verdict uses plain bullets without the blockquote (legacy format), **auto-repair** by wrapping the bullet block inside the canonical blockquote tags. If the verdict is not under a `### Verdict` heading, wrap it in one. Print: `[qa-reviewer]   ↳ Management Summary verdict: <ok|blockquote-wrapped|heading-added|missing|no-severity-cue|no-bullets>`

## 3. Required sub-sections (exactly FIVE, order enforced)

The following headings MUST be present inside `## Management Summary`, in this order:

1. `### Verdict`
2. `### Top Findings` (legacy name `### Top Threats` is **auto-renamed** to `### Top Findings`)
3. `### Architecture Assessment`
4. `### Mitigations` (with `#### Prioritized Mitigations` and `#### Follow-up Mitigations` sub-tables). The legacy name `### Follow-up Actions` is auto-rewritten to `### Mitigations`.
5. `### Operational Strengths`

**Numbered sub-section check:** Scan all headings inside `## Management Summary` for numeric prefixes — patterns like `### 1.1 Verdict`, `### 1.2 Top Findings`, `### 2. Architecture Assessment`. **Auto-strip** any leading `<digit>.<digit> ` or `<digit>. ` prefix from these headings. Log: `[qa-reviewer]   ↳ Management Summary numbered headings: <n> stripped`.

When `CHECK_REQUIREMENTS=true`, `### Requirements Compliance` is also mandatory (placed between Mitigations and Operational Strengths). Print: `[qa-reviewer]   ↳ Management Summary sub-sections: <n>/5 present (+requirements: <ok|missing|n/a>)`

## 4. Forbidden sub-sections

The following headings are banned:

- `### Risk Distribution` / `### STRIDE Coverage` → **auto-strip** (lives in Threat Register only).
- `### ⚠ Worst Case Scenarios` / `### Worst Case Scenarios` / `### Worst Case Scenario` (any variant) → **auto-strip** and migrate bullet content into the Verdict's red HTML blockquote. The reference format integrates worst-case scenarios as the bullets inside the Verdict blockquote — a standalone sub-section is a legacy layout. See the migration rule in §5 below.
- `### Top Threats` / `### Top Critical Findings` / `### Critical Findings` → **auto-rename** to `### Top Findings` (and update table columns to new 7-column format: # | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations).
- `### Recommended Priority Actions` / `### Immediate Actions` → flag: merged into `### Mitigations` (Prioritized Mitigations sub-table).
- `### Key Strengths` → **auto-rewrite** to `### Operational Strengths`.
- `### Overall Security Rating` → flag: the Verdict heading carries the rating.
- `#### Structural Defects` → flag: merged into Architecture Assessment table.

Print: `[qa-reviewer]   ↳ Management Summary forbidden sub-sections: <n> flagged, <n> auto-stripped, <n> auto-renamed`

## 5. Verdict blockquote (replaces legacy separate Worst Case Scenarios check)

The `### Verdict` section MUST contain an embedded red HTML `<blockquote>` with the worst-case-scenario bullets. The blockquote style MUST include `border-left: 3px solid #dc2626; background: #fef2f2`. Checks:

1. **Blockquote presence inside Verdict (auto-repair):** If `### Verdict` is present but contains plain bullets outside any blockquote, **auto-repair** by wrapping the bullet block in the canonical tags:
   ```
   <br/>

   <blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

   <existing bullet lines>

   </blockquote>

   <br/>
   ```
   The blockquote MUST sit between the opening sentence and the closing prose sentences — do not replace either.

2. **Standalone Worst Case Scenarios heading migration (auto-strip + merge):** If a standalone `### ⚠ Worst Case Scenarios` / `### Worst Case Scenarios` / `### Worst Case Scenario` heading exists anywhere inside `## Management Summary`:
   - Extract the heading's bullet content (bold scenario names + F-NNN/T-NNN references).
   - Convert scenario paragraphs into single-line bullets (`- **<Name>** — <sentence>. *([F-NNN](#f-NNN))*`) if necessary.
   - **Auto-strip** the standalone heading and its surrounding `<blockquote>` wrapper.
   - **Auto-merge** the extracted bullets into the Verdict blockquote. When the Verdict already has its own bullets, append the migrated ones; deduplicate by scenario name.
   - Drop any "See [Critical Attack Chain]" trailing link from the migrated content — that link is not part of the new Verdict format.

3. **Content checks (inside Verdict blockquote):**
   - Contains between 2 and 5 bold bullet names (lines matching `- **<Name>** — …`).
   - Scenario names are business outcomes, not technical descriptions.
   - Each bullet references at least one `[F-NNN](#f-NNN)` (preferred) or `[T-NNN](#t-NNN)` link; the reference MUST be wrapped in italics and parentheses (e.g. `*([F-009](#f-009))*`).
   - No `[M-` references (mitigations live in Top Findings and Mitigations section).

4. **Markdown blockquote fallback:** If a Markdown blockquote (`> `) is used instead of HTML, **auto-convert** it to the HTML form with red styling.

Print: `[qa-reviewer]   ↳ Management Summary Verdict blockquote: <n> bullets, blockquote=<html-ok|wrapped|missing>, legacy-WCS-migrated=<yes|no>`

## 6. Top Findings table

`### Top Findings` (the pre-pass renames legacy `### Top Threats` / `### Top Risks` deterministically) MUST contain a table (not a bullet list). The table MUST have 7 columns: `#` (rank), `Criticality` (emoji 🔴/🟠), `Finding` (F-NNN link + short title), `Component` (C-NN link + name), `Threat` (TH-NN link + category name), `Vektor` (linked to Appendix A anchor), `Primary Mitigations` (M-NNN links). Verify:

- Every row has a `#` rank number in the first column.
- Every `Criticality` cell has 🔴 (Critical) or 🟠 (High) emoji.
- Every `Finding` cell contains a clickable `[F-NNN](#f-NNN)` link followed by a short title (em-dash separator). Legacy `[T-NNN]` IDs in this column are flagged — the primary ID in the Top Findings table is F-NNN.
- Every `Component` cell contains `[C-NN](#c-NN) — <name>`.
- Every `Vektor` cell is a clickable link to Appendix A (e.g. `[Internet Anon](#vektor-internet-anon)`). Bare text Vektor values without links are auto-repaired.
- Every `Primary Mitigations` cell contains at least one `[M-NNN](#m-NNN) — <short action>` link.
- All 🔴 rows appear before 🟠 rows.
- A legend line follows the table: `> 🔴 = Critical · 🟠 = High. **Vektor** values link to full definitions in [Appendix A — Vektor Taxonomy](#appendix-a-vektor-taxonomy).`
- Legacy column formats (old 6-column: Severity | ID | Description | Impact | Mitigation | Effort) are flagged for rewrite; the check logs the column mismatch but does NOT auto-rewrite (too destructive — leave for manual re-run).
- If the old bullet-list format is detected (lines starting with `- **[T-`), flag for table rewrite.

Print: `[qa-reviewer]   ↳ Management Summary Top Findings: table with <n> rows, <n> format issues, vektor-links=<n>/<n>`

## 7. Architecture Assessment table

`### Architecture Assessment` MUST contain a table with **exactly three columns**: `Defect`, `Description`, `Key Findings`. Verify:

- The column header row matches `| Defect | Description | Key Findings |` (case-insensitive on header names).
- The Defect cell is a bold short phrase (e.g. `**Secrets in source code**`).
- The Key Findings column contains clickable `[F-NNN](#f-NNN)` (preferred) or `[T-NNN](#t-NNN)` links, each followed by a short label: `[F-NNN](#f-NNN) — <short label>` (e.g. `[F-009](#f-009) — SQL injection in product search`). Bare F-NNN/T-NNN links without a label are a format defect — add the label from the Threat Register. Multiple findings in the same cell are `<br/>`-separated.
- The section closes with a line referencing `[§7 Security Architecture](#7-security-architecture)`.
- An opening 🔴/🟡/🟢 severity-cue sentence precedes the table; a short framing sentence (e.g. "Four cross-cutting defects drive …") sits between the verdict sentence and the table.

Legacy 5-column form (`Severity | Layer | Defect | Consequence | Enables`) is deprecated but accepted — the check logs the column mismatch. Do NOT auto-rewrite 5-col → 3-col (too destructive; leave for manual re-run). Bullet-list form (`#### Structural Defects` + bullets) is flagged for rewrite.

Print: `[qa-reviewer]   ↳ Management Summary Architecture Assessment: schema=<3-col-ok|legacy-5-col|bullets>, <n> rows, <n> format issues`

## 8. Mitigations sub-tables

`### Mitigations` MUST contain two sub-tables under `####` headings. If the legacy heading `### Follow-up Actions` is found instead, **auto-rewrite** it to `### Mitigations` and wrap the existing table as `#### Follow-up Mitigations`, then generate a `#### Prioritized Mitigations` table from the Critical findings in Top Findings.

Both sub-tables MUST use the same five columns: **`ID`, `Mitigation`, `Component`, `Addresses`, `Effort`**. Column mismatch (e.g. Follow-up using `Why` instead of `Addresses`, or retaining the legacy 4-column `Priority | Mitigation | Addresses | Effort` schema) is flagged — the check logs the column mismatch but does NOT auto-rewrite 4-col → 5-col (too destructive).

Verify `#### Prioritized Mitigations`:

- ID column contains clickable `[M-NNN](#m-NNN)` links.
- Mitigation column contains the mitigation title (plain text or bold, no M-ID prefix — the ID is in the ID column).
- Component column contains `[C-NN](#c-NN) <Component name>` links. When a mitigation spans multiple components, stack them with `<br/>` inside the cell.
- Addresses column contains clickable `[F-NNN](#f-NNN)` links, each followed by a short label: `[F-NNN](#f-NNN) — <short description>` (e.g. `[F-009](#f-009) — SQL injection in product search`). Bare F-NNN links without a label are a format defect — add the label from the Threat Register. Multiple findings are `<br/>`-separated. Legacy `[T-NNN]` IDs in this column are accepted during the transition period but flagged for upgrade to F-NNN.
- Effort column contains one of Low/Medium/High.
- Rows are sorted by effort ascending (Low first), then by count of Addresses findings descending (highest-leverage first).
- Every Critical finding from the Top Findings table has at least one corresponding row in the Prioritized table.

Verify `#### Follow-up Mitigations`:

- Same five columns as Prioritized (ID, Mitigation, Component, Addresses, Effort).
- Same content rules apply to the Component and Addresses cells.
- Same sort order (effort asc, then findings-addressed desc).
- No M-IDs already covered in the Prioritized Mitigations table appear here.

Print: `[qa-reviewer]   ↳ Management Summary Mitigations: schema=<5-col-ok|legacy-4-col>, prioritized=<n> rows, follow-up=<n> rows, legacy-rewrite=<yes|no>`

## 9. Operational Strengths (format only)

`### Operational Strengths` MUST contain the **3-column cluster table** defined in `agents/shared/ms-template.md` (columns: `Strength`, `What's in Place`, `Effectiveness`). The detailed cluster validation (cluster-name lookup, evidence presence, effectiveness drift) is owned by Check 3i — this format check only verifies the column header. A 2-column or 4-column table is a **hard fail**. The legacy 5-column form (`Architectural Control | Implementation | Effectiveness | Gap | Mitigates`) is detected and auto-rewritten by Check 3i — see there. The table MUST end with a `**Bottom line:**` sentence. When more than 8 rows qualify, a truncation footnote `_+N additional controls — see [Section 7](#7-security-architecture)._` sits between the last table row and the `**Bottom line:**` line. When verdict is 🟡 or 🔴, an introductory framing sentence is required before the table.

Print: `[qa-reviewer]   ↳ Management Summary Operational Strengths: schema=<3-col-ok|legacy-5-col|other-FAIL>, <n> rows, truncation-footnote=<present|n/a>, bottom-line=<present|missing>`

## 10. Prose purity

The Verdict opening/closing prose sentences (those outside the red HTML blockquote) and the Architecture Assessment intro prose must contain **no** `[T-` references, `[M-` references, `vscode://` links, or file paths. F-NNN / T-NNN / M-NNN links are allowed in: Verdict blockquote bullets, Top Findings table, Architecture Assessment table (Key Findings / Enables column), Mitigations tables (Prioritized + Follow-up), Requirements Compliance.

Print: `[qa-reviewer]   ↳ Management Summary prose purity: <n> references flagged`
