# Saved reports

Loaded by SKILL.md Step 4 only when `save_md`, `save_pdf` or `save_json` is set. Run the sections whose flag is set, in this order.

## Contents

- 4a — Markdown report (`save_md`): template and Markdown rules
- 4b — JSON report (`save_json`): copy of the Step 2.5 verdict
- 4c — PDF report (`save_pdf`): conversion from the 4a Markdown

### 4a — If `save_md` is true

Write the full report to `docs/security/appsec-requirements-report.md` (create `docs/security/` if needed).

The Markdown report is more detailed than the console, but still includes
only open requirements (`FAIL` and `PARTIAL`). Do not include `PASS` or
`UNVERIFIABLE` requirement entries. Prefix with a metadata table:

````markdown
# AppSec Requirements — <Project Name>

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 timestamp> |
| Repository | <git remote URL or directory name> |
| Source | <remote \| cached> |
| Open Requirements | <n> |
| 🔴 Failed | <n> |
| 🟡 Partial | <n> |
| 🟢 Passed | <n> |
| ⚪ Unverifiable | <n> |

## Open Requirements

> 🔴 fail · 🟡 partial — open gaps detailed below. 🟢 passed and ⚪ unverifiable are counted in the summary only.

| Status | Priority | ID | Requirement | Effort |
|--------|----------|----|-------------|--------|
| 🔴 FAIL | MUST | SEC-SQL | Parameterized SQL Queries | M |
| 🟡 PARTIAL | SHOULD | SEC-CSP-1 | Content Security Policy | S |

### 🔴 FAIL · MUST · SEC-SQL — Parameterized SQL Queries

> **Requirement:** Use parameterized SQL/HQL queries or ORM methods for database queries to prevent SQL injection.

Raw request input reaches `sequelize.query()` at `routes/search.ts:23`, so the query predicate can be changed by user-controlled input.

**Evidence:** `routes/search.ts:23`

**Risk:** An attacker can submit a crafted search term that changes the SQL predicate.

**Fix:** Replace string interpolation with bound parameters in `routes/search.ts`.

```ts
// Before
sequelize.query(`select * from product where name like '%${term}%'`)

// After
sequelize.query("select * from product where name like :term", {
  replacements: { term: `%${term}%` },
})
```

**Effort:** M

**Links:**
- Requirement: <full requirement url>
- Blueprint: <full blueprint section url, if available>
- Threat model: [F-014](docs/security/threat-model.md#f-014)

---

*Effort: S = under 1 hour · M = about half a day · L = multi-day or architectural change.*

````

Markdown rules:

- If the resolution banner reported `demo: true`, insert a blockquote warning
  directly under the `#` title: `> ⚠ **DEMO catalog** — audited against the
  packaged example requirements, not your organization's. Configure a real
  source with --requirements / an org profile.` Also set the metadata
  `| Source |` cell to `packaged example (DEMO)`.
- Prefix every status — in the summary metadata table, the overview table, and
  each `###` heading — with its criticality circle, reusing the threat model's
  house palette: 🔴 FAIL · 🟡 PARTIAL · 🟢 PASS · ⚪ UNVERIFIABLE. Keep the
  one-line palette legend (the `>` blockquote) directly under the
  `## Open Requirements` heading.
- Lead the `## Open Requirements` section with an overview table
  (`Status | Priority | ID | Requirement | Effort`) listing every open
  requirement in the sort order below. The detailed `###` blocks follow
  beneath it, so a reviewer can scan the whole gap list before reading details.
- Directly under each `###` heading, quote the requirement's **verbatim `text`**
  from the catalog as `> **Requirement:** <text>` (full text, not the derived
  title, not a paraphrase) — this is the demand being audited. Omit only when
  the catalog entry has no `text`.
- Close the report with the one-line effort legend shown above
  (`*Effort: S = … · M = … · L = …*`), preceded by a `---` rule.
- Sort open requirements with the same order as console output.
- Use one `###` heading per open requirement: `### <STATUS> · <PRIORITY> · <ID> — <Title>`.
- Include full URLs for requirement and blueprint links.
- If `req_to_threats[req_id]` is non-empty (from Step 1.5), add one Threat model bullet per linked `F-NNN`, linking to `docs/security/threat-model.md#f-nnn`. Canonical link shape: `[F-NNN · Risk](docs/security/threat-model.md#f-nnn)`.
- Include a short before/after code block only when there is meaningful code evidence. Omit code blocks for missing process controls or absent configuration.
- Do not add a Passed section.
- Do not add an Unverifiable section.

Print: `✓ Markdown report written to docs/security/appsec-requirements-report.md`

### 4b — If `save_json` is true

The canonical structured verdict was **already written** in Step 2.5
(`.requirements-audit.json`, schema `requirements-audit.schema.json`, summary
recomputed). `--json` simply exposes it as a visible deliverable — do not author
a second, differently-shaped JSON:

```bash
cp "$AUDIT_OUTPUT_DIR/.requirements-audit.json" \
   "$AUDIT_OUTPUT_DIR/appsec-requirements-report.json"
```

Print: `✓ JSON report written to docs/security/appsec-requirements-report.json`

### 4c — If `save_pdf` is true

The PDF is converted from the Markdown report, so this runs **after** Step 4a
(which always runs when `save_pdf` is set, because `--pdf` implies `save_md`).
Convert it with the shared, deterministic exporter — the requirements report has
no Mermaid diagrams, so pass `--no-mermaid` (skips mmdc/Chrome; needs only
pandoc + weasyprint):

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/exporters/export_pdf.py" \
  --input "$AUDIT_OUTPUT_DIR/appsec-requirements-report.md" \
  --output "$AUDIT_OUTPUT_DIR/appsec-requirements-report.pdf" \
  --no-mermaid
PDF_EXIT=$?
```

Handle the result by exit code (the exporter is self-describing on stderr):
- `0` — print `✓ PDF report written to docs/security/appsec-requirements-report.pdf`.
- `1` — a hard dependency (pandoc or weasyprint) is missing. This is **non-fatal**: the Markdown report was still written. Print:
  `⚠ PDF skipped — install pandoc + weasyprint (the Markdown report was saved).`
- `2` / `3` — input/conversion error. Print `⚠ PDF conversion failed (see message above); the Markdown report was saved.`

Never abort the audit because the PDF step failed — the console findings and the
Markdown report are the primary deliverables.
