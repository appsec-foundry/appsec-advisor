# QA Cross-reference style rules (Check 3f)

Used by `appsec-qa-reviewer` Check 3f. Ordinary table and list references to `T-NNN`, `M-NNN`, `F-NNN`, `TH-NN`, or `C-NN` use `[X-NNN](#x-nnn) — <short title>`. The composer deliberately uses shorter forms in narrow tables, headings, and inline citations; those cases are listed below. When a labelled reference list appears outside a table, two or more entries render as Markdown bullets.

The check is deterministic and auto-repairs violations in-place. It runs exactly once per QA pass.

## 1. Title lookup

Build the title lookup from the Threat Register rows, Mitigation Register headings, Finding anchors, Component anchors, and Threat Category anchors:

- For each row `| <a id="t-NNN"></a>T-NNN | <component> | <stride> | <scenario> | …`, derive `title_t[T-NNN]` as the first ≤60 characters of the scenario up to the first `:`, `.`, or `(`. Strip leading markdown backticks. Fall back to the first non-empty word-group when no delimiter is found.
- For each heading `#### <a id="m-NNN"></a>M-NNN — <title>`, derive `title_m[M-NNN]` as the text after ` — ` up to end-of-line, stripped.
- For each finding anchor `### <a id="f-NNN"></a>F-NNN — <title>`, derive `title_f[F-NNN]` from the text after ` — `. Fall back to `threat-model.yaml → findings[].title` when the anchor heading uses the bare ID form.
- For each component anchor `### <a id="c-NN"></a>C-NN — <name>` (Section 2.3 Components), derive `title_c[C-NN]` from the text after ` — `. Fall back to `threat-model.yaml → components[].name` when the heading is bare.
- For each category anchor `#### <a id="th-NN"></a>TH-NN — <Category>`, derive `title_th[TH-NN]` from the text after ` — `.

## 2. Reference-site classification

| Location | Shape required | Violation |
|----------|----------------|-----------|
| Table ID column (first cell, matches `\| <a id="t-NNN"></a>T-NNN`) | **Bare ID** — no link, no title | — |
| Table reference cell (any column named `Mitigations`, `Addresses`, `Linked Threats`, `Enables`, `Controls`) with ≥2 refs | `[X-NNN](#x-nnn) — <title><br/>[X-NNN](#x-nnn) — <title>` | Missing title OR comma-separated (no `<br/>`) |
| Table reference cell with exactly 1 ref | `[X-NNN](#x-nnn) — <title>` | Missing title |
| Prose outside tables — Mitigation Register `**Addresses:**` with ≥2 refs | Bullet list, one `- [X-NNN](#x-nnn) — <title>` per line | Missing title OR comma-separated |
| Prose outside tables — Mitigation Register `**Addresses:**` with 1 ref | Inline `**Addresses:** [X-NNN](#x-nnn) — <title>` | Missing title |
| Inline prose citation | `[X-NNN](#x-nnn) (<short title>)` or compact `[X-NNN](#x-nnn)` where the sentence already supplies the meaning | Missing link |
| Narrow table or summary chip explicitly owned by the composer | `[X-NNN](#x-nnn)` | Missing link |

## 3. Auto-repair rules

Applied in this order, single `Edit` batch per file:

a. **Bare-ID → link.** In eligible prose, tables, and lists, wrap bare `T-NNN`, `M-NNN`, `F-NNN`, `TH-NN`, and `C-NN` references with their anchor link. Skip the contexts in Section 4.

b. **Ordinary link without a title → titled link.** In a table or list that requires labels, rewrite `[X-NNN](#x-nnn)` to `[X-NNN](#x-nnn) — <title>` using the lookup from step 1. Normalize legacy bare-space and colon forms to the same em-dash form. Do not expand compact or inline forms owned by the composer.

c. **Comma-list outside tables → bullet list.** In the Mitigation Register `## 9.` body only: any `**Addresses:** …, …` line carrying ≥2 references is converted to a bullet list (see template in `phase-group-threats.md`).

d. **Comma-list inside tables → `<br/>`-separated.** Any table cell matching `\| [^|]*[T|M]-\d{3}[^|]*, [^|]*[T|M]-\d{3}[^|]*\|` is rewritten to `<br/>`-separated form, each entry `[X-NNN](#x-nnn) — <title>`.

## 4. Edge cases — do NOT repair

- IDs inside code fences (```` ``` ````) or inline code spans (`` ` ``).
- IDs inside HTML comments (`<!-- … -->`).
- IDs inside Mermaid diagram blocks (` ```mermaid `).
- The anchor definition site itself: `<a id="t-001"></a>T-001`, `<a id="m-001"></a>M-001`.
- The `ID` column of any table (first `|`-separated cell of a row, when the table header line is exactly `| ID |`).
- Markdown headings and Table of Contents entries, where nested links break the generated slug.
- Existing HTML anchors produced by fixed-layout tables.
- Inline references already followed by a parenthetical short title.
- Compact references in the Verdict, narrow Assets cells, Top Weaknesses proof lists, and the Critical Attack Tree findings pointer.
- A reference whose title cannot be resolved. Keep the link compact and let orphan and schema checks report the missing source data.
