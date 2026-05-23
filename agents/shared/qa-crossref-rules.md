# QA Cross-reference style rules (Check 3f)

Used by `appsec-qa-reviewer` Check 3f. Enforces the convention from `phase-group-threats.md` → "Cross-reference linking rule (all sections)": every `T-NNN`, `M-NNN`, `F-NNN`, `TH-NN`, or `C-NN` that is used as a **reference** (not an identifier in an ID column) MUST be shaped `[X-NNN](#x-nnn) — <short title>` (uniform reference schema, em-dash separator) and — when it appears outside a table — MUST render as a Markdown bullet list when ≥2 references are on the same logical line.

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
| Parenthetical inside a sentence (`…(T-005 — Hardcoded RSA key)…`) | `([X-NNN](#x-nnn) — <title>)` | Missing link |

## 3. Auto-repair rules

Applied in this order, single `Edit` batch per file:

a. **Bare-ID → link.** Any `\bT-\d{3}\b`, `\bM-\d{3}\b`, `\bF-\d{3}\b`, `\bTH-\d{2}\b`, or `\bC-\d{2}\b` outside a Mermaid block, a code fence, the ID-column anchor site, or an existing `[X-NNN](#x-nnn)` is wrapped with the anchor link.

b. **Link-without-em-dash → link+em-dash+title.** Any `[X-NNN](#x-nnn)` (where `X ∈ {T, M, F, TH, C}`) not immediately followed by ` — ` on the same visual unit (same table cell, same prose clause up to `,` or `;` or `.`) is rewritten to `[X-NNN](#x-nnn) — <title>` using the lookup from step 1. The legacy bare-space form (`[C-01](#c-01) REST API`) and colon form (`[F-009](#f-009): SQL injection`) are both rewritten to the uniform em-dash form — this is the single reference schema for every linked entity in the document.

c. **Comma-list outside tables → bullet list.** In the Mitigation Register `## 9.` body only: any `**Addresses:** …, …` line carrying ≥2 references is converted to a bullet list (see template in `phase-group-threats.md`).

d. **Comma-list inside tables → `<br/>`-separated.** Any table cell matching `\| [^|]*[T|M]-\d{3}[^|]*, [^|]*[T|M]-\d{3}[^|]*\|` is rewritten to `<br/>`-separated form, each entry `[X-NNN](#x-nnn) — <title>`.

## 4. Edge cases — do NOT repair

- IDs inside code fences (```` ``` ````) or inline code spans (`` ` ``).
- IDs inside HTML comments (`<!-- … -->`).
- IDs inside Mermaid diagram blocks (` ```mermaid `).
- The anchor definition site itself: `<a id="t-001"></a>T-001`, `<a id="m-001"></a>M-001`.
- The `ID` column of any table (first `|`-separated cell of a row, when the table header line is exactly `| ID |`).
