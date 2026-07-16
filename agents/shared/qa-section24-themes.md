# QA Section 2.4 — Security Architecture Assessment

Referenced by `appsec-qa-reviewer` Check 7b. The deterministic helpers `check_contract` (section presence + heading order), `check_paragraph_density` (prose length), `check_diagram_compactness` (node count + label width + threat-traceability), and the §6 narrative checks own the bulk of validation. This file documents only the residual semantic rules.

## Canonical layout — nine numbered H4 sub-sections

§2.4 (also accepted as `### 2.3` / `### 2.5` for shifted numbering) MUST contain in this order:

1. `#### 2.4.1 Architecture Patterns`
2. `#### 2.4.2 Key Architectural Risks`
3. `#### 2.4.3 Secret Management`
4. `#### 2.4.4 Authentication`
5. `#### 2.4.5 Authorization & Access Control`
6. `#### 2.4.6 Input Validation & Output Encoding`
7. `#### 2.4.7 Separation & Isolation`
8. `#### 2.4.8 Defense-in-Depth`
9. `#### 2.4.9 Overall Architecture Security Rating`

Legacy renames (apply when the contract gate has not already auto-fixed): `#### Trust Model Evaluation` → delete (merged into 2.4.4). `#### Authentication and Authorization Architecture` → delete (merged into 2.4.4 / 2.4.5). `#### Cross-Cutting Architecture Findings` → delete heading but keep body. `##### 1. Secret Management` through `##### 6. Defense-in-Depth` (H5 numbered themes) → rewrite to the H4 numbered form `#### 2.4.3` through `#### 2.4.8`. `**Secret Management**` bold-paragraph variant → same rewrite. Missing themes → append `<!-- QA: Section 2.4 is missing sub-section "2.4.<n> <title>" — add the micro-template body. See phase-group-architecture.md → "The six architecture themes" -->`.

## Theme body micro-template (2.4.3 to 2.4.8)

Each theme body MUST contain in order:
- `**Current state.**` / `**Current state:**` — 1–3 sentences
- `**Structural defects:**` — 3 to 5 bulleted items
- `**Impact.**` — 1–3 sentences
- `**Target architecture.**` — 1–3 sentences
- `**Linked threats:**` — clickable `[T-NNN](#t-NNN)` references

Missing block → `<!-- QA: theme "<heading>" is missing required block "<label>" -->`. Block > 3 sentences → `<!-- QA: theme "<heading>" contains an overly long prose paragraph (>3 sentences) — compress to 1–3 -->`.

**Code references mandatory for themes 2.4.3 / 2.4.4 / 2.4.5.** Secret Management, Authentication, and Authorization MUST contain at least one `vscode://` link or `[file:line]` reference in `Current state.` or `Structural defects:` bullets. Missing → `<!-- QA: theme "<heading>" is missing code references — themes 2.4.3/2.4.4/2.4.5 must include concrete file:line locations -->`. Themes 2.4.6–2.4.8: code refs allowed but optional.

**Library names allowed for key root-cause context.** Exhaustive transitive-dependency inventories → `<!-- QA: theme "<heading>" contains excessive library version inventory — keep only key root-cause libraries -->`. Allowed: 1–2 key libraries per theme. Key-size notation (`RSA-1024`, `RSA-2048`) is never flagged.

**Theme length cap.** Prose-only: 25 lines. With diagram: 40 lines. Over cap → `<!-- QA: theme "<heading>" is <n> lines — cap is 25/40 -->`.

**Sound-architecture short form.** Single sentence beginning `**Current state.**` ending "No systemic finding." — bullets/Impact/Target/Linked-threats optional; length cap relaxed to 5 lines.

## Per-theme Mermaid diagrams (2.4.3 to 2.4.8)

Diagram type must be `graph LR` or `graph TB`. Any other type (`sequenceDiagram`, `classDiagram`, `flowchart`, `stateDiagram`, `erDiagram`, `gantt`, `pie`, `journey`) → `<!-- QA: theme "<heading>" uses diagram type \`<type>\` — only \`graph LR\` or \`graph TB\` is allowed -->`.

Any Mermaid block inside `2.4.6 Input Validation` or `2.4.8 Defense-in-Depth` is **forbidden** and auto-stripped with `<!-- QA: theme "<heading>" must not contain a Mermaid diagram — this theme is bullets-only. Diagram auto-stripped. -->`.

Node count > 7 → `<!-- QA: theme "<heading>" diagram has <n> nodes — cap is 7 -->`. Node labels may include short file references (`routes/login.ts\nRaw SQL`); full absolute paths or `vscode://` URLs inside labels are flagged. For C4 diagrams (§2.1 / §2.2 / §2.3) labels must remain abstract (User, IdP, Vault, API, DB).

Missing `**Key takeaway:**` after the closing fence → `<!-- QA: theme "<heading>" diagram is missing its **Key takeaway:** sentence -->`.

### Mandatory-diagram matrix at `DIAGRAM_DEPTH=standard+`

Read `DIAGRAM_DEPTH` from the header metadata row (`| Depth | quick|standard|thorough |`):

| Theme | `quick` | `standard` | `thorough` |
|---|---|---|---|
| 2.4.3 Secret Management | — | recommended | **mandatory** |
| 2.4.4 Authentication | — | **mandatory** | **mandatory** |
| 2.4.5 Authorization & Access Control | — | optional | optional |
| 2.4.6 Input Validation | — | forbidden | forbidden |
| 2.4.7 Separation & Isolation | — | optional | optional |
| 2.4.8 Defense-in-Depth | — | forbidden | forbidden |

Mandatory + missing → `<!-- QA: theme "<heading>" is missing its mandatory Mermaid diagram at DIAGRAM_DEPTH=<depth> -->`. Optional / recommended are never flagged for absence.
