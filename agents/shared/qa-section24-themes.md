# QA Section 2.4 — Security Architecture Assessment rules

Used by `appsec-qa-reviewer` Check 7b. Validates the numbered layout, theme-body micro-template, and per-theme Mermaid diagrams in Section 2.4 (`### 2.4 Security Architecture Assessment` — also accepted as `### 2.3` or `### 2.5` for systems that shift numbering).

## 1. Numbered layout

Section 2.4 MUST contain exactly nine `####` H4 sub-sections, each prefixed with its canonical number:

1. `#### 2.4.1 Architecture Patterns`
2. `#### 2.4.2 Key Architectural Risks`
3. `#### 2.4.3 Secret Management`
4. `#### 2.4.4 Authentication`
5. `#### 2.4.5 Authorization & Access Control`
6. `#### 2.4.6 Input Validation & Output Encoding`
7. `#### 2.4.7 Separation & Isolation`
8. `#### 2.4.8 Defense-in-Depth`
9. `#### 2.4.9 Overall Architecture Security Rating`

Walk the Section 2.4 block (from `### 2.4` to the next `### ` or `## ` heading) and collect every `#### ` heading. Apply these checks:

### 1a. Legacy non-numbered H4 headings

Pre-flat-layout artefacts MUST be rewritten or stripped:

- `#### Trust Model Evaluation` → delete the sub-section (merged into 2.4.4)
- `#### Authentication and Authorization Architecture` → delete the sub-section (merged into 2.4.4 / 2.4.5)
- `#### Cross-Cutting Architecture Findings` → delete the heading **but keep the body** (it contained the six legacy themes; the themes below get auto-renamed to numbered H4)
- `#### Architecture Patterns` (unnumbered) → rename to `#### 2.4.1 Architecture Patterns`
- `#### Key Architectural Risks` (unnumbered) → rename to `#### 2.4.2 Key Architectural Risks`
- `#### Overall Architecture Security Rating` (unnumbered) → rename to `#### 2.4.9 Overall Architecture Security Rating`

For deletions, print `[qa-reviewer]   ↳ Section 2.4 legacy sub-section removed: <heading>` and leave a single-line marker `<!-- QA: stripped legacy sub-section "<heading>" — content is now distributed across 2.4.3 through 2.4.8 per phase-group-architecture.md → "Section 2.4 layout" -->` at the deletion point.

### 1b. Legacy H5 themes inside the (now-removed) Cross-Cutting block

The six themes used to be `##### 1. Secret Management` through `##### 6. Defense-in-Depth` — H5 headings with a leading integer. For each occurrence inside Section 2.4, rewrite the heading in place to its new numbered H4 form:

- `##### 1. Secret Management` → `#### 2.4.3 Secret Management`
- `##### 2. Authentication` → `#### 2.4.4 Authentication`
- `##### 3. Authorization & Access Control` → `#### 2.4.5 Authorization & Access Control`
- `##### 4. Input Validation & Output Encoding` → `#### 2.4.6 Input Validation & Output Encoding`
- `##### 5. Separation & Isolation` → `#### 2.4.7 Separation & Isolation`
- `##### 6. Defense-in-Depth` → `#### 2.4.8 Defense-in-Depth`

Also accept `**Secret Management**` (bold-paragraph variant with no heading at all) and rewrite to the same numbered H4. Print: `[qa-reviewer]   ↳ Section 2.4 theme headings normalised: <n> rewrites`.

### 1c. Missing themes

After normalisation, all nine expected sub-sections must be present. For each missing number, append at the end of Section 2.4: `<!-- QA: Section 2.4 is missing sub-section "2.4.<n> <title>" — add the micro-template body (Current state / Structural defects / Impact / Target architecture / Linked threats). See phase-group-architecture.md → "The six architecture themes" -->`. Print: `[qa-reviewer]   ↳ Section 2.4 sub-sections: <n>/9 present`.

### 1d. Out-of-order / gap check

Extract the numeric sequence from the numbered H4 headings in reading order and verify it is exactly `[2.4.1, 2.4.2, 2.4.3, 2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9]`. A gap or reorder is flagged with `<!-- QA: Section 2.4 heading sequence is <observed> — expected 2.4.1 through 2.4.9 in order. Reorder the sub-sections. -->` at the first out-of-place heading.

## 2. Theme body format (2.4.3 to 2.4.8)

For each of the six theme sub-sections, walk the body (between its `#### 2.4.<n>` heading and the next `#### ` heading) and enforce:

1. **Bullet-first micro-template.** The body MUST contain (in order) the following labelled blocks, each introduced by a bold label:
   - `**Current state.**` or `**Current state:**` (one sentence follows on the same line or the next)
   - `**Structural defects:**` (followed by a bulleted list of 3 to 5 items — the `- ` bullets start on the next line)
   - `**Impact.**` (one sentence)
   - `**Target architecture.**` (one or two sentences)
   - `**Linked threats:**` (followed by clickable `[T-NNN](#t-NNN)` references — mandatory when any T-NNN is linked; omit only in the sound-architecture short form described below)
   Missing blocks are flagged: `<!-- QA: theme "<heading>" is missing required block "<label>" — see phase-group-architecture.md → "Per-theme template" -->`.

2. **Prose blocks are concise but not artificially truncated.** Each labelled block (`Current state.`, `Impact.`, `Target architecture.`) may be one to three sentences. If any block exceeds 3 sentences, flag: `<!-- QA: theme "<heading>" contains an overly long prose paragraph (>3 sentences) — compress to 1–3 sentences. -->`. Exception: the sound-architecture short form described below.

3. **Code references REQUIRED in themes 2.4.3, 2.4.4, 2.4.5.** Secret Management, Authentication, and Authorization themes MUST contain at least one `vscode://` link or `[file:line]` reference in their `Current state.` sentence or `Structural defects:` bullets. If none are found, flag: `<!-- QA: theme "<heading>" is missing code references — themes 2.4.3/2.4.4/2.4.5 must include concrete file:line locations. -->`. For themes 2.4.6 through 2.4.8, code references are optional but allowed.

4. **Library names allowed for key context.** When a library name and version appear as the root cause of a structural defect (e.g., an outdated JWT library), they are allowed. Exhaustive version inventories (listing every transitive dependency) are flagged: `<!-- QA: theme "<heading>" contains excessive library version inventory — keep only key root-cause libraries. -->`. Allowed: naming 1–2 key libraries per theme. The word "RSA-1024" or "RSA-2048" (key size) is never flagged.

5. **Theme length cap.** Count rendered lines from the `####` heading to the next `####` heading (exclusive). If > 25 lines and no diagram is present, or > 40 lines with a diagram, flag: `<!-- QA: theme "<heading>" is <n> lines — the cap is 20 lines (prose-only) or 35 lines (with diagram). Compress the bullets. -->`.

6. **Sound-architecture short form.** When the entire body is a single sentence beginning with `**Current state.**` and ending with "No systemic finding.", the bullets/Impact/Target/Linked-threats blocks are optional and the length cap is relaxed to 5 lines. Skip checks 1 and 2 in that case.

Print: `[qa-reviewer]   ↳ Section 2.4 theme bodies: <n>/6 checked, <n> missing-block, <n> over-prose, <n> file-refs, <n> lib-versions, <n> over-length`

## 3. Per-theme Mermaid diagrams

Two themes are **mandatory** at `standard` depth or higher, and the caps are applied per-theme instead of summed across the whole Cross-Cutting block.

For each theme (2.4.3 to 2.4.8), run:

1. **Wrong diagram type.** Any ```` ```mermaid ```` block inside the theme whose first non-whitespace keyword is `sequenceDiagram`, `classDiagram`, `stateDiagram`, `erDiagram`, `gantt`, `pie`, `journey`, or `flowchart` is flagged: `<!-- QA: theme "<heading>" uses diagram type `<type>` — only `graph LR` or `graph TB` is allowed in Section 2.4 themes. See phase-group-architecture.md → "Per-theme Mermaid diagrams" -->`.

2. **Prohibited-theme diagram.** Any ```` ```mermaid ```` block inside `2.4.6 Input Validation & Output Encoding` or `2.4.8 Defense-in-Depth` is flagged regardless of type and auto-removed: `<!-- QA: theme "<heading>" must not contain a Mermaid diagram — this theme is bullets-only (see phase-group-architecture.md → "Forbidden-theme reasoning"). Diagram auto-stripped. -->`.

3. **Node-count overload.** Count nodes (lines matching `^\s*\w+[\[\(]`). If > 7, flag: `<!-- QA: theme "<heading>" diagram has <n> nodes — the cap is 7. Simplify, split, or drop the diagram. -->`.

4. **Node labels may include short file references.** For 2.4.x theme diagrams, node labels MAY include short file references (e.g., `routes/login.ts\nRaw SQL`) to help locate the architectural defect. Full absolute paths or `vscode://` URLs inside node labels are still flagged. For C4-level diagrams (2.1, 2.2, 2.3), node labels must remain abstract (User, IdP, Vault, API, DB).

5. **Missing Key takeaway.** If a diagram is present, a single-sentence `**Key takeaway:**` line MUST appear between the closing ```` ``` ```` fence and the first labelled block. If missing, flag: `<!-- QA: theme "<heading>" diagram is missing its **Key takeaway:** sentence -->`.

6. **Mandatory-diagram enforcement at standard+ depth.** Read `DIAGRAM_DEPTH` from the header metadata row (`| Depth | quick|standard|thorough |`) and apply the matrix:

   | Theme | `quick` | `standard` | `thorough` |
   |---|---|---|---|
   | 2.4.3 Secret Management | — | recommended (not enforced) | **mandatory** |
   | 2.4.4 Authentication | — | **mandatory** | **mandatory** |
   | 2.4.5 Authorization & Access Control | — | optional | optional |
   | 2.4.6 Input Validation | — | forbidden | forbidden |
   | 2.4.7 Separation & Isolation | — | optional | optional |
   | 2.4.8 Defense-in-Depth | — | forbidden | forbidden |

   For each theme marked **mandatory** at the current depth where no `graph LR` / `graph TB` block is present, flag at the top of the theme body: `<!-- QA: theme "<heading>" is missing its mandatory Mermaid diagram at DIAGRAM_DEPTH=<depth>. See phase-group-architecture.md → "Per-theme Mermaid diagrams" → mandatory matrix. -->`.

   Themes marked "optional" or "recommended" are never flagged for missing diagrams — only for presence of a forbidden type, overload, or missing takeaway.

Print: `[qa-reviewer]   ↳ Section 2.4 theme diagrams: <n> present, <n> mandatory-missing, <n> forbidden-stripped, <n> wrong-type, <n> overload, <n> label-pollution, <n> missing-takeaway`
