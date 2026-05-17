---
# Management Summary Template
# Shared reference — loaded on-demand by phase-group-threats.md before composing the MS draft.
# Do NOT load this file at Phase 9 STRIDE dispatch time — it costs ~4k tokens.
# Load it just before writing .management-summary-draft.md (end of Phase 9).
---

### Build Management Summary — MANDATORY at all depth levels

**Prose-style anchor — read once before composing the draft.** The Management Summary is the most-read prose surface of the entire report. Apply the rules from `agents/shared/prose-style.md` (specificity, falsifiability, information-density, scannable structure, no boilerplate) to every sentence you write here. Load it now if you have not already in this Phase:

```bash
cat "$CLAUDE_PLUGIN_ROOT/agents/shared/prose-style.md"
```

Concretely for the MS: opening sentences carry the severity cue + the worst-case attacker capability — not metaphors. Bullet bodies name the mechanism (specific endpoint, file:line, library call). Architecture-Assessment defect descriptions describe the structural deficiency, not its rhetorical impact. Architecture-Assessment closing sentences are not sermons. Any sentence whose only job is to introduce the next sentence gets cut.

After the Threat Register and Mitigation Register are complete, generate a **Management Summary** section. This section is placed **after the Table of Contents and before Section 1** in the final output. **The Management Summary MUST be generated at every `ASSESSMENT_DEPTH` level — including `quick`.** It is the single most important section for stakeholders. Skipping it due to turn budget pressure is never acceptable — if turns are tight, reduce other sections (e.g., skip Architecture Assessment themes at quick depth) but always emit the Management Summary.

**Purpose:** Executives and architects who do not read the full report must walk away from the first ninety seconds knowing four things — *how bad it is*, *what the top risks are*, *what the worst case looks like end-to-end*, and *what must happen first*. The summary answers those four questions and nothing else. Per-threat details, file references, CWE numbers, severity counts and effort estimates belong in Sections 8, 9 and 10 — **not** here.

**Presentation rules (load-bearing):**

- **Scannability beats completeness.** When a choice must be made between "one more sentence" and "one fewer line", cut the sentence. The reader has 90 seconds.
- **Every T-NNN and M-NNN in this section must be a clickable link** — never bare text.
- **Zero severity-count noise.** The Management Summary does not render Risk Distribution tables, STRIDE Coverage tables, or severity totals (e.g. "5 Critical and 14 High…"). Those live in the Threat Register alone.
- **Tables over bullets for structured data.** Top Findings, Mitigations (Prioritized + Follow-up), and Operational Strengths use tables — they are easier to scan than bullet lists and align columns for comparison.
- **Worst-case scenarios are rendered as bullets inside the Verdict blockquote.** The Verdict section is framed by a red HTML box (`<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">`) that contains the attack-path bullets with F-NNN references. There is **no separate `### ⚠ Worst Case Scenarios` sub-section** — the bullets inside the Verdict blockquote *are* the worst-case scenarios.

```markdown
## Management Summary

### Verdict

<Verdict — structured as: opening sentence + red HTML blockquote with bullet points + closing assessment. The opening sentence MUST begin with a severity cue — 🟢 ready / 🟡 acceptable with caveats / 🔴 not production-ready — followed by a plain-language verdict stating the worst-case attacker capability and, when relevant, Critical/High counts. Then a red HTML blockquote containing 2–5 bullet points, each naming one critical attack path in bold followed by a one-sentence plain-language explanation and an italicised F-NNN citation in parentheses. After the blockquote, 1–2 closing sentences with the overall assessment.

**Closing-sentence rule (load-bearing — failed in 2026-05 runs).** The closing sentence MUST add **new information** that the bullets above did not already convey. It MUST NOT restate the attack paths (the bullets already named them). Acceptable framings, in order of preference: (a) the business or regulatory consequence ("any user data processed by this deployment is treated as breached"), (b) the operating context that makes the posture critical ("the deployment is reachable from the public internet without WAF/IDS"). NEVER open the closing with "No meaningful security boundary exists between…" — that phrase appears verbatim in the example below and reviewers flag it as a generic AI cliché. Do NOT cite compliance standards (ASVS, NIST SP 800-53, ISO 27001, PCI-DSS, etc.) in this sentence — pauschale "fails standard X" claims are not defensible without a per-control gap analysis, which belongs in a separate report. Pick one of (a)/(b) and write a sentence that is specific to THIS system. No CWE numbers, no file paths, no threat counts outside the opening sentence. F-NNN links inside the blockquote are allowed and expected.>

<Example:>

🔴 **CRITICAL SECURITY POSTURE** — An unauthenticated attacker can achieve full system compromise within minutes through multiple independent paths. The assessment identified **7 Critical** and **12 High** findings.

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

- **Full database theft without login** — A SQL Injection flaw in the product search lets any internet user extract the entire customer table in a single web request. *([F-009](#f-009))*
- **Admin login without a password** — A SQL Injection flaw in the login endpoint allows an attacker to log in as any user, including administrators, without knowing the password. *([F-014](#f-014))*
- **Server takeover from a normal user account** — Any logged-in user can send a crafted B2B order to run arbitrary OS commands on the server. *([F-010](#f-010))*
- **Admin impersonation via a leaked source-code secret** — The RSA private key used to sign session tokens is committed to the public repository; an attacker downloads it and issues valid admin tokens offline. *([F-001](#f-001), [F-005](#f-005))*

</blockquote>

Any customer data processed by this deployment must be treated as already breached: the application is reachable from the public internet, the database holds plaintext PII alongside MD5-hashed credentials, and there is no detective control (no WAF, no IDS, no rate limit on the affected endpoints) that would flag exploitation in flight.

<End example. The closing sentence above names the consequence (data treated as breached) and the operating context (internet-reachable, no detective controls), NOT a restatement of the bullets. Adapt the bullets and the closing to the actual findings of THIS system. For 🟡 verdicts the bullets describe caveats; for 🟢 verdicts the blockquote may be omitted entirely and replaced by a short affirming paragraph.>

### Top Findings

<Intro sentence: "The **<N> highest-risk items** across code, configuration and architecture, sorted by impact-weighted score. F-IDs jump to full finding detail in [§8.B](#8b-critical-categories); AF-IDs jump to [§8.G](#8g-architectural-findings).">

<⚠ MANDATORY single-table layout (Phase-5, replaces the legacy two-table form). The table lists findings DIRECTLY — no separate Top Threats category table. The Category column carries the architectural pattern signal; a category-level overview remains in §8.A for reference but is NOT rendered in the Management Summary.>

**Sort order (mandatory, enforced by QA Check 3h):**

1. **Primary — triage-supplied `findings_ranked[]`** from `.triage-flags.json → ranking.views.top_findings`. Phase 11 reads this view and renders the table in exactly that order. The triage-validator computes the ranking using impact-weighted-v2 scoring (severity 150× + impact 40× + breach 15× + likelihood 3× + top25 5× + cvss 1×; contributor −50; ranking-cap −100).
2. **Fallback** (only when `.triage-flags.json` is absent or v1): sort by `effective_severity` desc → `breach_distance` asc → `cvss` desc → F-ID asc.

**Threshold:** include findings with `effective_severity ∈ {Critical, High}` (detective-capped findings like CWE-778 fall under High and may or may not make the cut). Limit to **15–20 rows** — when more findings qualify, truncate and append a footnote `_+N additional ≥High findings — see [Section 8.B](#8b-critical-categories) and [Section 8.G](#8g-architectural-findings)._` Anchors use the unsuffixed forms (`#8b-critical-categories`, `#8g-architectural-findings`) — no count-suffix.

**Never sort by F-ID alone.** The table's job is to give executives and engineers the highest-leverage fixes first — numeric ID order contradicts that.

| # | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations |
|---|-------------|---------|-----------|--------|--------|---------------------|
| 1 | 🔴 Critical | [F-NNN](#f-NNN) — <short finding title, ≤50 chars> | [C-NN](#c-NN) — <Component name> | [TH-NN](#th-NN) — <Category name> | [Internet Anon](#vektor-internet-anon) | [M-NNN](#m-NNN) — <short action, ≤30 chars> (P1) |
| 2 | 🟠 High | [AF-NNN](#af-NNN) — <architectural weakness title> | Architecture | [TH-NN](#th-NN) — <Category name> | [n/a](#vektor-n-a) | [M-NNN](#m-NNN) — <short action> (P2) |

**Primary Mitigations column — title + priority required.** Every `[M-NNN](#m-nnn)` link MUST be followed by a short action label (≤30 characters) AND a trailing priority token `(P1)` / `(P2)` / `(P3)` / `(P4)` in parentheses, matching the mitigation's rollout priority from the Mitigation Register. Example: `[M-007](#m-007) — Parameterize all raw SQL queries (P1)`. Bare M-NNN links, missing labels, or missing priority tokens are format defects that QA Check 3h auto-repairs using the M-NNN title + priority from the YAML Mitigation Register. When multiple mitigations address a single finding, separate them with `<br/>` inside the cell. When the finding has ≥3 mitigations, render the top-2 and append `<br/>+N more`.

**Column semantics:**

| Column | Width | Content |
|---|---|---|
| `#` | narrow | 1-based rank from the triage view |
| `Criticality` | narrow | Emoji + word (🔴 Critical / 🟠 High). When `effective_severity > raw risk`, append ` *(effektiv)*` and render the effective value |
| `Finding` | wide | `[F-NNN](#f-NNN) — <short title>` — **uniform reference schema** (em-dash separator, same as mitigations and threats). Title is the first clause of the finding's scenario, truncated at the first `:` / `.` outside backticks, max 50 chars. **Do not inline the component reference here** — it belongs in the dedicated `Component` column |
| `Component` | narrow | `[C-NN](#c-NN) — <Component name>` — **uniform reference schema** (em-dash separator, same as findings and mitigations). Single linked cell, no `<br/><small>` wrapper. Resolved from `threat-model.yaml → findings[].component` (the canonical component id) and rendered with the component's canonical name. For AF-NNN entries whose scope is the whole architecture (no single component), render the literal string `Architecture` |
| `Threat` | medium | `[TH-NN](#th-NN) — <Category name>` — the architectural pattern (enables scanning for systemic clusters). **Required** — bare text categories without links are a format defect. |
| `Vektor` | narrow | `[<kebab-case id>](#vektor-<id>)` — clickable link to Appendix A — Vektor Taxonomy. Values: `Internet Anon`, `Internet User`, `Internet Priv User`, `Victim-Required`, `Build-Time`, `Repo-Read`, `n/a`. Bare-text Vektor values without links are a format defect auto-repaired by QA. |
| `Primary Mitigations` | medium | Up to 2 M-IDs separated by `<br/>`, each with short action label AND trailing `(P1)`/`(P2)`/`(P3)`/`(P4)` token. When the finding has ≥3 mitigations, append `<br/>+N more` |

**Clickability rule:** every F-NNN, TH-NN, M-NNN in this table MUST be a live anchor link. The F-NNN links are the **canonical cross-reference mechanism** throughout the document — every architecture-assessment paragraph, trust-boundary row, and control-catalog entry references findings by `[F-NNN](#f-NNN)`. This single table is the primary landing page for every F-ID link in the report.

> 🔴 = Critical · 🟠 = High. **"(effektiv)"** = Severity elevated via keystone role in a compound chain. **Vektor** values link to full definitions in [Appendix A — Vektor Taxonomy](#appendix-a-vektor-taxonomy).

<Worst-case scenarios are rendered as the bullets inside the Verdict blockquote above — there is no separate `### ⚠ Worst Case Scenarios` sub-section. The bullets already carry business-language names and F-NNN citations; nothing further is emitted between Top Findings and Architecture Assessment.>

### Architecture Assessment

<Opening line with a 🔴/🟡/🟢 verdict cue in bold, then 1–2 sentences stating the architectural verdict. It is allowed to reference F-NNN links in this opening prose when they anchor the verdict claim. No file paths, no CWE numbers.>

<Followed by a short framing sentence introducing the table. Compute the percentage from the actual finding coverage, do NOT free-text it: count distinct F-NNN/AF-NNN references in the Key Findings column, divide by the total High+Critical finding count from the threat register, round to nearest 5%. Example: "Four cross-cutting defects drive 55% of all High/Critical findings:".>

<Table with the key cross-cutting architectural defects. Columns: Defect, Description, Key Findings. Sorted by impact. This 3-column schema is canonical.>

<Defect selection rule: prefer existing AF-NNN clusters, then weak/missing security_controls[] that mitigate High/Critical findings, then repeated High/Critical findings sharing a CWE, finding_type_id, component boundary, or missing control. Do not add free-form "architecture concerns" that are not backed by findings or control gaps.>

<**Completeness rule (D — load-bearing).** Every High and Critical finding MUST be cited in at least one defect row's Key Findings column. Before submitting the table, list each High+Critical F-NNN and verify it appears at least once. If a finding doesn't fit any of the 4 defect rows you've chosen, add a fifth row labelled `Other High/Critical Findings` and cite the orphan finding(s) there. This rule is the difference between a defect table that summarises the report and one that cherry-picks the easy stories — the second drives the user back to the Threat Register to discover what was skipped. Architectural-finding-class (CSRF, request-forgery, etc.) defects MUST NOT be included unless at least one F-NNN with the corresponding CWE actually exists in the register; do not invent defect rows that do not anchor to a real finding.>

| Defect | Description | Key Findings |
|--------|-------------|--------------|
| **<defect name>** | <one-sentence description of the structural weakness and its architectural reach> | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> |
| **<defect name>** | <description> | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> |

<The Key Findings column MUST include a short label after each F-NNN link: `[F-NNN](#f-NNN) — <short label>`. Multiple findings are `<br/>`-separated inside the cell. Bare F-NNN links without a label are a format defect.>

<Closing line linking to §7: `See **[§7 Security Architecture](#7-security-architecture)** for the full per-domain assessment …`>

### Mitigations

This section presents all mitigations in two tiers: prioritized (fix immediately / next release) and follow-up (subsequent sprints).

#### Prioritized Mitigations

<One intro sentence: these address the Critical/High findings from the Top Findings table above. Entries are ordered by effort (lowest first), then by number of findings addressed (highest first).>

| ID | Mitigation | Component | Addresses | Effort |
|----|-----------|-----------|-----------|--------|
| [M-NNN](#m-NNN) | <title> | [C-NN](#c-NN) <Component name> | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> | Low/Medium/High |

<One row per Prioritized mitigation. The Addresses column links back to the finding IDs from the Top Findings table. Every finding reference MUST include a short label after the F-NNN link. Every Critical finding in Top Findings MUST have at least one row here.>

#### Follow-up Mitigations

<One intro sentence: these address the remaining High/Medium findings not covered above. Same ordering rule (effort asc, then findings-addressed desc).>

| ID | Mitigation | Component | Addresses | Effort |
|----|-----------|-----------|-----------|--------|
| [M-NNN](#m-NNN) | <title> | [C-NN](#c-NN) <Component name> | [F-NNN](#f-NNN) — <short label> | Low/Medium/High |
| [M-NNN](#m-NNN) | <title> | [C-NN](#c-NN) <Component name> | [F-NNN](#f-NNN) — <short label> | Low/Medium/High |

<Both tables use the same five columns (ID, Mitigation, Component, Addresses, Effort) for visual consistency. The Component cell is a clickable `[C-NN](#c-NN) <name>` reference; when a mitigation spans multiple components, stack them with `<br/>`. The Addresses column uses F-NNN IDs with short labels, `<br/>`-separated.>

### Requirements Compliance

<ONLY when CHECK_REQUIREMENTS=true. Omit this entire subsection otherwise.>

**Baseline:** [<requirements source name or URL>](<url>)
**Result:** <N> requirements checked — <N_pass> PASS · <N_fail> FAIL · <N_antipattern> ANTI-PATTERN · <N_partial> PARTIAL

<Up to 3 bullets — architectural violations and ANTI-PATTERN findings only. The full list lives in Section 7b.
Selection order: ❌ ANTI-PATTERN `MUST` first, then ❌ ANTI-PATTERN `SHOULD`, then ❌ FAIL with `architectural_violation=true` `MUST`, then ❌ FAIL with `architectural_violation=true` `SHOULD`, then ❌ FAIL `MUST` requirements when fewer than 3 architectural slots are filled.
Each bullet format: "- **[REQ-ID](url) — <title>** `MUST/SHOULD`: <one sentence describing the systemic risk and its business impact>."
When zero architectural violations or ANTI-PATTERN findings exist, omit all bullets (keep only Baseline + Result lines).>

→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*

### Operational Strengths

<When the overall verdict is 🟡 or 🔴, open with: "Despite the <intentionally vulnerable / structurally deficient> design, the project implements several security-relevant controls. None fully mitigate Critical findings, but each reduces part of the attack surface.">

<⚠ MANDATORY 5-column table. The columns are `Architectural Control`, `Implementation`, `Effectiveness`, `Gap`, `Mitigates`. Legacy 3-column form (`Control / What it provides / Limitation`) is deprecated and auto-rewritten by QA Check 3i. Every row MUST use a **canonical architectural control name** from `$CLAUDE_PLUGIN_ROOT/data/architectural-controls.yaml` (not a library name). List 5–8 rows minimum, drawn from the rows in Section 7 (Identified Security Controls) where effectiveness ∈ {Adequate, Partial}. Missing controls do NOT appear in Operational Strengths — they live only in Section 7.>

| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |
|-----------------------|----------------|---------------|-----|-----------|
| Multi-Factor Authentication | TOTP via `otplib` on std login | ⚠️ Partial | Not enforced on OAuth or API-token paths | [T-016](#t-016) — 2FA bypass |
| HTTP Security Headers | `helmet` (X-CTO, X-FO) | ⚠️ Partial | CSP absent; HSTS absent | [T-024](#t-024) — XSS via DomSanitizer, [T-039](#t-039) — Missing CSP |
| Parameterized Database Access | Sequelize ORM default | ⚠️ Partial | Raw string interpolation in search+login | [T-009](#t-009) — SQL injection product search |
| Authentication Rate Limiting | `express-rate-limit` on reset+2FA | 🔶 Weak | Not on /login; spoofable X-Forwarded-For key | [T-036](#t-036), [T-038](#t-038) |
| <... 5–8 rows total, one per existing control with effectiveness ≥ Weak ...> | | | | |

**Bottom line:** <One sentence summarizing that these controls narrow specific attack surfaces but none eliminates a Critical finding on its own.>

→ *Full details: [Section 2](#2-architecture-diagrams) · [Critical Attack Chain](#critical-attack-chain) · [Section 7](#7-threat-register) · [Section 9](#9-mitigation-register).*
```

**Column semantics:**

| Column | Content | Source |
|---|---|---|
| `Architectural Control` | Canonical tech-agnostic name | `architectural-controls.yaml → controls[].name` |
| `Implementation` | One-line how it's realised here (library + entry point or file) | Free text |
| `Effectiveness` | One of ✅ Adequate · ⚠️ Partial · 🔶 Weak (never Missing in this table) | Shared scale with Section 7 |
| `Gap` | Concrete shortcoming, one sentence | Derived from Section 7 "Limitation" |
| `Mitigates` | Linked threats this control is intended to affect | `[T-NNN](#t-NNN) — <short label>` format, `<br/>`-separated when ≥2 |

**Relationship to Section 7 (Identified Security Controls).** Operational Strengths is a **filtered view** of Section 7 — rows with `effectiveness ∈ {adequate, partial, weak}`. `❌ Missing` controls live only in Section 7. The QA reviewer Check 3i validates that every control name in Operational Strengths appears verbatim in Section 7 (same canonical name) and that no Missing control appears here.

**Rules — the hard constraints the QA reviewer enforces:**

- **`### Verdict` heading first, with integrated red HTML blockquote.** The first sub-section after `## Management Summary` MUST be `### Verdict`. Structure: (1) opening sentence with 🟢/🟡/🔴 severity cue + one-sentence verdict + (optionally) the `N Critical / M High` finding counts, (2) **a red HTML blockquote** containing 2–5 bold bullet points — each naming one critical attack path in business language followed by a plain-language explanation and a parenthesised italic F-NNN citation (e.g. `*([F-009](#f-009))*`), (3) 1–2 closing sentences with the overall assessment. The blockquote uses `<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">` with a `<br/>` spacer above it. The bullets inside this blockquote **are** the worst-case scenarios — do not emit a separate `### ⚠ Worst Case Scenarios` heading. F-NNN links are allowed inside the blockquote; CWE numbers and file paths remain forbidden.
- **Required sub-sections — exactly FIVE, presence and order enforced by the template:** `### Verdict`, `### Top Findings`, `### Architecture Assessment`, `### Mitigations` (with `#### Prioritized Mitigations` and `#### Follow-up Mitigations` sub-tables), `### Operational Strengths`. The `### Requirements Compliance` sub-section is mandatory **only** when `CHECK_REQUIREMENTS=true` and is placed between Mitigations and Operational Strengths.
- **Top Findings is a table, not a bullet list.** The table MUST have columns: `#`, `Criticality`, `Finding`, `Component`, `Threat`, `Vektor`, `Primary Mitigations`. Include ALL Critical findings and top High findings up to 15–20 rows total. Criticality emojis: 🔴 for Critical, 🟠 for High. Every Primary Mitigations cell MUST include a short action label AND a trailing priority token: `[M-NNN](#m-NNN) — <short action> (P1)`. Every Vektor cell MUST be a link to Appendix A. A legend line MUST follow the table. Finding IDs use the `[F-NNN](#f-NNN)` format; Component IDs use `[C-NN](#c-NN)`; Threat IDs use `[TH-NN](#th-NN)`.
- **Management Summary sub-sections MUST NOT be numbered.** Headings like `### 1.1 Verdict`, `### 1.2 Top Findings` are a generation defect — the QA reviewer auto-strips the numeric prefix. Every Management Summary heading is a plain `### <Name>` with no leading digit or section number.
- **Architecture Assessment uses a table.** The canonical form used in the reference output has columns: `Defect`, `Description`, `Key Findings` (each F-NNN link is followed by a short label via em-dash). A closing `See §7 Security Architecture` reference line is required. A legacy form with columns `Severity | Layer | Defect | Consequence | Enables` remains accepted but is deprecated — QA Check 3h does not rewrite it, it only checks that every F-NNN/T-NNN link carries a short label.
- **Mitigations section contains two sub-tables with identical 5-column structure.** Both use columns: `ID`, `Mitigation`, `Component` (`[C-NN](#c-NN) <name>`, `<br/>`-separated when ≥2), `Addresses` (F-NNN list with short labels, `<br/>`-separated), `Effort` (Low/Medium/High). `#### Prioritized Mitigations` lists mitigations for Critical / High findings, ordered by effort ascending then by coverage count descending. `#### Follow-up Mitigations` lists the remaining P2/P3/P4 mitigations in the same ordering. Every Critical finding in Top Findings MUST have at least one row in the Prioritized table. The legacy 4-column form (`Priority | Mitigation | Addresses | Effort`) is deprecated.
- **Operational Strengths MUST be a 5-column table** with columns: `Architectural Control`, `Implementation`, `Effectiveness`, `Gap`, `Mitigates`. The legacy 3-column form (`Control / What it provides / Limitation`) is deprecated — QA Check 3i auto-rewrites detected legacy tables. A 2-column table is FORBIDDEN. The table MUST have 5–8 rows minimum; when more rows would qualify, truncate and append a `_+N additional controls — see [Section 7](#7-security-architecture)._` footnote. Every control name MUST match a canonical name from `architectural-controls.yaml`. Ends with a `**Bottom line:**` sentence. The introductory paragraph before the table is mandatory when verdict is 🟡 or 🔴.
- **Forbidden sub-sections — the QA reviewer strips them on sight:**
  - `### Risk Distribution` / `### STRIDE Coverage` → lives in the Threat Register alone.
  - `### ⚠ Worst Case Scenarios` / `### Worst Case Scenarios` / `### Worst Case Scenario` (any variant) → **auto-strip** and merge their bullets into the Verdict's blockquote. The reference format integrates worst-case scenarios into the Verdict section; a standalone sub-section is a legacy layout.
  - `### Top Threats` / `### Top Critical Findings` / `### Critical Findings` → use `### Top Findings` table (F-NNN format, 7 columns).
  - `### Recommended Priority Actions` / `### Immediate Actions` → merged into `### Mitigations` (Prioritized Mitigations sub-table).
  - `### Follow-up Actions` (legacy name) → auto-rewrite to `### Mitigations` with two sub-tables.
  - `### Key Strengths` → auto-rewrite to `### Operational Strengths`.
  - `### Overall Security Rating` → the Verdict heading already carries the rating.
  - `#### Structural Defects` → merged into the Architecture Assessment table.
  - `### 1.1 Verdict` / `### 1.2 Top Findings` / any `### <digit>.<digit> <Name>` inside Management Summary → auto-strip the numeric prefix, keep the heading text.
- **No file paths or vscode:// links anywhere in the Management Summary.** F-NNN / M-NNN / T-NNN / TH-NN / C-NN links are allowed in the Verdict blockquote, Top Findings, Architecture Assessment (Key Findings / Enables column), and Mitigations. File references live in the Threat Register and Mitigation Register only.
- **No duplication — three roles, three places:** Management Summary = verdict-with-scenarios / top findings table / architecture defects table / mitigations / strengths. `## Critical Attack Chain` = attack-chain diagrams (visual). Threat Register = full per-finding detail (tabular).
