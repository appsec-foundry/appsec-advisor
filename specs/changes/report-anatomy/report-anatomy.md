# Report anatomy

This document fixes the shape of `threat-model.md`: which chapters exist, in which order, what each chapter covers, which subsections, tables, and labelled fields it always has, and how a finding and a mitigation are built. A change to that shape is a product change and needs operator approval.

It does not fix wording, ranking, limits, diagram geometry, or how content is produced. Those stay in `data/sections-contract.yaml`, the renderer, the authoring prompts, and the schemas.

Each chapter states what it **covers** and its **structure**. Headings, field labels, and table headers written as `code` must appear exactly so and in the stated order; a test checks them against a rendered report. A part marked *(optional)* may be absent; its condition lives in the contract. An absent optional part leaves no empty heading, label, or column.

## Front matter

**Covers:** identity of the assessed project and how to navigate the report.

**Structure:**

- Info box with project name, version, repository, and license.
- `## Changelog` *(optional)* with the table `| Version | Date | Mode | Depth | Reasoning | Baseline → Current | Δ Threats | Code | Note |`.
- Quick-mode notice *(optional)*.
- `## Table of Contents`.

## Management Summary

**Covers:** the overall verdict, the systemic weaknesses, the most important threats and what to do first, and what already works. A reader who stops here knows how bad it is and what to fix first.

**Structure:** `## Management Summary` with these blocks in order:

1. `### Verdict`: a 🟢, 🟡, or 🔴 rating with a highlighted statement citing at least two findings, followed by `**About this assessment:**`, `**Method and limits:**`, `**Risk distribution:**`, and a list of the security concerns behind the rating.
2. `### Top Weaknesses` *(optional)*: one bullet per `W-NNN` with severity and a one-sentence summary.
3. `### Open Questions for the Team` *(optional)*: at most three bullets, each a decision only the team can settle.
4. `### Security Posture & Top Threats`:
   - `**Figure 1a - Runtime Architecture and Threat Overview**`
   - `**Figure 1b - Supply Chain and Build**` *(optional)*
   - `**Figure 2 - Attack Routes and Impact**`
   - the threat actors behind the numbered routes
   - the table `| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |`. Every route in Figure 2 has exactly one row, and every row links its findings into §8.
5. `### Top Mitigations`: the table `| # | Component | Mitigation | Addresses | Effort |`.
6. `### AI / LLM Exposure` *(optional)*: one bullet per affected OWASP LLM Top 10 category with its findings.
7. `### Requirements Compliance` *(optional)*: `**Baseline:**`, `**Overall status:**`, `**Result:**`.
8. `### Operational Strengths`: the table `| Strength | What's in Place | Effectiveness |` and a `**Bottom line:**`.

## Critical Attack Tree *(optional)*

**Covers:** how the Critical findings combine toward the attacker's goal.

**Structure:** `## Critical Attack Tree` with one goal-decomposition diagram.

## §1 System Overview

**Covers:** what the system is, what was analyzed and what was not, who interacts with it, and where trust changes.

**Structure:** `## 1. System Overview` with:

- `### Scope`: number of components, how many were analyzed, what is out of scope, and the basis of the assessment.
- `### Identified Actors` *(optional)*: the table `| Actor | Type | Access | Scenarios | Attributed findings |`.
- `### Trust Boundaries` *(optional)*: the table `| ID | Boundary / crossing | Exposure | Kind | Assumption & verdict | Linked findings |`.

## §2 Architecture Diagrams

**Covers:** the system from outside in: context, containers, and components with their `C-NN` identifiers. The diagrams are generated from the model, not written by the analysis.

**Structure:** `## 2. Architecture Diagrams` with:

- `### 2.1 System Context`: one diagram.
- `### 2.2 Container Architecture`: one diagram.
- `### 2.3 Components`: one diagram, the table `| Component | Inbound flows | Data handled | Threats | Controls: worst effectiveness per domain |`, and the table `| ID | Name | Type | Key Paths | Linked Threats | Scope |`.

## §3 Attack Walkthroughs *(optional)*

**Covers:** how the Critical and High findings are exploited step by step, alone and chained.

**Structure:** `## 3. Attack Walkthroughs` with:

- `### 3.1 Attack Chain Overview`: one `#### Chain N — <name>` per chain, each with a diagram and a closing `**Key takeaway:**`.
- one `### 3.N <title>` per walked-through finding, each with a sequence diagram.

## §4 Assets

**Covers:** what is worth protecting, how sensitive it is, and which findings threaten it.

**Structure:** `## 4. Assets` with the table `| Asset | Classification | Description | Linked Threats |`.

## §5 Attack Surface

**Covers:** every entry point an attacker can reach, split by whether authentication is required.

**Structure:** `## 5. Attack Surface` with `### 5.1 Unauthenticated Entry Points (n)` and `### 5.2 Authenticated Entry Points (n)`, each with the table `| Method | Route | Risk | Notes |` when it has entries.

## §6 Security Architecture

**Covers:** for each control family, which controls exist, how well they work, and which findings show their gaps. The unit is the control, not the finding.

**Structure:** `## 6. Security Architecture` with these subsections, always all of them, in this order:

1. `### 6.1 Security Control Overview`: only the table `| Control category | Verdict | Main reason |`, one row per family.
2. `### 6.2 Identity and Authentication Controls`
3. `### 6.3 Session and Token Controls`
4. `### 6.4 Authorization Controls`
5. `### 6.5 Query Construction and Data Access Controls`
6. `### 6.6 Input Boundary Validation Controls`
7. `### 6.7 Output Encoding and Rendering Controls`
8. `### 6.8 Browser and Cross-Origin Controls`
9. `### 6.9 Cryptography Secrets and Data Protection`
10. `### 6.10 File Parser and Outbound Request Controls`
11. `### 6.11 Operations Runtime and Supply Chain Controls`
12. `### 6.12 Real-time and Not Applicable Controls`
13. `### 6.13 Defense-in-Depth Summary`

Each family from 6.2 to 6.12 has the same block:

- `**Verdict:**` one of Adequate, Partial, Weak, Unsafe, Missing, or Not applicable.
- `**Controls covered:**` links to every control below.
- `**Implemented controls:**` what exists.
- `**Assessment:**` the architectural conclusion for the family.
- one `#### 6.N.M <control>` per assessed control, each with a short intro, `**Security assessment**`, and `**Relevant findings**` as a list. The primary login and session-token flows in 6.2 and 6.3 add a sequence diagram.

A family with the verdict Not applicable has no controls below it. `### 6.13 Defense-in-Depth Summary` has `**Verdict:**` and two short lists, what holds and what to repair first, and no table.

When the run skips §6, a one-line placeholder stands in its place.

## §7 Weakness Register *(optional)*

**Covers:** the systemic control gaps behind the findings, each with its findings, affected components, and a structural and tactical remedy.

**Structure:** `## 7. Weakness Register` with a list of all weaknesses ordered by severity, then one `### W-NNN — <title>` per weakness with:

| Field | Required? |
|---|---|
| severity and status line (confirmed or design risk, number of findings) | required |
| description of the control gap | required |
| `**Architectural anti-pattern - <name>.**` | optional |
| `**Confirmed findings:**` | optional |
| `**Practice sites:**` | optional |
| `**Architecture evidence:**` | required |
| `**Affected components:**` | optional |
| `**Remediation:**` with `**Structural**` and optionally `**Tactical**` | required |

## §7b Requirements Compliance *(optional)*

**Covers:** which requirements of the checked catalog are met, violated, or not assessable.

**Structure:** `## 7b. Requirements Compliance` with `### Requirement Scope` and `### Requirements Traceability` containing the table `| Requirement | Status | Risk | Findings | Mitigations | Guidance |`.

## §8 Findings Register

**Covers:** every finding with location, attack, evidence, and fix.

**Structure:** `## 8. Findings Register` with an intro, `**Risk Distribution:**`, `**STRIDE Coverage:**`, and `**Findings index:**`, then one group per severity that has findings: `### 🔴 Critical (n)`, `### 🟠 High (n)`, `### 🟡 Medium (n)`, `### 🟢 Low (n)`.

A finding card is `#### F-NNN · <title>`. The title names the weakness, not the file. It has these fields in this order:

| Field | Content | Required? |
|---|---|---|
| `**Severity:**` · `**Component:**` · `**Location:**` | Severity, component `C-NN`, source location. An unproven finding is marked as unproven. | required |
| `**Violates:**` | Violated catalog requirements. | optional |
| `**Weakness:**` | The `W-NNN` this finding belongs to. | optional |
| `**Trust boundary gap:**` | The trust boundary whose assumption fails. | optional |
| `**Instances (n):**` | Further locations, grouped by file. | optional |
| `**Issue:**` | What the attacker does and achieves. | required |
| `**Root cause:**` | Why the code allows it, specific to this finding. | optional |
| `**Evidence:**` | Verification status (✓, ◌, ↻) and what the code shows. | required |
| code excerpt | Source lines, secrets redacted. | optional |
| `**Fix:**` | The required change, linked to `M-NNN`. | required |
| `**Classification:**` | Weakness class, STRIDE, CWE, OWASP, walkthrough link. | required |

## §9 Abuse Cases

**Covers:** which abuse scenarios were verified against the code and with what outcome.

**Structure:** `## 9. Abuse Cases`. Always present. When verification did not run or nothing applied, a one-line note replaces the content. Otherwise one `### AC-T-NNN — <title>` per scenario with:

- a summary line with `**Source:**`, `**Actor:**`, `**Combined Risk:**`, and `**Verdict:**`
- `**Goal:**`
- `**Prerequisite:**` *(optional)*
- `**Attack chain**` with the table `| Step | Finding | Outcome |`
- `**Scenario impact**` *(optional)*
- `**Blocking mitigations**` *(optional)*

It ends with `### Generic catalog — evaluated, not applicable` *(optional)* and the table `| Scenario | Source | Why not applicable |`.

## §10 Mitigation Register

**Covers:** every mitigation, ordered by urgency, with the steps to implement it and a way to verify it.

**Structure:** `## 10. Mitigation Register` with a legend and `**Mitigations index:**`, then `### P1 — Immediate`, `### P2 — This Sprint`, `### P3 — Next Quarter`, and `### P4 — Backlog`. An empty group shows a one-line note.

A mitigation block is `#### M-NNN — <title>`. The title names the action. It has these fields in this order:

| Field | Content | Required? |
|---|---|---|
| `**Addresses:**` | Findings it resolves. | required |
| `**Weaknesses addressed:**` | `W-NNN` it addresses. | optional |
| `**Prevents CWEs:**` | CWEs it prevents. | optional |
| `**Requirements at stake:**` | Catalog requirements involved. | optional |
| `**Priority:**` · `**Effort:**` · `**File:**` | P1–P4, effort, main location. | required; File optional |
| `**Why:**` | Why it is needed. | optional |
| `**How:**` | Ordered steps, optionally followed by an example implementation. | required for P1/P2 |
| `**Verification:**` | How to confirm the fix works. | required for P1/P2 |
| `**Blueprint:**` | Organization blueprint link. | optional |
| `**Reference:**` | External guide. | optional |

Every finding has at least one mitigation.

## §11 Out of Scope

**Covers:** what this method cannot see, what was excluded, and which components were not analyzed in depth.

**Structure:** `## 11. Out of Scope` with `### Not Covered by This Method`, `### Excluded from This Assessment`, and `### Components Not Individually Analyzed` *(optional)* with the table `| ID | Component | Reason not analyzed |`.

## Appendices

**Covers:** how the run went and the attack-vector vocabulary used in the findings.

**Structure:**

- `## Appendix: Run Statistics` with the table `| Field | Value |` and `### Per-Stage Breakdown` with `| Stage | Description | Agent | Model | Duration | Tool calls | Tokens |`.
- `## Appendix: Composition Notes` *(optional)*.
- `## Appendix A — Attack Vector Taxonomy` with one `### <vector>` per attack vector used.
