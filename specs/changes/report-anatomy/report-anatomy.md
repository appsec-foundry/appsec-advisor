# Report anatomy

This document describes the shape of the threat-model report (`threat-model.md`): which chapters it has, what each chapter covers, which subsections and tables it contains, and how a finding, a mitigation, and a weakness are built. A change to that shape is a product change and needs the approval of the plugin's maintainer.

It does not describe wording, ranking, limits, diagram geometry, or how content is produced. Those live in the sections contract (`data/sections-contract.yaml`), the code that renders the report, the prompts that write its prose, and the schemas.

## Overview

A report has these chapters, in this order. Chapters in *italics* appear only under a condition.

1. Front matter: info box, *Changelog*, *quick-mode notice*, Table of Contents
2. Management Summary
3. *Critical Attack Tree*
4. §1 System Overview
5. §2 Architecture Diagrams
6. *§3 Attack Walkthroughs*
7. §4 Assets
8. §5 Attack Surface
9. *§6 Security Architecture*
10. *§7 Weakness Register*
11. *§7b Requirements Compliance*
12. §8 Findings Register
13. §9 Abuse Cases
14. §10 Mitigation Register
15. §11 Out of Scope
16. Appendices: Run Statistics, *Composition Notes*, Attack Vector Taxonomy

Section numbers are fixed, so links such as `#8-findings-register` stay the same from run to run. When a numbered chapter is absent, its number is skipped.

## How to read this document

- **always** means the part appears whenever the part above it appears. **only when** names the condition under which it appears. An absent part leaves no empty heading, field, or column.
- Text in `code` is exact: headings and table headers must appear in the report as written, and the test checks them. Text in **bold** describes content that the test does not check.
- In headings, `N` and `NNN` stand for a number, `(n)` for a count, and `<...>` for free text.

## Front matter

Covers the identity of the assessed project and how to navigate the report.

- Info box with project name, version, repository, and license — always.
- `## Changelog` — only when the model has earlier versions.
  - Table: `| Version | Date | Mode | Depth | Reasoning | Baseline → Current | Δ Threats | Code | Note |`
- Quick-mode notice — only when the run used quick depth.
- `## Table of Contents` — always.

## Management Summary

Covers the overall verdict, the systemic weaknesses, the most important threats, what to do first, and what already works. A reader who stops here knows how bad it is and what to fix first.

- `## Management Summary` — always. Its blocks appear in this order:
  - `### Verdict` — always. A 🟢, 🟡, or 🔴 rating with a highlighted statement citing at least two findings, then **About this assessment**, **Method and limits**, **Risk distribution**, and the security concerns behind the rating.
  - `### Top Weaknesses` — only when the Weakness Register has entries. One bullet per weakness with severity and a one-sentence summary.
  - `### Open Questions for the Team` — only when a decision is open that only the team can settle. At most three questions.
  - `### Security Posture & Top Threats` — always. **Figure 1a** (runtime architecture and threats), **Figure 1b** (supply chain and build, only when a build is evidenced), **Figure 2** (attack routes and impact), and the threat actors behind the routes. Every route in Figure 2 has exactly one table row, and every row links its findings into §8.
    - Table: `| # | Threat Description | Findings (→ Component) | Risk & Impact | Fix |`
  - `### Top Mitigations` — always.
    - Table: `| # | Component | Mitigation | Addresses | Effort |`
  - `### AI / LLM Exposure` — only when the system has an LLM or AI surface. One bullet per affected OWASP LLM Top 10 category with its findings.
  - `### Requirements Compliance` — only when a requirements catalog was checked. The overall result: **Baseline**, **Overall status**, and **Result**. The per-requirement detail is in §7b.
  - `### Operational Strengths` — always, closing with a **Bottom line**.
    - Table: `| Strength | What's in Place | Effectiveness |`

## Critical Attack Tree

Covers how the Critical findings combine toward the attacker's goal.

- `## Critical Attack Tree` — only when there are at least two Critical findings. One goal-decomposition diagram.

## §1 System Overview

Covers what the system is, what was analyzed and what was not, who interacts with it, and where trust changes.

- `## 1. System Overview` — always.
  - `### Scope` — always. Number of components, how many were analyzed, what is out of scope, and the basis of the assessment.
  - `### Identified Actors` — only when actors were identified.
    - Table, only when actor roles were resolved: `| Actor | Type | Access | Scenarios | Attributed findings |`
    - Table, only when no actor role was resolved: `| Actor | Role | Reach | Findings | Components |`
  - `### Trust Boundaries` — only when trust boundaries were derived.
    - Table: `| ID | Boundary / crossing | Exposure | Kind | Assumption & verdict | Linked findings |`

## §2 Architecture Diagrams

Covers the system from outside in: context, containers, and components. The diagrams are generated from the model, not written by the analysis.

- `## 2. Architecture Diagrams` — always.
  - `### 2.1 System Context` — always. One diagram.
  - `### 2.2 Container Architecture` — always. One diagram.
  - `### 2.3 Components` — always. One diagram and two tables.
    - Table: `| Component | Inbound flows | Data handled | Threats | Controls: worst effectiveness per domain |`
    - Table: `| ID | Name | Type | Key Paths | Linked Threats | Scope |`

## §3 Attack Walkthroughs

Covers how the Critical and High findings are exploited step by step, alone and chained.

- `## 3. Attack Walkthroughs` — only when the run did not use quick depth.
  - `### 3.1 Attack Chain Overview` — only when findings form a chain. One diagram per chain, each closing with a **Key takeaway**.
  - `### 3.N <title>` — always, one per walked-through finding, each with a sequence diagram.

## §4 Assets

Covers what is worth protecting, how sensitive it is, and which findings threaten it.

- `## 4. Assets` — always.
  - Table, only when findings link to assets: `| Asset | Classification | Description | Linked Threats |`
  - Table, only when no finding links to an asset: `| Asset | Classification | Description |`

## §5 Attack Surface

Covers every entry point an attacker can reach, split by whether authentication is required.

- `## 5. Attack Surface` — always.
  - `### 5.1 Unauthenticated Entry Points (n)` — always.
    - Table, only when there are entries: `| Method | Route | Risk | Notes |`
  - `### 5.2 Authenticated Entry Points (n)` — always.
    - Table, only when there are entries: `| Method | Route | Risk | Notes |`

## §6 Security Architecture

Covers, for each control family, which controls exist, how well they work, and which findings show their gaps. The unit is the control, not the finding.

- `## 6. Security Architecture` — only when the run did not skip it. Otherwise a one-line note says that it was skipped. All thirteen subsections appear, in this order:
  - `### 6.1 Security Control Overview` — always. Only the overview table, one row per family.
    - Table: `| Control category | Verdict | Main reason |`
  - `### 6.2 Identity and Authentication Controls` — always.
  - `### 6.3 Session and Token Controls` — always.
  - `### 6.4 Authorization Controls` — always.
  - `### 6.5 Query Construction and Data Access Controls` — always.
  - `### 6.6 Input Boundary Validation Controls` — always.
  - `### 6.7 Output Encoding and Rendering Controls` — always.
  - `### 6.8 Browser and Cross-Origin Controls` — always.
  - `### 6.9 Cryptography Secrets and Data Protection` — always.
  - `### 6.10 File Parser and Outbound Request Controls` — always.
  - `### 6.11 Operations Runtime and Supply Chain Controls` — always.
  - `### 6.12 Real-time and Not Applicable Controls` — always.
  - `### 6.13 Defense-in-Depth Summary` — always. A **Verdict** and two short lists, what holds and what to repair first. No table.

Each family from 6.2 to 6.12 has the same block. A family whose verdict is Not applicable has only the verdict.

1. **Verdict**: Adequate, Partial, Weak, Unsafe, Missing, or Not applicable.
2. **Controls covered**: links to every control below.
3. **Implemented controls**: what exists.
4. **Assessment**: the architectural conclusion for the family.
5. One subsection per assessed control, each with a short intro, **Security assessment**, and **Relevant findings** as a list. The login and session-token flows in 6.2 and 6.3 add a sequence diagram.

The analysis writes this block. The quality checks of every run hold it to the contract, so the test checks only the list of subsections.

## §7 Weakness Register

Covers the systemic control gaps behind the findings, each with its findings, affected components, and a structural and tactical remedy.

- `## 7. Weakness Register` — only when at least one weakness was derived. A list of all weaknesses ordered by severity, then one entry per weakness.
  - `### W-NNN — <title>` — always, one per weakness. The title names the missing or misused control.

Each weakness entry has these fields, in this order:

| Field | Content | When |
|---|---|---|
| **severity line** | Severity, confirmed or design risk, and the number of findings. | always |
| **description** | The control gap. | always |
| `**Architectural anti-pattern - <name>.**` | The anti-pattern behind the gap. | only when one applies |
| `**Confirmed findings:**` | The findings that confirm the gap. | only when there are any |
| `**Practice sites:**` | Code locations that show the unsafe practice without a confirmed finding. | only when there are any |
| `**Architecture evidence:**` | The controls and sources the assessment rests on. | always |
| `**Affected components:**` | The affected components. | only when there are any |
| `**Remediation:**` | A structural change and, when they exist, the mitigations that fix individual findings. | always |

## §7b Requirements Compliance

Covers, per requirement of the checked catalog, whether it is met, violated, or not assessable.

- `## 7b. Requirements Compliance` — only when a requirements catalog was checked.
  - `### Requirement Scope` — only when the catalog resolution was recorded.
  - `### Requirements Traceability` — always.
    - Table: `| Requirement | Status | Risk | Findings | Mitigations | Guidance |`

## §8 Findings Register

Covers every finding with location, attack, evidence, and fix.

- `## 8. Findings Register` — always. An intro, **Risk Distribution**, **STRIDE Coverage**, and a **Findings index**, then the findings grouped by severity.
  - `### 🔴 Critical (n)` — only when there are Critical findings.
  - `### 🟠 High (n)` — only when there are High findings.
  - `### 🟡 Medium (n)` — only when there are Medium findings.
  - `### 🟢 Low (n)` — only when there are Low findings.

Each finding is a card `#### F-NNN · <title>`. The title names the weakness, not the file. Its fields appear in this order:

| Field | Content | When |
|---|---|---|
| `**Severity:**` | Severity, component, and source location on one line. An unproven finding is marked as unproven. | always |
| `**Violates:**` | The violated catalog requirements. | only when a checked requirement is violated |
| `**Weakness:**` | The weakness this finding belongs to. | only when it belongs to one |
| `**Trust boundary gap:**` | The trust boundary whose assumption fails. | only when one applies |
| `**Instances (n):**` | Further locations, grouped by file. | only when there is more than one location |
| `**Issue:**` | What the attacker does and achieves. | always |
| `**Root cause:**` | Why the code allows it, specific to this finding. | only when the analysis wrote one |
| `**Evidence:**` | The verification result and what the code shows. | only when evidence was recorded |
| **code excerpt** | The source lines, secrets redacted. | only for Critical and High findings |
| `**Fix:**` | The required change and its mitigation. | always |
| `**Classification:**` | Weakness class, STRIDE category, CWE, OWASP Top 10, and the walkthrough link. | always |

## §9 Abuse Cases

Covers which abuse scenarios were checked against the code and with what outcome. When the check did not run or no scenario applied, a one-line note replaces the content.

- `## 9. Abuse Cases` — always.
  - `### AC-T-NNN — <title>` — only when a scenario was checked. A summary line with **Source**, **Actor**, **Combined Risk**, and **Verdict**, then **Goal**, **Prerequisite** when one exists, **Attack chain**, and **Scenario impact** and **Blocking mitigations** when they exist.
    - Table: `| Step | Finding | Outcome |`
  - `### Generic catalog — evaluated, not applicable` — only when catalog scenarios were ruled out.
    - Table: `| Scenario | Source | Why not applicable |`

## §10 Mitigation Register

Covers every mitigation, ordered by urgency, with the steps to implement it and a way to verify it.

- `## 10. Mitigation Register` — always. A legend and a **Mitigations index**, then four priority groups. An empty group shows a one-line note.
  - `### P1 — Immediate` — always.
  - `### P2 — This Sprint` — always.
  - `### P3 — Next Quarter` — always.
  - `### P4 — Backlog` — always.

Each mitigation is a block `#### M-NNN — <title>`. The title names the action. Every finding has at least one mitigation. The fields appear in this order:

| Field | Content | When |
|---|---|---|
| `**Addresses:**` | The findings it resolves. | always |
| `**Weaknesses addressed:**` | The weaknesses it addresses. | only when it addresses a weakness |
| `**Prevents CWEs:**` | The CWEs it prevents. | only when known |
| `**Requirements at stake:**` | The catalog requirements involved. | only when a catalog was checked |
| `**Priority:**` | Priority, effort, and the main file on one line. | always |
| `**Why:**` | Why it is needed. | only when the analysis wrote it |
| `**How:**` | Ordered steps, optionally followed by an example implementation. | only when P1 or P2, and then always |
| `**Verification:**` | How to confirm that the fix works. | only when P1 or P2, and then always |
| `**Blueprint:**` | The organization's implementation blueprint. | only when one is configured |
| `**Reference:**` | An external guide. | only when one applies |

## §11 Out of Scope

Covers what this method cannot see, what was excluded, and which components were not analyzed in depth.

- `## 11. Out of Scope` — always.
  - `### Not Covered by This Method` — always.
  - `### Excluded from This Assessment` — always.
  - `### Components Not Individually Analyzed` — only when components were left out.
    - Table: `| ID | Component | Reason not analyzed |`

## Appendices

Covers how the run went and the attack-vector vocabulary used in the findings.

- `## Appendix: Run Statistics` — always.
  - Table: `| Field | Value |`
  - `### Per-Stage Breakdown` — only when stage timings were recorded.
    - Table: `| Stage | Description | Agent | Model | Duration | Tool calls | Tokens |`
- `## Appendix: Composition Notes` — only when the previous rendering reported warnings.
- `## Appendix A — Attack Vector Taxonomy` — always.
  - `### <vector>` — always, one per attack vector used.

## Glossary

- **F-NNN, M-NNN, W-NNN, C-NN, AC-T-NNN**: identifiers of a finding, mitigation, weakness, component, and abuse case. They stay the same within one model.
- **P1 to P4**: mitigation priority, from before the next deployment (P1) to backlog (P4).
- **✓, ◌, ↻**: evidence verified, ambiguous, or carried over unverified from an earlier, deeper run.
- **Confirmed** or **design risk**: a weakness backed by confirmed findings, or one shown only by unsafe practice or a missing control.
- **Unproven**: a finding whose insecure state is observed but whose exploitability is not established.
- **Quick depth**: the fastest assessment depth, which skips §3, §6, and abuse-case checks.

## Changing the report's shape

The approved version of this document is `specs/report-anatomy.md`. A change follows these steps:

1. Propose the new wording under `specs/changes/<name>/` and get it approved.
2. Update `specs/report-anatomy.md`, the contract, and the renderer together.
3. Run `python3 -m pytest tests/test_report_anatomy.py`. It fails until all three agree.

The test checks only the parts in `code`:

- Every level-2 and level-3 heading in a rendered report must be listed here, in the listed order. A heading marked always must appear when its parent appears.
- Every table must be listed under its heading. A table without "only when" must appear when its heading appears.
- The fields of a finding, mitigation, or weakness must follow the order of its field table, and every field marked always must appear.
- The chapter order and the §6 subsections must also match the contract, so a chapter that no test report renders is still checked.

The test renders two frozen runs: `tests/fixtures/report-anatomy/quick-run` for most chapters and `tests/fixtures/e2e/frozen-run` for §3.
