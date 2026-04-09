# Phase Group: Threat Enumeration & Synthesis (Phases 9–10)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 9: STRIDE Threat Enumeration — via sub-agents

**⚠ SEQUENCING: STRIDE analyzers MUST NOT be dispatched before Phase 9.** They require outputs from Phases 6 (INTERFACES), 7 (TRUST_BOUNDARIES), and 8 (CONTROLS).

### Component Selection

Always include: Auth/identity, Authorization, components handling PII/payments, Admin panel, Public API gateway. For Moderate/Complex: each backend service, frontend SPA, queue consumers, CI/CD pipeline. **Cap at `MAX_STRIDE_COMPONENTS`** (default 5, set by `--assessment-depth`).

**Frontend SPA override:** If the recon scanner detected a frontend framework (Section 7.19) or client-side code patterns (Sections 7.10, 7.20–7.24), the frontend SPA MUST be included as a STRIDE component at **all** depth levels, including `quick`. The browser is a large, distinct attack surface that cannot be skipped. This overrides the component cap — if adding the frontend exceeds `MAX_STRIDE_COMPONENTS`, drop the lowest-risk non-auth component instead.

| ASSESSMENT_DEPTH | MAX_STRIDE_COMPONENTS | Selection strategy |
|-----------------|----------------------|-------------------|
| `quick` | 3 | Auth + highest-risk component + public API (+ frontend SPA if detected, see override above) |
| `standard` | 5 | Auth, AuthZ, PII/payment, Admin, public API, frontend SPA |
| `thorough` | 8 | All mandatory + backend services, frontend, queues, CI/CD pipeline |

### CI/CD Pipeline as STRIDE component

**When `ASSESSMENT_DEPTH=standard` or `thorough`** and CI/CD workflow files were found by the recon scanner (Section 5): include the CI/CD pipeline as a STRIDE component if it fits within `MAX_STRIDE_COMPONENTS`. Use component ID `ci-cd-pipeline`.

Pass these additional context fields in the STRIDE analyzer prompt:
- `COMPONENT_DESCRIPTION`: "CI/CD pipeline — build, test, and deployment automation. Includes workflow definitions, secret handling, artifact publishing, and deployment triggers."
- `INTERFACES`: workflow trigger events (push, PR, schedule, workflow_dispatch), artifact registries, deployment targets
- `TRUST_BOUNDARIES`: external Actions/images crossing into build environment, secrets injected at runtime, artifact publish boundary
- `SUPPLY_CHAIN_FINDINGS`: recon-summary sections 7.14–7.17 (unpinned Actions, container images, dependency confusion, postinstall hooks)

The STRIDE analyzer will use `SUPPLY_CHAIN_FINDINGS` to generate evidence-backed threats for the pipeline component (see STRIDE analyzer supply chain patterns).

### Dispatch

For each component, use Agent tool:
- `subagent_type`: `appsec-plugin:appsec-stride-analyzer`
- `description`: `STRIDE analysis for <COMPONENT_NAME>`
- `run_in_background`: `true`
- `prompt`: include COMPONENT_ID, COMPONENT_NAME, COMPONENT_DESCRIPTION, COMPONENT_COMPLEXITY, MAX_TURNS, INTERFACES, TRUST_BOUNDARIES, CONTROLS, KNOWN_SECRETS, KNOWN_VULNS, KNOWN_LLM_PATTERNS, SUPPLY_CHAIN_FINDINGS (for ci-cd-pipeline component only, from recon-summary 7.14–7.17), COMPLIANCE_SCOPE, ASSET_TIER, PRIOR_FINDINGS (for this component), KNOWN_THREATS (for this component), REPO_ROOT, OUTPUT_DIR, CONTEXT_FILE

**Dynamic turn budget:** Pass `MAX_TURNS=<N>` in the prompt, using the depth-adjusted values from the skill:
- Simple components: `MAX_TURNS=STRIDE_TURNS_SIMPLE` (quick: 10, standard: 15, thorough: 20)
- Moderate components: `MAX_TURNS=STRIDE_TURNS_MODERATE` (quick: 15, standard: 22, thorough: 28)
- Complex components: `MAX_TURNS=STRIDE_TURNS_COMPLEX` (quick: 20, standard: 31, thorough: 35)

If the `STRIDE_TURNS_*` variables are not set, use the standard defaults (15/22/31).

Dispatch all simultaneously with `run_in_background: true`. Then poll for output files.

### Validation & Retry

Validate each `$OUTPUT_DIR/.stride-<id>.json`. On failure: retry once synchronously, skip if still invalid.

### Merge

1. Merge all threat lists + Phase 8b threat candidates (if requirements enabled)
2. **Priority-aware risk for requirement threats:** For threats sourced from `requirements-compliance` or `architectural-anti-pattern`, apply the priority-derived minimum risk from Phase 8b (MUST FAIL ≥ High, architectural violations escalated by one level). If the standard Likelihood × Impact risk is already higher, keep the higher value.
3. Assign global IDs: T-001, T-002, … (by risk descending). Architectural violation threats sort first within their risk tier.
4. Deduplicate same root cause across components
5. Cross-reference prior findings from `$OUTPUT_DIR/.threat-modeling-context.md`
6. Known threats integration (open → verify, accepted → Section 11, mitigated → verify, false-positive → skip)
7. **Normalize component names:** Each unique component in the merged threat list must use a single consistent name. If the same component has different names from different analyzers (e.g., "Auth Service" vs "Auth Module"), unify to one name — use the name from the STRIDE analyzer dispatch prompt (`COMPONENT_NAME`). Do not use variant names like "Auth Service / API" alongside "Auth Module" for the same component.

### Coverage Checks

**When `ASSESSMENT_DEPTH=quick`:** Skip all coverage checks — the STRIDE analysis itself is sufficient at quick depth. Proceed directly to Merge.

**When `ASSESSMENT_DEPTH=standard` or `thorough`:**

**A — OWASP Top 10:** Verify at least one threat per OWASP 2021 category. Add gap threats for missing.

**B — Business logic:** Check workflow bypass, privilege abuse, mass enumeration, economic abuse, state manipulation.

**C — OWASP LLM Top 10 (conditional):** If AI/LLM integration was detected in recon (Section 7.13), verify coverage for each applicable LLM threat category. Add gap threats for missing. Skip if no LLM detected.

### Risk Rating Methodology (Section 8 intro)

Before the Threat Register table, include a brief methodology note:

```markdown
**Risk methodology:** Risk = Likelihood × Impact. Likelihood considers exploitability, attack complexity, and required privileges. Impact considers confidentiality, integrity, and availability effects on the identified assets. Ratings: Critical, High, Medium, Low.
```

Then the **Risk Distribution** and **STRIDE Coverage** summary lines, followed by the table.

### CWE References in Threat Register

Each threat row in the Threat Register table **MUST** include a CWE reference in the Threat Scenario cell. Append the CWE ID at the end of the scenario text in parentheses, e.g.: `... allowing full database extraction. (CWE-89)`. Use the most specific applicable CWE — every threat has an applicable CWE.

### Requirements Integration in Sections 8, 9, and 10

**When `CHECK_REQUIREMENTS=true` and requirement metadata is available from Phase 8b:**

**Section 8 — Threat Register: Violated Requirements**

For **every** threat row that has associated requirement IDs from Phase 8b (not just Critical threats), append a `Violated: [ID](url), …` note inside the Threat Scenario cell, after the CWE reference. This ensures requirement violations are visible at all severity levels — not just for Critical threats expanded in Section 9. Format example: `... file read. (CWE-611) Violated: [IV-002](url)`.

**Section 9 — Critical Findings template (extended):**
```markdown
### <severity-badge> T-NNN — Title

**Scenario:** <threat scenario text>

**Current state:** <what is present or absent>

**Violated Requirements:** [SEC-AUTH-1](url) — <requirement title>, [SEC-CRYPTO-2](url) — <requirement title>

→ **Mitigation:** [M-NNN — Mitigation Title](#m-NNN)

---
```

The **Violated Requirements** line is only present when the threat has associated requirement IDs from Phase 8b. List each violated requirement as a clickable link (using the URL from the requirements YAML) followed by the requirement title. If the requirement has no URL, render as plain `[SEC-AUTH-1]` without a link.

**Section 10 — Mitigation Register template (extended):**
```markdown
### <a id="m-NNN"></a>M-NNN · Title

**Addresses:** [T-001](#t-001), [T-002](#t-002)
**Fulfills Requirements:** [SEC-AUTH-1](url) — <title>, [SEC-AUTH-3](url) — <title>
**Priority:** <badge> | **Effort:** <level>

**Why:** ...
**How:** ...
```

The **Fulfills Requirements** line lists all requirement IDs that are satisfied when this mitigation is implemented. Derive this by collecting the requirement IDs from all threats this mitigation addresses. Only present when requirements are enabled and the mitigation addresses at least one requirement-linked threat.

### Build Mitigation Register

Assign M-NNN IDs. Merge mitigations when they produce the same physical change. Update threat records with mitigation_ids. When requirements are enabled, propagate requirement IDs from threat candidates to their mitigations for the **Fulfills Requirements** field. **Only propagate requirement IDs that actually appear as "Violated Requirements" on the addressed threats — do NOT invent or add requirement IDs that were not generated by Phase 8b.**

### Cross-reference linking rule (all sections)

When writing `threat-model.md`, ALL T-NNN and M-NNN references in ALL sections MUST be written as clickable Markdown links from the start — do not rely on the QA reviewer to linkify them afterward:

- In table cells: `[T-001](#t-001)` not bare `T-001`
- Comma-separated: `[T-001](#t-001), [T-002](#t-002)` not `T-001, T-002`
- In prose: `[M-003](#m-003)` not bare `M-003`

This applies to: Section 2 (Key Architectural Risks — Linked Threats), Section 4 (Assets — Linked Threats), Section 5 (Attack Surface — Linked Threats), Section 6 (Trust Boundaries — Linked Threats), Section 7 (Controls — Linked Threats), Section 8 (Threat Register — Mitigations column), Section 9 (Critical Findings), and Section 10 (Mitigation Register — Addresses field).

### Build Management Summary

After the Threat Register and Mitigation Register are complete, generate a **Management Summary** section. This section is placed **after the Table of Contents and before Section 1** in the final output.

```markdown
## Management Summary

This threat model identified **<N> threats** across <N> components of <System Name>, with the following risk distribution:

| Risk Level | Count | Key Areas |
|------------|-------|-----------|
| 🔴 Critical | <N> | <1-2 word summary per critical threat area, e.g. "JWT forgery, SQL injection"> |
| 🟠 High | <N> | <summary> |
| 🟡 Medium | <N> | <summary> |
| 🟢 Low | <N> | <summary> |

### Key Strengths

<2-4 bullet points highlighting existing adequate controls (✅ from Section 7) or positive architectural decisions. Be specific — cite the actual control with file reference, not generic praise.>
- <e.g., "Container runs as non-root (UID 65532) on a distroless base image — limits post-exploitation impact">
- <e.g., "SBOM generation integrated into Docker build — enables supply chain visibility">

### Requirements Compliance

<ONLY when CHECK_REQUIREMENTS=true. Omit this entire subsection otherwise.>

**Baseline:** [<requirements source name or URL>](<url>)
**Result:** <N> requirements checked — ✅ <N> PASS · ❌ <N> FAIL · ❌ <N> ANTI-PATTERN · ⚠️ <N> PARTIAL

<If any architectural violations or anti-patterns were detected, show them first:>

**⚠ Architectural violations:**
- **[<REQ-ID>](<url>) — <title>:** <one sentence describing the systemic risk — e.g., "SPA stores tokens in localStorage instead of using a BFF pattern, exposing all sessions to XSS token theft">
- ...

Top violated MUST requirements:
- **[<REQ-ID>](<url>) — <title>:** <one sentence why it fails>
- ...

→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*

### Top Findings

<For each Critical finding (max 5), one bullet point:>
- **[T-NNN — <Title>](#t-NNN):** <One sentence summary of risk and business impact>

### Recommended Priority Actions

<Top 5 mitigations by priority, ordered Critical→High:>
1. **[M-NNN — <Title>](#m-NNN)** (Effort: <level> · addresses <N> threats) — <One sentence describing the fix>
2. ...

### Overall Security Rating

<🔴/🟡/🟢> **<Rating text>** — <One sentence justification from Section 2.x Security Architecture Assessment>

→ *Full details in [Threat Register](#8-threat-register) and [Mitigation Register](#10-mitigation-register).*
```

**Rules:**
- All T-NNN and M-NNN references must be clickable links to their anchors
- Keep the summary concise — max ~40 lines. Executives read this, not the full report
- The "Key Areas" column uses short phrases, not full sentences
- "Key Strengths" lists 2-4 genuine positive controls from Section 7 (only ✅ Adequate items), with specific file references. If no controls are ✅ Adequate, omit the subsection entirely
- "Requirements Compliance" subsection is only present when `CHECK_REQUIREMENTS=true` and requirement data was processed. Architectural violations/anti-patterns are always listed first (all of them — these are systemic). Then list up to 3 top violated `MUST` requirements (non-architectural). The baseline source must identify which requirements YAML was used (URL, "cached", or "plugin fallback")
- "Top Findings" lists only Critical threats; if fewer than 3 Critical, include the highest-risk High threats to reach 3-5 items
- "Recommended Priority Actions" lists mitigations ordered by Priority (Critical first), then by lowest Effort within the same priority level. Include the count of threats each mitigation addresses
- "Key Areas" in the risk table must be derived from actual threat titles — do not list areas that have no corresponding threat in the register

## Phase 10: Secret & Dependency Scan Synthesis

**Step 1 — Hardcoded Secrets (always):** Read Section 7.12 and Section 8 from `$OUTPUT_DIR/.recon-summary.md`. Incorporate Critical/High secrets as threats (Information Disclosure / Spoofing). Use only file:line references and redacted snippets.

**Step 2 — SCA Results (only when `WITH_SCA=true`):** Poll for `$OUTPUT_DIR/.dep-scan.json`. Validate, retry once if invalid. Incorporate:
- `vulnerable_dependencies` → Tampering/Supply Chain threats (deduplicate against STRIDE analyzer findings that already used `KNOWN_VULNS`)

If `WITH_SCA` is not set: skip SCA incorporation entirely.
