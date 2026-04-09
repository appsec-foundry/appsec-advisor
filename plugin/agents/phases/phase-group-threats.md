# Phase Group: Threat Enumeration & Synthesis (Phases 9–10)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 9: STRIDE Threat Enumeration — via sub-agents

**⚠ SEQUENCING: STRIDE analyzers MUST NOT be dispatched before Phase 9.** They require outputs from Phases 6 (INTERFACES), 7 (TRUST_BOUNDARIES), and 8 (CONTROLS).

### Component Selection

Always include: Auth/identity, Authorization, components handling PII/payments, Admin panel, Public API gateway. For Moderate/Complex: each backend service, frontend SPA, queue consumers, CI/CD. Cap at 8 components.

### Dispatch

For each component, use Agent tool:
- `subagent_type`: `appsec-plugin:appsec-stride-analyzer`
- `description`: `STRIDE analysis for <COMPONENT_NAME>`
- `run_in_background`: `true`
- `prompt`: include COMPONENT_ID, COMPONENT_NAME, COMPONENT_DESCRIPTION, INTERFACES, TRUST_BOUNDARIES, CONTROLS, KNOWN_SECRETS, KNOWN_VULNS, KNOWN_LLM_PATTERNS, REPO_ROOT, OUTPUT_DIR, CONTEXT_FILE

**Dynamic turn budget:** Pass `MAX_TURNS=<N>` in the prompt:
- Simple components (static assets, simple CRUD, no auth logic): `MAX_TURNS=15`
- Moderate components (standard API, single-concern service): `MAX_TURNS=22`
- Complex components (auth service, payment, multi-integration): `MAX_TURNS=31`

Dispatch all simultaneously with `run_in_background: true`. Then poll for output files.

### Validation & Retry

Validate each `$OUTPUT_DIR/.stride-<id>.json`. On failure: retry once synchronously, skip if still invalid.

### Merge

1. Merge all threat lists + Phase 8b threat candidates (if requirements enabled)
2. Assign global IDs: T-001, T-002, … (by risk descending)
3. Deduplicate same root cause across components
4. Cross-reference prior findings from `$OUTPUT_DIR/.threat-modeling-context.md`
5. Known threats integration (open → verify, accepted → Section 11, mitigated → verify, false-positive → skip)

### Coverage Checks

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

Each threat row in the Threat Register table **should** include a CWE reference in the Threat Scenario cell. Append the CWE ID at the end of the scenario text in parentheses, e.g.: `... allowing full database extraction. (CWE-89)`. Use the most specific applicable CWE. If no CWE applies, omit.

### Requirements Integration in Sections 9 and 10

**When `CHECK_REQUIREMENTS=true` and requirement metadata is available from Phase 8b:**

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

Assign M-NNN IDs. Merge mitigations when they produce the same physical change. Update threat records with mitigation_ids. When requirements are enabled, propagate requirement IDs from threat candidates to their mitigations for the **Fulfills Requirements** field.

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

### Top Findings

<For each Critical finding (max 5), one bullet point:>
- **[T-NNN — <Title>](#t-NNN):** <One sentence summary of risk and business impact>

### Recommended Priority Actions

<Top 5 mitigations by priority, ordered Critical→High:>
1. **[M-NNN — <Title>](#m-NNN)** (Effort: <level>) — <One sentence describing the fix>
2. ...

### Overall Security Rating

<🔴/🟡/🟢> **<Rating text>** — <One sentence justification from Section 2.x Security Architecture Assessment>

→ *Full details in [Threat Register](#8-threat-register) and [Mitigation Register](#10-mitigation-register).*
```

**Rules:**
- All T-NNN and M-NNN references must be clickable links to their anchors
- Keep the summary concise — max ~30 lines. Executives read this, not the full report
- The "Key Areas" column uses short phrases, not full sentences
- "Top Findings" lists only Critical threats; if fewer than 3 Critical, include the highest-risk High threats to reach 3-5 items
- "Recommended Priority Actions" lists mitigations ordered by Priority (Critical first), then by lowest Effort within the same priority level
- When requirements are enabled, add a line after the risk table: `**Requirements compliance:** <N> checked, <N> PASS, <N> FAIL — see [Section 7](#7-identified-security-controls) for details.`

## Phase 10: Secret & Dependency Scan Synthesis

**Step 1 — Hardcoded Secrets (always):** Read Section 7.12 and Section 8 from `$OUTPUT_DIR/.recon-summary.md`. Incorporate Critical/High secrets as threats (Information Disclosure / Spoofing). Use only file:line references and redacted snippets.

**Step 2 — SCA Results (only when `WITH_SCA=true`):** Poll for `$OUTPUT_DIR/.dep-scan.json`. Validate, retry once if invalid. Incorporate:
- `vulnerable_dependencies` → Tampering/Supply Chain threats (deduplicate against STRIDE analyzer findings that already used `KNOWN_VULNS`)

If `WITH_SCA` is not set: skip SCA incorporation entirely.
