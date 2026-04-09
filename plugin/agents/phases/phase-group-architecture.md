# Phase Group: Architecture & Analysis (Phases 3–8)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 3: Architecture Modeling

### Section introductory sentences (mandatory for all sections)

Every top-level section (`## N. Title`) in the final `threat-model.md` **must** open with one or two sentences that explain **what** this section contains and **why** it matters for the security assessment. Write the intro before the first subsection heading, table, or diagram. Keep it concise (1-3 sentences). Examples:

- **Section 2 (Architecture Diagrams):** "The following diagrams model the system architecture at different abstraction levels using the C4 model. Security-relevant aspects are highlighted in red."
- **Section 3 (Security-Relevant Use Cases):** "These sequence diagrams document security-critical flows, showing both normal operation and potential attack vectors."
- **Section 4 (Assets):** "The table below identifies all assets requiring protection, classified by sensitivity, with cross-references to the threats that target them."
- **Section 5 (Attack Surface):** "All identified entry points through which an attacker can interact with the system, including protocol, authentication requirements, and linked threats."
- **Section 6 (Trust Boundaries):** "Trust boundaries mark transitions between different trust levels. Weaknesses at these boundaries are primary sources of security risk."
- **Section 7 (Identified Security Controls):** Start with a brief **critical gaps summary** paragraph before the controls table.
- **Section 8 (Threat Register):** Start with risk methodology note and Risk Distribution block (see Phase 9).
- **Section 9 (Critical Findings):** "The following findings require immediate attention due to their critical risk rating. Each finding links to its recommended mitigation in the [Mitigation Register](#10-mitigation-register)."
- **Section 10 (Mitigation Register):** "Prioritized measures to address identified threats. Each mitigation references the threats it addresses and includes concrete implementation guidance."
- **Section 11 (Out of Scope):** "Areas deliberately excluded from this assessment, including accepted risks and items requiring separate analysis."

Adapt the wording to the specific system — do not use the examples verbatim.

### Architecture modeling

Derive the system's architecture from code and config. Determine complexity:

- **Simple** (monolith, single service): one architecture diagram
- **Moderate** (multiple services, clear layers): Context + Container diagrams
- **Complex** (microservices, many bounded contexts): Context + Container + Component diagrams

**DIAGRAM_DEPTH override:** The `DIAGRAM_DEPTH` variable (from `--assessment-depth`) can restrict diagram output regardless of detected complexity:

| DIAGRAM_DEPTH | C4 diagrams produced | Use case diagrams (Phase 4) |
|---------------|---------------------|-----------------------------|
| `minimal` | Context + Technology Architecture only (skip Containers/Components even if Complex) | Top 3 only: Authentication, Authorization, Input Validation |
| `standard` | By detected complexity tier (default behavior) | All applicable flows |
| `extended` | By detected complexity tier + additional drill-down for security-critical services | All applicable flows + explicit failure-path alt/else blocks for each |

Section numbering by complexity tier (no gaps):

| Complexity | Sections | Numbers |
|------------|----------|---------|
| Simple | Context · Tech Arch · Security Assessment | 2.1 · 2.2 · 2.3 |
| Moderate | Context · Containers · Tech Arch · Assessment | 2.1 · 2.2 · 2.3 · 2.4 |
| Complex | Context · Containers · Components · Tech Arch · Assessment | 2.1 · 2.2 · 2.3 · 2.4 · 2.5 |

Use C4 model conventions. Every node must include concrete technology details:
```
"<Component Name>\n<Framework + Version>\n<Runtime / Language>\n<Deployment: platform/env>"
```

All diagrams: Mermaid `graph TD`, max 4–5 nodes per subgraph, edges with protocol/route labels, trust boundaries as subgraphs with emoji labels.

Write Security Architecture Assessment last: Architecture Patterns table, Trust Model Evaluation, Auth & Authz Architecture, Key Architectural Risks, Overall Rating.

## Phase 4: Security-Relevant Use Cases

Produce Mermaid `sequenceDiagram` for each security-critical flow:
- Input Validation, Frontend Security, Database Security
- Authentication flow, Authorization/access control
- Secret Management, OAuth/OIDC flow (if present), BFF token flow (if present)
- Additional security-critical flows specific to this system

Annotate arrows with actual HTTP methods/routes. Show failure paths.

## Phase 5: Asset Identification

Identify: Data assets (PII, credentials, financial), Code/IP assets, Infrastructure assets, Availability assets.

## Phase 6: Attack Surface Mapping

Enumerate all entry points. Run exposed route audit:
1. Discover all registered routes (framework-specific patterns)
2. Confirm auth middleware coverage
3. Check for accidentally exposed routes (actuator, debug, API docs, admin, metrics)
4. OAuth/OIDC callback and redirect_uri audit (if applicable)

## Phase 7: Trust Boundary Analysis

Identify trust level changes: External vs authenticated vs admin, public vs internal vs data tier, container boundaries, third-party integrations.

**Mandatory browser↔server boundary:** If a frontend SPA or client-side application is present, the browser↔server boundary MUST be explicitly identified as a primary trust boundary. The browser is an untrusted execution environment — all data originating from the client (URL parameters, form data, localStorage, postMessage, WebSocket messages) must be treated as attacker-controlled. This boundary shapes STRIDE analysis for the frontend component in Phase 9.

## Phase 8: Identified Security Controls

**⚠ Token-saving rule: Reuse Phase 2 findings — do NOT re-grep what the recon-scanner already found.**

Read Section 7 of `$OUTPUT_DIR/.recon-summary.md`. The recon-scanner has already scanned 24 security categories with file:line references and observations. **Use these findings directly as your baseline** for each domain's effectiveness rating:

**When `DIAGRAM_DEPTH=minimal` (quick mode):** Use recon-summary findings as-is for all domains. Do NOT run any active greps — rate controls purely from the recon baseline. This saves 5-10 turns. Mark the Section 7 heading with `<!-- Controls rated from recon baseline only (quick mode) -->`.

**Otherwise (standard/extended):**

1. For each domain below, find the matching recon-summary subsection (7.1–7.24)
2. If the recon summary provides file references and observations → **use them as-is** to rate the control. Do NOT re-grep these patterns.
3. **Only run active greps** when:
   - The recon summary says "No matches found" for a domain (confirm the ❌ Missing rating)
   - You need to check a specific sub-aspect not covered by the recon patterns (e.g., OAuth PKCE enforcement details)
   - The recon summary is ambiguous and you need one targeted grep to disambiguate ⚠️ Partial vs ✅ Adequate

Domains: IAM, Authorization, Data Protection, Secret Management, Frontend Security (framework config, sanitizer usage, DOM sink exposure — use recon 7.8, 7.19), Output Encoding, CSP (Content-Security-Policy presence and restrictiveness — use recon 7.18; rate ❌ if no CSP header found), CORS (origin allowlist and credential handling — use recon 7.18; rate ❌ if `Access-Control-Allow-Origin: *` with credentials), Audit & Logging, Infrastructure & Network, Dependency & Supply Chain, Security Testing, OAuth/OIDC Implementation, SPA/BFF Architecture (token storage, cookie flags, auth guards — use recon 7.10, 7.24).

Rate each: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

**Linked Threats column:** The controls table MUST include a "Linked Threats" column. For controls rated ⚠️ Partial, 🔶 Weak, or ❌ Missing, reference the T-NNN IDs of threats exploiting that control gap as clickable links (`[T-NNN](#t-NNN)`). For ✅ Adequate controls, use `—`.

### Dependency & Supply Chain — sub-controls

This domain requires checking **all** of the following sub-controls. Use recon-summary sections 7.14–7.17 as baseline (same token-saving rule as other domains).

| Sub-control | ✅ Adequate | ⚠️ Partial | ❌ Missing |
|-------------|-----------|------------|-----------|
| **CVE scanning** | SCA tool in CI (`npm audit`, `pip-audit`, Snyk, etc.) with blocking on Critical/High | SCA runs but only advisory / not blocking | No SCA in CI or manifests |
| **Lockfile pinning** | Lockfile present, committed, and CI validates integrity (`npm ci` / `pip install --require-hashes`) | Lockfile present but no integrity validation in CI | No lockfile or lockfile in `.gitignore` |
| **CI/CD action pinning** | All GitHub Actions / GitLab images pinned to commit SHA or digest | Mix of SHA-pinned and tag-only references | Actions pinned to mutable tags (`@v3`, `@latest`) or no pinning |
| **Container image hygiene** | Base images pinned to digest (`@sha256:`), official/verified images, no `latest` | Images pinned to version tags but no digest | `FROM <image>:latest` or no tag |
| **Dependency confusion** | Private registry configured, scoped packages (`@org/`), no dual-source `--extra-index-url` | Partial scoping or private registry for some ecosystems | Unscoped internal package names without private registry |
| **Postinstall scripts** | No install hooks, or hooks are audited and `ignore-scripts` configured where appropriate | Install hooks present but limited to build tasks (compilation) | Hooks run network requests or arbitrary commands without audit |

**Overall domain rating:** Derive from the sub-control ratings. If any sub-control is ❌, the domain is at most 🔶 Weak. If all are ✅, rate ✅ Adequate.

## Phase 8b: Requirements Compliance (conditional)

**Only when `CHECK_REQUIREMENTS=true`.** Read `.requirements.yaml`, verify each requirement via Grep+Read, assign PASS/PARTIAL/FAIL/UNVERIFIABLE. Generate threat candidates from FAILs for Phase 9.

### Priority-aware risk escalation

The requirement's `priority` field directly influences the risk rating of the generated threat candidate:

| Requirement priority | FAIL → minimum risk | PARTIAL → minimum risk | Rationale |
|---------------------|--------------------|-----------------------|-----------|
| `MUST` | High | Medium | Mandatory requirements — violation is a policy breach |
| `SHOULD` | Medium | Low | Recommended — violation is a gap, not a breach |
| `MAY` | Low | Low | Optional — informational only |

When computing the final risk for a requirement-sourced threat, use the higher of: (a) the priority-derived minimum from the table above, or (b) the risk derived from the standard Likelihood × Impact matrix. This ensures that a violated `MUST` requirement never appears as Low risk, even if exploitation seems unlikely.

### Architectural requirements — elevated handling

Some requirements represent **architectural decisions** rather than implementation details. Violating these has systemic impact — it means the system is built on a fundamentally weaker foundation, not just missing a control.

**Detection:** A requirement is architectural if any of the following apply:
- It mandates a specific architectural pattern (BFF, standard auth service, SSO, API gateway)
- It mandates using a standard/centralized service instead of a custom implementation
- It appears in a blueprint section whose title contains "architecture", "pattern", or "blueprint"
- Its `text` contains terms like "standard", "centralized", "approved", "must use" followed by a service or pattern name

**Examples from the baseline:**
- `SSLM-AUTN`: "Only use one of the standardized KN authentication services for SSO" — architectural (mandates standard auth)
- `SEC-USER-AUTH`: "Users MUST be authenticated using standard KN authentication mechanisms with mandatory MFA" — architectural (standard auth + MFA)
- `SEC-API-AUTH`: "APIs must mutually authenticate using a secure and standard mechanism" — architectural (standard API auth)
- BFF blueprint pattern: "Implement a Backend-for-Frontend (BFF) for user-context API access in your SPA" — architectural (mandates BFF for SPAs)

**When an architectural requirement is violated:**
1. Set `architectural_violation: true` in the threat candidate metadata
2. Escalate the risk by one level (Medium → High, High → Critical) — architectural violations have cascading impact
3. The scenario text must explain **why** this is architectural: what systemic risk the custom/missing pattern creates (e.g., "Custom auth implementation instead of standard SSO increases attack surface and loses centralized security controls")
4. These violations are surfaced prominently in the management summary (see below)

### Architectural anti-pattern detection

Beyond explicit requirements, Phase 8b should check for common architectural anti-patterns when a relevant blueprint exists in `.requirements.yaml`. These are checked regardless of whether a matching requirement exists:

| Anti-pattern | Detection signal | Why it matters |
|-------------|-----------------|---------------|
| **SPA without BFF** | Frontend framework detected (recon 7.19) + tokens in localStorage (recon 7.10) + no BFF proxy pattern (recon 7.10 shows no `bff` or `backend.for.frontend` match) | Tokens exposed to XSS in browser; no server-side session control |
| **Custom auth instead of standard SSO** | Auth mechanism is custom JWT/session (recon 7.1) + no SSO/OIDC provider detected (recon 7.9 shows no OIDC issuer, `/.well-known/`, or known SSO SDK) | Loses centralized auth management, audit trail, MFA enforcement |
| **Direct database access from frontend** | API routes that proxy raw SQL or expose ORM queries directly to client-controlled parameters without an intermediate service layer | No separation of concerns; SQL injection risk multiplied |
| **Secrets in environment variables without vault** | Secrets loaded from env vars (recon 7.6) + no vault/secrets-manager integration detected | No rotation, no access audit, no encryption at rest |

For each detected anti-pattern:
1. Generate a threat candidate with `source: "architectural-anti-pattern"`, `architectural_violation: true`
2. Set minimum risk to High (these are systemic)
3. If a matching blueprint section exists, set `remediation.blueprint` to the relevant blueprint URL
4. Add to the Section 7b table with status `❌ ANTI-PATTERN` (distinct from FAIL — indicates missing architectural pattern, not a specific requirement violation)

### Requirement metadata for Phase 9 integration

For each FAIL, PARTIAL, or ANTI-PATTERN requirement, emit a **threat candidate** that carries requirement metadata:

- `source`: `"requirements-compliance"` or `"architectural-anti-pattern"`
- `requirement_id`: the requirement's ID (e.g. `"SEC-AUTH-1"`) — for anti-patterns, use the closest matching requirement ID or `ARCH-<slug>` if no requirement matches
- `requirement_url`: the requirement's `url` from the YAML (may be null)
- `requirement_priority`: `MUST` / `SHOULD` / `MAY` (from YAML)
- `architectural_violation`: `true` / `false`
- `stride`: inferred STRIDE category
- `scenario`: derived from the FAIL evidence
- `component`: component where violation was found

This metadata is consumed by Phase 9 (Merge) to populate **Violated Requirements** fields in Sections 8, 9 and **Fulfills Requirements** fields in Section 10.

### Section 7b output format

When `CHECK_REQUIREMENTS=true`, write a **Section 7b — Requirements Compliance** in `threat-model.md` directly after Section 7. Add `- [7b. Requirements Compliance](#7b-requirements-compliance)` to the Table of Contents (after Section 7).

```markdown
## 7b. Requirements Compliance

This section summarizes the compliance status of each requirement from the [<requirements source name>](<url>) baseline. Requirements marked ❌ FAIL or ❌ ANTI-PATTERN have generated threat entries in the [Threat Register](#8-threat-register).

### Architectural Violations

<ONLY when architectural violations or anti-patterns were detected. Omit if none.>

These findings represent **systemic architectural gaps** — missing patterns or standard services that have cascading security impact beyond individual controls.

| Violation | Priority | Evidence | Risk | Linked Threats |
|-----------|----------|----------|------|----------------|
| [<ID>](<url>) — <title> | MUST | <what's missing and why it's architectural> | <High/Critical> | [T-NNN](#t-NNN) |

### Full Compliance Table

| Requirement | Priority | Title | Status | Evidence | Linked Threats |
|-------------|----------|-------|--------|----------|----------------|
| [<ID>](<url>) | MUST | <title> | ❌ ANTI-PATTERN | <architectural pattern missing> | [T-NNN](#t-NNN) |
| [<ID>](<url>) | MUST | <title> | ❌ FAIL | <brief evidence of violation> | [T-NNN](#t-NNN) |
| [<ID>](<url>) | SHOULD | <title> | ⚠️ PARTIAL | <what's present, what's missing> | [T-NNN](#t-NNN) |
| [<ID>](<url>) | MUST | <title> | ✅ PASS | <brief evidence of compliance> | — |

**Summary:** <N> requirements checked — ✅ <N> PASS · ❌ <N> FAIL · ❌ <N> ANTI-PATTERN · ⚠️ <N> PARTIAL
```

**Rules:**
- Order rows by: ❌ ANTI-PATTERN first, then ❌ FAIL, then ⚠️ PARTIAL, then ✅ PASS. Within each status group, order by priority: MUST first, then SHOULD, then MAY
- The "Priority" column shows the requirement's priority from the YAML
- The "Linked Threats" column links to threats generated from FAIL/PARTIAL/ANTI-PATTERN requirements in Phase 9
- Each requirement ID is a clickable link using the `url` from the requirements YAML. If no URL, render as plain text
- The "Evidence" column is brief (one line) — cite the file:line or config that proves compliance or violation
- The "Architectural Violations" subsection provides executive visibility into systemic gaps — keep each row to 1-2 sentences
