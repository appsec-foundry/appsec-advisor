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

## Phase 8: Identified Security Controls

Actively search for each security domain using grep (do not rely on Phase 2 memory):
IAM, Authorization, Data Protection, Secret Management, Frontend Security, Output Encoding, Audit & Logging, Infrastructure & Network, Dependency & Supply Chain, Security Testing, OAuth/OIDC Implementation, SPA/BFF Architecture.

Rate each: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

## Phase 8b: Requirements Compliance (conditional)

**Only when `CHECK_REQUIREMENTS=true`.** Read `.requirements.yaml`, verify each requirement via Grep+Read, assign PASS/PARTIAL/FAIL/UNVERIFIABLE. Generate threat candidates from FAILs for Phase 9.

### Requirement metadata for Phase 9 integration

For each FAIL or PARTIAL requirement, emit a **threat candidate** that carries requirement metadata. Use the same singular format as the orchestrator's Phase 8b:

- `source`: `"requirements-compliance"`
- `requirement_id`: the requirement's ID (e.g. `"SEC-AUTH-1"`)
- `requirement_url`: the requirement's `url` from the YAML (may be null)
- `stride`: inferred STRIDE category
- `scenario`: derived from the FAIL evidence
- `component`: component where violation was found

This metadata is consumed by Phase 9 (Merge) to populate **Violated Requirements** fields in Section 9 and **Fulfills Requirements** fields in Section 10.
