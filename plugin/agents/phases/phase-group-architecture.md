# Phase Group: Architecture & Analysis (Phases 2–7)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 2: Architecture Modeling

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

## Phase 3: Security-Relevant Use Cases

Produce Mermaid `sequenceDiagram` for each security-critical flow:
- Input Validation, Frontend Security, Database Security
- Authentication flow, Authorization/access control
- Secret Management, OAuth/OIDC flow (if present), BFF token flow (if present)
- Additional security-critical flows specific to this system

Annotate arrows with actual HTTP methods/routes. Show failure paths.

## Phase 4: Asset Identification

Identify: Data assets (PII, credentials, financial), Code/IP assets, Infrastructure assets, Availability assets.

## Phase 5: Attack Surface Mapping

Enumerate all entry points. Run exposed route audit:
1. Discover all registered routes (framework-specific patterns)
2. Confirm auth middleware coverage
3. Check for accidentally exposed routes (actuator, debug, API docs, admin, metrics)
4. OAuth/OIDC callback and redirect_uri audit (if applicable)

## Phase 6: Trust Boundary Analysis

Identify trust level changes: External vs authenticated vs admin, public vs internal vs data tier, container boundaries, third-party integrations.

## Phase 7: Identified Security Controls

Actively search for each security domain using grep (do not rely on Phase 1 memory):
IAM, Authorization, Data Protection, Secret Management, Frontend Security, Output Encoding, Audit & Logging, Infrastructure & Network, Dependency & Supply Chain, Security Testing, OAuth/OIDC Implementation, SPA/BFF Architecture.

Rate each: ✅ Adequate | ⚠️ Partial | 🔶 Weak | ❌ Missing

## Phase 7b: Requirements Compliance (conditional)

**Only when `CHECK_REQUIREMENTS=true`.** Read `.requirements.yaml`, verify each requirement via Grep+Read, assign PASS/PARTIAL/FAIL/UNVERIFIABLE. Generate threat candidates from FAILs for Phase 8.
