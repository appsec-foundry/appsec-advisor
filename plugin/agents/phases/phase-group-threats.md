# Phase Group: Threat Enumeration & Synthesis (Phases 8–9)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 8: STRIDE Threat Enumeration — via sub-agents

**⚠ SEQUENCING: STRIDE analyzers MUST NOT be dispatched before Phase 8.** They require outputs from Phases 5 (INTERFACES), 6 (TRUST_BOUNDARIES), and 7 (CONTROLS).

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

1. Merge all threat lists + Phase 7b threat candidates (if requirements enabled)
2. Assign global IDs: T-001, T-002, … (by risk descending)
3. Deduplicate same root cause across components
4. Cross-reference prior findings from `$OUTPUT_DIR/.threat-modeling-context.md`
5. Known threats integration (open → verify, accepted → Section 11, mitigated → verify, false-positive → skip)

### Coverage Checks

**A — OWASP Top 10:** Verify at least one threat per OWASP 2021 category. Add gap threats for missing.

**B — Business logic:** Check workflow bypass, privilege abuse, mass enumeration, economic abuse, state manipulation.

**C — OWASP LLM Top 10 (conditional):** If AI/LLM integration was detected in recon (Section 7.13), verify coverage for each applicable LLM threat category. Add gap threats for missing. Skip if no LLM detected.

### Build Mitigation Register

Assign M-NNN IDs. Merge mitigations when they produce the same physical change. Update threat records with mitigation_ids.

## Phase 9: Secret & Dependency Scan Synthesis

**Step 1 — Hardcoded Secrets (always):** Read Section 7.12 and Section 8 from `$OUTPUT_DIR/.recon-summary.md`. Incorporate Critical/High secrets as threats (Information Disclosure / Spoofing). Use only file:line references and redacted snippets.

**Step 2 — SCA Results (only when `WITH_SCA=true`):** Poll for `$OUTPUT_DIR/.dep-scan.json`. Validate, retry once if invalid. Incorporate:
- `vulnerable_dependencies` → Tampering/Supply Chain threats (deduplicate against STRIDE analyzer findings that already used `KNOWN_VULNS`)

If `WITH_SCA` is not set: skip SCA incorporation entirely.
