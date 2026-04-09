# Phase Group: Reconnaissance & Context (Phases 1–2)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 1: Context Resolution

Invoke the `appsec-plugin:appsec-context-resolver` agent immediately.

**→ TOOL CALL REQUIRED:** Use the Agent tool now:
- `subagent_type`: `appsec-plugin:appsec-context-resolver`
- `description`: `Resolve context for threat model`
- `prompt`: `REPO_ROOT=<absolute repo path>`, `OUTPUT_DIR=<absolute output path>`, `CHECK_REQUIREMENTS=<true|false>`, and `REQUIREMENTS_URL_OVERRIDE=<url>` (only if set)

Wait for the agent to complete. **If `CHECK_REQUIREMENTS=true` and `$OUTPUT_DIR/.threat-modeling-context.md` does not exist**, the context-resolver aborted because requirements were unavailable. Print the error and stop the assessment.

Otherwise, read `$OUTPUT_DIR/.threat-modeling-context.md` and store team, asset tier, compliance scope, prior findings, known threats, known exceptions, architecture notes, and business context for use throughout the assessment.

## Phase 2: Reconnaissance

**Step 1 — Dispatch recon-scanner (synchronous):**

Log `AGENT_INVOKE` before and `AGENT_DONE` after the dispatch.

**→ TOOL CALL REQUIRED:** Use the Agent tool now:
- `subagent_type`: `appsec-plugin:appsec-recon-scanner`
- `description`: `Reconnaissance scan`
- `run_in_background`: `false`
- `prompt`: `REPO_ROOT=<absolute repo path>` and `OUTPUT_DIR=<absolute output path>`

Read `$OUTPUT_DIR/.recon-summary.md`. Store contents for Phases 3–11:
- **Manifest list** (Section 3) → needed for dep-scanner dispatch
- **Preliminary components** (Section 9) → starting point for Phase 3
- **Security findings** (Section 7) → used in Phases 4, 6, 7, 8, 9
- **Business context** (Section 1) → System Overview and Asset Identification

If `.recon-summary.md` is missing, fall back to minimal inline scan.

**Step 2 — Dispatch dep-scanner (background, only when `WITH_SCA=true`):**

**Skip this step if `WITH_SCA` is not set or `false`.** SCA is optional — hardcoded secrets are already covered by the recon-scanner (category 12), insecure defaults by Phase 8.

**If `WITH_SCA=true`:**

Log `AGENT_DISPATCH` (not `PHASE_START`) before the dispatch.

**→ TOOL CALL REQUIRED:** Use the Agent tool now:
- `subagent_type`: `appsec-plugin:appsec-dep-scanner`
- `description`: `SCA dependency scan`
- `run_in_background`: `true`
- `prompt`: include `REPO_ROOT=<absolute repo path>`, `OUTPUT_DIR=<absolute output path>`, and `MANIFESTS=<comma-separated list>`

Do **not** wait — continue through Phases 3–8. Phase 10 will read the result.
