# Phase Group: Reconnaissance & Context (Phases 0–1)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 0: Context Resolution

Invoke the `appsec-plugin:appsec-context-resolver` agent immediately.

**→ TOOL CALL REQUIRED:** Use the Agent tool now:
- `subagent_type`: `appsec-plugin:appsec-context-resolver`
- `description`: `Resolve context for threat model`
- `prompt`: `REPO_ROOT=<absolute repo path>` and `CHECK_REQUIREMENTS=<true|false>`

Wait for the agent to complete. **If `CHECK_REQUIREMENTS=true` and `docs/security/.threat-modeling-context.md` does not exist**, the context-resolver aborted because requirements were unavailable. Print the error and stop the assessment.

Otherwise, read `docs/security/.threat-modeling-context.md` and store team, asset tier, compliance scope, prior findings, known threats, known exceptions, architecture notes, and business context for use throughout the assessment.

## Phase 1: Reconnaissance

**Step 1 — Dispatch recon-scanner (synchronous):**

**Log the dispatch** (AGENT_INVOKE) before invoking, and **log the return** (AGENT_DONE) after:
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   threat-analyst  AGENT_INVOKE   appsec-recon-scanner  Reconnaissance scan" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null
```

**→ TOOL CALL REQUIRED:** Use the Agent tool now:
- `subagent_type`: `appsec-plugin:appsec-recon-scanner`
- `description`: `Reconnaissance scan`
- `run_in_background`: `false`
- `prompt`: `REPO_ROOT=<absolute repo path>`

After completion, log:
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   threat-analyst  AGENT_DONE   appsec-recon-scanner  Recon complete" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null
```

Read `docs/security/.recon-summary.md`. Store contents for Phases 2–10:
- **Manifest list** (Section 3) → needed for dep-scanner dispatch
- **Preliminary components** (Section 9) → starting point for Phase 2
- **Security findings** (Section 7) → used in Phases 3, 5, 6, 7, 8
- **Business context** (Section 1) → System Overview and Asset Identification

If `.recon-summary.md` is missing, fall back to minimal inline scan.

**Step 2 — Dispatch dep-scanner (background, only when `WITH_SCA=true`):**

**Skip this step if `WITH_SCA` is not set or `false`.** SCA is optional — hardcoded secrets are already covered by the recon-scanner (category 12), insecure defaults by Phase 7.

**If `WITH_SCA=true`:**

**Log the background dispatch** (use `AGENT_DISPATCH`, **not** `PHASE_START`):
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   threat-analyst  AGENT_DISPATCH   appsec-dep-scanner  SCA dependency scan (background, model: <dep-scanner model>)" >> "$REPO_ROOT/docs/security/.agent-run.log" 2>/dev/null
```

**→ TOOL CALL REQUIRED:** Use the Agent tool now:
- `subagent_type`: `appsec-plugin:appsec-dep-scanner`
- `description`: `SCA dependency scan`
- `run_in_background`: `true`
- `prompt`: include `REPO_ROOT=<absolute repo path>` and `MANIFESTS=<comma-separated list>`

Do **not** wait — continue through Phases 2–7. Phase 9 will read the result.
