# Phase Group: Reconnaissance & Context (Phases 1–2)

This file is read by the orchestrator at runtime to load phase instructions.

## Phases 1 + 2: Parallel Dispatch (since M2.7)

Phase 1 (context-resolver) reads external policy and prior findings. Phase 2 (recon-scanner) analyzes the codebase. They have **zero data dependencies** — no output of Phase 1 feeds into Phase 2, and vice versa. Dispatching them in parallel saves ~60 s of wall-clock time on a typical run.

**Execution protocol:**

1. **Before dispatch:** resolve the recon fingerprint skip (see below) to decide whether recon needs to run at all.
2. **Resolve the context cache hit** (see `appsec-threat-analyst.md` → Phase 1 Step B staleness check) to decide whether the context-resolver needs to run.
3. **Dispatch both in a single orchestrator turn** using two Agent tool calls. Each call that is needed gets `run_in_background: true` (or `false` if only one is dispatched — the idle one can skip). If both are skipped (cache hits on both), jump directly to Phase 3.
4. **Wait for both to complete** before proceeding to Phase 3. Read both output files and store their contents.

**Error handling:** If the context-resolver aborts (requirements unavailable + `CHECK_REQUIREMENTS=true`), halt the assessment regardless of whether recon succeeded. If the recon-scanner fails but the context-resolver succeeded, fall back to minimal inline scan (same as before).

### Phase 1: Context Resolution

**⚠ Staleness check first** — see `appsec-threat-analyst.md` → Phase 1 Step B for the `CTX_SKIP` logic. If `CTX_SKIP=true`, do not dispatch. Otherwise:

**→ TOOL CALL REQUIRED (dispatch as part of the parallel batch):**
- `subagent_type`: `appsec-plugin:appsec-context-resolver`
- `description`: `Resolve context for threat model`
- `run_in_background`: `true` (parallel with recon — unless recon is skipped, then `false` is fine)
- `prompt`: `REPO_ROOT=<absolute repo path>`, `OUTPUT_DIR=<absolute output path>`, `CHECK_REQUIREMENTS=<true|false>`, and `REQUIREMENTS_URL_OVERRIDE=<url>` (only if set)

Log `AGENT_INVOKE` before dispatch. After the agent returns (or cache hit): read `$OUTPUT_DIR/.threat-modeling-context.md` and store team, asset tier, compliance scope, prior findings, known threats, known exceptions, architecture notes, and business context for use throughout the assessment.

**If `CHECK_REQUIREMENTS=true` and `$OUTPUT_DIR/.threat-modeling-context.md` does not exist**, the context-resolver aborted because requirements were unavailable. Print the error and stop the assessment.

### Phase 2: Reconnaissance

### Incremental fingerprint skip (resolve BEFORE the parallel dispatch)

Before dispatching the recon-scanner, check whether Phase 2 can be skipped entirely. Phase 2 is the single most expensive phase in the orchestrator (25 turns + 24 grep categories), so skipping it when nothing security-relevant has changed is the biggest token-saving lever in incremental mode.

**Skip condition** — all three must be true:

1. `INCREMENTAL=true`
2. `$OUTPUT_DIR/.recon-summary.md` exists from the previous run
3. `baseline_state.py check-fingerprint` exits 0 (recon fingerprint unchanged)

```bash
if [ "$INCREMENTAL" = "true" ] && [ -f "$OUTPUT_DIR/.recon-summary.md" ]; then
  if python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" check-fingerprint \
       --output-dir "$OUTPUT_DIR" --repo-root "$REPO_ROOT" 2>&1; then
    RECON_SKIP="true"
  else
    RECON_SKIP="false"
  fi
else
  RECON_SKIP="false"
fi
```

**If `RECON_SKIP=true`:**

1. Log and print: `[Phase 2/11] ⟳ Recon cached — fingerprint unchanged since previous run, reusing .recon-summary.md`
2. Read the existing `.recon-summary.md` directly (skip Step 1 below).
3. Still run Step 2 (dep-scanner dispatch) if `WITH_SCA=true` — the dep-scanner has its own cache and will fast-path if manifests are unchanged.
4. Jump to Phase 3 (or wait for Phase 1 to complete if it is still running in background).

**If `RECON_SKIP=false`:**

1. Run Step 1 (recon-scanner dispatch) as part of the parallel batch.
2. After the recon-scanner returns, the updated fingerprint will be written to `.appsec-cache/baseline.json` during Phase 11 — no action needed here.

**Conservative fingerprinting rule:** `baseline_state.py` uses a whitelist of known manifest/Dockerfile/IaC file types. If a new unknown file type shows up that might carry security-relevant changes (e.g. a novel IaC format), the fingerprint check will still say "unchanged" for that file — which is unsafe. Mitigation: when in doubt about coverage, force a full scan with `--full`. The fingerprint is a best-effort optimization, not a correctness guarantee.

### Step 1 — Dispatch recon-scanner (parallel with Phase 1):

Log `AGENT_INVOKE` before dispatch. Log `AGENT_DONE` after the agent returns.

**→ TOOL CALL REQUIRED (dispatch as part of the parallel batch):**
- `subagent_type`: `appsec-plugin:appsec-recon-scanner`
- `description`: `Reconnaissance scan`
- `run_in_background`: `true` (parallel with context-resolver — unless context is skipped, then `false` is fine)
- `prompt`: `REPO_ROOT=<absolute repo path>` and `OUTPUT_DIR=<absolute output path>`

After both Phase 1 and Phase 2 have returned, read `$OUTPUT_DIR/.recon-summary.md`. Store contents for Phases 3–11:
- **Manifest list** (Section 3) → needed for dep-scanner dispatch
- **Preliminary components** (Section 9) → starting point for Phase 3
- **Security findings** (Section 7) → used in Phases 4, 6, 7, 8, 9
- **Business context** (Section 1) → System Overview and Asset Identification

If `.recon-summary.md` is missing, fall back to minimal inline scan.

### Step 2 — Dispatch dep-scanner (background, only when `WITH_SCA=true`):

**Skip this step if `WITH_SCA` is not set or `false`.** SCA is optional — hardcoded secrets are already covered by the recon-scanner (category 12), insecure defaults by Phase 8.

**If `WITH_SCA=true`:**

Log `AGENT_DISPATCH` (not `PHASE_START`) before the dispatch.

**Pre-compute manifest hashes (mandatory):** Before dispatching the dep-scanner, compute an 8-char md5 hash for each manifest file in a single Bash call. Batch this with the `AGENT_DISPATCH` log echo for zero extra turns:

```bash
(cd "$REPO_ROOT" && md5sum $MANIFESTS 2>/dev/null | awk '{printf "%s:%s\n", $2, substr($1,1,8)}')
```

Capture the output as a comma-separated `path:hash,path:hash,…` map and pass it to the dep-scanner as `MANIFEST_HASHES`. This saves the dep-scanner one turn on cache validation.

**→ TOOL CALL REQUIRED:** Use the Agent tool now:
- `subagent_type`: `appsec-plugin:appsec-dep-scanner`
- `description`: `SCA dependency scan`
- `run_in_background`: `true`
- `prompt`: include `REPO_ROOT=<absolute repo path>`, `OUTPUT_DIR=<absolute output path>`, `MANIFESTS=<comma-separated list>`, and `MANIFEST_HASHES=<path:hash,…>`

Do **not** wait — continue through Phases 3–8. Phase 10 will read the result.
