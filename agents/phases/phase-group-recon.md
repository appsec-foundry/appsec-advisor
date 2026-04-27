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
- `subagent_type`: `appsec-advisor:appsec-context-resolver`
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

### Step 0 — Deterministic pattern pre-pass (M3.1)

Run `scripts/recon_patterns.py all` **before** dispatching the recon-scanner agent. The script handles Categories 11 (Exposed Routes), 14 (CI/CD Supply Chain), 17 (Postinstall Scripts), and 18 (Security Headers/CORS) deterministically — pattern matching with no LLM judgement. Running it from the orchestrator (not from inside the agent) guarantees it always runs, eliminating the regression where the LLM agent sometimes skips it under turn pressure (observed 2026-04-26: 415 s recon vs 240 s spec).

```bash
if [ "$RECON_SKIP" = "false" ]; then
  if [ "${SCAN_MANIFEST:-false}" = "true" ]; then
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/recon_patterns.py" all \
      --repo-root "$REPO_ROOT" \
      --manifest-file "$OUTPUT_DIR/.scan-manifest.txt" \
      > "$OUTPUT_DIR/.recon-patterns.json" 2>/dev/null
  else
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/recon_patterns.py" all \
      --repo-root "$REPO_ROOT" \
      > "$OUTPUT_DIR/.recon-patterns.json" 2>/dev/null
  fi
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   recon-scanner  STEP_END   Deterministic pre-pass (Categories 11/14/17/18) → .recon-patterns.json" >> "$OUTPUT_DIR/.agent-run.log"
fi
```

The recon-scanner agent will see `.recon-patterns.json` already on disk and consume it (its prompt skips LLM grep for those four categories). On script failure (e.g. data file missing) the agent falls back to LLM grep — same as before, just slower.

### Step 0b — Deterministic data-relations extraction (M21)

Run `scripts/extract_data_relations.py` immediately after Step 0a, in the same Bash batch. The script discovers ORM models (Sequelize, Mongoose, TypeORM, Prisma) and the routes that consume them; the result is one JSON file the data-persistence STRIDE analyzer reads as its FOCUS_PATHS source instead of re-discovering from scratch (data-layer historically takes 170 s mean across 8 Juice-Shop runs — multi-hop reasoning across model + route + raw-query is the bottleneck).

```bash
if [ "$RECON_SKIP" = "false" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/extract_data_relations.py" \
      "$REPO_ROOT" --quiet 2>/dev/null || true
  # Output: $OUTPUT_DIR/.fragments/data-relations.json
fi
```

Best-effort: failure (no ORM detected, parse error, etc.) is non-fatal — the data-layer STRIDE analyzer falls back to its existing Grep-driven discovery.

### Step 1 — Dispatch recon-scanner (parallel with Phase 1):

Log `AGENT_INVOKE` before dispatch. Log `AGENT_DONE` after the agent returns.

**→ TOOL CALL REQUIRED (dispatch as part of the parallel batch):**
- `subagent_type`: `appsec-advisor:appsec-recon-scanner`
- `description`: `Reconnaissance scan`
- `run_in_background`: `true` (parallel with context-resolver — unless context is skipped, then `false` is fine)
- `prompt`: `REPO_ROOT=<absolute repo path>` and `OUTPUT_DIR=<absolute output path>` and `SCAN_MANIFEST=<value of SCAN_MANIFEST variable — true or false>`

After both Phase 1 and Phase 2 have returned, read `$OUTPUT_DIR/.recon-summary.md`. Store contents for Phases 3–11:
- **Manifest list** (Section 3) → needed for dep-scanner dispatch
- **Preliminary components** (Section 9) → starting point for Phase 3
- **Security findings** (Section 7) → used in Phases 4, 6, 7, 8, 9
- **Business context** (Section 1) → System Overview and Asset Identification

If `.recon-summary.md` is missing, fall back to minimal inline scan.

### Step 2 — Launch dep-scan in background (only when `WITH_SCA=true`):

**Skip this step if `WITH_SCA` is not set or `false`.** SCA is optional — hardcoded secrets are already covered by the recon-scanner (category 12), insecure defaults by Phase 8.

**If `WITH_SCA=true`:**

The dep-scan is now a deterministic Python script (`scripts/dep_scan.py`) — **no Agent dispatch**, no LLM turns consumed. It honors the same `.dep-scan.json` schema as the former agent and uses the same manifest-hash cache (1-hour TTL).

Launch it as a background process so it runs in parallel with Phases 3–8. Log `AGENT_DISPATCH` for visibility in `.agent-run.log` even though no agent is dispatched — downstream tooling expects the line.

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   dep-scan  AGENT_DISPATCH   SCA dependency scan (script: dep_scan.py)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
nohup python3 "$CLAUDE_PLUGIN_ROOT/scripts/dep_scan.py" \
  --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" \
  --manifests "$MANIFESTS" \
  > "$OUTPUT_DIR/.dep-scan.stdout" 2>&1 &
echo $! > "$OUTPUT_DIR/.dep-scan.pid"
```

`$MANIFESTS` is the comma-separated relative-path list captured from the recon summary (Section 3). When omitted, `dep_scan.py` auto-discovers manifests by walking the repo — but passing the recon-curated list is preferred (faster, more accurate scope).

Do **not** wait — continue through Phases 3–8. Phase 10 will `wait` on the PID and read `.dep-scan.json`.
