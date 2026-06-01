# Phase Group: Reconnaissance & Context (Phases 1–2)

This file is read by the orchestrator at runtime to load phase instructions.

## Phases 1 + 2: Parallel Dispatch (since M2.7)

Phase 1 (context-resolver) reads external policy and prior findings. Phase 2 (recon-scanner) analyzes the codebase. They have **zero data dependencies** — no output of Phase 1 feeds into Phase 2, and vice versa. Dispatching them in parallel saves ~60 s of wall-clock time on a typical run.

**Execution protocol:**

1. **Before dispatch:** resolve the recon fingerprint skip (see below) to decide whether recon needs to run at all.
2. **Resolve the context cache hit** (see `appsec-threat-analyst.md` → Phase 1 Step B staleness check) to decide whether the context-resolver needs to run.
2b. **Resolve `HAS_IAC_SURFACE`** — run the `compgen` pre-check (see below, before Step 0a) to decide whether the config-scanner needs to run. This check has no dependency on Phase 2 output and must run before the parallel dispatch turn.
3. **Dispatch all needed agents in a single orchestrator turn** using up to three Agent tool calls (context-resolver, recon-scanner, config-scanner). Each call that is needed gets `run_in_background: true`; if only one agent is dispatched, use `run_in_background: false`. If all three are skipped, jump directly to Phase 3.
4. **Wait for all background agents to return** before proceeding to Phase 3. Context-resolver typically finishes in 3–6 min; recon-scanner takes 5–15 min. **CRITICAL: When context-resolver returns first, the recon-scanner is still running in the background — do NOT check `.recon-summary.md` at that point and do NOT re-dispatch recon-scanner. Simply wait for the already-running background agent to complete.** Only after the recon-scanner agent itself returns should you read `.recon-summary.md`.

**Error handling:** If the context-resolver aborts (requirements unavailable + `CHECK_REQUIREMENTS=true`), halt the assessment regardless of whether recon succeeded. If the recon-scanner fails but the context-resolver succeeded, fall back to minimal inline scan (same as before).

### Phase 1: Context Resolution

**⚠ Staleness check first** — see `appsec-threat-analyst.md` → Phase 1 Step B for the `CTX_SKIP` logic. If `CTX_SKIP=true`, do not dispatch. Otherwise:

**→ TOOL CALL REQUIRED (dispatch as part of the parallel batch):**
- `subagent_type`: `appsec-advisor:appsec-context-resolver`
- `description`: `Resolve context for threat model`
- `run_in_background`: `true` (parallel with recon — unless recon is skipped, then `false` is fine)
- `model`: `$CONTEXT_RESOLVER_MODEL` from `.skill-config.json` (defaults to `sonnet`; under `--reasoning-model haiku-economy` becomes `haiku` regardless of depth — pure file-IO + summary task)
- `prompt`: `REPO_ROOT=<absolute repo path>`, `OUTPUT_DIR=<absolute output path>`, `CHECK_REQUIREMENTS=<true|false>`, and `REQUIREMENTS_URL_OVERRIDE=<url>` (only if set)

Log `AGENT_INVOKE` before dispatch. After the agent returns (or cache hit): read `$OUTPUT_DIR/.threat-modeling-context.md` and store team, asset tier, compliance scope, prior findings, known threats, known exceptions, architecture notes, and business context for use throughout the assessment.

**Log `PHASE_END` immediately after the context-resolver returns** (or after the cache-hit short-circuit), batched with the post-return processing Bash call so the parallel-dispatch branch leaves a clean phase-pair in `.agent-run.log`. Without this PHASE_END, the `ASSESSMENT_PHASES` aggregator drops Phase 1 from the per-phase cost breakdown entirely (it pairs PHASE_START + PHASE_END to compute durations). The PHASE_END label MUST carry the `(parallel with Phase 2)` suffix so a reader does not naively sum Phase 1 + Phase 2 durations as wall-clock — they overlap by design.

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  PHASE_END   [Phase 1/11] Context Resolution complete (parallel with Phase 2)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

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
3. Jump to Phase 3 (or wait for Phase 1 to complete if it is still running in background).

**If `RECON_SKIP=false`:**

1. Run Step 1 (recon-scanner dispatch) as part of the parallel batch.
2. After the recon-scanner returns, the updated fingerprint will be written to `.appsec-cache/baseline.json` during Phase 11 — no action needed here.

**Conservative fingerprinting rule:** `baseline_state.py` uses a whitelist of known manifest/Dockerfile/IaC file types. If a new unknown file type shows up that might carry security-relevant changes (e.g. a novel IaC format), the fingerprint check will still say "unchanged" for that file — which is unsafe. Mitigation: when in doubt about coverage, force a full scan with `--full`. The fingerprint is a best-effort optimization, not a correctness guarantee.

### Pre-check — resolve HAS_IAC_SURFACE (before parallel dispatch)

Run this in the same Bash batch as the RECON_SKIP check above — before dispatching any agents. The check is a pure filesystem lookup with no dependency on Phase 2 output.

```bash
HAS_IAC_SURFACE=false
for pattern in "Dockerfile" "*.dockerfile" "docker-compose*.yml" "docker-compose*.yaml" \
               ".github/workflows/*.yml" ".github/workflows/*.yaml" \
               ".github/dependabot.yml" ".github/dependabot.yaml" \
               "renovate.json" "renovate.json5" ".renovaterc" \
               ".npmrc" ".yarnrc.yml"; do
  if compgen -G "$REPO_ROOT/$pattern" > /dev/null 2>&1 \
     || compgen -G "$REPO_ROOT/**/$pattern" > /dev/null 2>&1; then
    HAS_IAC_SURFACE=true
    break
  fi
done
echo "HAS_IAC_SURFACE=$HAS_IAC_SURFACE"
```

If `HAS_IAC_SURFACE=false` → write a schema-valid stub immediately so downstream phases see a consistent shape:

```bash
if [ "$HAS_IAC_SURFACE" = "false" ]; then
  cat > "$OUTPUT_DIR/.config-scan-findings.json" <<'JSON'
{"parse_error": "skipped: no IaC surface detected", "findings": []}
JSON
fi
```

The error-stub branch requires only `[parse_error, findings]` — both consumers (Phase 9 / Phase 10) treat findings as authoritative and a `parse_error` key as "no findings to merge". No agent is dispatched when `HAS_IAC_SURFACE=false`.

**R5 check:** On large monorepos the `compgen -G "**/..."` globs may be slow cold-cache. If the time between pre-phase start and `HAS_IAC_SURFACE` resolution exceeds 500 ms, switch to top-level-only globs (drop `**/`).

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
- `model`: `$RECON_SCANNER_MODEL` from `.skill-config.json`. Default routing is `haiku` at every depth and reasoning tier — recon is grep-based pattern detection plus lookup-table verdicts (e.g. lockfile-disable severity per ecosystem, repo-visibility-conditional severity for self-hosted runners), all decision-table-driven and Haiku-suitable. Override per-run via `APPSEC_RECON_SCANNER_MODEL=sonnet` if a specific repo needs Sonnet's stronger instruction-following on novel patterns.
- `prompt`: `REPO_ROOT=<absolute repo path>` and `OUTPUT_DIR=<absolute output path>` and `SCAN_MANIFEST=<value of SCAN_MANIFEST variable — true or false>`

After both Phase 1 and Phase 2 have returned, read `$OUTPUT_DIR/.recon-summary.md`. Store contents for Phases 3–11:
- **Manifest list** (Section 3) → needed by Phase 10 emit_known_bad_libs.py manifest walk
- **Preliminary components** (Section 9) → starting point for Phase 3
- **Security findings** (Section 7) → used in Phases 4, 6, 7, 8, 9
- **Business context** (Section 1) → System Overview and Asset Identification

If `.recon-summary.md` is missing **after the recon-scanner agent has already returned**, fall back to minimal inline scan. Do **not** check for `.recon-summary.md` while the recon-scanner is still running and use its absence as a reason to re-dispatch — the file will appear once the agent finishes writing it.

### Step 1c — Cross-repo register update (recon Category 25 merge)

After `.recon-summary.md` is on disk, rebuild the cross-repo register so it merges Recon's code-grep-discovered SCM/SaaS deps (Section 7.25) with the declared and sibling/submodule entries that Phase 1 already captured. This single source feeds the STRIDE dispatcher slice, `coverage_checks.check_cross_repo`, and Phase 11 §5/§7 rendering.

Always run the rebuild — the script is idempotent and writes an empty register cleanly when no inputs are present. `--declared-json` is optional; the builder ignores the flag when the file does not exist (typical when context-resolver did not run, e.g. some incremental fast paths).

```bash
DECLARED_ARG=""
[ -f "$OUTPUT_DIR/.related-repos-loaded.json" ] && \
  DECLARED_ARG="--declared-json $OUTPUT_DIR/.related-repos-loaded.json"

python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_cross_repo_register.py" \
    --repo-root      "$REPO_ROOT" \
    $DECLARED_ARG \
    --recon-summary  "$OUTPUT_DIR/.recon-summary.md" \
    --output         "$OUTPUT_DIR/.cross-repo-register.json"
```

Declared entries win over sibling/submodule, which win over recon-discovered entries when names collide. Drift-guarded by `tests/test_build_cross_repo_register.py::TestDeclaredMerge`.

## Phase 2.5: Configuration & IaC Scan (M3.5)

Runs **in parallel with Phases 1 and 2** (no recon dependency). The config-scanner
reads `$CLAUDE_PLUGIN_ROOT/data/config-iac-checks.yaml` and filesystem globs
directly — it does not consume `.recon-summary.md`. Phase 2.5 catches
configuration-level security issues that the per-component STRIDE analyzers
in Phase 9 would miss (Dockerfile hardening, GH Actions privilege, docker-compose
trust boundaries, Dependabot/Renovate disablement, `.npmrc` TLS bypass).

### Pre-check

`HAS_IAC_SURFACE` is resolved before the parallel dispatch — see "Pre-check —
resolve HAS_IAC_SURFACE" section above (before Step 0a). The stub file is also
written there when `HAS_IAC_SURFACE=false`. No further action needed here when
`HAS_IAC_SURFACE=false` — proceed to Phase 3 after all background agents return.

### Dispatch — when IaC surface exists

**→ TOOL CALL REQUIRED (parallel with Phases 1+2 — dispatched in the same
orchestrator turn as context-resolver and recon-scanner):**

- `subagent_type`: `appsec-advisor:appsec-config-scanner`
- `description`: `Configuration & IaC scan`
- `run_in_background`: `true` (parallel with Phases 1+2; use `false` only when
  config-scanner is the sole dispatched agent — see State-Matrix in
  `appsec-threat-analyst.md` Step B)
- `model`: `$CONFIG_SCANNER_MODEL` from `.skill-config.json` (defaults to
  `haiku` at all reasoning tiers — YAML-rule-engine task,
  pattern-matching against a static check catalog, Haiku-suitable at every
  depth. Override via `APPSEC_CONFIG_SCANNER_MODEL`.)
- `prompt`: `REPO_ROOT=<absolute repo path>`, `OUTPUT_DIR=<absolute output path>`,
  `CLAUDE_PLUGIN_ROOT=<plugin root>`, `ASSESSMENT_DEPTH=<quick|standard|thorough>`

Log `AGENT_INVOKE` and `PHASE_START [Phase 2.5/N]` in the **same Bash batch**
as Phase 1/2 `AGENT_INVOKE` lines — identical second-level timestamp lets the
`ASSESSMENT_PHASES` aggregator detect parallelism. Example:

```bash
[ "$HAS_IAC_SURFACE" = "true" ] && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst    PHASE_START   [Phase 2.5/11] Configuration & IaC Scan — dispatching config-scanner (parallel with Phases 1+2)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
[ "$HAS_IAC_SURFACE" = "true" ] && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   config-scanner    AGENT_INVOKE  Configuration & IaC scan (model: $CONFIG_SCANNER_MODEL)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

After the agent returns — log `AGENT_DONE` and `PHASE_END` with parallel suffix:

```bash
CONFIG_SCAN_DONE_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "$CONFIG_SCAN_DONE_TS  [--------]  INFO   config-scanner    AGENT_DONE    Configuration & IaC scan complete" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
echo "$CONFIG_SCAN_DONE_TS  [--------]  INFO   threat-analyst    PHASE_END     [Phase 2.5/11] Configuration & IaC Scan complete (parallel with Phases 1+2)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

The `PHASE_END` label **MUST** carry the `(parallel with Phases 1+2)` suffix so
the `ASSESSMENT_PHASES` aggregator (see `phase-group-finalization.md:1142`) does
not add Phase 2.5 wall-clock to the sequential total. Without the suffix, every
run statistics appendix overstates total wall-clock by ~30–90 s.

Then validate the output against the schema:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py" \
    config_scan_findings "$OUTPUT_DIR/.config-scan-findings.json"
```

If validation fails (`exit != 0`) — log a warning and continue. The
config-scan is enrichment, not blocking; missing or malformed output
should not abort the assessment.

### Handoff to downstream phases

- **Phase 9 STRIDE-Analyzer dispatches:** the orchestrator passes a
  component-scoped slice of `.config-scan-findings.json` as the new
  `CONFIG_SCAN_FINDINGS` Group-B parameter when dispatching the
  `ci-cd-pipeline` component (or a synthetic `developer-workstation`
  component when `.claude/`/`.cursor/` etc. are present). The analyzer
  uses these as supplementary evidence in its existing **Supply chain
  threat analysis** sub-block.
- **Phase 10 Threat Merge:** the orchestrator merges
  `.config-scan-findings.json` entries into `.threats-merged.json` with
  `source: "config-scan"` and global `T-NNN`/`F-NNN` IDs alongside the
  STRIDE merge.

### Failure handling

If the config-scanner agent fails (agent dispatch error, schema validation
failure, missing output file) — log the failure with `AGENT_ERROR` but
**do not abort the assessment**. The Phase 9 STRIDE pass still runs
without `CONFIG_SCAN_FINDINGS`; the missing-finding-class is documented
in the run log so users know coverage was reduced.

## Phase 2.6: Architecture Coverage Pre-pass (arch.md)

After Phase 2.5 returns (whether dispatched or skipped), run two
deterministic Python scripts that produce the architecture-coverage
artifacts consumed by Phases 6 (`attack_surface[]`), 8 (`security_controls[]`),
9 (Phase-9 bridge), and 11 (Section 7.2 hypothesis table).

Both are pure pattern extraction with no LLM judgement — they MUST run
unconditionally so that "always-on" rule evaluation is honoured even on
repos with no detected framework (the engine still emits `not_applicable`
rows for every rule, which is the audit signal QA needs).

### Step 1 — Route inventory

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/route_inventory.py" \
    --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" > /dev/null

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_END   Route inventory pre-pass → .route-inventory.json" >> "$OUTPUT_DIR/.agent-run.log"
```

The script scans Express/Koa/Fastify/Hapi/NestJS, FastAPI/Flask/Django,
Spring/JAX-RS, and ASP.NET minimal-API patterns. Output is
`$OUTPUT_DIR/.route-inventory.json` conforming to
`schemas/route-inventory.schema.json`. Phase 6 consumes it directly.

### Step 2 — Architecture coverage engine

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/architecture_coverage_checks.py" \
    --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" > /dev/null

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_END   Architecture coverage engine → .architecture-coverage.json" >> "$OUTPUT_DIR/.agent-run.log"
```

The engine evaluates the 5 hard rules (cookie hardening, CORS wildcard +
credentials, JWT algorithm whitelist, cleartext transport, management-
endpoint exposure) and the 4 threat-hypothesis rules (XSS, SQLi, broken
authorization, broken input validation). Output is
`$OUTPUT_DIR/.architecture-coverage.json` conforming to
`schemas/architecture-coverage.schema.json`.

### Handoff to downstream phases

- **Phase 6 (Attack Surface Mapping):** prefer `.route-inventory.json` as
  the deterministic `attack_surface[]` baseline. The "single combined
  route grep" fallback only runs when the inventory is empty or carries
  unsupported_route_files.
- **Phase 8 (Security Controls):** pre-populates `security_controls[]`
  with one row per `control_assessments[]` entry (status in
  {partial, weak, missing, anti_pattern}); the mechanism-discovery loop
  then adds anything BEYOND this architectural baseline.
- **Phase 9 (Threat Merge):** the bridge `arch_coverage_to_threats.py
  merge-into` injects high-confidence `anti_pattern_candidates[]` and
  any `confirmed` hypotheses as threats with `source: architecture-coverage`
  / `source: threat-hypothesis`.
- **Phase 11 (Finalization):** unpromoted hypotheses are persisted via
  `arch_coverage_to_threats.py persist-hypotheses` into
  `threat-model.yaml#threat_hypotheses[]` so the Section 7.2 renderer
  can produce the "Threat Hypotheses Requiring Validation" table.

### Failure handling

Both Phase 2.6 scripts are idempotent and exit non-zero only on missing
inputs (no repo root, no valid output dir). On any other failure, log
`AGENT_WARN` and continue — downstream phases all guard on missing files
("if .route-inventory.json exists, prefer it; otherwise fall back"). The
architecture-coverage delivery is enrichment, not blocking.

## Phase 2.7: Actor Layer Resolution & Discovery

**Skip when:** `ASSESSMENT_DEPTH = quick`.

After Phase 2.6 completes, run the Actor Layer. This phase is fully
deterministic for the static layers and conditionally LLM-driven for
discovery.

### Step 1 — Resolve static actor layers (deterministic)

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst    PHASE_START   [Phase 2.7/N] Actor Layer Resolution" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null

python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_actors.py" \
    --plugin-root "$CLAUDE_PLUGIN_ROOT" \
    --repo-root "$REPO_ROOT" \
    --output-dir "$OUTPUT_DIR" \
    ${ORG_PROFILE_EFFECTIVE:+--org-profile-effective "$ORG_PROFILE_EFFECTIVE"} \
    --signals "$OUTPUT_DIR/.recon-signals.json"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst    STEP_END   Actor static resolution → .actors-merged-static.json" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

`ORG_PROFILE_EFFECTIVE` is the path to `.org-profile-effective.json` when an org
profile is active; skip the flag when no profile is configured.

Outputs: `$OUTPUT_DIR/.actors-merged-static.json` (input for discovery).

### Step 2 — Compute discovery cache key

Five-input composition per actors.md §8 — any change invalidates the discovery cache:

1. `recon-summary-content` — `.recon-summary.md`
2. `config-scan-content` — `.config-scan-findings.json`
3. `actors_inputs_fingerprint` — read from `.actor-fingerprints.json` (written by Step 1's resolve_actors.py)
4. `plugin_version` — sha of `agents/appsec-actor-discoverer.md` (catches prompt edits and agent-config changes)
5. `discovery_prompt_version` — explicit semver from the `DISCOVERY_PROMPT_VERSION` HTML-comment marker in the discoverer agent file (bump by hand on any semantic prompt change)

```bash
DISCOVERY_CACHE_KEY=$(python3 - <<'EOF'
import hashlib, os, json, re

output_dir = os.environ.get("OUTPUT_DIR", "")
plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")

def sha_file(path):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    return ""

def read_actors_fingerprint():
    p = os.path.join(output_dir, ".actor-fingerprints.json")
    if not os.path.exists(p):
        return ""
    try:
        return json.load(open(p)).get("actors_inputs_fingerprint", "")
    except Exception:
        return ""

def read_discovery_prompt_version():
    p = os.path.join(plugin_root, "agents", "appsec-actor-discoverer.md")
    if not os.path.exists(p):
        return ""
    m = re.search(r"DISCOVERY_PROMPT_VERSION:\s*([0-9]+\.[0-9]+\.[0-9]+)", open(p).read())
    return m.group(1) if m else ""

parts = [
    sha_file(os.path.join(output_dir, ".recon-summary.md")),
    sha_file(os.path.join(output_dir, ".config-scan-findings.json")),
    read_actors_fingerprint(),
    sha_file(os.path.join(plugin_root, "agents", "appsec-actor-discoverer.md")),
    read_discovery_prompt_version(),
]
print(hashlib.sha256("||".join(parts).encode()).hexdigest())
EOF
)
```

### Step 3 — LLM Actor Discovery (when not cached and not quick)

Check if discovery output is current:

```bash
DISCOVERY_CACHED=$(python3 - <<'EOF'
import json, os
p = os.path.join(os.environ.get("OUTPUT_DIR",""), ".actors-discovered.json")
if not os.path.exists(p):
    print("miss")
    raise SystemExit(0)
with open(p) as f:
    d = json.load(f)
print("hit" if d.get("discovery_cache_key") == os.environ.get("DISCOVERY_CACHE_KEY","") else "miss")
EOF
)
```

When `DISCOVERY_CACHED=hit` AND `REFRESH_ACTOR_DISCOVERY != true`: skip Step 3 (cache valid).

When `DISCOVERY_CACHED=miss` OR `REFRESH_ACTOR_DISCOVERY=true`: dispatch the discovery agent:

```
Agent(
  subagent_type: "appsec-advisor:appsec-actor-discoverer",
  description: "Actor Discovery (Phase 2.7)",
  prompt: "
OUTPUT_DIR=$OUTPUT_DIR
REPO_ROOT=$REPO_ROOT
ASSESSMENT_DEPTH=$ASSESSMENT_DEPTH
DISCOVERY_CACHE_KEY=$DISCOVERY_CACHE_KEY
MODEL_ID=$ACTOR_DISCOVERY_MODEL
  "
)
```

After the agent returns, verify `.actors-discovered.json` exists and is valid JSON.
On failure: log `AGENT_WARN`, write an empty discovery sentinel, continue without
blocking the assessment.

### Step 4 — Finalize resolved actor set (with discovery)

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_actors.py" \
    --plugin-root "$CLAUDE_PLUGIN_ROOT" \
    --repo-root "$REPO_ROOT" \
    --output-dir "$OUTPUT_DIR" \
    ${ORG_PROFILE_EFFECTIVE:+--org-profile-effective "$ORG_PROFILE_EFFECTIVE"} \
    --signals "$OUTPUT_DIR/.recon-signals.json" \
    --discovery-output "$OUTPUT_DIR/.actors-discovered.json"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst    PHASE_END   [Phase 2.7/N] Actor Layer complete → .actors-resolved.json" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

Outputs: `$OUTPUT_DIR/.actors-resolved.json` (consumed by per-component slicing).

### Quick-mode handling

When `ASSESSMENT_DEPTH=quick`: call `resolve_actors.py --quick` which runs only
the static layers and writes `.discovery-skipped.json`. Skip Steps 2–3 entirely.
The resolved set still drives actor-tagging in the STRIDE analyzers.

### Failure handling

`resolve_actors.py` is idempotent. On any failure: log `AGENT_WARN` and continue.
STRIDE analysis runs without actor attribution when `.actors-resolved.json` is
absent (`RELEVANT_ACTORS_INDEX_PATH=none`).
