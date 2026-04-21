# Enhanced Run Statistics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enhance the Run Statistics appendix to include CLI invocation, token consumption breakdown, multi-model cost estimates (with/without caching, API vs subscription), agent roster with models, and per-phase durations with agent attribution — in both the generator template and the current report.

**Architecture:** Four files are modified: the generator template (`phase-group-finalization.md`) defines what future runs produce, the QA reviewer (`appsec-qa-reviewer.md`) patches token/cost placeholders, the skill layer (`SKILL.md`) patches duration placeholders and prints the console summary, and the current report/YAML are patched with data from this run. No changes to `verify_run_costs.py` — it already produces all needed data.

**Tech Stack:** Markdown templates, YAML schema, Bash log parsing, Python JSON output from `verify_run_costs.py`

**Spec:** `docs/superpowers/specs/2026-04-14-enhanced-run-statistics-design.md`

---

### Task 1: Update YAML schema in phase-group-finalization.md

**Files:**
- Modify: `agents/phases/phase-group-finalization.md:28-31`

- [ ] **Step 1: Add `run_statistics` block to YAML schema**

In `agents/phases/phase-group-finalization.md`, replace lines 28-31 (from `analysis_duration_seconds` through `recommend_full_rerun` closing comment) with the expanded schema that includes `run_statistics`:

```markdown
  analysis_duration_seconds: <int>
  recommend_full_rerun: <bool>        # true when the baseline's analysis_version
                                      # was older than the current plugin; CI can
                                      # read this via `yq '.meta.recommend_full_rerun'`
  run_statistics:                       # written with null tokens/cost by Phase 11;
                                        # populated by QA Check 12 via verify_run_costs.py
    tokens:
      input: <int | null>
      output: <int | null>
      cache_write: <int | null>
      cache_read: <int | null>
      total: <int | null>
    cost:
      billing: <api | subscription>     # "api" when ANTHROPIC_API_KEY is set, else "subscription"
      models:                           # one entry per unique model used in the run
        <model-key>:                    # e.g. "sonnet-4-6", "opus-4-6"
          with_caching: <float | null>
          without_caching: <float | null>
      cache_savings_pct: <float | null>
      cost_verified: <bool>             # true after QA Check 12 cross-check passes
    agents:                             # roster of agents that ran (populated by Phase 11)
      - name: <string>                  # e.g. "threat-analyst", "stride-analyzer"
        model: <string>                 # e.g. "claude-sonnet-4-6"
        role: <string>                  # e.g. "Orchestrator", "STRIDE analysis"
        phases: <string>                # e.g. "1, 3-8, 10-11", "9 (5 instances)"
```

The old flat fields `tokens_total`, `estimated_cost`, `cost_verified` (added by QA Check 12) are superseded by the structured `run_statistics` block. The QA reviewer must be updated accordingly (Task 3).

- [ ] **Step 2: Verify the edit**

Read back lines 28-60 of `phase-group-finalization.md` to confirm the schema is well-formed and the surrounding context (changelog section starting at the old line 33) is intact.

- [ ] **Step 3: Commit**

```bash
cd /home/mrohr/appsec-advisor
git add agents/phases/phase-group-finalization.md
git commit -s -m "feat: add run_statistics block to threat-model.yaml schema"
```

---

### Task 2: Replace Run Statistics appendix template in phase-group-finalization.md

**Files:**
- Modify: `agents/phases/phase-group-finalization.md:444-543`

- [ ] **Step 1: Replace the Run Statistics appendix spec**

Replace lines 444-543 (from `#### Run Statistics Appendix (verbose only)` through `Extract agent names and models...`) with the enhanced 6-subsection template. The replacement content is:

````markdown
#### Run Statistics Appendix (verbose only)

**Only emit this appendix when `VERBOSE_REPORT=true`.** When `VERBOSE_REPORT=false` (default), omit the appendix entirely — no `## Appendix: Run Statistics` heading, no tables, no ToC entry.

At the end of Part D, after Section 10 (Out of Scope), append a horizontal rule and an unnumbered appendix section. This appendix is the **single location for all run metadata** — there is no metadata table at the top of the report.

Extract per-phase durations from `$OUTPUT_DIR/.agent-run.log` by pairing `PHASE_START` and `PHASE_END` timestamps for each phase. **Use actual timestamps from the log — never use `~` estimated durations.** If a PHASE_START/PHASE_END pair is missing for a phase, write `n/a` for that phase's duration.

Extract agent names and models from `AGENT_INVOKE` / `AGENT_START` lines in `.agent-run.log`. Only include agents that actually ran — omit context-resolver on cache hit, omit dep-scanner when `WITH_SCA=false`.

The `Tokens` and `Cost Estimate` tables are written entirely as `_pending_` — they are patched by the QA reviewer's Check 12 (via `verify_run_costs.py`). The `Assessment Total`, `QA Review`, and `Grand Total` duration rows are also `_pending_` — patched by the skill layer after Stage 2 completes.

Format — the appendix has 6 subsections:

```markdown
---

## Appendix: Run Statistics

### Run Metadata

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 UTC timestamp> |
| Invocation | `/create-threat-model <INVOCATION_ARGS>` |
| Assessment Mode | <Full scan (initial) / Full (--full) / Incremental (auto) / Incremental (--incremental)> |
| Plugin Version | appsec-advisor <PLUGIN_VERSION> (analysis v<ANALYSIS_VERSION>) |
| Assessment Depth | <quick / standard / thorough> (components: <N>, STRIDE turns: <S>/<M>/<C>) |
| Repository | `<REPO_ROOT>` |
| Baseline SHA | `<BASELINE_SHA>` or n/a (first full run) |
| Current SHA | `<CURRENT_SHA>` |
```

```markdown
### Agents & Models

| Agent | Model | Role | Phases |
|-------|-------|------|--------|
| threat-analyst | <model> | Orchestrator — architecture, controls, synthesis, finalization | 1, 3-8, 10-11 |
| context-resolver | <model> | Resolves repo context and business docs | 1 |
| recon-scanner | <model> | Tech stack and security pattern reconnaissance | 2 |
| dep-scanner | <model> | SCA dependency vulnerability scan | 2 |
| stride-analyzer | <model> | Per-component STRIDE threat analysis | 9 (<N> instances) |
| qa-reviewer | _pending_ | Cross-reference validation, link fixes, consistency | Post-assessment |
```

Only include agents that actually ran. The `qa-reviewer` row is always included with `_pending_` model — patched by the skill layer after Stage 2. The `dep-scanner` row is only included when `WITH_SCA=true`. The `context-resolver` row is only included when context resolution was not a cache hit.

```markdown
### Phase Duration Breakdown

| Phase | Description | Agent(s) | Duration |
|-------|-------------|----------|----------|
| Phase 1 | Context Resolution | context-resolver (<model>) or threat-analyst (<model>) [cache hit] | Xm YYs |
| Phase 2 | Reconnaissance | recon-scanner (<model>) | Xm YYs |
| Phase 3 | Architecture Modeling (<N> diagrams) | threat-analyst (<model>) | Xm YYs |
| Phase 4 | Security Use Cases | threat-analyst (<model>) | Xm YYs |
| Phase 5 | Asset Identification | threat-analyst (<model>) | Xm YYs |
| Phase 6 | Attack Surface Mapping | threat-analyst (<model>) | Xm YYs |
| Phase 7 | Trust Boundary Analysis | threat-analyst (<model>) | Xm YYs |
| Phase 8 | Security Controls Catalog | threat-analyst (<model>) | Xm YYs |
| Phase 9 | STRIDE Threat Enumeration (<N> components) | <N> x stride-analyzer (<model>) | Xm YYs |
| Phase 10 | Scan Synthesis | threat-analyst (<model>) | Xm YYs |
| Phase 11 | Finalization (YAML + MD composition) | threat-analyst (<model>) | Xm YYs |
| **Assessment Total** | | | **_pending_** |
| QA Review | Cross-reference validation, link fixes, consistency checks | qa-reviewer (<model>) | _pending_ |
| **Grand Total** | | | **_pending_** |
```

> Phases 1–2 run in parallel. Phases 3–8 run in parallel. Phase 9 dispatches N STRIDE analyzers in parallel. Wall-clock durations overlap; the Assessment Total reflects actual analysis time from `analysis_duration_seconds` in threat-model.yaml.

```markdown
### Token Consumption

| Category | Tokens |
|----------|--------|
| Input | _pending_ |
| Output | _pending_ |
| Cache Write | _pending_ |
| Cache Read | _pending_ |
| **Total** | **_pending_** |

> Host-session tokens only. Sub-agent tokens (e.g., stride-analyzer) are executed within the host session and included in these totals.
```

```markdown
### Cost Estimate

| Metric | <model-1> | <model-2> |
|--------|-----------|-----------|
| With prompt caching | _pending_ | _pending_ |
| Without prompt caching | _pending_ | _pending_ |
| Cache savings | _pending_ | _pending_ |

> Billing: _pending_ (api / subscription). Costs under each model's pricing are shown for reference since sub-agents may use different models. Actual billing depends on which model processed each token.

<details><summary>API pricing reference (per 1M tokens)</summary>

| Model | Input | Output | Cache Write | Cache Read |
|-------|-------|--------|-------------|------------|
| claude-sonnet-4-6 | $3.00 | $15.00 | $3.75 | $0.30 |
| claude-opus-4-6 | $15.00 | $75.00 | $18.75 | $1.50 |
| claude-haiku-4-5 | $0.80 | $4.00 | $1.00 | $0.08 |

</details>
```

**Cost Estimate column headers:** dynamically determined from `agent_models` in the YAML — one column per unique model used. When only one model is used (no `agent_models` override), show a single value column with that model's name as header. The pricing reference table is static and always included.

**Billing label in the blockquote:** replace `_pending_` with `api` or `subscription (estimated)` — patched by QA Check 12.

```markdown
### Coverage Summary

| Metric | Count |
|--------|-------|
| Components analyzed | <N> (<list of component IDs>) |
| Total threats identified | <N> |
| Critical threats | <N> |
| High threats | <N> |
| Medium threats | <N> |
| Low threats | <N> |
| Mitigations generated | <N> |
| Security controls rated | <N> |
| Attack surface entry points | <N> (N unauthenticated, N authenticated) |
| Trust boundaries mapped | <N> |
| Assets catalogued | <N> |
```

**Phase Duration table rules:**

- The table MUST NOT use `<details>` collapse — the durations are always visible.
- The **Agent(s)** column shows which agent executed each phase and its model in parentheses. For phases run inline by the orchestrator (Phases 3–8), the agent is `threat-analyst`. For dispatched sub-agents, show the sub-agent name. For Phase 9, show the count of stride-analyzer instances (e.g., `5 x stride-analyzer (opus-4-6)`).
- For phases that ran in parallel (same PHASE_START timestamp), show the wall-clock duration of the parallel group for each phase row — this makes it clear they overlapped.
- The `Assessment Total` row uses `analysis_duration_seconds` from `threat-model.yaml` (excludes permission prompt wait time).
- The `QA Review` and `Grand Total` rows are filled by the skill layer after Stage 2 completes.

**How to compute per-phase durations:** Use Bash to parse `$OUTPUT_DIR/.agent-run.log` and extract paired `PHASE_START` / `PHASE_END` timestamps:

```bash
# Extract phase timing pairs from .agent-run.log
while IFS= read -r line; do
  if [[ "$line" == *PHASE_START* ]]; then
    PHASE_KEY=$(echo "$line" | grep -oP '\[Phase \S+\]')
    PHASE_TS=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
    eval "START_${PHASE_KEY//[^0-9b]/}=$( date -d "$PHASE_TS" +%s 2>/dev/null )"
  elif [[ "$line" == *PHASE_END* ]]; then
    PHASE_KEY=$(echo "$line" | grep -oP '\[Phase \S+\]')
    PHASE_TS=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
    END_SEC=$( date -d "$PHASE_TS" +%s 2>/dev/null )
    # pair with corresponding START to compute elapsed
  fi
done < "$OUTPUT_DIR/.agent-run.log"
```

Extract agent names and models from `AGENT_INVOKE` / `AGENT_START` lines in the log. If parsing fails for any phase, write `n/a` for that row's duration rather than showing 0s.

**How to populate the Agents & Models table:** Parse `AGENT_INVOKE` and `AGENT_START` lines in `.agent-run.log`. Each line contains the agent name and `model: <value>`. Map agents to their roles and phases:

| Agent pattern in log | Role | Phases |
|---------------------|------|--------|
| `threat-analyst` (ASSESSMENT_START) | Orchestrator — architecture, controls, synthesis, finalization | 1, 3-8, 10-11 |
| `context-resolver` (AGENT_INVOKE) | Resolves repo context and business docs | 1 |
| `recon-scanner` (AGENT_INVOKE) | Tech stack and security pattern reconnaissance | 2 |
| `dep-scanner` (AGENT_INVOKE) | SCA dependency vulnerability scan | 2 |
| `stride-analyzer` (AGENT_INVOKE, multiple) | Per-component STRIDE threat analysis | 9 (<count> instances) |

Count stride-analyzer instances from the number of `stride-analyzer.*AGENT_INVOKE` lines. The `qa-reviewer` row is always written with `_pending_` model — it is patched by the skill layer after Stage 2 provides the QA reviewer's model.
````

- [ ] **Step 2: Verify the edit**

Read back lines 444-560 of `phase-group-finalization.md` to confirm the replacement is clean, no duplicate headings, and the content after the replacement (line 544+ in the old file) is intact.

- [ ] **Step 3: Commit**

```bash
cd /home/mrohr/appsec-advisor
git add agents/phases/phase-group-finalization.md
git commit -s -m "feat: enhance Run Statistics appendix template with agents, tokens, multi-model costs"
```

---

### Task 3: Update QA reviewer Check 12 patching instructions

**Files:**
- Modify: `agents/appsec-qa-reviewer.md:989-1031`

- [ ] **Step 1: Replace Check 12c and 12d with updated patching targets**

Replace lines 989-1031 (from `### 12c — Patch Run Statistics appendix` through `**Print when done:**`) with instructions targeting the new table structures:

```markdown
### 12c — Patch Run Statistics appendix in threat-model.md

If `$OUTPUT_DIR/threat-model.md` contains a `## Appendix: Run Statistics` section, use the Edit tool to update the following tables with verified delta values from the JSON output. **Only patch values; do not restructure tables or add/remove sections.**

**Token Consumption table** (subsection `### Token Consumption`):
Replace the `_pending_` rows with verified delta values:
```
| Input | <totals.in formatted with thousands separators> |
| Output | <totals.out formatted with thousands separators> |
| Cache Write | <totals.cache_write formatted with thousands separators> |
| Cache Read | <totals.cache_read formatted with thousands separators> |
| **Total** | **<totals.total_tokens formatted with thousands separators>** |
```

**Cost Estimate table** (subsection `### Cost Estimate`):
Replace `_pending_` cells in the multi-column cost table. The table has one column per model used in the run.

For each model key in `mixed_model_costs` (from the JSON output):
- "With prompt caching" cell → `mixed_model_costs[model].cached`. If `billing` is `"subscription"`, prefix with `~$` and append ` (estimated)`. If `"api"`, prefix with `$`.
- "Without prompt caching" cell → `mixed_model_costs[model].no_cache`. Same billing prefix.
- "Cache savings" cell → `totals.cache_savings_pct`% (same value for all columns — savings % is token-based, not model-based).

If `mixed_model_costs` is null (single-model run), use `totals.cost` and `totals.no_cache_cost` in a single column.

Replace the billing `_pending_` in the blockquote below the table with:
- `api` when `billing` is `"api"`
- `subscription (estimated)` when `billing` is `"subscription"`

**threat-model.yaml `meta.run_statistics` section:**
If `$OUTPUT_DIR/threat-model.yaml` exists, use Edit to update the `run_statistics:` block under `meta:`:
```yaml
  run_statistics:
    tokens:
      input: <totals.in>
      output: <totals.out>
      cache_write: <totals.cache_write>
      cache_read: <totals.cache_read>
      total: <totals.total_tokens>
    cost:
      billing: "<billing>"
      models:
        <model-key-1>:
          with_caching: <mixed_model_costs[model-key-1].cached>
          without_caching: <mixed_model_costs[model-key-1].no_cache>
        <model-key-2>:
          with_caching: <mixed_model_costs[model-key-2].cached>
          without_caching: <mixed_model_costs[model-key-2].no_cache>
      cache_savings_pct: <totals.cache_savings_pct>
      cost_verified: true
```

If `mixed_model_costs` is null (single model), write a single entry under `models:` using `totals.cost` and `totals.no_cache_cost`.

Print: `[qa-reviewer]   ↳ Run Statistics patched: token consumption + cost estimate tables in threat-model.md, run_statistics in yaml`

### 12d — Fallback

If `verify_run_costs.py` exits non-zero or the JSON is unparseable:
1. Log: `[qa-reviewer]   ↳ Token/cost verification FAILED (exit code <N>)`
2. Add a QA comment at the top of the Run Statistics appendix:
   ```
   <!-- QA: Token/cost verification failed — verify_run_costs.py exit code <N>. Cost data in this section is unverified. Manual review recommended. -->
   ```
3. Do NOT modify any existing cost data on failure.

**Print when done:** `[qa-reviewer]   ↳ Token/cost verification: <OK|MISMATCH|FAILED> — total: <N> tokens, ~$<N.NN> (delta-verified across <N> sessions, cache savings <N>%)`
```

- [ ] **Step 2: Verify the edit**

Read back lines 989-1050 of `appsec-qa-reviewer.md` to confirm the instructions are well-formed and don't break surrounding content.

- [ ] **Step 3: Commit**

```bash
cd /home/mrohr/appsec-advisor
git add agents/appsec-qa-reviewer.md
git commit -s -m "feat: update QA Check 12 to patch enhanced Run Statistics tables and YAML run_statistics"
```

---

### Task 4: Update skill-layer console summary in SKILL.md

**Files:**
- Modify: `skills/create-threat-model/SKILL.md:530-633`

- [ ] **Step 1: Replace the console summary Run Statistics section**

Replace lines 530-633 (from `Then extract run statistics from` through `Use Grep on the file`) with the enhanced console summary format that includes token breakdown and multi-model costs:

```markdown
Then extract run statistics from `$OUTPUT_DIR/.hook-events.log` and `$OUTPUT_DIR/.agent-run.log` and print them:
```
  -- Run Statistics --------------------------------------------
  Total Duration      : <Xm YYs>  (assessment: <Xm YYs> + QA review: <Xm YYs>)
    Phase 1   Context Resolution      threat-analyst (sonnet-4-6)    :  0m 02s
    Phase 2   Reconnaissance          recon-scanner (sonnet-4-6)     :  4m 19s
    Phase 3   Architecture Modeling    threat-analyst (sonnet-4-6)    :  0m 21s
    ...
    Phase 9   STRIDE Enumeration      5x stride-analyzer (opus-4-6)  : 18m 30s
    ...
    Phase 11  Finalization            threat-analyst (sonnet-4-6)     :  0m 30s
    QA        QA Review               qa-reviewer (sonnet-4-6)        :  5m 35s
  Agents              : threat-analyst=sonnet-4-6, recon-scanner=sonnet-4-6, stride-analyzer=opus-4-6, qa-reviewer=sonnet-4-6
  Tokens              : <total> total (in: <input>, out: <output>, cache_write: <cw>, cache_read: <cr>)
  Est. Cost           :
    <model-1> rates   : <prefix>$<cached> cached / <prefix>$<no_cache> no cache
    <model-2> rates   : <prefix>$<cached> cached / <prefix>$<no_cache> no cache
    Cache savings     : <n.n>%
    Billing           : <api / subscription (estimated)>
```

**How to extract run statistics:** Parse `$OUTPUT_DIR/.hook-events.log` and `$OUTPUT_DIR/.agent-run.log`. For durations and models, use Bash with grep/awk. For tokens and cost, call the delta-based verification script — **do not** manually sum SESSION_STOP lines, as they are cumulative per session and naive summation produces grossly inflated numbers. Extract the data as follows:

1. **Duration** — compute three values plus per-phase breakdown. Duration values must reflect **actual analysis time**, not wall-clock time. Wall-clock timestamps include time spent waiting for user permission prompts, which can dwarf the real work.
   
   **Assessment duration** (Stage 1 only): read `analysis_duration_seconds` from `threat-model.yaml`. This value is written by the orchestrator agent and represents actual analysis time, excluding any idle waits for permission prompts.
   ```bash
   ASSESS_SECS=$(grep 'analysis_duration_seconds:' "$OUTPUT_DIR/threat-model.yaml" | grep -oP '\d+' | head -1)
   if [ -n "$ASSESS_SECS" ]; then
     ASSESS_DUR="$((ASSESS_SECS / 60))m $(printf '%02d' $((ASSESS_SECS % 60)))s"
   fi
   ```
   If `threat-model.yaml` does not contain `analysis_duration_seconds`, fall back to the `ASSESSMENT_END` line in `.agent-run.log`:
   ```bash
   ASSESS_DUR=$(grep 'ASSESSMENT_END' "$OUTPUT_DIR/.agent-run.log" | grep -oP 'completed in \K\d+ min \d+ s' | head -1)
   ```
   Note: the `.agent-run.log` fallback uses wall-clock time and may overcount if permission prompts caused delays.
   
   **QA duration**: compute from QA reviewer timestamps in `.agent-run.log` (QA typically has no permission-prompt delays since all permissions are already granted by then):
   ```bash
   QA_START=$(grep 'qa-reviewer.*AGENT_START' "$OUTPUT_DIR/.agent-run.log" | tail -1 | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
   QA_END=$(grep 'qa-reviewer.*AGENT_COMPLETE' "$OUTPUT_DIR/.agent-run.log" | tail -1 | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
   ```
   Convert both to epoch seconds with `date -d "$TS" +%s` and subtract. Format as `Xm YYs`. If either timestamp is missing, omit the QA duration from the breakdown.
   
   **Total duration**: sum of assessment + QA durations (not wall-clock first-to-last timestamp). If QA duration is unavailable, show assessment duration only.
   
   Format the output as: `Total Duration: Xm YYs  (assessment: Xm YYs + QA review: Xm YYs)`
   
   **Per-phase durations and agents**: extract from `PHASE_START`/`PHASE_END` lines in `.agent-run.log`. For each phase, compute the duration from the timestamp delta between its PHASE_START and PHASE_END. Also extract the agent that ran each phase from `AGENT_INVOKE`/`AGENT_DISPATCH` lines — map phase numbers to agents (e.g., Phase 2 → recon-scanner, Phase 9 → stride-analyzer). Include the model in parentheses (extract from the `model:` field in the AGENT_INVOKE line). For STRIDE analyzers dispatched in parallel, show the count (e.g., `5x stride-analyzer (opus-4-6)`). Phases that ran inline within another phase (same start/end timestamp) should show `(inline)` as the duration. Append a QA row at the end using the QA duration computed above.

   Format each line as: `    Phase N   <Description padded to 24 chars>  <agent (model) padded to 30 chars>  : <duration>`

   ```
     Phase 1   Context Resolution      threat-analyst (sonnet-4-6)    :  0m 02s
     Phase 2   Reconnaissance          recon-scanner (sonnet-4-6)     :  4m 19s
     ...
     Phase 9   STRIDE Enumeration      5x stride-analyzer (opus-4-6)  : 18m 30s
     ...
     QA        QA Review               qa-reviewer (sonnet-4-6)        :  5m 35s
   ```

   If `PHASE_START`/`PHASE_END` lines are not found, fall back to the `ASSESSMENT_PHASES` summary line. If neither is found, skip the per-phase breakdown.

2. **Agents** — grep for `AGENT_INVOKE`, `AGENT_DISPATCH`, and `AGENT_START` lines in `.agent-run.log`, extract the agent name and `model: <value>` field. Use full model short names (e.g., `sonnet-4-6`, `opus-4-6`). Also include the orchestrator's own model from the `ASSESSMENT_START` line. Deduplicate — if the same agent was spawned multiple times with the same model, list it once. Format as comma-separated `agent=model` pairs.

3. **Tokens and Cost** — invoke the delta-based verification script:
   ```bash
   COST_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/verify_run_costs.py" "$OUTPUT_DIR" --json 2>/dev/null)
   COST_EXIT=$?
   ```
   
   Parse the JSON output to extract:
   - **Tokens**: format as `<total> total (in: <input>, out: <output>, cache_write: <cw>, cache_read: <cr>)`. All values with thousands separators.
   - **Est. Cost**: show one line per model. When `mixed_model_costs` is present, iterate each model key and show `<model> rates: <prefix>$<cached> cached / <prefix>$<no_cache> no cache`. When single model, show one line. Prefix is `~` for subscription, empty for API.
   - **Cache Savings**: `totals.cache_savings_pct`%.
   - **Billing**: `api` or `subscription (estimated)`.
   - **Cross-check**: append `(verified)` or `(MISMATCH)` after the billing line.
   
   **Why delta-based extraction is required:** SESSION_STOP lines in `.hook-events.log` are **cumulative** per session ID. A Claude Code session can span multiple skill invocations, and sessions are reused for subagent work and post-assessment activity. Naive summation of raw values inflates costs by 3–50x depending on session reuse. The verification script determines the assessment run window, computes per-session deltas, and cross-verifies against the API pricing formula.
   
   **Fallback**: If the script fails (exit code ≥ 2), print: `  Tokens/Cost     : unavailable (verify_run_costs.py failed)`

   If `.hook-events.log` does not exist, skip the "Run Statistics" section entirely — do not print it with zeros or placeholders.

4. **Patch placeholders into threat-model.md** — After extracting durations (item 1), use the Edit tool to replace `_pending_` placeholders in the `## Appendix: Run Statistics` section:
   - `| **Assessment Total** | | | **_pending_** |` → actual assessment duration
   - QA Review duration row → actual QA duration
   - `| **Grand Total** | | | **_pending_** |` → actual total duration (assessment + QA)
   - qa-reviewer `_pending_` model in Agents & Models table → actual model from QA AGENT_START log line
   
   Token and cost placeholders are patched by the QA reviewer's Check 12, not by the skill layer. If the QA reviewer did not run (e.g., dry-run mode), and `_pending_` placeholders remain for tokens/cost, replace them with `n/a`.
   If `.hook-events.log` is not available, replace all `_pending_` with `n/a`.
```

- [ ] **Step 2: Verify the edit**

Read back lines 530-650 of `SKILL.md` to confirm the replacement is clean and the surrounding `Log files:` block and `To extract metrics:` line are intact.

- [ ] **Step 3: Commit**

```bash
cd /home/mrohr/appsec-advisor
git add skills/create-threat-model/SKILL.md
git commit -s -m "feat: enhance skill-layer console summary with token breakdown and multi-model costs"
```

---

### Task 5: Patch current threat-model.md Run Statistics with full data

**Files:**
- Modify: `/home/mrohr/juice-shop/docs/security/threat-model.md:1553-1580`

- [ ] **Step 1: Extract all data needed for the patch**

Run these commands to gather the data:

```bash
OUTPUT_DIR="/home/mrohr/juice-shop/docs/security"
CLAUDE_PLUGIN_ROOT="/home/mrohr/appsec-advisor"

# 1. Phase timing from agent-run.log
echo "=== Phase timing ==="
grep -E 'PHASE_START|PHASE_END' "$OUTPUT_DIR/.agent-run.log"

# 2. Agent/model info
echo "=== Agents ==="
grep -E 'AGENT_INVOKE|AGENT_START|ASSESSMENT_START' "$OUTPUT_DIR/.agent-run.log"

# 3. Token/cost data
echo "=== Cost JSON ==="
python3 "$CLAUDE_PLUGIN_ROOT/scripts/verify_run_costs.py" "$OUTPUT_DIR" --json 2>/dev/null
```

- [ ] **Step 2: Replace the Run Statistics section**

Using the Edit tool, replace the entire block from `## Appendix: Run Statistics` (line 1553) through the end of the file (line 1580) with the fully populated enhanced appendix. Use the data extracted in Step 1. The content should look like:

```markdown
## Appendix: Run Statistics

### Run Metadata

| Field | Value |
|-------|-------|
| Generated | 2026-04-14T12:00:00Z |
| Invocation | `/create-threat-model --stride-model opus --full --verbose` |
| Assessment Mode | Full (--full) |
| Plugin Version | appsec-advisor 0.9.0-beta (analysis v1) |
| Assessment Depth | standard (components: 5, STRIDE turns: 15/22/31) |
| Repository | `/home/mrohr/juice-shop` |
| Baseline SHA | n/a (first full run) |
| Current SHA | `7380ce7120e289fc6bea861efd3fcba89261a6a8` |

### Agents & Models

| Agent | Model | Role | Phases |
|-------|-------|------|--------|
| threat-analyst | claude-sonnet-4-6 | Orchestrator — architecture, controls, synthesis, finalization | 1, 3-8, 10-11 |
| recon-scanner | claude-sonnet-4-6 | Tech stack and security pattern reconnaissance | 2 |
| stride-analyzer | claude-opus-4-6 | Per-component STRIDE threat analysis | 9 (5 instances) |
| qa-reviewer | claude-sonnet-4-6 | Cross-reference validation, link fixes, consistency | Post-assessment |

### Phase Duration Breakdown

| Phase | Description | Agent(s) | Duration |
|-------|-------------|----------|----------|
| Phase 1 | Context Resolution | threat-analyst (sonnet-4-6) [cache hit] | 0m 00s |
| Phase 2 | Reconnaissance | recon-scanner (sonnet-4-6) | 1m 52s |
| Phase 3 | Architecture Modeling (4 diagrams) | threat-analyst (sonnet-4-6) | 0m 27s |
| Phase 4 | Security Use Cases | threat-analyst (sonnet-4-6) | (inline) |
| Phase 5 | Asset Identification | threat-analyst (sonnet-4-6) | (inline) |
| Phase 6 | Attack Surface Mapping | threat-analyst (sonnet-4-6) | (inline) |
| Phase 7 | Trust Boundary Analysis | threat-analyst (sonnet-4-6) | (inline) |
| Phase 8 | Security Controls Catalog | threat-analyst (sonnet-4-6) | (inline) |
| Phase 9 | STRIDE Threat Enumeration (5 components) | 5 x stride-analyzer (opus-4-6) | 2m 57s |
| Phase 10 | Scan Synthesis | threat-analyst (sonnet-4-6) | (inline) |
| Phase 11 | Finalization (YAML + MD composition) | threat-analyst (sonnet-4-6) | 38m 21s |
| **Assessment Total** | | | **44m 20s** |
| QA Review | Cross-reference validation, link fixes, consistency checks | qa-reviewer (sonnet-4-6) | 0m 58s |
| **Grand Total** | | | **45m 18s** |

> Phases 3-8 ran inline (same timestamp). Phase 9 dispatched 5 STRIDE analyzers in parallel. The Assessment Total reflects wall-clock time from ASSESSMENT_START to ASSESSMENT_END.

### Token Consumption

| Category | Tokens |
|----------|--------|
| Input | 56 |
| Output | 19,215 |
| Cache Write | 170,160 |
| Cache Read | 1,487,042 |
| **Total** | **1,676,473** |

> Host-session tokens only. Sub-agent tokens (stride-analyzer) are executed within the host session and included in these totals.

### Cost Estimate

| Metric | sonnet-4-6 | opus-4-6 |
|--------|------------|----------|
| With prompt caching | ~$1.37 | ~$6.90 |
| Without prompt caching | ~$2.27 | ~$11.36 |
| Cache savings | 39.8% | 39.8% |

> Billing: subscription (estimated). Costs under each model's pricing are shown for reference since sub-agents may use different models. Actual billing depends on which model processed each token.

<details><summary>API pricing reference (per 1M tokens)</summary>

| Model | Input | Output | Cache Write | Cache Read |
|-------|-------|--------|-------------|------------|
| claude-sonnet-4-6 | $3.00 | $15.00 | $3.75 | $0.30 |
| claude-opus-4-6 | $15.00 | $75.00 | $18.75 | $1.50 |
| claude-haiku-4-5 | $0.80 | $4.00 | $1.00 | $0.08 |

</details>

### Coverage Summary

| Metric | Count |
|--------|-------|
| Components analyzed | 5 (auth-service, rest-api, frontend-spa, file-processor, data-access) |
| Total threats identified | 30 |
| Critical threats | 7 |
| High threats | 12 |
| Medium threats | 10 |
| Low threats | 1 |
| Mitigations generated | 23 |
```

**Note:** The exact token/cost values in the patch must come from the actual `verify_run_costs.py` output extracted in Step 1, not from the example above. The example shows the expected format. Use the last SESSION_STOP line's cumulative values as the final snapshot (the run only had one session, so the cumulative final values ARE the delta — baseline was zero).

- [ ] **Step 3: Commit**

```bash
cd /home/mrohr/juice-shop
git add docs/security/threat-model.md
git commit -s -m "feat: populate enhanced Run Statistics appendix with full run data"
```

---

### Task 6: Patch current threat-model.yaml with run_statistics block

**Files:**
- Modify: `/home/mrohr/juice-shop/docs/security/threat-model.yaml:16-17`

- [ ] **Step 1: Add run_statistics block to YAML meta**

Using the Edit tool, insert the `run_statistics` block after `analysis_duration_seconds: null` and before `recommend_full_rerun: false`. Use the actual values from the `verify_run_costs.py` output and the agent-run.log:

Replace:
```yaml
  analysis_duration_seconds: null
  recommend_full_rerun: false
```

With:
```yaml
  analysis_duration_seconds: 2660
  recommend_full_rerun: false
  run_statistics:
    tokens:
      input: 56
      output: 19215
      cache_write: 170160
      cache_read: 1487042
      total: 1676473
    cost:
      billing: "subscription"
      models:
        sonnet-4-6:
          with_caching: 1.3726
          without_caching: 2.27
        opus-4-6:
          with_caching: 6.90
          without_caching: 11.36
      cache_savings_pct: 39.8
      cost_verified: true
    agents:
      - name: "threat-analyst"
        model: "claude-sonnet-4-6"
        role: "Orchestrator — architecture, controls, synthesis, finalization"
        phases: "1, 3-8, 10-11"
      - name: "recon-scanner"
        model: "claude-sonnet-4-6"
        role: "Tech stack and security pattern reconnaissance"
        phases: "2"
      - name: "stride-analyzer"
        model: "claude-opus-4-6"
        role: "Per-component STRIDE threat analysis"
        phases: "9 (5 instances)"
      - name: "qa-reviewer"
        model: "claude-sonnet-4-6"
        role: "Cross-reference validation, link fixes, consistency"
        phases: "Post-assessment"
```

**Note:** The exact token/cost values must come from the actual `verify_run_costs.py` output. Also fix `analysis_duration_seconds` from `null` to the actual value (2660 seconds, computed from ASSESSMENT_START to ASSESSMENT_END timestamps).

- [ ] **Step 2: Verify the edit**

Read back lines 16-55 of `threat-model.yaml` to confirm the YAML is well-formed and the `changelog:` section below is intact.

- [ ] **Step 3: Commit**

```bash
cd /home/mrohr/juice-shop
git add docs/security/threat-model.yaml
git commit -s -m "feat: add run_statistics block to threat-model.yaml meta"
```
