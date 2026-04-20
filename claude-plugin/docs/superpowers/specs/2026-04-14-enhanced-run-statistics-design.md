# Enhanced Run Statistics — Design Spec

**Date:** 2026-04-14
**Scope:** Run Statistics appendix in threat-model.md, `run_statistics` in threat-model.yaml, generator template in phase-group-finalization.md, QA reviewer Check 12 patching in appsec-qa-reviewer.md, skill-layer console summary in SKILL.md

## Problem

The Run Statistics appendix is missing critical operational data:

1. **CLI invocation** — not rendered in the report despite being available in `meta.invocation`
2. **Token consumption** — no breakdown (input, output, cache write, cache read, total)
3. **Cost estimates** — no with/without caching comparison, no multi-model pricing, no API vs subscription distinction
4. **Agent roster** — no table of which agents ran, their models, and which phases they served
5. **Phase durations** — the template specifies per-phase durations with agent attribution, but the orchestrator emits a simpler status-only table

These gaps exist in both the current report output and the generator template instructions.

## Changes

### 1. Generator Template — `phase-group-finalization.md` (lines 454-543)

Replace the Run Statistics appendix spec with 6 subsections. The appendix is only emitted when `VERBOSE_REPORT=true` (unchanged).

#### 1A. Run Metadata table

```markdown
### Run Metadata

| Field | Value |
|-------|-------|
| Generated | <ISO 8601 UTC timestamp> |
| Invocation | `/create-threat-model <INVOCATION_ARGS>` |
| Assessment Mode | <Full scan (initial) / Full (--full) / Incremental (auto) / Incremental (--incremental)> |
| Plugin Version | appsec-plugin <PLUGIN_VERSION> (analysis v<ANALYSIS_VERSION>) |
| Assessment Depth | <quick / standard / thorough> (components: <N>, STRIDE turns: <S>/<M>/<C>) |
| Repository | `<REPO_ROOT>` |
| Baseline SHA | `<BASELINE_SHA>` or n/a (first full run) |
| Current SHA | `<CURRENT_SHA>` |
```

**Change from current:** adds the `Invocation` row (the CLI call). Values are populated by the orchestrator during Phase 11 composition from variables already in scope.

#### 1B. Agents & Models table (new)

```markdown
### Agents & Models

| Agent | Model | Role | Phases |
|-------|-------|------|--------|
| threat-analyst | <model> | Orchestrator — architecture, controls, synthesis, finalization | 1, 3-8, 10-11 |
| context-resolver | <model> | Resolves repo context and business docs | 1 |
| recon-scanner | <model> | Tech stack and security pattern reconnaissance | 2 |
| dep-scanner | <model> | SCA dependency vulnerability scan | 2 (only when WITH_SCA=true) |
| stride-analyzer | <model> | Per-component STRIDE threat analysis | 9 (<N> instances) |
| qa-reviewer | <model> | Cross-reference validation, link fixes, consistency | Post-assessment |
```

**Populated from:** `AGENT_INVOKE` / `AGENT_START` lines in `.agent-run.log`. Only agents that actually ran are listed (e.g., dep-scanner is omitted when `WITH_SCA=false`, context-resolver is omitted on cache hit). The `qa-reviewer` row is always included with `_pending_` model — patched by the skill layer after Stage 2 completes.

**Phase 9 detail:** show instance count in parentheses, e.g., "9 (5 instances)".

#### 1C. Phase Duration Breakdown (enhanced)

Same table structure as current but with stricter agent attribution:

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

**Change from current:** the Agent(s) column is mandatory and must always be filled with the actual agent name and model in parentheses. Duration values extracted from PHASE_START/PHASE_END timestamp pairs in `.agent-run.log`. Assessment Total, QA Review, and Grand Total rows are `_pending_` — patched by the skill layer.

#### 1D. Token Consumption table (new subsection, replaces inline rows)

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

All values are `_pending_` — patched by QA reviewer Check 12 using `verify_run_costs.py` output.

#### 1E. Cost Estimate table (new subsection, replaces inline rows)

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

**Column headers:** dynamically determined from `agent_models` — show one column per unique model used. When only one model is used, show a single value column. The pricing reference table is static and always included.

**Billing label:** "Actual cost" when `billing=api` (ANTHROPIC_API_KEY detected), "Estimated cost" when `billing=subscription`.

All `_pending_` values are patched by QA reviewer Check 12.

#### 1F. Coverage Summary (unchanged)

Same structure as current — components, threats by severity, mitigations, controls, attack surface, trust boundaries, assets.

### 2. YAML Schema — `phase-group-finalization.md` (lines 9-31)

Add `run_statistics` under `meta:` after `recommend_full_rerun`:

```yaml
  run_statistics:                       # populated by QA Check 12; null until then
    tokens:
      input: <int>
      output: <int>
      cache_write: <int>
      cache_read: <int>
      total: <int>
    cost:
      billing: <api|subscription>       # "api" when ANTHROPIC_API_KEY is set
      models:                           # one entry per unique model used
        <model-key>:                    # e.g. "sonnet-4-6", "opus-4-6"
          with_caching: <float>
          without_caching: <float>
      cache_savings_pct: <float>
      cost_verified: <bool>             # true after QA Check 12 cross-check passes
    agents:                             # roster of agents used in this run
      - name: <string>                  # e.g. "threat-analyst"
        model: <string>                 # e.g. "claude-sonnet-4-6"
        role: <string>                  # e.g. "Orchestrator"
        phases: <string>               # e.g. "1, 3-8, 10-11"
```

This replaces the current flat `tokens_total`, `estimated_cost`, `cost_verified` fields. The old fields are removed.

**Written by Phase 11:** the `run_statistics` block is written with `null` values for tokens/cost (they aren't available yet) and populated `agents` list (available from log data).

**Patched by QA Check 12:** tokens and cost sections are filled from `verify_run_costs.py` output.

### 3. QA Reviewer Check 12 — `appsec-qa-reviewer.md` (lines 989-1031)

Update Check 12c to target the new table structures:

**Token Consumption table patching:** same as current — replace `_pending_` rows with verified delta values from `totals.in`, `totals.out`, `totals.cache_write`, `totals.cache_read`, `totals.total_tokens`.

**Cost Estimate table patching:** replace `_pending_` cells in the multi-column table. For each model in `mixed_model_costs`:
- "With prompt caching" → `mixed_model_costs[model].cached` (prefix `~` for subscription)
- "Without prompt caching" → `mixed_model_costs[model].no_cache` (prefix `~` for subscription)
- "Cache savings" → `totals.cache_savings_pct`%

If `mixed_model_costs` is null (single model), use `totals.cost` and `totals.no_cache_cost` in a single column.

Replace the billing `_pending_` with `api` or `subscription (estimated)`.

**YAML patching:** replace `null` values in `meta.run_statistics.tokens` and `meta.run_statistics.cost` with verified data from `verify_run_costs.py`. Set `cost_verified: true` on cross-check OK.

### 4. Skill Layer Console Summary — `SKILL.md`

Update the "Run Statistics" section in the console summary (printed after Stage 2) to include the same enhanced data:

```
  -- Run Statistics --------------------------------------------
  Total Duration      : Xm YYs  (assessment: Xm YYs + QA review: Xm YYs)
    Phase 1  Context Resolution     : context-resolver (sonnet-4-6) :  0m 29s
    Phase 2  Reconnaissance         : recon-scanner (sonnet-4-6)    :  1m 52s
    ...
    Phase 9  STRIDE Enumeration     : 5x stride-analyzer (opus-4-6) :  2m 57s
    ...
  Agents              : threat-analyst=sonnet-4-6, recon-scanner=sonnet-4-6, stride-analyzer=opus-4-6, qa-reviewer=sonnet-4-6
  Tokens              : 358,475 total (in: 18, out: 6,613, cache_write: 142,204, cache_read: 209,640)
  Est. Cost           :
    sonnet-4-6 rates  : ~$0.70 cached / ~$1.15 no cache
    opus-4-6 rates    : ~$3.48 cached / ~$5.77 no cache
    Cache savings     : 39.8%
    Billing           : subscription (estimated)
```

### 5. Current Report Patch — `threat-model.md`

After implementing the generator changes, patch the current report's Run Statistics section with the full data available from the just-completed run. Use data from:
- `.agent-run.log` — phase timing, agent names/models
- `verify_run_costs.py --json` — tokens, costs, mixed-model estimates
- `threat-model.yaml` — metadata (invocation, SHAs, mode, etc.)

## Data Flow

```
Phase 11 (orchestrator)
  ├── Writes: Run Metadata, Agents & Models, Phase Durations, Coverage Summary
  ├── Writes: Token/Cost tables with _pending_ placeholders
  └── Writes: YAML meta.run_statistics with null tokens/cost, populated agents

QA Check 12 (qa-reviewer)
  ├── Runs: verify_run_costs.py --json
  ├── Patches: Token Consumption table in MD
  ├── Patches: Cost Estimate table in MD
  └── Patches: meta.run_statistics.tokens/cost in YAML

Skill layer (post-Stage 2)
  ├── Patches: Assessment Total / QA Review / Grand Total duration rows
  ├── Patches: qa-reviewer model in Agents & Models table (if still _pending_)
  └── Prints: Console summary with full data
```

## Files Modified

| File | Change |
|------|--------|
| `claude-plugin/agents/phases/phase-group-finalization.md` | Replace Run Statistics appendix spec (lines 454-543) with enhanced 6-subsection template; add `run_statistics` to YAML schema (lines 28-31) |
| `claude-plugin/agents/appsec-qa-reviewer.md` | Update Check 12c patching instructions (lines 989-1019) to target new table structures and new YAML fields |
| `claude-plugin/skills/create-threat-model/SKILL.md` | Update console summary format (lines 530-623) with token breakdown, multi-model costs, agent roster |
| `juice-shop/docs/security/threat-model.md` | Patch current report's Run Statistics with full data from this run |
| `juice-shop/docs/security/threat-model.yaml` | Add `run_statistics` block to meta section |

## Non-Goals

- No changes to `verify_run_costs.py` — it already produces all needed data
- No changes to `.agent-run.log` format — existing log lines have sufficient data
- No changes to `.hook-events.log` format
- No schema_version bump — `run_statistics` is additive and optional; existing consumers ignore unknown keys
