# Phase Group: Threat Enumeration & Synthesis (Phases 9–10)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 9: STRIDE Threat Enumeration — via sub-agents

**⚠ SEQUENCING: STRIDE analyzers MUST NOT be dispatched before Phase 9.** They require outputs from Phases 6 (INTERFACES), 7 (TRUST_BOUNDARIES), and 8 (CONTROLS).

### Incremental Mode — Per-Component Dispatch Decision

When `INCREMENTAL=true`, the orchestrator does **not** dispatch a STRIDE analyzer for every selected component. Instead, for each component from the baseline `threat-model.yaml.components[]`, decide between four paths:

1. **Re-dispatch** — if `component ∈ SECURITY_RELEVANT_COMPONENTS` (changed files map to this component AND the security relevance filter classified at least one of those files as security-relevant), re-run the STRIDE analyzer as for a full scan. Overwrite `.stride-<component-id>.json`. **New threats get fresh T-IDs** from `.appsec-cache/baseline.json.id_counters.next_threat_id`; **existing threats keep their T-IDs** if the analyzer produces the same finding (match on `component_id` + `cwe` + `title` fingerprint).
2. **Carry forward** — if no changed file maps to this component, **reuse** the existing `.stride-<component-id>.json`. Verify its integrity first:
   ```bash
   # Pseudocode — the orchestrator inlines this as a Bash call
   EXPECTED=$(python3 -c "import json; print(json.load(open('$OUTPUT_DIR/.appsec-cache/baseline.json'))['stride_files'].get('$COMPONENT_ID', {}).get('sha256', ''))")
   ACTUAL="sha256:$(sha256sum "$OUTPUT_DIR/.stride-$COMPONENT_ID.json" | awk '{print $1}')"
   [ "$EXPECTED" = "$ACTUAL" ] && echo "CARRY_FORWARD_OK" || echo "CARRY_FORWARD_HASH_MISMATCH"
   ```
   On `CARRY_FORWARD_OK`, read the file directly. On `CARRY_FORWARD_HASH_MISMATCH` (someone hand-edited the file, or the baseline cache is out of sync), fall back to re-dispatch.
3. **Carry forward (low-risk delta)** — if `changed_files ∩ component.paths ≠ ∅` BUT the security relevance filter classified ALL of those files as non-security-relevant (only cosmetic/documentation/styling changes), carry forward the existing `.stride-<component-id>.json` using the same integrity check as path 2. Track as `LOW_RISK_SKIPPED_COMPONENTS` with `skip_reason: "non-security changes only"`. This avoids expensive STRIDE re-analysis for changes like comment edits, CSS fixes, or logging updates within a component's directory.
4. **Fresh analysis for new components** — if the diff contains a new Dockerfile, service directory, or otherwise introduces a component that was not in baseline `components[]`, dispatch a fresh STRIDE analyzer with new T-IDs pulled from the counter.

**Removed components** — if a component from baseline `components[]` has all its `paths` gone from the repo (directory deleted, Dockerfile removed), mark every one of its threats as `status: resolved` with `resolution_reason: "component removed"` and add them to the new changelog entry's `resolved.threats`. Do not delete the yaml entries — the out-of-scope / resolved records stay as historical context.

**Security relevance filter** — the filter runs as part of the delta detection in the orchestrator (see `appsec-threat-analyst.md` → "Security Relevance Filter" section). By Phase 9, `SECURITY_RELEVANT_COMPONENTS` and `LOW_RISK_SKIPPED_COMPONENTS` are already computed. The filter is a Python script (`scripts/security_relevance_filter.py`) that uses path/extension heuristics and diff content pattern matching — no LLM calls.

**Dirty-set computation — run ONCE at the start of Phase 9:**

```bash
# Assumes BASELINE_SHA was resolved in the Incremental Mode section of appsec-threat-analyst.md
if [ "$INCREMENTAL" = "true" ]; then
  CHANGED_FILES=$(git -C "$REPO_ROOT" diff --name-only "$BASELINE_SHA"..HEAD 2>/dev/null; git -C "$REPO_ROOT" diff --name-only 2>/dev/null)
  CHANGED_FILES=$(echo "$CHANGED_FILES" | sort -u | sed '/^$/d')
  echo "CHANGED_FILES ($(echo "$CHANGED_FILES" | wc -l)):"
  echo "$CHANGED_FILES"
fi
```

For each `component` in `threat-model.yaml.components[]`, use its `paths[]` globs to decide membership. A component is **dirty** if any `changed_file` matches any `path` glob. Store the dirty set as `DIRTY_COMPONENTS` (space-separated component IDs) for reference by the dispatch loop below.

**Changelog accounting** — track these lists during Phase 9 so Phase 11 can write the changelog entry:

- `REANALYZED_COMPONENTS` — components re-dispatched (security-relevant dirty set + new components)
- `CARRIED_FORWARD_COMPONENTS` — components whose `.stride-<id>.json` was reused (no changed files)
- `LOW_RISK_SKIPPED_COMPONENTS` — dirty components skipped because the security relevance filter classified all their changes as non-security-relevant
- `REMOVED_COMPONENTS` — baseline components with no surviving paths
- `ADDED_THREATS` — T-IDs minted in this run
- `CHANGED_THREATS` — T-IDs that existed before but whose fingerprint changed
- `RESOLVED_THREATS` — T-IDs from removed or re-analyzed components that were not re-produced

When `INCREMENTAL=false`, skip this whole decision tree and select components as described under "Component Selection" below.

### Component Selection

Always include: Auth/identity, Authorization, components handling PII/payments, Admin panel, Public API gateway. For Moderate/Complex: each backend service, frontend SPA, queue consumers, CI/CD pipeline. **Cap at `MAX_STRIDE_COMPONENTS`** (default 5, set by `--assessment-depth`).

**Frontend SPA override:** If the recon scanner detected a frontend framework (Section 7.19) or client-side code patterns (Sections 7.10, 7.20–7.24), the frontend SPA MUST be included as a STRIDE component at **all** depth levels, including `quick`. The browser is a large, distinct attack surface that cannot be skipped. This overrides the component cap — if adding the frontend exceeds `MAX_STRIDE_COMPONENTS`, drop the lowest-risk non-auth component instead.

| ASSESSMENT_DEPTH | MAX_STRIDE_COMPONENTS | Selection strategy |
|-----------------|----------------------|-------------------|
| `quick` | 3 | Auth + highest-risk component + public API (+ frontend SPA if detected, see override above) |
| `standard` | 5 | Auth, AuthZ, PII/payment, Admin, public API, frontend SPA |
| `thorough` | 8 | All mandatory + backend services, frontend, queues, CI/CD pipeline |

### CI/CD Pipeline as STRIDE component

**When `ASSESSMENT_DEPTH=standard` or `thorough`** and CI/CD workflow files were found by the recon scanner (Section 5): include the CI/CD pipeline as a STRIDE component if it fits within `MAX_STRIDE_COMPONENTS`. Use component ID `ci-cd-pipeline`.

Pass these additional context fields in the STRIDE analyzer prompt:
- `COMPONENT_DESCRIPTION`: "CI/CD pipeline — build, test, and deployment automation. Includes workflow definitions, secret handling, artifact publishing, and deployment triggers."
- `INTERFACES`: workflow trigger events (push, PR, schedule, workflow_dispatch), artifact registries, deployment targets
- `TRUST_BOUNDARIES`: external Actions/images crossing into build environment, secrets injected at runtime, artifact publish boundary
- `SUPPLY_CHAIN_FINDINGS`: recon-summary sections 7.14–7.17, 7.26, 7.27, and 7.28 (unpinned Actions, container images, dependency confusion, postinstall hooks, ecosystem CI install integrity, dependency management tooling, SCA tooling, `pull_request_target` misuse, `permissions:` hardening, self-hosted runner exposure, AI coding assistant & IDE agent configurations)

The STRIDE analyzer will use `SUPPLY_CHAIN_FINDINGS` to generate evidence-backed threats for the pipeline component (see STRIDE analyzer supply chain patterns).

### Taxonomy slice pre-dispatch (mandatory)

**Before dispatching any STRIDE analyzer**, generate component-specific taxonomy slices to reduce per-analyzer input tokens. Run all slice commands in a **single batched Bash call**:

```bash
# Batch taxonomy slicing — one command per component, all in one Bash call
for cid_and_type in "<COMPONENT_ID>:<COMPONENT_TYPE>" ...; do
  cid="${cid_and_type%%:*}"
  ctype="${cid_and_type##*:}"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/slice_taxonomy.py" "$ctype" "$OUTPUT_DIR" \
    --component-id "$cid" \
    --data-dir "$CLAUDE_PLUGIN_ROOT/data" \
    --taxonomies "threats,cwe,controls,chains" \
  || echo "BASH_WARN: taxonomy slice failed for $cid — STRIDE analyzer will use full taxonomies"
done
```

**COMPONENT_TYPE** is derived from the component's COMPONENT_ID and COMPONENT_DESCRIPTION:
- ID contains `frontend`, `spa`, `web`, `react`, `angular`, `vue`, `client` → type `frontend`
- ID contains `auth`, `identity`, `login`, `session`, `jwt`, `oauth` → type `auth`
- ID contains `admin`, `management`, `dashboard`, `backoffice` → type `admin`
- ID contains `database`, `db`, `repository`, `datastore` → type `database`
- ID contains `ci-cd`, `cicd`, `pipeline`, `build` → type `ci-cd`
- ID contains `websocket`, `realtime`, `socket`, `streaming` → type `realtime`
- Any other component (generic backend, API gateway, etc.) → type `backend-api`

For unknown types, `slice_taxonomy.py` writes a full passthrough slice (exit 1, non-fatal — the analyzer reads the same data as before). The STRIDE analyzer reads from `$OUTPUT_DIR/.taxonomy-slices/<COMPONENT_ID>/` when `TAXONOMY_SLICE_DIR` is passed; this dir is cleaned up by `runtime_cleanup.py` at post-QA.

### Dispatch

**Pre-dispatch echo (user-visible manifest, once per run — mandatory since v0.9.1):** Immediately before the parallel `Agent` dispatch block (and together with the `AGENT_INVOKE` batch below), print **one purpose line plus one line per component** so the user sees exactly what is about to be analyzed in parallel. The per-component line includes id, complexity tier, and turn budget so the expected wall-clock differences are visible up front.

Format:
```
  ⟶ Dispatching stride-analyzer × <N> components (parallel) — per component: enumerate Spoofing/Tampering/Repudiation/Information-Disclosure/DoS/EoP threats with CWE + file:line evidence → .stride-<id>.json
     • <component-name> (<component-id>, <simple|moderate|complex>, MAX_TURNS=<n>)
     • <component-name> (<component-id>, <simple|moderate|complex>, MAX_TURNS=<n>)
     …
```

Batch the echoes with the `AGENT_INVOKE` Bash call below so no extra turn is spent.

For each component, use Agent tool:
- `subagent_type`: `appsec-advisor:appsec-stride-analyzer`
- `description`: `STRIDE analysis for <COMPONENT_NAME>`
- `run_in_background`: `true`
- `prompt`: **emit the parameters in the order below.** The three groups are ordered by cache-friendliness — stable values across all dispatches come first so the Claude Code prompt-cache prefix covers them; component-specific values come next; large volatile JSON blobs come last. See CLAUDE.md → "Prompt caching contract" for the full rationale.

  **Group A — stable across every STRIDE dispatch (cache-friendly prefix):**
  `REPO_ROOT`, `OUTPUT_DIR`, `COMPLIANCE_SCOPE`, `ASSET_TIER`, `TAXONOMY_SLICE_DIR` (path only; the file contents differ per component but the path template is stable)

  **Group B — component-specific scalars and short lists:**
  `COMPONENT_ID`, `COMPONENT_NAME`, `COMPONENT_DESCRIPTION`, `COMPONENT_COMPLEXITY`, `MAX_TURNS`, `ESTIMATED_THREAT_COUNT`, `INTERFACES`, `TRUST_BOUNDARIES`, `CONTROLS`, `KNOWN_SECRETS`, `KNOWN_VULNS`, `KNOWN_LLM_PATTERNS`, `SUPPLY_CHAIN_FINDINGS` (for `ci-cd-pipeline` component only, from recon-summary 7.14–7.17 and 7.26)

  **Group C — large volatile JSON blobs (emit LAST):**
  `PRIOR_FINDINGS_INDEX` (inline JSON slice for this component from `.prior-findings-index.json`, or `none`), `KNOWN_THREATS_INDEX` (inline JSON slice for this component, or `none`), `CROSS_REPO_CONTEXT` (see below)

**Prior-findings index propagation (mandatory):** The orchestrator passes a component-scoped JSON slice of `$OUTPUT_DIR/.prior-findings-index.json` as the `PRIOR_FINDINGS_INDEX` parameter. The STRIDE analyzer uses this instead of reading `.threat-modeling-context.md` — Phase 1 has already extracted file/line/excerpt for every prior finding. Do **not** pass `CONTEXT_FILE` as a parameter; the STRIDE analyzer no longer needs it when the index is populated. Only pass `CONTEXT_FILE` when a prior finding indicates deeper context (e.g. a known-threat row with cross-component dependencies) and the JSON index is insufficient.

**Cross-repo context propagation:** When `.threat-modeling-context.md` contains a **Cross-Repository Dependency Threat Models** section with entries, the orchestrator extracts a component-scoped slice as `CROSS_REPO_CONTEXT`. For each STRIDE component, include only the cross-repo dependencies that the component directly communicates with (match via interfaces/trust boundaries). Format as inline JSON:

```json
CROSS_REPO_CONTEXT=[
  {"name":"auth-service","type":"scm-sibling","threat_model":"found","threats_open":3,"threats_critical":1,"interface":"REST API"},
  {"name":"Stripe","type":"saas","threat_model":"n/a","interface":"SDK"}
]
```

If the component has no cross-repo interfaces, pass `CROSS_REPO_CONTEXT=none`. The STRIDE analyzer uses this to:
- **Elevate risk** at trust boundaries where the sibling has no threat model (`threat_model: missing`) — add a note to affected threats: "Upstream service `<name>` has no threat model; threats at this boundary may be underestimated."
- **Cross-reference** open threats from siblings with a threat model — if the sibling has Critical/High open threats at the shared interface, consider how those threats propagate into this component.
- **SaaS shared responsibility** — for SaaS dependencies, consider the shared responsibility boundary: the SaaS provider secures their infrastructure, but API key management, webhook validation, and data handling remain the consumer's responsibility.

**Dynamic turn budget:** Pass `MAX_TURNS=<N>` in the prompt, using the depth-adjusted values from the skill:
- Simple components: `MAX_TURNS=STRIDE_TURNS_SIMPLE` (quick: 10, standard: 15, thorough: 20)
- Moderate components: `MAX_TURNS=STRIDE_TURNS_MODERATE` (quick: 15, standard: 22, thorough: 28)
- Complex components: `MAX_TURNS=STRIDE_TURNS_COMPLEX` (quick: 20, standard: 31, thorough: 35)

If the `STRIDE_TURNS_*` variables are not set, use the standard defaults (15/22/31).

**Thin-component cap (mandatory):** Before dispatching, inspect the component's pre-estimate using the recon data already in working memory. If **all** the following hold, cap the turn budget at **8** instead of the depth-based default:

1. The component has fewer than 3 interfaces in `INTERFACES`
2. Recon Section 9 lists fewer than 5 source files tied to this component's entry points
3. Recon Section 7.8 (dangerous sinks) lists **zero** matches for this component's files
4. Recon Section 7.12 (hardcoded secrets) lists **zero** matches for this component's files

Pass `MAX_TURNS=8` and `ESTIMATED_THREAT_COUNT=low` in this case — the analyzer uses the low estimate to skip coverage reruns and cut short after the six STRIDE passes.

**Moderate pre-estimate:** If the component has 3–6 interfaces and ≤2 dangerous sink matches, pass `ESTIMATED_THREAT_COUNT=moderate` and the standard `STRIDE_TURNS_MODERATE` budget.

**Complex pre-estimate:** Pass `ESTIMATED_THREAT_COUNT=high` and `STRIDE_TURNS_COMPLEX` when the component has ≥7 interfaces, or ≥3 dangerous sink matches, or is explicitly called out as high-risk (auth service, payment processor, admin panel with privileged operations).

The `ESTIMATED_THREAT_COUNT` parameter lets the analyzer decide whether it can afford expensive verification grepping or should stay lean. It is advisory — the analyzer may still record more threats than estimated if evidence warrants it.

Dispatch all simultaneously with `run_in_background: true`. **Each component MUST be dispatched as a separate Agent tool call** using `subagent_type: "appsec-advisor:appsec-stride-analyzer"` and `model: $STRIDE_MODEL` (the reasoning-model-resolved ID — overrides the agent's frontmatter default). Issue all Agent calls in a single orchestrator turn (parallel tool calls). Do NOT perform STRIDE analysis inline in the orchestrator — the orchestrator does not have the STRIDE prompt and cannot produce the structured `.stride-<id>.json` output format. Then enter the progress-polling loop described below.

**⚠ MANDATORY per-component dispatch log (since M2.7):** Background agents spawned via `run_in_background: true` do **not** reliably emit `AGENT_INVOKE` log lines through the hook logger — production runs showed only 1 of 5 dispatched STRIDE analyzers logged. The orchestrator MUST therefore emit its own `AGENT_INVOKE` and `AGENT_DONE` lines explicitly, one per component, so `.agent-run.log` shows which components were analyzed and how long each one took. Emit the lines in a single batched Bash call **immediately before** the Agent tool dispatch block and **immediately after** the Validation & Retry step (once each `.stride-<id>.json` is present):

```bash
# Before dispatch — one line per component (batch all into one Bash call):
for cid in <comp-id-1> <comp-id-2> <comp-id-n>; do
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   stride-analyzer  AGENT_INVOKE   STRIDE analysis for $cid (model: $STRIDE_MODEL, MAX_TURNS=$TURNS)" >> "$OUTPUT_DIR/.agent-run.log"
done
```

```bash
# After Validation & Retry — one line per component with file size as a proxy for work done:
for f in "$OUTPUT_DIR"/.stride-*.json; do
  cid=$(basename "$f" .json | sed 's/^\.stride-//')
  sz=$(wc -c < "$f" 2>/dev/null || echo 0)
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   stride-analyzer  AGENT_DONE     STRIDE analysis for $cid complete (${sz} bytes)" >> "$OUTPUT_DIR/.agent-run.log"
done
```

Both templates run in one Bash turn each — no per-component turn overhead. The `AGENT_INVOKE` lines must be emitted **before** the `Agent` tool dispatches so they appear before the long polling loop in chronological order. The `AGENT_DONE` lines must be emitted **after** Validation & Retry so a missing stride file does not get a false "done" entry.

### Progress polling loop (mandatory — replaces the old "poll for output files" step)

Each dispatched `appsec-stride-analyzer` writes `$OUTPUT_DIR/.progress/<component-id>.json` at the start of each of its 9 substeps (Loading context, Reading source files, the six STRIDE letters, Writing output). The orchestrator polls these files so the user sees real sub-agent progress instead of a silent wait.

**Per-poll Bash call (one orchestrator turn per round):**

```bash
sleep 20 && PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" --heartbeat >/dev/null 2>&1 && python3 "$CLAUDE_PLUGIN_ROOT/scripts/stride_progress.py" "$OUTPUT_DIR" <EXPECTED> 2>&1 | sed "s/^/  ↳ (+${ES}) /"; echo "exit=$?"
```

Skip the leading `sleep 20 && ` on the **first** poll so the user sees the initial state immediately after dispatch.

**Heartbeat pulse.** Each poll refreshes the lock's heartbeat via `acquire_lock.py --heartbeat`. This keeps `$OUTPUT_DIR/.appsec-lock` marked "fresh" so a concurrent `/appsec-advisor:status` or next-run pre-flight does not mistakenly classify the lock as hung. Conversely, if the orchestrator itself stalls (extended thinking without emitting any Bash calls) the heartbeat stops advancing and after 5 minutes the lock is classified `hung` by the next `acquire_lock.py` invocation — freeing the resource without a 1-hour wait. The heartbeat call is silent (`>/dev/null 2>&1`) so it does not add noise to the progress output.

**Control flow:**

1. Print `  ↳ [<k>/<N>] Polling <EXPECTED> STRIDE analyzers…` and fire the first poll call (no sleep)
2. Read `exit=` at the end of the Bash output
3. If `exit=0` — every `.stride-<id>.json` output file exists → exit the loop and proceed to **Validation & Retry**
4. If `exit=1` — not ready yet → issue the next poll Bash call (with the leading `sleep 20 &&`)
5. Cap the loop at **12 rounds** (≈ 4 minutes of waiting). On the 12th round still returning `exit=1`, log a `BASH_WARN` line like `STRIDE poll cap reached — proceeding with <ready>/<EXPECTED> outputs present` and fall through to Validation & Retry. Missing components get the normal "skip if still invalid" handling.

The script prints one line of the form:

```
[stride] 3/5 ready  —  Auth Service [4/9 Tampering] · REST API [2/9 reading sources] · Frontend SPA ✓ · Admin ✓ · Public API [1/9 starting]
```

A trailing `⧗` marker on a component means its progress file has not been updated for more than 3 minutes — typically a hint that the sub-agent is stuck on a long tool call or has exhausted its turn budget. If the same component shows `⧗` for three consecutive rounds, the orchestrator may break out of the loop early and rely on Validation & Retry to recover.

### Validation & Retry

Validate each `$OUTPUT_DIR/.stride-<id>.json`. On failure: retry once synchronously, skip if still invalid.

### Hybrid merger (optional — activated by MERGER_MODEL)

When `$MERGER_MODEL` is set to an Opus identifier (opt-in via `--reasoning-model opus-cheap` or `opus`, default at `--assessment-depth thorough`), the orchestrator may delegate the dedup-judgment portion of the merge to `appsec-threat-merger`. The inline "Merge" section below remains the authoritative specification — the hybrid path is a drop-in replacement for Steps 4–5 (dedup + systemic consolidation) that offloads those judgments to a focused Opus call.

Pipeline:

1. **Collect** — `python3 "$CLAUDE_PLUGIN_ROOT/scripts/merge_threats.py" collect --output-dir "$OUTPUT_DIR"`
   - Reads all `.stride-*.json`, runs mechanical exact-dedup (same CWE + STRIDE + evidence.file + line), groups near-duplicate candidates (shared CWE + STRIDE letter with ≥2 members), writes `$OUTPUT_DIR/.merge-candidates.json`.
   - If the resulting `candidate_group_count` is `0`, **skip the merger dispatch entirely** — no ambiguous groups means nothing for LLM judgment.

2. **Dispatch `appsec-threat-merger`** (only when candidates exist):

   Print before dispatch:
   ```
     ⟶ Dispatching threat-merger — deduplicates <n> candidate groups via CWE + component + title fingerprint → merge decisions feed .threats-merged.json  (expect ~30s)
   ```

   ```
   subagent_type: "appsec-advisor:appsec-threat-merger"
   description: "Dedup / consolidate candidate threat groups"
   model: $MERGER_MODEL
   run_in_background: false
   prompt: |
     REPO_ROOT=<REPO_ROOT>
     OUTPUT_DIR=<OUTPUT_DIR>
     MODEL_ID=<MERGER_MODEL>
     CANDIDATES_FILE=<OUTPUT_DIR>/.merge-candidates.json
     COMPONENT_MAP=<inline JSON of {component_id: {name, trust_boundaries}}>
   ```
   Log `AGENT_INVOKE` / `AGENT_DONE` in the same style as the triage-validator dispatch above, using `$MERGER_MODEL` in the message.

3. **Finalize** — `python3 "$CLAUDE_PLUGIN_ROOT/scripts/merge_threats.py" finalize --output-dir "$OUTPUT_DIR"`
   - Reads `.merge-candidates.json` + (if present) `.merge-decisions.json`, applies decisions, performs the deterministic 8-field sort, assigns `T-001`..`T-NNN`, writes `.threats-merged.json`.
   - If `.merge-decisions.json` is missing (merger failed or was skipped), every candidate group is treated as "keep all" — no dedup, but no data loss.

The hybrid path produces a `.threats-merged.json` whose schema is byte-compatible with the inline merge output — downstream steps (coverage checks, Phase 10 SCA synthesis, Phase 10b triage validation) do not need to know which path produced the file.

**Fallback rule:** if the hybrid path fails at any step (non-zero exit from `merge_threats.py`, missing output, or merger dispatch error), the orchestrator logs `BASH_WARN` and falls back to the inline Merge section below for this run.

### Merge

0. **Build the `known_vulns_seen` set** for Phase 10 pre-filtering. While iterating the raw STRIDE outputs, collect every `(component_id, cve_id, evidence.file)` tuple from threats whose source is `KNOWN_VULNS`. Keep the set in working memory — Phase 10 Step 2 uses it to deduplicate SCA findings in O(1) per candidate.
1. Merge all threat lists + Phase 8b threat candidates (if requirements enabled)
2. **Priority-aware risk for requirement threats:** For threats sourced from `requirements-compliance` or `architectural-anti-pattern`, apply the priority-derived minimum risk from Phase 8b (MUST FAIL ≥ High, architectural violations escalated by one level). If the standard Likelihood × Impact risk is already higher, keep the higher value.
3. **Assign global IDs deterministically.** Apply the full lexicographic sort key below to the merged threat list, then iterate once and assign `T-001`, `T-002`, … in order. Every field must be evaluated — no tie-breaker is optional. Two runs on an unchanged codebase MUST produce the same T-NNN for the same underlying threat.

   Sort key (compare left-to-right, first non-equal field wins):

   1. `architectural_violation` — `true` before `false` (systemic issues lead their risk tier)
   2. `risk` — Critical → High → Medium → Low
   3. `stride` — S → T → R → I → D → E (fixed category order, never alphabetical)
   4. `component_id` — alphabetical (case-insensitive)
   5. `cwe` — numeric ascending, parsing the integer after `CWE-` (threats without a CWE sort last within this field)
   6. `evidence.file` — alphabetical (repo-relative path)
   7. `evidence.line` — numeric ascending (threats with `null` line sort last)
   8. `title` — alphabetical (final tie-break; should not be reached when fields 1–7 are populated)

   Do not reorder after assignment. The sort is the single source of truth for T-NNN ordering — any later per-section display sort MUST derive from the same key (see §8 split-by-severity rule).
4. Deduplicate same root cause across components
5. **Systemic-threat consolidation (mandatory).** When three or more threats share the **same root cause** but appear on different endpoints or components, consolidate them into a single *systemic* entry. The most common patterns:
   - **IDOR / Missing ownership checks** on multiple resource endpoints (wallet, order-history, user-data, memories) — consolidate into one threat titled e.g. "Systemic IDOR — missing ownership checks across authenticated resource endpoints" with the individual endpoints listed as sub-items in the Threat Scenario cell
   - **Raw SQL string interpolation** across multiple route handlers — consolidate into one threat when the defect is the same pattern
   - **Unauthenticated management endpoints** (/metrics, /ftp, /logs, /api-docs) — consolidate when the root cause is "missing auth middleware on management routes"
   - **bypassSecurityTrustHtml / disabled sanitization** across multiple frontend components — consolidate when the root cause is "sanitizer bypass"
   
   Consolidated threats use the highest severity among the merged items and list every affected endpoint in the Scenario cell as a bullet list. Individual endpoint rows are removed from the register. The consolidated threat links to the Cross-Cutting Architecture Finding (Section 2.x) that explains the systemic pattern.
   
   **Do not consolidate** when the root causes differ (e.g. SQL injection and NoSQL injection are different defects even though both are injection). **Do not consolidate** when only two threats share a root cause — the overhead of a systemic entry is only justified at three or more.
6. Cross-reference prior findings from `$OUTPUT_DIR/.threat-modeling-context.md`
7. Known threats integration (open → verify, accepted → Section 10, mitigated → verify, false-positive → skip)
8. **Normalize component names:** Each unique component in the merged threat list must use a single consistent name. If the same component has different names from different analyzers (e.g., "Auth Service" vs "Auth Module"), unify to one name — use the name from the STRIDE analyzer dispatch prompt (`COMPONENT_NAME`). Do not use variant names like "Auth Service / API" alongside "Auth Module" for the same component.

### Coverage Checks

**When `ASSESSMENT_DEPTH=quick`:** Skip all coverage checks — the STRIDE analysis itself is sufficient at quick depth. Proceed directly to Merge.

**When `ASSESSMENT_DEPTH=standard` or `thorough`:**

**Checks A and D run deterministically via `scripts/coverage_checks.py`** (Sprint 2 Item #6). Issue one Bash call before starting the inline Merge — the script reads `.threats-merged.json` and `.threat-modeling-context.md` and emits a JSON report listing OWASP-2021 categories with zero coverage plus cross-repo boundaries whose upstream threat model is missing. For every gap, the report includes a ready-to-merge `suggested_threat` block tagged `source: coverage-gap`. Inject each suggested_threat into the merged threat list with a fresh T-ID (follow the Phase 10 finalize ID assignment rules) and do not re-evaluate via LLM — the script's classification is authoritative.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/coverage_checks.py" all --output-dir "$OUTPUT_DIR" > "$OUTPUT_DIR/.coverage-gaps.json"
```

Parse the JSON:
- `owasp.missing[].suggested_threat` — one entry per uncovered OWASP category. Append to the merged threat list as-is. `component_id` is `null` (component-agnostic); optionally re-scope to the highest-risk component if evidence warrants.
- `cross_repo.uncovered_boundaries[].suggested_threat` — one entry per dependency whose threat model is missing AND whose name/interface is not mentioned in any threat. Append to the merged threat list as-is.
- `gap_count` — total gap-threat count; include in the Phase 9 summary log line.

**A — OWASP Top 10 (deterministic, via script):** Set-membership check of threat CWEs against `data/owasp-top10-cwes.yaml` (10 categories, 2021 mapping). Gaps surface as `coverage_category: A0N:2021` gap-threats. No LLM involvement.

**B — Business logic (LLM):** Check workflow bypass, privilege abuse, mass enumeration, economic abuse, state manipulation. This check requires judgement over workflow semantics and remains inline.

**C — OWASP LLM Top 10 (LLM, conditional):** If AI/LLM integration was detected in recon (Section 7.13), verify coverage for each applicable LLM threat category. Skip if no LLM detected. Judgement-heavy — remains inline.

**D — Cross-repository boundary coverage (deterministic, via script):** The script parses the "Cross-Repository Dependency Threat Models" section of `.threat-modeling-context.md`, identifies every dependency with `threat_model: missing`, and marks a boundary as covered iff at least one merged threat references the dependency's name or interface. Uncovered boundaries yield gap-threats at `stride: Information Disclosure`, `risk: Medium` for auth/PII interfaces, `risk: Low` otherwise. No LLM involvement.

### Merged Threats JSON Dump

After Merge (steps 0–8) and Coverage Checks complete — and **before** emitting the Section 7 markdown tables — write the full merged threat list to `$OUTPUT_DIR/.threats-merged.json`. This file is the canonical structured source consumed by downstream deterministic tooling (diagram annotator, YAML export, SARIF export, changelog writer); downstream steps read this file instead of re-parsing the rendered Section 7 markdown.

**Mandatory.** If this step is skipped, the diagram annotator has no structured input and the fragments remain unannotated.

**Schema (`$OUTPUT_DIR/.threats-merged.json`):**

```json
{
  "version": 1,
  "generated_at": "<ISO 8601 UTC timestamp>",
  "threats": [
    {
      "t_id": "T-001",
      "component_id": "auth-service",
      "component_name": "Auth Service",
      "stride": "Tampering",
      "risk": "Critical",
      "likelihood": "High",
      "impact": "Critical",
      "title": "Hardcoded RSA Private Key",
      "cwe": "CWE-321",
      "evidence": {"file": "lib/insecurity.ts", "line": 22},
      "source": "stride",
      "architectural_violation": false
    }
  ]
}
```

**Field rules:**

- `t_id` — global ID exactly as written in Section 7; one-for-one with the `### 8.x` sub-tables
- `component_id` — stable ID from the STRIDE analyzer (same as `.stride-<id>.json` filename)
- `component_name` — canonical name after step 8 normalization
- `stride` — full word (`Spoofing`, `Tampering`, `Repudiation`, `Information Disclosure`, `Denial of Service`, `Elevation of Privilege`); never single-letter
- `risk`, `likelihood`, `impact` — one of `Critical`, `High`, `Medium`, `Low`
- `title` — 2–6 word human-readable title. For Critical threats, use the identical text that appears in the `## Critical Attack Chain` Quick-reference Title column. For non-Critical threats, derive by converting the remediation title from imperative to noun phrase (e.g. "Remove hardcoded RSA key" → "Hardcoded RSA Private Key")
- `cwe` — mandatory, must match the CWE reference in the Section 7 Scenario cell
- `evidence` — `{file, line}`; `file` repo-relative, `line` integer or `null`
- `source` — one of `stride`, `requirements-compliance`, `architectural-anti-pattern`, `known-vuln`, `dep-scan`, `coverage-gap`
- `architectural_violation` — `true` when the Phase 9 escalation rule was applied, else `false`

**Ordering:** rows MUST appear in the same order as the global T-NNN assignment from Merge step 3 (`T-001` first, `T-NNN` last). Two runs on an unchanged codebase MUST produce byte-identical output modulo the `generated_at` timestamp.

**Write protocol:** Invoke a single `python3 -c` Bash call that takes the merged list on stdin and writes the file with `json.dump(..., indent=2, ensure_ascii=False, sort_keys=False)`. Do not hand-write this file via Edit / Write — it must be a deterministic dump of the in-memory merged state so downstream tools can trust it.

### Section 8 layout — architectural categories at the top, findings grouped underneath (Phase 3, analysis_version ≥ 2)

**Schema change (analysis_version 2, Phase 3).** The old flat `threats[]` list is replaced by a two-level structure in `threat-model.yaml`:

```yaml
threat_categories:          # 18 architectural patterns (TH-01 .. TH-18)
  - id: TH-01
    title: Injection
    cwe_pillar: CWE-707
    cwe_primary: CWE-74
    owasp_top10_2021: A03
    aggregated:
      max_risk: Critical
      max_cvss: 10.0
      finding_count: 7
      stride_present: [Tampering, Elevation of Privilege]
    mitigation_ids: [M-007, M-008, M-005, M-009]
    finding_ids: [F-006, F-009, F-010, F-011, F-014, F-019, F-024, F-025]

findings:                   # ~50 concrete code-level findings (F-001 .. F-NNN)
  - id: F-009
    threat_category_id: TH-01         # primary category (REQUIRED, FK)
    additional_categories: []         # optional, when a finding spans multiple
    legacy_id: T-009                  # retained for traceability to v1 baselines
    component: rest-api
    stride: Information Disclosure
    title: SQL injection in product search
    scenario: "…file:line…"
    evidence: [{path, lines}]
    likelihood: High
    impact: Critical
    risk: Critical
    cvss_v3_1: {score, vector}
    cwe: [CWE-89]
    cwe_top25_rank: 3
    mitigation_ids: [M-007]
```

**Category IDs** come from `$CLAUDE_PLUGIN_ROOT/data/threat-category-taxonomy.yaml` — **never invent a new `TH-NN` outside that file**. The STRIDE-analyzer and merger agents read the taxonomy at startup and must assign every finding to exactly one primary category; they may record up to two `additional_categories` when a finding legitimately spans patterns (e.g. T-010 notevil RCE belongs primarily to TH-05 Code Execution but is also an instance of TH-01 Injection).

**Finding IDs.** `F-NNN` (zero-padded, starts at 001) — stable across incremental runs via the same baseline fingerprinting used for old `T-NNN` IDs. A newly-discovered finding gets the next unused `F-NNN` in the baseline. Retired findings leave holes in the sequence. IDs are **per-project**, not global across plugin runs.

**Legacy-ID mapping.** Every finding carries `legacy_id: T-NNN` when migrated from a v1 baseline. The top of `threat-model.yaml` additionally carries a `legacy_id_map:` block for bulk lookups:

```yaml
legacy_id_map:
  T-001: F-001
  T-002: F-002
  T-003: F-008          # consolidated — two legacy IDs point to one finding
  T-004: F-004
```

External systems (SARIF export, Jira tickets, SIEM rules) that referenced `T-NNN` keep working — the migration script writes an id_map alongside. New runs report both `F-NNN` (primary) and `T-NNN` (legacy) on every finding row; after two full-run cycles the legacy column can be dropped per-project.

**Section 8 rendering layout.** Section 8 opens with methodology + distribution blocks (same as v1), then splits into **four rendered halves**:

1. `### 8.A Categories at a glance` — a compact executive table of all 18 THs with aggregated counts, max risk, and linked mitigations. Categories with zero findings in this project are omitted.
2. `### 8.B <severity> Categories (<N>)` — one sub-section per severity (Critical / High / Medium / Low), where each severity groups **categories** (not individual findings). Inside each category block, a nested findings table lists the concrete F-NNN rows.
3. `### 8.C Compound Attack Chains` — cross-cutting chains (`CC-NN`) where two or more findings combine to produce elevated architectural risk. Each chain distinguishes **keystone** findings (direct exploit vectors) from **contributor** findings (amplifiers). Omit the entire sub-section when zero chains are identified.
4. `### 8.D Architectural Findings` — systemic architectural weaknesses (`AF-NNN`) that aggregate multiple code-level findings and point to underlying design defects. These cannot be patched — they require architectural rework. Emit as anchored sub-blocks (see template below). Omit when zero AFs exist.

```markdown
## 8. Threat Register

<methodology paragraphs + Risk Matrix + CVSS v4 note — unchanged>

**Risk Distribution:** Critical: <N> · High: <N> · Medium: <N> · Low: <N> · **Total findings: <N>**
**STRIDE Coverage:** Spoofing: <N> · Tampering: <N> · …
**Category Distribution:** <M> of 18 categories active — Critical: <n> · High: <n> · Medium: <n> · Low: <n>

### 8.A Categories at a glance

| TH | Category | Max Risk | Findings | Top Finding | OWASP | Pillar | Mitigated by |
|----|----------|---------|----------|-------------|-------|--------|--------------|
| [TH-01](#th-01) | Injection | 🔴 Critical (CVSS 10.0) | 7 (4🔴 3🟠) | [F-011](#f-011) Mass assignment | [A03](url) | [CWE-707](url) | M-007, M-008, M-005, M-009 |
| [TH-02](#th-02) | Broken Authentication | 🔴 Critical (CVSS 10.0) | 6 | [F-005](#f-005) JWT admin forgery | [A07](url) | [CWE-693](url) | M-001, M-003, M-004 |
| … |

Sort: max-CVSS desc → finding_count desc → TH-ID asc.

### 8.B Critical Categories (<n>)

#### <a id="th-01"></a>TH-01 — Injection

> <One-sentence category description from the taxonomy + one-sentence codebase-specific observation.>

| Property | Value |
|---|---|
| **Max Risk** | 🔴 Critical (CVSS 10.0) |
| **CWE Pillar** | [CWE-707](…) — Improper Neutralization |
| **Canonical CWE** | [CWE-74](…) — Improper Neutralization of Special Elements |
| **OWASP** | [A03:2021](…) — Injection |
| **CWE Top 25** | 🏆 contains CWE-79 (#2), CWE-89 (#3), CWE-94 (#11) |
| **Findings** | 7 (4 Critical, 3 High, 0 Medium, 0 Low) |
| **Mitigated by** | [M-007](…) — Parameterize SQL queries · [M-008](…) — Replace notevil · [M-005](…) — Disable XXE · [M-009](…) — Field allowlist |

**Findings in this category:**

| ID | Legacy | Finding | Component | Risk | CVSS | CWE | Evidence | Mitigation |
|----|--------|---------|-----------|------|------|-----|----------|------------|
| [F-009](#f-009) | T-009 | SQL injection in product search | REST API | 🔴 Critical | 9.1 | [CWE-89](…) 🏆#3 | `routes/search.ts:42` | [M-007](#m-007) |
| [F-014](#f-014) | T-014 | SQL injection in login | Auth Service | 🔴 Critical | 9.1 | [CWE-89](…) 🏆#3 | `routes/login.ts:23` | [M-007](#m-007) |
| [F-019](#f-019) | T-019 | NoSQL `$where` injection | Product Reviews | 🟠 High | 8.3 | [CWE-943](…) | `routes/showProductReviews.ts:18` | [M-015](#m-015) |
| … |

---

#### <a id="th-02"></a>TH-02 — Broken Authentication

<similar block>

### 8.B High Categories (<n>)

<same layout — categories whose max_risk is High>

### 8.B Medium Categories (<n>)

<same>

### 8.B Low Categories (<n>)

<same — usually omitted>
```

**Sort order within a severity sub-section:** max-CVSS desc → finding_count desc → TH-ID asc.

**Within each category block, findings table sort:** Risk desc → CVSS desc → F-ID asc.

**Category omission rule:** Categories with zero findings in this project are omitted from 8.A AND 8.B — the category framework is universal, but the report shows only the categories actually present. The "Category Distribution" line above states `M of 18 categories active` so the reader knows what was evaluated but not found.

---

### §8.C Compound Attack Chains — CC-NN template

Compound chains document cross-cutting attack paths where two or more findings combine to produce elevated risk. Render **one anchored block per chain** with a 2-column property table followed by a narrative explanation.

**Severity model:** A chain's effective severity is the maximum severity across its *keystone* members. Contributors are amplifiers — their individual severity is capped at High even if the chain is Critical, because removing a contributor alone does not close the chain.

**Template (emit verbatim, one block per CC-NN, separated by `---`):**

```markdown
### 8.C Compound Attack Chains

<Intro paragraph naming the number of chains and the keystone/contributor distinction. Example: "Juice Shop exhibits **<N> recognised compound attack chains** — combinations of findings that, in aggregate, pose elevated architectural risk. Each chain distinguishes **keystone** findings (direct exploit vector, effective severity = chain severity) from **contributor** findings (amplifiers / defense-in-depth failures, capped at High)." >

#### <a id="cc-NN"></a>CC-NN — <Short chain title — business outcome phrasing>

| | |
|--- |--- |
| **Compound severity** | 🔴 Critical / 🟠 High / 🟡 Medium |
| **Severity justification** | <1–3 sentence explanation of why the combination rises to this severity and which member(s) drive it.> |
| **Breach distance** | 1 (internet) / 2 (auth user) / 3 (privileged) — use the lowest breach distance across keystone members |
| **Keystones** *(effective <chain severity>)* | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> |
| **Contributors** *(capped at High)* | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> |
| **Mitigates by breaking** | <mitigation A — one sentence on how it severs the chain> · <mitigation B — …> |

**Keystone:** <1–3 sentence narrative describing the direct exploit mechanism and why it alone realises the chain.>

**Contributors (amplifiers, not individually Critical):** <1–3 sentence narrative describing how each contributor amplifies the keystone's impact. Explicitly state "Fixing only <contributor> does NOT close the chain" when applicable.>

---

<next CC-NN block>
```

**Field rules:**

- **Compound severity** must be the max severity across all keystone members — never lower than any keystone's individual effective_severity, and never higher than the highest keystone.
- **Keystones row** is mandatory — every CC-NN must have ≥ 1 keystone. A chain with only contributors is a defect (it means the bundle has no direct exploit vector and should be merged into §8.D Architectural Findings instead).
- **Contributors row** is optional — omit the row entirely when the chain has no contributors (a single-keystone chain with no amplifiers).
- **Mitigates by breaking** — list the M-NNN identifiers (with short labels) that sever the chain by removing the keystone OR blocking a contributor. Use ` · ` separator.
- **Anchors:** `<a id="cc-NN"></a>` is mandatory so Top Findings and §8.B can link back. Heading format: `#### <a id="cc-NN"></a>CC-NN — <title>`.

**Ordering:** CC-01 is assigned deterministically by the orchestrator during Phase 10 — sort chains by (severity desc → breach_distance asc → keystone_count desc → stable-ID-for-tiebreaker) and assign `CC-01`, `CC-02`, … in that order. Stable across incremental runs: a chain keeps its CC-NN when its keystone-set (member IDs) is unchanged between runs.

**Omission rule:** emit `### 8.C Compound Attack Chains` only when ≥ 1 chain exists. When zero chains: skip the entire sub-section (do not emit an empty heading).

---

### §8.D Architectural Findings — AF-NNN template

Architectural findings capture systemic design defects that aggregate multiple code-level findings. Unlike code-level F-NNN, an AF cannot be fixed with a single code change — it requires architectural rework (service decomposition, vault integration, network segmentation, input-validation redesign, etc.).

**Template (emit verbatim, one block per AF-NNN, separated by `---`):**

```markdown
### 8.D Architectural Findings

<Intro paragraph naming the number of AFs and their architectural nature. Example: "Beyond concrete code/config findings, <N> **systemic architectural weaknesses** were identified. Each aggregates multiple code-level findings and points to the underlying design defect. These cannot be patched — they require architectural rework (service decomposition, vault integration, network segmentation, etc.)." >

#### <a id="af-NNN"></a>AF-NNN — <Architectural weakness title>

> <1–3 sentence business-language description of the architectural defect. This blockquote is the executive-readable summary — no jargon, no CWE numbers, no file paths.>

| | |
|--- |--- |
| **Architectural theme** | <One of: Separation / SecretManagement / InputValidation / AttackSurfaceDesign / SessionDesign / DefenseInDepth / SupplyChain / IdentityModel / DataProtection> |
| **Severity** | 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low |
| **Impact** | Critical / High / Medium / Low |
| **Structural defect** | <One-sentence description of the design flaw itself, abstracted from any single finding.> |
| **Target architecture** | <One-sentence description of the correct design that would eliminate this class of finding.> |
| **Remediation effort** | Low / Medium / High |
| **Aggregates findings** | [F-NNN](#f-NNN) — <short label>[F-NNN](#f-NNN) — <short label> |
| **Primary mitigations** | [M-NNN](#m-NNN) — <short label>[M-NNN](#m-NNN) — <short label> |
| **Derived from** | [§7.2](#72-key-architectural-risks) row <n> — <theme> (or: [§7.13 Secret Management](#713-secret-management), [§7.14 Defense-in-Depth Assessment](#714-defense-in-depth-assessment), etc.) |

---

<next AF-NNN block>
```

**Field rules:**

- **Architectural theme** — MUST be one value from the enumeration (`Separation`, `SecretManagement`, `InputValidation`, `AttackSurfaceDesign`, `SessionDesign`, `DefenseInDepth`, `SupplyChain`, `IdentityModel`, `DataProtection`). The theme links the AF to its §7 domain sub-section.
- **Severity vs Impact** — Severity is the standard Risk rating (Likelihood × Impact with architectural escalation); Impact is the pure C/I/A impact without likelihood. Both are required because an AF can have Critical impact but Medium severity when exploitation requires a rare keystone condition.
- **Aggregates findings** — list every F-NNN this AF represents. Format: `[F-NNN](#f-NNN) — <short label>`, one per cell line. Concatenation style in reference uses no separator between entries — keep that convention (each `[F-NNN]` link starts a new logical line inside the table cell; `<br/>` is optional but recommended for readability).
- **Primary mitigations** — the top 1–3 M-IDs that meaningfully reduce the architectural risk. Do not list every related M; restrict to the highest-leverage ones.
- **Derived from** — provenance link to the architectural source that identified this AF: the relevant `§7.2` row for domain-derived AFs, or a cross-cutting sub-section (`§7.13 Secret Management`, `§7.14 Defense-in-Depth Assessment`). Additional references to recon-summary sections are allowed after a `+` separator.
- **Blockquote** — the opening `>` paragraph is mandatory; it is the business-readable summary.
- **Anchor** — `<a id="af-NNN"></a>` is mandatory. Heading format: `#### <a id="af-NNN"></a>AF-NNN — <title>`.

**AF-NNN assignment:** AF-001..AF-NNN is assigned deterministically during Phase 9 when the orchestrator aggregates cross-cutting patterns. Stable across incremental runs: an AF keeps its ID when its `architectural_theme` + ≥ 50% of its aggregated-findings set is unchanged between runs.

**Omission rule:** emit `### 8.D Architectural Findings` only when ≥ 1 AF exists. Otherwise skip the entire sub-section.

---

### Legacy (v1) section 7 layout — methodology, distribution, then split-by-severity

*Retained for `analysis_version=1` baselines and migration paths.* New runs use the two-level layout above.

Section 7 (Threat Register) opens with a one-sentence reader-orientation, the methodology note including the explicit Risk Matrix, the Risk Distribution / STRIDE Coverage summary, and is then split into four sub-sections — one per severity level. A single 30-row table is unreadable in rendered Markdown, so the orchestrator MUST emit four separate tables.

```markdown
## 8. Threat Register

The threat register lists every confirmed STRIDE finding with its evidence, current state, and the mitigation that addresses it. Threats are split into four sub-sections by severity so the reader can see at a glance what is critical and what is hardening work.

**Risk methodology:** Risk = Likelihood × Impact. Likelihood considers exploitability, attack complexity, and required privileges. Impact considers confidentiality, integrity, and availability effects on the identified assets. The table below is the single source of truth for converting (Likelihood, Impact) to a final Risk rating — every threat row in this section must be consistent with it.

| Likelihood \ Impact | Low | Medium | High | Critical |
|---|---|---|---|---|
| **Critical** | Medium | High | Critical | Critical |
| **High** | Low | Medium | High | Critical |
| **Medium** | Low | Medium | Medium | High |
| **Low** | Low | Low | Medium | High |

**Escalation rule (architectural violations):** When a threat is tagged `architectural_violation: true`, the Risk is escalated by exactly one level compared to the value in the matrix above (Medium → High, High → Critical). This rule makes architectural violations visible without bending the Likelihood/Impact scoring.

**CVSS v4.0 column (conditional).** When at least one threat in the register carries a `cvss_v4` vector, add a `CVSS v4` column as the column immediately **after** `Risk` in each sub-section table. Cell format: `<base_score> (<severity>)` linked to the FIRST.org calculator, e.g. `[9.3 (Critical)](https://www.first.org/cvss/calculator/4-0#<url-encoded-vector>)`. Threats without a vector show `—` (em dash). If the register has **zero** CVSS vectors, omit the column entirely — do not render a column of em dashes. Append a single-line note below the methodology paragraph: *"CVSS v4.0 scores are attached only to threats with concrete, exploitable evidence (injection, auth bypass, crypto misuse, dependency CVEs). Design-, policy-, and coverage-sourced threats are scored qualitatively via the Likelihood × Impact matrix."*

**Risk Distribution:** Critical: <N> · High: <N> · Medium: <N> · Low: <N> · **Total: <N>**
**STRIDE Coverage:** Spoofing: <N> · Tampering: <N> · Repudiation: <N> · Information Disclosure: <N> · Denial of Service: <N> · Elevation of Privilege: <N>

**Consistency invariants (QA-enforced):**

1. Every Risk cell in the sub-section tables MUST match the Likelihood/Impact matrix above — no exceptions without an explicit `architectural_violation: true` escalation note in the threat row
2. The counts in the "Risk Distribution" line MUST sum to the **Total** and MUST equal the row counts in the four sub-section headings (`### 7.1 Critical (<N>)` …)
3. The counts in the "STRIDE Coverage" line MUST sum to the **Total** — one threat has exactly one primary STRIDE category; never split a threat across two categories

### 7.1 Critical (<N>)

These findings combine high exploitability with maximum impact. Every entry here is referenced by T-NNN from the `## Critical Attack Chain` block (placed directly after the Management Summary) and is the source of the P1 rollout actions in the Management Summary's Immediate Actions table. Section 7.1 is the authoritative per-finding source — the Attack Chain block links back here, never duplicates this content.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| ... |

### 8.2 High (<N>)

High-rated threats require remediation in the current sprint or quarter. They typically gate the next release.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| ... |

### 8.3 Medium (<N>)

Medium-rated threats represent meaningful gaps with either reduced exploitability or contained impact. They should be tracked and remediated as part of normal hardening work.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| ... |

### 8.4 Low (<N>)

Low-rated threats document residual risk and minor hygiene issues. They are typically addressed opportunistically as part of related work.

| ID | Component | STRIDE | Threat Scenario | Likelihood | Impact | Risk | Controls in Place | Mitigations |
|----|-----------|--------|-----------------|------------|--------|------|-------------------|-------------|
| ... |
```

**Rules for the split:**

- Each sub-section is its own H3 heading and its own table — never collapse two severity tiers into one table
- The count in parentheses (`Critical (6)`) must match the number of rows in the sub-section
- Sort within each sub-section using the **same deterministic sort key defined in the Merge step (fields 1–8)**, skipping field 2 (`risk`) since every row in a sub-section already shares the same risk. This guarantees that Section 7 sub-tables are presented in the same order as the global T-NNN assignment — a reader scanning 8.1 top-to-bottom sees T-001, T-002, … in sequence without gaps
- If a severity tier has zero threats, still emit the H3 with a single line: `_No threats at this severity level._` and skip the table — do not omit the heading entirely (it preserves consistent navigation anchors)
- **Severity encoding rule — Risk column only.** The `Likelihood` and `Impact` cells use **plain words** (`Critical`, `High`, `Medium`, `Low`) — no emoji markers. Only the final `Risk` cell carries an emoji severity badge (`🔴 Critical`, `🟠 High`, `🟡 Medium`, `🟢 Low`). This reduces emoji density from three per row to one and keeps the emoji meaningful (it highlights the conclusion, not the intermediate scores). Inline HTML `<span>` badges remain forbidden everywhere
- The Risk Distribution and STRIDE Coverage lines come **once** at the top of Section 7, not repeated in each sub-section

### CWE References in Threat Register

Each threat row in the Threat Register table **MUST** include a CWE reference in the Threat Scenario cell as a **clickable link** to the MITRE CWE entry. Format: `[CWE-NNN](https://cwe.mitre.org/data/definitions/NNN.html)`. Append at the end of the scenario text, e.g.: `... allowing full database extraction. [CWE-89](https://cwe.mitre.org/data/definitions/89.html).` For threats with multiple CWEs, comma-separate: `[CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-74](https://cwe.mitre.org/data/definitions/74.html).` Use the most specific applicable CWE — every threat has an applicable CWE. **Never use bare `CWE-NNN` text** — always link it.

**Mandatory classification tag (Phase 1E and later).** Immediately after the CWE link(s) in every scenario cell, append a compact three-part classification tag sourced from `$CLAUDE_PLUGIN_ROOT/data/cwe-taxonomy.yaml`:

```
[CWE-NNN](cwe-url) 🏆 Top 25 #R · Pillar [CWE-PPP](pillar-url) · OWASP [A0X:2021](owasp-url)
```

Segments:

| Segment | When emitted | Format | Source |
|---|---|---|---|
| 🏆 Top 25 #R | CWE has `cwe_top25_2024` rank set in taxonomy | `🏆 Top 25 #<rank>` | `cwes.CWE-NNN.cwe_top25_2024` |
| Pillar | CWE has `pillar` field ≠ null (i.e. CWE is not itself a pillar) | `Pillar [CWE-PPP](url)` | `cwes.CWE-NNN.pillar` + `pillars.CWE-PPP.url` |
| OWASP | CWE has `owasp_top10_2021` mapping | `OWASP [A0X:2021](url)` | `cwes.CWE-NNN.owasp_top10_2021` + `owasp_top10_2021_urls.A0X` |

The three segments are separated by ` · ` (middle-dot with spaces). If a segment is unavailable, skip it — do not emit empty placeholders. The tag is **in addition to** the CWE link, on the same line, same cell.

Example row in Threat Register for T-009 (SQL injection in product search):

```markdown
| <a id="t-009"></a>T-009 | REST API | Information Disclosure | SQL injection in product search: … [CWE-89](https://cwe.mitre.org/data/definitions/89.html) 🏆 Top 25 #3 · Pillar [CWE-707](https://cwe.mitre.org/data/definitions/707.html) · OWASP [A03:2021](https://owasp.org/Top10/A03_2021-Injection/) | High | Critical | 🔴 Critical | … | [M-007](#m-007) — Parameterize raw queries |
```

**When an LLM-related OWASP code is used** (`LLM03`, `LLM04`, etc. from `cwe-taxonomy.yaml → owasp_llm_top10`), emit it alongside the OWASP Top 10 tag with the same formatting, e.g. `OWASP [A10:2021](…) · LLM [LLM03](…)`. Only LLM-integrated components trigger this — the STRIDE analyzer decides.

**Never invent taxonomy data** — if a CWE is not in `cwe-taxonomy.yaml`, leave only the CWE link and add an inline HTML comment `<!-- QA: CWE-NNN not in cwe-taxonomy.yaml -->` so the QA reviewer's Check 3g flags it for taxonomy maintenance.

### Requirements Integration in Sections 8, 9, and 10

**When `CHECK_REQUIREMENTS=true` and requirement metadata is available from Phase 8b:**

**Section 7 — Threat Register: Violated Requirements**

For **every** threat row that has associated requirement IDs from Phase 8b (not just Critical threats), append a `Violated: [ID](url), …` note inside the Threat Scenario cell, after the CWE reference. This ensures requirement violations are visible at all severity levels — not just for Critical threats surfaced in the `## Critical Attack Chain` block. Format example: `... file read. [CWE-611](https://cwe.mitre.org/data/definitions/611.html). Violated: [IV-002](url)`.

**Critical Attack Chain layout (mandatory) — rendered directly after the Management Summary:**

The Critical Attack Chain is a **thin, promoted section** placed **immediately after the Management Summary, before Section 1**. It is **unnumbered** (heading: `## Critical Attack Chain`, anchor `#critical-attack-chain`) because it serves as the visual extension of the Management Summary's `### Worst Case Scenarios` bullet list — the bullets describe *what* happens in prose, this section shows *how* it happens as a diagram.

Its job is to show the *chain(s)* — how Critical (and optionally High) findings combine into attacker workflows — and to link back to the detailed rows in Section 8.1 and the step-by-step walkthroughs in Section 3. Full narrative detail (Scenario, Current state, Violated Requirements) lives in Section 8.1; detailed sequenceDiagrams per Critical finding live in Section 3 (Attack Walkthroughs), rendered by Phase 4 of the orchestrator.

**Multiple chains are allowed and encouraged when they exist.** The old template rendered exactly one diagram. The new template renders **1 to 3 chains**, one per distinct end-to-end attack path identified in the Management Summary's Worst Case Scenarios. If two scenarios share the same root (e.g. both start from unauthenticated SQL injection on the login form) but diverge at the second step, they count as two distinct chains and MUST be rendered as two separate `graph LR` blocks — do not merge them into one mega-diagram with branching subgraphs, which is unreadable.

**Section 3 (Attack Walkthroughs)** holds the detailed `sequenceDiagram` blocks — one per Critical finding, rendered by Phase 4 of the orchestrator. The `## Critical Attack Chain` block remains the thin executive-level overview, and Section 3 remains distinct from it: the Attack Chain shows *how Criticals chain together* (one `graph LR` per scenario, max 3), Section 3 shows *each Critical in detail* (one `sequenceDiagram` per finding). Do not duplicate the Mermaid chain diagram or the quick-reference table in Section 3 — they live **only** in `## Critical Attack Chain`.

When there are 0 or 1 Critical findings, skip the `## Critical Attack Chain` section entirely — a single Critical cannot form a "chain" with itself. Section 3 still renders in that case: if `CRIT_COUNT == 1` it contains one attack walkthrough for that single Critical finding; if `CRIT_COUNT == 0` it contains the empty-state stub documented in Phase 4.

```markdown
## Critical Attack Chain

The diagrams below show how Critical findings combine into distinct attacker workflows. Each chain corresponds to one bullet under *Worst Case Scenarios* in the Management Summary. Nodes link directly to their full detail row in Section 7.1 — no finding is re-described here.

### Chain 1 — Unauthenticated RCE

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated<br/>attacker"]):::crit
    T1["T-001<br/>Hardcoded RSA key"]:::crit
    T2["T-003<br/>JWT forgery"]:::crit
    T3["T-006<br/>RCE via eval"]:::crit
    Goal(["Shell on host"]):::crit
    Start -->|"public repo"| T1
    T1 -->|"sign admin JWT"| T2
    T2 -->|"admin session"| T3
    T3 -->|"code execution"| Goal
```

**Key takeaway:** <one sentence — e.g. "A single HTTP request with a self-signed administrator JWT is enough to land a shell on the server, because every step of the chain sits on the public attack surface.">

### Chain 2 — Mass data exfiltration

```mermaid
graph LR
    classDef crit fill:#FFB6C1,stroke:#c00,color:#000,stroke-width:2px
    Start(["Unauthenticated<br/>attacker"]):::crit
    T4["T-002<br/>SQLi login bypass"]:::crit
    T5["T-007<br/>UNION SELECT dump"]:::crit
    Goal(["Full customer DB"]):::crit
    Start -->|"login form"| T4
    T4 -->|"admin session"| T5
    T5 -->|"40k accounts"| Goal
```

**Key takeaway:** <one sentence — e.g. "Unauthenticated SQL injection on the login endpoint yields the complete customer database including weakly-hashed passwords in under a minute.">

<Optional Chain 3 — render only when a third distinct end-to-end path exists (e.g. supply-chain, stored XSS → session theft, SSRF → cloud metadata). Never pad — if fewer than 3 distinct chains exist, stop after the last real one.>

### Quick reference — Critical findings

| ID | Title | Component | Violated Requirements | Mitigation |
|----|-------|-----------|------------------------|------------|
| [T-001](#t-001) | Hardcoded RSA Private Key | Auth Service | [DP-005](url), [AC-005](url) | [M-001](#m-001) · P1 |
| [T-002](#t-002) | SQL Injection in Login | Auth Service | [IV-004](url) | [M-002](#m-002) · P1 |
| … | | | | |
```

**Rules for `## Critical Attack Chain`:**

- **No per-finding prose blocks — ever.** The old template had a `### 🔴 T-NNN — Title` heading with a Scenario / Current state / Violated Requirements / Mitigation block for each finding. Do **not** emit those blocks — they duplicate Section 7.1. The Quick-reference table is the only per-finding presentation allowed.
- **Heading is unnumbered.** Render as `## Critical Attack Chain` (anchor `#critical-attack-chain`), not `## 9. Critical Attack Chain` and not `## 1.5 …`. The absence of a number is deliberate and tells the reader this is part of the executive summary, not a numbered finding section.
- **Position is non-negotiable.** Immediately after the Management Summary, immediately before Section 1. Never after Section 7.
- The intro sentence is mandatory and must come before the first chain heading.
- **Render between 1 and 3 chains** — one per distinct end-to-end attack path. Each chain is a `### Chain <N> — <Scenario name>` heading followed by exactly one `graph LR` block followed by exactly one `**Key takeaway:**` sentence. The chain headings match the Scenario names used in the Management Summary's `### Worst Case Scenarios` bullet list, one-to-one, so the reader can map the textual bullet to its visual diagram without guessing.
- **Chain count rules:** emit 0 chains (skip the whole section) when `CRIT_COUNT <= 1`. Emit exactly 1 chain when `CRIT_COUNT == 2` (one linear path). Emit 2 or 3 chains when distinct end-to-end paths exist. Never merge two distinct chains into one branching diagram.
- The chain diagrams use `graph LR` (the only place where LR is allowed — chains read like sequences) and the `crit` classDef shown above.
- Each chain node is one Critical finding labeled with its T-NNN and a 2–3 word summary; edges describe the attacker capability gained at each step.
- Each chain MUST have exactly one `**Key takeaway:**` sentence immediately under its diagram — this is what the QA reviewer looks for, not a single shared takeaway at the section level.
- The Quick-reference table is rendered **once**, at the end of the section (after the last chain) — not per chain. It lists every Critical finding that appears in any of the chains. Columns: ID, Title, Component, Mitigation. Word severity only (no emoji) — severity is implicit. Include `Violated Requirements` as comma-separated clickable IDs *only when* `CHECK_REQUIREMENTS=true`; otherwise drop the column.
- **Mitigation column MUST include a short explanation** after the M-NNN link: `[M-NNN](#m-NNN) — <short action>` (e.g. `[M-001](#m-001) — Parameterized queries`). Bare M-NNN links without an explanation are a format defect.
- Section 8.1 remains the authoritative per-finding source — any reader clicking a T-NNN link in the Quick-reference table or in a chain node lands on the full row with Scenario, Likelihood, Impact, Risk, Controls in Place, and Mitigation.

**Section 3 — Attack Walkthroughs:**

Section 3 is rendered by **Phase 4** of the orchestrator — see `phase-group-architecture.md` → "Phase 4: Attack Walkthroughs (renders Section 3)" for the full rendering contract. Phase 9's job is to verify the heading exists; Phase 4 fills the content.

```markdown
## 3. Attack Walkthroughs

<body — either the Phase-4-rendered sequenceDiagram blocks, or the stub below when CRIT_COUNT == 0>
```

**Empty-state stub (when CRIT_COUNT == 0):**

```markdown
## 3. Attack Walkthroughs

_No critical-severity attack walkthroughs — the highest-severity findings are documented in [Section 8 — Threat Register](#8-threat-register). This section renders step-by-step attack flows for Critical findings only; other severities are catalogued in the threat register tables._
```

**Three roles, three places:**

| Where | What | For whom |
|---|---|---|
| `## Critical Attack Chain` (after Mgmt Summary) | 1 high-level `graph LR` showing how Critical findings chain together | Executive — 30 seconds |
| Section 8.1 Critical | Tabular per-finding rows with Evidence, CWE, Mitigation | Engineer — 5 minutes |
| **Section 3 Attack Walkthroughs** | 1 detailed `sequenceDiagram` per Critical finding, alt=current / else=post-mitigation | Reviewer walking through the exploit — 15 minutes |

**Section 9 — Mitigation Register template (canonical, applies to every mitigation):**

Section 9 renders mitigations grouped by rollout priority. Each priority bucket (`### P1 — Immediate`, `### P2 — This Sprint`, `### P3 — Next Quarter`, `### P4 — Backlog`) opens with a 1-sentence intro and a `---` separator, followed by one anchored block per M-NNN.

**Section 9 top-level layout:**

```markdown
## 9. Mitigation Register

Mitigations are grouped by rollout priority. Within each priority group, entries are ordered by effort (lowest first), then by number of findings addressed (highest first).

### P1 — Immediate

These mitigations address Critical-severity findings or compound vulnerabilities with active exploitation potential. They should be completed before the next release.

---

<M-NNN blocks for P1 mitigations>

### P2 — This Sprint

<intro sentence — "These mitigations address High-severity findings or deferred-Critical work that requires more than trivial effort.">

---

<M-NNN blocks for P2 mitigations>

### P3 — Next Quarter

<intro sentence>

---

<M-NNN blocks for P3 mitigations>

### P4 — Backlog

<intro sentence>

---

<M-NNN blocks for P4 mitigations>
```

**Per-mitigation block template (emit verbatim for every M-NNN):**

When a mitigation addresses **two or more** findings, the `**Addresses:**` block MUST be a bullet list — one `[F-NNN](#f-NNN) — <short title>` per line. When a mitigation addresses exactly one finding, a single inline `[F-NNN](#f-NNN) — <short title>` is acceptable. **Never** emit a comma-separated inline list outside of tables, and **never** emit a bare `F-NNN` without both the `(#f-NNN)` anchor and the short title.

```markdown
#### <a id="m-NNN"></a>M-NNN — <Mitigation title>

**Addresses:**
- [F-NNN](#f-NNN) — <short finding title, ≤60 chars>
- [F-NNN](#f-NNN) — <short finding title, ≤60 chars>

**Prevents CWEs:**

- ➚ [CWE-NNN](https://cwe.mitre.org/data/definitions/NNN.html) — <CWE title>
- ➚ [CWE-NNN](https://cwe.mitre.org/data/definitions/NNN.html) — <CWE title>

**Fulfills Requirements:**
- [SEC-AUTH-1](url) — <title>
- [SEC-AUTH-3](url) — <title>

**Blueprint guidance:** [BP-XYZ](url) — <Blueprint title> · <section title>

**Priority:** **P1 — Immediate**

**Severity:** 🔴 Critical

**Effort:** Low

**Why:** <1–3 sentences explaining the root-cause link and why this mitigation is the highest-leverage fix. When a Blueprint applies, quote the Blueprint rationale verbatim before adding custom commentary.>

**How:**
1. <numbered step — first step quotes the Blueprint section verbatim when one applies>
2. <next step>
3. <next step>

```<lang>
// Before (<file>:<line>):
<code>

// After:
<code>
```

**Verification:** <1–3 sentences describing concrete verification — a curl command, a test name, a specific log line, a configuration check, or a `git log` grep.>

**Reference:** ➚ [CWE-NNN](url) Pillar ➚ [CWE-NNN](url) · OWASP ➚ [AXX:2021](url)

---
```

**Field rules — every mitigation MUST follow this exact order and contain every field unless explicitly marked optional:**

| Field | Required? | Notes |
|-------|-----------|-------|
| `#### <a id="m-NNN"></a>M-NNN — <title>` heading | always | Four-hash heading (not three) so the M-NNN blocks render as sub-sections of the priority group. Anchor ID `m-NNN` is mandatory — every cross-reference elsewhere lands on this anchor. |
| `**Addresses:**` | always | Bullet list (`- [F-NNN](#f-NNN) — <title>`) when ≥2 addressed findings; single inline `[F-NNN](#f-NNN) — <title>` when exactly 1. **Never** bare IDs, **never** comma-separated unless inside a markdown table row. |
| `**Prevents CWEs:**` | always when ≥ 1 CWE is distinctly prevented by this fix | Bullet list of `➚ [CWE-NNN](url) — <title>` — each CWE on its own line. When the mitigation prevents exactly one CWE, inline form `**Prevents CWEs:** ➚ [CWE-NNN](url) — <title>` is acceptable. |
| `**Fulfills Requirements:**` | only when CHECK_REQUIREMENTS=true and the mitigation addresses at least one requirement-linked finding | Derived from requirement IDs propagated by Phase 8b — never invent IDs |
| `**Blueprint guidance:**` | only when a matching blueprint section was attached by the STRIDE analyzer (`remediation.blueprint`) **and** the requirements YAML loaded a `blueprints[]` section | See Blueprint propagation rule below |
| `**Priority:**` | always | Bold form: `**P1 — Immediate**` / `**P2 — This Sprint**` / `**P3 — Next Quarter**` / `**P4 — Backlog**`. See P1–P4 rollout priority section below. Note: the Priority line is also encoded in the parent `### P<n>` heading — the per-block line provides redundant anchoring that survives heading-strip operations. |
| `**Severity:**` | always | One of 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low — derived from the highest risk among addressed findings. Use the emoji-only badge — never inline HTML `<span>`. On its own line. |
| `**Effort:**` | always | `Low` (< 2h, single file) · `Medium` (half-day, multi-file) · `High` (multi-day, architectural). On its own line. |
| `**Why:**` | always | 1–3 sentences. **When a Blueprint applies, quote the Blueprint rationale verbatim** before adding any custom commentary. |
| `**How:**` | always | Numbered steps. **When a Blueprint applies, the first step MUST come from the Blueprint section** — do not invent your own first step. |
| Code block | when fix involves code or config | Language-tagged before/after snippet (3–10 lines). The `Before` snippet carries a `(<file>:<line>)` provenance comment on the first line; the `After` snippet shows the fixed form. Omit the block only when the fix is purely operational (e.g. "rotate the secret in vault"). |
| `**Verification:**` | always | Concrete check the developer can run after the fix — never "verify the fix works". |
| `**Reference:**` | always | CWE Pillar link + OWASP Top 10 / OWASP LLM link (external CWE/OWASP URL — never internal anchor). Use `➚` arrow prefix per link for visual consistency. |
| `---` separator | always (between blocks) | A standalone `---` line between consecutive M-NNN blocks within a priority group; not required before the first block of a group (the group's own `---` after the intro sentence serves). |

The **Fulfills Requirements** line lists all requirement IDs that are satisfied when this mitigation is implemented. Derive this by collecting the requirement IDs from all threats this mitigation addresses. Only present when requirements are enabled and the mitigation addresses at least one requirement-linked threat.

**Consistency rule — Fulfills Requirements is non-optional when any linked threat has one.** When `CHECK_REQUIREMENTS=true` and *any* of the addressed threats carry a `Violated Requirements` list, the mitigation MUST emit a `**Fulfills Requirements:**` line. The only legitimate case for omitting the line is when every addressed threat has zero violated requirements. The QA reviewer flags any mitigation that addresses a requirement-linked threat but silently drops the line.

**Compliance-count consistency rule (QA-enforced).** When `CHECK_REQUIREMENTS=true`, the Requirements Compliance sub-section of the Management Summary and Section 7b MUST report the **exact same** four numbers: `<N> requirements checked — <N_pass> PASS · <N_fail> FAIL · <N_antipattern> ANTI-PATTERN · <N_partial> PARTIAL`. Both locations derive from the same Phase 8b output — a drift between the two is a bug the QA reviewer fails the report on. Do not re-count in either location; both sub-sections read from the same set of totals.

### Blueprint propagation rule (mandatory when blueprints are loaded)

The STRIDE analyzers attach a `remediation.blueprint` field to threats whenever a matching blueprint section was found in `.requirements.yaml`. The orchestrator MUST propagate this into the Mitigation Register according to the following rule:

1. **Collect blueprints from addressed threats.** When building an `M-NNN` entry, gather the `remediation.blueprint` value from every threat this mitigation addresses.
2. **Pick the most relevant single blueprint.** If multiple addressed threats reference different blueprints, choose the blueprint that covers the largest share of addressed threats. If a tie, pick the blueprint section whose title best matches the mitigation title. Never list more than one blueprint per mitigation — pick one.
3. **Render as `**Blueprint guidance:**` line** in the format produced by the STRIDE analyzer (`[BP-ID](section-url) — Blueprint title · Section title`).
4. **When a Blueprint applies, the Blueprint section URL becomes the canonical reference.** Do not add a separate `**Reference:**` line with an OWASP cheatsheet — the Blueprint section already links to the cheatsheet internally.
5. **Why/How content.** The `**Why:**` line MUST quote one to two sentences from the Blueprint section verbatim before adding any commentary. The `**How:**` first step MUST be the action mandated by the Blueprint section. Subsequent How steps may add codebase-specific detail.
6. **Fallback rule** — if no blueprint was matched for any addressed threat, omit the `**Blueprint guidance:**` line entirely and use the `remediation.reference` (OWASP cheatsheet or CWE) as the canonical source instead. The `**Why:**` and `**How:**` then come from the cheatsheet, not invented prose.

**Never invent a blueprint reference** — only use blueprint IDs that exist verbatim in the loaded `.requirements.yaml` `blueprints[]` section. If the requirements YAML has no `blueprints[]` section, this rule does not apply and the `**Blueprint guidance:**` field is omitted from every mitigation.

### P1–P4 rollout priority (mandatory on every mitigation)

Severity (Critical/High/Medium/Low) describes *how bad* a threat is. Rollout priority (P1–P4) describes *how soon* the team must act. They are independent — a Critical threat with a complex fix can still be P2 if the immediate fix is impractical, and a High-effort architectural change addressing a Medium threat can still be P3.

Assign each mitigation exactly one of:

| Tag | Meaning | Time horizon | Assignment criteria (any one matches) |
|-----|---------|--------------|---------------------------------------|
| **P1 — Immediate** | Production deployment must not happen until this is fixed | 0–48 hours | Critical severity AND (unauthenticated exploit OR Effort=Low) · OR a hardcoded production secret · OR an active exploit chain |
| **P2 — This Sprint** | Must land in the current sprint, before the next release | ≤ 2 weeks | Critical severity with auth gate or Medium effort · OR High severity with Low/Medium effort · OR a P1 follow-up that depends on it |
| **P3 — Next Quarter** | Planned architectural work, scheduled but not blocking | 1–3 months | High severity with High effort · OR Medium severity with Low/Medium effort · OR architectural refactor (BFF, OIDC migration) |
| **P4 — Backlog / Hardening** | Defense-in-depth, no acute exploit | Opportunistic | Medium/Low severity with no exploit chain · OR Low effort hardening that adds redundancy |

**Resolution algorithm — apply in order, stop at first match:**

1. Mitigation addresses any **Critical**-rated threat AND `effort = Low` → **P1**
2. Mitigation addresses any **Critical**-rated threat that is exploitable without authentication → **P1**
3. Mitigation addresses any threat tagged `architectural_violation: true` AND `effort != High` → **P1**
4. Mitigation addresses any **Critical**-rated threat (any other case) → **P2**
5. Mitigation addresses any **High**-rated threat AND `effort != High` → **P2**
6. Mitigation addresses any **High**-rated threat AND `effort = High` → **P3**
7. Mitigation is an architectural refactor (e.g. BFF migration, OIDC adoption, secret manager rollout) → **P3**
8. All addressed threats are **Medium** → **P3** if `effort = Low`, otherwise **P4**
9. Otherwise → **P4**

The chosen priority determines the order in Section 10. Group entries by priority — `## P1 — Immediate`, then `## P2 — This Sprint`, then `## P3 — Next Quarter`, then `## P4 — Backlog`. Inside each priority group, order by lowest effort first, then by addressed-threat count descending.

### Build Mitigation Register

Assign M-NNN IDs. Merge mitigations when they produce the same physical change. Update threat records with mitigation_ids.

For each merged M-NNN entry:

1. **Aggregate addressed threats** — collect every T-NNN this mitigation resolves, plus their severity and `architectural_violation` metadata.
2. **Severity badge** — set `**Severity:**` to the highest severity among addressed threats, using the emoji-only badge (🔴/🟠/🟡/🟢).
3. **Compute P1–P4 rollout priority** — apply the resolution algorithm in the "P1–P4 rollout priority" section above. Record the chosen priority on the mitigation.
4. **Propagate requirement IDs** — when CHECK_REQUIREMENTS is true, collect all requirement IDs from the addressed threats' `Violated Requirements` and emit them on the `**Fulfills Requirements:**` line. **Only propagate requirement IDs that actually appear as "Violated Requirements" on the addressed threats — do NOT invent or add requirement IDs that were not generated by Phase 8b.**
5. **Propagate Blueprint** — apply the "Blueprint propagation rule" above. Pick at most one blueprint per mitigation. When the requirements YAML has no `blueprints[]` section, skip this step entirely.
6. **Compose Why/How from authoritative source** — when a Blueprint applies, the `**Why:**` quotes the Blueprint section verbatim and the `**How:**` first step is the Blueprint-mandated action. Otherwise, fall back to the OWASP cheatsheet referenced in `remediation.reference`. Never invent fix prose without an authoritative source.
7. **Verification line** — every mitigation MUST end with a one-or-two sentence `**Verification:**` line describing how to confirm the fix. Derive it from the threat scenario (e.g. for SQLi: "Send `' OR 1=1--` as the email field; the server must respond 401 instead of 200").

### Cross-reference linking rule (all sections)

When writing `threat-model.md`, every T-NNN and M-NNN that appears in the report falls into exactly one of two categories:

### 1. As an ID (no label)

When T-NNN or M-NNN appears in a column named **"ID"** in a table, it is an **identifier** — just the bare link, no description. The adjacent column (Title, Description, Summary, Threat Scenario) already describes the item.

```
| ID | Title | ...
|----|-------|
| [T-001](#t-001) | SQL injection — authentication bypass | ...
```

This applies to: Top Findings table (# column — rank, not ID), Critical Attack Chain quick-reference table (ID column), Attack Walkthrough summary table (ID column), Threat Register (ID column).

Also no label on: anchor definition sites (`<a id="t-001"></a>T-001`), inside Mermaid diagram blocks (node labels carry their own text), Mitigation Register headings (`### M-001 — <full title>`).

### 2. As a reference (always with label)

When T-NNN or M-NNN appears in **any other column** (Mitigation, Addresses, Enables, Linked Threats, Controls in Place) or **in prose**, it is a **reference** — always with a short description.

**Format (uniform reference schema):** `[X-NNN](#x-nnn) — <short label>` — applies identically to every linked entity with an anchor: findings (`F-NNN`), architectural findings (`AF-NNN`), threats (`T-NNN`), threat categories (`TH-NN`), mitigations (`M-NNN`), and components (`C-NN`). One em-dash, one space on each side, short label ≤50 chars. No legacy variants (bare space, colon, `>`, `<br/><small>`) — these are auto-repaired by QA Check 3f.

**In prose:** `...the hardcoded RSA private key ([T-005](#t-005) — Hardcoded RSA key) enables...`

**In table cells with a single reference:**
```
| ... | Mitigations |
|-----|-------------|
| ... | [M-001](#m-001) — Parameterized queries |
```

**In table cells with multiple references — use `<br/>` line breaks:**
```
| ... | Linked Threats |
|-----|---------------|
| ... | [T-001](#t-001) — SQL injection login<br/>[T-002](#t-002) — SQL injection search |
```

Use `<br/>` to separate multiple references in table cells — not comma-separated (too long to scan), and not `<ul><li>` (renders poorly in some Markdown table implementations).

**In prose / outside tables — use Markdown bullet lists:**

When listing linked threats outside of table cells (e.g. after `**Linked threats:**` headings in Section 2.5 Security Architecture Assessment themes), render each reference as a Markdown bullet point:

```markdown
**Linked threats:**

- [T-001](#t-001) — SQL injection login
- [T-002](#t-002) — SQL injection search
- [T-006](#t-006) — MD5 password hashing
```

This applies to all `**Linked threats:**` blocks in the architecture assessment themes (2.5.3–2.5.9). The label is on its own line preceded by `**Linked threats:**` as a standalone paragraph, followed by a blank line, then the bullet list.

**Consistency rule:** Each T-NNN or M-NNN MUST use the **same short label everywhere** it appears in the report. The label is a 2–5 word summary of the threat or mitigation title. Decide the label once (during Phase 9 when composing the Threat Register) and reuse it verbatim in every subsequent reference — Management Summary, Critical Attack Chain, Architecture Assessment, Assets, Attack Surface, Trust Boundaries, Controls, Threat Register (Mitigations column), and Mitigation Register (Addresses field).

**Mitigation Register `**Addresses:**` field — special case.** The Mitigation Register lives under `## 9.` (prose/list context, not inside a table). The `**Addresses:**` line therefore MUST follow the "outside tables" rule — render every addressed threat as a Markdown bullet on its own line, each shaped `- [T-NNN](#t-NNN) — <short label>`. When exactly one threat is addressed, a single inline form `[T-NNN](#t-NNN) — <short label>` on the same line as `**Addresses:**` is acceptable. **Never** emit bare `T-NNN`, **never** emit comma-separated prose lists. The QA reviewer's Check 3c enforces this and auto-repairs violations.

**Prose references — rendering exception.** When a short-label reference is embedded inside a sentence (e.g. "…the hardcoded RSA private key ([T-005](#t-005) — Hardcoded RSA key) enables…"), wrap the reference in parentheses so the reading flow is preserved. This is the only place where the "bullet list outside tables" rule is relaxed — a parenthetical short-label reference in a sentence is treated as inline.

### Build Management Summary — MANDATORY at all depth levels

After the Threat Register and Mitigation Register are complete, generate a **Management Summary** section. This section is placed **after the Table of Contents and before Section 1** in the final output. **The Management Summary MUST be generated at every `ASSESSMENT_DEPTH` level — including `quick`.** It is the single most important section for stakeholders. Skipping it due to turn budget pressure is never acceptable — if turns are tight, reduce other sections (e.g., skip Architecture Assessment themes at quick depth) but always emit the Management Summary.

**Purpose:** Executives and architects who do not read the full report must walk away from the first ninety seconds knowing four things — *how bad it is*, *what the top risks are*, *what the worst case looks like end-to-end*, and *what must happen first*. The summary answers those four questions and nothing else. Per-threat details, file references, CWE numbers, severity counts and effort estimates belong in Sections 8, 9 and 10 — **not** here.

**Presentation rules (load-bearing):**

- **Scannability beats completeness.** When a choice must be made between "one more sentence" and "one fewer line", cut the sentence. The reader has 90 seconds.
- **Every T-NNN and M-NNN in this section must be a clickable link** — never bare text.
- **Zero severity-count noise.** The Management Summary does not render Risk Distribution tables, STRIDE Coverage tables, or severity totals (e.g. "5 Critical and 14 High…"). Those live in the Threat Register alone.
- **Tables over bullets for structured data.** Top Findings, Mitigations (Prioritized + Follow-up), and Operational Strengths use tables — they are easier to scan than bullet lists and align columns for comparison.
- **Worst-case scenarios are rendered as bullets inside the Verdict blockquote.** The Verdict section is framed by a red HTML box (`<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">`) that contains the attack-path bullets with F-NNN references. There is **no separate `### ⚠ Worst Case Scenarios` sub-section** — the bullets inside the Verdict blockquote *are* the worst-case scenarios.

```markdown
## Management Summary

### Verdict

<Verdict — structured as: opening sentence + red HTML blockquote with bullet points + closing assessment. The opening sentence MUST begin with a severity cue — 🟢 ready / 🟡 acceptable with caveats / 🔴 not production-ready — followed by a plain-language verdict stating the worst-case attacker capability and, when relevant, Critical/High counts. Then a red HTML blockquote containing 2–5 bullet points, each naming one critical attack path in bold followed by a one-sentence plain-language explanation and an italicised F-NNN citation in parentheses. After the blockquote, 1–2 closing sentences with the overall assessment. No CWE numbers, no file paths, no threat counts outside the opening sentence. F-NNN links inside the blockquote are allowed and expected.>

<Example:>

🔴 **CRITICAL SECURITY POSTURE** — An unauthenticated attacker can achieve full system compromise within minutes through multiple independent paths. The assessment identified **7 Critical** and **12 High** findings.

<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">

- **Full database theft without login** — A SQL Injection flaw in the product search lets any internet user extract the entire customer table in a single web request. *([F-009](#f-009))*
- **Admin login without a password** — A SQL Injection flaw in the login endpoint allows an attacker to log in as any user, including administrators, without knowing the password. *([F-014](#f-014))*
- **Server takeover from a normal user account** — Any logged-in user can send a crafted B2B order to run arbitrary OS commands on the server. *([F-010](#f-010))*
- **Admin impersonation via a leaked source-code secret** — The RSA private key used to sign session tokens is committed to the public repository; an attacker downloads it and issues valid admin tokens offline. *([F-001](#f-001), [F-005](#f-005))*

</blockquote>

No meaningful security boundary exists between the internet-facing attack surface and complete administrative control. The combination of these attack chains means the deployment is not production-ready.

<End example. Adapt the bullets and closing sentences to the actual findings. For 🟡 verdicts the bullets describe caveats; for 🟢 verdicts the blockquote may be omitted entirely and replaced by a short affirming paragraph.>

### Top Findings

<Intro sentence: "The **<N> highest-risk items** across code, configuration and architecture, sorted by impact-weighted score. F-IDs jump to full finding detail in [§8.B](#8b-critical-categories); AF-IDs jump to [§8.D](#8d-architectural-findings).">

<⚠ MANDATORY single-table layout (Phase-5, replaces the legacy two-table form). The table lists findings DIRECTLY — no separate Top Threats category table. The Category column carries the architectural pattern signal; a category-level overview remains in §8.A for reference but is NOT rendered in the Management Summary.>

**Sort order (mandatory, enforced by QA Check 3h):**

1. **Primary — triage-supplied `findings_ranked[]`** from `.triage-flags.json → ranking.views.top_findings`. Phase 11 reads this view and renders the table in exactly that order. The triage-validator computes the ranking using impact-weighted-v2 scoring (severity 150× + impact 40× + breach 15× + likelihood 3× + top25 5× + cvss 1×; contributor −50; ranking-cap −100).
2. **Fallback** (only when `.triage-flags.json` is absent or v1): sort by `effective_severity` desc → `breach_distance` asc → `cvss` desc → F-ID asc.

**Threshold:** include findings with `effective_severity ∈ {Critical, High}` (detective-capped findings like CWE-778 fall under High and may or may not make the cut). Limit to **15–20 rows** — when more findings qualify, truncate and append a footnote `_+N additional ≥High findings — see [Section 8.B](#8b-critical-categories) and [Section 8.D](#8d-architectural-findings)._` Anchors use the unsuffixed forms (`#8b-critical-categories`, `#8d-architectural-findings`) — no count-suffix.

**Never sort by F-ID alone.** The table's job is to give executives and engineers the highest-leverage fixes first — numeric ID order contradicts that.

| # | Criticality | Finding | Component | Threat | Vektor | Primary Mitigations |
|---|-------------|---------|-----------|--------|--------|---------------------|
| 1 | 🔴 Critical | [F-NNN](#f-NNN) — <short finding title, ≤50 chars> | [C-NN](#c-NN) — <Component name> | [TH-NN](#th-NN) — <Category name> | [Internet Anon](#vektor-internet-anon) | [M-NNN](#m-NNN) — <short action, ≤30 chars> (P1) |
| 2 | 🟠 High | [AF-NNN](#af-NNN) — <architectural weakness title> | Architecture | [TH-NN](#th-NN) — <Category name> | [n/a](#vektor-n-a) | [M-NNN](#m-NNN) — <short action> (P2) |

**Primary Mitigations column — title + priority required.** Every `[M-NNN](#m-nnn)` link MUST be followed by a short action label (≤30 characters) AND a trailing priority token `(P1)` / `(P2)` / `(P3)` / `(P4)` in parentheses, matching the mitigation's rollout priority from the Mitigation Register. Example: `[M-007](#m-007) — Parameterize all raw SQL queries (P1)`. Bare M-NNN links, missing labels, or missing priority tokens are format defects that QA Check 3h auto-repairs using the M-NNN title + priority from the YAML Mitigation Register. When multiple mitigations address a single finding, separate them with `<br/>` inside the cell. When the finding has ≥3 mitigations, render the top-2 and append `<br/>+N more`.

**Column semantics:**

| Column | Width | Content |
|---|---|---|
| `#` | narrow | 1-based rank from the triage view |
| `Criticality` | narrow | Emoji + word (🔴 Critical / 🟠 High). When `effective_severity > raw risk`, append ` *(effektiv)*` and render the effective value |
| `Finding` | wide | `[F-NNN](#f-NNN) — <short title>` — **uniform reference schema** (em-dash separator, same as mitigations and threats). Title is the first clause of the finding's scenario, truncated at the first `:` / `.` outside backticks, max 50 chars. **Do not inline the component reference here** — it belongs in the dedicated `Component` column |
| `Component` | narrow | `[C-NN](#c-NN) — <Component name>` — **uniform reference schema** (em-dash separator, same as findings and mitigations). Single linked cell, no `<br/><small>` wrapper. Resolved from `threat-model.yaml → findings[].component` (the canonical component id) and rendered with the component's canonical name. For AF-NNN entries whose scope is the whole architecture (no single component), render the literal string `Architecture` |
| `Threat` | medium | `[TH-NN](#th-NN) — <Category name>` — the architectural pattern (enables scanning for systemic clusters). **Required** — bare text categories without links are a format defect. |
| `Vektor` | narrow | `[<kebab-case id>](#vektor-<id>)` — clickable link to Appendix A — Vektor Taxonomy. Values: `Internet Anon`, `Internet User`, `Internet Priv User`, `Victim-Required`, `Build-Time`, `Repo-Read`, `n/a`. Bare-text Vektor values without links are a format defect auto-repaired by QA. |
| `Primary Mitigations` | medium | Up to 2 M-IDs separated by `<br/>`, each with short action label AND trailing `(P1)`/`(P2)`/`(P3)`/`(P4)` token. When the finding has ≥3 mitigations, append `<br/>+N more` |

**Clickability rule:** every F-NNN, TH-NN, M-NNN in this table MUST be a live anchor link. The F-NNN links are the **canonical cross-reference mechanism** throughout the document — every architecture-assessment paragraph, trust-boundary row, and control-catalog entry references findings by `[F-NNN](#f-NNN)`. This single table is the primary landing page for every F-ID link in the report.

> 🔴 = Critical · 🟠 = High. **"(effektiv)"** = Severity elevated via keystone role in a compound chain. **Vektor** values link to full definitions in [Appendix A — Vektor Taxonomy](#appendix-a-vektor-taxonomy).

<Worst-case scenarios are rendered as the bullets inside the Verdict blockquote above — there is no separate `### ⚠ Worst Case Scenarios` sub-section. The bullets already carry business-language names and F-NNN citations; nothing further is emitted between Top Findings and Architecture Assessment.>

### Architecture Assessment

<Opening line with a 🔴/🟡/🟢 verdict cue in bold, then 1–2 sentences stating the architectural verdict. It is allowed to reference F-NNN links in this opening prose when they anchor the verdict claim. No file paths, no CWE numbers.>

<Followed by a short framing sentence introducing the table (e.g. "Four cross-cutting defects drive ~40% of all findings:").>

<Table with the key cross-cutting architectural defects. Columns: Defect, Description, Key Findings. Sorted by impact. This 3-column schema is canonical.>

| Defect | Description | Key Findings |
|--------|-------------|--------------|
| **<defect name>** | <one-sentence description of the structural weakness and its architectural reach> | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> |
| **<defect name>** | <description> | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> |

<The Key Findings column MUST include a short label after each F-NNN link: `[F-NNN](#f-NNN) — <short label>`. Multiple findings are `<br/>`-separated inside the cell. Bare F-NNN links without a label are a format defect.>

<Closing line linking to §7: `See **[§7 Security Architecture](#7-security-architecture)** for the full per-domain assessment …`>

### Mitigations

This section presents all mitigations in two tiers: prioritized (fix immediately / next release) and follow-up (subsequent sprints).

#### Prioritized Mitigations

<One intro sentence: these address the Critical/High findings from the Top Findings table above. Entries are ordered by effort (lowest first), then by number of findings addressed (highest first).>

| ID | Mitigation | Component | Addresses | Effort |
|----|-----------|-----------|-----------|--------|
| [M-NNN](#m-NNN) | <title> | [C-NN](#c-NN) <Component name> | [F-NNN](#f-NNN) — <short label><br/>[F-NNN](#f-NNN) — <short label> | Low/Medium/High |

<One row per Prioritized mitigation. The Addresses column links back to the finding IDs from the Top Findings table. Every finding reference MUST include a short label after the F-NNN link. Every Critical finding in Top Findings MUST have at least one row here.>

#### Follow-up Mitigations

<One intro sentence: these address the remaining High/Medium findings not covered above. Same ordering rule (effort asc, then findings-addressed desc).>

| ID | Mitigation | Component | Addresses | Effort |
|----|-----------|-----------|-----------|--------|
| [M-NNN](#m-NNN) | <title> | [C-NN](#c-NN) <Component name> | [F-NNN](#f-NNN) — <short label> | Low/Medium/High |
| [M-NNN](#m-NNN) | <title> | [C-NN](#c-NN) <Component name> | [F-NNN](#f-NNN) — <short label> | Low/Medium/High |

<Both tables use the same five columns (ID, Mitigation, Component, Addresses, Effort) for visual consistency. The Component cell is a clickable `[C-NN](#c-NN) <name>` reference; when a mitigation spans multiple components, stack them with `<br/>`. The Addresses column uses F-NNN IDs with short labels, `<br/>`-separated.>

### Requirements Compliance

<ONLY when CHECK_REQUIREMENTS=true. Omit this entire subsection otherwise.>

**Baseline:** [<requirements source name or URL>](<url>)
**Result:** <N> requirements checked — <N_pass> PASS · <N_fail> FAIL · <N_antipattern> ANTI-PATTERN · <N_partial> PARTIAL

<Up to 3 bullets — only architectural violations. The full list lives in Section 7b.>

→ *Full compliance details in [Section 7b — Requirements Compliance](#7b-requirements-compliance).*

### Operational Strengths

<When the overall verdict is 🟡 or 🔴, open with: "Despite the <intentionally vulnerable / structurally deficient> design, the project implements several security-relevant controls. None fully mitigate Critical findings, but each reduces part of the attack surface.">

<⚠ MANDATORY 5-column table. The columns are `Architectural Control`, `Implementation`, `Effectiveness`, `Gap`, `Mitigates`. Legacy 3-column form (`Control / What it provides / Limitation`) is deprecated and auto-rewritten by QA Check 3i. Every row MUST use a **canonical architectural control name** from `$CLAUDE_PLUGIN_ROOT/data/architectural-controls.yaml` (not a library name). List 5–8 rows minimum, drawn from the rows in Section 7 (Identified Security Controls) where effectiveness ∈ {Adequate, Partial}. Missing controls do NOT appear in Operational Strengths — they live only in Section 7.>

| Architectural Control | Implementation | Effectiveness | Gap | Mitigates |
|-----------------------|----------------|---------------|-----|-----------|
| Multi-Factor Authentication | TOTP via `otplib` on std login | ⚠️ Partial | Not enforced on OAuth or API-token paths | [T-016](#t-016) — 2FA bypass |
| HTTP Security Headers | `helmet` (X-CTO, X-FO) | ⚠️ Partial | CSP absent; HSTS absent | [T-024](#t-024) — XSS via DomSanitizer, [T-039](#t-039) — Missing CSP |
| Parameterized Database Access | Sequelize ORM default | ⚠️ Partial | Raw string interpolation in search+login | [T-009](#t-009) — SQL injection product search |
| Authentication Rate Limiting | `express-rate-limit` on reset+2FA | 🔶 Weak | Not on /login; spoofable X-Forwarded-For key | [T-036](#t-036), [T-038](#t-038) |
| <... 5–8 rows total, one per existing control with effectiveness ≥ Weak ...> | | | | |

**Bottom line:** <One sentence summarizing that these controls narrow specific attack surfaces but none eliminates a Critical finding on its own.>

→ *Full details: [Section 2](#2-architecture-diagrams) · [Critical Attack Chain](#critical-attack-chain) · [Section 7](#7-threat-register) · [Section 9](#9-mitigation-register).*
```

**Column semantics:**

| Column | Content | Source |
|---|---|---|
| `Architectural Control` | Canonical tech-agnostic name | `architectural-controls.yaml → controls[].name` |
| `Implementation` | One-line how it's realised here (library + entry point or file) | Free text |
| `Effectiveness` | One of ✅ Adequate · ⚠️ Partial · 🔶 Weak (never Missing in this table) | Shared scale with Section 7 |
| `Gap` | Concrete shortcoming, one sentence | Derived from Section 7 "Limitation" |
| `Mitigates` | Linked threats this control is intended to affect | `[T-NNN](#t-NNN) — <short label>` format, `<br/>`-separated when ≥2 |

**Relationship to Section 7 (Identified Security Controls).** Operational Strengths is a **filtered view** of Section 7 — rows with `effectiveness ∈ {adequate, partial, weak}`. `❌ Missing` controls live only in Section 7. The QA reviewer Check 3i validates that every control name in Operational Strengths appears verbatim in Section 7 (same canonical name) and that no Missing control appears here.

**Rules — the hard constraints the QA reviewer enforces:**

- **`### Verdict` heading first, with integrated red HTML blockquote.** The first sub-section after `## Management Summary` MUST be `### Verdict`. Structure: (1) opening sentence with 🟢/🟡/🔴 severity cue + one-sentence verdict + (optionally) the `N Critical / M High` finding counts, (2) **a red HTML blockquote** containing 2–5 bold bullet points — each naming one critical attack path in business language followed by a plain-language explanation and a parenthesised italic F-NNN citation (e.g. `*([F-009](#f-009))*`), (3) 1–2 closing sentences with the overall assessment. The blockquote uses `<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">` with a `<br/>` spacer above it. The bullets inside this blockquote **are** the worst-case scenarios — do not emit a separate `### ⚠ Worst Case Scenarios` heading. F-NNN links are allowed inside the blockquote; CWE numbers and file paths remain forbidden.
- **Required sub-sections — exactly FIVE, presence and order enforced by the template:** `### Verdict`, `### Top Findings`, `### Architecture Assessment`, `### Mitigations` (with `#### Prioritized Mitigations` and `#### Follow-up Mitigations` sub-tables), `### Operational Strengths`. The `### Requirements Compliance` sub-section is mandatory **only** when `CHECK_REQUIREMENTS=true` and is placed between Mitigations and Operational Strengths.
- **Top Findings is a table, not a bullet list.** The table MUST have columns: `#`, `Criticality`, `Finding`, `Component`, `Threat`, `Vektor`, `Primary Mitigations`. Include ALL Critical findings and top High findings up to 15–20 rows total. Criticality emojis: 🔴 for Critical, 🟠 for High. Every Primary Mitigations cell MUST include a short action label AND a trailing priority token: `[M-NNN](#m-NNN) — <short action> (P1)`. Every Vektor cell MUST be a link to Appendix A. A legend line MUST follow the table. Finding IDs use the `[F-NNN](#f-NNN)` format; Component IDs use `[C-NN](#c-NN)`; Threat IDs use `[TH-NN](#th-NN)`.
- **Management Summary sub-sections MUST NOT be numbered.** Headings like `### 1.1 Verdict`, `### 1.2 Top Findings` are a generation defect — the QA reviewer auto-strips the numeric prefix. Every Management Summary heading is a plain `### <Name>` with no leading digit or section number.
- **Architecture Assessment uses a table.** The canonical form used in the reference output has columns: `Defect`, `Description`, `Key Findings` (each F-NNN link is followed by a short label via em-dash). A closing `See §7 Security Architecture` reference line is required. A legacy form with columns `Severity | Layer | Defect | Consequence | Enables` remains accepted but is deprecated — QA Check 3h does not rewrite it, it only checks that every F-NNN/T-NNN link carries a short label.
- **Mitigations section contains two sub-tables with identical 5-column structure.** Both use columns: `ID`, `Mitigation`, `Component` (`[C-NN](#c-NN) <name>`, `<br/>`-separated when ≥2), `Addresses` (F-NNN list with short labels, `<br/>`-separated), `Effort` (Low/Medium/High). `#### Prioritized Mitigations` lists mitigations for Critical / High findings, ordered by effort ascending then by coverage count descending. `#### Follow-up Mitigations` lists the remaining P2/P3/P4 mitigations in the same ordering. Every Critical finding in Top Findings MUST have at least one row in the Prioritized table. The legacy 4-column form (`Priority | Mitigation | Addresses | Effort`) is deprecated.
- **Operational Strengths MUST be a 5-column table** with columns: `Architectural Control`, `Implementation`, `Effectiveness`, `Gap`, `Mitigates`. The legacy 3-column form (`Control / What it provides / Limitation`) is deprecated — QA Check 3i auto-rewrites detected legacy tables. A 2-column table is FORBIDDEN. The table MUST have 5–8 rows minimum; when more rows would qualify, truncate and append a `_+N additional controls — see [Section 7](#7-security-architecture)._` footnote. Every control name MUST match a canonical name from `architectural-controls.yaml`. Ends with a `**Bottom line:**` sentence. The introductory paragraph before the table is mandatory when verdict is 🟡 or 🔴.
- **Forbidden sub-sections — the QA reviewer strips them on sight:**
  - `### Risk Distribution` / `### STRIDE Coverage` → lives in the Threat Register alone.
  - `### ⚠ Worst Case Scenarios` / `### Worst Case Scenarios` / `### Worst Case Scenario` (any variant) → **auto-strip** and merge their bullets into the Verdict's blockquote. The reference format integrates worst-case scenarios into the Verdict section; a standalone sub-section is a legacy layout.
  - `### Top Threats` / `### Top Critical Findings` / `### Critical Findings` → use `### Top Findings` table (F-NNN format, 7 columns).
  - `### Recommended Priority Actions` / `### Immediate Actions` → merged into `### Mitigations` (Prioritized Mitigations sub-table).
  - `### Follow-up Actions` (legacy name) → auto-rewrite to `### Mitigations` with two sub-tables.
  - `### Key Strengths` → auto-rewrite to `### Operational Strengths`.
  - `### Overall Security Rating` → the Verdict heading already carries the rating.
  - `#### Structural Defects` → merged into the Architecture Assessment table.
  - `### 1.1 Verdict` / `### 1.2 Top Findings` / any `### <digit>.<digit> <Name>` inside Management Summary → auto-strip the numeric prefix, keep the heading text.
- **No file paths or vscode:// links anywhere in the Management Summary.** F-NNN / M-NNN / T-NNN / TH-NN / C-NN links are allowed in the Verdict blockquote, Top Findings, Architecture Assessment (Key Findings / Enables column), and Mitigations. File references live in the Threat Register and Mitigation Register only.
- **No duplication — three roles, three places:** Management Summary = verdict-with-scenarios / top findings table / architecture defects table / mitigations / strengths. `## Critical Attack Chain` = attack-chain diagrams (visual). Threat Register = full per-finding detail (tabular).

### Persist Management Summary draft — MANDATORY before Phase 9 PHASE_END

**⚠ Before logging PHASE_END for Phase 9**, write the fully composed Management Summary to `$OUTPUT_DIR/.management-summary-draft.md`. This file is the handoff mechanism between Phase 9 (which has all threats, mitigations, and architecture data in working memory) and Phase 11 (which composes the final report). Phase 11 Part A MUST read this file and embed its contents verbatim as the `## Management Summary` section.

The draft file must contain the complete `## Management Summary` section with all five required sub-sections (`### Verdict` — with worst-case-scenarios bullets rendered inside its red HTML blockquote, `### Top Findings`, `### Architecture Assessment`, `### Mitigations` with `#### Prioritized Mitigations` and `#### Follow-up Mitigations`, `### Operational Strengths`) formatted exactly as specified in the "Build Management Summary" section above. Write it using a single Write tool call.

**Why this intermediate file exists:** In prior runs, the Management Summary was composed in-memory during Phase 9 but then lost when the LLM transitioned through Phase 10 and into Phase 11's multi-turn composition. Writing it to disk eliminates this failure mode — Phase 11 reads the file instead of relying on working memory.

**⚠ Hard gate — Phase 9 CANNOT log PHASE_END until the draft file exists.** Immediately after the Write tool call, assert the file is on disk and non-empty AND passes the structural validator. Any failure aborts Phase 9 with a `BASH_ERROR` that forces a re-composition in the same turn:

```bash
DRAFT="$OUTPUT_DIR/.management-summary-draft.md"
if [ ! -s "$DRAFT" ]; then
  echo "BASH_ERROR: $DRAFT missing or empty — Phase 9 cannot complete without a Management Summary draft. Re-compose and re-Write." >&2
  exit 1
fi
# Validate canonical structure before PHASE_END (exits non-zero on failure).
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" ms_structure "$DRAFT" || {
  echo "BASH_ERROR: Management Summary draft failed canonical-structure validation. Re-compose with the 5 canonical sub-sections (Verdict / Top Findings / Architecture Assessment / Mitigations / Operational Strengths) — numbered prefixes (1.1 / 1.2 / …) are forbidden." >&2
  exit 1
}
```

The `ms_structure` check auto-repairs numbered prefixes and legacy heading names in place (`### 1.1 Verdict` → `### Verdict`, `### Top Threats` → `### Top Findings`, etc.) before validating; only structurally missing canonical sub-sections or an absent Verdict blockquote produce a non-zero exit.

### Phase 9 completion — log PHASE_END immediately

**⚠ MANDATORY — emit PHASE_END for Phase 9 here, directly after all merge/coverage steps complete AND after the Management Summary draft is written, NOT deferred to Phase 11.** Batch this with the threat count computation so no turn is wasted on logging alone:

```bash
TOTAL_9=$(( ${CRIT:-0} + ${HIGH:-0} + ${MED:-0} + ${LOW:-0} ))
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  PHASE_END   [Phase 9/11] STRIDE — ${TOTAL_9} threats (Critical: ${CRIT:-0}, High: ${HIGH:-0}, Medium: ${MED:-0}, Low: ${LOW:-0})" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

If `CRIT`/`HIGH`/`MED`/`LOW` are not yet in scope, substitute the actual counts inline. Do not defer this log entry to Phase 11 — retroactive PHASE_END entries make the timing data useless.

---

## Phase 10: Secret & Dependency Scan Synthesis

**Step 1 — Hardcoded Secrets (always):** Read Section 7.12 and Section 7 from `$OUTPUT_DIR/.recon-summary.md`. Incorporate Critical/High secrets as threats (Information Disclosure / Spoofing). Use only file:line references and redacted snippets.

**Step 2 — SCA Results (only when `WITH_SCA=true`):** The dep-scan is now produced by the deterministic Python script `scripts/dep_scan.py` (launched in Phase 2 Step 2 as a background process), not by an agent. Wait for it to finish, then read `.dep-scan.json`:

```bash
if [ -f "$OUTPUT_DIR/.dep-scan.pid" ]; then
  DEP_SCAN_PID=$(cat "$OUTPUT_DIR/.dep-scan.pid" 2>/dev/null | tr -d '[:space:]')
  # Validate the PID before polling. An empty file or non-numeric content
  # would make `kill -0 ""` exit 1 instantly — the loop would still run
  # 120 iterations of useless `sleep 1`. Worse, a numeric-but-stale PID
  # from a killed prior run could be recycled by an unrelated process,
  # causing us to wait up to 120 s for a stranger's workload.
  if ! printf '%s' "$DEP_SCAN_PID" | grep -qE '^[0-9]+$' \
      || ! kill -0 "$DEP_SCAN_PID" 2>/dev/null; then
    echo "DEP_SCAN_SKIP: .dep-scan.pid missing, malformed, or already exited (pid='$DEP_SCAN_PID')" >&2
    rm -f "$OUTPUT_DIR/.dep-scan.pid"
  else
    # Bound the wait at 120s — dep_scan.py has its own per-tool 90s timeout,
    # so a clean run finishes well within this window even on slow networks.
    for _ in $(seq 1 120); do
      kill -0 "$DEP_SCAN_PID" 2>/dev/null || break
      sleep 1
    done
    rm -f "$OUTPUT_DIR/.dep-scan.pid"
  fi
fi
```

Then validate `.dep-scan.json` against the schema (same `validate_intermediate.py --schema dep_scan` path as before). Incorporate:
- `vulnerable_dependencies` → Tampering/Supply Chain threats

Log `AGENT_DONE` for the dep-scan after the wait completes (parity with the legacy agent's logging contract):

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   dep-scan  AGENT_DONE     SCA dependency scan complete" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

**Pre-built dedup index (mandatory, built during STRIDE Merge):** During the Phase 9 Merge step, the orchestrator MUST build a `known_vulns_seen` set while iterating the merged threat list — a set of `(component_id, cve_id, evidence.file)` tuples for every threat that originated from the STRIDE analyzers' `KNOWN_VULNS` input. Keep this set in working memory. In Phase 10 Step 2, iterate `vulnerable_dependencies` once and drop any entry whose `(component, cve, manifest)` tuple is already in the set. Do not re-compare threat-by-threat — the pre-built set makes dedup O(1) per candidate.

If the `known_vulns_seen` set was not built (e.g. no STRIDE analyzers used KNOWN_VULNS), fall back to a linear scan but log a `BASH_WARN` that the pre-filter was skipped.

If `WITH_SCA` is not set: skip SCA incorporation entirely.

### Phase 10 completion — refresh merged dump, annotate diagrams, log PHASE_END

**Step A — refresh `.threats-merged.json` (mandatory when Phase 10 added threats).**
If Phase 10 added any hardcoded-secret or SCA threats to the register, re-write `$OUTPUT_DIR/.threats-merged.json` so the file reflects the **final** threat list including the new T-NNN entries. Use the same deterministic dump protocol as the Phase 9 dump step. If Phase 10 added no threats (pure STRIDE run with SCA disabled and no hardcoded secrets), leave the file as-is.

**Step B — annotate diagrams (mandatory, non-fatal).**
Invoke both diagram annotators against the rendered `threat-model.md`. They read the merged JSON and rewrite Mermaid blocks in place:

- `annotate_architecture.py` — for every ``graph`` block with `%% component: <id>` comments, injects severity badge, classDef, click link, and one-line legend.
- `annotate_sequences.py` — for every ``sequenceDiagram`` with `%% components:`, `%% stride:`, and `%% attack-path` markers, injects a `Note over` line into the attack branch listing the top-3 matching threats.

Both scripts are idempotent; rerunning is safe.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/annotate_architecture.py" \
  --markdown "$OUTPUT_DIR/threat-model.md" \
  --threats  "$OUTPUT_DIR/.threats-merged.json" \
  >> "$OUTPUT_DIR/.agent-run.log" 2>&1 \
  || echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  WARN   threat-analyst  annotate_architecture failed — C4 diagrams remain unannotated" >> "$OUTPUT_DIR/.agent-run.log"

python3 "$CLAUDE_PLUGIN_ROOT/scripts/annotate_sequences.py" \
  --markdown "$OUTPUT_DIR/threat-model.md" \
  --threats  "$OUTPUT_DIR/.threats-merged.json" \
  >> "$OUTPUT_DIR/.agent-run.log" 2>&1 \
  || echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  WARN   threat-analyst  annotate_sequences failed — sequence diagrams remain unannotated" >> "$OUTPUT_DIR/.agent-run.log"
```

A non-zero exit code from either script is **logged as a warning, not treated as a fatal error** — unannotated diagrams are better than a broken pipeline. The most common cause of failure is a Phase-3/Phase-4 agent skipping the `%% component:` / `%% components:` / `%% stride:` / `%% attack-path` comment contract; in that case Section 7 is still correct and the human reader still gets clean (uncolored, unannotated) diagrams.

**Step C — log PHASE_END (⚠ MANDATORY — emit for Phase 10 here, after synthesis completes, NOT deferred to Phase 11):**

```bash
SCA_STATUS="${WITH_SCA:-false}"
if [ "$SCA_STATUS" = "true" ]; then SCA_MSG="SCA incorporated"; else SCA_MSG="SCA skipped"; fi
SECRET_COUNT=$(grep -c "HARDCODED_SECRET\|hardcoded" "$OUTPUT_DIR/.recon-summary.md" 2>/dev/null || echo 0)
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  PHASE_END   [Phase 10/11] Scan Synthesis — ${SECRET_COUNT} secrets from recon, ${SCA_MSG}" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## Phase 10b: Triage Validation — pre-flight Python + ranking agent

**Sequencing:** Phase 10b runs **after** Phase 10 Step C completes and **before** Phase 11 begins.

Phase 10b is split into two sub-steps:
1. **Pre-flight validation (Python, deterministic)** — `scripts/triage_validate_ratings.py` runs Steps 1–5 (consistency, plausibility, priority, completeness, CVSS scope) without an LLM. Output is merged into `.triage-flags.json`.
2. **Ranking agent (LLM)** — `appsec-triage-validator` runs Step 6 only (breach-distance inference, compound-chain detection, effective-severity computation, multi-view ranking).

### Sub-step A — Pre-flight rating validation (Python)

**Print before running:**
```
[Phase 10b/11] ▶ Triage Validation…
  ↳ Step 1/2 — Pre-flight rating validation (Python)…
  ↳ Validating <THREAT_COUNT> threats across <COMPONENT_COUNT> components
```

Run the deterministic pre-flight validator as a Bash call:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/triage_validate_ratings.py" \
  "$OUTPUT_DIR" --depth "$ASSESSMENT_DEPTH"
PRE_FLIGHT_EXIT=$?
```

**Log the call:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   Phase 10b pre-flight validation (triage_validate_ratings.py, depth: $ASSESSMENT_DEPTH)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

If the script exits non-zero, log a warning and continue — the pre-flight check is non-fatal:
```bash
if [ "$PRE_FLIGHT_EXIT" -ne 0 ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  WARN   threat-analyst  AGENT_ERROR   triage_validate_ratings.py exited $PRE_FLIGHT_EXIT — continuing without pre-flight flags" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
fi
```

### Sub-step B — Ranking agent (LLM)

Invoke `appsec-triage-validator` as a **blocking** (not background) sub-agent. It must complete before Phase 11 starts because Phase 11 reads `.threats-merged.json` (which Phase 10b may annotate with effective_severity fields) and `.triage-flags.json → ranking`.

**Print before dispatch:**
```
[Phase 10b/11]   ↳ Step 2/2 — Ranking & effective-severity (LLM agent)…
  ⟶ Dispatching triage-validator — infers breach distance, detects compound attack chains, computes effective severity, re-ranks top threats → .triage-flags.json  (expect ~30s)
```

**Agent tool parameters:**

```
subagent_type: "appsec-advisor:appsec-triage-validator"
description: "Triage validation of threat ratings"
model: $TRIAGE_MODEL
run_in_background: false
prompt: |
  REPO_ROOT=<REPO_ROOT>
  OUTPUT_DIR=<OUTPUT_DIR>
  ASSESSMENT_DEPTH=<ASSESSMENT_DEPTH>
  MODEL_ID=<TRIAGE_MODEL>
```

Pass `$TRIAGE_MODEL` (resolved from `--reasoning-model` by the skill) as the Agent tool's `model` parameter — overrides the agent's frontmatter `model: sonnet` default.

**Log before dispatch:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  AGENT_INVOKE   Triage validation (model: $TRIAGE_MODEL)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

### Post-dispatch

After the agent returns, verify that `$OUTPUT_DIR/.triage-flags.json` exists. Read its `summary` block.

**Log after completion:**
```bash
TRIAGE_FLAGS=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/.triage-flags.json')); print(f\"{d['summary']['total_flags']} flags ({d['summary']['warnings']} warnings, {d['summary']['info']} info)\")" 2>/dev/null || echo "0 flags (read error)")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  AGENT_DONE     Triage validation complete — $TRIAGE_FLAGS" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

**Print after completion:**
```
[Phase 10b/11] ✓ Triage Validation — <n> total flags (<w> warnings, <i> info)  [pre-flight + ranking]
```

### Error handling

If `appsec-triage-validator` fails (no `.triage-flags.json` written, or the file is invalid JSON), log a warning and continue to Phase 11 without triage annotations. Triage validation is **non-fatal** — a missing triage report does not block finalization.

```bash
if [ ! -f "$OUTPUT_DIR/.triage-flags.json" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  WARN   threat-analyst  AGENT_ERROR   Triage validator did not produce .triage-flags.json — continuing without triage flags" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
fi
```
