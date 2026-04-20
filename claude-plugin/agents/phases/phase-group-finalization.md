# Phase Group: Output & Finalization (Phase 11)

This file is read by the orchestrator at runtime to load phase instructions.

## `threat-model.yaml` Schema (v1)

The yaml is the **single structured baseline** for incremental runs. It is always written when `WRITE_YAML=true` (which is now the default — see SKILL.md flag matrix). Schema version 1:

```yaml
meta:
  schema_version: 1
  plugin_version: <semver>            # e.g. "0.9.0-beta" — read from plugin.json
  analysis_version: <int>             # semantic analysis version — bumped when
                                      # STRIDE prompts, recon categories, or
                                      # severity/CWE mapping change materially
  generated: <ISO>                   # UTC, e.g. 2026-04-11T10:22:00Z
  invocation: <string>               # full command, e.g. "/create-threat-model --assessment-depth thorough --stride-model opus --full --verbose"
                                      # always prefixed with "/create-threat-model"; empty args → "/create-threat-model"
  mode: full | incremental
  git:
    commit_sha: <full sha>            # CURRENT_SHA at the time of this run
    branch: <branch name>
    remote_url: <git remote origin url — optional>
  baseline_ref: <sha>                 # only set when mode=incremental; equal to the previous run's meta.git.commit_sha
  model: <model id>                   # e.g. claude-sonnet-4-6
  agent_models:                       # models used by sub-agents (when different from orchestrator)
    stride-analyzer: <model id>       # e.g. claude-opus-4-6 (only present when --stride-model was passed)
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

changelog:                            # append-only history, newest first
  - version: <int>                    # monotonic, 1, 2, 3, ...
    date: <ISO>
    mode: full | incremental
    plugin_version: <semver>          # plugin version that produced this entry
    analysis_version: <int>           # analysis version that produced this entry
    baseline_sha: <sha | null>        # null for full runs
    current_sha: <sha>
    changed_files: <int>              # 0 for full-rebuild entries
    reanalyzed_components: [<id>, ...]
    carried_forward_components: [<id>, ...]
    added:
      threats: [<T-ID>, ...]
      components: [<id>, ...]
      attack_surface: [<E-ID>, ...]
    changed:
      threats: [<T-ID>, ...]
    resolved:
      threats: [<T-ID>, ...]
      reason_by_id:
        <T-ID>: "<reason>"
    note: <string>                    # only for full-rebuild entries

components:                           # NEW in v1 — file-to-component mapping
  - id: <stable-id>                   # e.g. auth-svc — MUST be stable across runs
    name: <human name>
    kind: service | library | frontend | worker | cli | infrastructure
    paths: [<glob>, ...]              # path globs used by incremental dirty-set mapping
    threat_ids: [<T-ID>, ...]         # for quick lookup; authoritative source is threats[]
    last_analyzed_sha: <sha>          # the commit sha at the last successful STRIDE run for this component

assets: [...]                         # existing structure
attack_surface: [...]                 # existing structure; each entry has a stable E-ID
trust_boundaries: [...]               # existing structure
cross_repo_dependencies:              # auto-discovered cross-repo and SaaS dependencies
  - name: <string>                    # e.g. "auth-service", "Stripe"
    type: scm-sibling | saas          # how it was discovered
    interface: <string>               # REST API, gRPC, SDK, WebSocket, etc.
    repo_hint: <string | null>        # git URL, relative path, or null for SaaS
    threat_model:
      status: found | missing | outdated | n/a   # n/a for SaaS
      generated: <ISO | null>
      threats_total: <int | null>
      threats_critical: <int | null>
      threats_high: <int | null>
      threats_open: <int | null>
      components: [<string>, ...]     # component names from sibling TM
threats: [...]                        # existing structure; T-IDs MUST be stable across incremental runs
mitigations: [...]                    # existing structure; M-IDs stable
security_controls: [...]              # existing structure
requirements_compliance: [...]        # only when CHECK_REQUIREMENTS=true
out_of_scope: [...]                   # existing structure
```

**Hard invariants** (enforced by baseline_state.py and by incremental logic in Phase 9):

1. `meta.schema_version` is 1. Bump it only alongside a migration path.
2. T-IDs, M-IDs, and E-IDs are **stable across runs**. A carried-forward component must keep every one of its T-IDs. New IDs come from `.appsec-cache/baseline.json.id_counters`.
3. `changelog[]` is **append-only**. Never rewrite or delete historical entries, even on a full rebuild — instead, prepend a new `mode: full` entry.
4. `components[].paths` is the source of truth for the Phase 9 dirty-set mapping. Keep it in sync with the actual directory layout.
5. `meta.git.commit_sha` MUST be set to `git rev-parse HEAD` at the end of Phase 11, on every write. This is what the next run uses as baseline.
6. `meta.plugin_version` and `meta.analysis_version` MUST be read from `$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json` via `plugin_meta.py get` — never hardcoded. Every new `changelog[]` entry carries the same pair that was active at the time of that run, so a user can later reconstruct which claude-plugin/analysis version produced which threats.
7. `meta.recommend_full_rerun` is set to `true` iff the prior baseline's `analysis_version` was older than the current one but still in `compatible_analysis_versions` (i.e. `plugin_meta.py check-compat` returned exit 10). It is set to `false` on full runs and on equal-version incremental runs.

The renderer (`render_threat_model.py`) does not know or care about this schema — the yaml is composed and written directly by the orchestrator in Phase 11. The schema lives here as the authoritative contract.

## Mode-Aware Write Gate

Phase 11 writes several artifacts. Which artifacts actually get written depends on `INCREMENTAL`. This gate is the **single source of truth** — every Write tool call in this phase must consult it.

| `INCREMENTAL` | `threat-model.md` | `threat-model.yaml` | `.appsec-cache/baseline.json` | `.stride-*.json` retention | changelog entry |
|---|---|---|---|---|---|
| `false` (full) | **overwrite** | **overwrite** (changelog history preserved, new `mode: full` entry appended) | **overwrite** | regenerated | append `mode: full` entry |
| `true` (incremental) | **update in place** (Changelog section refreshed) | **update in place** (append new entry to `changelog[]`) | **update** (refresh fingerprints + id counters) | per-component overwrite or carry-forward | append `mode: incremental` entry |

**Computed flag** — set this once at the start of Phase 11:
```bash
if [ "$INCREMENTAL" = "true" ]; then
  WRITE_MODE="incremental"
else
  WRITE_MODE="full"
fi
```

Dry-run mode is handled entirely by the skill layer — it redirects `OUTPUT_DIR` to a temp directory. The orchestrator and finalization phase always write normally to whatever `OUTPUT_DIR` they receive.

All subsequent substeps branch on `$WRITE_MODE`.

## Phase 11: Finalization

### Phase Start — capture epoch, checkpoint, and determine N

The PHASE_START Bash call for Phase 11 MUST do three things in one batch:

1. Reset the phase-epoch so all `(+MMmSSs)` elapsed timers below measure Phase 11 only, not earlier phases.
2. Write the phase-11 checkpoint.
3. Print the PHASE_START line.

```bash
date +%s > "$OUTPUT_DIR/.phase-epoch"
echo "CHECKPOINT phase=11 status=writing_output" > "$OUTPUT_DIR/.appsec-checkpoint"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  PHASE_START   [Phase 11/11] Finalization…" >> "$OUTPUT_DIR/.agent-run.log"
```

**Compute `N` (total substep count) at phase start** based on `WRITE_MODE` and active flags. Keep `N` stable for the whole phase — advance `k` even if a step is skipped so the final print shows `[N/N]`:

| `WRITE_MODE` | Base substeps | +SARIF | +Pentest | `N` |
|---|---|---|---|---|
| `full` | lock+precompute, write yaml, write cache, write fragments, render md (compose), qa contract gate, clear-checkpoint = **7** | +1 if `WRITE_SARIF=true` | +1 if `WRITE_PENTEST_TASKS=true` | **7–9** |
| `incremental` | lock+precompute, update yaml, update cache, refresh fragments, render md (compose), qa contract gate, clear-checkpoint = **7** | +1 if `WRITE_SARIF=true` | +1 if `WRITE_PENTEST_TASKS=true` | **7–9** |
| `repair` | write/update targeted fragments from `.qa-repair-plan.json`, render md (compose), qa contract gate, clear-checkpoint = **4** | +0 | +0 | **4** |

Note: the old `WRITE_YAML=false` path no longer exists — yaml is now always-on. The `--no-yaml` escape hatch (if set) simply omits the yaml write substep and subtracts 1 from `N`. `repair` mode is entered by the skill's Re-Render Loop (see `skills/create-threat-model/SKILL.md`) when the QA reviewer emits a non-empty `.qa-repair-plan.json`; it skips every upstream phase and only reopens the fragment+compose pipeline.

Substitute the concrete integer for every `N` below. Do not write the literal letter `N` into log lines.

**The LLM NEVER writes `threat-model.md` directly** — the only legal writer is `compose_threat_model.py`. Previous versions of this document described a "Parts A–D" hand-composed flow; that path has been **removed**. If any prompt in this file seems to instruct a direct `Write` of `threat-model.md`, treat it as a stale artefact and use the fragment-driven path instead (Substeps 4 + 5 in the canonical table below).

### Plugin Version Stamping

Before composing the yaml or md (and **before** the pre-compute substep below), read the current plugin version and classify the prior baseline's compatibility. This happens once, produces four shell variables, and is reused by substeps 1–5 and the final summary.

```bash
PLUGIN_VERSION=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/plugin_meta.py" get plugin_version)
ANALYSIS_VERSION=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/plugin_meta.py" get analysis_version)

# Classify the prior baseline. Only meaningful for incremental mode; for full
# runs RECOMMEND_FULL is always false.
if [ "$WRITE_MODE" = "incremental" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" check-compat \
    --output-dir "$OUTPUT_DIR"
  COMPAT_EXIT=$?
  case "$COMPAT_EXIT" in
    0)  RECOMMEND_FULL=false ;;   # equal — no action
    10) RECOMMEND_FULL=true  ;;   # older but compatible — recommend
    20) RECOMMEND_FULL=true  ;;   # incompatible — gate should have caught this; be loud
    30) RECOMMEND_FULL=true  ;;   # legacy baseline, no version — recommend
    *)  RECOMMEND_FULL=false ;;
  esac
else
  RECOMMEND_FULL=false
fi

# Extract prior analysis_version from the baseline yaml (if any) for the
# header callout. Empty string when absent.
PRIOR_ANALYSIS_VERSION=""
if [ -f "$OUTPUT_DIR/threat-model.yaml" ]; then
  PRIOR_ANALYSIS_VERSION=$(grep -E '^\s{2}analysis_version:' "$OUTPUT_DIR/threat-model.yaml" | head -1 | awk '{print $2}')
fi

echo "PLUGIN_META: plugin_version=$PLUGIN_VERSION analysis_version=$ANALYSIS_VERSION recommend_full=$RECOMMEND_FULL prior=$PRIOR_ANALYSIS_VERSION"
```

Use these variables when composing the yaml `meta` block, every new `changelog[]` entry, the md header metadata table, and the assessment summary footer. **Never hardcode the version strings** — they must come from `plugin_meta.py` so that bumping `plugin.json` is enough to roll a release.

**Rendering the baseline-older callout in `threat-model.md`:** when `RECOMMEND_FULL=true` AND `WRITE_MODE=incremental`, emit the following block directly under the header metadata table:

```markdown
> ⚠ **Baseline is older than the current plugin**
>
> The previous threat model was produced with `analysis_version=<PRIOR_ANALYSIS_VERSION>`; the current plugin runs `analysis_version=<ANALYSIS_VERSION>`.
> This incremental run carried the existing findings forward, but the STRIDE analysis logic has since been improved.
> **Recommendation:** run `/appsec-plugin:create-threat-model --full` at your next opportunity to pick up the improvements.
```

Omit the callout entirely when `RECOMMEND_FULL=false`.

### Write Output Files

**⚠ MANDATORY STEP_START CONTRACT — no exceptions:**

- Every substep below MUST emit exactly one STEP_START log line **before** performing its work.
- Each STEP_START MUST be **batched in the same Bash / tool call** as the work it describes — never spend an extra orchestrator turn on logging alone. If a substep is implemented by a `Write` tool call (not Bash), emit the log in a preceding Bash call that **also advances** something concrete (e.g. reading a count, pre-computing a variable) so the turn is not wasted.
- The format is non-negotiable and identical to Phase 3–10: `[Phase 11 +${ES}] [k/N] <description>`. Any deviation breaks the ASSESSMENT_SUMMARY parser.
- Silent substeps (no STEP_START) are treated as a Phase 11 defect — this is the single most common reason Phase 11 looks like a hang.

**Elapsed-time helper — inline at the start of every STEP_START Bash call:**
```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60)))
```

**Canonical STEP_START echo — substitute `<k>`, concrete integer for `N`, and `<description>`:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [<k>/<N>] <description>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

Also mirror each step to stdout: `  ↳ [<k>/<N>] <description>  (+${ES})`.

**Substeps (in order) — every one MUST log before doing the work:**

**⚠ ORDERING INVARIANT (since M2.7): write the YAML _before_ the Markdown.** The yaml is the structured baseline that every future incremental run reads; if a substep crashes, the Markdown can always be re-rendered from the yaml, but a missing yaml breaks the baseline and forces a full rebuild on the next run. Previously the md was written first, and several production runs ended mid-markdown-Write with no yaml on disk — leaving an orphan md and a broken incremental pipeline. The new order fixes this at zero cost: both files still need the same merged-threat data, and yaml is cheap to serialize (~45 KB of structured data vs ~90 KB of composed prose).

**ALSO — release the lock BEFORE the slow MD compose (since M2.7).** The old placement (`k=N`, last) meant the lock leaked on any mid-Write crash. Phase 11 is single-session and no other phase runs in parallel, so releasing the lock at `k=1` is safe and guarantees cleanup even if the LLM session dies during the long md compose.

| `k` | Description template | Condition | Batched with |
|-----|----------------------|-----------|--------------|
| 1 | `Releasing lock + pre-computing final counts…` | always | the Bash block that runs `rm -f "$OUTPUT_DIR/.appsec-lock"` + the count computation below. The lock is released first because Phase 11 is terminal; the pre-compute runs in the same turn so no budget is wasted on lock cleanup alone. |
| 2 | `Writing threat-model.yaml (canonical baseline)…` | **always — skip ONLY when `WRITE_YAML=false` (user passed `--no-yaml`).** Yaml is the canonical baseline for future incremental runs; skipping it by default breaks the incremental pipeline. | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.yaml`. **⚠ This MUST run before the md write — see ordering invariant above.** Immediately after the Write succeeds, advance the checkpoint: `echo 'CHECKPOINT phase=11 step=2 status=yaml_written' > "$OUTPUT_DIR/.appsec-checkpoint"` so that a crash during the md compose leaves a recoverable state. |
| 3 | `Updating .appsec-cache/baseline.json…` | always | the Bash call that invokes `baseline_state.py update` — see "Baseline Cache Update" below. This runs here (right after yaml) rather than at the end so the cache is consistent with the yaml even if later md composition fails. |
| 4 | `Writing data fragments for threat-model.md…` | always | Bash STEP_START + several `Write` tool calls (one per LLM-authored fragment) — see "Fragment-driven composition" below. The LLM emits schema-validated JSON data for the Verdict / Architecture Assessment / Critical Attack Chain sections and prose Markdown for the handful of prose-only sections. Advance checkpoint to `step=4 status=fragments_written` only after `validate_fragment.py` accepts every data fragment. |
| 5 | `Rendering threat-model.md (contract-driven composition)…` | always | Bash call to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" --output-dir "$OUTPUT_DIR"`. The renderer is deterministic — identical fragments produce byte-identical output. No Markdown is ever written by the LLM in this step. Advance checkpoint to `step=5 status=md_rendered`. |
| 6 | `Running QA structural checks…` | always | Bash call to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" all "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT"`. Includes the contract-compliance check (`qa_checks.py contract`) as a hard gate — on failure the composition is re-run. Advance checkpoint to `step=6 status=qa_clean`. |
| 7 *or* 8 | `Generating SARIF export (<n> results) and writing threat-model.sarif.json…` (substitute `<n>`) | only if `WRITE_SARIF=true` | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.sarif.json` |
| 8 *or* 9 | `Generating pentest tasks (<n> eligible threats) and writing pentest-tasks.yaml…` (substitute `<n>`) | only if `WRITE_PENTEST_TASKS=true` | the Bash call that invokes `render_pentest_tasks.py` — see "Pentest-Task Export" below. The `<n>` counter reports only the threats that passed the eligibility filter, not the full threat-register size. |
| N | `Clearing checkpoint + printing summary…` | always, LAST | the final cleanup Bash call — removes `.appsec-checkpoint` and prints the assessment summary. The lock has already been released at `k=1`, so this substep only clears the checkpoint marker. |

### Pentest-Task Export

When `WRITE_PENTEST_TASKS=true`, emit `$OUTPUT_DIR/pentest-tasks.yaml` *after* the SARIF export (or after the md write if SARIF is off) by calling the dedicated renderer. The orchestrator does NOT compose this file in-prompt — the exporter is deterministic Python and keeps the CWE eligibility logic identical to the CVSS-scope enforcement in Phase 10b.

```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [<k>/<N>] Generating pentest tasks and writing pentest-tasks.yaml…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_pentest_tasks.py" \
  --merged "$OUTPUT_DIR/.threats-merged.json" \
  --output "$OUTPUT_DIR/pentest-tasks.yaml" \
  --dialect "${PENTEST_FORMAT:-generic}" \
  --threat-model "threat-model.yaml" \
  ${PENTEST_TARGET_URL:+--target-url "$PENTEST_TARGET_URL"}
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py" \
  pentest_tasks "$OUTPUT_DIR/pentest-tasks.yaml"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  FILE_WRITE   $OUTPUT_DIR/pentest-tasks.yaml" >> "$OUTPUT_DIR/.agent-run.log"
```

**Why run the validator in the same step:** the exporter is deterministic, but a malformed `.threats-merged.json` (e.g. a missing `evidence` block) could still pass the eligibility filter and produce an invalid task list. Running `validate_intermediate.py pentest_tasks` immediately catches that at Phase 11 rather than surfacing the failure in downstream pentest tooling.

**Safety defaults.** The renderer marks every task with `safety.read_only=true` and `safety.destructive_actions=forbidden`. A consumer tool (Strix etc.) MUST respect those fields or it risks running destructive probes against production. If the team explicitly wants state-changing tests, they can post-process the generated file — the orchestrator never emits a task with destructive actions enabled by default.

**Completion summary footer.** When `WRITE_PENTEST_TASKS=true` and `pentest-tasks.yaml` exists, append a `<OUTPUT_DIR>/pentest-tasks.yaml  (<n> bytes, <t> tasks)` line to the file-list block, next to the SARIF line.

**Substep 1 — release lock + pre-compute counts (mandatory Bash template, batched with the `[1/N]` STEP_START):**

```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [1/<N>] Releasing lock + pre-computing final counts…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
# Release lock FIRST so any mid-phase crash below cannot leak it. Phase 11 is terminal.
rm -f "$OUTPUT_DIR/.appsec-lock"
echo 'CHECKPOINT phase=11 step=1 status=lock_released' > "$OUTPUT_DIR/.appsec-checkpoint"
CRIT=$(grep -c '"risk": *"Critical"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
HIGH=$(grep -c '"risk": *"High"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
MED=$(grep -c '"risk": *"Medium"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
LOW=$(grep -c '"risk": *"Low"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
COMPS=$(ls "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | wc -l)
MITS=$(grep -c '"mitigation_title"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
echo "COUNTS: crit=$CRIT high=$HIGH med=$MED low=$LOW comps=$COMPS mits=$MITS"
```

Use the printed `COUNTS:` line to populate concrete numbers in the Management Summary, Section 8 headings (`### 7.1 Critical (<CRIT>)`, …), and the assessment summary footer. These counts are ground truth — do not recompute them by eye during composition.

**Substep 2 — write threat-model.yaml (MUST run before md write):**

Compose the full yaml body in memory (schema at top of this file). The Write tool call in this substep carries the yaml `content:` argument. Batch it with a `[2/<N>] Writing threat-model.yaml (canonical baseline)…` STEP_START echo **in the same turn**. Yaml composition is ~45 KB and typically completes in one turn; if the model needs a second turn to finish, the checkpoint from substep 1 is enough to recover.

**Why yaml first:** if the run crashes during the subsequent ~90 KB markdown write (historically the most expensive and failure-prone substep in Phase 11), the canonical structured baseline is already on disk. Any future run — incremental, full, or resume — can read the yaml to know what was found, the markdown can be re-rendered from it, and the incremental pipeline is not broken.

**After the Write succeeds, advance the checkpoint in the next Bash batch:**
```bash
echo 'CHECKPOINT phase=11 step=2 status=yaml_written' > "$OUTPUT_DIR/.appsec-checkpoint"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  FILE_WRITE   $OUTPUT_DIR/threat-model.yaml" >> "$OUTPUT_DIR/.agent-run.log"
```

**Substep 3 — update baseline cache:**

Run the `baseline_state.py update` block from the "Baseline Cache Update" section below, batched with a `[3/<N>] Updating .appsec-cache/baseline.json…` STEP_START echo. The cache is now consistent with the yaml even if md composition later fails. Advance checkpoint to `step=3 status=cache_updated`.

**Substeps 4–6 — Contract-driven fragment composition (since M2.8)**

⚠ **Major architectural change — the LLM no longer writes `threat-model.md` directly.** Instead, the orchestrator writes schema-validated data fragments and short prose-Markdown fragments into `$OUTPUT_DIR/.fragments/`, then invokes the deterministic `compose_threat_model.py` renderer to produce the final Markdown. This eliminates the recurring structural-drift failure mode where the LLM invented its own Management Summary layout, dropped the Verdict blockquote, renamed Top Findings to "Top Threats", or numbered sub-sections `1.1 … 1.5`.

**How the LLM contributes content — and how it is constrained:**

| Section | Fragment file | LLM writes | Renderer guarantees |
|---|---|---|---|
| Verdict (MS) | `.fragments/ms-verdict.json` | `{severity, opening, bullets[], closing}` — schema-validated against `schemas/fragments/verdict.schema.json` | Red HTML blockquote, F-/T-NNN anchor linkification, 🟢/🟡/🔴 emoji, heading `### Verdict` (unnumbered). |
| Architecture Assessment (MS) | `.fragments/ms-architecture-assessment.json` | `{verdict_severity, verdict_prose, framing, defects[]}` — schema-validated | 3-column table (Defect / Description / Key Findings), heading `### Architecture Assessment`, closing §7 reference. |
| Top Findings (MS) | — | (no fragment — derived from `threat-model.yaml` + triage ranking) | 7-column table, canonical sort order, max-20 rows, legend. |
| Mitigations (MS) | — | (no fragment — derived from `threat-model.yaml → mitigations[]`) | Prioritized + Follow-up sub-tables, 5 columns each, effort-asc sort. |
| Operational Strengths (MS) | `.fragments/operational-strengths-overrides.json` (optional) | `{intentionally_vulnerable_or_deficient, bottom_line}` | 5-column table filtered from `security_controls[]`, 5–8 rows, bottom-line sentence. |
| Critical Attack Chain | `.fragments/critical-attack-chain.json` | `{intro, mermaid{nodes,edges}, key_takeaway, stages[]}` | Mermaid `graph LR`, Stage/Finding/Mitigation table, unnumbered `## Critical Attack Chain`. |
| System Overview (§1) | `.fragments/system-overview.md` | Plain Markdown starting with `## 1. System Overview` | Heading-match validation, inlined verbatim. |
| Architecture Diagrams (§2) | `.fragments/architecture-diagrams.md` | Plain Markdown with required `### 2.1 System Context`, `### 2.3 Security Architecture Assessment`, and at least one `` ```mermaid `` block | Required-subsection + required-pattern validation. |
| Attack Walkthroughs (§3) | `.fragments/attack-walkthroughs.md` | Plain Markdown with at least one `sequenceDiagram` per Critical finding | Required-pattern validation. |
| Assets (§4) | `.fragments/assets.md` | Plain Markdown containing a `\| Asset \|` table | Required-pattern validation. |
| Attack Surface (§5) | `.fragments/attack-surface.md` | Plain Markdown with required `### 5.1 Unauthenticated…` and `### 5.2 Authenticated…` sub-sections | Required-subsection validation. |
| Security Architecture (§7) | `.fragments/security-architecture.md` | Plain Markdown starting with `## 7. Security Architecture` | Heading-match validation. |
| Threat Register (§8) | — | (no fragment — derived from `threat-model.yaml → threats[]`) | Risk Distribution + STRIDE Coverage lines, 8.1–8.4 sub-tables with 9-column schema, ID anchors. |
| Mitigation Register (§9) | — | (no fragment — derived from `threat-model.yaml → mitigations[]`) | P1–P4 sub-sections, per-mitigation heading with anchor, **Addresses / Priority / Severity / Effort / Why / How / Verification** block. |
| Out of Scope (§10) | `.fragments/out-of-scope.md` | Plain Markdown starting with `## 10. Out of Scope` | Heading-match validation. |
| Appendix: Run Statistics | — | (no fragment — derived from `threat-model.yaml → meta.run_statistics`) | Deterministic tables, only rendered when `verbose_report=true`. |
| Appendix A: Vektor Taxonomy | — | (no fragment — derived from `claude-plugin/data/breach-vector-taxonomy.yaml`) | Fixed `<a id="vektor-…">` anchor per vektor. |

**Hard gates (all must pass or the whole Phase 11 re-runs):**

1. After every fragment Write, call `validate_fragment.py` for JSON fragments and `compose_threat_model.py` will re-validate at render time. A schema violation aborts with `RENDER_FAILED` and a pointer to the offending field:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_fragment.py" verdict "$OUTPUT_DIR/.fragments/ms-verdict.json" || {
     echo "BASH_ERROR: ms-verdict.json failed schema validation — fix and re-Write before continuing." >&2
     exit 1
   }
   ```

2. After rendering, run the contract-compliance check:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" contract "$OUTPUT_DIR/threat-model.md" || {
     echo "BASH_ERROR: threat-model.md violates sections-contract.yaml — inspect the printed issues and re-render." >&2
     exit 1
   }
   ```

3. Optional layer-3 auto-repair for MS heading drift (numeric prefixes, legacy names) via `qa_checks.py ms_structure` — runs inside `qa_checks.py all` during substep 6.

**What the LLM does NOT do any more:** the composer **never** emits Markdown for the Management Summary, Threat Register, Mitigation Register, ToC, infobox, changelog, or appendices. All of those are machine-rendered. This cuts Phase 11 output tokens from ~50k to ~4k and makes the output byte-identical across reruns with unchanged inputs.

---

## Legacy direct-write path — REMOVED

The multi-part "Parts A–D" direct-write flow that this file used to document has been **removed**. It required the LLM to emit the entire ~90 KB markdown body via `Write`/`heredoc` tool calls, which repeatedly drifted from `sections-contract.yaml` and produced non-canonical Management Summaries, missing appendices, and forbidden section numbering.

**Current rule (since M2.8, enforced since M3.0):** Every render of `threat-model.md` goes through:

```
.fragments/*.json|md  →  python3 compose_threat_model.py --output-dir $OUTPUT_DIR --strict
```

- The orchestrator writes fragments under `$OUTPUT_DIR/.fragments/` (Substep 4 in the canonical table above).
- The renderer is the single legal writer of `threat-model.md` (Substep 5).
- A `Write` tool call with `file_path=$OUTPUT_DIR/threat-model.md` from the orchestrator is a **policy violation** — the skill's post-Phase-11 contract gate will detect the structural drift and spawn a repair cycle.

## Fragment authoring reference

The sections below describe the **content expected inside each fragment**. They are prescriptions for the fragment authors (the orchestrator during Substep 4), not instructions to write markdown directly. Every fragment is validated against `schemas/fragments/<name>.schema.json` (for `data` fragments) or against required-pattern/required-subsection rules in `data/sections-contract.yaml` (for `markdown` fragments) before the renderer runs.

### What the Management Summary fragments must encode

The report always starts with `# Threat Model — <Project Name>`, followed immediately by a **project infobox** — a blockquote table with at-a-glance project metadata. See `appsec-threat-analyst.md` → "Project infobox" for the full field list and extraction rules. The infobox is always rendered (not gated on `VERBOSE_REPORT`). After the infobox, emit `---`.

When `meta.recommend_full_rerun=true`, render a `> ⚠ **Baseline is older than the current plugin (analysis v<OLD> → v<NEW>). A full re-assessment is recommended.**` callout directly below the `---`.

**A2. Changelog**

Placed immediately below the header (after `---`), **always rendered** when `changelog[]` in `threat-model.yaml` is non-empty (append-only history, newest entry first). See "Changelog Section" below for the exact template.

**A3. Table of Contents (fully numbered)**

Generate a Markdown ordered list (`1.`, `2.`, …) from actual sections produced. **Management Summary and Critical Attack Chain are numbered entries** at the top of the list — they are not unnumbered bullet points. The numbering is:

1. Management Summary
2. Critical Attack Chain (omit when < 2 Critical findings)
3. System Overview (= `## 1. System Overview`)
4. Architecture Diagrams (= `## 2. Architecture Diagrams`)
5. … (continue for all subsequent `## N.` sections)
N. Appendix: Run Statistics (only when `VERBOSE_REPORT=true`)

The Changelog section is **not** listed in the ToC (it is a meta-section between the infobox and the ToC). Sub-sections (e.g. `2.1 System Context`, `8.1 Critical`) are indented with `   -` under their parent. The ToC numbers are a **presentation sequence** — they do not change the `## N.` heading numbers in the actual sections (Section 1 remains `## 1. System Overview`, not `## 3. System Overview`).

**A4. Management Summary — ⚠ MANDATORY, NEVER OMIT**

The Management Summary is the **single most important section** for stakeholders. **A threat model without a Management Summary is considered incomplete and broken — equivalent to a missing Threat Register.** If turn budget is tight, reduce other sections (shorten Architecture Assessment themes, skip optional diagrams) but **always emit the full Management Summary**.

**Source:** Read the draft from `$OUTPUT_DIR/.management-summary-draft.md` (written by Phase 9) and embed its contents verbatim. If the draft file does not exist (error recovery path), compose the Management Summary inline from the `.stride-*.json` data — but this is a fallback, not the normal path. Log a warning if the draft file is missing: `WARN: .management-summary-draft.md not found — composing Management Summary inline`.

The Management Summary section MUST contain **exactly five** required sub-sections in this exact order. Every sub-section uses the format defined in `phase-group-threats.md` → "Build Management Summary":

1. `### Verdict` — Opening sentence with 🟢/🟡/🔴 severity cue, then a **red HTML blockquote** containing 2–5 bold bullet points naming the critical attack paths in business language — each ending with an F-NNN reference in italics (e.g. `*([F-009](#f-009))*`). The blockquote uses `<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">`. After the blockquote, 1–2 closing sentences with the overall assessment. The worst-case scenarios are rendered **as the bullets inside this blockquote** — there is no separate `### ⚠ Worst Case Scenarios` sub-section.
2. `### Top Findings` — table with 7 columns: `#` (rank), `Criticality` (🔴/🟠), `Finding` (F-NNN link + short title), `Component` (C-NN link + name, or literal `Architecture` for AF-NNN), `Threat` (TH-NN link + category), `Vektor` (linked to Appendix A), `Primary Mitigations` (M-NNN links — each followed by short action and trailing priority token `(P1)`/`(P2)`/…). Include ALL Critical findings and top High findings (up to 15–20 rows total). Legend line after table.
3. `### Architecture Assessment` — prose intro + table with columns: Defect, Description, Key Findings (or: Severity, Layer, Defect, Consequence, Enables for the legacy form). Every F-NNN/T-NNN link in Key Findings/Enables includes a short label. Closes with a "See §7 Security Architecture" reference.
4. `### Mitigations` — contains two sub-tables:
   - `#### Prioritized Mitigations` — mitigations that address the Critical/High findings from the Top Findings table. Ordered by effort (lowest first), then by coverage count.
   - `#### Follow-up Mitigations` — P2/P3/P4 mitigations for remaining High/Medium findings not covered above.
   - Both tables use **five columns**: `ID`, `Mitigation`, `Component` (`[C-NN](#c-NN) <name>`), `Addresses` (F-NNN list with short labels, `<br/>`-separated), `Effort` (Low/Medium/High). Every finding reference in the Addresses column includes a short label: `[F-NNN](#f-NNN) — <short description>`.
5. `### Operational Strengths` — **5-column table** (`Architectural Control`, `Implementation`, `Effectiveness`, `Gap`, `Mitigates`) with 5–8 rows. Closes with a trailing `_+N additional controls — see [Section 7](#7-security-architecture)._` footnote when the catalog has more than 8 eligible rows, then a `**Bottom line:**` sentence.

Optional: `### Requirements Compliance` (only when `CHECK_REQUIREMENTS=true`), placed between Mitigations and Operational Strengths.

Optional: `### Triage Notes` (only when `$OUTPUT_DIR/.triage-flags.json` exists and contains warnings). Placed between Operational Strengths and the end of the Management Summary. Contains a brief summary of triage validation results:

```markdown
### Triage Notes

The automated triage validator flagged **<n> warnings** across the threat assessment that may warrant manual review:

| Flag | Affected Threats | Issue |
|------|-----------------|-------|
| TF-001 | T-003, T-007 | <message from flag> |
| ... | ... | ... |

> These flags indicate potential rating inconsistencies — they do not invalidate the threat model. Review each flag and adjust ratings if appropriate.
```

If `.triage-flags.json` has zero warnings (only `info` flags or no flags at all), omit this sub-section entirely.

**A5. Critical Attack Chain**

**Unnumbered** `## Critical Attack Chain` section, placed **immediately** after the Management Summary and **before** Section 1. Contains: attack-chain Mermaid diagram (`graph LR`) + "Key takeaway" sentence + quick-reference table linking back to Section 7.1. The anchor is `#critical-attack-chain`. Omit the section entirely when there are 0 or 1 Critical findings (a single Critical cannot form a chain).

**A6. Sections 1–4**

- Section 1 — System Overview
- Section 2 — Architecture Diagrams (all sub-sections, all Mermaid blocks)
- Section 3 — Attack Walkthroughs (one `sequenceDiagram` per Critical finding)
- Section 4 — Assets

This part contains the diagrams and is typically the largest (~30–35 KB). Advance checkpoint to `step=4 status=part_a_written`.

**⚠ Part A hard gate — validate Management Summary structure before advancing checkpoint.** Immediately after the Write tool call completes, in the same Bash batch that advances the checkpoint, run the deterministic structural validator. It auto-repairs numbered prefixes and legacy heading names in place (e.g. `### 1.1 Verdict` → `### Verdict`, `### Top Threats` → `### Top Findings`) and exits non-zero when a canonical sub-section is missing. A non-zero exit blocks Part B — the orchestrator re-composes Part A in the same turn:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" ms_structure "$OUTPUT_DIR/threat-model.md" || {
  echo "BASH_ERROR: Part A Management Summary failed canonical-structure validation. Re-emit Part A using the five canonical sub-sections (### Verdict with red HTML blockquote / ### Top Findings 7-col table / ### Architecture Assessment 3-col table / ### Mitigations with Prioritized + Follow-up sub-tables / ### Operational Strengths 5-col table). Do NOT use numbered prefixes (1.1/1.2/…). See phase-group-threats.md → Build Management Summary." >&2
  exit 1
}
echo 'CHECKPOINT phase=11 step=4 status=part_a_written' > "$OUTPUT_DIR/.appsec-checkpoint"
```

**Section numbering:** Section 3 is "Attack Walkthroughs" (step-by-step exploitation sequence diagrams, one per Critical finding). The old "Security-Relevant Use Cases", "Critical Findings", and standalone "Trust Boundaries" sections have been removed. Trust boundary content is integrated into §7.11 Infrastructure & Network Segmentation. The canonical numbering is: 1 System Overview, 2 Architecture Diagrams, 3 Attack Walkthroughs, 4 Assets, 5 Attack Surface, 7 Security Architecture, 8 Threat Register, 9 Mitigation Register, 10 Out of Scope. **Note: section 6 is intentionally absent** — it was the former Trust Boundaries section; the gap preserves external links from prior runs.

### What the Attack Surface + Security Architecture fragments must encode

The previous "Substep 5 Part B" direct-write step is removed. The fragments driving §5 and §7 are:

- `.fragments/attack-surface.md` — §5 Attack Surface, must contain `### 5.1 Unauthenticated Entry Points` and `### 5.2 Authenticated Entry Points` sub-sections per `sections-contract.yaml`. If cross-repository dependencies exist, include a dedicated `### 5.3 Cross-Repository Dependency Coverage` sub-section inside the same fragment.
- `.fragments/security-architecture.md` — §7 Security Architecture, must contain the 14 canonical sub-sections (7.1 Overview … 7.14 Defense-in-Depth Assessment). Section 6 is intentionally absent (former Trust Boundaries — gap preserved for external link stability).
- `.fragments/requirements-compliance.md` — §7b Requirements Compliance, only when `CHECK_REQUIREMENTS=true`.

The renderer concatenates them in the order declared by `document.order`. The rules below describe how those fragments must be composed; they apply to fragment authoring only.

### Triage-supplied ranking (Phase 4) — single source of sort order

Starting at `analysis_version = 2`, the **triage-validator emits a `ranking` block in `.triage-flags.json`** (schema `v2`) that contains the canonical ordering for:

- Top Findings table in the Management Summary (findings ≥ High)
- Section 8.A "Categories at a glance"
- Prioritized Mitigations table in the Management Summary (Critical-eff first)
- Section 8.C Compound Attack Chains (narrative content)

Phase 11 **MUST** consume this block and render from it. Never re-compute sort order from `threat-model.yaml` alone — that risks drift between triage's risk-first ranking and a naive CVSS-desc rendering. The triage step factors in breach_distance, compound-chain elevation, and effective severity; a local re-sort erases those signals.

**Read protocol (first action of Phase 11 Part A):**

```bash
if [ -f "$OUTPUT_DIR/.triage-flags.json" ]; then
  TRIAGE_VERSION=$(python3 -c "import json; print(json.load(open('$OUTPUT_DIR/.triage-flags.json')).get('version', 1))")
  if [ "$TRIAGE_VERSION" = "2" ]; then
    TRIAGE_HAS_RANKING=true
  fi
fi
```

When `TRIAGE_HAS_RANKING=true`:

1. **Top Findings table (Management Summary, single table)** — iterate `ranking.views.top_findings.findings_ranked[]` where `effective_severity ∈ {Critical, High}` and render up to **15 rows** in that exact order. Columns: `# | Criticality (🔴/🟠) | Finding (F-NNN link + short title) | Component (C-NN link + name) | Threat (TH-NN link + category name) | Vektor (linked to Appendix A anchor) | Primary Mitigations (M-NNN links)`. The component reference is a dedicated column — never inlined into the Finding cell as `<br/><small>…</small>`. This single table replaces the prior two-table (Top Threats + Top Findings drilldown) layout. See `phase-group-threats.md` → "Top Findings" for the complete template.
2. **Section 8.A** — architectural overview; iterate `ranking.views.top_threats.categories_ranked[]` covering **all** active categories. This section is the category-level landing page for readers who want the architectural pattern view.
3. **Prioritized Mitigations** — iterate `ranking.views.prioritized_mitigations.mitigations_ranked[]`. Emit P1 for mitigations whose `max_addressed_severity == Critical`, P2 for High, P3/P4 for the rest per existing priority rules.
4. **Section 8.C** — render `ranking.views.chains.chains_ranked[]` as CC-NN blocks with keystone/contributor split, narrative, breach_distance, severity_justification.

When `TRIAGE_HAS_RANKING=false` (legacy v1 or missing triage output):

- Fall back to the legacy per-severity sort (Risk desc → F-ID asc) with a warning `<!-- QA: no triage ranking available — used legacy sort. Re-run with analysis_version ≥ 2 for impact-weighted ordering. -->`.

**Invariant (QA-enforced by Check 3h).** The sequence of F-IDs in the rendered Top Findings table, read top-to-bottom, MUST match `ranking.views.top_findings.findings_ranked[*].id` in the same top-to-bottom order, truncated at 15 rows and filtered to `effective_severity ∈ {Critical, High}`. Any drift is flagged and auto-repaired by QA.

**Forbidden in the Management Summary (QA strips on sight):**
- A separate `### Top Threats` heading or any category-level table — this was the pre-Phase-5 layout. The category-level overview belongs in §8.A, not in the MS.
- Two tables back-to-back showing overlapping content (one finding-level, one category-level). The MS has exactly ONE such table (the Top Findings table with F-NNN IDs).
- Numbered sub-section headings inside Management Summary (e.g. `### 1.1 Verdict`) — strip the numeric prefix, keep the heading text.

### Section 7 rendering rules (Security Architecture — Phase 2 unified catalog)

**Section heading:** `## 7. Security Architecture` (not "Identified Security Controls" — that was the legacy name).

Section 7 is the unified security architecture section. It opens with **7.1 Overview** (a high-level summary derived from Section 2.4), followed by per-domain subsections (7.2–7.12), and closes with two cross-cutting subsections (7.13 Secret Management, 7.14 Defense-in-Depth Assessment). The trust boundary content formerly in standalone section 6 is integrated into 7.11 Infrastructure & Network Segmentation.

**Section intro paragraph** (mandatory, before any sub-section):

```markdown
## 7. Security Architecture

This section consolidates the architectural narrative (patterns, per-domain assessment, cross-cutting topics) with the canonical control catalog. Each domain contains architectural reasoning and the controls that implement — or fail to implement — it.

**Reading guide**
- [§7.1 Overview](#71-overview) — architecture patterns, overall rating
- [§7.2](#72-key-architectural-risks)..[§7.12](#712-dependency--supply-chain) — Per-domain narrative + controls
- [§7.13 Secret Management](#713-secret-management) — cross-cutting
- [§7.14 Defense-in-Depth Assessment](#714-defense-in-depth-assessment) — cross-cutting

**Catalog totals:** ✅ <n> Adequate · ⚠️ <n> Partial · 🔶 <n> Weak · ❌ <n> Missing · <total> controls tracked.

**Gap summary:** <one-paragraph narrative of the top 3 most impactful gaps, naming the Missing/Weak controls and the threats they would mitigate.>
```

**7.1 Overview (mandatory opening sub-section):**

Render as `### 7.1 Overview` containing two parts pulled from Section 2.4 data:

1. **Architecture Patterns table** — same 8-pattern table as in §2.4.1 but with condensed Assessment column (≤50 chars). Columns: Pattern | Status | Assessment | See also. The "See also" column links to the relevant domain sub-section (e.g. `[§7.3](#73-identity--access-management)`).
2. **Overall Architecture Security Rating** — one bold paragraph with the 🔴/🟡/🟢 verdict from §2.4.9.

**7.2 Key Architectural Risks (mandatory):**

Render as `### 7.2 Key Architectural Risks` — same table as §2.4.2 but with full Why-this-matters prose. Intro sentence mandatory.

**Step 1 — Read `security_controls[]`** from the YAML. Each entry carries the Phase-2 unified schema (see `phase-group-architecture.md` → "Phase 8 output schema"): `id`, `architectural_control`, `domain`, `implementation`, `effectiveness`, `gaps`, `mitigates_findings`, `references`, `positive_framing`, `show_in_strengths_by_default`.

**Step 2 — Group by domain.** The domain enum comes from `$CLAUDE_PLUGIN_ROOT/data/architectural-controls.yaml → domains`. Render each domain as a sub-section `### 7.<n> <domain-title>`, sorted in this canonical order:

1. `7.3 IAM` — Identity & Access Management (Auth flows: describe and evaluate each distinct flow — password login, OAuth, TOTP/2FA, API token — as a sub-subsection `#### 7.3.x <Flow Name>`)
2. `7.4 AuthZ` — Authorization
3. `7.5 InputVal` — Input Validation & Output Encoding
4. `7.6 DataProt` — Data Protection & Session Management
5. `7.7 FrontendSec` — Frontend Security
6. `7.8 RealTime` — Real-time / WebSocket
7. `7.9 AI` — AI / LLM (omit when no AI-related controls exist)
8. `7.10 Audit` — Audit & Logging
9. `7.11 Infra` — Infrastructure & Network Segmentation (integrate former Trust Boundaries content here: include the trust boundary table with columns `# | Boundary | From | To | Enforcement | Key Weakness | Linked Threats`, followed by the controls table)
10. `7.12 SupplyChain` — Dependency & Supply Chain
11. `7.13 SecretMgmt` — Secret Management (cross-cutting — renders the §2.4.3 content as a standalone subsection with the current-state vs. target-state diagram when `ASSESSMENT_DEPTH=thorough`)
12. `7.14 DefenseInDepth` — Defense-in-Depth Assessment (cross-cutting — renders the §2.4.8 content as a standalone subsection with a layered-defense evaluation table)

Omit any sub-section with zero controls AND no architectural narrative. The numbering remains stable — if `AI` is omitted, `Audit` still becomes `7.10` (skip the empty slot). `7.13` and `7.14` are always emitted regardless of control count.

**Step 3 — Within each sub-section, render the controls table.** Columns, in order:

| Column | Width | Content |
|---|---|---|
| ID | narrow | `SC-NN` |
| Architectural Control | medium | canonical name, not a link |
| Implementation | wide | `implementation.description` + file refs (`[path:L-L](vscode://file/...)`) |
| Effectiveness | narrow | emoji from `effectiveness_scale` (`✅` / `⚠️` / `🔶` / `❌`) + word |
| Mitigates | medium | `[T-NNN](#t-NNN) — <title>` list, `<br/>`-separated. For `effectiveness: missing` rows, prefix with `expected:` to signal these are threats the control *would* mitigate if present |
| References | narrow | `[CWE-NNN](url), ASVS <ref>, NIST <ref>` on one line |

**Step 4 — Sort rows within each sub-section.** Primary: effectiveness severity descending (Missing > Weak > Partial > Adequate — so the user sees the gaps first). Secondary: count of mitigates_findings descending. Tertiary: SC-ID ascending as stabiliser.

**Step 5 — Emit a domain summary line** below each sub-section's table:

```
_Domain summary: ✅ 1 Adequate · ⚠️ 2 Partial · 🔶 1 Weak · ❌ 3 Missing (7 controls total)_
```

**Step 6 — Emit the section-wide summary** at the very top of Section 7 (below the intro paragraph, above the first sub-section):

```markdown
**Catalog totals:** ✅ <n> Adequate · ⚠️ <n> Partial · 🔶 <n> Weak · ❌ <n> Missing · <total> controls tracked.

**Gap summary:** <one-paragraph narrative of the top 3 most impactful gaps, naming the Missing/Weak controls and the threats they would mitigate. This paragraph replaces the old free-form gap summary and is auto-derived from the controls catalog.>
```

### Operational Strengths — filter view (Management Summary)

Operational Strengths in the Management Summary block is a **deterministic filter** over the same `security_controls[]` list — no separate composition step. Rules:

1. **Include when:** `effectiveness ∈ {adequate, partial, weak}` **AND** `show_in_strengths_by_default == true`.
2. **Exclude when:** `effectiveness == missing` (those live only in Section 7) OR `show_in_strengths_by_default == false` (explicit opt-out).
3. **Cap:** at most 8 rows. When more than 8 pass the filter, sort by effectiveness ascending (Adequate first — positive leads) then by count of `mitigates_findings` descending (highest-leverage controls first), and take the top 8. Emit a footnote: `_+<n> additional controls — see [Section 7](#7-security-architecture)._`
4. **Column-mapping:** Architectural Control → `Architectural Control`; Implementation description → `Implementation`; Effectiveness → `Effectiveness` (emoji + word); `gaps[]` joined with `; ` → `Gap`; `mitigates_findings[]` rendered as `[T-NNN](#t-NNN) — <title>` `<br/>`-separated → `Mitigates`.

**Consistency rule (QA-enforced, Check 7d).** Every row in Operational Strengths MUST exist verbatim in Section 7 with the same `architectural_control` name, same effectiveness emoji, and identical or superset `mitigates_findings`. Drift between the two tables is a generation defect and the QA reviewer auto-rewrites Operational Strengths from the catalog when it detects one.

**Orchestrator note.** In Phase 11 Part A (Management Summary), when composing Operational Strengths, the orchestrator reads `security_controls[]` from the **just-written YAML** (not from in-memory state) so the filter operates on the canonical persisted catalog. This guarantees that any catalog edit flows into both views.

**Cross-Repository Dependency Coverage (conditional sub-section of Section 5):**

When `.threat-modeling-context.md` contains a **Cross-Repository Dependency Threat Models** section with at least one entry, render a `### 5.x Cross-Repository Dependency Coverage` sub-section at the end of Section 5. This sub-section contains:

1. An introductory sentence: "The following table shows the threat model coverage status of services and SaaS integrations that this system communicates with across repository boundaries."

2. The coverage table:

```markdown
| Dependency | Type | Threat Model | Last Assessed | Threats (C/H/M/L) | Open | Interface | Trust Boundary |
|------------|------|-------------|---------------|-------------------|------|-----------|----------------|
| auth-service | SCM sibling | ✓ found | 2026-03-28 | 1/3/8/2 | 3 | REST API | service ↔ auth-service |
| notification-svc | SCM sibling | ✗ missing | — | — | — | gRPC | service ↔ notification-svc |
| Stripe | SaaS | n/a | — | — | — | SDK | service ↔ Stripe (internet) |
| Auth0 | SaaS | n/a | — | — | — | REST API | service ↔ Auth0 (internet) |
```

3. A summary note:
   - If any SCM sibling has `✗ missing`: "**⚠ Unanalyzed boundaries:** `<list>` have no threat model. Threats originating from these services cannot be correlated. Consider running a threat assessment on these repositories."
   - If all SCM siblings have `✓ found`: "All SCM sibling dependencies have threat models. Cross-boundary threat correlation is available."

Omit this sub-section entirely when no cross-repo dependencies were discovered.

Typically ~15–20 KB. Advance checkpoint to `step=5 status=part_b_written`.

### How §8, §9, §10 and the appendices are produced

§8 Threat Register, §9 Mitigation Register, §10 Out of Scope and both appendices are rendered from `threat-model.yaml` + `claude-plugin/data/breach-vector-taxonomy.yaml` by `compose_threat_model.py`. The orchestrator does **not** author a fragment for them (except `.fragments/out-of-scope.md` for §10 and, conditionally, `.fragments/compound-chains.json` + `.fragments/architectural-findings.json` under §8.C/§8.D).

**Triage flags in Threat Register:** when `$OUTPUT_DIR/.triage-flags.json` exists, `compose_threat_model.py` already reads it and annotates each affected threat row (`⚠️ TRIAGE:` / `ℹ️ TRIAGE:`). The orchestrator does not duplicate that work.

#### Run Statistics Appendix (verbose only)

**Only emit this appendix when `VERBOSE_REPORT=true`.** When `VERBOSE_REPORT=false` (default), omit the appendix entirely — no `## Appendix: Run Statistics` heading, no tables, no ToC entry.

At the end of Part D, after Section 10 (Out of Scope), append a horizontal rule and an unnumbered appendix section. This appendix is the **single location for all run metadata** — there is no metadata table at the top of the report.

Extract per-phase durations from `$OUTPUT_DIR/.agent-run.log` by pairing `PHASE_START` and `PHASE_END` timestamps for each phase. **Prefer actual timestamps from the log.** When log-parsing succeeds, render exact `Xm YYs` / `YYs` forms. When a PHASE_START/PHASE_END pair is missing or malformed, **rounded approximate values in the form `~30s` / `~2m` / `~1m 30s` are acceptable as a fallback** — they come from the wall-clock estimates the orchestrator carries during the run. Only write `n/a` when no timing signal exists at all (neither log pairs nor wall-clock estimates). The reference output at `examples/juice-shop/threat-model-juiceshop-thorough.md` uses the `~`-prefixed rounded form — that output format is canonical for the baseline four-subsection appendix described below.

Extract agent names and models from `AGENT_INVOKE` / `AGENT_START` lines in `.agent-run.log`. Only include agents that actually ran — omit context-resolver on cache hit, omit dep-scanner when `WITH_SCA=false`.

The `Tokens` and `Cost Estimate` tables are written entirely as `_pending_` in the extended 7-section form — they are patched by the QA reviewer's Check 12 (via `verify_run_costs.py`). The `Assessment Total`, `QA Review`, and `Grand Total` duration rows are also `_pending_` — patched by the skill layer after Stage 2 completes.

**Two appendix shapes are accepted.** The **baseline four-subsection form** (used by the reference output) is the minimum contract: `Run Metadata` (flat `Field | Value` table at the top, no sub-heading) + `### Per-Phase Duration Breakdown` + `### Coverage Summary` + `### Agent Dispatch Log`. The **extended seven-subsection form** described below adds `Agents & Models`, `Token Consumption`, `Cost Estimate`, and `Per-Agent Cost Breakdown` — these are emitted only when `verify_run_costs.py` is available and the log carries usable token/cost events. When any of the four extended tables would render as `_pending_` across every cell, **collapse to the baseline four-subsection form** — do not emit a table of `_pending_` placeholders in user-facing output.

Format — the appendix has up to 7 subsections (Run Metadata, Agents & Models, Phase Duration Breakdown, Token Consumption, Cost Estimate, Per-Agent Cost Breakdown, Coverage Summary):

```markdown
---

## Appendix: Run Statistics

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

### Agents & Models

| Agent | Model | Role | Phases |
|-------|-------|------|--------|
| threat-analyst | <model> | Orchestrator — architecture, controls, synthesis, finalization | 1, 3-8, 10-11 |
| context-resolver | <model> | Resolves repo context and business docs | 1 |
| recon-scanner | <model> | Tech stack and security pattern reconnaissance | 2 |
| dep-scanner | <model> | SCA dependency vulnerability scan | 2 |
| stride-analyzer | <model> | Per-component STRIDE threat analysis | 9 (<N> instances) |
| qa-reviewer | _pending_ | Cross-reference validation, link fixes, consistency | Post-assessment |

Only include agents that actually ran. The `qa-reviewer` row is always included with `_pending_` model — patched by the skill layer after Stage 2. The `dep-scanner` row is only included when `WITH_SCA=true`. The `context-resolver` row is only included when context resolution was not a cache hit.

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

### Per-Agent Cost Breakdown

| Agent | Sessions | Tokens | Cost | % of Total |
|-------|----------|--------|------|------------|
| _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |

> Primary-agent attribution: each host session's delta is rolled up to the agent with the most AGENT_SPAWN events in that session. Sub-agent tokens (e.g. stride-analyzer instances dispatched by the orchestrator) are executed inside the host session and therefore roll up under their parent agent. Rows marked with `*` indicate sessions that hosted more than one agent — attribution is approximate in those cases.

### Coverage Summary

| Metric | Count |
|--------|-------|
| Components Analyzed | <N> |
| Threats Identified | <N> |
| Critical Threats | <N> |
| High Threats | <N> |
| Medium Threats | <N> |
| Low Threats | <N> |
| Mitigations Generated | <N> |
| P1 Mitigations | <N> |
| P2 Mitigations | <N> |
| P3 Mitigations | <N> |
| P4 Mitigations | <N> |
| Security Controls Rated | <N> |
| Controls Adequate | <N> |
| Controls Partial | <N> |
| Controls Weak | <N> |
| Controls Missing | <N> |
| Attack Surface Entry Points | <N> (<n-unauth> unauthenticated, <n-auth> authenticated) |
| Trust Boundaries Mapped | <N> |
| Assets Catalogued | <N> |

### Agent Dispatch Log

| Agent | Model | Purpose |
|-------|-------|---------|
| appsec-context-resolver | <model> | External context + requirements |
| appsec-recon-scanner | <model> | Codebase reconnaissance |
| appsec-stride-analyzer × <N> | <model> | STRIDE threat enumeration per component |
| appsec-dep-scanner | <model> | SCA dependency vulnerability scan *(only when `WITH_SCA=true`)* |
| appsec-triage-validator | <model> | Cross-component rating consistency *(only when analysis v2+)* |
| appsec-qa-reviewer | <model> | Post-assessment validation and link repair |
```

**Agent Dispatch Log rules:**
- **Purpose column** is prose — not the phase number or the YAML role name. Describe what the agent did in this run.
- **Model column** uses the canonical model ID (`claude-sonnet-4-6`, `claude-opus-4-7`, `claude-haiku-4-5`). When a model override applied, show the override.
- **× <N>** multiplier on `appsec-stride-analyzer` reflects the number of dispatched component-level instances.
- **Conditional rows** — skip `appsec-dep-scanner` when `WITH_SCA=false`, skip `appsec-context-resolver` on a cache hit, skip `appsec-triage-validator` when `analysis_version < 2`.
- **Qa-reviewer row** — emitted unconditionally with the model the skill layer will use in Stage 2 (sonnet by default).

**Cost Estimate column headers:** dynamically determined from `agent_models` in the YAML — one column per unique model used. When only one model is used (no `agent_models` override), show a single value column with that model's name as header. The pricing reference table is static and always included.

**Billing label in the blockquote:** replace `_pending_` with `api` or `subscription (estimated)` — patched by QA Check 12.

**Phase Duration table rules:**

- The table MUST NOT use `<details>` collapse — the durations are always visible.
- The **Agent(s)** column is included in the extended 7-section form; in the baseline 4-section form the table collapses to `Phase | Description | Duration` (3 columns — see reference output).
- When the Agent(s) column IS rendered: for phases run inline by the orchestrator (Phases 3–8), the agent is `threat-analyst`. For dispatched sub-agents, show the sub-agent name. For Phase 9, show the count of stride-analyzer instances (e.g., `5 x stride-analyzer (opus-4-6)`).
- For phases that ran in parallel (same PHASE_START timestamp), show the wall-clock duration of the parallel group for each phase row — this makes it clear they overlapped.
- The `Assessment Total` row uses `analysis_duration_seconds` from `threat-model.yaml` (excludes permission prompt wait time). In the baseline form, the total is rendered as `**Total** | | **~<Xm YYs>**` (2-col data).
- The `QA Review` and `Grand Total` rows are filled by the skill layer after Stage 2 completes. When those signals are unavailable, omit both rows (the baseline form skips them).
- Phase-label strings in the Description column should match current phase names (`Attack Walkthroughs`, not the legacy `Security Use Cases`; `Security Architecture Catalog`, not the legacy `Security Controls Catalog`). The reference predates some phase-label renames — new runs use the current labels.

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

**Error recovery:** if a turn fails during Part B/C/D, the earlier parts are already on disk. A `--resume` run can read the partial file, determine which `## N.` section heading was last written, and resume from the next part. The QA reviewer can also work with a partial file (it checks section-by-section).

**Section layout:** 10 numbered sections (1–10) plus unnumbered Management Summary, Critical Attack Chain, and Appendix. Section 3 is "Attack Walkthroughs" (sequence diagrams per Critical finding). The old "Critical Findings" section has been removed — its content was redundant with the Critical Attack Chain.

### Baseline Snapshot — ALWAYS run before composing output

**⚠ This step runs for BOTH `incremental` AND `full` modes whenever `$OUTPUT_DIR/threat-model.yaml` exists.** It is the foundation for the changelog delta — without the snapshot, a `--full` overwrite loses all information about what used to be in the model.

1. **Read the existing baseline yaml** — before any composition or write, parse `$OUTPUT_DIR/threat-model.yaml` if it exists and extract: `meta.git.commit_sha` (= `BASELINE_SHA`), `components[]`, `threats[]`, `mitigations[]`, `changelog[]`. Store in memory as `BASELINE_SNAPSHOT` (a dict keyed by `t_id`, `component_id`, etc.).

   **Use Python (via Bash) for robust YAML parsing** — never grep the yaml directly (strings like `commit_sha:` may appear inside threat descriptions and confuse naive parsing):

   ```bash
   BASELINE_SNAPSHOT=$(python3 -c "
   import json, sys, yaml
   try:
       with open('$OUTPUT_DIR/threat-model.yaml') as f:
           data = yaml.safe_load(f)
       if not isinstance(data, dict):
           sys.exit(1)
       out = {
           'baseline_sha':  (data.get('meta') or {}).get('git', {}).get('commit_sha'),
           'analysis_ver':  (data.get('meta') or {}).get('analysis_version'),
           'components':    {c['id']: c for c in (data.get('components') or []) if isinstance(c, dict) and c.get('id')},
           'threats':       {t['t_id']: t for t in (data.get('threats') or []) if isinstance(t, dict) and t.get('t_id')},
           'mitigations':   {m['m_id']: m for m in (data.get('mitigations') or []) if isinstance(m, dict) and m.get('m_id')},
           'changelog':     data.get('changelog') or [],
       }
       print(json.dumps(out))
   except (FileNotFoundError, yaml.YAMLError, KeyError, TypeError):
       sys.exit(1)
   " 2>/dev/null)
   if [ -n "$BASELINE_SNAPSHOT" ]; then
     HAS_BASELINE=true
     BASELINE_SHA=$(printf '%s' "$BASELINE_SNAPSHOT" | python3 -c "import json,sys;print(json.load(sys.stdin).get('baseline_sha') or '')")
     # Extract additional fields from $BASELINE_SNAPSHOT JSON as needed during delta computation.
   else
     HAS_BASELINE=false
     BASELINE_SHA=
   fi
   ```

   Keep `BASELINE_SNAPSHOT` as a shell-variable JSON blob and re-parse it with `python3 -c "import json,sys; ..."` pipelines whenever you need a subset (threats-by-id, component-ids, etc.). This avoids re-reading the yaml file multiple times during Phase 11.

2. Determine `HAS_BASELINE`:
   - `true` if the yaml exists and parses, **regardless of mode** (the Bash above sets this)
   - `false` if the yaml is missing (first-ever run) or unparseable

### Delta Computation — runs when `HAS_BASELINE=true`

From `BASELINE_SNAPSHOT` vs. the freshly-assembled current state, derive:

- `added_threats` — T-IDs in current but not in baseline
- `changed_threats` — T-IDs present in both but with different `severity`, `cwe`, `evidence.file`, `evidence.line`, or `mitigations[]` — with one-line note per ID describing what changed (e.g. `"severity High → Critical"`, `"evidence moved to auth/session.ts:89"`)
- `resolved_threats` — baseline T-IDs **not present in current**:
  - In **incremental** mode: only resolved if the baseline's owning component was re-analyzed (otherwise the threat was carried forward)
  - In **full** mode: any baseline T-ID missing from the fresh threat register is resolved — with `reason_by_id` set to `"not reproduced on full re-analysis"` unless the component itself was removed (then `"component removed"`)
- `added_components`, `removed_components`
- `reanalyzed_components` — incremental: dirty-set; full: **all** components
- `carried_forward_components` — incremental only (empty list in full mode)
- `low_risk_skipped_components` — incremental only
- `added_entry_points`, `changed_entry_points` (from `attack_surface[]` delta, if populated)

Store the resulting counts as `DELTA_ADDED`, `DELTA_CHANGED`, `DELTA_RESOLVED` (integers) and the first 5 IDs of each as `SAMPLE_ADDED`, `SAMPLE_CHANGED`, `SAMPLE_RESOLVED` (comma-separated strings with ellipsis if truncated, e.g. `"T-042, T-043, T-044, +2 more"`). The skill-level Completion Summary reads these values from `changelog[0]` in the final yaml.

### Changelog Entry Composition

Compose the new changelog entry in memory based on the mode and baseline presence:

**When `WRITE_MODE=incremental`** (always has baseline by construction — the mode would have aborted otherwise):

```yaml
- version: <last_version + 1>
  date: <ISO now>
  mode: incremental
  plugin_version: <PLUGIN_VERSION>        # from plugin_meta.py
  analysis_version: <ANALYSIS_VERSION>    # from plugin_meta.py
  baseline_sha: <BASELINE_SHA>
  current_sha: <CURRENT_SHA>
  changed_files: <count>
  reanalyzed_components: [<id>, ...]
  carried_forward_components: [<id>, ...]
  low_risk_skipped_components: [<id>, ...]
  added:
    threats: [<T-ID>, ...]
    components: [<id>, ...]
    attack_surface: [<E-ID>, ...]
  changed:
    threats: [<T-ID>, ...]
    notes_by_id:
      <T-ID>: "<what changed>"
  resolved:
    threats: [<T-ID>, ...]
    reason_by_id:
      <T-ID>: "<reason>"
```

**When `WRITE_MODE=full` AND `HAS_BASELINE=true`** (this is the main case for `--full` overwrites — it now produces a fully detailed changelog just like incremental, so the user can see exactly what changed):

```yaml
- version: <last_version + 1>
  date: <ISO now>
  mode: full
  plugin_version: <PLUGIN_VERSION>
  analysis_version: <ANALYSIS_VERSION>
  baseline_sha: <BASELINE_SHA>            # from prior yaml — yes, even for full
  current_sha: <CURRENT_SHA>
  note: "full rebuild — all components re-analyzed"
  reanalyzed_components: [<id>, ...]      # all current components
  carried_forward_components: []           # always empty for full
  added:
    threats: [<T-ID>, ...]                 # T-IDs absent from baseline
    components: [<id>, ...]
    attack_surface: [<E-ID>, ...]
  changed:
    threats: [<T-ID>, ...]
    notes_by_id:
      <T-ID>: "<what changed>"
  resolved:
    threats: [<T-ID>, ...]                 # baseline T-IDs not reproduced
    reason_by_id:
      <T-ID>: "not reproduced on full re-analysis" | "component removed"
```

**When `WRITE_MODE=full` AND `HAS_BASELINE=false`** (truly first run — no prior yaml, OR `REBUILD=true` after the skill-level wipe):

```yaml
- version: 1
  date: <ISO now>
  mode: full
  plugin_version: <PLUGIN_VERSION>
  analysis_version: <ANALYSIS_VERSION>
  baseline_sha: null
  current_sha: <CURRENT_SHA>
  note: <see below>
```

Choose `note` based on whether `REBUILD=true` was passed in the invocation prompt:
- `REBUILD=true` → `"full rebuild — prior threat model and changelog history were discarded on user request (--rebuild)"`
- `REBUILD` not set or `false` → `"initial assessment"`

Skip the `added`/`changed`/`resolved` blocks entirely in this case — there is nothing to diff against.

### Finalize

1. **Prepend** the new entry to `changelog[]` in the yaml (newest first). For the first-run case, `changelog[]` starts with just the single `v1` entry.
2. Write the yaml.
3. **Render the Changelog section** in `threat-model.md` (see template below).
4. **Update `.appsec-cache/baseline.json`** — refresh `recon_fingerprint`, `id_counters`, `stride_files[<id>].sha256` for all components touched in this run.
5. T-IDs of carry-forward components (incremental only) **must remain stable** — do not renumber. For full-mode T-IDs: if a threat in the new run matches a baseline threat by CWE + component_id + evidence.file + evidence.line, **reuse the baseline T-ID** rather than assigning a fresh one. This keeps T-ID references stable across full re-runs so links in external systems (Jira, Linear) don't break.

### Changelog Section Template (rendered into `threat-model.md`)

The Changelog section is inserted immediately below the header metadata table and before the Management Summary. It renders `changelog[]` in descending order (newest first). Template:

```markdown
## Changelog

_Append-only history of assessment runs. Most recent first._

### v<N> — <date> (<mode>, baseline `<short_sha>` → `<short_sha>`)

- **Added:** <n> threats (<list T-IDs>), <n> components (<list>), <n> entry points (<list E-IDs>)
- **Changed:** <n> threats (<T-ID: "reason", ...>)
- **Resolved:** <n> threats (<T-ID: "reason", ...>)
- **Re-analyzed:** <component list>
- **Carried forward:** <component list>
- **Changed files:** <count>

### v<N-1> — <date> (<mode>, ...)

...

### v1 — <date> (full — initial assessment)

- First assessment — <n> threats identified across <n> components.
```

**Rendering rules:**
- A `mode: full` entry **with** a baseline (i.e. `baseline_sha` is not null) renders the full `Added/Changed/Resolved` breakdown — everything the user needs to understand what changed in the overwrite.
- A `mode: full` entry **without** a baseline (`baseline_sha: null`, typically the first `v1` entry) shows only `version`, `date`, and `note` — there is no prior state to diff against.
- A `mode: incremental` entry always shows the full breakdown.
- Empty lists are omitted (don't print `Added: 0 threats`).
- T-IDs and E-IDs are rendered as clickable internal anchors to their entries in Section 5/8.
- The section is `## Changelog` (level-2), matching the other top-level sections.

### Baseline Cache Update

Before the lock-release substep, refresh `$OUTPUT_DIR/.appsec-cache/baseline.json` via the `baseline_state.py` helper:

```bash
if [ "$WRITE_MODE" = "incremental" ] || [ "$WRITE_MODE" = "full" ]; then
  mkdir -p "$OUTPUT_DIR/.appsec-cache"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" update \
    --output-dir "$OUTPUT_DIR" \
    --repo-root "$REPO_ROOT" \
    --mode "$WRITE_MODE"
fi
```

The helper reads the freshly-written `threat-model.yaml`, computes manifest/Dockerfile/IaC hashes against `$REPO_ROOT`, increments `id_counters.next_threat_id` past the highest T-ID in the yaml, and writes sha256 for every `.stride-<id>.json`. If the helper is missing (pre-M2.6 plugin), log a warning and continue — the yaml alone is sufficient baseline for the next run, just without the Phase 2 recon-skip optimization.

### Clear Checkpoint & Compute Duration (substep `N`)

The lock has already been released at `[1/N]`. This final substep only clears the checkpoint marker and computes the duration used in the summary. Batch the final STEP_START echo with the cleanup in one Bash call:

```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [<N>/<N>] Clearing checkpoint + printing summary…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
# Lock was already released at substep 1; this step is terminal only.
rm -f "$OUTPUT_DIR/.appsec-lock"        # defensive no-op — already removed
rm -f "$OUTPUT_DIR/.appsec-checkpoint"
END_EPOCH=$(date +%s)
ELAPSED=$(( END_EPOCH - START_EPOCH ))
DURATION=$(printf "%d min %02d s" $(( ELAPSED / 60 )) $(( ELAPSED % 60 )))
```

### Assessment Log Entry

**⚠ MANDATORY — always log ASSESSMENT_END, even if earlier phases failed:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  ASSESSMENT_END   Assessment completed in ${DURATION}  threats=<N> mitigations=<N> files=[threat-model.md<, threat-model.yaml><, threat-model.sarif.json>] (CET: $(TZ=Europe/Berlin date '+%Y-%m-%d %H:%M:%S %Z'))" >> "$OUTPUT_DIR/.agent-run.log"
```
Replace `<N>` with actual counts. Include only files actually written in the `files=[...]` list.

### Runtime Cleanup (since M2.8)

Remove transient artifacts that have no value after a successful run. The cleanup is **gated** — it only fires when **all** conditions hold:

1. `KEEP_RUNTIME_FILES` is not `true` (user did not opt out via `--keep-runtime-files`)
2. `$OUTPUT_DIR/threat-model.md` exists (the run produced a real report)
3. The most recent 100 lines of `.agent-run.log` contain no `AGENT_ERROR` entries (no observable failure)

If any condition is not met, leave every transient file in place — the user is presumed to need the artifacts for debugging.

**Whitelist — exactly these are removed (no wildcards beyond the pinned globs):**

| Path | Origin |
|---|---|
| `$OUTPUT_DIR/.dep-scan.pid` | `dep_scan.py` background launch (Phase 2) |
| `$OUTPUT_DIR/.dep-scan.stdout` | `dep_scan.py` background launch (Phase 2) |
| `$OUTPUT_DIR/.merge-candidates.json` | `merge_threats.py collect` (Phase 9) |
| `$OUTPUT_DIR/.merge-decisions.json` | `appsec-threat-merger` (Phase 9) |
| `$OUTPUT_DIR/.management-summary-draft.md` | Phase 9 → Phase 11 handoff |
| `$OUTPUT_DIR/.phase-epoch` | per-phase elapsed-time anchor |
| `$OUTPUT_DIR/.session-agent-map` | hook session tracking |
| `$OUTPUT_DIR/.progress/` (directory) | per-component STRIDE substep state |

**Explicitly NOT removed** — the audit trail (`.threat-modeling-context.md`, `.recon-summary.md`, `.dep-scan.json`, `.stride-*.json`, `.threats-merged.json`, `.triage-flags.json`, `.architect-review.md`), the incremental cache (`.appsec-cache/`), and all log files (`.agent-run.log[.1.2]`, `.hook-events.log[.1.2]`).

**Cleanup batch — single Bash call:**

```bash
KEEP_RUNTIME_FILES="${KEEP_RUNTIME_FILES:-false}"
CLEANUP_REASON=""
if [ "$KEEP_RUNTIME_FILES" = "true" ]; then
  CLEANUP_REASON="opt-out (--keep-runtime-files)"
elif [ ! -f "$OUTPUT_DIR/threat-model.md" ]; then
  CLEANUP_REASON="threat-model.md missing — run incomplete"
elif tail -100 "$OUTPUT_DIR/.agent-run.log" 2>/dev/null | grep -q AGENT_ERROR; then
  CLEANUP_REASON="AGENT_ERROR present in recent log lines"
fi

if [ -z "$CLEANUP_REASON" ]; then
  REMOVED=0
  for path in \
      "$OUTPUT_DIR/.dep-scan.pid" \
      "$OUTPUT_DIR/.dep-scan.stdout" \
      "$OUTPUT_DIR/.merge-candidates.json" \
      "$OUTPUT_DIR/.merge-decisions.json" \
      "$OUTPUT_DIR/.management-summary-draft.md" \
      "$OUTPUT_DIR/.phase-epoch" \
      "$OUTPUT_DIR/.session-agent-map"; do
    [ -e "$path" ] && rm -f "$path" && REMOVED=$((REMOVED + 1))
  done
  if [ -d "$OUTPUT_DIR/.progress" ]; then
    rm -rf "$OUTPUT_DIR/.progress"
    REMOVED=$((REMOVED + 1))
  fi
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  RUNTIME_CLEANUP   removed ${REMOVED} transient artifacts" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
else
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  RUNTIME_CLEANUP   skipped (${CLEANUP_REASON})" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
fi
```

**Drift guard:** the whitelist above is also pinned in `tests/test_runtime_cleanup.py`. Adding a new transient artifact (e.g. a future `.merger.stderr`) requires updating both the cleanup whitelist here and the test — that is intentional. Without the test, a forgotten transient file would silently accumulate over many runs.

### Print Final Summary

```
══════════════════════════════════════════════════════════════
  Assessment Summary
══════════════════════════════════════════════════════════════

  Duration       : <DURATION>  (per-phase breakdown below)
  Started (CET)  : <CET start time>
  Finished (CET) : <CET end time>
  Plugin         : appsec-plugin <PLUGIN_VERSION> (analysis v<ANALYSIS_VERSION>)
  Mode           : <full | incremental>
  Depth          : <quick | standard | thorough>
  Baseline compat: <equal|older-compatible|incompatible|legacy|n/a>  ← n/a for full runs
                   ← when older-compatible or legacy: "Recommendation: re-run with --full"
  Flags          : WITH_SCA=<true|false>  CHECK_REQUIREMENTS=<true|false>
                   WRITE_YAML=<true|false>  WRITE_SARIF=<true|false>
  Baseline SHA   : <BASELINE_SHA | n/a>           ← only for incremental modes
  Current SHA    : <CURRENT_SHA>
  Changelog      : v<N> added to threat-model.md

  Phase Durations:
    Phase 1  Context Resolution     :  Xm YYs
    Phase 2  Reconnaissance         :  Xm YYs
    Phase 3  Architecture Modeling   :  Xm YYs
    Phase 4  Security Use Cases      :  Xm YYs
    Phase 5  Asset Identification    :  Xm YYs
    Phase 6  Attack Surface          :  Xm YYs
    Phase 7  Trust Boundaries        :  Xm YYs
    Phase 8  Security Controls       :  Xm YYs
    Phase 8b Requirements            :  Xm YYs   ← only if CHECK_REQUIREMENTS=true
    Phase 9  STRIDE Enumeration      :  Xm YYs
    Phase 10 Scan Synthesis          :  Xm YYs
    Phase 11 Finalization            :  Xm YYs

  Compute per-phase durations by pairing PHASE_START and PHASE_END
  timestamps in $OUTPUT_DIR/.agent-run.log. For each phase, parse the
  ISO timestamp at the start of the PHASE_START line and the PHASE_END
  line, convert to epoch seconds with `date -d "$TS" +%s`, and subtract.
  Format as Xm YYs. If a PHASE_START has no matching PHASE_END (phase
  was skipped or failed), omit that row.

  Context Sources:
    External context : <provided|not configured|disabled|unavailable>
    Business context : <found|not found>
    Requirements     : <remote|cached|fallback|disabled|unavailable>
    Known threats    : <n entries (<n> open, <n> accepted)|not found>
    Repo files read  : <n from context-resolver>

  Pipeline (agent · model · maxTurns · status):
    context-resolver : <model> · <maxTurns> turns · .threat-modeling-context.md written
    recon-scanner    : <model> · <maxTurns> turns · .recon-summary.md written (<n> lines)
    dep-scanner      : <model> · <maxTurns> turns · .dep-scan.json (<n> vulnerable deps)
                       ← if WITH_SCA=false: "skipped (SCA not requested)"
                       ← if cache hit: "cache hit (age: <N>m)"
    stride-analyzer  : <model> · <maxTurns> turns × <n> components — <n> threats total
                       Components: <component-id-1>, <component-id-2>, …
    qa-reviewer      : <model> · <maxTurns> turns (runs next, skill-level)

  Results:
    Complexity tier  : <Simple|Moderate|Complex>
    Diagrams         : <n> (C4 + use case + tech arch)
    Requirements     : <n> checked (<n> PASS, <n> FAIL) | not checked
    Threats          : <n> (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
    Mitigations      : <n>
    Critical findings: <n>

  Change Summary (when a baseline existed — i.e. any run against a prior threat-model.yaml):
    Re-analyzed          : <n> components (<list>)
    Carried forward      : <n> components (<list>)    ← incremental only; always empty in full mode
    Changed files        : <count>                     ← incremental only; omit for full
    Delta                : +<n> threats, ~<n> threats, -<n> threats
      Added T-IDs        : <first 5 T-IDs, + N more if truncated>
      Changed T-IDs      : <first 5 T-IDs with short note, + N more>
      Resolved T-IDs     : <first 5 T-IDs with reason, + N more>
    Changelog entry      : v<N> added to threat-model.md (<date>)

  If no baseline existed (first-run full assessment), omit this block entirely.

  Paths:
    Repository   : <REPO_ROOT>
    Output       : <OUTPUT_DIR>

  Files Written:
    <OUTPUT_DIR>/threat-model.md          (<n> lines)
    <OUTPUT_DIR>/threat-model.yaml        (<n> lines)  ← always, unless --no-yaml
    <OUTPUT_DIR>/.appsec-cache/baseline.json
    <OUTPUT_DIR>/threat-model.sarif.json  (<n> bytes)  ← only if WRITE_SARIF
    <OUTPUT_DIR>/pentest-tasks.yaml  (<n> bytes, <t> tasks)  ← only if WRITE_PENTEST_TASKS

  Intermediate Files:
    <OUTPUT_DIR>/.threat-modeling-context.md  (<n> chars)
    <OUTPUT_DIR>/.recon-summary.md            (<n> chars)
    <OUTPUT_DIR>/.dep-scan.json               (<n> chars)  ← only if WITH_SCA
    <OUTPUT_DIR>/.stride-*.json               <n> files

  Tokens & Cost:
    Aggregated token/cost data is written automatically to
    <OUTPUT_DIR>/.hook-events.log (ASSESSMENT_SUMMARY / ASSESSMENT_TOKENS)
    and mirrored to <OUTPUT_DIR>/.agent-run.log after the session ends.
    Per-agent breakdowns are in the SESSION_STOP entries.

══════════════════════════════════════════════════════════════
```

**Note:** The QA review runs separately at the skill level after this agent completes.

---

### Vektor Taxonomy Appendix

Append **Appendix A — Vektor Taxonomy** at the very end of the document, after the Run Statistics appendix (or after Section 10 when `VERBOSE_REPORT=false`). This appendix is **always emitted** — it provides the definitions for the `Vektor` column in the Top Findings table and enables readers to interpret breach-distance values throughout the report.

**Template (emit verbatim, substituting example links with the actual findings cited in this run):**

```markdown
## <a id="appendix-a-vektor-taxonomy"></a>Appendix A — Vektor Taxonomy

Canonical source: [claude-plugin/data/breach-vector-taxonomy.yaml](../../../appsec-plugin/claude-plugin/data/breach-vector-taxonomy.yaml). Each entry defines one attacker position / exposure class used in the Vektor column across this document. The taxonomy is deliberately coarse (7 categories) so reviewers can group findings by reachability at a glance.

| Vektor | Breach Distance | Attacker Position | Examples |
|--- |--- |--- |--- |
| [internet-anon](#vektor-internet-anon) | 1 | Unauthenticated attacker from the public internet | <examples: F-NNN / AF-NNN short-label list, `<br/>`-separated> |
| [internet-user](#vektor-internet-user) | 2 | Any authenticated low-privilege user | <examples> |
| [internet-priv-user](#vektor-internet-priv-user) | 2 | Authenticated admin-level user | <examples> |
| [victim-required](#vektor-victim-required) | 2 | Needs victim interaction (XSS, CSRF, open redirect) | <examples> |
| [build-time](#vektor-build-time) | 3 | Attacker controls a build input (dep, base image, CI, training data) | <examples> |
| [repo-read](#vektor-repo-read) | 3 | Attacker gains read access to source repository | <examples> |
| [n-a](#vektor-n-a) | — | Architectural / meta-finding with no runtime entry point | <examples — typically AF-NNN only> |

### <a id="vektor-internet-anon"></a>Internet Anon

**Breach distance:** 1 — Internet-reachable.
**Attacker position:** Unauthenticated attacker from the public internet.
**Preconditions:** Endpoint is reachable from the internet (no IP allowlist, no VPN) AND no authentication middleware blocks the request.
**Typical CWEs:** ➚ [CWE-89](https://cwe.mitre.org/data/definitions/89.html), ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ➚ [CWE-306](https://cwe.mitre.org/data/definitions/306.html), ➚ [CWE-327](https://cwe.mitre.org/data/definitions/327.html), ➚ [CWE-611](https://cwe.mitre.org/data/definitions/611.html), ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/), ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/).

### <a id="vektor-internet-user"></a>Internet User

**Breach distance:** 2 — Authenticated low-privilege user.
**Attacker position:** Any authenticated low-privilege user (valid JWT / session).
**Preconditions:** Attacker has signed up or otherwise obtained a valid user session AND endpoint is behind auth but not behind role/admin checks.
**Typical CWEs:** ➚ [CWE-287](https://cwe.mitre.org/data/definitions/287.html), ➚ [CWE-352](https://cwe.mitre.org/data/definitions/352.html), ➚ [CWE-434](https://cwe.mitre.org/data/definitions/434.html), ➚ [CWE-611](https://cwe.mitre.org/data/definitions/611.html), ➚ [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), ➚ [A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/), ➚ [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/), ➚ [A10:2021](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/).

### <a id="vektor-internet-priv-user"></a>Internet Priv User

**Breach distance:** 2 — Authenticated admin-level user.
**Attacker position:** Authenticated admin-level user (JWT with admin role or equivalent).
**Preconditions:** Attacker holds admin credentials or has elevated privileges AND endpoint is gated on admin role but still exploitable once reached.
**Typical CWEs:** ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ➚ [CWE-94](https://cwe.mitre.org/data/definitions/94.html), ➚ [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/).

### <a id="vektor-victim-required"></a>Victim-Required

**Breach distance:** 2 — Requires user interaction.
**Attacker position:** Attacker needs victim interaction — social engineering, crafted link, or live session.
**Preconditions:** Victim must click a link, load a page, or have an active session. Applies to XSS, CSRF, click-jacking, open redirect.
**Typical CWEs:** ➚ [CWE-79](https://cwe.mitre.org/data/definitions/79.html), ➚ [CWE-352](https://cwe.mitre.org/data/definitions/352.html), ➚ [CWE-601](https://cwe.mitre.org/data/definitions/601.html), ➚ [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html).
**Typical OWASP Top 10:** ➚ [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/), ➚ [A03:2021](https://owasp.org/Top10/A03_2021-Injection/).

### <a id="vektor-build-time"></a>Build-Time

**Breach distance:** 3 — Supply-chain position.
**Attacker position:** Attacker controls a build input — CI runner, dependency, base image, or external data fetched during build.
**Preconditions:** Compromise of a dependency, registry, or base image OR compromise of a CI runner with write access to artifacts.
**Typical CWEs:** ➚ [CWE-506](https://cwe.mitre.org/data/definitions/506.html), ➚ [CWE-829](https://cwe.mitre.org/data/definitions/829.html), ➚ [CWE-1039](https://cwe.mitre.org/data/definitions/1039.html), ➚ [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html).
**Typical OWASP Top 10:** ➚ [A08:2021](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/).
**OWASP LLM:** ➚ [LLM03:2025](https://genai.owasp.org/llmrisk/llm03-2025-supply-chain/), ➚ [LLM04:2025](https://genai.owasp.org/llmrisk/llm04-2025-data-and-model-poisoning/).

### <a id="vektor-repo-read"></a>Repo-Read

**Breach distance:** 3 — Source-code access required.
**Attacker position:** Attacker gains read access to source repository (leaked clone, forked fork, insider, compromised developer workstation).
**Preconditions:** Read access to the source tree at or after commit time — no runtime exploit needed; the vulnerability is the content of the repo.
**Typical CWEs:** ➚ [CWE-312](https://cwe.mitre.org/data/definitions/312.html), ➚ [CWE-540](https://cwe.mitre.org/data/definitions/540.html), ➚ [CWE-798](https://cwe.mitre.org/data/definitions/798.html).
**Typical OWASP Top 10:** ➚ [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/), ➚ [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/).

### <a id="vektor-n-a"></a>n/a

**Breach distance:** not applicable.
**Attacker position:** Architectural / meta-finding — no runtime entry point. The finding describes a design defect that aggregates multiple code-level findings.
**Preconditions:** Finding ID starts with `AF-` (architectural) rather than `F-` (code-level).
**Typical CWEs:** none (AFs do not carry a primary CWE directly).
**Typical OWASP Top 10:** derived from the aggregated children (see each AF's own references).
```

**Canonical IDs (kebab-case, lowercase).** The anchor IDs are `vektor-internet-anon`, `vektor-internet-user`, `vektor-internet-priv-user`, `vektor-victim-required`, `vektor-build-time`, `vektor-repo-read`, `vektor-n-a`. In the Top Findings table, the link text is the human-readable form (e.g. `[Internet Anon](#vektor-internet-anon)`), in the summary table here it is the kebab-case ID (e.g. `[internet-anon](#vektor-internet-anon)`).

**Examples column.** Populate the `Examples` cells with 2–4 F-NNN/AF-NNN references from this run whose Vektor matches the row, formatted `[F-NNN](#f-NNN) — <short label>` and `<br/>`-separated. When a row has zero matching findings in this run, emit `_none in this assessment_`.

**Cross-reference rule:** Every Vektor value in the Top Findings table MUST be a clickable link to its definition in this appendix. Bare text Vektor values without links are a format defect auto-repaired by QA.
