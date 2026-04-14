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
6. `meta.plugin_version` and `meta.analysis_version` MUST be read from `$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json` via `plugin_meta.py get` — never hardcoded. Every new `changelog[]` entry carries the same pair that was active at the time of that run, so a user can later reconstruct which plugin/analysis version produced which threats.
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

| `WRITE_MODE` | Base substeps | +SARIF | `N` |
|---|---|---|---|
| `full` | lock+precompute, write yaml, write cache, write md Part A, Part B, Part C, Part D, clear-checkpoint = **9** | +1 if `WRITE_SARIF=true` | **9 or 10** |
| `incremental` | lock+precompute, update yaml (with new changelog entry), update cache, write md Part A, Part B, Part C, Part D, clear-checkpoint = **8** | +1 if `WRITE_SARIF=true` | **8 or 9** |

Note: the old `WRITE_YAML=false` path no longer exists — yaml is now always-on. The `--no-yaml` escape hatch (if set) simply omits the yaml write substep and subtracts 1 from `N`.

Substitute the concrete integer for every `N` below. Do not write the literal letter `N` into log lines.

**Why only 4–6 substeps (previously 7–9):** Earlier versions of this file listed "Building Management Summary", "Assembling Table of Contents", "Writing Sections 1-7", "Writing Section 8", and "Writing Sections 9-11" as five separate substeps. In reality, all of that content is composed as the single `content:` argument of one `Write` tool call — there is no way to observe the individual sections as separate tool invocations. Listing them as distinct STEP_START entries created a visible "hang" at `[1/7] Building Management Summary…` while Claude spent 1–3 minutes generating the ~90 KB markdown body in a single turn, with substeps 2–5 silently skipped. The honest substep model below names composition as one opaque step and warns the user *before* the silence begins, batched with a cheap pre-compute so the warning reaches the terminal before the Write turn starts.

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
| 4 | `Writing threat-model.md Part A (Header → Section 4)…` | always | Bash STEP_START + Write tool call. Contains: (A1) title + project infobox, (A2) changelog, (A3) numbered ToC, (A4) **Management Summary with all 6 required sub-sections — NEVER OMIT**, (A5) Critical Attack Chain, (A6) Sections 1–3 (~30–35 KB). Advance checkpoint to `step=4 status=part_a_written`. |
| 5 | `Writing threat-model.md Part B (Sections 5–7)…` | always | Bash STEP_START + append (heredoc or Read+Write). Contains sections 5–7 incl. 7b (~15–20 KB). Advance checkpoint to `step=5 status=part_b_written`. |
| 6 | `Writing threat-model.md Part C (Section 8 — Threat Register)…` | always | Bash STEP_START + append. Contains section 8 (8.1–8.4 by severity) (~20–25 KB). Advance checkpoint to `step=6 status=part_c_written`. |
| 7 | `Writing threat-model.md Part D (Sections 9–11)…` | always | Bash STEP_START + append. Contains sections 9–11 (~15–20 KB). Advance checkpoint to `step=7 status=md_written`. |
| 7 *or* 8 | `Generating SARIF export (<n> results) and writing threat-model.sarif.json…` (substitute `<n>`) | only if `WRITE_SARIF=true` | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.sarif.json` |
| N | `Clearing checkpoint + printing summary…` | always, LAST | the final cleanup Bash call — removes `.appsec-checkpoint` and prints the assessment summary. The lock has already been released at `k=1`, so this substep only clears the checkpoint marker. |

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

**Substeps 4–7 — Split markdown composition (since M2.7)**

The markdown is composed in **four sequential parts** instead of one monolithic ~90 KB write. Use **Bash heredoc append** (`cat >> "$FILE" <<'EOF'`) for Parts B–D to avoid re-emitting earlier parts as output tokens. Only Part A uses the Write tool (it creates the file). This reduces total Phase 11 output tokens from ~50k to ~15k and cuts wall-clock time from ~50 minutes to ~15 minutes.

**⚠ MANDATORY: Use Bash heredoc for Parts B, C, D.** The Write tool forces the LLM to generate the full file content as output tokens. For a 1300-line document, that is ~50k tokens and ~30 minutes of generation time. Bash heredoc (`cat >> file <<'EOF' ... EOF`) streams the content through the shell at near-zero token cost because the heredoc content is passed as the Bash command argument, not generated as output tokens. The Write tool MUST only be used for Part A (file creation).

**Split boundary rationale:** the split points are chosen so each part is self-contained and does not need forward-references to content in a later part. Cross-references (e.g. `[T-001](#t-001)`) work because anchors are defined in the same part or in an earlier part. The only backward reference is the Table of Contents (Part A), which lists sections written in Parts B–D — compose the ToC after you know the section headings (all heading text is determined by STRIDE/recon data already in working memory).

**Substep 4 — Part A: Header through Section 4 (Assets).**

Log `[4/<N>] Writing threat-model.md Part A (Header → Section 4)…` in a Bash call that also reads input sizes **and deletes any existing `threat-model.md`** so the Write tool creates a fresh file rather than requiring a Read of the old one:

```bash
PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [4/<N>] Writing threat-model.md Part A (Header → Section 4)…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
# Delete existing md so the Write tool creates a new file from scratch.
# This prevents the harness from requiring a Read of the old file, which
# would load the prior report's structure into context and bias composition
# (e.g., reproducing a missing Management Summary from the old output).
rm -f "$OUTPUT_DIR/threat-model.md"
YAML_LINES=$(wc -l < "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null || echo 0)
MGMT_LINES=$(wc -l < "$OUTPUT_DIR/.management-summary-draft.md" 2>/dev/null || echo 0)
echo "INPUT_SIZES: yaml=$YAML_LINES management_summary_draft=$MGMT_LINES"
```

**⚠ CRITICAL — Do NOT Read the old `threat-model.md` during a full run.** When the Write tool harness says "you must Read the file first before overwriting", that requirement is satisfied by deleting the file above — the Write tool then treats it as a new file creation, not an overwrite. Reading the old file loads its structure into the LLM's context window and biases composition toward reproducing the prior report's layout (including any defects like a missing Management Summary or missing metadata table). The `rm -f` above ensures a clean slate.

Then issue a **Write** tool call for `$OUTPUT_DIR/threat-model.md` containing all of the following in this exact order:

**A1. Title + Project Infobox**

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

The Management Summary section MUST contain all six required sub-sections in this exact order. Every sub-section uses the format defined in `phase-group-threats.md` → "Build Management Summary":

1. `### Verdict` — Opening sentence with 🟢/🟡/🔴 severity cue, then 2–4 bold bullet points naming the critical attack paths with short explanations, then 1–2 closing sentences with overall assessment. No T-NNN/M-NNN links, no threat counts.
2. `### Top Threats` — table with columns: Severity (🔴/🟠), ID, Description, Impact, Mitigation, Effort. Include ALL Critical findings and top 5 High findings. Every Mitigation cell includes a short action label: `[M-NNN](#m-NNN) — <short action>`. Legend line after table.
3. `### ⚠ Worst Case Scenarios` — inside red HTML blockquote (`<blockquote style="border-left: 3px solid #dc2626; background: #fef2f2; padding: 16px 20px; margin: 0;">`). 2–4 business-language scenarios. Last line links to Critical Attack Chain.
4. `### Architecture Assessment` — prose intro + table with columns: Severity (emoji), Layer, Defect, Consequence, Enables. Every T-NNN link in Enables includes a short label: `[T-NNN](#t-NNN) — <short label>`. Legend line after table.
5. `### Mitigations` — contains two sub-tables:
   - `#### Prioritized Mitigations` — P1 mitigations that address the Critical findings from the Top Threats table.
   - `#### Follow-up Mitigations` — P2/P3 mitigations for High/Medium findings not covered above.
   - Both tables use the same four columns: Priority, Mitigation, Addresses, Effort. Every threat reference in the Addresses column includes a short label: `[T-NNN](#t-NNN) — <short description>`. When multiple threats are addressed, use `<br/>` to separate them in table cells.
6. `### Operational Strengths` — **3-column table** (Control, What it provides, Limitation) with 5–8 rows. 2-column tables are FORBIDDEN. Ends with `**Bottom line:**` sentence.

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

**Section numbering:** Section 3 is "Attack Walkthroughs" (step-by-step exploitation sequence diagrams, one per Critical finding). The old "Security-Relevant Use Cases" and "Critical Findings" sections have been removed. The numbering is: 1 System Overview, 2 Architecture Diagrams, 3 Attack Walkthroughs, 4 Assets, 5 Attack Surface, 6 Trust Boundaries, 7 Identified Security Controls, 8 Threat Register, 9 Mitigation Register, 10 Out of Scope.

**Substep 5 — Part B: Sections 5–7 (Attack Surface, Trust Boundaries, Controls).**

Log `[5/<N>] Writing threat-model.md Part B (Sections 5–7)…` and **append** using Bash heredoc:
```bash
cat >> "$OUTPUT_DIR/threat-model.md" <<'PART_B_EOF'
<Part B content here>
PART_B_EOF
```
**Do NOT use the Write tool for Parts B–D** — it would re-emit the entire file as output tokens.

Part B contains:
- Section 4 — Attack Surface
- Section 5 — Trust Boundaries (including **Cross-Repository Dependency Coverage** sub-section when cross-repo dependencies were discovered — see below)
- Section 6 — Identified Security Controls
- **Section 6b — Requirements Compliance** (only when `CHECK_REQUIREMENTS=true`)

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

**Substep 6 — Part C: Section 8 (Threat Register).**

Log `[6/<N>] Writing threat-model.md Part C (Section 8 — Threat Register)…` and append to the file.

Part C contains:
- Section 7 — Threat Register (7.1 Critical, 7.2 High, 7.3 Medium, 7.4 Low)

**Triage flags in Threat Register:** Before composing the Threat Register tables, check if `$OUTPUT_DIR/.triage-flags.json` exists. If it does, read the flags and annotate affected threats:

- For each threat that has entries in `.triage-flags.json`, append a triage note below the threat's scenario cell in the table:
  `⚠️ TRIAGE: <flag message>` (for `warning` severity flags)
  `ℹ️ TRIAGE: <flag message>` (for `info` severity flags)
- Multiple flags on the same threat are rendered as separate lines
- If `.triage-flags.json` does not exist or has zero flags, skip triage annotation silently

This is the densest tabular section (~20–25 KB for 24 threats with full evidence). A dedicated turn prevents it from competing with diagram rendering or walkthrough prose for output budget. Advance checkpoint to `step=6 status=part_c_written`.

**Substep 7 — Part D: Sections 9–10 (Mitigations, Out of Scope).**

Log `[7/<N>] Writing threat-model.md Part D (Sections 9–10)…` and append to the file.

Part D contains:
- Section 9 — Mitigation Register (grouped by rollout priority: P1, P2, P3, P4)
- Section 10 — Out of Scope
- **Appendix: Run Statistics** — an unnumbered section appended after the last numbered section. Contains the total assessment duration, per-phase duration breakdown, tokens, and estimated cost. See "Run Statistics Appendix" below.

Typically ~15–20 KB. After it succeeds, advance checkpoint to `step=7 status=md_written`.

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

**Cost Estimate column headers:** dynamically determined from `agent_models` in the YAML — one column per unique model used. When only one model is used (no `agent_models` override), show a single value column with that model's name as header. The pricing reference table is static and always included.

**Billing label in the blockquote:** replace `_pending_` with `api` or `subscription (estimated)` — patched by QA Check 12.

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

**Error recovery:** if a turn fails during Part B/C/D, the earlier parts are already on disk. A `--resume` run can read the partial file, determine which `## N.` section heading was last written, and resume from the next part. The QA reviewer can also work with a partial file (it checks section-by-section).

**Section layout:** 10 numbered sections (1–10) plus unnumbered Management Summary, Critical Attack Chain, and Appendix. Section 3 is "Attack Walkthroughs" (sequence diagrams per Critical finding). The old "Critical Findings" section has been removed — its content was redundant with the Critical Attack Chain.

### Incremental Update Rules

When `WRITE_MODE=incremental`:

1. **Read the existing baseline** — before any composition, parse `$OUTPUT_DIR/threat-model.yaml` to extract: `meta.git.commit_sha` (= `BASELINE_SHA`), `components[]`, `threats[]`, `mitigations[]`, `changelog[]`. These are the carry-forward sources.
2. **Compute the delta** — from the dirty-set identified in Phase 9 (re-analyzed components) vs. the baseline's components/threats, derive:
   - `added_threats` — new T-IDs not in baseline `threats[]`
   - `changed_threats` — T-IDs present in both but with different `severity`, `cwe`, `evidence`, or `mitigations`
   - `resolved_threats` — baseline T-IDs whose owning component was re-analyzed but no longer produced them (or whose component was removed entirely)
   - `added_components`, `removed_components`, `reanalyzed_components`, `carried_forward_components`, `low_risk_skipped_components`
   - `added_entry_points`, `changed_entry_points` (from `attack_surface[]` delta, if the block is populated)
3. **Compose the new changelog entry** in memory:
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
     low_risk_skipped_components: [<id>, ...]  # dirty but non-security-relevant changes
     added:
       threats: [<T-ID>, ...]
       components: [<id>, ...]
       attack_surface: [<E-ID>, ...]
     changed:
       threats: [<T-ID>, ...]     # with note on what changed
     resolved:
       threats: [<T-ID>, ...]
       reason_by_id:
         <T-ID>: "<reason — component removed / no longer observed / ...>"
   ```
4. **Prepend** this entry to `changelog[]` in the yaml (newest first), then write yaml.
5. **Render the Changelog section** in `threat-model.md` (see template below).
6. **Update `.appsec-cache/baseline.json`** — refresh `recon_fingerprint`, `id_counters`, `stride_files[<id>].sha256` for all components touched in this run.
7. T-IDs of carry-forward components **must remain stable** — do not renumber.

When `WRITE_MODE=full`:

1. **Preserve the existing `changelog[]`** if `$OUTPUT_DIR/threat-model.yaml` already exists — read its current `changelog[]`, then **prepend** a new entry:
   ```yaml
   - version: <last_version + 1>
     date: <ISO now>
     mode: full
     plugin_version: <PLUGIN_VERSION>
     analysis_version: <ANALYSIS_VERSION>
     baseline_sha: null
     current_sha: <CURRENT_SHA>
     note: "full rebuild — all sections regenerated"
   ```
2. If no existing yaml exists (first run ever), start `changelog[]` with a single `version: 1, mode: full, note: "initial assessment"` entry.
3. Rewrite the rest of the yaml normally (components, threats, assets, etc.).
4. Render the Changelog section in `threat-model.md` even for full runs — a first-run full assessment produces a changelog with one `v1 — initial assessment` entry.

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
- A `mode: full` entry shows only `version`, `date`, and `note` — no added/changed/resolved breakdown (everything is "new" in a full rebuild).
- A `mode: incremental` entry shows the full breakdown.
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

  Incremental Summary (only when Mode = incremental):
    Changed files        : <count>
    Re-analyzed          : <n> components (<list>)
    Carried forward      : <n> components (<list>)
    Delta                : +<n> threats, ~<n> threats, -<n> threats
    Changelog entry      : v<N> added to threat-model.md (<date>)

  Paths:
    Repository   : <REPO_ROOT>
    Output       : <OUTPUT_DIR>

  Files Written:
    <OUTPUT_DIR>/threat-model.md          (<n> lines)
    <OUTPUT_DIR>/threat-model.yaml        (<n> lines)  ← always, unless --no-yaml
    <OUTPUT_DIR>/.appsec-cache/baseline.json
    <OUTPUT_DIR>/threat-model.sarif.json  (<n> bytes)  ← only if WRITE_SARIF

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
