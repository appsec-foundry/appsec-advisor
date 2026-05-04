# Phase Group: Output & Finalization (Phase 11)

This file is read by the orchestrator at runtime to load phase instructions.

## Progress visibility helper — `scripts/log_event.py`

Every `PHASE_START` / `PHASE_END` / `STEP_START` / `STEP_END` echo in this phase group **MUST** go through `scripts/log_event.py` rather than a raw `echo … >> .agent-run.log` call. The helper:

1. Writes the canonical log entry to `$OUTPUT_DIR/.agent-run.log` (same format as the legacy raw echo — downstream parsers are unchanged).
2. Mirrors a compact one-line summary to **stderr** with an auto-computed elapsed-time prefix (e.g. `↳ (+2m15s) Phase 11/11 · step 4/7 · Writing fragments…`), so the user sees phase/step progress in the Bash tool card even without `--verbose`.

Call shape:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" step-start "[Phase 11] [4/7] Writing fragments…"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" phase-end   "[Phase 11/11] ✓ Finalization complete"
```

The second positional arg is one of `phase-start | phase-end | step-start | step-end | info`. For `info`, pass the event name and detail as the third and fourth args (`info CUSTOM_EVENT "detail text"`). Raw `echo … >> .agent-run.log` calls that bypass the helper are a visibility regression — the user loses the live progress line.

## `threat-model.yaml` Schema (v1)

The yaml is the **single structured baseline** for incremental runs. It is always written when `WRITE_YAML=true` (the default — see SKILL.md flag matrix).

**Authoritative schema:** `$CLAUDE_PLUGIN_ROOT/schemas/threat-model.output.schema.yaml` (JSON-Schema draft 2020-12, enforced by `scripts/validate_intermediate.py`). Read it for field definitions, enum values, and required/optional constraints. The `appsec-threat-analyst.md` agent references the same schema; do not duplicate structural examples here — keep this file focused on the finalization-specific invariants below.

**Write-time field contract** (the schema file is authoritative; fields named here are the ones finalization must actively populate):

- `meta:` — `schema_version: 1`, `commit_sha:` (current HEAD), `baseline_ref:` (prior commit_sha or null), `run_statistics:` (written null, populated by QA Check 12).
- `changelog:` — **append-only**, newest first. Every entry carries `version:`, `baseline_sha:`, `current_sha:`, and the three delta sub-blocks `added:` / `changed:` / `resolved:`.
- `components:` — list of components with `paths:` (globs — source of truth for Phase 9 dirty-set) and `threat_ids:` (quick-lookup list).
- `tier_root_causes:` — **mandatory when ≥1 threat exists** (else omit). Per-architectural-tier root-cause bullets shown in the `Security Posture at a Glance` heatmap. Three keys: `client:`, `application:` (alias `server`), `data:`. Each is a list of 1–5 strings, **max 80 characters each**, expressing the architectural defect in plain language (e.g. `"missing input neutralization on raw SQL paths"`, `"hardcoded crypto secrets in source"`, `"no auth middleware on management endpoints"`). Derive from the threats grouped by their component's tier — each bullet should aggregate ≥2 findings sharing a root-cause class. **Skip a tier entirely** (omit the key) if it has no threats; **never emit empty arrays** — the renderer's fallback "(no root causes documented)" is only meaningful when the field is genuinely missing for an entire run, not for an individual tier.

**Hard invariants** (enforced by baseline_state.py and by incremental logic in Phase 9):

1. `meta.schema_version` is 1. Bump it only alongside a migration path.
2. T-IDs, M-IDs, and E-IDs are **stable across runs**. A carried-forward component must keep every one of its T-IDs. New IDs come from `.appsec-cache/baseline.json.id_counters`.
3. `changelog[]` is **append-only**. Never rewrite or delete historical entries, even on a full rebuild — instead, prepend a new `mode: full` entry.
4. `components[].paths` is the source of truth for the Phase 9 dirty-set mapping. Keep it in sync with the actual directory layout.
5. `meta.git.commit_sha` MUST be set to `git rev-parse HEAD` at the end of Phase 11, on every write. This is what the next run uses as baseline.
6. `meta.plugin_version` and `meta.analysis_version` MUST be read from `$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json` via `plugin_meta.py get` — never hardcoded. Every new `changelog[]` entry carries the same pair that was active at the time of that run, so a user can later reconstruct which analysis version produced which threats.
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

**M3.1 — Crash-safe PHASE_END.** If the agent's session is interrupted between PHASE_START and the explicit PHASE_END (Stage 2 cut-off, harness OOM, user STOP), `.agent-run.log` shows an open phase and the run-statistics appendix renders `(?)` for Phase 11 duration. To make PHASE_END crash-safe, the agent SHOULD register a Bash trap immediately after PHASE_START so any abnormal exit still writes a closing line:

```bash
# Register a trap that emits a PHASE_END_ABORTED line on shell exit.
# Skill normal-completion path overwrites this with a regular PHASE_END.
trap 'echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  WARN   threat-analyst  PHASE_END_ABORTED   [Phase 11/11] crashed before normal completion" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null' EXIT
```

The trap is **best-effort** — when Claude Code itself terminates the session, the trap may not fire. But for the common case (compose script error, fragment write OSError, etc.) the trap closes the log cleanly so downstream `aggregate_run_issues.py` doesn't compute negative or `(?)` durations.

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
> **Recommendation:** run `/appsec-advisor:create-threat-model --full` at your next opportunity to pick up the improvements.
```

Omit the callout entirely when `RECOMMEND_FULL=false`.

### Write Output Files

**⚠ MANDATORY STEP_START CONTRACT — no exceptions:**

- Every substep below MUST emit exactly one STEP_START log line **before** performing its work.
- Each STEP_START MUST be **batched in the same Bash / tool call** as the work it describes — never spend an extra orchestrator turn on logging alone. If a substep is implemented by a `Write` tool call (not Bash), emit the log in a preceding Bash call that **also advances** something concrete (e.g. reading a count, pre-computing a variable) so the turn is not wasted.
- The format is non-negotiable and identical to Phase 3–10: `[Phase 11 +${ES}] [k/N] <description>`. Any deviation breaks the ASSESSMENT_SUMMARY parser.
- Silent substeps (no STEP_START) are treated as a Phase 11 defect — this is the single most common reason Phase 11 looks like a hang.

**Elapsed-time helper — use `phase_elapsed.py` to avoid variable-assignment compounds that trigger permission prompts:**
```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/phase_elapsed.py" "$OUTPUT_DIR"
```
This outputs `<seconds> <MMmSSs>` (e.g. `127 2m07s`). Use the second token as `ES` in the next echo call.

**Canonical STEP_START echo:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +<ES>] [<k>/<N>] <description>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

When elapsed time is not critical, simply omit the `+<ES>` suffix to avoid the extra python3 call.

Also mirror each step to stdout: `  ↳ [<k>/<N>] <description>  (+${ES})`.

**Substeps (in order) — every one MUST log before doing the work:**

**⚠ ORDERING INVARIANT (since M2.7): write the YAML _before_ the Markdown.** The yaml is the structured baseline that every future incremental run reads; if a substep crashes, the Markdown can always be re-rendered from the yaml, but a missing yaml breaks the baseline and forces a full rebuild on the next run. Previously the md was written first, and several production runs ended mid-markdown-Write with no yaml on disk — leaving an orphan md and a broken incremental pipeline. The new order fixes this at zero cost: both files still need the same merged-threat data, and yaml is cheap to serialize (~45 KB of structured data vs ~90 KB of composed prose).

**Lock release happens LAST (since M3.3).** The previous "release at `k=1`" placement meant Phase 11's longest substeps (fragment authoring + compose, up to 15 min) ran with no lock, which blinded the anti-stall heartbeat classifier to the phase with the highest historical hang rate. The new rule: keep the lock held until the final substep and refresh its heartbeat at every `STEP_START` boundary. If the orchestrator hangs mid-Phase-11, the heartbeat goes stale after 5 min and the next run reaps the lock as `hung` — without needing to wait the 1 h mtime fallback. The small risk (lock leaks on a hard crash) is outweighed by the much larger benefit (deterministic stall detection).

| `k` | Description template | Condition | Batched with |
|-----|----------------------|-----------|--------------|
| 1 | `Pre-computing final counts…` | always | the Bash block below that refreshes the lock heartbeat and runs the count aggregation. The lock is NOT released here — it stays alive through Phase 11 so the anti-stall classifier has a heartbeat to watch. Every subsequent substep's Bash block also refreshes the heartbeat as its first line (see templates). |
| 2 | `Writing threat-model.yaml (canonical baseline)…` | **always — skip ONLY when `WRITE_YAML=false` (user passed `--no-yaml`).** Yaml is the canonical baseline for future incremental runs; skipping it by default breaks the incremental pipeline. | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.yaml`. **⚠ This MUST run before the md write — see ordering invariant above.** Immediately after the Write succeeds, advance the checkpoint: `echo 'CHECKPOINT phase=11 step=2 status=yaml_written' > "$OUTPUT_DIR/.appsec-checkpoint"` so that a crash during the md compose leaves a recoverable state. |
| 3 | `Updating .appsec-cache/baseline.json…` | always | the Bash call that invokes `baseline_state.py update` — see "Baseline Cache Update" below. This runs here (right after yaml) rather than at the end so the cache is consistent with the yaml even if later md composition fails. |
| 4 | `Writing data fragments for threat-model.md…` | always | Bash STEP_START + several `Write` tool calls (one per LLM-authored fragment) — see "Fragment-driven composition" below. The LLM emits schema-validated JSON data for the Verdict / Architecture Assessment / Critical Attack Chain sections and prose Markdown for the handful of prose-only sections. Advance checkpoint to `step=4 status=fragments_written` only after `validate_fragment.py` accepts every data fragment. |
| 4b | `Pre-render fragment gate…` | always | Bash call to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_fragment.py" pre-render-gate "$OUTPUT_DIR"`. Runs immediately after all fragment Writes and before compose. Validates every known JSON fragment in `.fragments/` in one shot, writes `.pre-render-report.json`, and exits 1 if any schema check fails — preventing a structurally broken document from being committed to the repo. See example Bash block below. |
| 5 | `Rendering threat-model.md (contract-driven composition)…` | always | Bash call to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" --output-dir "$OUTPUT_DIR"`. The renderer is deterministic — identical fragments produce byte-identical output. No Markdown is ever written by the LLM in this step. Advance checkpoint to `step=5 status=md_rendered`. |
| 6 | `Running QA structural checks…` | always | **Single Bash call** to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" all "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT"`. Advance checkpoint to `step=6 status=qa_clean`. **Sprint 1C (M3.5) — strictly deterministic.** This step is one Bash invocation only. Do **NOT** read its JSON output, do **NOT** spawn fragment Writes mid-step, do **NOT** invoke `compose_threat_model.py` again. Any required repair is owned by the **skill-layer Re-Render Loop** that runs *after* Phase 11 returns; mixing repair into Step 6 burns LLM turns (the 2026-04-27 run lost 4m 41s here because the orchestrator interpreted Step 6 output as a signal to rewrite `security-posture-attack-paths.json` mid-step, instead of letting the skill manage the repair plan). If `qa_checks.py all` exits non-zero, log the exit code and proceed to Step 7 — the contract-gate downstream of Stage 2 will pick up any drift via `.qa-repair-plan.json`. |
| 7 *or* 8 | `Generating SARIF export (<n> results) and writing threat-model.sarif.json…` (substitute `<n>`) | only if `WRITE_SARIF=true` | the `Write` tool call that creates `$OUTPUT_DIR/threat-model.sarif.json` |
| 8 *or* 9 | `Generating pentest tasks (<n> eligible threats) and writing pentest-tasks.yaml…` (substitute `<n>`) | only if `WRITE_PENTEST_TASKS=true` | the Bash call that invokes `render_pentest_tasks.py` — see "Pentest-Task Export" below. The `<n>` counter reports only the threats that passed the eligibility filter, not the full threat-register size. |
| N | `Releasing lock + clearing checkpoint + printing summary…` | always, LAST | the final cleanup Bash block — `rm -f "$OUTPUT_DIR/.appsec-lock"`, `rm -f "$OUTPUT_DIR/.appsec-checkpoint"`, and the assessment summary print. This is the ONLY lock-release site in the happy path; a mid-Phase-11 crash leaves the lock in place with a stale heartbeat so the next run's `acquire_lock.py` classifies it as `hung` and reaps it. |

### Pentest-Task Export

When `WRITE_PENTEST_TASKS=true`, emit `$OUTPUT_DIR/pentest-tasks.yaml` *after* the SARIF export (or after the md write if SARIF is off) by calling the dedicated renderer. The orchestrator does NOT compose this file in-prompt — the exporter is deterministic Python and keeps the CWE eligibility logic identical to the CVSS-scope enforcement in Phase 10b.

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] [<k>/<N>] Generating pentest tasks and writing pentest-tasks.yaml…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
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

**Substep 1 — pre-compute counts + first heartbeat (mandatory Bash template, batched with the `[1/N]` STEP_START):**

```bash
# log_event.py writes the canonical STEP_START entry to .agent-run.log AND
# mirrors a compact progress line ("↳ (+2m15s) Phase 11/11 · step 1/<N> · Pre-computing final counts…")
# to stderr so the user sees it in the Bash tool card even without --verbose.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" step-start "[Phase 11] [1/<N>] Pre-computing final counts…"
# Refresh lock heartbeat — keeps the anti-stall classifier seeing progress.
# The lock is released only at the final substep (see N/N below).
python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" --heartbeat 2>/dev/null || true
echo 'CHECKPOINT phase=11 step=1 status=counts_computed' > "$OUTPUT_DIR/.appsec-checkpoint"
CRIT=$(grep -c '"risk": *"Critical"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
HIGH=$(grep -c '"risk": *"High"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
MED=$(grep -c '"risk": *"Medium"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
LOW=$(grep -c '"risk": *"Low"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
COMPS=$(ls "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | wc -l)
MITS=$(grep -c '"mitigation_title"' "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
echo "COUNTS: crit=$CRIT high=$HIGH med=$MED low=$LOW comps=$COMPS mits=$MITS"
```

**Heartbeat pattern — prefix every Phase 11 substep's Bash block with this line** so the anti-stall classifier watches the whole phase, not just the first substep:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" --heartbeat 2>/dev/null || true
```

Cheap (< 10 ms), idempotent, safe on a missing lock file. Failure to refresh is intentionally non-fatal — the next substep will retry.

**Final substep — release lock + clear checkpoint (`[N/N]` template):**

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" step-start "[Phase 11] [N/<N>] Releasing lock + clearing checkpoint…"
rm -f "$OUTPUT_DIR/.appsec-lock"
rm -f "$OUTPUT_DIR/.appsec-checkpoint"
echo "ASSESSMENT_COMPLETE"
```

Use the printed `COUNTS:` line to populate concrete numbers in the Management Summary, Section 8 headings (`### 7.1 Critical (<CRIT>)`, …), and the assessment summary footer. These counts are ground truth — do not recompute them by eye during composition.

**Substep 2 — write threat-model.yaml (MUST run before md write):**

Compose the full yaml body in memory (schema at top of this file). The Write tool call in this substep carries the yaml `content:` argument.

**F-NNN ID reflow rule (CRITICAL — non-negotiable):** When transferring threats from `.threats-merged.json` into `yaml.threats[]`:

- **Every** entry in `.threats-merged.json` MUST be present in `yaml.threats[]` with a sequential F-NNN id.
- F-NNNs MUST be **contiguous starting at F-001** with no gaps. Drop a threat ⇒ shift every subsequent F-NNN down by one.
- The mapping is `{merged.threats[i].id (T-NNN)} → F-{i+1:03d}`, but **only when `i+1` reflects the position after any drops**, not the original `t_id` slot.
- If you legitimately omit a threat (e.g. duplicate consolidated into another), reflow IDs and update the `original_id:` field of every later threat to its merged-source `id`. Never leave gaps like `F-013, F-015` — `validate_intermediate.py` flags this as a contract advisory and downstream cross-refs become tombstones.

**Bad** (the 2026-05-01 juice-shop bug): merged.json has 32 threats including T-014 "Default Admin Credentials Hardcoded in Static Data"; the LLM dropped that one without reflowing, producing `F-001…F-013, F-015…F-032` (F-014 missing, dead `[F-014](#f-014)` link in any place that referenced it).

**Good:** if you drop the same T-014 threat, every subsequent F-NNN shifts: `F-001…F-013, F-014 (was T-015), F-015 (was T-016), …, F-031 (was T-032)`.

**Requirement linkage — populate `violated_requirements` per threat:** When composing `threats[]` in the yaml, for every threat in `.threats-merged.json` that carries a `requirement_id` field, set `violated_requirements: ["<requirement_id>"]` on the corresponding yaml threat entry. For threats without `requirement_id`, emit `violated_requirements: []` (or omit the field — both are valid per the output schema). This is the bridge that lets `check-appsec-requirements` look up T-IDs by requirement ID without re-parsing Markdown. Batch it with a `[2/<N>] Writing threat-model.yaml (canonical baseline)…` STEP_START echo **in the same turn**. Yaml composition is ~45 KB and typically completes in one turn; if the model needs a second turn to finish, the checkpoint from substep 1 is enough to recover.

**Mitigation synthesis (mandatory before YAML write — §9 depends on this):**

Before writing `threat-model.yaml`, synthesise `mitigations[]` from the `mitigation_title` strings in `.threats-merged.json`:

1. Read every `mitigation_title` from `.threats-merged.json` entries.
2. Group entries whose `mitigation_title` describes the same physical fix (same library upgrade, same config change) into one M-NNN record.
3. Emit each group as a `mitigations[]` entry using **canonical field names** (`title` not `mitigation_title`; `threat_ids` not `addresses`):

```yaml
mitigations:
  - id: M-001                    # sequential from M-001
    title: "..."                 # cleaned-up from mitigation_title
    threat_ids: [T-001, T-003]   # all T-IDs this mitigation covers
    priority: P1                 # computed per P1–P4 algorithm (phase-group-threats.md:1123)
    severity: Critical           # max severity across threat_ids
    effort: Medium               # from remediation.effort in .threats-merged.json
```

4. Back-link each threat: set `threats[i].mitigations: [M-NNN]` for every addressed T-ID so the Top Findings and Threat Register Mitigation columns render M-NNN links instead of "—".

**Field-name invariant:** `title` (not `mitigation_title`), `threat_ids` (not `addresses`). A yaml that ships `mitigation_title:` produces `(untitled)` headings and empty Mitigation columns — the schema validator rejects it.

**Why yaml first:** if the run crashes during the subsequent ~90 KB markdown write (historically the most expensive and failure-prone substep in Phase 11), the canonical structured baseline is already on disk. Any future run — incremental, full, or resume — can read the yaml to know what was found, the markdown can be re-rendered from it, and the incremental pipeline is not broken.

**After the Write succeeds, advance the checkpoint in the next Bash batch:**
```bash
echo 'CHECKPOINT phase=11 step=2 status=yaml_written' > "$OUTPUT_DIR/.appsec-checkpoint"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  FILE_WRITE   $OUTPUT_DIR/threat-model.yaml" >> "$OUTPUT_DIR/.agent-run.log"

# Schema-validate the freshly-written yaml against schemas/threat-model.output.schema.yaml.
# Hard gate: a non-zero exit means the yaml is structurally invalid and the
# downstream md render would silently produce broken cross-references (e.g.
# `(untitled)` Mitigation Register headings, empty Mitigation columns).
# Migration advisories for legacy field names (`mitigation_title` →
# `title`, `addresses` → `threat_ids`) are emitted as `ADVISORY:` lines and
# do NOT fail the gate — they are surfaced so the producer fixes the
# upstream source. See agents/phases/phase-group-threats.md →
# "Build Mitigation Register" → "Canonical yaml shape".
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py" \
  threat_model_output "$OUTPUT_DIR/threat-model.yaml" \
  | tee -a "$OUTPUT_DIR/.agent-run.log"
VALIDATE_RC=${PIPESTATUS[0]}
if [ "$VALIDATE_RC" -ne 0 ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  ERROR  threat-analyst  YAML_INVALID  threat-model.yaml failed schema validation — see ADVISORY/INVALID lines above. Fix before continuing." >> "$OUTPUT_DIR/.agent-run.log"
  exit 1
fi
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
| Security Posture — Attack Paths | `.fragments/security-posture-attack-paths.json` | `{schema_version: 1, actors:[…], attack_paths:[{class, actor, target, description, architectural_root_causes, findings, attack_chains, impact}]}` — schema-validated against `schemas/fragments/security-posture-attack-paths.schema.json` | Drives the seven numbered attack-class bullets (① ⑦) below the heatmap. See "Authoring `security-posture-attack-paths.json`" below for the per-class authoring guide. |
| System Overview (§1) | `.fragments/system-overview.md` | Plain Markdown starting with `## 1. System Overview`. **Do NOT repeat deployment topology** (port numbers, container base image, runtime user, network exposure) — that information already lives in §2.1 System Context as a labelled diagram. §1 covers business purpose, primary user roles, in-scope/out-of-scope perimeter; §2 covers the *how* of deployment. | Heading-match validation, inlined verbatim. |
| Architecture Diagrams (§2) | `.fragments/architecture-diagrams.md` | Plain Markdown with required `### 2.1 System Context`, `### 2.3 Security Architecture Assessment`, and at least one `` ```mermaid `` block. **Captions must distinguish the C4 levels:** §2.1 = *System Context (system + external actors + datastores)*; §2.2 = *Container Architecture (deployable units + their internal interfaces)*; §2.3 = *Security Architecture Assessment*. The two diagrams have different scopes — overlap in node labels is acceptable, but the captions must explain WHAT each diagram adds beyond the previous one. | Required-subsection + required-pattern validation. |
| Attack Walkthroughs (§3) | `.fragments/attack-walkthroughs.md` | Plain Markdown with at least one `sequenceDiagram` per Critical finding. **§3.1 intro paragraph** must explicitly note that *§3 documents the Critical findings as sequence diagrams; all findings are tabularly documented in §8*. **Heading format (HARD RULE):** `### 3.X {ShortTitle}` where `{ShortTitle}` is **2–6 words, ≤60 characters, and matches the `title` field of the corresponding F-NNN in `threat-model.yaml`**. The F-NNN appears once in a `**Source:** [F-NNN](#f-nnn)` line below the heading, not three times across heading/diagram-title/bullet. <br>**Good:** `### 3.4 Stored XSS in Feedback` (28 chars). <br>**Bad:** `### 3.4 T-003 — Stored XSS in Feedback Leading to Admin Account Takeover` (72 chars — includes obsolete T-NNN prefix AND the full sentence form of the title). <br>**Anchor convention:** chain anchors MUST be on a separate line above the heading using the canonical CC-NN slug (`<a id="cc-1"></a>\n#### CC-1 — Title`), NOT `chain-N` and NOT inline. Inline `<a>` tags break right-side TOC outline panels in many markdown viewers. **Headings > 100 characters trip `qa_checks.py:check_heading_hygiene` and force a Re-Render Loop iteration.** | Required-pattern validation + heading-length gate. |
| Assets (§4) | `.fragments/assets.md` | Plain Markdown containing a `\| Asset \|` table | Required-pattern validation. |
| Attack Surface (§5) | `.fragments/attack-surface.md` | Plain Markdown with required `### 5.1 Unauthenticated…` and `### 5.2 Authenticated…` sub-sections | Required-subsection validation. |
| Security Architecture (§7) | `.fragments/security-architecture.md` | Plain Markdown starting with `## 7. Security Architecture` | Heading-match validation. |
| Threat Register (§8) | — | (no fragment — derived from `threat-model.yaml → threats[]`) | Risk Distribution + STRIDE Coverage lines, 8.1–8.4 sub-tables with 9-column schema, ID anchors. |
| Mitigation Register (§9) | — | (no fragment — derived from `threat-model.yaml → mitigations[]`) | P1–P4 sub-sections, per-mitigation heading with anchor, **Addresses / Priority / Severity / Effort / Why / How / Verification** block. |
| Out of Scope (§10) | `.fragments/out-of-scope.md` | Plain Markdown starting with `## 10. Out of Scope` | Heading-match validation. |
| Appendix: Run Statistics | — | (no fragment — derived from `threat-model.yaml → meta.run_statistics`) | Deterministic tables, only rendered when `verbose_report=true`. |
| Appendix A: Vektor Taxonomy | — | (no fragment — derived from `data/breach-vector-taxonomy.yaml`) | Fixed `<a id="vektor-…">` anchor per vektor. |

### Authoring `security-posture-attack-paths.json`

The Security Posture heatmap aggregates every code-level finding into **seven canonical attack classes** defined by `data/attack-class-taxonomy.yaml`:

1. `injection` — SQL / NoSQL / XML / YAML / OS-command injection (CWE-89/77/78/611/643/943/94 …)
2. `auth-bypass` — credential / signing-key / hash weaknesses (CWE-287/294/321/326/327/328/347/798)
3. `privilege-escalation` — missing/bypassable authorisation checks (CWE-269/285/639/862/863/620/732)
4. `sensitive-data-exposure` — confidential files/secrets reachable on unauth routes (CWE-200/319/532/548/552/22/601 …)
5. `remote-code-execution` — server-side code-execution sinks (CWE-94/95/502/913/918/1321)
6. `cross-site-scripting` — XSS in any form (CWE-79/80/83/84/85/86)
7. `cross-site-request-forgery` — CSRF / overly permissive CORS (CWE-352/942)

For each class with **≥ 1 matching finding** in the threat register, emit one entry in `attack_paths[]` (skip empty classes — never emit zero-finding entries). Order MUST match the order in the taxonomy file (so the renderer assigns ① to the first non-empty class, ② to the second, etc., without gaps).

Per-entry authoring rules:

- **`class`** — slug from the list above. Each slug appears at most once across the array.
- **`actor`** — the threat actor that initiates the attack (or, for victim-targeting classes ⑥/⑦, the actor that is *targeted by* the arrow). Pick from the slugs in `data/posture-actor-labels.yaml`. Add the slug to the top-level `actors` list as well.
- **`target`** — `client` / `application` / `data` / `victim`. Direct attacks land on a tier; XSS/CSRF land on `victim`.
- **`description`** — **ONE generic sentence describing the class as a whole**, NOT a per-vector walkthrough. Keep it CWE-cluster-level (e.g. "user input flows into a server-side interpreter without parameterisation"), not finding-specific. Hard limit: 280 chars.
- **`architectural_root_causes`** — 0–5 AF-NNN ids that aggregate the findings in this class. Pull from `architectural_findings[]` in `threat-model.yaml`. Empty array if no AF maps to the class.
- **`findings`** — 1–12 F-NNN ids. **Required.** A class with zero findings must be omitted from the array.
- **`attack_chains`** — 0–5 chain ids of the form `cc-NN` (canonical CC-NN slug; same anchor as the §8.F Compound Attack Chains headers and the `<a id="cc-NN">` markers in §3.1). Empty array if no chain materialises this class.
- **`impact`** — 1–4 outcome slugs from `data/business-impact-taxonomy.yaml`: `customer-session-hijack`, `full-admin-takeover`, `full-server-compromise`, `customer-data-exfiltration`. Order matters — most likely / highest-severity first.

**Canonical example — copy this shape verbatim, do NOT invent your own field names:**

```json
{
  "schema_version": 1,
  "actors": ["internet-anon", "internet-user", "victim-required"],
  "attack_paths": [
    {
      "class": "injection",
      "actor": "internet-anon",
      "target": "application",
      "description": "User input flows into a server-side interpreter without parameterisation, enabling SQL / OS-command / template execution.",
      "architectural_root_causes": ["af-01"],
      "findings": ["F-001", "F-002"],
      "attack_chains": ["cc-1"],
      "impact": ["customer-data-exfiltration", "full-admin-takeover"]
    },
    {
      "class": "cross-site-scripting",
      "actor": "victim-required",
      "target": "victim",
      "description": "Attacker-controlled input reaches the rendered DOM without escaping; victim's browser executes the payload.",
      "architectural_root_causes": [],
      "findings": ["F-015", "F-016", "F-017"],
      "attack_chains": [],
      "impact": ["customer-session-hijack"]
    }
  ]
}
```

**Forbidden field names** (these come from kill-chain / attack-flow schemas and are NOT this schema): `id`, `title`, `threat_chain`, `entry_point`, `target_asset`, `attacker_skill`, `steps_count`, `severity`. The renderer will fall back to a deterministic CWE-derived diagram if it sees these instead of the canonical fields above — losing the LLM-authored AF and chain links.

Validate with `python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_fragment.py" security-posture-attack-paths "$OUTPUT_DIR/.fragments/security-posture-attack-paths.json"` before continuing. **If the fragment is missing or malformed**, the renderer falls back to a deterministic CWE→class assignment with no AF/chain links — a working but reduced output. Always emit the fragment when possible to surface the LLM-derived AF and chain links.

**Hard gates (all must pass or the whole Phase 11 re-runs):**

1. After every fragment Write, call `validate_fragment.py` for JSON fragments and `compose_threat_model.py` will re-validate at render time. A schema violation aborts with `RENDER_FAILED` and a pointer to the offending field. **Batch the validation with a per-fragment checkpoint update in the same Bash call** — this gives the skill-level Phase-11 cutoff detector and the resume path a precise picture of how many fragments survived a crash:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" --heartbeat 2>/dev/null || true
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_fragment.py" verdict "$OUTPUT_DIR/.fragments/ms-verdict.json" || {
     echo "BASH_ERROR: ms-verdict.json failed schema validation — fix and re-Write before continuing." >&2
     exit 1
   }
   FRAG_N=$(ls "$OUTPUT_DIR"/.fragments/*.{md,json} 2>/dev/null | wc -l)
   echo "phase=11 step=4 status=fragment_writing fragments_written=$FRAG_N timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTPUT_DIR/.appsec-checkpoint"
   ```

   The heartbeat refresh is the standard Phase-11-substep prefix (see "Heartbeat pattern" below) — every Bash block inside Phase 11 must carry it so the anti-stall classifier never falsely flags a fragment-writing run as hung.

   The same two lines (`FRAG_N=…` + `echo … > .appsec-checkpoint`) MUST be appended to every fragment-validate Bash block, not just the verdict one. The `fragments_written` counter is what the skill's `STAGE11_CUTOFF` banner reports — without it, a Phase 11 crash leaves the checkpoint stuck at the outer `phase=11 status=started` and we cannot tell from disk whether 1 or 11 fragments made it. Two lines per fragment is a cheap diagnostic insurance policy.

2. **Substep 4b — pre-render gate** (runs after all fragment Writes, before compose):

   ```bash
   PE=$(cat "$OUTPUT_DIR/.phase-epoch" 2>/dev/null || date +%s) && EL=$(( $(date +%s) - PE )) && ES=$(printf "%dm%02ds" $((EL/60)) $((EL%60))) \
   && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11 +${ES}] [4b/<N>] Pre-render fragment gate…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_fragment.py" pre-render-gate "$OUTPUT_DIR" || {
     echo "BASH_ERROR: pre-render gate failed — fix the listed fragments and re-run substep 4." >&2
     exit 1
   }
   ```

   The gate writes `$OUTPUT_DIR/.pre-render-report.json` (kept by the post-QA cleanup wave). **Exit code 1 means one of two things:**
   - the `.fragments/` directory is missing entirely — the orchestrator bypassed the fragment pipeline (this used to be silent; since M3.2 it is a hard fail because the downstream compose step never runs when fragments are missing);
   - one or more of the 8 unconditional required fragments (`ms-verdict.json`, `ms-architecture-assessment.json`, `system-overview.md`, `architecture-diagrams.md`, `attack-walkthroughs.md`, `assets.md`, `attack-surface.md`, `security-architecture.md`) is missing, or a JSON fragment fails its schema.

   Either way: fix the fragments and repeat the Write + gate cycle before proceeding to compose. **Do not work around this gate by Writing `threat-model.md` directly** — the skill's post-Stage-1 fragment check (see `SKILL.md` → "Post-Stage-1 fragment precondition") re-runs the same check and fails the run visibly.

3. After rendering, run the contract-compliance check:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" contract "$OUTPUT_DIR/threat-model.md" || {
     echo "BASH_ERROR: threat-model.md violates sections-contract.yaml — inspect the printed issues and re-render." >&2
     exit 1
   }
   ```

3. Optional layer-3 auto-repair for MS heading drift (numeric prefixes, legacy names) via `qa_checks.py ms_structure` — runs inside `qa_checks.py all` during substep 6.

4. **If compose fails with `RENDER_FAILED: …` or `RENDER_HINT: …`** — it has written `$OUTPUT_DIR/.pre-render-repair-plan.json`. Read that file (single `actions[0]` entry), edit **only** the listed `fragments_to_rewrite` path, follow the `remediation` text verbatim, then re-run compose. Do **not** guess which fragment is at fault — the plan is authoritative. This exists specifically to short-circuit the old fix-loop where the orchestrator mis-edited `architecture-diagrams.md` when the real offender was `security-architecture.md`.

   **Exit-code contract:**
   - `0` → render succeeded, plan file is auto-deleted.
   - `1` → render failed but the pre-render repair budget is not yet exhausted; apply the fix from the plan and re-run compose (max 3 attempts per fragment).
   - `4` → render failed and the repair budget is exhausted (`.pre-render-repair-plan.json.status == "exhausted"`). **Do NOT re-invoke compose within this Stage 1 dispatch.** Stop Phase 11, log the exhaustion, and let the skill-level Re-Render Loop drive a fresh repair iteration with a new Stage 1 turn budget. Looping locally burns through Stage 1 turns without escaping the failure mode.

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" --output-dir "$OUTPUT_DIR"
   RC=$?
   if [ "$RC" -eq 4 ]; then
     echo "BASH_ERROR: compose repair budget exhausted — escalating to skill-level Re-Render Loop." >&2
     exit 4
   elif [ "$RC" -ne 0 ]; then
     if [ -f "$OUTPUT_DIR/.pre-render-repair-plan.json" ]; then
       echo "BASH_ERROR: compose failed — read .pre-render-repair-plan.json and fix the listed fragment, then re-run compose." >&2
     fi
     exit "$RC"
   fi
   ```

   **§7 Security Architecture drift pattern (most common).** The required 14 subsections are 7.1 Overview, 7.2 Key Architectural Risks, 7.3 IAM, 7.4 Authorization, 7.5 Input Validation & Output Encoding, 7.6 Data Protection & Session Management, 7.7 Frontend Security, **7.8 Real-time / WebSocket**, **7.9 AI / LLM**, 7.10 Audit & Logging, 7.11 Container & Runtime Security, 7.12 Dependency & Supply Chain, 7.13 Secret Management, 7.14 Defense-in-Depth Assessment. Dropping 7.8 and 7.9 shifts every later heading by 2 and breaks the renderer. When no WebSockets / no AI surface are found in the repo, the subsections still MUST exist — emit them with a single-paragraph "_Not applicable — no WebSocket / Socket.IO usage detected by recon-scanner._" body and no control table.

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

**Section numbering:** Section 3 is "Attack Walkthroughs" (step-by-step exploitation sequence diagrams, one per Critical finding). The old "Security-Relevant Use Cases", "Critical Findings", and standalone "Trust Boundaries" sections have been removed. Trust boundary content is integrated into §7.11 Container & Runtime Security. The canonical numbering is: 1 System Overview, 2 Architecture Diagrams, 3 Attack Walkthroughs, 4 Assets, 5 Attack Surface, 7 Security Architecture, 8 Threat Register, 9 Mitigation Register, 10 Out of Scope. **Note: section 6 is intentionally absent** — it was the former Trust Boundaries section; the gap preserves external links from prior runs.

### What the Attack Surface + Security Architecture fragments must encode

The previous "Substep 5 Part B" direct-write step is removed. The fragments driving §5 and §7 are:

- `.fragments/attack-surface.md` — §5 Attack Surface, must contain `### 5.1 Unauthenticated Entry Points` and `### 5.2 Authenticated Entry Points` sub-sections per `sections-contract.yaml`. If cross-repository dependencies exist, include a dedicated `### 5.3 Cross-Repository Dependency Coverage` sub-section inside the same fragment.
- `.fragments/security-architecture.md` — §7 Security Architecture, must contain the 14 canonical sub-sections (7.1 Overview … 7.14 Defense-in-Depth Assessment). Section 6 is intentionally absent (former Trust Boundaries — gap preserved for external link stability).
- `.fragments/requirements-compliance.md` — §7b Requirements Compliance, only when `CHECK_REQUIREMENTS=true`.

The renderer concatenates them in the order declared by `document.order`. The rules below describe how those fragments must be composed; they apply to fragment authoring only.

### Authoring `security-architecture.md` — scaffold-fill protocol

The pre-generator (`pregenerate_fragments.py`) writes a **structural scaffold** into `.fragments/security-architecture.md` before Phase 11 starts. The scaffold contains:

- All 14 required sub-section headings (satisfying the pre-render gate).
- Machine-derived controls tables and Mermaid sequence diagrams (verified against `threat-model.yaml`).
- A **structured §7.1 Overview scaffold** with `**Control coverage**` bullets pre-populated from `security_controls[]` (Adequate / Partial / Weak-or-Missing groupings). The LLM expands the trailing NARRATIVE_PLACEHOLDER with two short bulleted sub-blocks (top risk themes + defense-in-depth posture) — see §"7.1 Overview" below for the exact contract. The deprecated **Gap-Summary block** (both prose and table forms) was removed post-2026-05; do NOT re-introduce a `**Gap summary:**` paragraph or table.
- HTML comment markers the LLM **must replace** with narrative prose:
  - `<!-- NARRATIVE_PLACEHOLDER: section=7.1 … -->` — appears once at the bottom of §7.1; replaced with bulleted top-themes + defense-in-depth bullet (NO prose).
  - `<!-- NARRATIVE_PLACEHOLDER: domain=<id> … -->` — appears before each domain's controls table (§7.2–§7.14).
  - `<!-- NARRATIVE_PLACEHOLDER: flow=7.3.N … -->` — appears before each `#### 7.3.N` auth-method sub-subsection.
  - `<!-- FINDINGS_PLACEHOLDER: … -->` — appears after each §7.3.N Mermaid diagram; contains a pre-populated finding list the LLM edits in place.

**Step-by-step authoring protocol for substep 4 (security-architecture.md):**

1. **Read the scaffold:**
   ```bash
   cat "$OUTPUT_DIR/.fragments/security-architecture.md"
   ```
   Do NOT start from a blank file — the scaffold contains machine-verified data (control IDs, finding IDs, CWE refs) that must be preserved.

2. **Do NOT add a `**Gap summary:**` block** (neither prose paragraph nor table). The Gap-Summary section was removed post-2026-05 — its prose form duplicated the Management Summary's Top Findings, and its table form duplicated §7.2 Key Architectural Risks. The structured `### 7.1 Overview` block (Control coverage bullets + Top themes bullets + Defense-in-depth bullet) is the canonical replacement. If your scaffold contains a stale Gap-Summary block from a pre-2026-05 cache, delete it.

3. **Replace every `<!-- NARRATIVE_PLACEHOLDER: domain=<id> -->` comment** with a 2–4 sentence domain assessment that:
   - Names the dominant control deficiency in this domain.
   - Explains the realistic attacker capability it enables (e.g., "An unauthenticated attacker can forge any user's JWT using the publicly readable private key").
   - Cross-references the highest-severity finding IDs in this domain as `[T-NNN](#t-nnn)`.
   - Never repeats the table data verbatim — the table is the evidence, the narrative is the interpretation.

4. **Replace every `<!-- NARRATIVE_PLACEHOLDER: flow=7.3.N -->` comment** with a 2–3 sentence flow introduction per the spec in "§7.3 Identity & Access Management — per-auth-method decomposition": name the endpoint path(s), implementation files, cryptographic primitives / libraries in use, token/session TTL, and rate-limiting status.

5. **Replace every `<!-- FINDINGS_PLACEHOLDER -->` comment** with the final `**Findings in this flow:**` trailer using the pre-populated list as a starting point. Prune finding IDs that do not actually apply to this specific flow; add any that do apply and are missing. Use the format:
   ```
   **Findings in this flow:** [T-NNN](#t-nnn) — <short title><br/>[T-NNN](#t-nnn) — <short title>
   ```
   When no findings apply to this specific flow, use `**Findings in this flow:** — none` (never leave this line absent — the QA gate enforces its presence).

6. **Fill the `**Risk assessment:**` placeholders** in each §7.3.N block with a 2–4 sentence assessment ending with `**Residual risk:** Critical|High|Medium|Low — <one-line justification>`.

7. **Do NOT modify** the Mermaid sequence diagrams, the controls tables, the section headings, the SC-NN IDs, or the T-NNN IDs embedded in the table cells — those are machine-verified data anchors. Only replace the HTML comment placeholder lines and the `<!-- replace … -->` trailer stubs.

8. **Write the completed fragment** back to `.fragments/security-architecture.md`. The file must start with `## 7. Security Architecture` and must contain no remaining `<!-- NARRATIVE_PLACEHOLDER` or `<!-- FINDINGS_PLACEHOLDER` tokens — the pre-render gate checks for these and fails the build if any are still present. (`GAP_SUMMARY_PLACEHOLDER` was removed; the Gap-Summary table is now rendered deterministically by `_build_gap_summary`.)

**Quality bar:** the narrative in a complete `security-architecture.md` should allow a security-aware reader who has NOT read the full threat register to understand (a) what the dominant attack surface looks like, (b) which controls are absent and why that matters, and (c) what a realistic worst-case exploitation chain looks like for each auth flow. Refer to "Section 7 rendering rules" below and the worked example at lines 656–691 of this file for the complete structural spec and a full §7.3.1 example block.

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

Section 7 is the unified security architecture section. It opens with **7.1 Overview** (a high-level summary derived from Section 2.4), followed by per-domain subsections (7.2–7.12), and closes with two cross-cutting subsections (7.13 Secret Management, 7.14 Defense-in-Depth Assessment). The trust boundary content formerly in standalone section 6 is integrated into 7.11 Container & Runtime Security.

**Section intro paragraph** (mandatory, before any sub-section):

```markdown
## 7. Security Architecture

This section consolidates the architectural narrative (patterns, per-domain assessment, cross-cutting topics) with the canonical control catalog. Each domain contains architectural reasoning and the controls that implement — or fail to implement — it.

**Reading guide**
- [§7.1 Overview](#71-overview) — control coverage, top themes, defense-in-depth posture
- [§7.2](#72-key-architectural-risks)..[§7.12](#712-dependency--supply-chain) — Per-domain narrative + controls
- [§7.13 Secret Management](#713-secret-management) — cross-cutting
- [§7.14 Defense-in-Depth Assessment](#714-defense-in-depth-assessment) — cross-cutting

**Catalog totals:** ✅ <n> Adequate · ⚠️ <n> Partial · 🔶 <n> Weak · ❌ <n> Missing · <total> controls tracked.
```

**No `**Gap summary:**` paragraph** — the prose form was deprecated post-2026-05 because it duplicated §7.2 "Key Architectural Risks" and the §Management Summary "Top Findings" table without adding analysis. The structured §7.1 Overview bullets below replace it.

**7.1 Overview (mandatory opening sub-section) — STRUCTURED BULLETS, not prose:**

Render as `### 7.1 Overview`. The pre-generator emits a scaffold with the **Control coverage** bullets already filled in from `security_controls[]`. Your job is to expand the `<!-- NARRATIVE_PLACEHOLDER: section=7.1 ... -->` slot with **two short bulleted sub-blocks**:

1. **Top architectural risk themes (3 bullets, ≤2 sentences each).** Each bullet names one cluster of related findings and the architectural property that enables them (e.g. "**Cryptographic key mismanagement** — RSA signing key, HMAC secret and cookie secret all hardcoded in source. Compromises the integrity of every JWT, session cookie and OAuth handshake the server issues."). Cite the cluster's threats with linked refs at the end of the bullet, e.g. `→ [T-005](#t-005), [T-013](#t-013)`. **No prose paragraphs.**
2. **Defense-in-depth posture (1 bullet, ≤3 sentences).** State whether layered defenses exist (WAF, network segmentation, row-level security, audit alerting, rate-limiting at the edge), and describe the realistic blast radius of a single successful attack. End with a bold `**Posture:**` rating: 🔴 None / 🟡 Limited / 🟢 Layered.

Do **not** add an "Architecture Patterns table" — that table moved to §7.2 to avoid duplication. Do **not** add an "Overall Architecture Security Rating" sentence — the verdict lives in the Management Summary at the top of the document.

**7.2 Key Architectural Risks (mandatory):**

Render as `### 7.2 Key Architectural Risks` — same table as §2.4.2 but with full Why-this-matters prose. Intro sentence mandatory.

**Step 1 — Read `security_controls[]`** from the YAML. Each entry carries the Phase-2 unified schema (see `phase-group-architecture.md` → "Phase 8 output schema"): `id`, `architectural_control`, `domain`, `implementation`, `effectiveness`, `gaps`, `mitigates_findings`, `references`, `positive_framing`, `show_in_strengths_by_default`.

**Step 2 — Group by domain.** The domain enum comes from `$CLAUDE_PLUGIN_ROOT/data/architectural-controls.yaml → domains`. Render each domain as a sub-section `### 7.<n> <domain-title>`, sorted in this canonical order:

1. `7.3 IAM` — Identity & Access Management — requires the per-auth-method decomposition described below.
2. `7.4 AuthZ` — Authorization
3. `7.5 InputVal` — Input Validation & Output Encoding
4. `7.6 DataProt` — Data Protection & Session Management
5. `7.7 FrontendSec` — Frontend Security
6. `7.8 RealTime` — Real-time / WebSocket
7. `7.9 AI` — AI / LLM (omit when no AI-related controls exist)
8. `7.10 Audit` — Audit & Logging
9. `7.11 Infra` — Container & Runtime Security (integrate former Trust Boundaries content here: include the trust boundary table with columns `# | Boundary | From | To | Enforcement | Key Weakness | Linked Threats`, followed by the controls table)
10. `7.12 SupplyChain` — Dependency & Supply Chain
11. `7.13 SecretMgmt` — Secret Management (cross-cutting — renders the §2.4.3 content as a standalone subsection with the current-state vs. target-state diagram when `ASSESSMENT_DEPTH=thorough`)
12. `7.14 DefenseInDepth` — Defense-in-Depth Assessment (cross-cutting — renders the §2.4.8 content as a standalone subsection with a layered-defense evaluation table)

Omit any sub-section with zero controls AND no architectural narrative. The numbering remains stable — if `AI` is omitted, `Audit` still becomes `7.10` (skip the empty slot). `7.13` and `7.14` are always emitted regardless of control count.

**§7.3 Identity & Access Management — per-auth-method decomposition (mandatory, hard-enforced).**

§7.3 inventories the application's **authentication mechanisms** — Password Login, OAuth/OIDC, TOTP/2FA, JWT Issuance, JWT Validation, Session Management, etc. The sub-blocks under §7.3 describe each *mechanism* with its control surface, its failure modes, and the threats it currently fails to prevent.

**ABSOLUTE RULE — sub-blocks describe AUTH METHODS, not ATTACKS.** Headings like "alg:none Bypass Flow", "JWT Forgery Flow", "Session Hijack Flow", "Credential Stuffing Flow" are **forbidden** in §7.3 — those are *exploitation paths* and belong in §3 Attack Walkthroughs. The contract gate (`auth_method_decomposition` in `data/sections-contract.yaml`) enforces this with a `forbidden_heading_patterns` list that hard-fails the build when an attack-shaped heading appears under §7.3. The pattern list includes `\bbypass\b`, `\bforgery\b`, `\bhijack\b`, `\battack\b`, `\bexploit\b`, `alg:none`. If you have a worthy attack story to document, place it as a new walkthrough under §3, not as a §7.3.N sub-block.

Each sub-block is a self-contained mini-report: flow introduction, sequence diagram of the **current implementation** (showing the *mechanism*, with a `Note over …` annotation at any point where a control is missing), a scoped controls table, a risk assessment, and a findings list. Apply the following rules:

1. **One `#### 7.3.N <Method Name> Flow` sub-subsection per row of the §7.3 controls table** (`Control` column). `N` is a 1-based monotonic counter in table-row order. The heading text must contain the method's distinguishing tokens verbatim so a downstream QA check (`auth_method_decomposition` in `sections-contract.yaml`) can match rows to headings via token-subset. Examples of valid pairs:

   | Controls-table `Control` row | Matching `####` heading                   |
   |---|---|
   | Password Login              | `#### 7.3.1 Password Login Flow`           |
   | Google OAuth                | `#### 7.3.2 Google OAuth 2.0 Flow`         |
   | JWT Signing                 | `#### 7.3.3 JWT Issuance & Signing Flow`   |
   | JWT Validation              | `#### 7.3.4 JWT Validation Flow`           |
   | 2FA / TOTP                  | `#### 7.3.5 TOTP / 2FA Flow`               |

   If two rows genuinely share a single flow (e.g. `JWT Signing` and `JWT Validation` are rendered as one end-to-end JWT sub-block), either **collapse the two rows into one** in the controls table OR declare a synonym override under `sections.security_architecture.domain_required_rules` in `data/sections-contract.yaml` — but do not leave a row without a sub-subsection on either side.

2. **Each `####` sub-subsection MUST contain these five elements, in this order:**

   **(a) Flow introduction (2–3 sentences).** Name the endpoint path(s), the implementation files, the cryptographic primitives / libraries in use, the token / session TTL, and the rate-limiting status. No hand-waving; every sentence carries a concrete fact the reader can verify.

   **(b) A Mermaid `sequenceDiagram`.** The diagram shows the *legitimate-user* flow as it is currently implemented — login → session/token issuance → request authorization → logout where applicable — with `Note over …` annotations at any control gap (e.g. "Note over INSEC: Private key hardcoded — see T-005"). The protagonist is the **end user**, not an attacker. Attack-path sequence diagrams (attacker forging tokens, exploiting alg:none, stealing sessions) belong in §3 Attack Walkthroughs and MUST NOT appear here.

   **(c) A controls table scoped to the flow.** Columns: `Control | Implementation | Effectiveness | Finding`. One row per control active in the flow (parameterised SQL, hashing, JWT signing, token storage, rate limiting, …). The `Finding` column cites `[T-NNN](#t-nnn) — <short title>` for each weakness present; `—` for adequate controls.

   **(d) A `**Risk assessment:**` trailer (2–4 sentences).** Summarise the worst realistic outcome, how attacker positions interact with the listed controls, and what compounding weaknesses change the picture. End with a bold `**Residual risk:** Critical|High|Medium|Low — <one-line justification>` line so reviewers can extract per-flow severity at a glance.

   **(e) A `**Findings in this flow:**` trailer.** Clickable-link list with titles, separated by `<br/>`:

   ```markdown
   **Findings in this flow:** [T-001](#t-001) — Hardcoded RSA key<br/>[T-013](#t-013) — MD5 password hashing
   ```

   When no direct findings apply to the flow, use the literal short form:

   ```markdown
   **Findings in this flow:** — none
   ```

   This is a signal, not an oversight — reviewers will read `— none` as "covered, no gaps here", whereas a missing trailer is a structural defect that fails the QA gate.

3. **Bidirectional T-ID consistency.** Every T-NNN cited in the `**Findings in this flow:**` trailer MUST also appear in the `Linked Threats` cell of the controls-table row(s) that map to this sub-subsection. If the trailer surfaces a finding that the row's Linked Threats cell does not, that is a data inconsistency — fix it by adding the T-ID to the row's cell (preferred) or removing it from the trailer if the association was spurious. Section 7.3 is the only place in the threat model where the same finding is both categorised (table cell) and walked-through (diagram), and the QA gate enforces that those two views agree.

4. **Numbering stability.** The `7.3.N` prefix is stable within one run (recompute from table order) but can shift across runs when the controls table grows. That is expected — anchor links into §7.3.N use the canonical slug (`#731-password-login-flow`) which travels with the heading text, not the number, so external cross-references survive renumbering.

**Worked example of a complete §7.3.1 block:**

```markdown
#### 7.3.1 Password Login Flow

The password login endpoint `POST /rest/user/login` is served by `routes/login.ts:37` and validates credentials against the Sequelize `Users` model. Passwords are hashed with MD5 (no salt) at `lib/insecurity.ts:47` and compared via a raw SQL `SELECT` statement with string interpolation. Successful authentication issues an RS256 JWT valid for 6 hours, signed with the hardcoded private key at `lib/insecurity.ts:23`.

\`\`\`mermaid
sequenceDiagram
    actor U as User
    participant API as Express API
    participant DB as SQLite
    U->>API: POST /rest/user/login email=x password=y
    Note over API: routes/login.ts:37 raw SQL interpolation
    API->>DB: SELECT * FROM Users WHERE email='x' AND password='md5(y)'
    Note over DB: admin'-- bypasses password check
    DB-->>API: user row
    API->>API: jwt.sign RS256 hardcoded key
    API-->>U: token in body
    Note over U: localStorage.setItem('token', jwt) — XSS-readable
\`\`\`

| Control | Implementation | Effectiveness | Finding |
|---|---|---|---|
| SQL Parameterization | Absent — raw string interpolation in `routes/login.ts:37` | ❌ Missing | [T-003](#t-003) — SQL Injection Authentication Bypass |
| Password Hashing | MD5, unsalted (`lib/insecurity.ts:47`) | ❌ Missing | [T-013](#t-013) — MD5 Weak One-Way Function |
| JWT Signing | RS256 with hardcoded private key (`lib/insecurity.ts:23`) | ❌ Missing | [T-001](#t-001) — Hardcoded RSA Key |
| Token Storage (client) | `localStorage.setItem('token', ...)` | ❌ Missing | [T-017](#t-017) — JWT in localStorage |
| Rate Limiting | None on `/rest/user/login` | ❌ Missing | [T-020](#t-020) — Brute Force Absent |

**Risk assessment:** The password login flow is the single highest-impact authentication entry point and is simultaneously the weakest. Raw SQL interpolation permits authentication bypass via `admin'--`, MD5 unsalted hashing enables offline rainbow-table cracking, and the hardcoded RSA signing key compounds these by making any forged session indistinguishable from a legitimate one. With no rate limit, credential-stuffing is free and unbounded. **Residual risk:** Critical — any unauthenticated internet user can obtain admin-level access within seconds using public payloads.

**Findings in this flow:** [T-001](#t-001) — Hardcoded RSA Key<br/>[T-002](#t-002) — alg:none JWT Bypass<br/>[T-003](#t-003) — SQL Injection Login Bypass<br/>[T-013](#t-013) — MD5 Password Hashing<br/>[T-017](#t-017) — JWT in localStorage<br/>[T-020](#t-020) — Brute Force Absent
```

Use this example as a structural template. Every §7.3.N block in your output must replicate the five elements in the same order with the same prose conventions.

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
```

**No Gap-Summary block** (post-2026-05). The prior `**Gap summary** — <intro>:` table was removed because (a) the prose paragraph form drifted into copies of the Management Summary's Top Findings, and (b) the tabular form duplicated §7.2 "Key Architectural Risks". The information now lives only in §7.1 Overview (structured bullets) and §7.2 (full risk table). The LLM MUST NOT add a Gap-Summary block in any form.

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

§8 Threat Register, §9 Mitigation Register, §10 Out of Scope and both appendices are rendered from `threat-model.yaml` + `data/breach-vector-taxonomy.yaml` by `compose_threat_model.py`. The orchestrator does **not** author a fragment for them (except `.fragments/out-of-scope.md` for §10 and, conditionally, `.fragments/compound-chains.json` + `.fragments/architectural-findings.json` under §8.C/§8.D).

#### Authoring `.fragments/architectural-findings.json` (Substep 4e)

When `critical_count + high_count ≥ 3`, scan the STRIDE outputs for cross-cutting patterns: findings that share the same CWE family across ≥2 components, or ≥3 findings pointing to the same missing architectural control (e.g. no input validation layer, no centralised auth gate, no secrets management). For each such cluster emit one AF-NNN block.

Write `.fragments/architectural-findings.json` (validated against `schemas/fragments/architectural-findings.schema.json`):

```json
{
  "intro": "<One sentence naming the count: 'N systemic architectural weaknesses were identified…'>",
  "findings": [
    {
      "id": "AF-001",
      "title": "<Architectural weakness title — ≤70 chars>",
      "description": "<2–3 sentences: what the pattern is, why it is systemic, which components are affected>",
      "contributing_findings": ["T-001", "T-003", "T-009"],
      "architectural_theme": "<e.g. 'Missing input validation layer'>",
      "remediation_approach": "<High-level architectural fix — not a patch-level step>"
    }
  ]
}
```

**Omit the file entirely** (do not write an empty `{"findings":[]}`) when zero cross-cutting patterns exist. The renderer emits the §8.G heading + fallback message when the file is absent; it skips the section entirely when `critical_count + high_count < 3`.

Also populate `architectural_findings[]` in `threat-model.yaml` with the same AF-NNN entries so cross-references in §8.B category blocks resolve correctly.

**Triage flags in Threat Register:** when `$OUTPUT_DIR/.triage-flags.json` exists, `compose_threat_model.py` already reads it and annotates each affected threat row (`⚠️ TRIAGE:` / `ℹ️ TRIAGE:`). The orchestrator does not duplicate that work.

#### Run Statistics Appendix (verbose only)

**Only emit this appendix when `VERBOSE_REPORT=true`.** When `VERBOSE_REPORT=false` (default), omit the appendix entirely — no `## Appendix: Run Statistics` heading, no tables, no ToC entry.

At the end of Part D, after Section 10 (Out of Scope), append a horizontal rule and an unnumbered appendix section. This appendix is the **single location for all run metadata** — there is no metadata table at the top of the report.

Extract per-phase durations from `$OUTPUT_DIR/.agent-run.log` by pairing `PHASE_START` and `PHASE_END` timestamps for each phase. **Prefer actual timestamps from the log.** When log-parsing succeeds, render exact `Xm YYs` / `YYs` forms. When a PHASE_START/PHASE_END pair is missing or malformed, **rounded approximate values in the form `~30s` / `~2m` / `~1m 30s` are acceptable as a fallback** — they come from the wall-clock estimates the orchestrator carries during the run. Only write `n/a` when no timing signal exists at all (neither log pairs nor wall-clock estimates). The reference output at `examples/threat-modeler/threat-model-juice-shop-thorough.md` uses the `~`-prefixed rounded form — that output format is canonical for the baseline four-subsection appendix described below.

Extract agent names and models from `AGENT_INVOKE` / `AGENT_START` lines in `.agent-run.log`. Only include agents that actually ran — omit context-resolver on cache hit, omit dep-scanner when `WITH_SCA=false`.

The `Tokens` and `Cost Estimate` tables are written entirely as `_pending_` in the extended 7-section form — they are patched by the QA reviewer's Check 12 (via `verify_run_costs.py`). The `Assessment Total`, `QA Review`, and `Grand Total` duration rows are also `_pending_` — patched by the skill layer after Stage 3 completes.

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
| Plugin Version | appsec-advisor <PLUGIN_VERSION> (analysis v<ANALYSIS_VERSION>) |
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

Only include agents that actually ran. The `qa-reviewer` row is always included with `_pending_` model — patched by the skill layer after Stage 3. The `dep-scanner` row is only included when `WITH_SCA=true`. The `context-resolver` row is only included when context resolution was not a cache hit.

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
- **Qa-reviewer row** — emitted unconditionally with the model the skill layer will use in Stage 3 (sonnet by default).

**Cost Estimate column headers:** dynamically determined from `agent_models` in the YAML — one column per unique model used. When only one model is used (no `agent_models` override), show a single value column with that model's name as header. The pricing reference table is static and always included.

**Billing label in the blockquote:** replace `_pending_` with `api` or `subscription (estimated)` — patched by QA Check 12.

**Phase Duration table rules:**

- The table MUST NOT use `<details>` collapse — the durations are always visible.
- The **Agent(s)** column is included in the extended 7-section form; in the baseline 4-section form the table collapses to `Phase | Description | Duration` (3 columns — see reference output).
- When the Agent(s) column IS rendered: for phases run inline by the orchestrator (Phases 3–8), the agent is `threat-analyst`. For dispatched sub-agents, show the sub-agent name. For Phase 9, show the count of stride-analyzer instances (e.g., `5 x stride-analyzer (opus-4-6)`).
- For phases that ran in parallel (same PHASE_START timestamp), show the wall-clock duration of the parallel group for each phase row — this makes it clear they overlapped.
- The `Assessment Total` row uses `analysis_duration_seconds` from `threat-model.yaml` (excludes permission prompt wait time). In the baseline form, the total is rendered as `**Total** | | **~<Xm YYs>**` (2-col data).
- The `QA Review` and `Grand Total` rows are filled by the skill layer after Stage 3 completes. When those signals are unavailable, omit both rows (the baseline form skips them).
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

Count stride-analyzer instances from the number of `stride-analyzer.*AGENT_INVOKE` lines. The `qa-reviewer` row is always written with `_pending_` model — it is patched by the skill layer after Stage 3 provides the QA reviewer's model.

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
  changed_lines: { insertions: <ins>, deletions: <del> }   # optional, from git diff --shortstat
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
  changed_files: <count>
  changed_lines: { insertions: <ins>, deletions: <del> }   # optional, from git diff --shortstat
  note: "full rebuild"                    # optional, see note guidance below
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
- `REBUILD=true` → `"full rebuild — prior history discarded"`
- `REBUILD` not set or `false` → `"initial assessment"`

Skip the `added`/`changed`/`resolved` blocks entirely in this case — there is nothing to diff against.

### `note` guidance — keep it terse, factual, structured-data-complementary

The changelog's structured fields (`added`, `changed`, `resolved`, `changed_files`, `changed_lines`, `added.components`, `added.attack_surface`, `reanalyzed_components`, `carried_forward_components`) already carry every delta the reader needs. The `note` field is a **canonical short marker**, not a run summary.

**Rules:**
- ≤ 12 words. One short sentence. No periods-separated prose.
- Do **not** re-summarise Added / Changed / Resolved threats — the renderer already enumerates them with links.
- Do **not** list component names, file paths, technical findings, or scope bullets in `note`.
- Prefer omitting `note` entirely when a structured delta is present and no special condition applies.

**Allowed canonical strings (use verbatim when they apply):**
- `"initial assessment"` — first run, no baseline.
- `"full rebuild — prior history discarded"` — `--rebuild` wipe.
- `"no security-relevant changes"` — incremental run where every changed file was filtered as noise-only.
- `"full rebuild"` — `--full` rerun with an existing baseline, when no other note applies. Often better to omit.

Anything longer is truncated by the renderer (`changelog.md.j2` at 100 chars, `changelog-table.md.j2` at 60 chars) and is treated as a defect by the QA reviewer.

### Capturing `changed_lines` — `git diff --shortstat`

When `BASELINE_SHA` is known, capture code-churn line counts alongside `changed_files`:

```bash
if [ -n "$BASELINE_SHA" ]; then
  SHORTSTAT=$(git -C "$REPO_ROOT" diff --shortstat "${BASELINE_SHA}..HEAD" 2>/dev/null || true)
  # Example: " 12 files changed, 340 insertions(+), 45 deletions(-)"
  INS=$(printf '%s' "$SHORTSTAT" | grep -oE '[0-9]+ insertion' | grep -oE '[0-9]+' || echo 0)
  DEL=$(printf '%s' "$SHORTSTAT" | grep -oE '[0-9]+ deletion'  | grep -oE '[0-9]+' || echo 0)
  # Emit as `changed_lines: {insertions: <INS>, deletions: <DEL>}` in the entry.
  # Omit the field entirely (do not emit `null`) if the git command failed
  # or the repo is shallow — the renderer treats absence as "no line data".
fi
```

The rendered bullet becomes `- **Changed files:** 12 (+340/-45 lines)` when both are present, and falls back to `- **Changed files:** 12` when they are not.

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

- **Changed files:** <count> (+<ins>/-<del> lines)
- **Added:** <n> threats (<first 5 T-IDs>, +<extra> more)
- **Changed:** <n> threats (<T-ID: "reason", ...first 5, +<extra> more>)
- **Resolved:** <n> threats (<T-ID: "reason", ...first 5, +<extra> more>)
- **Architecture:** +<n> components (<list>), +<n> entry points (<list E-IDs>)
- **Re-analyzed:** <component list>
- **Carried forward:** <component list>

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
- **Added / Changed / Resolved enumerate threats only** — no components, no entry points, no file paths. Component and entry-point additions appear in the separate **Architecture** bullet. This keeps each bullet readable and makes security-relevant architecture changes visible at a glance.
- **Architecture bullet** renders only when `added.components` or `added.attack_surface` is non-empty. Dropped entirely otherwise.
- **Line stats:** the `Changed files` bullet appends `(+<ins>/-<del> lines)` only when `changed_lines.insertions` and `.deletions` are both populated. Omitted otherwise — no `(+0/-0 lines)` noise on empty diffs.
- T-IDs and E-IDs are rendered as clickable internal anchors to their entries in Section 5/8.
- **Detail cap:** T-ID enumeration in `Added` / `Changed` / `Resolved` is capped at the first 5 IDs with a `, +<n> more` suffix when truncated. This keeps a full-rebuild entry with dozens of added/changed threats readable at a glance. The yaml persists the complete list — the cap applies to the markdown only. Mirrors `_sample_ids` in `scripts/render_completion_summary.py` (same 5-item cap).
- The section is `## Changelog` (level-2), matching the other top-level sections.

### Baseline Cache Update

Before the lock-release substep, refresh `$OUTPUT_DIR/.appsec-cache/baseline.json` via the `baseline_state.py` helper:

```bash
if [ "$WRITE_MODE" = "incremental" ] || [ "$WRITE_MODE" = "full" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" update \
    --output-dir "$OUTPUT_DIR" \
    --repo-root "$REPO_ROOT" \
    --mode "$WRITE_MODE"
fi
```

> **Note:** `.appsec-cache` is created by `acquire_lock.py` at assessment start — no separate `mkdir -p` needed here.

The helper reads the freshly-written `threat-model.yaml`, computes manifest/Dockerfile/IaC hashes against `$REPO_ROOT`, increments `id_counters.next_threat_id` past the highest T-ID in the yaml, and writes sha256 for every `.stride-<id>.json`. If the helper is missing (pre-M2.6 plugin), log a warning and continue — the yaml alone is sufficient baseline for the next run, just without the Phase 2 recon-skip optimization.

### Clear Checkpoint & Compute Duration (substep `N`)

This final substep releases the lock and clears the checkpoint marker. The lock was kept alive through every prior Phase 11 substep (heartbeat-refreshed) so the anti-stall classifier could monitor progress; releasing it here marks the run as cleanly complete. Batch the final STEP_START echo with the cleanup in one Bash call:

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] [<N>/<N>] Releasing lock + clearing checkpoint + printing summary…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
rm -f "$OUTPUT_DIR/.appsec-lock"
rm -f "$OUTPUT_DIR/.appsec-checkpoint"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_agent_end.py" "$OUTPUT_DIR" "threat-analyst" "<MODEL>" "$START_EPOCH"
```

> `log_agent_end.py` computes elapsed time from `START_EPOCH` and appends the `AGENT_END` line. The old `END_EPOCH=$(date +%s) && ELAPSED=... && DURATION=...` block started with variable assignments — not matchable by Claude Code allow rules. Store the formatted duration printed by `log_agent_end.py` for the `ASSESSMENT_END` line below if needed, or compute it inline via `python3 -c "import time; e=int(time.time())-$START_EPOCH; print(f'{e//60} min {e%60:02d} s')"` in a separate call.

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
| `$OUTPUT_DIR/.assessment-summary-emitted` | Phase 11 dedup marker |
| `$OUTPUT_DIR/.prior-findings-index.json` | Phase 5 → Phase 9 cross-reference cache |
| `$OUTPUT_DIR/.stage1-resume-count` | skill-level resume-loop counter (cut-off recovery) |
| `$OUTPUT_DIR/.skill-config.json` | skill resolved-config snapshot (M3.3 — was leaking on crash) |
| `$OUTPUT_DIR/.recon-patterns.json` | deterministic recon pre-pass output (M3.1 — Phase 2 input) |
| `$OUTPUT_DIR/.progress/` (directory) | per-component STRIDE substep state |

**Explicitly NOT removed by Phase 11** — the audit trail (`.threat-modeling-context.md`, `.recon-summary.md`, `.dep-scan.json`, `.stride-*.json`, `.threats-merged.json`, `.triage-flags.json`, `.architect-review.md`), the incremental cache (`.appsec-cache/`), QA/architect status files (removed later by the skill-level post-QA and post-architect cleanup — see SKILL.md → Completion Summary), the compose-input `.fragments/` directory and the pre-render gate report `.pre-render-report.json` (both removed by post-QA cleanup once QA has verified the rendered MD), and all log files (`.agent-run.log[.1.2]`, `.hook-events.log[.1.2]`).

**Cleanup call — the orchestrator MUST invoke the standalone script instead of hand-rolling Bash:**

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage pre-qa
```

The script is deterministic, idempotent, and enforces both the whitelist above and the safety gates (`KEEP_RUNTIME_FILES`, `threat-model.md` presence, absence of `AGENT_ERROR` in recent log tail). It writes one `RUNTIME_CLEANUP` line to `.agent-run.log` indicating the stage, number of paths removed, and any that were preserved with a reason.

> **Design note.** Earlier builds of the plugin asked the orchestrator to emit an inline Bash cleanup block in the same turn as its final log lines. Observed in 2026-04-21 production runs: on roughly half of incremental runs the orchestrator skipped the block because turn-budget pressure shifted attention to the primary md-compose output. Moving the logic into `runtime_cleanup.py` and calling it from the skill removes the LLM-compliance dependency — the script runs unconditionally as long as the skill reaches its Completion Summary.

**Post-QA and post-architect waves — called by the skill layer, not the orchestrator.** The QA reviewer leaves `.qa-status.json` and (when violations exist) `.qa-repair-plan.json`; the architect reviewer leaves `.architect-status.json` / `.architect-repair-plan.json`. The skill calls:

```bash
# After Stage 3 (QA reviewer) returns and the Re-Render Loop (if any) exits clean:
python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-qa

# After Stage 4 (architect reviewer) returns (only when ARCHITECT_REVIEW=true):
python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-architect
```

The post-QA wave additionally removes `.fragments/` (compose inputs). The post-architect wave removes `.architect-status.json` / `.architect-repair-plan.json` only when the latter is empty or absent — otherwise the failing plan is preserved for debugging.

**Drift guard:** the whitelist above is pinned in `tests/test_runtime_cleanup.py` (covers both the Phase 11 Bash legacy listing — for backward-compatibility with callers that bypass the script — and the three constant lists inside `scripts/runtime_cleanup.py`). Adding a new transient artifact requires updating all three locations — that is intentional.

### Print Final Summary

```
══════════════════════════════════════════════════════════════
  Assessment Summary
══════════════════════════════════════════════════════════════

  Duration       : <DURATION>  (per-phase breakdown below)
  Started (CET)  : <CET start time>
  Finished (CET) : <CET end time>
  Plugin         : appsec-advisor <PLUGIN_VERSION> (analysis v<ANALYSIS_VERSION>)
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

Canonical source: [data/breach-vector-taxonomy.yaml](../../../appsec-advisor/data/breach-vector-taxonomy.yaml). Each entry defines one attacker position / exposure class used in the Vektor column across this document. The taxonomy is deliberately coarse (7 categories) so reviewers can group findings by reachability at a glance.

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
