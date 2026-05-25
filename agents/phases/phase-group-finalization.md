# Phase Group: Output & Finalization (Phase 11)

This file is read by the orchestrator at runtime to load phase instructions.

## ⚠ MANDATORY §7 SCAFFOLD-FILL — at standard/thorough depth

At `--assessment-depth standard` or `thorough`, the Phase 11 Substep 4 fragment-authoring step **MUST fill every `<!-- NARRATIVE_PLACEHOLDER -->` comment** in `$OUTPUT_DIR/.fragments/security-architecture.md`. The pre-generator emits the scaffold structure (headings, tables, control rows); the LLM authors only the per-placeholder prose **in place** — never re-emits headings, never rewrites tables, never deletes the scaffold structure.

**Hard contract** (verified juice-shop 2026-05-25 standard-depth run failed this — every §7.4-§7.12 placeholder shipped unfilled with a `⚠ Section narrative incomplete` banner in the rendered md):

| Required action | Where | When | Quick check |
|---|---|---|---|
| Read `prose-style.md` once | `agents/shared/prose-style.md` | Substep 4 entry | one Bash `cat` call before first Write |
| Fill `**Verdict:** <icon>` for §7.2-§7.12 | each domain heading | per subsection | choose one of `🟢 Adequate` / `🟡 Partial` / `🟠 Weak` / `🔴 Unsafe` / `🔴 Missing` |
| Fill `**Implemented controls:**` | each domain heading | per subsection | positive inventory; forbidden openers: `None`, `No `, `Missing`, `Not implemented` |
| Fill `**Assessment:**` | each domain heading | per subsection | 2-4 sentences; specific defects with file:line evidence |
| Fill per-control `1-2 sentences in plain language` + `**Security assessment**` | each `#### 7.X.Y` | per control | 2-4 sentence evidence-grounded prose |

**Failure mode if skipped:** the renderer emits a `⚠ Section narrative incomplete` banner in §7 of the final report. The banner explicitly calls out "Stage-2 fill step did not author them" — visible to every reader and an embarrassment-quality signal. At quick depth this is suppressed (different banner: `ⓘ ... by design`).

**Budget check:** if `BUDGET_CRITICAL` fires before Substep 4 completes, the WRAP_UP_TRIGGERED path still REQUIRES authoring §7.1 (Overview synthesis) — the per-domain narratives are P2 (deferrable) but §7.1 is P1. Do not let the run end with §7.1 unfilled.

See "Authoring `security-architecture.md` — scaffold-fill protocol" section below for the detailed authoring rules + per-domain checklist.

## Progress visibility helper — `scripts/log_event.py`

Every `PHASE_START` / `PHASE_END` / `STEP_START` / `STEP_END` echo in this phase group **MUST** go through `scripts/log_event.py` rather than a raw `echo … >> .agent-run.log` call. The helper:

1. Writes the canonical log entry to `$OUTPUT_DIR/.agent-run.log` (same format as the legacy raw echo — downstream parsers are unchanged).
2. Mirrors a compact one-line summary to **stderr** with an auto-computed elapsed-time prefix (e.g. `↳ (+2m15s) Phase 11/11 · step 4/7 · Writing fragments…`), so the user sees phase/step progress in the Bash tool card even without `--verbose`.
3. Updates `$OUTPUT_DIR/.appsec-progress.json` with the latest phase, step, agent, and label for `/appsec-advisor:status --live` and `scripts/watch_run.py`.

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

- `meta:` — `schema_version: 1`, `commit_sha:` (current HEAD), `baseline_ref:` (prior commit_sha or null), `run_statistics:` (written null, populated by the `render_completion_summary.py --patch-placeholders` call after QA — see RC-3 note below), `repo_url:` (**MUST** be set to `git remote get-url origin` output, or left null only when no remote exists — this populates the Repository field in §1 System Overview).
- `changelog:` — **append-only**, newest first. Every entry carries `version:`, `baseline_sha:`, `current_sha:`, and the three delta sub-blocks `added:` / `changed:` / `resolved:`.
- `components:` — list of components with `paths:` (globs — source of truth for Phase 9 dirty-set) and `threat_ids:` (quick-lookup list). Every component **MUST** carry a `tier:` field set to one of `client` / `application` / `data`. The renderer uses this to populate the three-tier heatmap; without it the tier is inferred from keywords and may mis-classify. At least one component with `tier: data` is required whenever the application uses a database, cache, or file store — do not subsume data-layer threats into the `application` component.
- `attack_surface:` — composed by `build_threat_model_yaml.py` from `$OUTPUT_DIR/.attack-surface-overrides.json` (Phase 6 sidecar) overlaid on the Python-derived baseline. If Phase 6 wrote no sidecar, the builder hard-fails with `MISSING SIDECAR`. A missing or empty `attack_surface:` causes schema validation to fail (`INVALID: root: 'attack_surface' is a required property`) and renders §5 Attack Surface with "(0)" counts.
- `trust_boundaries:` — composed from `$OUTPUT_DIR/.trust-boundaries.json` (Phase 7 sidecar). Builder hard-fails if the sidecar is absent. A missing or empty `trust_boundaries:` causes schema validation to fail.
- `security_controls:` — composed from `$OUTPUT_DIR/.security-controls.json` (Phase 8 sidecar). Builder hard-fails if the sidecar is absent. A missing or empty `security_controls:` causes schema validation to fail and renders §7 Operational Strengths empty and layer tables §2.4.1–2.4.4 empty.
- `tier_root_causes:` — **mandatory when ≥1 threat exists** (else omit). Per-architectural-tier root-cause bullets shown in the `Security Posture at a Glance` heatmap. Three keys: `client:`, `application:` (alias `server`), `data:`. Each is a list of 1–5 strings, **max 80 characters each**, expressing the architectural defect in plain language (e.g. `"missing input neutralization on raw SQL paths"`, `"hardcoded crypto secrets in source"`, `"no auth middleware on management endpoints"`). Derive from the threats grouped by their component's tier — each bullet should aggregate ≥2 findings sharing a root-cause class. **Skip a tier entirely** (omit the key) if it has no threats; **never emit empty arrays** — the renderer's fallback "(no root causes documented)" is only meaningful when the field is genuinely missing for an entire run, not for an individual tier.

**Hard invariants** (enforced by baseline_state.py and by incremental logic in Phase 9):

1. `meta.schema_version` is 1. Bump it only alongside a migration path.
2. T-IDs, M-IDs, and E-IDs are **stable across runs**. A carried-forward component must keep every one of its T-IDs. New IDs come from `.appsec-cache/baseline.json.id_counters`.
3. `changelog[]` is **append-only**. Never rewrite or delete historical entries, even on a full rebuild — instead, prepend a new `mode: full` entry.
4. `components[].paths` is the source of truth for the Phase 9 dirty-set mapping. Keep it in sync with the actual directory layout.
5. `meta.git.commit_sha` MUST be set to `git rev-parse HEAD` at the end of Phase 11, on every write. This is what the next run uses as baseline.
5a. `meta.repo_url` MUST be set to `$(git remote get-url origin 2>/dev/null || true)` at the end of Phase 11. A missing `repo_url` causes §1 System Overview to render `_n/a_` for the Repository field.
6. `meta.plugin_version` and `meta.analysis_version` MUST be read from `$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json` via `plugin_meta.py get` — never hardcoded. Every new `changelog[]` entry carries the same pair that was active at the time of that run, so a user can later reconstruct which analysis version produced which threats.
7. `meta.recommend_full_rerun` is set to `true` iff the prior baseline's `analysis_version` was older than the current one but still in `compatible_analysis_versions` (i.e. `plugin_meta.py check-compat` returned exit 10). It is set to `false` on full runs and on equal-version incremental runs.

The renderer (`render_threat_model.py`) does not know or care about this schema — the yaml is composed by `scripts/build_threat_model_yaml.py` (deterministic Python builder, since 2026-05-24 cutover) from `.threats-merged.json` + 7 sidecar JSON files and written atomically in Phase 11 Substep 2. The schema lives here as the authoritative contract.

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

# Classify depth drift relative to the prior run. Only meaningful for
# incremental mode; on first runs and full rebuilds DEPTH_DOWNGRADE stays
# false because there is no comparable prior depth on disk.
#
# Why this matters: quick mode applies QUICK_STRIDE_PROFILE
# (max_threats_per_category=2, skip_verification_greps, turn_budget_hard_cap=25
# — see scripts/resolve_config.py). When the prior run was at a higher
# depth, fewer threats per category may surface in this run; baseline T-IDs
# that were genuinely present can land in the changelog `resolved` block as
# "not reproduced on full re-analysis" even though the underlying code is
# unchanged. The header callout below makes that risk visible to the user
# instead of silently dropping findings into Resolved.
DEPTH_DOWNGRADE=false
PRIOR_RUN_DEPTH=""
if [ "$WRITE_MODE" = "incremental" ] && [ -f "$OUTPUT_DIR/.appsec-cache/baseline.json" ]; then
  PRIOR_RUN_DEPTH=$(python3 -c "import json,sys;
try:
    print((json.load(open('$OUTPUT_DIR/.appsec-cache/baseline.json')).get('last_run_depth') or '').strip().lower())
except Exception:
    print('')" 2>/dev/null)
  CUR_DEPTH=$(printf '%s' "${ASSESSMENT_DEPTH:-standard}" | tr '[:upper:]' '[:lower:]')
  _depth_rank() {
    case "$1" in
      quick)    echo 1 ;;
      standard) echo 2 ;;
      thorough) echo 3 ;;
      *)        echo 0 ;;
    esac
  }
  PRIOR_RANK=$(_depth_rank "$PRIOR_RUN_DEPTH")
  CUR_RANK=$(_depth_rank "$CUR_DEPTH")
  if [ -n "$PRIOR_RUN_DEPTH" ] && [ "$PRIOR_RANK" -gt 0 ] && [ "$CUR_RANK" -gt 0 ] && [ "$CUR_RANK" -lt "$PRIOR_RANK" ]; then
    DEPTH_DOWNGRADE=true
  fi
fi

echo "PLUGIN_META: plugin_version=$PLUGIN_VERSION analysis_version=$ANALYSIS_VERSION recommend_full=$RECOMMEND_FULL prior=$PRIOR_ANALYSIS_VERSION depth_downgrade=$DEPTH_DOWNGRADE prior_depth=$PRIOR_RUN_DEPTH"
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

**Rendering the depth-downgrade callout in `threat-model.md`:** when `DEPTH_DOWNGRADE=true` AND `WRITE_MODE=incremental`, emit the following block directly below the baseline-older callout (or directly under the header metadata table when the baseline-older callout is omitted). Both callouts may co-exist — they describe independent risks (analysis-version drift vs. assessment-depth drift) and the user needs both signals.

```markdown
> ⚠ **Assessment depth downgraded from `<PRIOR_RUN_DEPTH>` to `<ASSESSMENT_DEPTH>`**
>
> The previous run analysed at `--assessment-depth <PRIOR_RUN_DEPTH>`; this run uses `--assessment-depth <ASSESSMENT_DEPTH>`.
> Quick / standard depth profiles cap STRIDE output per category and skip verification greps, so a finding that was reproduced at `<PRIOR_RUN_DEPTH>` depth may be absent from this run's STRIDE output without the underlying code being fixed.
> Entries in the `Resolved` changelog block carrying `reason: "not reproduced on full re-analysis"` are therefore **not a confirmed remediation** — they reflect absence in the new STRIDE pass, not verified absence of the vulnerability.
> **Recommendation:** re-run with `--assessment-depth <PRIOR_RUN_DEPTH>` (or `--full`) before treating any newly-resolved finding as fixed.
```

Omit the callout entirely when `DEPTH_DOWNGRADE=false`.

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
| 2 | `Writing threat-model.yaml (canonical baseline)…` | **always — skip ONLY when `WRITE_YAML=false` (user passed `--no-yaml`).** Yaml is the canonical baseline for future incremental runs; skipping it by default breaks the incremental pipeline. | **Single Bash call** to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_threat_model_yaml.py" "$OUTPUT_DIR"` (deterministic builder — since Substep-2 cutover 2026-05-24, see "Substep 2" below). **⚠ This MUST run before the md write.** The builder reads `.threats-merged.json` + 7 sidecars, writes the yaml atomically, and self-validates. Immediately after the Bash exits 0, advance the checkpoint: `echo 'CHECKPOINT phase=11 step=2 status=yaml_written' > "$OUTPUT_DIR/.appsec-checkpoint"`. |
| 3 | `Updating .appsec-cache/baseline.json…` | always | the Bash call that invokes `baseline_state.py update` — see "Baseline Cache Update" below. This runs here (right after yaml) rather than at the end so the cache is consistent with the yaml even if later md composition fails. |
| 4 | `Writing data fragments for threat-model.md…` | always | Bash STEP_START + several `Write` tool calls (one per LLM-authored fragment) — see "Fragment-driven composition" below. The LLM emits schema-validated JSON data for the Verdict / Architecture Assessment / Critical Attack Chain sections and prose Markdown for the handful of prose-only sections. Advance checkpoint to `step=4 status=fragments_written` only after `validate_fragment.py` accepts every data fragment. |
| 4b | `Pre-render fragment gate…` | always | Bash call to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_fragment.py" pre-render-gate "$OUTPUT_DIR"`. Runs immediately after all fragment Writes and before compose. Validates every known JSON fragment in `.fragments/` in one shot, writes `.pre-render-report.json`, and exits 1 if any schema check fails — preventing a structurally broken document from being committed to the repo. See example Bash block below. |
| 5 | `Rendering threat-model.md (contract-driven composition)…` | always | Bash call to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" --output-dir "$OUTPUT_DIR"`. The renderer is deterministic — identical fragments produce byte-identical output. No Markdown is ever written by the LLM in this step. Advance checkpoint to `step=5 status=md_rendered`. |
| 6 | `Running QA structural checks…` | always | **Single Bash call** to `python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" all "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT"`. Advance checkpoint to `step=6 status=qa_clean`. **Sprint 1C (M3.5) — strictly deterministic.** This step is one Bash invocation only. Do **NOT** read its JSON output, do **NOT** spawn fragment Writes mid-step, do **NOT** invoke `compose_threat_model.py` again. Any required repair is owned by the **skill-layer Re-Render Loop** that runs *after* Phase 11 returns; mixing repair into Step 6 burns LLM turns (the 2026-04-27 run lost 4m 41s here because the orchestrator interpreted Step 6 output as a signal to rewrite `security-posture-attack-paths.json` mid-step, instead of letting the skill manage the repair plan). If `qa_checks.py all` exits non-zero, log the exit code and proceed to Step 7 — the contract-gate downstream of Stage 2 will pick up any drift via `.qa-repair-plan.json`. **RC.B — do NOT invoke `render_completion_summary.py --patch-placeholders` here.** The agent cannot observe its own duration/tokens (only available post-Agent-return). The skill-level final `--patch-placeholders` call (after every stage has written to `.stage-stats.jsonl`) is the authoritative patch point. Patching here produces a Run Statistics appendix that under-reports total wall-clock and skips Stage 2/3 rows. |
| 7 *or* 8 | `Generating SARIF export (<n> results) and writing threat-model.sarif.json…` (substitute `<n>`) | only if `WRITE_SARIF=true` | the Bash call that invokes `scripts/export_sarif.py` — see "SARIF Export" below. The LLM does NOT author SARIF; the exporter derives it deterministically from `threat-model.yaml`. |
| 8 *or* 9 | `Generating pentest tasks (<n> eligible threats) and writing pentest-tasks.yaml…` (substitute `<n>`) | only if `WRITE_PENTEST_TASKS=true` | the Bash call that invokes `render_pentest_tasks.py` — see "Pentest-Task Export" below. The `<n>` counter reports only the threats that passed the eligibility filter, not the full threat-register size. |
| N | `Releasing lock + clearing checkpoint + printing summary…` | always, LAST | the final cleanup Bash block — `rm -f "$OUTPUT_DIR/.appsec-lock"`, `rm -f "$OUTPUT_DIR/.appsec-checkpoint"`, and the assessment summary print. This is the ONLY lock-release site in the happy path; a mid-Phase-11 crash leaves the lock in place with a stale heartbeat so the next run's `acquire_lock.py` classifies it as `hung` and reaps it. |

### SARIF Export

When `WRITE_SARIF=true`, emit `$OUTPUT_DIR/threat-model.sarif.json` *after* `threat-model.yaml` is on disk and before the pentest export. SARIF is generated by deterministic Python — the LLM never authors SARIF directly. The exporter reads `threat-model.yaml` (single source of truth), maps each threat to a SARIF rule + result, and writes `threat-model.sarif.json` in SARIF v2.1.0 shape. Field semantics (helpUri fallback, CVSS propagation, location omission for evidence-less threats, risk→level mapping) live in `scripts/export_sarif.py`.

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] [<k>/<N>] Generating SARIF export and writing threat-model.sarif.json…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_sarif.py" \
  --threat-model "$OUTPUT_DIR/threat-model.yaml" \
  --output       "$OUTPUT_DIR/threat-model.sarif.json"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  FILE_WRITE   $OUTPUT_DIR/threat-model.sarif.json" >> "$OUTPUT_DIR/.agent-run.log"
```

**Why deterministic Python:** The previous LLM-authored SARIF path produced ~5–15 KB of output tokens per run and could drift from the yaml's threat register (e.g., dropped helpUris, inconsistent CVSS propagation). Migrating to `export_sarif.py` (introduced 2026-05) eliminates both costs. The helper is unit-tested in `tests/test_export_sarif.py` against the structural SARIF validator in `tests/test_sarif_validation.py`.

**Required yaml fields:** `threats[].id` (T-NNN), `stride`, `title`, `scenario`, `risk`, `likelihood`, `impact`, and `source` (mandatory — see invariant #6 in `agents/appsec-threat-analyst.md`). Optional: `cwe`, `evidence[]`, `mitigation_ids`, `remediation_reference`, `cvss_v4`. A missing `evidence[]` produces a SARIF result without `locations`; a missing `cvss_v4` omits the `security-severity` property and falls back to the qualitative `level`.

### Pentest-Task Export

When `WRITE_PENTEST_TASKS=true`, emit `$OUTPUT_DIR/pentest-tasks.yaml` *after* the SARIF export (or after the md write if SARIF is off) by calling the dedicated renderer. The orchestrator does NOT compose this file in-prompt — the exporter is deterministic Python. It emits concrete finding-verification tasks with the CWE eligibility logic aligned to Phase 10b, then enriches the output from `threat-model.yaml` with the `attack_surface[]` endpoint catalog and architecture-driven probes from weak/missing/partial `security_controls[]`.

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

**Substep 2 — build threat-model.yaml deterministically (MUST run before md write):**

⚠ **Cutover 2026-05-24 — Substep 2 is now a single Bash call, NOT an LLM Write.** The historical 130-line LLM-yaml-composition protocol (compose in memory → narrate → Write 40 KB) burned 13 k output tokens per run and produced silent `YAML_INVARIANT_DRIFT` warnings (stride/title/evidence rewrites). It has been replaced by `scripts/build_threat_model_yaml.py`, a deterministic Python builder that reads on-disk artifacts (`.threats-merged.json` + 7 sidecars) and composes the yaml in <100 ms.

**Required upstream artifacts** — the builder hard-fails if any are missing:

| Artifact | Producer | Reads into |
|----------|----------|------------|
| `$OUTPUT_DIR/.threats-merged.json` | Phase 10b | `threats[]`, `mitigations[]` baseline |
| `$OUTPUT_DIR/.components.json` (sidecar) | Phase 3 | `components[]` with `tier` |
| `$OUTPUT_DIR/.assets.json` (sidecar) | Phase 5 | `assets[]` |
| `$OUTPUT_DIR/.trust-boundaries.json` (sidecar) | Phase 7 | `trust_boundaries[]` |
| `$OUTPUT_DIR/.security-controls.json` (sidecar) | Phase 8 | `security_controls[]` |
| `$OUTPUT_DIR/.attack-surface-overrides.json` (sidecar) | Phase 6 | `attack_surface[]` (Python baseline + curations/additions overlay) |
| `$OUTPUT_DIR/.mitigation-overrides.json` (sidecar) | Phase 10b | `mitigations[]` splits/additions overlay |
| `$OUTPUT_DIR/.tier-root-causes.json` (sidecar) | Phase 10b | `tier_root_causes` |

**Substep 2 Bash block (template):**

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" --heartbeat 2>/dev/null || true
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" step-start "[Phase 11 +<ES>] [2/<N>] Writing threat-model.yaml (canonical baseline)…"

# Deterministic yaml build. Reads sidecars + .threats-merged.json,
# writes $OUTPUT_DIR/threat-model.yaml atomically. Exits non-zero on:
#   - missing required sidecar
#   - schema validation failure
#   - orphan T-ID / M-ID cross-ref
python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_threat_model_yaml.py" "$OUTPUT_DIR" 2>&1 | tee -a "$OUTPUT_DIR/.agent-run.log"
BUILD_RC=${PIPESTATUS[0]}
if [ "$BUILD_RC" -ne 0 ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  ERROR  threat-analyst  YAML_BUILD_FAILED  build_threat_model_yaml.py exit=$BUILD_RC — see lines above for missing sidecar / schema failure / orphan ID." >> "$OUTPUT_DIR/.agent-run.log"
  exit 1
fi

echo 'CHECKPOINT phase=11 step=2 status=yaml_written' > "$OUTPUT_DIR/.appsec-checkpoint"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  FILE_WRITE   $OUTPUT_DIR/threat-model.yaml" >> "$OUTPUT_DIR/.agent-run.log"

# Defense-in-depth: re-validate after write. The builder validates internally,
# but a hard external re-check catches any future builder regressions and
# anchors the same gate the legacy LLM-write path used.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py" \
  threat_model_output "$OUTPUT_DIR/threat-model.yaml" \
  | tee -a "$OUTPUT_DIR/.agent-run.log"
VALIDATE_RC=${PIPESTATUS[0]}
if [ "$VALIDATE_RC" -ne 0 ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  ERROR  threat-analyst  YAML_INVALID  threat-model.yaml failed schema validation after deterministic build — builder regression, file a bug." >> "$OUTPUT_DIR/.agent-run.log"
  exit 1
fi
```

**No LLM narration in Substep 2.** The next action after STEP_START [2/N] is the Bash block above. Do not compose yaml in chat, do not describe what fields go where — the Python builder owns the entire composition.

**If the builder fails:** Read its stderr line (logged via `tee` into `.agent-run.log`). The 3 common failure modes:
- **`MISSING SIDECAR <path>`** — a phase did not write its sidecar. Re-read the phase's sidecar instructions in `phase-group-architecture.md` (Phases 3/5/6/7/8) or `phase-group-threats.md` (Phase 10b).
- **`ORPHAN_TID <T-NNN>` / `ORPHAN_MID <M-NNN>`** — a sidecar references an ID that does not exist in baseline. Fix the sidecar.
- **`SCHEMA_FAIL <field>: <reason>`** — a sidecar violates its schema. Fix the offending field.

Do NOT hand-write the yaml as a fallback — the LLM-write path is removed for cause (token burn + silent invariant drift).

<!-- LEGACY LLM-WRITE PROTOCOL — REMOVED 2026-05-24 (Substep-2 cutover).
     130 lines of compose-in-memory / verbatim-copy / F-NNN-reflow / mitigation-synthesis /
     priority-P1-P4-invariant guidance lived here. All of it is now enforced inside
     scripts/build_threat_model_yaml.py (deterministic Python). If you are debugging
     a yaml-build failure, read the script — do NOT reintroduce LLM yaml composition. -->

**Substep 3 — update baseline cache:**

Run the `baseline_state.py update` block from the "Baseline Cache Update" section below, batched with a `[3/<N>] Updating .appsec-cache/baseline.json…` STEP_START echo. The cache is now consistent with the yaml even if md composition later fails. Advance checkpoint to `step=3 status=cache_updated`.

**Substeps 4–6 — Contract-driven fragment composition (since M2.8)**

⚠ **Major architectural change — the LLM no longer writes `threat-model.md` directly.** Instead, the orchestrator writes schema-validated data fragments and short prose-Markdown fragments into `$OUTPUT_DIR/.fragments/`, then invokes the deterministic `compose_threat_model.py` renderer to produce the final Markdown. This eliminates the recurring structural-drift failure mode where the LLM invented its own Management Summary layout, dropped the Verdict blockquote, renamed Top Findings to "Top Threats", or numbered sub-sections `1.1 … 1.5`.

**Prose-style anchor — load before authoring any prose fragment.** Every `opening`/`closing`/`bullets[].body` in `ms-verdict.json`, every `verdict_prose`/`framing`/`defects[].description` in `ms-architecture-assessment.json`, and every prose-Markdown fragment under `.fragments/` (system-overview, architecture-diagrams captions, attack-walkthroughs intros, security-architecture domain text, NARRATIVE_PLACEHOLDER replacements) is read by software engineers and architects in the rendered report. Read **both** the rules file and the worked-examples file once at the start of substep 4, before the first fragment Write:

```bash
cat "$CLAUDE_PLUGIN_ROOT/agents/shared/prose-style.md"
cat "$CLAUDE_PLUGIN_ROOT/agents/shared/prose-samples.md"
```

Apply the five rules (specificity, falsifiability, information-density, scannable structure, no boilerplate) to every prose field, and **imitate the AFTER shape of the Before/After pairs** in `prose-samples.md` — Sonnet follows worked examples more reliably than abstract rules. The banned-vocabulary list in `prose-samples.md` is forbidden in every prose field you author (`leverage`, `robust`, `comprehensive`, `holistic`, `seamless`, `crucial`, `ensure`, `facilitate`, `several` without a number, `furthermore`/`moreover`/`additionally`, meta-floskeln like `it is worth noting`, AI-end-cadences like `X is Y across the Z`).

Run the five-question pre-write self-check from `prose-samples.md` before saving each prose fragment. The QA reviewer rejects fragments whose prose reads as generic rhetoric or restates table content. A measure that shortens prose at the cost of information is **not** an improvement — keep facts, drop filler.

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
| System Overview (§1) | `.fragments/system-overview.md` | **DETERMINISTIC ONLY (P2 — A4).** The skill force-regenerates this fragment from `threat-model.yaml` via `pregenerate_fragments.py --force --only system-overview.md`. Phase 11 substep 4 MUST NOT write to this path — any LLM-authored content will be overwritten by the canonical version before Stage 2 dispatches. | Heading-match validation, inlined verbatim. |
| Architecture Diagrams (§2) | `.fragments/architecture-diagrams.md` | **DETERMINISTIC ONLY (P2 — A4).** The skill force-regenerates this fragment from `threat-model.yaml` via the pre-generator. Phase 11 substep 4 MUST NOT write to this path. The pre-generator emits all required mermaid blocks (System Context, Container Architecture, Components, Technology Architecture) using the canonical audit palette and FontAwesome icons — keeping the prompt out of node-label authoring eliminates the historical drift modes (`\n` literal labels, missing classDefs, incorrect subgraph sets, oversized labels). | Required-subsection + required-pattern validation. |
| Attack Walkthroughs (§3) | `.fragments/attack-walkthroughs.md` | Plain Markdown with at least one `sequenceDiagram` per Critical finding. **§3.1 intro paragraph** must explicitly note that *§3 documents the Critical findings as sequence diagrams; all findings are tabularly documented in §8*. **Heading format (HARD RULE):** `### 3.X {ShortTitle}` where `{ShortTitle}` is **2–6 words, ≤60 characters, and matches the `title` field of the corresponding F-NNN in `threat-model.yaml`**. The F-NNN appears once in a `**Source:** [F-NNN](#f-nnn)` line below the heading, not three times across heading/diagram-title/bullet. <br>**Good:** `### 3.4 Stored XSS in Feedback` (28 chars). <br>**Bad:** `### 3.4 T-003 — Stored XSS in Feedback Leading to Admin Account Takeover` (72 chars — includes obsolete T-NNN prefix AND the full sentence form of the title). <br>**Anchor convention:** chain anchors MUST be on a separate line above the heading using the canonical CC-NN slug (`<a id="cc-1"></a>\n#### CC-1 — Title`), NOT `chain-N` and NOT inline. Inline `<a>` tags break right-side TOC outline panels in many markdown viewers. **Headings > 100 characters trip `qa_checks.py:check_heading_hygiene` and force a Re-Render Loop iteration.** <br>**T-NNN labels in chain `graph LR` blocks (P2 — A2):** When a node label contains a `T-NNN` reference, the keyword text MUST share at least one meaningful word with the `title` field of that finding in `threat-model.yaml`. Mismatches (e.g. labeling `T-001` as "SQL injection" when T-001 is actually the RSA-key finding) are flagged by `qa_checks.py chain_tid_consistency` and trigger a Re-Render Loop iteration. <br>**FontAwesome convention (post-2026-05):** in every `sequenceDiagram` block, declare human actors with the `actor` keyword and a `fa:` icon: `actor ATK as fa:fa-user-secret Attacker` (adversaries) or `actor U as fa:fa-user Customer` (victims/legitimate users). System participants carry a role-matching icon: `fa:fa-server` for backends, `fa:fa-database` for data stores, `fa:fa-shield-halved` for auth middleware, `fa:fa-code-branch` for source repos, `fa:fa-cogs` for compute/runtime, `fa:fa-google` for Google IdP. The `### 3.1 Attack Chain Overview` `graph LR` blocks use the audit palette (`classDef risk fill:#f3dada,stroke:#b71c1c,color:#7f0000,stroke-width:2px` and `classDef impact fill:#0f172a,stroke:#000,color:#fff,stroke-width:2px`) and FA-icon-prefixed node labels. **Forbidden palettes:** the legacy `#FFB6C1` Pastellrosa, `#FFE0B2` Pastellorange, and `#C8E6C9` Pastellgrün from the C4 cookbook do not pass audit/print muster — replace with the audit equivalents above. | Required-pattern validation + heading-length gate + chain T-ID consistency. |
| Assets (§4) | `.fragments/assets.md` | **DETERMINISTIC ONLY (P2 — A4).** The skill force-regenerates this fragment from `threat-model.yaml → assets[]` (5-column table with A-NNN IDs). Phase 11 substep 4 MUST NOT write to this path. | Required-pattern validation. |
| Attack Surface (§5) | `.fragments/attack-surface.md` | **DETERMINISTIC ONLY (P2 — A4).** The skill force-regenerates this fragment from `threat-model.yaml → attack_surface[]`. Phase 11 substep 4 MUST NOT write to this path. | Required-subsection validation. |
| Security Architecture (§7) | `.fragments/security-architecture.md` | **SCAFFOLD-FILL (P2 — A4 + A5).** The pre-generator writes a structural scaffold with `<!-- NARRATIVE_PLACEHOLDER -->` comments. Phase 11 substep 4 / Stage 2 LLM **fills only the placeholders in place** — never replaces the scaffold structure, never re-emits headings or tables. **At quick depth, §7.4-§7.12 placeholders are stripped by the pre-generator** so the LLM has no expansion bait there; the agent fills only §7.1, §7.2, §7.3 (with per-auth-method flow blocks), §7.13, §7.14. | Heading-match validation. |
| Threat Register (§8) | — | (no fragment — derived from `threat-model.yaml → threats[]`) | Risk Distribution + STRIDE Coverage lines, 8.1–8.4 sub-tables with 9-column schema, ID anchors. |
| Mitigation Register (§9) | — | (no fragment — derived from `threat-model.yaml → mitigations[]`) | P1–P4 sub-sections, per-mitigation heading with anchor, **Addresses / Priority / Severity / Effort / Why / How / Verification** block. |
| Out of Scope (§10) | `.fragments/out-of-scope.md` | **DETERMINISTIC ONLY (P2 — A4).** The skill force-regenerates this fragment from `threat-model.yaml → out_of_scope[]`. Phase 11 substep 4 MUST NOT write to this path. | Heading-match validation. |
| Appendix: Run Statistics | — | (no fragment — derived from `threat-model.yaml → meta.run_statistics`) | Deterministic tables, only rendered when `verbose_report=true`. |
| Appendix A: Vektor Taxonomy | — | (no fragment — derived from `data/breach-vector-taxonomy.yaml`) | Fixed `<a id="vektor-…">` anchor per vektor. |

### Authoring `ms-architecture-assessment.json`

Do not invent architectural defects from prose intuition alone. Select the 3–6 `defects[]` rows from the highest-signal structured inputs, in this order:

1. `threat-model.yaml → threats[]` clusters keyed by `architectural_theme`. Pick themes with the largest count of High/Critical findings.
2. `threat-model.yaml → security_controls[]` entries rated `Missing`, `Weak`, or `Partial` that mitigate High/Critical findings.
3. `.triage-flags.json` / Top Findings clusters where several High/Critical findings share the same CWE family, `finding_type_id`, component boundary, or missing control.

Each defect row must name the design property, not the symptom list. Good row names: `Secrets in source code`, `Missing authorization boundary`, `No centralized input-validation layer`. Bad row names: `Several security issues`, `Critical vulnerabilities found`.

Keep the Management Summary compact:
- `description` is one sentence.
- `findings[]` contains the representative F-NNN/T-NNN references that prove the defect.
- Do not repeat table data in `verdict_prose` or `framing`.

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

   **⚠⚠ HARD WHITELIST — `fragments_to_rewrite` is binding (not advisory):**

   The 2026-05-01 and 2026-05-04 juice-shop runs both demonstrated that the agent treats the "edit only" instruction as advisory and edits other fragments anyway when its initial fix does not converge. This burns 7-9 minutes of wall-clock per Stage 2 and risks API stream timeouts (12+ min silent reasoning loops). The constraint is now stated as an enforceable rule, not a suggestion:

   - **MUST edit only the path(s) listed in `actions[0].fragments_to_rewrite`.**
   - **MUST NOT edit any of these fragments unless they appear in the whitelist:**
     `ms-verdict.json`, `ms-architecture-assessment.json`, `attack-walkthroughs.md`, `security-posture-attack-paths.json`, `security-architecture.md`, `critical-attack-chain.json`, `compound-chains.json`, `operational-strengths-overrides.json`.
   - **HARD BAN (P2 — A4):** `system-overview.md`, `architecture-diagrams.md`, `assets.md`, `attack-surface.md`, `out-of-scope.md` are **deterministic-only** and re-generated by the skill from `threat-model.yaml` *after* Phase 11 returns. Any LLM Write to these paths is silently overwritten — do not waste turns on them. If a repair plan names one of these as a target, that is a stale plan; the underlying fix lives in `threat-model.yaml` (regenerate the yaml, then the skill's pre-generator pass produces a clean fragment).
   - **MUST emit a `STEP_START` log line per repair iteration** (single Bash echo to `.agent-run.log` with the iteration counter and the listed fragment path). This keeps the API stream alive during the fix attempt and gives downstream diagnostics a trail. Without this, multi-minute silent edits trigger Anthropic's no-output-token timeout (the 2026-05-01 stream-kill root cause).
   - **MUST stop after 3 attempts per fragment** (compose `RC=4` indicates the per-fragment budget is exhausted). Do NOT retry a 4th time — escalate to the skill-level Re-Render Loop per the exit-code contract below.

   **Forbidden in repair-iteration mode:** opening `ms-verdict.json` or `ms-architecture-assessment.json` to "improve wording" while the actual repair plan flagged a different fragment. The repair plan's `fragments_to_rewrite` is the **only** thing you may edit until compose succeeds. Drift from this rule is a release-blocking violation flagged by `tests/test_pre_render_repair_scope.py` (drift-guard).

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

   **§7 Security Architecture drift pattern (most common).** The current v2 contract requires the 13 control-category subsections from `### 7.1 Security Control Overview` through `### 7.13 Defense-in-Depth Summary`. Do not repair by restoring the legacy 14-section layout or the retired 21-section intermediate layout. When no WebSocket / real-time / AI / GraphQL / gRPC surface exists, keep the `### 7.12 Real-time and Not Applicable Controls` section and record the absent domains there.

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
2. `### Top Findings` — table with 7 columns: `#` (rank), `Criticality` (🔴/🟠), `Finding` (F-NNN link + short title), `Component` (C-NN link + name, or literal `Architecture` for architecture-derived findings), `Threat` (TH-NN link + category), `Vektor` (linked to Appendix A), `Primary Mitigations` (M-NNN links — each followed by short action and trailing priority token `(P1)`/`(P2)`/…). Include ALL Critical findings and top High findings (up to 15–20 rows total). Legend line after table.
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
- `.fragments/security-architecture.md` — §7 Security Architecture, must contain the v2 13-section control-category layout (`### 7.1 Security Control Overview` … `### 7.13 Defense-in-Depth Summary`). Section 6 is intentionally absent (former Trust Boundaries — gap preserved for external link stability).
- `.fragments/requirements-compliance.md` — §7b Requirements Compliance, only when `CHECK_REQUIREMENTS=true`.

The renderer concatenates them in the order declared by `document.order`. The rules below describe how those fragments must be composed; they apply to fragment authoring only.

### Authoring `security-architecture.md` — scaffold-fill protocol

The pre-generator (`pregenerate_fragments.py`) writes a **structural scaffold** into `.fragments/security-architecture.md` before Phase 11 starts. The scaffold contains:

- All 13 required v2 sub-section headings from `data/sections-contract.yaml → security_architecture.schema_v2.required_subsections`.
- A `### 7.1 Security Control Overview` table with exactly `Control category | Verdict | Main reason` columns.
- Section-level labels for §7.2-§7.12: `**Verdict:**`, `**Controls covered:**`, `**Implemented controls:**`, `**Assessment:**`.
- One or more H4 subcontrol blocks per §7.2-§7.12 section. Every H4 block must contain `**Security assessment**` and `**Relevant findings**`.
- HTML comment placeholders the LLM replaces with evidence-grounded prose. Do not leave `<!-- NARRATIVE_PLACEHOLDER` tokens in the final fragment.

**Step-by-step authoring protocol for substep 4 (security-architecture.md):**

1. **Read the scaffold:**
   ```bash
   cat "$OUTPUT_DIR/.fragments/security-architecture.md"
   ```
   Do NOT start from a blank file — the scaffold contains machine-verified data (control IDs, finding IDs, CWE refs) that must be preserved.

2. **Do NOT add a `**Gap summary:**` block** (neither prose paragraph nor table). The overview table and §7.13 summary carry the architecture-level signal.

3. **Fill section-level labels in §7.2-§7.12.** Keep the exact labels. `**Controls covered:**` must be a comma-separated list of markdown links whose visible text exactly matches an H4 subcontrol heading in that section.

4. **Fill each H4 subcontrol.** `**Security assessment**` names the concrete code paths, libraries, routes, storage locations, or runtime settings that implement or weaken the control. `**Relevant findings**` is a bullet list of `[F-NNN](#f-nnn)` links, or `- No dedicated finding routed in this assessment.` when no finding maps directly.

5. **Use sequence diagrams only where they clarify a positive control flow.** Login, TOTP, JWT issuance, password reset, protected-route middleware, uploads, and outbound requests can benefit from `sequenceDiagram`. Header hardening, dependency pinning, logging, password hashing, or static data-protection controls usually do not.

6. **Do not emit legacy §7.3.N auth-flow structure.** No `#### 7.3.N <Method> Flow`, no `**Findings in this flow:**`, no control-table row/subblock matching. The current gate is `control_subsection_coverage`.

7. **Write the completed fragment** back to `.fragments/security-architecture.md`. The file must start with `## 7. Security Architecture`, contain the 13 v2 H3 headings, and contain no remaining `<!-- NARRATIVE_PLACEHOLDER` tokens.

**Quality bar:** the narrative in a complete `security-architecture.md` should allow a security-aware reader who has NOT read the full threat register to understand which controls exist, which controls fail, and which findings prove those failures.

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

Section 7 is the unified security architecture section. Under v2 it is organized by control category, not by SC IDs or legacy domain tables. It opens with `### 7.1 Security Control Overview`, then emits §7.2-§7.12 control-category sections, and closes with `### 7.13 Defense-in-Depth Summary`.

The required H3 headings are, in order:

1. `### 7.1 Security Control Overview`
2. `### 7.2 Identity and Authentication Controls`
3. `### 7.3 Session and Token Controls`
4. `### 7.4 Authorization Controls`
5. `### 7.5 Query Construction and Data Access Controls`
6. `### 7.6 Input Boundary Validation Controls`
7. `### 7.7 Output Encoding and Rendering Controls`
8. `### 7.8 Browser and Cross-Origin Controls`
9. `### 7.9 Cryptography Secrets and Data Protection`
10. `### 7.10 File Parser and Outbound Request Controls`
11. `### 7.11 Operations Runtime and Supply Chain Controls`
12. `### 7.12 Real-time and Not Applicable Controls`
13. `### 7.13 Defense-in-Depth Summary`

`### 7.1 Security Control Overview` contains one table only:

```markdown
| Control category | Verdict | Main reason |
|---|---|---|
```

Do not add control IDs, SC IDs, finding columns, gap-summary paragraphs, architecture-pattern tables, or duplicated risk tables to §7.1.

Every §7.2-§7.12 control-category section has this exact shape:

```markdown
### 7.N <Control Category>

**Verdict:** <emoji + concise verdict>

**Controls covered:** [Control A](#control-a), [Control B](#control-b).

**Implemented controls:** <one concrete inventory sentence>

**Assessment:** <section-level architecture conclusion>

#### Control A

**Security assessment**

<grounded prose; cite code paths, routes, libraries, storage locations, manifests>

**Relevant findings**

- [F-NNN](#f-nnn) - <short title>
```

Rules:

1. The visible text of each `**Controls covered:**` link must exactly match an H4 heading in the same section.
2. Every H4 control block must contain `**Security assessment**` and `**Relevant findings**`.
3. If no finding maps directly, use `- No dedicated finding routed in this assessment.` under `**Relevant findings**`.
4. Sequence diagrams are optional and only for flow-like controls. They are not required for primitives, lifecycle controls, static configuration, or supply-chain controls.
5. Do not emit retired `#### 7.3.N <Method> Flow` headings, `**Findings in this flow:**` trailers, legacy `What/How/Where` blocks, or SC-NN control tables under v2.
6. Dependency-driven findings must be referenced under §7.11; recon-observed TOTP/2FA must appear under §7.2; recon-observed Socket.IO/WebSocket must appear under §7.12 and must not be called not applicable.

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

§8 Threat Register, §9 Mitigation Register, §10 Out of Scope and both appendices are rendered from `threat-model.yaml` + `data/breach-vector-taxonomy.yaml` by `compose_threat_model.py`. The orchestrator does **not** author a fragment for them (except `.fragments/out-of-scope.md` for §10 and, conditionally, `.fragments/compound-chains.json` under §8.C).

Architecture-derived findings are NOT a separate fragment — they ARE `F-NNN` rows in `threats[]` with `source=architecture-coverage` or `source=threat-hypothesis` plus `architectural_theme` metadata. No `AF-NNN` ids and no `architectural_findings[]` list are emitted. Cluster grouping by theme is a computed view inside the renderer.

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
- `changed_threats` — T-IDs present in both but with different `severity`, `cwe`, `evidence.file`, `evidence.line`, or `mitigation_ids[]` — with one-line note per ID describing what changed (e.g. `"severity High → Critical"`, `"evidence moved to auth/session.ts:89"`)
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
  assessment_depth: <quick|standard|thorough>   # ASSESSMENT_DEPTH at run-time
  reasoning_model: <REASONING_MODEL>            # e.g. haiku-economy / opus-cheap / opus
  invocation: <INVOCATION_ARGS>                 # raw args string, e.g. "--quick --sarif"
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
  assessment_depth: <quick|standard|thorough>
  reasoning_model: <REASONING_MODEL>
  invocation: <INVOCATION_ARGS>
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
  assessment_depth: <quick|standard|thorough>
  reasoning_model: <REASONING_MODEL>
  invocation: <INVOCATION_ARGS>
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
| `$OUTPUT_DIR/.assessment-owner-sid` | session ownership marker |
| `$OUTPUT_DIR/.prior-findings-index.json` | Phase 5 → Phase 9 cross-reference cache |
| `$OUTPUT_DIR/.stage1-resume-count` | skill-level resume-loop counter (cut-off recovery) |
| `$OUTPUT_DIR/.skill-config.json` | skill resolved-config snapshot (M3.3 — was leaking on crash) |
| `$OUTPUT_DIR/.recon-patterns.json` | deterministic recon pre-pass output (M3.1 — Phase 2 input) |
| `$OUTPUT_DIR/.context-resolver.stdout` | context-resolver transient stdout |
| `$OUTPUT_DIR/.ctx-resolver.pid` | context-resolver background PID marker |
| `$OUTPUT_DIR/.recon-scanner.pid` | recon-scanner background PID marker |
| `$OUTPUT_DIR/.recon-scanner.stdout` | recon-scanner transient stdout |
| `$OUTPUT_DIR/.coverage-gaps.json` | Phase 9 coverage-gap intermediate |
| `$OUTPUT_DIR/.route-inventory.json` | deterministic route-extractor MVP (arch.md) — feeds Phase 6 `attack_surface[]` and architecture-coverage engine |
| `$OUTPUT_DIR/.architecture-coverage.json` | always-on architecture-coverage rule evaluations (arch.md) — feeds `security_controls[]` / `threat_hypotheses[]` / Phase-9 bridge |
| `$OUTPUT_DIR/.arch-coverage-threats.json` | Phase-9 bridge candidates from `arch_coverage_to_threats.py emit` — transient pre-merge buffer |
| `$OUTPUT_DIR/.scan-manifest.txt` | optional scan manifest intermediate |
| `$OUTPUT_DIR/.triage-ranking.json` | deterministic triage ranking intermediate |
| `$OUTPUT_DIR/.qa-prepass.json` | deterministic QA pre-pass handoff summary |
| `$OUTPUT_DIR/.appsec-progress.json` | latest live progress snapshot |
| `$OUTPUT_DIR/.skill-watchdog.tick` | skill-watchdog liveness marker |
| `$OUTPUT_DIR/.progress/` (directory) | per-component STRIDE substep state |
| `$OUTPUT_DIR/.taxonomy-slices/` (directory) | per-component taxonomy slices |
| `$OUTPUT_DIR/.dispatch-context/` (directory) | per-component volatile context slices passed to STRIDE analyzers |
| `$OUTPUT_DIR/.merge-context/` (directory) | focused volatile context passed to threat-merger |
| `$OUTPUT_DIR/.active-tool-calls/` (directory) | per-tool-call liveness markers |

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
| [internet-anon](#vektor-internet-anon) | 1 | Unauthenticated attacker from the public internet | <examples: F-NNN short-label list, `<br/>`-separated> |
| [internet-user](#vektor-internet-user) | 2 | Any authenticated low-privilege user | <examples> |
| [internet-priv-user](#vektor-internet-priv-user) | 2 | Authenticated admin-level user | <examples> |
| [victim-required](#vektor-victim-required) | 2 | Needs victim interaction (XSS, CSRF, open redirect) | <examples> |
| [build-time](#vektor-build-time) | 3 | Attacker controls a build input (dep, base image, CI, training data) | <examples> |
| [repo-read](#vektor-repo-read) | 3 | Attacker gains read access to source repository | <examples> |
| [n-a](#vektor-n-a) | — | Architectural / meta-finding with no runtime entry point | <examples — architecture-coverage F-NNN findings> |

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
**Attacker position:** Architectural / meta-finding — no runtime entry point. The finding describes a design-level defect surfaced by deterministic architecture-coverage rules.
**Preconditions:** Finding has `source=architecture-coverage` (anti-pattern) or `source=threat-hypothesis` (promoted hypothesis) and carries an `architectural_theme` value.
**Typical CWEs:** carried per-finding (e.g. CWE-942 for permissive CORS, CWE-862 for inconsistent authorization).
**Typical OWASP Top 10:** derived from the finding's CWE.
```

**Canonical IDs (kebab-case, lowercase).** The anchor IDs are `vektor-internet-anon`, `vektor-internet-user`, `vektor-internet-priv-user`, `vektor-victim-required`, `vektor-build-time`, `vektor-repo-read`, `vektor-n-a`. In the Top Findings table, the link text is the human-readable form (e.g. `[Internet Anon](#vektor-internet-anon)`), in the summary table here it is the kebab-case ID (e.g. `[internet-anon](#vektor-internet-anon)`).

**Examples column.** Populate the `Examples` cells with 2–4 F-NNN references from this run whose Vektor matches the row, formatted `[F-NNN](#f-NNN) — <short label>` and `<br/>`-separated. When a row has zero matching findings in this run, emit `_none in this assessment_`.

**Cross-reference rule:** Every Vektor value in the Top Findings table MUST be a clickable link to its definition in this appendix. Bare text Vektor values without links are a format defect auto-repaired by QA.
