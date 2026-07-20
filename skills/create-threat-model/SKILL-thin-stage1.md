# Compact Thin Stage 1

Authoritative only for `thin-full` full/rebuild runs. Forwarding is resident in
`SKILL-full-runtime.md`; do not read Stage 1 from `SKILL-impl.md`.

## Invariants

- `PARALLEL_STRIDE=true`: Analyst-A, bounded STRIDE waves, then Analyst-B;
  never inline STRIDE.
- Every analyst dispatch receives every non-null alias from the parent runtime
  plus `APPSEC_TRIAGE_DETERMINISTIC=1` and the branch-specific values below.
- Issue each wave in one assistant message with `run_in_background: false` and
  an explicit Agent `model`.
- Agent returns contain only status, paths, and blockers; they must not reproduce artifact bodies or evidence lists.
- The filesystem is authoritative after every Agent return.

Log `PARALLEL_STRIDE_RESOLVED` via `scripts/log_event.py`, including
`PARALLEL_STRIDE`, `LIVE_PHASE`, `MODE`, and raw `PARALLEL_STRIDE_ENV`.

Before the first Agent dispatch, snapshot the prior deliverables for the
failure-only recovery range and reset its per-invocation counter:

```bash
YAML_PRE_STAGE1=missing
MD_PRE_STAGE1=missing
[ ! -f "$OUTPUT_DIR/threat-model.yaml" ] || YAML_PRE_STAGE1=$(stat -c '%Y:%s' "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null || stat -f '%m:%z' "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null || echo missing)
[ ! -f "$OUTPUT_DIR/threat-model.md" ] || MD_PRE_STAGE1=$(stat -c '%Y:%s' "$OUTPUT_DIR/threat-model.md" 2>/dev/null || stat -f '%m:%z' "$OUTPUT_DIR/threat-model.md" 2>/dev/null || echo missing)
export YAML_PRE_STAGE1 MD_PRE_STAGE1
rm -f "$OUTPUT_DIR/.stage1-resume-count"
```

Capture `STAGE1_START_ISO`, mark both Stage-1 tasks in progress, and start the
fixed heartbeat watchdog from the parent runtime. Retain its task id.

## Parallel STRIDE path

Use this path when `PARALLEL_STRIDE=true`.

1. Set Stage-1a to `Phases 1–8 — recon → architecture → controls`. Dispatch
   foreground `appsec-advisor:appsec-threat-analyst` as `Threat Analysis &
   Triage` with all aliases and `STAGE1_PHASE_LIMIT=8`; record usage with
   `record_stage_stats.py --accumulate`.
2. Build and validate the manifest:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_stride_dispatch_manifest.py" "$OUTPUT_DIR" \
       --depth "$ASSESSMENT_DEPTH" --ceiling "$MAX_STRIDE_COMPONENTS" \
       --analyst-context "$OUTPUT_DIR/.stride-analyst-context.json" && \
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_dispatch_manifest.py" \
       "$OUTPUT_DIR/.stride-dispatch-manifest.json" "$OUTPUT_DIR"
   ```

   Show the full ANALYZED/SKIPPED block. On failure, log
   `PARALLEL_STRIDE_FALLBACK`, dispatch one foreground analyst with
   `RESUME_FROM_PHASE=9` and `STAGE1_PHASE_LIMIT=10b`, and skip fan-out.
   Otherwise initialize the wave plan as a hard gate (no inline fallback):

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/stride_dispatch_waves.py" init \
       "$OUTPUT_DIR" --concurrency "$STRIDE_CONCURRENCY"
   ```
3. Set the active form to `Phase 9 — STRIDE (<N> components, waves of up to
   <STRIDE_CONCURRENCY>)`. Repeatedly run
   `python3 "$CLAUDE_PLUGIN_ROOT/scripts/stride_dispatch_waves.py" claim
   "$OUTPUT_DIR"` and parse its JSON:
   - `status=complete` ends the loop.
   - Exit 1 / `status=blocked` means the persisted two-attempt budget is
     exhausted; stop before Analyst-B.
   - `status=claimed` returns exactly one wave's unfinished `components[]` and
     its one-based attempt counts. Dispatch only those components, all together
     in one assistant message. Attempt 1 is the normal pass; attempt 2 is the
     single retry. Persisted attempts survive parent-session resume.

   Each component uses `appsec-advisor:appsec-stride-analyzer`, description
   `STRIDE: <NAME>`, and the complete manifest mapping: `COMPONENT_ID`, `NAME`,
   `DESCRIPTION`, `PATHS`, `COMPLEXITY`, `MAX_TURNS`, `INTERFACES`,
   `TRUST_BOUNDARIES`, `CONTROLS`, `KNOWN_*`, `TAXONOMY_SLICE_DIR`, and every
   `index_paths.*` entry. Preserve Group A → B → C ordering. Each prompt also
   passes `REPO_ROOT`, `OUTPUT_DIR`, `CLAUDE_PLUGIN_ROOT`, and instructs the
   analyzer to export `OUTPUT_DIR` first. Reduce `STRIDE_MODEL` to the bare
   `sonnet`/`opus`/`haiku` Agent model alias. Zero findings are complete only
   with `partial=false`, `skipped_categories=[]`, and a schema-valid file.
4. Record each wave's summed STRIDE usage with `record_stage_stats.py
   --accumulate`. After the loop, run
   `python3 "$CLAUDE_PLUGIN_ROOT/scripts/stride_dispatch_waves.py" verify
   "$OUTPUT_DIR"`; any non-zero result is fatal and Analyst-B must not run.
5. After verification, set Stage-1a to `Phases 9–10b — merge → triage` and
   dispatch Analyst-B foreground with description
   `Threat Analysis & Triage (merge+triage)`, all aliases,
   `RESUME_FROM_PHASE=9-merge`, and `STAGE1_PHASE_LIMIT=10b`. Record its usage
   with `--accumulate`.

Accumulated stats use stage `1`, name `Threat Analysis & Triage`, actual usage,
and `--since-iso $STAGE1_START_ISO`; use each group's actual subagent type.
Stats failures are non-blocking.

## Serial fallback

When `PARALLEL_STRIDE=false`, dispatch one foreground
`appsec-advisor:appsec-threat-analyst` with description
`Threat Analysis & Triage`, all aliases, and `STAGE1_PHASE_LIMIT=10b`. Record
one non-accumulating Stage-1 stats row from its usage.

## Close and gate

After the final Stage-1 Agent return, send the final lock heartbeat, load
`TaskStop` if needed, stop the watchdog, and mark Stage 1a and 1b completed.
Then run exactly:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
  post-stage1 --output-dir "$OUTPUT_DIR"
```

Require `action=run_gate`, `stage=stage1`. When the abort reason reports missing
Stage-1 artifacts or an invalid Stage-1 completion checkpoint, load and follow
only the failure/cut-off recovery range named by the parent runtime. Any other
abort is fatal. Never dispatch Stage 1c or Stage 2 after an abort. The
controller owns artifact presence, completion-checkpoint freshness,
STRIDE-dispatch evidence, bootstrap-YAML recovery, schema validation, invariant
repair, deterministic ranking, auto-emitters, mitigation quality, and build
completeness.

An Agent stall result does not override a successful post-gate: the on-disk
completion checkpoint is authoritative. Only when the post-gate also reports
missing artifacts or an invalid checkpoint, emit `stall_notice.py` for Stage 1
and load the failure/cut-off recovery range named by the parent runtime. Do not
improvise a redispatch.
