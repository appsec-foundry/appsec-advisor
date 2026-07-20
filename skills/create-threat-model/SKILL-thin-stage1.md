# Compact Thin Stage 1

This file is authoritative only for `thin-full` full/rebuild runs. Configuration
aliases and the explicit forwarding contract are already resident from
`SKILL-full-runtime.md`; do not read the Stage-1 body from `SKILL-impl.md`.

## Invariants

- `PARALLEL_STRIDE=true` uses Analyst-A, one parallel STRIDE fan-out, then
  Analyst-B. Never replace this with inline STRIDE.
- Every analyst dispatch receives every non-null alias from the parent runtime
  plus `APPSEC_TRIAGE_DETERMINISTIC=1` and the branch-specific values below.
- All fan-out calls are issued in one assistant message, use
  `run_in_background: false`, and set the Agent `model` parameter explicitly.
- Every Agent prompt requests only a concise final status, written artifact
  paths, and blockers. It must not reproduce artifact bodies or evidence lists
  in its return prose; the filesystem is the handoff.
- The filesystem is authoritative after every Agent return.

Log the resolved branch with `scripts/log_event.py` event
`PARALLEL_STRIDE_RESOLVED`, including `PARALLEL_STRIDE`, `LIVE_PHASE`, `MODE`,
and the raw `PARALLEL_STRIDE_ENV` value.

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

1. Set the Stage-1a active form to `Phases 1–8 — recon → architecture → controls`.
   Dispatch `appsec-advisor:appsec-threat-analyst` in the foreground with
   description `Threat Analysis & Triage`, all forwarded aliases, and
   `STAGE1_PHASE_LIMIT=8`. Record its usage with `record_stage_stats.py
   --accumulate` before continuing.
2. Build and validate the manifest in one Bash call:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_stride_dispatch_manifest.py" "$OUTPUT_DIR" \
       --depth "$ASSESSMENT_DEPTH" --ceiling "$MAX_STRIDE_COMPONENTS" \
       --analyst-context "$OUTPUT_DIR/.stride-analyst-context.json" && \
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_dispatch_manifest.py" \
       "$OUTPUT_DIR/.stride-dispatch-manifest.json" "$OUTPUT_DIR"
   ```

   Show the builder's complete ANALYZED/SKIPPED selection block. If either
   command fails, log `PARALLEL_STRIDE_FALLBACK`, dispatch one foreground
   analyst with `RESUME_FROM_PHASE=9` and `STAGE1_PHASE_LIMIT=10b`, then skip
   the remaining fan-out steps.
3. Read `.stride-dispatch-manifest.json`, set the active form to
   `Phase 9 — STRIDE (<N> components)`, and issue every listed
   `appsec-advisor:appsec-stride-analyzer` call in one message. Description is
   `STRIDE: <NAME>`. Map all manifest fields, including `COMPONENT_ID`, `NAME`,
   `DESCRIPTION`, `PATHS`, `COMPLEXITY`, `MAX_TURNS`, `INTERFACES`,
   `TRUST_BOUNDARIES`, `CONTROLS`, `KNOWN_*`, `TAXONOMY_SLICE_DIR`, and every
   `index_paths.*` entry. Preserve Group A → B → C ordering. Each prompt also
   passes `REPO_ROOT`, `OUTPUT_DIR`, `CLAUDE_PLUGIN_ROOT`, and instructs the
   analyzer to export `OUTPUT_DIR` in its first Bash call. Reduce
   `STRIDE_MODEL` to the bare `sonnet`/`opus`/`haiku` Agent model alias.
4. After all analyzers return, inspect each `.stride-<id>.json`. A file with
   missing/empty `threats` or `partial=true` is a stub. Re-dispatch all stubs
   once, together in one message, with the original prompt. Judge recovery by
   re-reading the files, not by Agent return prose; log `STRIDE_STUB_RETRY_OK`
   or `STRIDE_STUB_RETRY_FAILED` through `log_event.py`. Do not retry twice.
5. Record the summed STRIDE usage with `record_stage_stats.py --accumulate`.
   Set the Stage-1a active form to `Phases 9–10b — merge → triage`, then
   dispatch Analyst-B in the foreground with description
   `Threat Analysis & Triage (merge+triage)`, all aliases,
   `RESUME_FROM_PHASE=9-merge`, and `STAGE1_PHASE_LIMIT=10b`. Record its usage
   with `--accumulate`.

Every accumulated stats call uses stage `1`, name `Threat Analysis & Triage`,
the actual model/usage values, and the shared `--since-iso
$STAGE1_START_ISO`. The STRIDE group uses subagent type
`appsec-advisor:appsec-stride-analyzer`; analyst calls use
`appsec-advisor:appsec-threat-analyst`. Stats failures are non-blocking.

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
