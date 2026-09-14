# Compact Thin Completion

Completion is deterministic. Do not dispatch analysis or repair agents here.
First run `orchestration_controller.py next --output-dir "$OUTPUT_DIR"` and
require `action=complete`, `stage=complete`, and this instruction file. Never
announce completion while the report is absent or a QA/architect status is
still `repair_required`.

## 1. Pre-summary release gates

Require `threat-model.md`, `threat-model.yaml`, and `.qa-secret-scan.json`.
Run the final pre-export checks read-only:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/reclassify_components.py" \
  --check --strict "$OUTPUT_DIR"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" toc_closure \
  "$OUTPUT_DIR/threat-model.md"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/aggregate_run_issues.py" "$OUTPUT_DIR" \
  --repo-root "$REPO_ROOT" --depth "$ASSESSMENT_DEPTH" || true
```

Compute `.scan-wall-seconds` from `.scan-start-epoch` when available, then run this argv (a wrong argv aborts the run at its last step):

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_completion_summary.py" \
  --output-dir "$OUTPUT_DIR" \
  --repo-root "$REPO_ROOT" \
  --mode "$MODE" \
  --reasoning-model "$REASONING_MODEL" \
  --assessment-depth "$ASSESSMENT_DEPTH" \
  --write-yaml --no-write-sarif \
  --no-write-pentest-tasks --no-write-threatdragon \
  --no-check-requirements --no-architect-review \
  --patch-placeholders --no-print
```

`--reasoning-model` takes `REASONING_MODEL`, not the session model; there are no `--model` or `--depth` flags. The script reads the run's deliverable switches from `.skill-config.json`; the `--[no-]…` pairs apply only without it. PDF and HTML have no summary flags. Pass `--plugin-dev`, `--verbose` and `--quiet` only when true. Placeholder patching is the only mutation permitted after review.

Immediately certify the persisted bytes:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" final_structure \
  "$OUTPUT_DIR/threat-model.md"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/assert_completeness.py" "$OUTPUT_DIR" \
  --phase render --plugin-root "$CLAUDE_PLUGIN_ROOT"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/section_integrity.py" "$OUTPUT_DIR" \
  --plugin-root "$CLAUDE_PLUGIN_ROOT"
```

Any non-zero release gate aborts before PDF/HTML export or an “Assessment
complete” message. Controller-materialized YAML-derived exports remain
unreleased until these gates pass. Do not repair in completion.

## 2. Exports and summary

Run each export whose `WRITE_PDF` / `WRITE_HTML` switch is true, unsandboxed so headless Chrome can render every diagram. Export failures are non-fatal but must remain visible; never weaken them with `--no-mermaid`.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_pdf.py" \
  --input "$OUTPUT_DIR/threat-model.md" --output "$OUTPUT_DIR/threat-model.pdf"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_html.py" --require-mermaid \
  --input "$OUTPUT_DIR/threat-model.md" --output "$OUTPUT_DIR/threat-model.html"
```

Do **not** call `stamp_threat_model.py` yourself: `render_completion_summary.py` backfills missing SARIF, Threat Dragon and pentest-task exports, then stamps, but never exports PDF or HTML, so run those first. Keep stamped-copy paths out of the response.

Run `render_completion_summary.py` once more with the identical argv from §1
minus `--patch-placeholders --no-print`. Capture stdout for the final response;
do not rewrite or summarize it. The script owns missing-deliverable warnings,
verdict, timing, cost, output paths, and next steps.

Before cleanup, run these best-effort baseline writers; the first records the recon fingerprint a later depth increase reuses:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" update \
  --output-dir "$OUTPUT_DIR" --repo-root "$REPO_ROOT" --mode full || true
python3 "$CLAUDE_PLUGIN_ROOT/scripts/persist_run_baseline.py" \
  --output-dir "$OUTPUT_DIR" --mode "$MODE" --depth "$ASSESSMENT_DEPTH" \
  --plugin-root "$CLAUDE_PLUGIN_ROOT" || true
python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_component_durations.py" \
  "$OUTPUT_DIR" || true
```

When `APPSEC_PLUGIN_DEV=1` and current run issues exist, retain the existing
post-summary diagnosis offer. It is optional and non-fatal, runs after the scan
figures were captured, and only the diagnostician may write `.run-bugs.json`.

## 3. Cleanup and response

Mark the final task complete. Unless `KEEP_RUNTIME_FILES=true`, run
`python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-qa`
and, when enabled, the same call with `--stage post-architect`. The stage is a
`--stage` flag with its own vocabulary (`all`, `pre-qa`, `post-qa`,
`post-architect`) — neither a positional argument nor the `stageN` labels used
elsewhere in this pipeline. Cleanup
must preserve canonical deliverables, audit artifacts, and
`.appsec-cache/baseline.json`. Always release the run lock, kept runtime files
included: `rm -f "$OUTPUT_DIR/.appsec-lock"`. Leave `.appsec-verbose` and
`.appsec-tracing` alone: the closing Stop hook still reads them and removes them.

Emit the captured completion-summary stdout verbatim as response text, then
exit 0. On any blocking branch, call `terminate_run.py --outcome failure` with
the run id, repo, depth, and a concise reason before reporting the error.
