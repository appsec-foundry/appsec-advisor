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

Compute `.scan-wall-seconds` from `.scan-start-epoch` when available. Then run
`render_completion_summary.py` exactly as written here — the flag names are not
guessable from the config keys, and a wrong argv aborts the run at its last
step:

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

`--repo-root` is required. `--reasoning-model` takes `REASONING_MODEL`, not the
session model, and `--assessment-depth` takes `ASSESSMENT_DEPTH`; there are no
`--model` or `--depth` flags. Each `WRITE_*`, `CHECK_REQUIREMENTS`, and
`ARCHITECT_REVIEW` switch is a flag pair — pass `--write-yaml` when the resolved
value is true and `--no-write-yaml` when it is false, never `--write-yaml true`.
Also pass `--plugin-dev`, `--verbose`, and `--quiet` only when their resolved
switches are true. PDF and HTML have no summary flags; the renderer reports
their actual files. Placeholder patching is the only mutation permitted after
review.

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

When requested, run `export_pdf.py` and `export_html.py --require-mermaid`
unsandboxed so headless Chrome can render every diagram. Export failures are
non-fatal but must remain visible; never weaken them with `--no-mermaid`.

Do **not** call `stamp_threat_model.py` yourself. `render_completion_summary.py`
already exports and then stamps, in that order, idempotently and with its output
captured. A separate call only re-prints the stamped copy set, which is
build-internal bookkeeping the reader cannot act on — keep those paths out of
the response for the same reason.

Run `render_completion_summary.py` once more with the identical argv from §1
minus `--patch-placeholders --no-print`. Capture stdout for the final response;
do not rewrite or summarize it. The script owns missing-deliverable warnings,
verdict, timing, cost, output paths, and next steps.

Before cleanup, run these best-effort measurement writers:

```bash
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
`.appsec-cache/baseline.json`. Always release `.appsec-lock` and remove this
run's verbose/tracing markers. When runtime files are kept, skip both cleanup
calls but still release run state.

Emit the captured completion-summary stdout verbatim as response text, then
exit 0. On any blocking branch, call `terminate_run.py --outcome failure` with
the run id, repo, depth, and a concise reason before reporting the error.
