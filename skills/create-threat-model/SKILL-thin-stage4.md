# Compact Thin Stage 4

Run only for a controller action with `stage=stage4`. Require the canonical
Markdown and YAML; missing input is blocking, not an editorial skip.

Stage 4 is one editorial pass over the report's wording, and it runs **once**.
Nothing here judges the report, so no change is re-reviewed and no repair agent
is dispatched.

## 1. Prepare

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_editorial_context.py" "$OUTPUT_DIR"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_editorial_diff.py" snapshot \
  --output-dir "$OUTPUT_DIR"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/architect_structural_checks.py" all \
  --output-dir "$OUTPUT_DIR" > "$OUTPUT_DIR/.architect-pre-pass.json"
```

The builder prints `blocks_total`; when it is `0`, skip §2 and §3. The
structural checks are advisory: the receipt surfaces their warnings, this stage
repairs nothing.

## 2. Dispatch once

Mark Stage 4 in progress, start the fixed heartbeat, print the handoff. Dispatch
`appsec-advisor:appsec-architect-reviewer` exactly once, with description
`Editorial pass`, `run_in_background: false`, and the resolved
`ARCHITECT_MODEL`. Pass only `OUTPUT_DIR` and `MODEL_ID`. Wait for the result;
do NOT end your turn while it runs. Never dispatch it twice. An Agent error is
non-fatal: continue at §3, where an absent plan applies nothing.

## 3. Apply, verify, re-render

Every write is deterministic. Capture both reports; the receipt reads them:

```bash
CTX="$OUTPUT_DIR/.dispatch-context/editorial"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/apply_editorial_plan.py" "$OUTPUT_DIR" \
  > "$CTX/apply-report.json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_editorial_diff.py" verify \
  --output-dir "$OUTPUT_DIR" --restore > "$CTX/guard-report.json"
```

Applier exit 1 means actions were rejected, guard exit 2 means the pass was
rolled back; both are expected. When `files_touched` is non-empty, re-render in
the canonical order, where every non-zero exit is blocking:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" \
  --output-dir "$OUTPUT_DIR" --strict
python3 "$CLAUDE_PLUGIN_ROOT/scripts/apply_prose_fixes.py" \
  "$OUTPUT_DIR/threat-model.md"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" gate \
  "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" "$REPO_ROOT"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/section_integrity.py" "$OUTPUT_DIR" \
  --plugin-root "$CLAUDE_PLUGIN_ROOT"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" unmasked_secrets \
  "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" \
  > "$OUTPUT_DIR/.qa-secret-scan.json"
```

A QA gate exit of `1`, `2` or `3` means the rewrite disagrees with a gate the
pre-edit report passed. Do not repair, do not dispatch: run
`check_editorial_diff.py restore --output-dir "$OUTPUT_DIR"`, re-run this block
over the restored bytes, and record the discarded polish. A non-zero exit there
is a hard abort.

## 4. Close the stage

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_editorial_receipt.py" "$OUTPUT_DIR"
```

It writes `.architect-status.json` and prints the receipt; emit that stdout
verbatim. Record Stage-4 stats, send the final heartbeat, stop the watchdog,
mark Stage 4 complete, call `orchestration_controller.py next`, and honor its
instruction file.
