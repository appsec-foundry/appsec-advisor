# Compact thin Stage 4

Require `stage=stage4`, canonical Markdown, and YAML. The architect review already ran after evidence verification and before triage. This stage verifies that its accepted ratings and fixes survived synthesis, enrichment, rendering, and QA. Do not dispatch another review or rewrite prose.

## Verify and close

Start Stage 4 and its fixed heartbeat. Run these gates in order. Every non-zero exit blocks completion; a failed preservation check is a producer defect, not permission to erase the audit or patch the report.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validators/validate_intermediate.py" threat_model_output "$OUTPUT_DIR/threat-model.yaml"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validators/validate_mitigation_quality.py" "$OUTPUT_DIR"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validators/section_integrity.py" "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validators/qa_checks.py" unmasked_secrets "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" > "$OUTPUT_DIR/.qa-secret-scan.json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/analyzers/architect_review_runtime.py" --output-dir "$OUTPUT_DIR"
```

Emit the final command's coverage receipt verbatim. `.architect-status.json` records gate success separately from review completeness. Missing, rejected, unresolved and unscheduled decisions never count as a completed semantic review. Rerendering an older model without review provenance reports `not_run` and does not start a paid review.

Send the final heartbeat, stop the watchdog, mark Stage 4 complete, and call `orchestrator/orchestration_controller.py next`. No packet retry, editorial pass or repair loop runs here.
