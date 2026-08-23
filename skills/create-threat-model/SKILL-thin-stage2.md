# Compact Thin Stage 2

Use only this Stage-2 runtime. The controller owns structural
pregeneration and the filesystem-authoritative compose handoff.

1. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     prepare-stage2 --output-dir "$OUTPUT_DIR"
   ```

   Require `stage=stage2`, `renderer_profile`, and a matching
   `dispatch_agent` or `dispatch_parallel` action. A returned `stage=stage1d`
   means Stage 1d never ran: load `SKILL-thin-stage1d.md` in full, follow it,
   then repeat this call.
2. Mark `Stage 2 - Report rendering` in progress, capture
   `STAGE2_START_ISO`, print the fixed banner, and start the heartbeat:

   ```text
   ▶ Stage 2 - Report rendering starting  (expect ~<EST_STAGE2> min, model: <RENDERER_MODEL>, renderer budget)
     ⟶ Authoring required LLM fragments and invoking the deterministic compose tail
   ```
3. Reduce `RENDERER_MODEL` to a bare Agent model alias and set it explicitly.
   Pass all non-null aliases from `SKILL-full-runtime.md`. Request only concise
   status, artifact paths, and blockers; never reproduce report bodies.

   - `ms-only`: call only `appsec-advisor:appsec-ms-renderer`, description
     `Render: Management Summary`. This is default
     Quick. The deterministic security-architecture scaffold remains on disk.
   - `parallel`: issue both calls in one message and wait for both. Call
     `appsec-advisor:appsec-secarch-renderer`, description
     `Render: §7 Security Architecture`; call
     `appsec-advisor:appsec-ms-renderer`, description
     `Render: Management Summary`.
   - `full`: call `appsec-advisor:appsec-threat-renderer`, description
     `Threat Model Renderer (Stage 2)`.

   Specialists write only their owned fragments and never compose. The profile
   never skips fragment validation, strict compose, prose fixes, QA autofix, or
   the Stage-3 secret gate.
4. Send the final heartbeat, stop the watchdog, mark Stage 2 completed, and
   record stats exactly as written — `--stage` takes the integer `2`, NOT the
   `stage2` label the controller's JSON uses everywhere else, and `--name` is
   required:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
     --stage 2 --name "<renderer_profile>" --agent "<agent_type>" \
     --model "<model>" --duration-ms <sum> --tool-uses <sum> --tokens <sum> \
     --subagent-type "<agent_type>" --since-iso "$STAGE2_START_ISO"
   ```

   For parallel, sum tokens and tool uses, use the larger duration, and pass one
   comma-separated `--subagent-type` value. Stats failure is non-blocking.
5. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     next --output-dir "$OUTPUT_DIR"
   ```

   The controller validates fragments and composes when ready. A Stage-2
   response naming a repair agent must dispatch it; any other Stage-2 response
   repeats this procedure. Continue only on Stage 3, Stage 4, or complete.
   Never infer completion from Agent prose or report-file presence.
