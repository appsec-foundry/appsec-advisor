# Compact Thin Stage 2

Do not read Stage 2 from `SKILL-impl.md`. The controller owns structural
pregeneration and the filesystem-authoritative compose handoff.

1. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     prepare-stage2 --output-dir "$OUTPUT_DIR"
   ```

   Require `stage=stage2`, `renderer_profile`, and a matching
   `dispatch_agent` or `dispatch_parallel` action.
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
     `Render: Management Summary`, with `RENDER_ROLE=ms`. This is default
     Quick. The deterministic security-architecture scaffold remains on disk.
   - `parallel`: issue both calls in one message and wait for both. Call
     `appsec-advisor:appsec-secarch-renderer`, description
     `Render: §7 Security Architecture`, with `RENDER_ROLE=secarch`; call
     `appsec-advisor:appsec-ms-renderer`, description
     `Render: Management Summary`, with `RENDER_ROLE=ms`.
   - `full`: call `appsec-advisor:appsec-threat-renderer`, description
     `Threat Model Renderer (Stage 2)`, with `RENDER_ROLE=full`.

   Specialists write only their owned fragments and never compose. The profile
   never skips fragment validation, strict compose, prose fixes, QA autofix, or
   the Stage-3 secret gate.
4. Send the final heartbeat, stop the watchdog, mark Stage 2 completed, and run
   `record_stage_stats.py` (`output_dir` is positional). Use the dispatched
   agent as `--agent`. For parallel, sum tokens and tool uses, use the larger
   duration, and pass one comma-separated `--subagent-type` value together with
   `--since-iso`.
5. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     next --output-dir "$OUTPUT_DIR"
   ```

   The controller validates fragments and composes when ready. A Stage-2
   response naming a repair agent must dispatch it; any other Stage-2 response
   repeats this procedure. Continue only on Stage 3, Stage 4, or complete.
   Never infer completion from Agent prose or report-file presence.
