# Compact Thin Stage 2

Do not read the Stage-2 body from `SKILL-impl.md`. The controller owns
structural pre-generation and the mandatory filesystem-authoritative compose
handoff.

1. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     prepare-stage2 --output-dir "$OUTPUT_DIR"
   ```

   Require `stage=stage2` and action `dispatch_agent` or `dispatch_parallel`.
2. Mark `Stage 2 - Report Rendering` in progress, capture `STAGE2_START_ISO`,
   print this banner, and start the fixed heartbeat watchdog:

   ```text
   ▶ Stage 2 - Report Rendering starting  (expect ~<EST_STAGE2> min, model: <RENDERER_MODEL>, renderer budget)
     ⟶ Authoring 2 LLM fragments + invoking compose_threat_model.py
     ⟶ Structural fragments prepared from YAML before rendering
   ```
3. Reduce `RENDERER_MODEL` to the bare Agent model alias and set it explicitly.
   Every renderer prompt receives all non-null aliases from
   `SKILL-full-runtime.md` and requests only concise final status, artifact
   paths, and blockers. Renderer return prose must not reproduce fragment or
   report bodies; the filesystem is the handoff.

   - `dispatch_parallel`: issue both calls in one assistant message and wait for
     both. Call `appsec-advisor:appsec-secarch-renderer` with description
     `Render: §7 Security Architecture` and `RENDER_ROLE=secarch`; call
     `appsec-advisor:appsec-ms-renderer` with description
     `Render: Management Summary` and `RENDER_ROLE=ms`. Specialists author only
     their owned fragments and never compose.
   - `dispatch_agent`: call `appsec-advisor:appsec-threat-renderer` with
     description `Threat Model Renderer (Stage 2)` and `RENDER_ROLE=full`.

4. Send the final heartbeat, stop the watchdog, mark the Stage-2 task
   completed, and record Stage-2 stats. For parallel rendering, sum tokens and
   tool uses but use the larger duration; pass both specialist subagent types
   and `--since-iso $STAGE2_START_ISO`.
5. Run the mandatory controller transition:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     next --output-dir "$OUTPUT_DIR"
   ```

   The controller composes from complete fragments when needed. If it returns
   `stage=stage2`, run this compact Stage-2 procedure again; do not emit a
   completion summary. If it returns Stage 3, Stage 4, or complete, continue
   with the parent runtime's stage-local schedule. Never infer completion from
   Agent return prose or stale report-file presence.
