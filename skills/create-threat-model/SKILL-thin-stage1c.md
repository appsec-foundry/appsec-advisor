# Compact Thin Stage 1c

This stage runs only when `SKIP_ABUSE_CASE_VERIFICATION=false`. Do not read the
Stage-1c body from `SKILL-impl.md`.

1. Mark `Stage 1c - Abuse Case Verification` in progress, capture
   `STAGE_ABUSE_START_ISO`, print this banner, and start the fixed heartbeat
   watchdog:

   ```text
   ▶ Stage 1c - Abuse Case Verification starting  (deterministic match + per-candidate sonnet verifier fan-out)
     ⟶ Chains each derived from §8 findings; verified step-by-step, then folded into §9
   ```
2. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     prepare-abuse --output-dir "$OUTPUT_DIR"
   ```

3. When the action is `dispatch_parallel`, issue one foreground
   `appsec-advisor:appsec-abuse-case-verifier` Agent call for every
   `candidates[]` entry in a single assistant message. Never dispatch them
   sequentially. Description: `Abuse case: <AC-ID>`. Each prompt contains:

   ```text
   ABUSE_CASE_ID=<AC-ID>
   MATCH_RESULT_PATH=<OUTPUT_DIR>/.abuse-case-matches.json
   REPO_ROOT=<REPO_ROOT>
   OUTPUT_DIR=<OUTPUT_DIR>
   CLAUDE_PLUGIN_ROOT=<CLAUDE_PLUGIN_ROOT>
   MODEL_ID=<ABUSE_VERIFIER_MODEL>
   ```

   Reduce `ABUSE_VERIFIER_MODEL` to the bare Agent model alias and set it
   explicitly. Do not default a full/versioned id to 4.6. Collect aggregate
   usage. Ask each verifier to return only concise status, artifact paths, and
   blockers, without reproducing evidence or artifact content. When the action
   is `run_gate`, no verifier is required.
   An abort, including a candidate count above the bounded fan-out limit, is
   fatal and must not silently drop candidates.
4. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     finalize-abuse --output-dir "$OUTPUT_DIR"
   ```

   Require `action=run_gate`, `stage=stage1c`. The controller owns merge,
   finalize, verified-finding promotion, YAML rebuild, configured release gate,
   ranking fold, and §9 rendering.
5. Send the final heartbeat, stop the watchdog, record the aggregated stats with
   `record_stage_stats.py` (`output_dir` is positional), and mark the task
   completed:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
       --stage 1 --variant abuse-verification --name "Abuse Case Verification" \
       --agent appsec-advisor:appsec-abuse-case-verifier \
       --model "$ABUSE_VERIFIER_MODEL" \
       --duration-ms <ms> --tool-uses <n> --tokens <n> 2>/dev/null || true
   ```

   With no candidates, record a zero-token deterministic row instead: same call
   with `--agent deterministic:match_abuse_cases.py --model none
   --duration-ms 0 --tool-uses 0 --tokens 0`.

Any configured abuse-case release-gate failure is fatal. Other matcher/verifier
pipeline failures remain visible in controller receipts and the event log.
