# Compact Thin Stage 1d

This stage runs only when `SKIP_ABUSE_CASE_VERIFICATION=false`. Do not read the
Stage-1d body from `SKILL-impl.md`.

1. Mark `Stage 1d - Abuse Case Verification` in progress, capture
   `STAGE_ABUSE_START_ISO`, print this banner, and start the fixed heartbeat
   watchdog:

   ```text
   ▶ Stage 1d - Abuse Case Verification starting  (deterministic match + per-candidate sonnet verifier fan-out)
     ⟶ Chains each derived from §8 findings; verified step-by-step, then folded into §9
   ```
2. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     prepare-abuse --output-dir "$OUTPUT_DIR"
   ```

3. For `dispatch_jobs[]`, call `verify-receipts` with all receipt paths and
   SHA-256 pairs as the final filesystem action. Then issue every job as a
   foreground `appsec-advisor:appsec-abuse-case-verifier` call in a
   single assistant message. Description: `Abuse case: <candidate_id> — <title>`
   from `candidate_titles`; fall back to the ID. Each prompt contains:

   ```text
   ABUSE_CASE_ID=<AC-ID>
   ABUSE_CASE_CONTEXT_PATH=<the job's sole input_artifact under .dispatch-context/abuse-cases/>
   REPO_ROOT=<REPO_ROOT>
   OUTPUT_DIR=<OUTPUT_DIR>
   CLAUDE_PLUGIN_ROOT=<CLAUDE_PLUGIN_ROOT>
   MODEL_ID=<ABUSE_VERIFIER_MODEL>
   ```

   Use the job's model alias; never replace a versioned ID with 4.6. Aggregate
   usage. Require concise status, paths, and blockers
   without reproducing evidence or artifact content. `run_gate` needs no
   verifier. Abort or candidate overflow is fatal; it must not silently drop candidates.
   Only the legacy shape lacks `dispatch_jobs[]`; retain its `candidates[]` fan-out and
   `MATCH_RESULT_PATH=<OUTPUT_DIR>/.abuse-case-matches.json` alias.
4. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     finalize-abuse --output-dir "$OUTPUT_DIR"
   ```

   Require `action=run_gate`, `stage=stage1d`. The controller owns merge,
   finding promotion, YAML rebuild, release gate, ranking, and §9 rendering.
5. Send the final heartbeat, stop the watchdog, record the aggregated stats with
   `record_stage_stats.py` (`output_dir` is positional), and mark the task
   completed:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
       --stage 1 --variant abuse-verification --name "Abuse Case Verification" \
       --agent appsec-advisor:appsec-abuse-case-verifier \
       --model "$ABUSE_VERIFIER_MODEL" \
       --duration-ms <ms> --tool-uses <n> --tokens <n> \
       --subagent-type appsec-advisor:appsec-abuse-case-verifier \
       --since-iso "$STAGE_ABUSE_START_ISO" 2>/dev/null || true
   ```

   With no candidates, record a zero-token deterministic row instead: same call
   with `--agent deterministic:match_abuse_cases.py --model none
   --duration-ms 0 --tool-uses 0 --tokens 0`.

Any configured abuse-case release-gate failure is fatal. Other matcher/verifier
pipeline failures remain visible in controller receipts and the event log.
