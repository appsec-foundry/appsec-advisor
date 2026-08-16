# Compact Thin Stage 1d

Run only when `SKIP_ABUSE_CASE_VERIFICATION=false`; do not read Stage 1d from `SKILL-impl.md`.

1. Mark Stage 1d in progress, capture `STAGE_ABUSE_START_ISO`, print the banner,
   and start the heartbeat:

   ```text
   ▶ Stage 1d - Abuse Case Verification starting  (deterministic match + per-candidate sonnet verifier fan-out)
   ```
2. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     prepare-abuse --output-dir "$OUTPUT_DIR"
   ```

3. For `dispatch_jobs[]`, call `verify-receipts` with all receipt paths and
   SHA-256 pairs as the final filesystem action. Then launch every job as an
   `appsec-advisor:appsec-abuse-case-verifier` call, launching the wave
   in ONE message. Pass no `run_in_background`. Description:
   `Abuse case: <candidate_id> — <title>`; use the ID if its title is missing.
   Each prompt contains:

   ```text
   ABUSE_CASE_ID=<AC-ID>
   ABUSE_CASE_CONTEXT_PATH=<the job's sole input_artifact under .dispatch-context/abuse-cases/>
   REPO_ROOT=<REPO_ROOT>
   OUTPUT_DIR=<OUTPUT_DIR>
   CLAUDE_PLUGIN_ROOT=<CLAUDE_PLUGIN_ROOT>
   MODEL_ID=<ABUSE_VERIFIER_MODEL>
   ACTION_ID=<context_plan.action_id>
   JOB_ID=<dispatch_jobs[].job_id>
   ```

   Use the job model alias; never replace a versioned ID with 4.6. Run
   one blocking waiter with every job's candidate id:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/wait_abuse_progress.py" "$OUTPUT_DIR" \
     <candidate ids from dispatch_jobs[]> --interval 20 --rounds 45
   ```

   Nonzero is fatal. Aggregate usage. Require concise status without reproducing evidence or artifact content.
   `run_gate` needs no verifier. Abort or overflow
   is fatal and must not silently drop candidates. The legacy shape lacks
   `dispatch_jobs[]`; retain its foreground `candidates[]` fan-out and
   `MATCH_RESULT_PATH=<OUTPUT_DIR>/.abuse-case-matches.json` alias.
4. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     finalize-abuse --output-dir "$OUTPUT_DIR"
   ```

   Require `action=run_gate`, `stage=stage1d`. The controller owns merge,
   promotion, YAML rebuild, gates, ranking, and §9 rendering.
5. Send the final heartbeat, stop the watchdog, record aggregated stats, and
   mark the task completed:

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

Configured release-gate failure is fatal. Other failures remain in receipts and the event log.
