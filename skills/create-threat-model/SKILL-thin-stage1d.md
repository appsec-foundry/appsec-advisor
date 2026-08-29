# Compact Thin Stage 1d

Run only when `SKIP_ABUSE_CASE_VERIFICATION=false`; use no other Stage-1d instructions.

1. Mark Stage 1d in progress, capture `STAGE_ABUSE_START_ISO`, print the banner,
   and start the heartbeat:

   ```text
   ▶ Stage 1d - Abuse case verification starting  (deterministic match + per-candidate sonnet verifier fan-out)
   ```
2. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     prepare-abuse --output-dir "$OUTPUT_DIR"
   ```

3. Call `verify-receipts --action-id <context_plan.action_id>` as the final
   filesystem action. Then launch every job as an
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

   Use the job model alias — `dispatch_jobs[].model`, else
   `dispatch_values.abuse_verifier_model_alias`; `MODEL_ID` keeps the operator
   id, which the Agent tool rejects. Never replace a versioned ID with 4.6. Run
   one blocking waiter with every job's candidate id:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/wait_abuse_progress.py" "$OUTPUT_DIR" \
     <candidate ids from dispatch_jobs[]> --interval 20 --rounds 45
   ```

   The waiter's exit status is informational; step 4 owns the retry, so do not
   branch on it or repeat steps 2-3 yourself. Aggregate usage.
   Require concise status without reproducing evidence or artifact content.
   Abort or overflow is fatal and must not silently drop candidates.
   `dispatch_jobs[]` is the only dispatch authority: `run_gate` needs no
   verifier — go to step 4 — even carrying `candidates[]`, which then stay
   unverified for the reason in its receipts. Never rebuild a fan-out from
   them; the guard rejects a verifier without `ACTION_ID`/`JOB_ID`.
4. Run:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
     finalize-abuse --output-dir "$OUTPUT_DIR"
   ```

   Require `stage=stage1d`. `run_gate` ends the stage; the controller owns
   merge, promotion, YAML rebuild, gates, ranking, and §9 rendering.
   `dispatch_parallel` is its one retry for verifiers that decided nothing:
   dispatch that wave as in step 3, wait, then call `finalize-abuse` again.
   The retry budget is persisted, so this cannot loop.
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
