# Assessment Controller Contract

`scripts/orchestrator/orchestration_controller.py` runs the security assessment. `assess` executes every phase in-process through tool-less structured model exchanges, validates each result, and renders and publishes the report; no session orchestrates it and no action protocol is exchanged. The launch helpers `assess-context-preview`, `assess-context-save` and `assess-stop` each print one JSON object for the `appsec-analyzer` skill.

## Business-context dialog

`assess-context-preview` builds `.business-context-preview.json` through `contexts/business_context_preview.py`, which owns the local discovery limits; its excerpts are untrusted preliminary evidence, never a complete inventory. It returns the plugin-owned instruction file `skills/appsec-analyzer/business-context.md`. The session asks at most two questions, the use case and the worst-case business harm, without further discovery or agent dispatch; technical attack mechanisms are not business-harm choices. Headless and skip-context runs bypass the dialog.

`assess-context-save` accepts `answered`, `skip` or `unchanged`. Only the fixed, bounded `.business-context-raw.md` supplies answers; the controller validates it and saves substantive answers in `docs/security/business-context.md`, preserving repository context and never persisting explicit run-only imports. Repository context uses that path first and the legacy `docs/business-context.md` only when it is absent; saving carries effective legacy context into the new file without modifying the legacy file. An invalid answer is rejected. Later runs read the saved context before formulating questions.

## Ownership

- `runtime/resolve_config.py` remains the source of truth for flags, paths, depth, models and output settings.
- `orchestrator/orchestration_controller.py` owns admission, phase order, job acceptance, the deterministic replacements listed below, and publication.
- Registered agent definitions supply role instructions; the controller validates every returned artifact against its output contract before accepting it.

## Agent call lifecycle and budget telemetry

These rules apply to agents other skills dispatch through the Agent tool; the assessment's own model exchanges are tool-less and use none of them.

Every Agent tool invocation uses the host `tool_use_id` as its immutable
`agent_call_id`. `scripts/runtime/agent_lifecycle.py` persists the schema-v1 lifecycle
under `.active-tool-calls/agent-lifecycle.json` and permits only
`AGENT_SPAWN -> AGENT_RUNNING -> AGENT_DONE | AGENT_FAILED`. Replayed terminal
events are no-ops; missing, reordered, or conflicting transitions emit
`AGENT_LIFECYCLE_REJECTED`. The host `agent_id` binds SubagentStart and
SubagentStop usage to the call. SubagentStop reads the child-specific
`agent_transcript_path` and retires the budget; a missing or later Agent
PostToolUse cannot reopen the call. A child's own `SubagentHandback` ends its
turns and every join once it came on the last allowed turn, when no
SubagentStop can follow, or the child stayed silent after it (OR-29). The common `transcript_path` belongs to the
parent session. A headless session persists neither transcript: SubagentStop
then defers the outcome instead of recording a failure, and the Agent
PostToolUse terminalizes the call and supplies its usage. A run or session ID
alone never assigns a role, usage record, or turn counter.

`scripts/runtime/budget_watchdog.py` opens one schema-v2 counter at call admission and
retires it with the terminal call. Budget markers retain the compatible JSON
list envelope but each new entry must validate against
`schemas/agent-call-budget-marker.schema.json`. Entries without a current
`agent_call_id + action_id + job_id + component_id + attempt` identity are
inert.

Terminal cleanup first emits `AGENT_FAILED` for any
remaining calls, retires their counters and markers, then removes
`.active-tool-calls/`.

A run that does not finish cleanly still reaches one terminal state.
`scripts/runtime/terminate_run.py` is that single terminator: it records `RUN_ABORTED`
unless a controller verdict already stands, closes the checkpoint, terminalizes
remaining calls, removes live markers, aggregates run issues, and releases the
lock when the run owns it. All of that is scoped to the run that owns the
directory: when the lock is held by a live run under a different run ID, the
terminator changes nothing there — not the lock, and not the checkpoint, live
markers or run issues that are the holder's state. The headless wrapper calls
it when the operator interrupts a requirements audit.

## Semantic architect review

When `architect_review` is enabled, the assessment reviews canonical findings after evidence handling and before triage; `scripts/analyzers/architect_review_runtime.py` plans the packets, collects the proposals and applies them in one transaction.

The controller persists `.architect-review.json` under `schemas/architect-review-runtime.schema.json`. The transaction binds the run, original canonical input, analyst context, scoring profile, policy, admitted packets, proposals and accepted output. Every consumer reconstructs the application with the correction core and the recorded scoring profile, including after transient configuration cleanup. A scoring-profile change during an in-flight review blocks publication. Completed transactions recover publication without dispatching again. Re-entered boundaries retain already returned results and never dispatch a returned or missing job again.

The YAML builder projects accepted fixes after mitigation grouping and before requirement annotation. Changed ratings rederive priorities on linked fix cards through their existing deterministic policy; unrelated authored priorities and separate review or investigation tasks remain intact. Old override cards have no source-bound exception proof and cannot override a changed rating or replace an accepted fix. Shared cards retain unrelated members. Enrichment rejects lost corrections; a finding legitimately below the configured report floor remains in the audit.

## Assessment controller failure policy

The deterministic assessment controller (`assess`) requires accepted architecture, component inventory, trust boundaries, controls and every component's STRIDE analysis before publishing a complete result. A resource-budget interruption may instead publish the separate incomplete snapshot described below; other failures before those foundations are accepted stop the run.

After that point, a failed model job or optional stage does not stop the run. The stage supplies a deterministic replacement, the gap is published as a run warning that names the replaced job, and the job writes no receipt, so a later run retries it. Replacements:

- an abuse case becomes not checked;
- a failed abuse-case derivation proposes no case;
- an evidence-review batch leaves its findings `ambiguous`;
- a merge-review batch keeps its findings separate;
- unanswered architect-review packets stay unreviewed;
- root-cause synthesis falls back to the title-derived tier view;
- the Management Summary keeps the deterministic verdict floor;
- a failed export is a warning.

The Security Architecture section remains required: its contract requires a sequence diagram per flow, which only its author can write. At any point, the run stops on a violated trust boundary (a read outside the admitted scope, a changed or foreign receipt, or source changed during the run), on a model that still violates its output contract, provenance or the secret gate after every deterministic repair, on an inconsistent register after the integrity steps, or on unsettled call accounting.

### Completion budget

`AssessmentBudget` owns resource admission under the same lock as concurrent call reservations. The controller plans the required Security Architecture job and outstanding STRIDE batches. Optional jobs protect all planned work; required analysis protects report completion. Estimates use the largest accepted job cost and duration for each role under the run's fixed model selection, with correction headroom; roles without observations use conservative call allowances. Exact constants and the parallel-work calculation live in `runtime/assessment_jobs.py`. Reused, revalidated jobs reduce outstanding work and contribute measured cost, while their previous costs remain charged to the run. The plan is reconstructed during resume, never taken from model output.

Every exchange and retry rechecks the reserve before dispatch. An optional job that cannot fit returns its existing deterministic replacement, records a budget-specific gap and writes no acceptance receipt. User cancellation, a stale or foreign receipt, source drift and unavailable accounting never take this fallback. A completed result still passes all existing report gates.

If required work cannot fit, `BudgetExhausted` interrupts the lifecycle and exits `3`. While it still owns the lock and after workers have joined, the lifecycle may write `.assessment-work/budget-report.md` from results accepted or revalidated in this session. The optional `partial_report` field of `schemas/multi-repo-state.schema.json` defines its structured projection, bounds and omission counts. Source verification, redaction against captured sources, inert rendering and the secret check precede the write. The snapshot identifies preliminary candidates and missing work, never claims completed analysis, and never enters the normal model/export publication path. Cancellation, unknown accounting or source/contract violations block it. A successful continuation removes the snapshot; a fresh attempt with changed limits reuses compatible accepted jobs through the existing cache.
