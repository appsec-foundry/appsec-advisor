# Deterministic controller for single-repository assessments

**Date:** 2026-10-12

**Status:** Plan. Nothing implemented. Built on a feature branch from `dev`.

**Source analysis:** `analysis-multi-vs-single-repo-cost-speed-2026-10-12.md`.

## Goal

A single-repository assessment runs without a session LLM orchestrator. A Python controller sequences every stage and calls each semantic role with an explicit model ID. The interactive skill keeps only preflight, the business-context dialog, and the launch.

Success means a single-repository run on the same target and depth costs less and finishes faster than the current runtime, with no loss of quality as graded by `eval-threat-model`.

Non-goals: changing analysis semantics, severity rules, or report structure; removing the legacy runtime before the new path is the default.

## Approach

Two paths lead to a deterministic controller. This plan takes path A and keeps path B as a fallback for individual roles.

| | A: single repository through `assess` | B: new Python loop around `next` |
|---|---|---|
| Driver | `assess_repositories` in `scripts/orchestrator/orchestration_controller.py` already sequences every stage without an LLM | New loop that calls `next`, executes the action, and calls the next gate |
| Roles | Tool-less host calls already exist for every role `assess` uses: `_assessment_role_instructions` adapts the registered role instructions, and the controller serves source excerpts | Current role agents unchanged, started as `claude -p` hosts |
| Transport | `ClaudeCliTransport` in `scripts/runtime/analyst_host.py`, tool-less | Needs a new transport variant with Bash and Write, because the role agents run helper scripts and write their artifacts; only `EXPLORE_TOOLS = "Read,Grep,Glob"` exists today |
| Telemetry | Host events and job receipts, as in the multi run | Agent lifecycle and budget rely on Agent-tool hooks; a parallel host path is needed |
| Trust | REQ-TRU-001 already holds: models read only controller-served excerpts | Hosts with Bash on untrusted repository content widen the attack surface |

Path A reuses a pipeline that already publishes reports, so the driver track and the role track from the analysis merge into one step for headless runs. Path B applies only to a role whose tool-less quality turns out to be insufficient; that role then gets the read-only `EXPLORE_TOOLS` on a copy, as the threat analyst does, not Bash or Write.

## Gaps between `assess` and the single-repository runtime

These differences decide what the single-repository path must add, refuse, or leave to the legacy runtime.

- **Unsupported flags** (`_ASSESSMENT_UNSUPPORTED`): `--incremental`, `--rerender`, `--dry-run`, `--base`, `--pr-mode`, `--restore-from`, `--clean-cache`, `--clean-all`, `--audit-requirements`, `--check-requirements`, `--max-wall-time`.
- **Repository count:** `assess` and `multi_repo_scope.admit` require at least two selections.
- **Quality review:** `assess` runs deterministic quality gates (secret redaction, `unmasked_secrets`, `final_structure`). No QA-reviewer agent, fragment-fixer agent, or repair loop was found in the `assess` path.
- **Threat merge:** `assess` merges deterministically (`merge_threats.py`); the threat-merger agent is not called.
- **Architect review:** present (`run_architect_review` in `scripts/orchestrator/assessment_review.py`), gated by `architect_review` in the resolved configuration, as in the single-repository runtime.
- **Business-context dialog:** `assess` captures declared context (`assessment_context.capture`) but runs no dialog; headless runs need none (REQ-BIZ-005).

## Phases

### Phase 0: Spike and baseline

Goal: show that path A produces a usable single-repository model and measure the gap.

1. Let `assess` accept one repository behind a temporary opt-in on the feature branch. Only the repository minimum and the default project name change.
2. Run Juice Shop at `standard` depth through the opt-in, and through the current runtime on `dev`, on the same commit of the target.
3. Grade both with `eval-threat-model`. Record cost, wall clock, findings by severity, and findings present in only one model.
4. From an interactive session, start the run once with `! scripts/run-headless.sh …` and once as a background Bash command. Record whether nested `claude -p` works, how the Bash sandbox treats its API traffic, and whether output appears live.
5. Investigate why the multi run's `.assessment-state.json` reads `status: failed` after publication.

Exit criterion: the comparison exists and shows no loss of real critical or high findings. If quality drops, the per-finding diff names the roles to examine before Phase 2.

### Phase 1: Decide the scope of the single-repository path

For each gap above, decide one of: implement in `assess`, refuse with a message that names the legacy runtime, or keep only in the legacy runtime. Proposed defaults:

- `--check-requirements` and `--audit-requirements`: implement, because requirement checks are a documented product capability.
- `--incremental`, `--rerender`, `--base`, `--pr-mode`: refuse in the first version and keep in the legacy runtime.
- QA review and repair: compare the QA findings of both Phase 0 models first; add a semantic review only if the deterministic gates miss defects the QA reviewer catches.

Present these decisions to the operator before Phase 2.

### Phase 2: Headless single-repository runs on the controller

1. Make the one-repository path in `assess` permanent, including the decided gaps from Phase 1.
2. Route a single `--repo` in `scripts/run-headless.sh` to `orchestration_controller.py assess`, with an explicit opt-out to the legacy runtime during the transition.
3. Update `docs/headless-mode.md`. Add a `CHANGELOG.md` entry, because cost and duration change for users.

Exit criterion: Phase 0 comparison repeated on Juice Shop and on one further neutral target (for example the Spring fixture) with the final code.

### Phase 3: Interactive runs launch the controller

1. `SKILL-full-runtime.md` keeps preflight, lock handling, and the business-context dialog. REQ-BIZ-005 requires the answers to reach the same run, so the dialog completes before the launch and the controller captures the result as declared context.
2. The session starts the controller with one background Bash command and waits for its task notification. Add the command to `data/required-permissions.yaml` and its tests.
3. The completion summary follows OR-38: the plugin delivers it, not the orchestrator.
4. Remove the session-model question (§2a) and `_session_model_advisory`, because every role now runs with an explicit model ID.
5. Define progress and cancellation without Task rows, for example a progress file the session reads on request and a stop command that ends the controller through the single terminator (OR-8).

### Phase 4: Retire the legacy orchestration

Only after the controller path has been the default in both modes:

- Remove guards that exist only for the session orchestrator: `check_stride_dispatch.py`, the `completion_relay` gate, the `wave_split_across_messages` telemetry, and the Agent-hook lifecycle decisions that no longer have a producer.
- Remove the Sonnet 4.6 economy pin for STRIDE; MD-9 already excludes it for tool-less STRIDE calls.

## Affected contracts

`python3 scripts/check_specs.py --for <path>` lists the bindings; the relevant ones are:

- **REQ-TRU-001** names "a combined assessment" for controller-served excerpts. A single-repository run through `assess` needs the same promise; the wording change requires operator approval.
- **REQ-PUR-003** describes the multi-repository headless run; its guards include `tests/test_run_headless_completion.py`.
- **REQ-BIZ-005** governs the interactive dialog in Phase 3.
- **REQ-FLW-003** applies unchanged: invalid analysis data stops the run.
- **OR-1** assigns Level-0 dispatch to the controller acting through compact runtimes; it needs an amendment for controller-launched hosts.
- **MD-9** extends from multi-repository to single-repository host calls.
- `docs/internal/contracts/orchestration-actions.md` describes the session runtime as the consumer of controller actions; Phase 3 changes that consumer.

## Proposed decision

To be confirmed by the operator before it is written to `docs/internal/decisions.md`:

> A single-repository assessment runs through the same Python controller as a combined assessment: the controller sequences every stage and calls each semantic role as a tool-less host with an explicit model ID, and the interactive session only completes preflight and the business-context dialog before launching it.

In plain terms: no LLM decides the order of stages or dispatches agents any more; models are only called for the analysis work itself, and always with the model the configuration names.

## Tests

- Extend `tests/test_multi_repo_assessment.py` and `tests/test_multi_repo_scope.py` for one repository: admission, project name, published model, and the untrusted preflight.
- Extend `tests/test_run_headless_completion.py` for the routing of a single `--repo` and the opt-out.
- `tests/test_check_permissions.py` for the new interactive launch command.
- Run `make validate test-for FILES="<changed files>"` per change and `make lint` after Python changes.

## Merge criterion

The branch merges into `dev` when Phase 2 is complete, the comparison on two targets shows no loss of real critical or high findings and an equal or better `eval-threat-model` result, and cost and wall clock are lower than the legacy runtime at the same depth. Phase 3 and Phase 4 can follow on separate branches.

## Risks

- **Quality of tool-less roles.** Controller-served excerpts can miss cross-file flows an exploring agent would follow. Mitigation: Phase 0 per-finding diff, path B with read-only tools for a role that needs it.
- **Feature loss.** Users of `--incremental`, `--rerender`, or PR mode lose them on the new path until implemented. Mitigation: refuse with a clear message and keep the legacy runtime reachable.
- **Interactive environment.** Nested `claude -p` from a session, sandbox network rules, and billing are unverified until Phase 0 step 4.
