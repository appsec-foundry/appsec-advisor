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
4. From an interactive session, start the run once with `! scripts/run-headless.sh …` and once as a background Bash command. Record whether nested `claude -p` works, how the Bash sandbox treats its API traffic, and whether the session can show the controller's per-stage progress lines live while the run continues.
5. Investigate why the multi run's `.assessment-state.json` reads `status: failed` after publication.

Exit criterion: the comparison exists and shows no loss of real critical or high findings. If quality drops, the per-finding diff names the roles to examine before Phase 2.

#### Phase 0 results (2026-10-13, Juice Shop `33518f5a0`, `standard`)

| | Controller (opt-in) | Legacy runtime |
|---|---|---|
| Outcome | Published report and model | Analysis complete; final YAML validation stopped publication (`business_context_trace.applied_finding_count`), so no `threat-model.md` |
| Findings | 93 (19 Critical, 34 High, 40 Medium) | 72 (10 Critical, 34 High, 24 Medium, 4 Low) |
| Evidence basis | 48 `llm-verified`, 45 `ambiguous` | 33 `llm-verified`, 6 `ambiguous`, 1 `refuted`, 25 `unchecked`, 7 unset |
| Cost | ≈ 6.65 USD in the final attempt (109 calls), plus earlier failed attempts whose accepted jobs it reused | 23.23 USD |
| Wall clock | Not measured cleanly; several restarts reused accepted jobs | 88 min |

The controller needed five fixes before a single repository completed: oversized binaries no longer reject admission, a job learns its remaining read budget instead of failing on it, an evidence-review rejection names the IDs to fix, a component's evidence review is split so every anchor fits the read budget, and a sole repository must name at least one protected asset.

Open from Phase 0:

- Step 3 is open: `eval-threat-model` has not graded either model, and the legacy run has no report to grade. The Critical count differs by a factor of about two; whether the controller over-rates or the legacy run under-reports is unknown until graded.
- Both runs read an untracked `docs/` tree of earlier plugin runs inside the Juice Shop checkout; the controller cited `docs/security-ab-legacy/.abuse-case-verdict-AC-T-006.json` as abuse-case evidence. A clean comparison needs a clean checkout, and plugin artifacts in a target should never serve as evidence.
- Step 4: the session shows the controller's progress lines live through a background command and a log monitor. Per-component and per-boundary lines need aggregation per stage for the console. The `!` start was not tested.
- Step 5: the reported `status: failed` was not reproduced; the final controller run recorded `complete`.

#### Phase 0 defect fixes (verified 2026-10-13, operator-approved)

A report comparison of a controller run against a legacy run found defects that share one cause: the controller rebuilds the legacy tail only partly and skips deterministic steps silently. Each cause below was reproduced and survived an independent challenge.

- **Namespace leak (MR-3, amended):** a single repository uses plain repository-relative paths; component names carry no repository suffix; renderers switch to multi-repository wording only for two or more repositories.
- **Metadata root:** `meta.git`, the repository URL, the project name (RA-18) and the Run Statistics paths come from the admitted scope and the masked copy of that repository, never from the combined root or the work directory. Invocation and durations come from the controller's own records.
- **Asset IDs:** assets are numbered `A-NNN` like the legacy fragment.
- **One tail (operator decision, 2026-10-13):** the controller writes its STRIDE results and scanner findings in the legacy sidecar shape and runs the same deterministic tail as the legacy runtime (collect, finalize, evidence guard, triage, finalization). `merge_assessment` keeps only its identity and source checks as a pre-merge validation. This replaces the partial re-implementation that skipped consolidation, actor attribution, the evidence guard, classification and design signals. The IDOR group consolidates per object or sink, for both runtimes.
- **Architecture inputs:** route, egress, role and topology inventories are built before discovery and architecture and reach those jobs as context; the ORM reconciler no longer depends on a discovered data tier.
- **Actors and abuse cases:** the controller merge runs actor attribution; an unknown registration signal never turns required abuse-case signals into absent ones.
- **Titles:** shortening never cuts a finding title in mid-phrase.
- **Guard:** a test compares the deterministic steps of the controller tail with the legacy tail; a deliberate omission is listed with its reason.

Order: red invariant tests, small fixes, structural changes, rerun on Juice Shop and one further repository.

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
5. The session shows one live console line per controller stage, sourced from the controller's progress output. If Phase 0 step 4 shows that live display is impossible, a progress file the session reads on request replaces it. Cancellation uses a stop command that ends the controller through the single terminator (OR-8).
6. The run asks no questions after the launch. Every user question, including the business-context dialog, completes before the controller starts; the controller gets no pause-and-resume point for user input.

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
