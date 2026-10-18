# AppSec Advisor clean composition implementation plan

Status: replanning proposal, 2026-10-18. The operator requested this plan and a session handoff after the [primary entry checkpoint](composition-offline-evidence-2026-10-18.md#primary-entry-source-checkpoint-and-operator-stop), with explicit instructions to avoid unnecessary work, tests and token consumption. This plan replaces the continuation order in that checkpoint. It does not approve feature removal, changed requirements or registered decisions, paid model runs, publication or public cutover.

Build a small plugin integration around the existing Analyzer. Reuse working packaging and analysis components, and remove avoidable coupling from the new integration before extending it. Existing code is not obsolete merely because it came from Advisor; preserve useful behavior and its controls. The immediate milestone is one installed primary workflow with public result consumers. It is an internal integration milestone, not a reduced replacement release.

## Starting point

Use committed revisions as references and inspect current branch state before editing. Concurrent work may have advanced since these observations.

| Component | Reference | Consequence |
| --- | --- | --- |
| Advisor | `762ca7a7`, current `dev` at planning time | Primary binding exists in source; its new installed real-engine replay is pending. |
| Isolated Analyzer checkpoint | `3a3ac3a0b04c5baec284c85d21fab8bd0906ac8c`, based on `443243f6d259989f5c2d0765491e1c2a2b7e50a4` | Public operations and host compatibility were added together. Inspect and split their responsibilities before integration. |
| Original Analyzer | `a189e75cfcf22eaa9bddcf6bef4fb8f6cf59cd35`, `main` at planning time | Contains subsequent assessment and reporting work. Preserve it; do not replace this tree with the isolated snapshot or commit directly to `main`. |
| Handoff location | Isolated clone `/tmp/appsec-composition-engine`; bundle `/tmp/appsec-composition-entry-engine.bundle` | Temporary recovery inputs, not release artifacts. Verify availability and commit identity; preserve the commit in the intended development history during integration. |

The checkpoint records 25 focused Analyzer cases and 39 focused Advisor cases. They establish only their documented source behavior. Older installed score and configuration evidence belongs to its recorded pins. No new primary-entry archive supersedes the preceding configuration archive. Reuse evidence where its behavior and inputs remain applicable; never label the new primary entry qualified from those earlier checks.

## What to retain and what to simplify

Use the existing [composition inventory](appsec-advisor-composition-inventory-2026-10-18.md) as a reference. Update only affected rows against current code; some listed API gaps have already been closed. Do not repeat the complete inventory or assume every old skill needs a separate replacement.

| Area | Proposed treatment | Boundary |
| --- | --- | --- |
| Assembly, artifact verification, pinned runtime, offline setup and preflight | Retain and adapt only where the selected workflow requires it. | No replacement installer or generic plugin framework. |
| Public status, progress, stop, results, query and export | Reuse existing operations and retain useful checkpoint additions. | Host consumers use public contracts; unavailable external profiles must not prevent cancellation. |
| Source admission, budgets, ownership, context validation and saved decisions | Preserve in Analyzer. | Host instructions do not become their enforcement mechanism. |
| Scanners, deterministic controller, validation and rendering | Reuse behind the engine boundary. | Rewrite or remove only a demonstrated dependency problem on the changed path; no whole-engine cleanup. |
| `--interactive-launch` and host-specific budget, worker and width defaults | Separate behavior from the general engine path, using existing profile/request facilities where possible. | One flag should not mix provider selection, legacy defaults, presentation and unattended execution. Preserve bounded execution and explicit budget semantics. |
| Deprecated budget aliases and `--component-workers` | Decide which published inputs still need compatibility. Translate retained aliases once at an explicit compatibility boundary. | Do not silently change numerical limits or reject a promised input. Removal requires a documented compatibility decision. |
| Start sequencing and progress monitoring in the skill | Move deterministic coordination into existing engine/host code; retain necessary questions and concise presentation. | Avoid a second scheduler, repeated model turns for polling, and host knowledge of private progress-file names. |
| Organization configuration | Keep validated ownership and effective policy. Use the existing engine configuration interface. | No additional profile-field migration without a selected consumer; no silent dropping or weakening of mandatory settings. |
| Separate show, ask, export, health, triage, diagnosis and repair skills | Group by user task when selecting the later public surface. | Fewer entry points may preserve the same functions. Deferring an internal milestone does not authorize deleting required functions from a release. |
| Baseline lifecycle | Retain its current adapter for this milestone. | Its extraction is independent work. |

## Implementation order

Complete these four work packages sequentially. Keep changes reviewable and commit after the required focused checks. Avoid a preliminary refactor that produces no usable workflow.

### 1 Select the boundary and split the checkpoint

Read the checkpoint and the relevant code diff, then identify which additions are reusable public operations and which encode historical host behavior. Check the current Analyzer implementation before adding an operation; status, progress, stop, results, export and validated result context already existed before the checkpoint.

Record a short disposition for the affected options and entry points in this plan or the existing inventory. Preserve business-context questions and answers, result history, saved decisions, required exports, diagnostics and recovery according to [requirements](../../../requirements.md). Existing [decisions](../decisions.md), including storage and the single deterministic control plane, remain binding. Show exact wording and a plain-language summary for confirmation before writing changed requirements or registered decisions. Propose any incompatible published interface change explicitly; do not infer approval from this planning request.

Integrate the useful Analyzer additions on a suitable development branch, reconciling current changes and preserving the isolated commit as evidence. Do not blindly cherry-pick the mixed checkpoint as the final design, import repository history again, overwrite concurrent work or alter existing release tags. If a product decision blocks one change, continue independent compatible work.

Completion: selected behavior and unresolved compatibility choices are explicit; the intended development branch contains the required public operations without losing subsequent Analyzer fixes. No new exhaustive ledger or architecture document is needed.

### 2 Simplify the primary host path

Use the existing Analyzer request/profile facilities to separate canonical execution settings from retained compatibility translations and display choices. Preserve the selected Claude execution path, explicit limits and unattended behavior. Reconcile profile precedence before moving defaults; a cleanup must not silently raise spending or change policy.

Consolidate deterministic preparation through the existing assessment-entry/controller boundary where it reduces real host sequencing. Reuse source admission, destination resolution, ownership checks, validated context and lifecycle code. The engine validates transitions and inputs; the skill gathers required user answers and presents outcomes. Add a new public operation or schema only if the existing boundary cannot express the needed interaction. Do not create a second orchestration system.

Keep host progress rendering separate from engine lifecycle. Consume public progress and holder data; the engine owns its internal feed location. A stopped or expired display must not stop the assessment. Result queries and exports reuse the existing validated readers and do not trigger another assistant or assessment.

Reduce the generated entry and its referenced instructions to the selected workflow. Remove duplicated option explanations and obsolete private-script references on this path. A primary invocation should not require loading a broad manual for unrelated workflows. Preserve byte provenance for retained engine-owned instructions and the pinned invocation binding.

Completion: one understandable path from host invocation to engine execution, with no host dependence on private run files and no model-managed retry or polling loop. Retained aliases have one translation point and the effective execution settings are inspectable.

### 3 Verify the installed workflow

Build clean committed engine and host inputs with the existing assembler, update the exact composition lock and install outside source checkouts. Reuse unchanged dependency artifacts and their existing verified digests. Build the next artifact after the selected source changes are ready; avoid repeated archive rebuilds for unrelated documentation edits.

Exercise the changed installed boundaries with the real pinned engine: invocation, configuration precedence, source/output admission, context handoff, progress, owner/display separation, stop, applicable resume behavior, and result query/export. Reuse completed-result fixtures for consumers that do not require a new model run. Cover a normal case, a neutral variant and representative refusal/failure cases for the changed mechanism, including preserved decisions where the changed path can affect them.

A controlled full assessment through the installed primary entry is still needed to establish the complete workflow. Obtain specific authorization for model spending or plan allowance before starting it. Reuse that run for the applicable lifecycle and result checks instead of paying for separate equivalent runs. Offline tests and a successful score command do not establish this evidence.

Completion: recorded source/artifact pins and focused installed evidence, with remaining live or native-platform gaps stated precisely. No public release claim follows from an internal Linux replay.

### 4 Extend only the selected surface and remove replaced paths

After the primary workflow works, address remaining user tasks in dependency order. For each, name the required behavior, public engine operation, host entry and old producer it replaces. Reuse query/export/diagnostic primitives before adding another command or skill. Add a missing operation only for a selected need.

Remove a legacy producer only when its callers are replaced and required behavior has evidence, or its removal has explicit product approval. Preserve results, history, accepted decisions and rollback inputs. A copied module is not removable merely because its name looks old.

Keep the existing Linux, macOS and native Windows scope, provider qualification, installation/upgrade/rollback, provenance and release gates. Run their required qualification when the corresponding release candidate or affected platform boundary is ready. Handle a known platform-specific implementation gap before claiming support; do not simulate support by relaxing controls. Keep unapproved live or release actions pending and complete independent offline work.

## Work and token limits

These constraints apply to the implementation session and the product work it performs.

- Read this plan, the checkpoint and applicable repository instructions first. Follow `check_specs.py` for each file before editing, then read only the relevant producers, contracts and consumers. Use bounded searches, diffs and excerpts rather than repeatedly dumping whole documents or repositories.
- Reuse the existing inventory and evidence. Record only changed decisions, new results and remaining blockers. Avoid parallel plans, repeated audits, cosmetic renames and generic abstraction work.
- Do not spawn agents unless the operator or applicable instructions explicitly request delegation. Batch independent reads; keep mutation and dependent work sequential.
- Keep updates short and tied to findings, decisions or blockers. Do not reproduce command output in prose or narrate routine tool calls.
- Keep parsing, validation, state transitions, progress polling and rendering deterministic. Do not introduce model calls to replace existing deterministic behavior or extra assistant sessions for result access.
- Load only the runtime instructions needed for the selected task. Avoid duplicate prompts and repeated progress events. Diagnose observed model/context cost before changing budgets or adding a cost-measurement subsystem; preserve necessary evidence and security checks.
- Do not broaden work solely to make the repository look clean. Stop when the selected behavior and required verification are complete.

## Required verification only

The repository's focused-check rule governs every package. Before each check, name the changed behavior, affected consumer or contract/security invariant it can exercise. If none applies, omit it even if routing selects it.

- Use `scripts/run_tests.py --list --path <changed-path>` as orientation, not an executable test plan. Prefer exact pytest node IDs. A stale Analyzer inventory is a routing gap to report, not permission to run the full suite or rebuild the whole inventory.
- Add tests only for changed behavior or a missing required regression. Reuse existing tests for unchanged behavior; do not duplicate implementations in assertions. Changed controls require intended and representative negative cases.
- Run lint and formatting checks only for changed Python files, respecting existing exclusions. For documentation-only changes, check only affected links, wording and contracts.
- Do not run baseline checks, full suites, coverage, whole groups, broad route audits or bundled targets for confidence. Do not rerun passed checks unless a later edit affects them. Follow the repository failure-only baseline procedure if a selected test fails.
- Replay a golden fixture if deterministic-tail or source-scanner behavior changes, as required by `AGENTS.md`; the planned host integration does not itself justify such a replay. Avoid changing test routes unless coverage ownership actually changes.
- Stage only task files, inspect the staged diff, then commit once required checks pass. Run no further checks after that commit unless a subsequent implementation change requires them.

## Session handoff

Start with work package 1 and proceed into compatible implementation after the new session is instructed to implement this plan. Do not stop after restating it. The immediate objective is a simplified installed primary workflow, not completion of every historical migration row.

At handoff or completion, report the committed revisions, retained compatibility decisions, required checks actually executed, installed evidence and the next unresolved dependency. Distinguish source implementation, installed integration, live qualification and public release. Keep the original checkpoint as historical evidence and add only the new evidence needed to explain the current state.


## Work package 1 disposition

The implementation session started from clean Advisor `dev` at `2aecaf71`. The isolated Analyzer checkpoint `3a3ac3a0` was merged with current original Analyzer `main` at `a189e75c` on the isolated `clean-composition` development branch. Both histories, including later assessment correction and completion-summary changes, are retained; the original working tree and release tags are unchanged.

| Boundary | Selected compatible treatment |
| --- | --- |
| Existing status, progress, stop, results, export and validated context | Reuse the current implementations. Retain checkpoint capability declarations, progress cursors, query and assessment-entry adapters. |
| `--interactive-launch` | Retain as a compatibility adapter; the new binding separates execution defaults, host, unattended mode and width. Equivalent inputs preserve the effective profile and snapshot identity. |
| Budget aliases and `--component-workers` | Retain all published aliases, USD 10/20/40 depth defaults, explicit hard-budget precedence, soft-budget conversion and 1–4 worker inputs. No incompatible removal is selected. |
| Source/output admission, context, ownership, history and accepted decisions | Preserve existing engine enforcement and storage. No controller, report or decision-store migration. |
| Host coordination and progress | Replace model-managed stop polling with bounded public-holder waiting. Let the engine choose its progress-feed location and let an expired display end independently. |
| Organization settings, baseline and other legacy workflows | Keep current validated dispatch and adapters; no additional fields, removals or public cutover. |

The changed producer path is the primary binding in `scripts/composition_runtime.py` and the host-default branch in Analyzer `appsec_analyzer/cli.py`: one compatibility flag previously combined settings, presentation and unattended behavior, while the skill named an engine-private progress file and instructed repeated model polling. Settings translation now belongs to Analyzer `assessment_entry.py`; the host selects presentation separately and uses public holder/progress responses. This preserves the existing limits and control plane without changing requirements or registered decisions. Installed evidence and remaining qualification are recorded after the committed source build.
