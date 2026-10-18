# AppSec Advisor clean composition implementation plan

Status: implementation checkpoint, 2026-10-18. Work packages 1 and 2 are implemented at source level; work package 3 has installed offline evidence, with live qualification pending. See [the current handoff](#current-session-handoff). The operator requested this plan and a session handoff after the [primary entry checkpoint](composition-offline-evidence-2026-10-18.md#primary-entry-source-checkpoint-and-operator-stop), with explicit instructions to avoid unnecessary work, tests and token consumption. This plan replaces the continuation order in that checkpoint. It does not approve feature removal, changed requirements or registered decisions, paid model runs, publication or public cutover.

Build a small plugin integration around the existing Analyzer. Reuse working packaging and analysis components, and remove avoidable coupling from the new integration before extending it. Existing code is not obsolete merely because it came from Advisor; preserve useful behavior and its controls. The immediate milestone is one installed primary workflow with public result consumers. It is an internal integration milestone, not a reduced replacement release.

## Starting point

Use committed revisions as references and inspect current branch state before editing. Concurrent work may have advanced since these observations.

| Component | Reference | Consequence |
| --- | --- | --- |
| Advisor | `acff74dd`, current `dev` at planning time | Primary binding exists in source; its new installed real-engine replay is pending. |
| Isolated Analyzer checkpoint | `3a3ac3a0b04c5baec284c85d21fab8bd0906ac8c`, based on `443243f6d259989f5c2d0765491e1c2a2b7e50a4` | Public operations and host compatibility were added together. Inspect and split their responsibilities before integration. |
| Original Analyzer | `a189e75cfcf22eaa9bddcf6bef4fb8f6cf59cd35`, `main` at planning time | Contains subsequent assessment and reporting work. Preserve it; do not replace this tree with the isolated snapshot or commit directly to `main`. |
| Handoff location | Isolated clone `/tmp/appsec-composition-engine`; bundle `/tmp/appsec-composition-entry-engine.bundle` | Temporary recovery inputs, not release artifacts. Verify availability and commit identity; preserve the commit in the intended development history during integration. |

The checkpoint records 25 focused Analyzer cases and 39 focused Advisor cases. They establish only their documented source behavior. Older installed score and configuration evidence belongs to its recorded pins. At planning time no primary-entry archive superseded the preceding configuration archive; the [final internal staging archive](#committed-implementation-and-installed-evidence) later did. Reuse evidence where its behavior and inputs remain applicable; never label the new primary entry qualified from those earlier checks.

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

## Proposed direction: lightweight host

Status: proposal recorded on 2026-10-18 at the operator's request; not approved. It approves no removal, marketplace cutover, model spending or changed requirement.

Target: Advisor keeps only assembly, branding, Claude interaction, display and the host adapters the [composition inventory](appsec-advisor-composition-inventory-2026-10-18.md) assigns to it. Analyzers, agents, schemas, data and portable skills come from pinned packaged components.

Measured state against engine wheel `50c0dedb`: the staging composition takes six host files from this repository. The repository still tracks the full engine tree, mostly as byte-identical copies of wheel members:

| Directory | Tracked files | Same path in wheel | Byte-identical |
| --- | --- | --- | --- |
| `scripts/` | 344 | 294 | 237 |
| `agents/` | 40 | 39 | 39 |
| `data/` | 71 | 64 | 62 |
| `schemas/` | 144 | 141 | 128 |
| `templates/` | 17 | 17 | 17 |

The marketplace entry still ships this repository tree, so its own `skills/appsec-analyzer` pipeline needs these copies until cutover. Removing them earlier breaks the published runtime.

Proposed order:

1. **Reproducible selection.** Commit the reviewed `unqualified-staging` lock and a build recipe that exports named committed revisions instead of reading working checkouts. Artifacts remain operator-supplied as the contract requires. Today the lock and build scripts exist only in the temporary artifact directory.
2. **Host gaps.** The staging composition delivers an empty `hooks/hooks.json` and no permission adapter. Decide per inventory row whether the host keeps the banner, steering, read/write gates, telemetry and permission setup, then supply each kept adapter through public engine operations.
3. **One owner per duplicated module.** `scripts/orchestrator/orchestration_controller.py` and `scripts/runtime/assessment_console.py` already differ from their wheel copies. The host bootstrap uses only the console's `render`; the console's own `follow` CLI imports `runtime.live_run_holder`, which the composition does not ship. Keep one owner and remove the other path at cutover.
4. **Directory disposition.** Classify every tracked file in the table as host-owned or engine copy. Each engine copy gets the removal condition "marketplace serves the composed build".
5. **Cutover.** After work package 3 has full-assessment evidence and the operator approves, switch the marketplace source to the composed build and remove the engine copies in one change, with rollback to the last tree-based release.

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

The implementation session started from clean Advisor `dev` at `ee631f5f`. The isolated Analyzer checkpoint `3a3ac3a0` was merged with current original Analyzer `main` at `a189e75c` on the isolated `clean-composition` development branch. Both histories, including later assessment correction and completion-summary changes, are retained; the original working tree and release tags are unchanged.

| Boundary | Selected compatible treatment |
| --- | --- |
| Existing status, progress, stop, results, export and validated context | Reuse the current implementations. Retain checkpoint capability declarations, progress cursors, query and assessment-entry adapters. |
| `--interactive-launch` | Retain as a compatibility adapter; the new binding separates execution defaults, host, unattended mode and width. Equivalent inputs preserve the effective profile and snapshot identity. |
| Budget aliases and `--component-workers` | Retain all published aliases, USD 10/20/40 depth defaults, explicit hard-budget precedence, soft-budget conversion and 1–4 worker inputs. No incompatible removal is selected. |
| Source/output admission, context, ownership, history and accepted decisions | Preserve existing engine enforcement and storage. No controller, report or decision-store migration. |
| Host coordination and progress | Replace model-managed stop polling with bounded public-holder waiting. Let the engine choose its progress-feed location and let an expired display end independently. |
| Organization settings, baseline and other legacy workflows | Keep current validated dispatch and adapters; no additional fields, removals or public cutover. |

The changed producer path is the primary binding in `scripts/composition_runtime.py` and the host-default branch in Analyzer `appsec_analyzer/cli.py`: one compatibility flag previously combined settings, presentation and unattended behavior, while the skill named an engine-private progress file and instructed repeated model polling. Settings translation now belongs to Analyzer `assessment_entry.py`; the host selects presentation separately and uses public holder/progress responses. This preserves the existing limits and control plane without changing requirements or registered decisions. Installed evidence and remaining qualification are recorded after the committed source build.


## Committed implementation and installed evidence

Work packages 1 and 2 are implemented at source level. Advisor commits `1d5f62f5` and `e2e64c12` separate primary execution defaults, presentation and deterministic stop waiting. Analyzer commit `50c0dedb283829956c04abfbcd3254e0a292b71b` on `clean-composition` contains the merged checkpoint and subsequent `main` work; the original Analyzer repository now also retains it on local `dev`, without changing its checked-out `main`, working files or tags. No requirements or registered decisions changed. No legacy producer was removed.

The engine now resolves the default feed under a canonical private output, refuses source-owned paths, linked feed files and an existing live holder, and retains explicit progress selections. This prevents the new automatic feed from introducing an unvalidated write before the retained controller's admission. The regression covers regular output, explicit selection, source-owned output, symlinks, hardlinks and a live holder. Canonical launch defaults and the retained adapter produce identical effective profiles and profile fingerprints across all depths, soft-budget conversion and explicit hard-budget/worker selections. This proves profile compatibility, not cross-version runtime resume.

| Final internal staging input/output | Recorded value |
| --- | --- |
| Advisor source | `e2e64c12b58164798c30f8c1478c556c59993f8a` |
| Analyzer source | `50c0dedb283829956c04abfbcd3254e0a292b71b` |
| Host ZIP SHA-256 | `e73a00693c0e9d06395efe90f5e77685b5f39663ee4d78043ac6fb5c56430c45` |
| Engine wheel SHA-256 | `5b6acf9e2caf60e0748559daf27e6b29b016f015ce987820d5235fe0990a4783` |
| Selection lock SHA-256 | `501305ab9cfb47de4c1408179b1604e65288698c7f3a5f769b8bf7e55ab76ad2` |
| Branded tarball SHA-256 | `4599e17ce7b96e99c4152f95d5011f959794f3fc685d3ac68fafd0d0ae1ec137` |
| Artifact directory | `/tmp/appsec-clean-composition-staging`; final archive under `dist-final/review-appsec-1.0.0-internal.tgz`, exact selection in `components.lock.json`, observations in `evidence.json` and named stdout/stderr files. |
| Installed replay | `/var/tmp/appsec-clean-composition-installed/installed plugin`, with a fresh sibling runtime; CPython 3.10, Linux x86_64. |

Clean committed exports produced the wheel and host payload. The final assembly reused that wheel and host payload after the generated invocation gained its explicit wait command; selected host bytes were compared to the final host revision. Portable skills and dependency wheels retain the preceding lock's exact digests. Build used existing local build `1.2.2.post1`, setuptools `59.6.0` and wheel `0.37.1`, without isolation downloads. This is not a locked release-build provenance claim. Assembly and organization packaging retained exact engine-owned instructions, component ownership and original source metadata. Installation used the existing offline hashed-wheel bootstrap with read-only plugin payload files; no sibling source checkout supplies engine implementation at runtime.

Twenty-two distinct focused Analyzer cases and 24 distinct focused Advisor cases passed. They cover the changed settings translation, retained aliases, profile identity, automatic feed destination/refusals, public-holder waiting, explicit width, exit forwarding, unchanged progress display, unavailable-profile consumers and generated-entry provenance/admission. Ruff lint and format checks passed on all seven changed Python files. Changed document targets exist. The inherited Analyzer test router still refuses its stale inventory; exact selectors came from the changed consumers. No route or inventory was edited, and no broad suite, coverage, golden-tail replay or route audit ran. No deterministic-tail or source-scanner behavior changed.

The 44 installed observations cover explicit setup/preflight, bound invocation and capabilities, packaged/preset/CLI/environment precedence, USD limits and worker aliases, provider-switch refusal, two neutral source/context layouts, retained context, source-owned output and untrusted-link refusal, public holder/progress cursors, display expiry without owner cancellation, bounded waiting, public stop, live/stale cleanup, retained state/cache bytes, saved results/query/summary, Markdown/YAML/SARIF/Threat Dragon/pentest-task exports, tampering refusal and two old-engine rejections of the new canonical selection. Delivered payload hashes remained unchanged. Result consumers reused the committed quick-run model with the existing test-state envelope; no report or production receipt was fabricated to claim assessment completion.

The lifecycle fixture was a controlled sleeping Python child, not an assessment controller. Public stop signalled it successfully; its unreleased fresh heartbeat correctly kept `wait` at exit 3. The harness initially expected exit 0 and stopped; the observation is retained as conservative refusal. Only the unexecuted tail continued after explicitly constructing stale test data, exercising public cleanup, and observing exit 0 for the released output. State and cache sentinels survived; this does not establish real accepted-job resume or controller shutdown. A new unit test also initially named Python's built-in exception instead of the bootstrap's exception; that assertion was corrected and only its failing case reran. A mistyped selector and wrong-working-directory lint invocation did not execute their intended checks; the corrected checks passed. No behavioral failure was waived.

Work package 3 remains incomplete until a specifically authorized full assessment exercises the installed primary entry and its applicable stop/resume/result lifecycle. No model spending was authorized or performed. Work package 4's replacement/removal prerequisite is therefore not met; remaining legacy tasks, hooks, diagnostics and recovery retain their current producers. Native macOS/Windows, provider qualification, upgrade/rollback, complete build provenance and release gates remain open. This final archive supersedes the preceding configuration-only archive for this internal Linux offline surface only; it is neither live workflow qualification nor a replacement release. No push, publication or public runtime switch occurred.


## Current session handoff

At the status-documentation request, Advisor `dev` was clean at `8eac23b0`; the implementation commits are `1d5f62f5` and `e2e64c12`, and `8eac23b0` records their installed evidence. The artifact pins above intentionally identify `e2e64c12`, not later documentation-only commits. Original Analyzer `dev` retains `50c0dedb`; its working tree was then on `main` at `a189e75c`. Later Analyzer work moved the checkout to `dev`, which still contains `50c0dedb`, while `main` stays at `a189e75c`. No reset, checkout or merge into `main` is needed to resume.

The exact selection, final archive and `evidence.json` listed above were still present when this handoff was written. They are temporary local evidence, not published or durable release artifacts. The replay used two scripts, `replay.py` and `continue-replay.py`, in the artifact directory because the initial harness stopped at the conservative fresh-lock refusal. The combined observations are in `evidence.json`; do not treat the first script alone as a passing full replay or rerun either script against its already populated directories.

Resume at work package 3's missing full-assessment evidence. Read the committed pins and existing observations, inspect current branch state for concurrent work, and obtain specific authorization for the selected target and finite model budget or plan allowance before any model-backed invocation. Exercise the installed primary entry and use that same authorized run for applicable real-controller progress, stop/resume and final result checks. Existing profile-identity tests and the sleeping-child fixture do not establish those lifecycle behaviors. If new implementation becomes necessary, change its producer and run only the newly required checks; reuse all unaffected evidence.

Model spending, publication, public cutover and incompatible interface removal remain unauthorized. Work package 4 must not remove a legacy producer before its replacement has the required evidence or explicit product approval. No new inventory, framework, broad test run or archive rebuild is needed merely to continue from this documentation checkpoint.
