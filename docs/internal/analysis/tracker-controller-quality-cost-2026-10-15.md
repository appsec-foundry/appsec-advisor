# Single-repository controller: quality, cost and runtime tracker

Status: Open, started 2026-10-15. This is the working record for bringing the headless single-repository controller (`APPSEC_SINGLE_REPO_CONTROLLER=1 scripts/run-headless.sh`) back to the cost, runtime and report depth of the previous controller. Update the status column and the measurement table with every change; a new session continues from here.

## Goal

Juice Shop once cost about USD 10 and finished quickly. The headless controller raised cost and runtime and produces a thinner model than the reference run of the previous controller. Each item below names its producer, the violated invariant and a fix at that producer, never in the rendered report.

## Measurements

Juice Shop checkout `/home/mrohr/juice-shop` at revision `33518f5`, standard depth, Sonnet 5.5, `--soft-budget 16 --rebuild`, unless stated otherwise. The reference model and report of the previous controller lie in `/home/mrohr/juice-shop2/docs/security`; compare new runs against it. Run directories under `/tmp` do not survive a reboot; the numbers here are the record.

| Run | Plugin state | Status | Runtime | Cost | Calls | Findings | Unresolved targets | Notes |
|---|---|---|---|---|---|---|---|---|
| `/tmp/124` | before `28537f56` | complete | 72.7 min | USD 12.84 | 124 | 74 | 18 (`server.ts` 458–667) | STRIDE USD 7.49 / 29 calls; evidence verifier USD 1.90 / 38 calls |
| `/tmp/125` | `28537f56` | complete | about 70 min | USD 13.45 | 125 | 81 | 4 | STRIDE USD 7.45 / 39 calls, 39 min call time; evidence verifier USD 2.07 / 24 calls, 12.5 min; Angular 15 STRIDE jobs (9 before) |
| Reference `/home/mrohr/juice-shop2/docs/security` | previous controller | complete | | | | 79 | | same Juice Shop revision; thorough depth and Opus: a confound for every comparison |

Comparison of `/tmp/124` with the reference: confirmed-exploitable / insecure-practice 22 / 52 against 67 / 12; Figure 1a "threats in the model" 26 against 67; data flows 8 against 19; findings with `attack_steps` / `mitigation_title` / `actor_ids` 2 / 20 / 20 against 15 / 79 / 62. The merge loses only 4 of 97 findings (3 refuted).

## Root causes

| ID | Status | Symptom | Cause | Fix |
|---|---|---|---|---|
| RC-A | Done (`28537f56`) | 18 route targets in `server.ts` unresolved | A route was decided at its registration line, not in the component that owns its handler; scanner leads on registration lines became own targets; cited context was not preloaded | Route targets follow handler ownership, registration windows and templates are related reads (MR-13); leads join their route decision; STRIDE and evidence jobs preload cited lines |
| RC-E | Done (`28537f56`) | `surface_coverage` output volume | Every coverage decision carried a reason and evidence | MR-11: a decision that links a finding needs no reason; others at most 160 characters |
| D-1 | Done (`28537f56`) | Security Architecture re-rendered for a quoted CORS origin | URL check also applied inside inline code | MR-14: URLs allowed only inside inline code spans |
| RC-H | Implemented (MR-15), pending commit | Same blank-line citation (`login.component.ts:93`, real 101–104) rejected in every Angular STRIDE job | Source slices reached the model as unnumbered line arrays (`runtime/multi_repo_scope.py` `read`), so models counted and drifted deep in a file; `validate_controls` lacked STRIDE's executable-line check, so a bad control citation was inherited | `assessment_host.read_slice` numbers every served line; `multi_repo_analysis.validate_executable_evidence` runs last in every evidence-citing role with an anchor-only correction (MR-2). Evidence: controls cited blank lines in about 11 % of citations in both runs; replay 4/182 bad citations unnumbered, 0/170 numbered |
| RC-I/J | Implemented, pending commit | Angular: one component-wide finding repeated 7 times (`/tmp/124`) and 15 times (`/tmp/125`); 15 jobs instead of 9 | Every target job received the whole component context and, since `28537f56`, its preloaded lines, which also shrank every job's target room | Only the first job of a split component carries the context lines and reports what only the context shows (`target_batches` `reserve_bytes`/`reserve_windows`). Replay: 15 to 11 jobs. Soft rule for later jobs, not enforced: a hard anchor rule could drop legitimate findings |
| RC-D | Decided (MR-16, 2026-10-15), implemented, pending commit | STRIDE and evidence review run strictly serially: 52 of about 70 minutes | `DiscoveryBudget` holds one reservation and a global `failed` flag (`runtime/multi_repo_discovery.py` `_invoke_once`); OR-5 covers only the session path | Run up to four components concurrently with per-call reservations under a lock; ordered results, receipts and notes |
| RC-K | Open | 4 targets unresolved in `/tmp/125` | Related reads miss guards and helpers: `app.use('/rest/user/authentication-details', security.isAuthorized())` at `server.ts:398` lies outside the related window 400–799 of the route at 601; helpers in `lib/insecurity.ts` belong to another component | Related ranges include every guard registration of the same path; decide how a target may read a helper owned by another component |
| F1 | Open | Admin actor missing in Figure 1a | `reconcile_privileged_roles` runs only on the session path (`orchestration_controller.py` `_bind_finalized_component_fingerprint`); the controller runs actor discovery after architecture, and the discoverer read no source | Reconcile privileged roles after controller actor discovery, or discover actors before architecture; derive privileged evidence deterministically from the route inventory and `source_auth_scanner` |
| F2 / RC-F | Open | No authentication variants on the application layer; 8 flows against 19 | One architecture job per repository with 12 reads never read `login.ts`, `2fa.ts` or `insecurity.ts`; no deterministic producer turns the route inventory (111 routes with `authn_handler_scheme`) into client flows; `egress_clients.py` excludes same-origin calls | Deterministic emitter: one client-to-handler-component flow per authentication scheme with `access_group` |
| F3 | Open | No markers on the data layer | Store markers come only from `stored` assets with `linked_threats` (`figure1_dfd.py` asset badges); the controller run produced two generic assets because the architecture job read no model files | Propose stored assets deterministically from ORM models and store evidence, or preload model files |
| F4 / RC-G | Open, partly decision | Figure 1a header 21 instead of 67; 62 of 81 findings `insecure-practice`; 66 of 96 findings without `actor_ids`; no capability pills | `merge_threats.py` downgrades every `ambiguous` review to `insecure-practice`; STRIDE jobs return 127 of 149 findings as practice; `multi-repo-discovery.schema.json` components carry no `deployment_zones` or `capabilities`, so `actor_attribution` finds no zone; `mitigation_title` missing from the controller STRIDE schema; `attack_steps` not required for Critical | Decide whether `ambiguous` downgrades on both paths alike; carry or derive zones and capabilities; add `mitigation_title`; tier gap needs a same-configuration run |
| D-3 / F5 | Open | Figure 1a legend: empty middle | `figure1_dfd.py` `_place_legend` puts all spare width into one gap: 1125 px gives 2 columns with a 385 px gap | Flexible block width, so three columns fit; geometry test bounding the gap |
| D-2 | Open | `../../ftp/legal.md` split into `../..` and code | `compose_threat_model.py` `_codify_inline_identifiers` | Keep relative paths whole |
| RC-B | Open | Titles keep `(login.component.ts:93)` after the anchor moved to 101 | The model writes the path bracket and `sha256`; the full contract is checked before `normalize` (`runtime/assessment_host.py`) | Controller sets the bracket for single-anchor findings with a model-facing schema; removed constraints move into instructions |
| RC-C | Decided: measure later | Field-level correction (MR-2) | | Re-measure after RC-A and RC-B |

Further observations, not yet checked: `tier_root_causes` exceeded `maxItems` 5 in call 0121; the CLI output cap of 32k for Sonnet 5.5 is unverified (maximum seen 30,883); the LLM-surface warning about `llmApiUrl` is plausible but unchecked.

## RC-D implementation plan (MR-16)

- `DiscoveryBudget` (`runtime/multi_repo_discovery.py`): a lock and condition guard `calls`, `spent_usd` and an in-flight count. `failed` becomes "a call is in flight or a cost is unsettled", which the checkpoint persists as unavailable accounting exactly as today; the retry and replacement decisions (`invoke`, `AssessmentJobs.exchange`) read only the unsettled part, otherwise a concurrent call would block every retry. A call whose ceiling exceeds the budget left after running reservations waits for a settlement while others run; with none running, today's smaller ceiling or exhaustion applies. The per-call reservation used by the timeout retry becomes thread-local.
- `AssessmentJobs` (`runtime/assessment_jobs.py`): checkpoint writes, `timing` and the inherited-receipt charge run under a lock; each component works on a child view with its own `notes` and `gaps`, joined in component order.
- `_assessment_stride` (`orchestrator/orchestration_controller.py`): the per-component body (targets, STRIDE jobs, evidence review) moves into a function run by a pool of four workers; documents, reviews and notes are collected by component position. The first failure stops new submissions through `should_stop`, waits for running jobs and re-raises, so resume keeps every accepted receipt.
- Host event files are numbered by a shared `itertools.count` (`_assessment_cli_host_factory`), which stays unique across threads.

## Open decisions

- **`ambiguous` review verdict:** keep the downgrade to `insecure-practice` on both paths, or neither.
- **Comparison run:** standard plus Sonnet for the effect of each fix; thorough plus Opus for a fair comparison with the reference.

## Order of work

1. Commit RC-H and RC-I/J after the affected controller modules pass.
2. RC-D as decided in MR-16.
3. F2/RC-F, F1, F4 zones and capabilities, D-3, F3, then RC-K, RC-B, D-2.
4. One measurement run with the `/tmp/124` configuration; record it in the table above.
