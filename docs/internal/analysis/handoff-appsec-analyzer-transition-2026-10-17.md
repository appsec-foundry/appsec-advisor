# Handoff: legacy retirement and appsec-analyzer transition

Status: open, 2026-10-17. Working record for the transition described in [the security assessment concept](../../proposals/application-security-assessment-concept.md). Target release 0.6.0-beta.5; the release happens only after the operator approves the completed work. Nothing is pushed; the tag `archive/create-threat-model` is local only.

## Done

| Commit | Change |
|---|---|
| `2d55fa1b` | Controller writes the `.gitignore` rule for a report folder in the checkout before admitting its source |
| `785c7e94` | Free-text focus is refused instead of dropped |
| `6368a4b6` | The controller skill has its own business-context dialog file |
| `a99bf64a`, `9872b1b7`, `4ab5f8ce` | `create-threat-model2` became `create-security-assessment`, then `appsec-analyzer` |
| `ff195737` | Session action protocol removed from the controller (12,331 → about 4,800 lines) |
| `6b87f4c3` | 33 legacy-only scripts removed |
| `a1c8984d` | Agents fragment-fixer, qa-reviewer, config-scanner and context-resolver removed; context template moved to `templates/threat-modeling-context.md` |
| `21d32256` | `run-headless.sh` sends every assessment to the controller; without `--repo` the current directory is the repository |
| `a886d531` | `skills/create-threat-model/` removed; `appsec-analyzer` is the packaged required skill, banner and status command |
| `96f43cda` | Seven protocol-only schemas removed |
| `9d299be8` | REQ-TRU-002 guarded at `redact_known_secrets.py`; `postscan_secret_check.py` removed |
| `44014dec` | Decisions `OR-7`, `CE-5` and `IN-3` retired, `OR-1` reworded for controller-launched roles (operator-approved, `specs/changes/retire-session-protocol-decisions/`) |
| `34099dcb` | `REQ-USE-004` keeps only history preservation, `REQ-FLW-009` promises refusal of a narrowed focus (operator-approved, `specs/changes/drop-incremental-and-focus-promises/`) |
| `b0409fd9` | A new scan over a completed assessment needs no `--rebuild` and continues its changelog; `--rebuild` resets it (operator chose this over "every rerun starts over") |
| `921c299e` | Lost guards replaced: a new controller guard for REQ-MOD-002 (weaknesses regrouped after ranking); existing controller-path tests bound to REQ-BIZ-010, REQ-FLW-006, REQ-MOD-004, REQ-PUR-001. REQ-BIZ-005 needed none: its controller guards cover the dialog handoff, same-run use, unsafe saves and kept context; the two-question limit is dialog prose only |
| `e7e8aee6` | Incremental reconciliation removed from the model builder with its tests and routes (unreachable: the controller always writes `mode: full`) |
| `384c513e` | Legacy resolver CLI removed: `main()` with its summary, run-plan and routing renderers, the incremental mode rules, the incremental business-context note and their baseline readers, the legacy single-repository guard against a combined prior model, and the builder's `_output_mode`. `resolve()` stays because `resolve_assessment()` resolves each admitted root through it; it now always sets `mode: full`. Resolver tests resolve in-process instead of running the script |
| `0d7622de` | Incremental flow-ID preservation removed from the trust-boundary input builder (ran only for `incremental`, which no producer sets) |
| `c8b8a0ec` | B: consumer skills renamed to `ask-`, `show-`, `export-`, `eval-security-assessment`, `triage-security-assessment` and `security-assessment-health`, without aliases; internal script, schema and storage names unchanged |
| `1875cc34`, `ad5b7913` | B: `update-threat-model` and `publish-threat-model` removed with the publish helper, its tests, route and `.gitignore` edit permission; the completion notice points at the export skill; `REQ-USE-007` is bound as an advisory to the export skill |
| `b072dc57` | B: every remaining `create-threat-model` mention in code, prompts, schemas and the requirements caller ID names `appsec-analyzer`; `--rerender` hints point at `--resume` or a new run; the golden report's invocation row was re-blessed after a replay showed it as the only markdown drift |
| `09a63952` | `REQ-PUR-004` names the assessment report; new `REQ-TRU-005` (results outside the repository by default, readable only by the current user) and decision `AS-1` (per-application destination `<repo-name>-<hash8>` under the user data directory, `--output` overrides), both advisory until C lands (operator-approved, `specs/changes/store-assessments-outside-the-repository/`) |
| `a88ab2fc` | C1: `scripts/shared/assessment_location.py` resolves `<base>/<repo-name>-<hash8>` (XDG/macOS/Windows base, normalized remote or canonical root) and creates it private, refusing symlinked, foreign or group-readable levels |
| `d14e9290` | C1: `scripts/shared/artifact_names.py` maps internal `threat-model.*` to published `security-assessment.*` and finds the one set a directory holds (both sets → `ArtifactSetError`); `locate()` and a CLI (`destination`, `locate --repo`) for skills; query and overview tools read either set |
| `67dd6b92` | C1: triage, health, status, baseline, eval, check_state and the agent logger read either set; cleanup knows the published product names |

Operator decisions taken in this work: incremental updates dropped for now; free-text focus refused; rerender and the QA reviewer not rebuilt; legacy agents removed and `config_scanner_model` / `context_resolver_model` accepted without effect; main skill named `appsec-analyzer`; consumer skills keep the `*-security-assessment` names from the concept.

Decisions taken without asking, following the concept and the code: old skill names in `skill_toggles` or a package policy fail validation as unknown names, which is the migration signal (no rename map); `publish-threat-model` is removed in B as the concept requires, although the open list had not named it; the requirements caller ID `create-threat-model` is renamed, so the reserved name stays free; `resolve()` stays as the per-root resolver of `resolve_assessment()` (the handoff had called it caller-less); output keys only the legacy skill printed (`mode_label`, `baseline_state`, `post_summary_note`, `preflight_status`) are no longer emitted.

## Open, in order

1. **C: artifacts and storage.** Order, so every commit keeps working: readers accept both sets (done for the tools above), then publication writes the new names, then the default destination moves, then the migration. Remaining steps:
   - **C2 publication.** The private workspace keeps the internal `threat-model.*` names; only publication renames. Planned edits, not committed yet:
     - `data/sections-contract.yaml`: both `title_template` values become `Security Assessment Report — …` and, for the `full` set, `Security Assessment Report - …` (it keeps its hyphen).
     - `compose_threat_model.py`: `_render_title` adds a focus line before the "Generated by" line: `_Analysis of security architecture, threats, and requirements implementation_` when `ctx.eval_context["check_requirements"]`, else `_Analysis of security architecture and threats_`.
     - `_figure_basename_for_md` returns `artifact_names.published_name(...)`, so figures and their links already carry `security-assessment.figure*`.
     - The visible prose that names `threat-model.yaml` / `threat-model.md` uses `artifact_names.MODEL` / `REPORT`: compose posture banner, trust-boundary rows, architecture TOC note; pregenerate "Not assessed" and "No assets enumerated".
     - Controller `_assessment_publish`: staging and output use `published_name()`, `staging / MODEL` for the yaml, published basenames in `_YAML_DERIVED_EXPORTS` and the PDF/HTML table (input `staging / REPORT`), and `_ASSESSMENT_PUBLISHED` lists `threat-model.md` plus `security-assessment.figure*.svg`.
     - Also: `stamp_threat_model.py` prefixes; `_assessment_artifacts` names; `_completion_step_rows` (`security-assessment.sarif.json`); `_assessment_gate_violations(model_path(scope.output))`; `AssessmentState._earlier_history` checks `MODEL` and the legacy name.
     - When the output directory held a legacy set before publication, remove only the fixed legacy product names after installing the new set. That keeps the overwrite that `test_docs_security_keeps_foreign_files_and_overwrites_a_legacy_report` guards; update its assertions and `test_a_new_scan_continues_the_history_and_a_rebuild_resets_it` to the new names.
     - Then re-bless the golden markdown via `scripts/threat_fixture.py replay` (expect title, focus line, figure links, prose names) and update tests pinning `Threat Model -` titles or `threat-model.figure` names.
   - **C3 destination.** `appsec-analyzer` skill and `run-headless.sh` take `assessment_location.py destination --repo` unless `--output` is given. The controller calls `private_directory()` when the output lies under `data_base()`, and runs with umask `077` so files are `0600`. Consumer skills (ask, show, triage, export, health, abuse-cases, analyze-threats) use `locate --repo`. Also switch the session banner discovery, `appsec_status`, `security_steering`, `hooks/progress.tsx`, `resolve_abuse_cases.THREAT_MODEL_FILE`, `aggregate_threat_summary`, `appsec-analyst-cli`, and the export defaults (`DEFAULT_INPUT_REL`). Add `<base>/appsec-advisor/**` to `data/required-permissions.yaml`. Repository-owned inputs stay in the checkout: `load_business_context.REPO_RELATIVE` and `assessment_context.LOCAL_CATALOG_PATHS` already read `docs/security/` in the repository, not the output directory. Verify the dialog save target too.
   - **C4 migration.** Interactive offer once; headless stops without `--migrate-legacy` / `--ignore-legacy`; import only a completed legacy set with history and triage; keep the old files.
   - When C lands, bind guards to `REQ-TRU-005` and `AS-1` (e.g. `tests/test_assessment_location.py`) and lift their coverage from advisory.
   - Remote URL normalization for the `AS-1` hash, decided without asking: strip user information, scheme and port, lowercase the host, drop a trailing `.git` and `/`, and treat `git@host:path` like `https://host/path`, so clones over SSH and HTTPS share one assessment.
2. **Documentation.** `docs/headless-mode.md`, `docs/threat-modeler.md`, `docs/model-selection.md`, `README.md` and `docs/internal/contracts/context-routing.md` still describe the legacy skill, its modes and flags; skill names are already current. Rewrite them after C so paths change once. `APPSEC_TELEMETRY_STRICT` is read by no script any more but still appears in `agents/shared/logging-standard.md`, `docs/internal/runbooks/acceptance-cohort.md` and `scripts/live_canary.py`.
3. **Changelog** for the user-visible changes, after C.
4. **Legacy remnants** (found on the way; none blocks C).
   - `build_parser()` still accepts legacy-only flags (`--incremental`, `--rerender`, `--dry-run`, `--clean-cache`, `--max-resumes`, `--pr-mode` and others), and `detect_conflicts()` still checks pairs among them. The controller refuses most of them by token before resolution (`_ASSESSMENT_UNSUPPORTED`); check what still reads each before removing it.
   - `DEPTH_PARAMS.max_repair_iterations` has no reader since the legacy re-render loop went.
   - `schemas/orchestration-action.schema.json` belongs to the removed action protocol but still feeds two vocabulary drift tests, `_MAX_ACTION_REASON` and `CONTEXT_V2_ARTIFACT_SCHEMA_VERSIONS`.
   - `check_state.py` (`needs_stage2`) and `recommend_fixes.py` (inline-shortcut and QA re-render plans) still diagnose legacy session states the controller never writes.
   - The trust-boundary input schemas still require `incremental` (always false); `_flow_identity` survives only for its own test.
   - Tests keep constants that point into the deleted `skills/create-threat-model/` (`test_lazy_phase_group_loading`, `test_qa_depth_profile`, `test_reasoning_model_resolution`, `test_runtime_cleanup`); `tests/e2e/run-repair.sh` still drives `--rerender`; the bug-report template names the removed `appsec-qa-reviewer`.
   - Unverified: whether a single-repository controller run refuses an output directory that holds a combined model. The removed resolver guard only ran on the legacy path.
   - `docs/internal/analysis/proposal-depth-downgrade-incremental-preservation.md` describes the removed reconciler; keep it as a dated analysis.

## Known state

- `tests/test_run_tests.py::test_modules_on_the_golden_fixture_replay_route_to_it` fails on a clean `HEAD` as well (`scripts/shared/_remote_url.py` lacks the `test_threat_fixture` route).
- `tests/test_context_routing.py::test_catalog_runtime_bindings_and_schemas_are_packaged` cannot run in the sandbox: it copies dot files the sandbox denies.
- The golden replay's `yaml` stage drifts (`project_name`, `project_description`, `repo_url`, `runtime` missing) on the pre-session commit `9337bd14` as well; `md` and `sarif` replay clean.
- `CHANGELOG.md` carries an uncommitted edit from another session; never stage it with this work.
- Other sessions commit documentation to `dev` in parallel; check `git log` before any history operation. Never `git commit --amend`: a parallel commit can land between a commit and its amend (it happened once and was repaired with `ad5b7913`).

## Working rules the operator set

- Run only the checks a change requires, and name what each one exercises. No broad module sweeps and no `make audit-test-routes` for small route additions.
- Verify reported gaps against the code before fixing them; the legacy inventory overstated several (secret check, requirements check).
- Prune tests at function or method level; never delete a class or helper because one member referenced removed code. Check module-level imports of deleted modules too.
- Stage explicit paths; `git rm` leaves deletions staged for the next commit.
