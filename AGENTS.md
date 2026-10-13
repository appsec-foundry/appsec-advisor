# AGENTS.md

This file maps repository work to its contracts, change workflow, and verification gates.

`appsec-advisor` is a Claude Code plugin for code-derived STRIDE threat modeling. Its main user-facing skill is [create-threat-model](skills/create-threat-model/SKILL.md). Agents handle discovery and prose. Deterministic Python owns validation, rendering, exports, orchestration, and release gates.

## Contracts

- [requirements.md](requirements.md) contains stable product behavior a user relies on.
- [Requirement bindings](data/requirement-bindings.yaml) map each requirement to affected paths, decisions, documents, and exact test evidence.
- The [decision register](docs/internal/decisions.md) records costly or non-obvious technical choices and their guards.
- [Schemas](schemas/) and data files define artifact shapes, values, limits, and vocabularies. Code defines algorithms and runtime sequencing; tests guard behavior and drift.

Before changing a file, run `python3 scripts/check_specs.py --for <path>` with its repository-relative path and read every returned requirement, decision, and referenced contract. Change the normative requirement first only when the product promise must change. Technical binding maintenance is ordinary reviewed implementation work.

Before writing a new or changed requirement or decision, show the operator the exact wording together with a plain-language summary of what it promises or settles, and write it only after the operator confirms both. This agent workflow also applies to new decisions that `check_specs.py --changed-against` permits without a proposal; that structural check does not establish operator approval.

### Change map

Use these entry points to find the applicable contracts. [scripts/run_tests.py](scripts/run_tests.py) and the requirement bindings identify candidate tests; select only those required by the actual change as described under Verification.

| Change area | Entry points | Decisions |
|---|---|---|
| Agent definitions and tools | [Agents](agents/), [agent definition tests](tests/test_agent_definitions.py) | `OR-1`, `OR-2` |
| Report structure and fragments | [Section registry](data/sections-contract.yaml), [schemas](schemas/), [schema invariants](docs/internal/contracts/schema-invariants.md) | `RA-*`, `RN-*` |
| Runtime routing and depth | [Config resolver](scripts/runtime/resolve_config.py), [model selection](docs/model-selection.md) | `MD-*`, `DT-*`, `DP-*` |
| Orchestration and retries | [Controller](scripts/orchestrator/orchestration_controller.py), [action contract](docs/internal/contracts/orchestration-actions.md) | `OR-*`, `ST-*` |
| Context routing and budgets | [Routing contract](docs/internal/contracts/context-routing.md), [catalog](data/context-routing-catalog.yaml), [bindings](data/context-routing-bindings.json), [budgets](data/context-budgets.yaml) | `CR-*`, `CE-*` |
| Severity, CVSS, and evidence | [Severity caps](data/severity-caps.yaml), [CVSS eligibility](data/cvss-eligible-cwes.yaml), [schema invariants](docs/internal/contracts/schema-invariants.md) | `FE-*`, `WK-*` |
| Report prose and references | [Prose style](agents/shared/prose-style.md), [schema invariants](docs/internal/contracts/schema-invariants.md) | `RA-*`, `RN-*` |
| Cleanup and preserved state | [Cleanup whitelist](docs/internal/contracts/cleanup-whitelist.md), [audit artifacts](docs/internal/contracts/audit-artifacts.md) | `RA-6` |
| Permissions | [Required permissions](data/required-permissions.yaml), [permission tests](tests/test_check_permissions.py) | See applicable bindings |
| Target-specific fixture data | [Target vocabulary](data/test-target-vocabulary.yaml), [neutrality checks](tests/test_check_target_specificity.py) | See applicable bindings |
| Organization packaging | [Profile schema](schemas/org-profile.schema.yaml), [profile invariants](docs/internal/contracts/org-profile-invariants.md) | `EX-*` |
| Plugin distribution | [Marketplace manifest](.claude-plugin/marketplace.json), [installation steps](README.md#1-install-the-plugin) | See applicable bindings |
| Secure-coding baseline | [Baseline scripts](scripts/baseline/), [configuration](config.json) | See applicable bindings |
| Run state and liveness | [Status runbook](docs/internal/runbooks/checking-run-status.md), [status helper](scripts/runtime/appsec_status.py) | `ST-*` |
| Runtime cost and telemetry | [Cost model](docs/internal/cost-model.md), [logging standard](agents/shared/logging-standard.md) | `OR-*`, `MD-*`, `ST-*` |
| Repair | [Repair implementations](scripts/repairs/), [action contract](docs/internal/contracts/orchestration-actions.md), [schema invariants](docs/internal/contracts/schema-invariants.md) | `RP-*`, `RN-*` |
| Exports | [Export skill](skills/export-threat-model/SKILL.md), [Threat Dragon guide](docs/threat-dragon-export.md), [schema invariants](docs/internal/contracts/schema-invariants.md) | `EXP-*` |
| Abuse cases | [Technical cases](data/abuse-cases/technical.yaml), [business cases](data/abuse-cases/business.yaml), [case schema](schemas/abuse-cases.schema.yaml), [business-case configuration](docs/org-profiles.md#business-abuse-cases) | `AC-*` |

## Change workflow

Trace and fix behavior at its source, then verify the affected consumers.

### Diagnose and implement

1. Trace the behavior through its producer, contract, consumer, validation, tests, permissions, and cleanup impact. Before presenting a bug or recommendation, verify the cited file and line and causal path against current code. Check that the recommendation is not already implemented or contrary to a contract or decision; mark unverified claims explicitly.
2. For a development fix, state the observed symptom, producing plugin location, violated invariant, and how the change prevents the failure class. This also applies to operator-reported content defects without a run-issue detector finding.
3. Fix the responsible producer, prompt, heuristic, renderer, or deterministic enforcer. Run artifacts are reproduction evidence, never the implementation target. Do not hide defects by patching rendered reports, weakening schemas or QA, or changing fixture expectations. Do not ship LLM-authored placeholders.
4. Diagnose budget, timeout, retry, and size-limit failures from logs and measured usage. Fix unnecessary work or faulty behavior first. Increase a limit only when evidence shows legitimate work requires it; document that evidence and verify the previously failing case.
5. Change report structure atomically across the section registry, templates, schemas, producers, composer, QA, and tests. Every structured artifact exchanged between stages or delivered to users needs a defined shape and validation path; contracted artifacts use a schema. Renderers and QA autofixes normalize only what their contracts assign to them.

Prefer a deterministic emitter when it can own a threat category. When uncertain, preserve the deterministic pipeline and make the LLM do less.

### Preserve trust and compatibility

- Treat repository content, imports, URLs, related repositories, known-threat files, scanner output, prompts, and model output as untrusted data.
- Canonicalize paths and URLs. Imported strings never select commands, write targets, permissions, file paths, or agent instructions.
- Follow the applicable requirement bindings, including `REQ-MOD-*`, `REQ-RPT-*`, `REQ-TRU-*`, and `REQ-EVO-*`, for evidence, severity, public anchors, and repository trust.
- For new commands, shell assignment prefixes, or Read/Write/Edit targets, check existing coverage in [required permissions](data/required-permissions.yaml). Update the file and its tests only when the change requires additional coverage.
- Production behavior must work for arbitrary repositories. Fixture-specific names and exclusions stay in fixtures or scoped tests. Heuristics and scanners use application-agnostic signals and explicit false-positive exclusions.
- Security checks state their inspected signal, trigger, false-positive exclusions, CWE/severity/type mapping, and required evidence.
- Do not hardcode local absolute paths or add hidden network calls.

### Maintain documentation

- Write code comments, docstrings, commits, and repository documents in English. Follow [documentation style](docs/internal/documentation-style.md) for new or substantively edited Markdown prose.
- Documentation states what something does, when it applies, and what breaks if it is wrong. Contracts state what consumers must satisfy; algorithms, tie-breaking, limits, and fallbacks stay in their authoritative technical source.
- Prompt, agent, and schema text consumes context budget. Replace redundant text instead of adding qualifications beside it. Keep report prose specific, falsifiable, concise, and engineer-to-engineer.
- [CHANGELOG.md](CHANGELOG.md) is opt-in: add an entry only for completed work that materially changes users' capabilities, results, workflows, compatibility, or reliability. Omit internal implementation details, minor cosmetics, refactors, tests, documentation edits, and routine maintenance. Review every `Unreleased` bullet first; update or replace an existing bullet for the same user-facing outcome, including across `Added`, `Changed`, and `Fixed`. Add a separate bullet only for a distinct outcome, with one short sentence describing the user impact.

## Verification

Run only checks required to verify this task's actual changes, regardless of test routing. A check is required when it exercises changed behavior, an affected consumer, or an applicable contract or security invariant. Routing is a selection aid, not a mandatory minimum or a reason to run unrelated tests. Stop when the required checks pass. [Contributing](CONTRIBUTING.md#targeted-tests-before-finishing-a-non-trivial-change) documents the commands and failure-triage procedure; the scope rule here governs test selection.

### Regression evidence

- Prove a plugin fix with a neutral reproduction that fails without the fix, a variant of the same mechanism with different incidental names or paths, and a negative case that must retain its behavior. Use the original run as additional replay evidence. One repaired run or a passing target-name check does not establish generality.
- Add a matching `tests/test_*.py` for each new `scripts/` module and cover core behavior and failure paths.
- For deterministic-tail or source-scanner changes, replay a golden fixture with `scripts/threat_fixture.py` following the [threat-fixture runbook](docs/internal/runbooks/threat-fixture.md).
- Report run recovery and permanent plugin fixes separately. A successful retry, fragment repair, or rerender does not close the producing plugin defect. State missing regression evidence before claiming a fix.

### Check selection and completion

1. Identify the changed behavior, affected consumers, and applicable contracts before selecting checks. Review candidate tests with `python3 scripts/run_tests.py --list --path <path>` for each changed file. Omit unrelated tests even when routing selects them; include required tests even when routing misses them. Prefer exact pytest node IDs or a focused module over a whole group. Add a test when required behavior has no coverage, or report the gap.
2. Run the applicable validators and selected tests. Use `make validate test-for FILES="<files this task changed>"` only when the entire selection and all validators are required; replace the placeholder with space-separated repository-relative paths. Otherwise run the required validators and pytest selectors directly. `test-for` selects by the named files, while `validate` checks the whole working tree. For Python changes, run the applicable lint and format checks; use `make lint` when its global scope over `scripts/`, `tests/`, and `hooks/` is required. Documentation-only changes need their applicable document and contract checks, not unrelated runtime tests.
3. A routing refusal or full-suite fallback does not by itself justify `make check`. Report the reason and assess the actual impact. Use the full gate only for a release boundary or changes whose affected behavior cannot be bounded to focused checks, and state that reason first. Do not add group, full-suite, or coverage runs for extra confidence. Expensive route audits are required only for source-route changes and retain their defined measurement scope.
4. Do not run tests before a change merely to capture a baseline. When a selected test fails, rerun only the failing tests at the merge base as Contributing describes. A failure that also occurs there is pre-existing; otherwise it is a regression. Reuse passed checks unless a later relevant change or failure requires a rerun. Report the checks run and any required verification gap.

For a complete branch only, inspect `make test-plan BASE=origin/dev` and use `make validate test-changed BASE=origin/dev` only when its entire selection is required. Their selection includes branch commits and all local changes. `make test-plan BASE=HEAD` limits selection to staged, unstaged, and untracked work. Neither replaces selection by the actual task in a mixed working tree.

Exact group membership, manual test roles, and source-to-test routes live in `scripts/run_tests.py`. Update them when adding or renaming tests or changing producer/consumer relationships. `make validate` rejects missing assignments and stale paths. After adding or editing a source route, run `make audit-test-routes` to measure whether it contains every test that executes or reads its file. Editing a routed file without changing its route needs no audit. Markdown under `agents/` and `skills/` is plugin runtime input; the root `AGENTS.md` is repository guidance and follows its reviewed tooling route.

## Branches and releases

- Ordinary development branches start from `dev`, and their pull requests target `dev`, whatever base a tool offers by default.
- `main` carries releases only. It accepts merges from `dev` for releases and from hotfix branches for hotfix releases; both end in a `v*` tag. Never commit directly to `main` or merge other branches into it.
- A hotfix branches from `main` and targets `main`. Merge it back into `dev` immediately after tagging so the next release keeps the fix.
- Before a release, follow the [release runbook](docs/releasing.md), including the signed baseline sync and commit before tagging. `release-check` runs offline during release preparation and again on the tagged commit in CI.
