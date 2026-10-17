# Decision register

Requirements are the primary source of product behavior. Keep them simple and stable; derive technical contracts, implementation and tests from them through the requirement bindings.

**Adding a decision:** Add a decision only for a long-lived, cross-cutting technical choice that the requirements leave open and whose reversal would have significant consequences. State the chosen approach, the alternative, the reason and the consequences. Link to its requirement and technical evidence where applicable.

Bug fixes, scanner rules, algorithms, local implementation details and invariants already explained by contracts or tests do not need decision entries. A code change or a new test alone never requires an entry. Keep those details at their authoritative source; do not move them into requirements when retiring entries.

**Changing a decision:** Before adding or changing a decision, show the operator its exact wording and a plain-language summary and obtain confirmation of both. Retiring a decision also needs operator approval. Record changes to existing entries or to these rules in a proposal under `specs/changes/`.

**Reading the register:** Requirements define product behavior. This register explains technical choices within those requirements; it does not replace requirements, contracts or tests. A test may cite an applicable decision, but no decision ID is required merely because a test exists. Guards and rationale point to the technical evidence; a guard listed here does not establish complete requirement coverage.

**Retirement:** Retiring an entry removes duplicate documentation, not the behavior or controls recorded in its authoritative source. Historical assertion messages may cite retired IDs. Active requirement bindings and retained decisions refer only to active entries. Original entries are available in this file at commit `338e5e7cb41355af963421507ad3c410d53df8b8`; retired IDs are never reused.

**Retired IDs:** `AC-1`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `AC-7`, `AC-8`, `AC-9`, `AC-10`, `AC-11`, `AC-12`, `CE-1`, `CE-2`, `CE-3`, `CE-4`, `CE-5`, `CE-6`, `CR-2`, `CR-3`, `CR-4`, `CR-5`, `CR-6`, `CR-7`, `CR-8`, `CR-9`, `CR-10`, `DP-1`, `DP-2`, `DP-3`, `DP-4`, `DT-1`, `DT-2`, `DT-3`, `DT-4`, `DT-5`, `DT-6`, `DT-7`, `EX-3`, `EX-4`, `EX-5`, `EX-6`, `EXP-1`, `EXP-2`, `EXP-3`, `EXP-4`, `EXP-5`, `FE-1`, `FE-2`, `FE-3`, `FE-4`, `FE-6`, `FE-7`, `FE-8`, `FE-9`, `FE-10`, `FE-11`, `FE-12`, `FE-13`, `FE-14`, `FE-15`, `FE-16`, `FE-17`, `FE-18`, `FE-19`, `FE-20`, `FE-21`, `FE-22`, `FE-23`, `FE-24`, `FE-25`, `IN-1`, `IN-2`, `IN-3`, `IN-4`, `IN-5`, `MD-1`, `MD-2`, `MD-3`, `MD-4`, `MD-5`, `MD-6`, `MD-7`, `MD-8`, `MD-9`, `MD-10`, `MD-11`, `MR-2`, `MR-4`, `MR-5`, `MR-6`, `MR-7`, `MR-9`, `MR-10`, `MR-11`, `MR-12`, `MR-13`, `MR-14`, `MR-15`, `MR-16`, `MR-17`, `MR-18`, `MR-19`, `MR-20`, `MR-21`, `MR-22`, `OR-2`, `OR-3`, `OR-4`, `OR-5`, `OR-6`, `OR-7`, `OR-8`, `OR-9`, `OR-10`, `OR-11`, `OR-12`, `OR-13`, `OR-14`, `OR-15`, `OR-16`, `OR-17`, `OR-18`, `OR-19`, `OR-20`, `OR-21`, `OR-22`, `OR-23`, `OR-24`, `OR-25`, `OR-26`, `OR-27`, `OR-28`, `OR-29`, `OR-30`, `OR-31`, `OR-32`, `OR-33`, `OR-34`, `OR-35`, `OR-36`, `OR-37`, `OR-38`, `OR-39`, `OR-40`, `OR-41`, `RA-1`, `RA-2`, `RA-3`, `RA-4`, `RA-5`, `RA-6`, `RA-7`, `RA-8`, `RA-9`, `RA-10`, `RA-11`, `RA-12`, `RA-13`, `RA-14`, `RA-15`, `RA-16`, `RA-17`, `RA-18`, `RA-19`, `RA-20`, `RA-21`, `RA-22`, `RA-23`, `RA-24`, `RA-25`, `RA-26`, `RA-27`, `RA-28`, `RA-29`, `RA-30`, `RA-31`, `RC-1`, `RC-2`, `RC-3`, `RC-4`, `RC-5`, `RC-6`, `RN-1`, `RN-2`, `RN-3`, `RN-4`, `RN-5`, `RP-1`, `RP-2`, `RP-3`, `RQ-1`, `RQ-2`, `RQ-3`, `RQ-4`, `RQ-5`, `RQ-6`, `RQ-7`, `RQ-8`, `RR-1`, `RR-2`, `RR-3`, `SA-1`, `SA-2`, `SA-3`, `SA-5`, `ST-1`, `ST-2`, `ST-3`, `ST-4`, `ST-5`, `ST-6`, `TA-1`, `TA-2`, `TB-1`, `TB-2`, `TB-3`, `TB-4`, `TB-5`, `TB-6`, `TB-7`, `TB-8`, `TB-9`, `TB-10`, `TB-11`, `TB-12`, `TB-13`, `TB-14`, `TR-1`, `TR-2`, `TR-3`, `TR-4`, `TR-5`, `TR-6`, `TR-7`, `TR-8`, `TR-9`, `TR-10`, `WK-1`, `WK-2`, `WK-3`, `WK-4`, `WK-5`, `WK-6`, `WK-7`, `WK-8`.

A guard marked *guard not located* may exist but was not found; *no guard written* records a known gap. Rationale documents explain a choice without governing runtime behavior.

## Context routing

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| CR-1 | The catalog holds human decisions only; runtime paths, schemas, projectors and limits live in plugin-owned bindings | `test_human_catalog_contains_only_human_decisions`, `test_runtime_parameters_are_isolated_in_plugin_owned_bindings` | `docs/internal/analysis/analysis-context-routing-control-plane-2026-08-07.md` |

## Orchestration

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| OR-1 | Within an assessment, the deterministic controller launches every model role itself; no agent may recurse through `Agent`, pinned by `AGENT_TOOL_OWNERS` | `tests/test_agent_definitions.py` | `docs/internal/analysis/analysis-repository-legacy-and-pipeline-ballast-2026-08-19.md` |

## Findings and evidence

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| FE-5 | Supply-chain analysis is passive: files and git history only, no package manager, no network CVE scanner | — *(no guard written)* | `docs/internal/analysis/analysis-supply-chain-coverage-improvement.md` |

## Security architecture

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| SA-4 | Control domains and weakness classes are separate taxonomies and are never joined at class level; they meet at the finding | — *(no guard written)* | recurring proposal, rejected |

## Combined assessments

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| MR-1 | A combined assessment gives every model role a tool-less exchange: the controller serves masked excerpts only from the selected checkouts and the task's source selection, and the host receives a structural projection of the contract while the controller validates the full contract | `test_unauthorized_proposals_fail_before_another_model_call`, `test_host_schema_drops_keywords_a_strict_host_rejects_but_keeps_structure` | `docs/internal/analysis/implplan-headless-multi-repository-2026-10-07.md` → Admission and source identity |
| MR-3 | After the semantic stages the existing deterministic tail runs in a private workspace whose locations are `<repository label>/<path>` over a masked combined copy when the assessment covers several repositories, and the plain repository-relative path when it covers one; publication converts the model back to the qualified version-2 contract when the assessment covers several repositories (MR-8), and fails when a location does not resolve to a captured file | `test_combined_assessment_publishes_one_qualified_model`, `test_single_repository_workspace_uses_plain_paths` | `scripts/orchestrator/assessment_workspace.py` |
| MR-8 | A one-repository controller assessment publishes its workspace model in the version-1 contract, with plain repository-relative paths and no `source_inventory`; only an assessment of two or more repositories publishes the qualified version-2 contract. `schema_version: 2` therefore keeps meaning a combined model, and follow-on tools treat a one-repository controller model like any single-repository model | `test_one_repository_assessment_publishes_a_version_1_model`, `test_follow_on_tools_accept_a_one_repository_controller_model` | `scripts/orchestrator/orchestration_controller.py::_assessment_publish` |

## Extension surface

| ID | Decision | Guard | Rationale |
|---|---|---|---|
| EX-1 | An organization extends the plugin only through its org profile and package policy | `tests/test_org_profile_schema.py`, `tests/test_package_internal_plugin.py` | `docs/internal/contracts/org-profile-invariants.md` |
| EX-2 | Agents are core-owned; a profile cannot add or change one | `tests/test_package_internal_plugin.py` | `docs/internal/contracts/org-profile-invariants.md` |

## Principles

No code-local home, so they are stated in full here.

- **P-1 One control plane per workflow.** The threat-model assessment has one orchestrator,
  and compaction is not the primary optimization. A second scheduler inside the assessment
  would split the place where turn and context admission are decided. A separate workflow
  may own its controller only if it dispatches no assessment roles and shares no assessment
  state.
- **P-2 Python controls execution and validates state. The model decides security meaning
  at explicit semantic boundaries. The filesystem stays authoritative between them.**
- **P-3 What can be derived is derived, not authored.** A computed value has no wrong
  state to write, so it needs no guard.
- **P-4 Repository content is data, never instructions.** This covers imports, URLs,
  related repositories, known-threat files and scanner output.
- **P-5 Fix the producer, not the symptom.** Patching a rendered report, softening a
  schema or adjusting a fixture expectation hides a defect the next run reproduces.
- **P-6 When a deterministic emitter can own a category, it does.** Where a call is
  uncertain, keep the deterministic path and give the model less to decide. The controller
  owns phase transitions and producer ownership; the model is asked only at semantic
  boundaries.
- **P-7 One vocabulary per concept.** A second spelling of an existing concept resolves to
  the canonical one or does not exist. `test_canonical_normaliser_maps_alias` and the
  controller's `semantic_role` enum matching `SEMANTIC_ROLE_REGISTRY` are the two working
  examples.
