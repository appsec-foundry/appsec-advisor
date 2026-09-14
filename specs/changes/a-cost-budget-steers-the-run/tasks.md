# Tasks

## Slice 1 — a budget can be declared, and a run that cannot fit does not start

- [x] Project a run's cost before it starts, from `last_run_cost_usd` in `.appsec-cache/baseline.json` for the same mode and depth, and otherwise from a parametric floor (`scripts/project_run_cost.py`).
- [x] Record the finished run's cost so the next projection rests on a measurement rather than a formula, and skip the write when the total is only a lower bound (`scripts/persist_run_baseline.py`, `scripts/baseline_state.py`).
- [x] Refuse admission when the projection does not fit, on the read-only path that creates no output directory and dispatches no agent (`scripts/orchestration_controller.py`).
- [x] Stop `_unsupported_runtime_reason` from rejecting the budget, and keep `max_wall_time_seconds` rejected (`scripts/orchestration_controller.py`).
- [x] Stop the wrapper from refusing the budget as an unsupported runtime option, and pass the budget and the depth into its admission call so the refusal happens before the output directory exists (`scripts/run-headless.sh`).
- [x] Rename the soft budget to `--soft-budget` and the organization key to `guardrails.soft_budget_usd`, keeping `--max-cost` and `max_cost_usd` as accepted deprecated spellings (`scripts/resolve_config.py`, `scripts/resolve_org_profile.py`, `schemas/org-profile.schema.yaml`, `schemas/orchestration-action.schema.json`).
- [x] Rename the wrapper's hard cut to `--hard-budget`, keep `--max-budget` as an alias, and derive it at 1.25 × the soft budget when only the soft budget is given (`scripts/run-headless.sh`).
- [x] Guard the two refusal paths, the cases that must not refuse (a first run, a rerender, a corrupt cache), the derived backstop, and that a refusal creates no output and reaches no dispatch (`tests/test_project_run_cost.py`, `tests/test_orchestration_controller.py`, `tests/test_run_headless_completion.py`, `tests/test_resolve_config.py`).
- [x] Say in the documentation which flag steers and which one kills, and that a subscription-mode figure is a price-table valuation rather than money billed (`docs/headless-mode.md`, `docs/threat-modeler.md`, `docs/internal/contracts/orchestration-actions.md`, `docs/org-profiles.md`).

## Open

- [x] Approve `REQ-FLW-004`, and the scope in `requirements.md` → `BUDGET-003`.
- [ ] Apply `REQ-FLW-004` to `specs/requirements.md` with its binding in `data/requirement-bindings.yaml`. Held until the behaviour it describes exists: the approved wording promises sizing, shedding, and the naming of excluded components, and slice 1 delivers only the refusal.
- [ ] Add a boundary checkpoint that compares measured cost plus projected remainder against the budget, using `scripts/cost_running_total.py` and this run's own observed per-agent cost and host ratio.
- [ ] Take the upper bound of the reserve, not its midpoint, whenever it comes from the parametric projection rather than a last-run cache.
- [ ] Write the shed decision to its own state file, never to `.budget-critical`, and give the abuse-case gate a second suppression reason distinct from a turn-budget claim (`scripts/orchestration_controller.py`, `scripts/budget_watchdog.py`).
- [ ] Implement the ladder in order: abuse-case verification, then STRIDE retries beyond a first attempt that produced output, then architect review and repair iterations beyond one.
- [ ] Drop STRIDE dispatch concurrency to one once the projection is within one wave of the budget (`scripts/resolve_config.py`, `scripts/stride_dispatch_waves.py`).
- [ ] Size the analyzed set to the budget by lowering the selection ceiling, shedding only internal-only components, and record the budget reason in the selection report (`scripts/build_stride_dispatch_manifest.py`).
- [ ] Refuse admission when the earned component set alone exceeds the budget, and when the inventory is in `passthrough` mode and offers no priority order to size along.
- [ ] Disclose every shed step and every budget-excluded component, extending the existing `_extract_stride_ceiling_events` reason rather than adding a channel (`scripts/aggregate_run_issues.py`), and state in the report's run statistics what the run spent against what it declared.
- [ ] Guard the ladder order, the disclosure, and that a budget never accepts an incomplete component.
- [ ] Replace the parametric constants in `scripts/project_run_cost.py` once a second run has been measured. They rest on one anchor today, which is why the floor refuses only what is clearly below it.
- [ ] Decide the two remaining open questions in `proposal.md`: budget scope across all stages versus analysis stages only, and whether sizing waits for the `deployment_zones` vocabulary. The backstop question is decided — the wrapper derives it.
