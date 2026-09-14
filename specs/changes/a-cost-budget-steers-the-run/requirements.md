# Sourced constraints

## BUDGET-001 A budget steers the run, it does not kill it

Source: operator request, 2026-09-05.

- A run that reaches its budget finishes cleanly and leaves a complete report.
- Overshooting the declared budget is acceptable; overshooting it grossly is not.
- The existing hard cut stays available at the host wrapper, as `--hard-budget` and its `--max-budget` alias, for anyone who needs a ceiling instead.

## BUDGET-002 Optional work is dropped early, not at the moment of overrun

Source: operator request, 2026-09-05; measured cost shape in `proposal.md`.

- The decision to drop optional work is taken from a projection, not from an overrun that has already happened.
- Abuse-case verification is the first item on the ladder.
- Dropped work is named in the report and in Run Issues.

## BUDGET-003 Coverage is not a budget lever, scope is

Source: `specs/requirements.md` → `REQ-FLW-002`, `REQ-FLW-003`; `scripts/stride_dispatch_waves.py` → `claim`; `scripts/build_stride_dispatch_manifest.py` → `select_stride_components`.

- Every analyzed component keeps complete STRIDE coverage in every depth mode.
- A component whose output is incomplete stays a failure; a budget never accepts it.
- A component already in the dispatch plan is analyzed or the run fails; a budget never abandons it mid-run.
- A budget may lower the selection ceiling before the plan exists, shedding only components the predicate marks internal-only, and never one earned through exposure, ci-cd or supply chain, crown-jewel, auth, frontend, or the exposure-unknown fail-safe.
- The report names the components a budget excluded.

## BUDGET-006 Ten percent is the target, twenty percent is the failure point

Source: operator request, 2026-09-05.

- A declared budget of $30 should end at or below about $33.
- Above about $36 the design has failed.
- A strict never-exceed guarantee exists only through the wrapper's hard cut, and it costs the report; the soft mechanism does not promise one.
- The flag name says which of the two it is: `--soft-budget` steers, `--hard-budget` kills.

## BUDGET-004 A budget that cannot be met is refused before it is spent

Source: operator request, 2026-09-05; `scripts/orchestration_controller.py` → `_unsupported_runtime_reason`.

- A projected cost above the budget stops the run at admission, before any output directory, run state, or dispatch exists.
- The refusal names the shortfall and what would fit.

## BUDGET-005 Cost figures state what they are

Source: `docs/internal/cost-model.md`; `scripts/cost_running_total.py` → `cost_is_floor`.

- Under subscription billing the figures are price-table valuations of token counts, not money billed.
- A run with unmetered agents reports its total as a lower bound, and a budget decision taken on a lower bound says so.
