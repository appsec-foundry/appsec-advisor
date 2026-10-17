# Drop the incremental and focus promises

## Problem

`appsec-analyzer` runs full assessments only. It refuses `--incremental`, and it refuses a free-text focus instead of running a full analysis under a narrowed label. `REQ-USE-004` still promised incremental updates and `REQ-FLW-009` a focus on specific components or directories, so both requirements described capabilities the product no longer has.

While checking `REQ-USE-004`, a further gap surfaced: the controller builds the model in a fresh workspace (`scripts/orchestrator/orchestration_controller.py`, `build_model`) that holds neither the published `threat-model.yaml` nor `.appsec-cache/baseline.json`, so `build_threat_model_yaml.py` finds no earlier changelog and every full run starts the history again.

## Goal

- `REQ-FLW-009`: "Users must be able to select analysis depth; a request to narrow the analysis to specific components or directories must be refused, never silently run in full." The focus refusal guard `test_unsupported_modes_stop_before_admission` joins its bindings.
- `REQ-USE-004`: "Full assessments must preserve the history of earlier results; deliberate rebuilds may reset the model and history." Its incremental guards leave the bindings; coverage is advisory until the controller carries history and a guard proves it.

## Non-goals

- Implementing the history carry-over; that follows as its own change with a guard.
- Removing incremental code paths from `resolve_config.py` or `build_threat_model_yaml.py`, or their tests.
- Adding a component or directory focus.

## Approval

The operator approved both wordings on 2026-10-17.
