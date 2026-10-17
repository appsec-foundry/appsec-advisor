# Retire decisions of the session action protocol

## Problem

Removing the legacy `create-threat-model` skill and the controller's session action protocol left three register entries describing mechanisms that no longer exist, and one entry naming one. `OR-7` makes call telemetry block under `APPSEC_TELEMETRY_STRICT`, which no script reads any more, and names a deleted guard. `CE-5` orders agent dispatch prompts that the controller no longer issues and cites the deleted `skills/create-threat-model/SKILL-thin-stage1-v2.md`. `IN-3` governs incremental runs, which `appsec-analyzer` refuses. `OR-1` assigns dispatch to "compact runtimes", the removed protocol, and its "Level-0 dispatch" wording would also cover skills that start agents from the main session.

## Goal

- Retire `OR-7`, `CE-5` and `IN-3`, and add them to the retired IDs.
- Reword `OR-1`: "Within an assessment, the deterministic controller launches every model role itself; no agent may recurse through `Agent`, pinned by `AGENT_TOOL_OWNERS`". Guard and rationale stay.
- Remove `test_decision_register_routes_to_the_caching_guard`, which pinned the `CE-5` row.

## Non-goals

- Changing `REQ-USE-004`; incremental requirement wording and the remaining `resolve_config` incremental guards are handled with it.
- Removing the stale `APPSEC_TELEMETRY_STRICT` mentions in `agents/shared/logging-standard.md`, `docs/internal/runbooks/acceptance-cohort.md` and `scripts/live_canary.py`.
- Changing any other entry; `CR-1`, `MR-1`, `MR-3`, `MR-8`, `EX-1`, `EX-2`, `FE-5` and `SA-4` describe the controller path and keep their wording.

## Approval

The operator approved the `OR-1` wording and the three retirements on 2026-10-17.
