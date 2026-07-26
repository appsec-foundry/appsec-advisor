# Orchestration Action Contract

`scripts/orchestration_controller.py` is the deterministic control plane for
the thin full/rebuild and rerender runtimes (the defaults; opt out with
`APPSEC_THIN_ORCHESTRATOR=0`). Its stdout is validated against
`schemas/orchestration-action.schema.json` before the skill consumes it.

## Ownership

- `resolve_config.py` remains the source of truth for flags, paths, modes,
  models, depth, and output settings.
- `orchestration_controller.py` owns thin-runtime selection, full/rebuild
  preflight mutations, Stage-1 post-analysis gates and completion-checkpoint
  freshness, abuse-case match/finalize, Stage-2 structural preparation,
  rerender artifact preconditions, fixed next-action classification, and
  compact dispatch values.
- `SKILL-full-runtime.md`, `SKILL-thin-stage1.md`,
  `SKILL-thin-stage1c.md`, `SKILL-thin-stage2.md`, and
  `SKILL-rerender-runtime.md` own user-visible output, Task lifecycle, and
  Level-0 Agent calls for their modes.
- `stride_dispatch_waves.py` owns deterministic bounded-wave scheduling,
  persisted two-attempt counters, resume selection, and the selected-component
  completion gate. It never changes component selection or analyzer prompts.
- Existing agents, phase groups, deterministic gates, renderer, QA, and
  cleanup remain authoritative for analysis and report quality.

The action is not a persisted runtime sidecar. Rehydration reads existing
`.skill-config.json`, checkpoints, validated phase artifacts, and status files.
Therefore it adds no cleanup-whitelist or diagnostic-bundle entry.

## Security and schema rules

- Action names and stage names are fixed enums.
- Abuse verifier candidates are bounded data-only identifiers; repository text
  cannot add commands, tools, paths, or instruction files to an action.
- `dispatch_values` has an allow-listed key set and bounded scalar/profile
  values; arbitrary command fields are rejected.
- `instruction_file` is selected only from plugin-owned constants. Repository
  content never supplies an action, command, write target, or instruction path.
- Full/rebuild cleanup matches the exact filename globs in the legacy runtime;
  prefix lookalikes and symlink targets must not be deleted.
- Rebuild archives the live changelog audit before deletion and fails closed if
  archiving fails.
- All new event lines use `event_log.py`.

## Rollout

The thin path is the default for full/rebuild and rerender;
`APPSEC_THIN_ORCHESTRATOR=0` is the permanent escape hatch back to
`SKILL-impl.md`. Incremental, resume, dry-run, deadline/cost, and live-phase
paths remain on `SKILL-impl.md` regardless. The full/rebuild thin path became
the default after the juice-shop standard
parity A/B held (2026-07-04): Critical severity identical at base (11=11) and
effective (21=21), remaining deltas attributable to STRIDE-analyzer run
variance rather than the orchestrator runtime.

Legacy mode also uses bounded post-Stage-1 reads: normal Stage 2, conditional
recovery, Stage 3, optional Stage 4, completion, and error handling are loaded
at their own boundaries rather than as one tail. The normal thin path instead
uses compact dedicated Stage-1/1c/2 runtimes and never reads those legacy
bodies. Both runtimes omit Stage 1c when abuse-case verification is disabled.
