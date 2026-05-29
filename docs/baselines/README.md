# Run baselines (Phase A0)

Frozen per-run measurements used as the **before** number for any
performance/token claim (see `docs/refactoring-plan.md` → A0). Without a
baseline here, no PR may assert a token or wall-time improvement.

## How a baseline is produced

`scripts/measure_run.py` folds the telemetry a run already emits into one
`.run-metrics.json`. It does **not** re-parse cost — it shells out to
`verify_run_costs.py --json`, whose delta logic is the single source of truth
for the cumulative-`SESSION_STOP` trap.

```bash
# 1. Run an assessment to completion against a test repo, e.g.:
#    /appsec-advisor:create-threat-model <repo> --depth standard
#    → leaves .stage-stats.jsonl, .hook-events.log, .agent-run.log in OUTPUT_DIR

# 2. Fold the telemetry into a metrics doc:
python3 scripts/measure_run.py <OUTPUT_DIR> --out -          # stdout
python3 scripts/measure_run.py <OUTPUT_DIR>                  # writes <OUTPUT_DIR>/.run-metrics.json

# 3. Check the result in under the matching name (see naming below):
#    docs/baselines/<repo>-<depth>-<plugin-version>.run-metrics.json
```

## What `.run-metrics.json` contains

| Key | Source | Use |
|---|---|---|
| `stages` | `.stage-stats.jsonl` | per-stage wall-time (`duration_ms`), tokens, tool_uses; deduped by stage (last write wins) |
| `verify_run_costs` | `verify_run_costs.py --json` | authoritative token deltas + cost, `per_agent`, `totals.cache_savings_pct`, `subagent_estimate.best_estimate`/`confidence` |
| `hook_events` | `.hook-events.log` | `stop_reasons` (matches the real `stop_reason=` emitter), `retry_hints` |
| `compose_stats` | `.compose-stats.json` | renderer pass-through when present |

## Naming convention

```
docs/baselines/<repo-slug>-<depth>-v<plugin-version>.run-metrics.json
```

e.g. `juice-shop-standard-v<X.Y.Z>.run-metrics.json`. Capture the two
canonical repos from the plan's Open Question 2 (Juice Shop + one internal
use-case with a different profile). Re-capture after any change that claims a
perf effect and diff against the prior file — the delta is the evidence.

## Reproducibility

`measure_run.py` output is a pure function of its input files (no wall-clock
stamp), so re-running it on the same frozen logs yields byte-identical JSON.
That is what makes a checked-in baseline a stable reference.
