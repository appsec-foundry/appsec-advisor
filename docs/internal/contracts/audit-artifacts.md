# Audit Artifacts

Files that runtime cleanup MUST preserve. Deleting them breaks post-run audit, SARIF traceability, or incremental T-ID stability.

| Path | Purpose |
|------|---------|
| `.threat-modeling-context.md` | Captured project context (recon summary + scope) |
| `.recon-summary.md` | Recon-scanner output — input to STRIDE |
| `.dep-scan.json` | Dependency scan findings |
| `.stride-*.json` | Per-component STRIDE fragments |
| `.threats-merged.json` | Canonical merged threat set |
| `.triage-flags.json` | Triage-validator verdicts |
| `.architect-review.md` | Stage-4 advisory output |
| `.agent-run.log` | Structured agent run log |
| `.hook-events.log` | Hook timing/diagnostic events |
| `.appsec-cache/` | Carry-forward cache directory |
| `.appsec-cache/baseline.json` | **Critical** — incremental anchor; deleting forces cold full scan and breaks T-ID stability |

Canonical enforcement: `scripts/runtime_cleanup.py` (the cleanup script must never list these), drift-guarded by `tests/test_runtime_cleanup.py`.

## Rebuild exception

`--rebuild` intentionally discards analysis sidecars and the incremental
baseline. Before deleting the live `threat-model-changelog.md` /
`threat-model-changelog.jsonl`, both the legacy rebuild mode and the thin
orchestration controller must archive them under `changelog-history/`.
Archiving is fail-closed: a failure aborts before any rebuild deletion.
