# Audit Artifacts

Files that runtime cleanup MUST preserve. Deleting them breaks post-run audit, SARIF traceability, or incremental T-ID stability.

| Path | Purpose |
|------|---------|
| `.threat-modeling-context.md` | Captured project context (recon summary + scope) |
| `.org-context.md`, `.org-context-manifest.json` | Preset-selected organization reference data and its per-document load, omission, size, and hash records |
| `.recon-summary.md` | Recon-scanner output — input to STRIDE |
| `.recon-signals.json` | Contracted actor, exposure, and deployable-unit signals required for validated recon reuse |
| `.dep-scan.json` | Dependency scan findings |
| `.stride-<component-id>.json`, `.stride-dispatch-manifest.json`, `.stride-selection.json`, `.stride-analyst-context.json` | Per-component STRIDE fragments and the three durable pre-fan-out sidecars below; the analyst context contains bounded component business and architecture projections |
| `.threats-merged.json` | Canonical merged threat set |
| `.triage-flags.json` | Triage-validator verdicts |
| `.trust-boundary-diagnostics.json` | Canonical endpoint-resolution failures and ambiguity audit |
| `.trust-boundary-renumber.json` | `{counter id: delivered id}` map from the contiguous `tb-1 … tb-N` delivery renumbering — lets post-build emitters translate the ids `.triage-flags.json` recorded |
| `.trust-boundary-coverage.json` | Mandatory crossing-signal dispositions and unresolved-signal audit |
| `.component-inventory-finalization.json` | Final component-ID set and endpoint-field fingerprint used by Stage 1b |
| `.data-flows.json` | Validated architecture topology handed from Stage 1a to Stage 1b |
| `.context-routing-plan.json`, `.context-routing-plan.receipt.json` | Human-labelled context-v2 delivery decisions, active bindings, and the exact-byte receipt for the plan |
| `.architect-review.md` | Stage-4 advisory output |
| `.agent-run.log` | Structured agent run log |
| `.hook-events.log` | Hook timing/diagnostic events |
| `.appsec-cache/` | Carry-forward cache directory |
| `.appsec-cache/baseline.json` | **Critical** — incremental anchor; deleting forces cold full scan and breaks T-ID stability |

Canonical enforcement: `scripts/runtime_cleanup.py` (the cleanup script must never list these), drift-guarded by `tests/test_runtime_cleanup.py`.

## The `.stride-` prefix is shared

Only `.stride-<component-id>.json` is a STRIDE result (`schemas/stride.schema.yaml`).
Four sidecars share the prefix and are written **before** the Phase-9 fan-out:

| Path | What it really is |
|------|-------------------|
| `.stride-dispatch-manifest.json` | Dispatch plan (`schemas/stride-dispatch-manifest.schema.yaml`) |
| `.stride-selection.json` | Component-selection report (`build_stride_dispatch_manifest.py`) |
| `.stride-analyst-context.json` | Analyst-A per-component context |
| `.stride-repository-registry.json` | Controller-only context-v2 mapping from declared local related repositories to validated roots; component projections under `.dispatch-context/` are the only mappings sent to STRIDE analyzers, and runtime cleanup removes both |

Cleanup and never-publish lists keep the broad `.stride-*.json` pattern on
purpose. Anything that **reads or counts** per-component results must go
through `scripts/stride_outputs.py` — a bare glob counts the sidecars as
finished components (it disabled the watchdog's Phase-9 canary, inflated the
progress widget, and put `dispatch-manifest` / `analyst-context` into the
merge audit trail and the incremental baseline). A new sidecar must be added
to `RESERVED_SIDECARS` in the same change; `tests/test_stride_outputs.py`
guards both halves.

## Rebuild exception

`--rebuild` intentionally discards analysis sidecars and the incremental
baseline. Before deleting the live `threat-model-changelog.md` /
`threat-model-changelog.jsonl`, both the legacy rebuild mode and the thin
orchestration controller must archive them under `changelog-history/`.
Archiving is fail-closed: a failure aborts before any rebuild deletion.
