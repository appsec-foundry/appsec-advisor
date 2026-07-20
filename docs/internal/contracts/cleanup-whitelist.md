# Runtime Cleanup Whitelist

Files and directories that `scripts/runtime_cleanup.py` always wipes from `$OUTPUT_DIR/` after a successful run (unless `--keep-runtime-files` / `KEEP_RUNTIME_FILES=true` is set).

Single source of truth: `scripts/runtime_cleanup.py` (`ALWAYS_FILES`, `ALWAYS_DIRS` constants). This file mirrors the same list and is pinned by `tests/test_runtime_cleanup.py::TestCleanupWhitelistDoc::test_filename_mentioned_in_docs` so the two cannot drift.

Audit artifacts (`docs/internal/contracts/audit-artifacts.md`) and incremental anchors (`.appsec-cache/baseline.json`) are **never** in this list.

## Always-cleaned files

```text
.dep-scan.pid
.dep-scan.stdout
.merge-candidates.json
.merge-decisions.json
.management-summary-draft.md
.phase-epoch
.session-agent-map
.assessment-summary-emitted
.assessment-owner-sid
.prior-findings-index.json
.stage1-resume-count
.skill-config.json
.recon-patterns.json
.context-resolver.stdout
.ctx-resolver.pid
.recon-scanner.pid
.recon-scanner.stdout
.coverage-gaps.json
.dispatch-waves.json
.route-inventory.json
.db-privilege-separation.json
.architecture-coverage.json
.arch-coverage-threats.json
.scan-manifest.txt
.triage-ranking.json
.qa-prepass.json
.appsec-progress.json
.skill-watchdog.tick
```

## Always-cleaned directories

```text
.progress/
.taxonomy-slices/
.dispatch-context/
.merge-context/
.active-tool-calls/
```
