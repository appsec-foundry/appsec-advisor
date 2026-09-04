# Runtime Cleanup Whitelist

Files and directories that `scripts/runtime_cleanup.py` always wipes from `$OUTPUT_DIR/` after a successful run (unless `--keep-runtime-files` / `KEEP_RUNTIME_FILES=true` is set).

The pipeline invokes `--stage post-qa`, which carries this wave when QA came back clean. A run that ended with QA unclean keeps every artifact below, because that is what a diagnosis reads.

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
.stride-attempts/
.producer-repair/
.stride-repository-registry.json
.route-inventory.json
.db-privilege-separation.json
.architecture-coverage.json
.arch-coverage-threats.json
.producer-retries.json
.scan-manifest.txt
.triage-ranking.json
.trust-boundary-assessment-input.json
.trust-boundary-candidates.json
.qa-prepass.json
.appsec-progress.json
.skill-watchdog.tick
.business-context-input.md
.pending-dispatch.json
.receipt-verification.json
```

`.business-context-input.md` is business context the user supplied for one run
without persisting it to `docs/business-context.md`. It is cleaned like any other
run input so it cannot shape a later scan unnoticed.

`.pending-dispatch.json` and `.receipt-verification.json` record which dispatch
is waiting for its receipts to be re-hashed and which ones were. Both belong to
one run's dispatch chain; carrying them forward would let a boundary pass on an
earlier run's verification.

## Opt-outs

- `--keep-runtime-files` / `KEEP_RUNTIME_FILES=true` preserves diagnostic runtime artifacts. The terminal outer-session hook still removes `.active-tool-calls/` because it is live state, not an audit artifact.
- `--keep-run-issues` holds back `.run-issues.json` alone. The run passes it when it offered a plugin diagnosis that was not taken, because `/appsec-advisor:diagnose-run` reads that file later.

## Always-cleaned directories

```text
.progress/
.taxonomy-slices/
.dispatch-context/
.merge-context/
.active-tool-calls/
```

The outer-session `Stop` hook and a controller `RUN_ABORTED` terminal gate remove
`.active-tool-calls/` even when runtime artifacts are otherwise preserved. They
first fail any running call and retire its budget counter and marker, so cleanup
cannot erase an unterminated lifecycle silently. Nested Agent stops must not
clear it while the parent run still owns the lock.
