# Rebuild Pre-flight Wipe (only when `REBUILD=true`)

> **Lazy-loaded mode file.** Read by `SKILL-impl.md` only when `REBUILD=true` and
> `DRY_RUN=false`. Kept out of `SKILL-impl.md` so the rebuild wipe never enters the
> resident full-run context — same just-in-time pattern as the lazy-loaded
> `agents/phases/phase-group-*.md` files. The control-flow position is the
> Rebuild-Pre-flight-Wipe anchor in `SKILL-impl.md` (after the Configuration Summary,
> before the Stage 1 Handoff Banner).

When `REBUILD=true` and `DRY_RUN=false`, wipe prior model and cached state **before** the Stage 1 handoff banner but **after** the Configuration Summary (so the user has already seen `Mode: rebuild (...)` and the `POST_SUMMARY_NOTE` warning).

Print the wipe header:

```

Rebuild: discarding prior threat model and all cached state.
  Removing from <OUTPUT_DIR>:
    threat-model.md / threat-model.yaml / threat-model.sarif.json / threat-model.pdf / threat-model.html / figure SVGs / pentest-tasks.yaml (if present)
    threat-model-<slug>.{md,yaml,sarif.json,pdf,html,figure*.svg} — prior slug/report-title variants (so a rebuild never leaves stale slugged reports alongside the fresh output)
    .architect-review.md, .threat-modeling-context.md, .recon-summary.md
    .sca-practice-findings.json, .known-bad-libs-findings.json
    .stride-*.json, .threats-merged.json, .triage-flags.json, .triage-ranking.json, .merge-*.json
    .fragments/ (compose inputs from prior contract version — must not survive a rebuild)
    .appsec-cache/ (baseline cache directory)
    .progress/, .taxonomy-slices/ (runtime-only directories)
    .appsec-checkpoint, .phase-epoch, .session-agent-map, .assessment-summary-emitted
    .skill-config.json, .recon-patterns.json, .compose-stats.json
    .context-resolver.stdout, .ctx-resolver.pid, .recon-scanner.pid, .recon-scanner.stdout
    .coverage-gaps.json, .scan-manifest.txt, .requirements.yaml
    .prior-findings-index.json, .stage1-resume-count
    .run-issues.json, .run-issues-fixes.json
    .pre-render-repair-plan.json, .qa-repair-plan.json, .qa-content-repair-plan.json,
    .architect-repair-plan.json (if present)
  Preserved:
    .agent-run.log, .hook-events.log (audit trail — overwritten by next run's ASSESSMENT_START)
    .activity-throttle (session-rate counter — intentionally survives rebuild)
    .appsec-lock (managed separately by the lock acquire/release mechanism)
  Note: --rebuild clears disk artifacts only. The in-process session context
    (conversation history cached in the Claude process) cannot be wiped by a
    script. If the cache_read bloat detector above fired, run /clear before
    re-invoking for a genuinely clean start.
```

Then perform the wipe in a single Bash call:

```bash
cd "$OUTPUT_DIR" 2>/dev/null || true
WIPED_COUNT=$(find . -maxdepth 1 \
  \( -name "threat-model.md" -o -name "threat-model.yaml" -o -name "threat-model.sarif.json" \
     -o -name "threat-model.pdf" -o -name "threat-model.html" -o -name "threat-model.figure*.svg" \
     -o -name "threat-model-*.md" -o -name "threat-model-*.yaml" -o -name "threat-model-*.sarif.json" \
     -o -name "threat-model-*.pdf" -o -name "threat-model-*.html" -o -name "threat-model-*.figure*.svg" \
     -o -name "pentest-tasks.yaml" -o -name ".architect-review.md" \
     -o -name ".threat-modeling-context.md" -o -name ".recon-summary.md" \
     -o -name ".sca-practice-findings.json" -o -name ".known-bad-libs-findings.json" \
     -o -name ".stride-*.json" -o -name ".threats-merged.json" -o -name ".triage-flags.json" \
     -o -name ".merge-*.json" -o -name ".appsec-checkpoint" \
     -o -name ".pre-render-repair-plan.json" -o -name ".qa-repair-plan.json" \
     -o -name ".qa-content-repair-plan.json" -o -name ".architect-repair-plan.json" \
     -o -name ".stage-stats.jsonl" -o -name ".direct-write-blocked" \
     -o -name ".phase-epoch" -o -name ".session-agent-map" \
     -o -name ".assessment-summary-emitted" -o -name ".skill-config.json" \
     -o -name ".recon-patterns.json" -o -name ".compose-stats.json" \
     -o -name ".context-resolver.stdout" -o -name ".ctx-resolver.pid" \
     -o -name ".recon-scanner.pid" -o -name ".recon-scanner.stdout" \
     -o -name ".coverage-gaps.json" -o -name ".scan-manifest.txt" \
     -o -name ".requirements.yaml" \
     -o -name ".prior-findings-index.json" -o -name ".stage1-resume-count" \
     -o -name ".triage-ranking.json" \
     -o -name ".run-issues.json" -o -name ".run-issues-fixes.json" \) \
  -print -delete 2>/dev/null | wc -l)
# .fragments/ MUST be wiped — stale compose inputs from a prior contract
# version are the #1 cause of the Phase 11 compose-fix-loop (see Bug 1 /
# §7 numbering drift). A --rebuild that leaves them on disk silently
# reuses fragments that do not match the current `sections-contract.yaml`.
# Sprint 3C (M3.5): also wipe .stage-stats.jsonl and .direct-write-blocked
# so a fresh rebuild starts with empty observability state — without this,
# `record_stage_stats.py` saw stale entries from the prior run and refused
# to log any of run N+1's stages (the 2026-04-27 run produced no stage
# stats at all because it was the second --rebuild in a row).
# .progress/ and .taxonomy-slices/ are runtime-only dirs that must not
# survive a rebuild.
rm -rf .fragments .appsec-cache .progress .taxonomy-slices 2>/dev/null
echo "  Removed $WIPED_COUNT files + .fragments/ + .appsec-cache/ + .progress/ + .taxonomy-slices/"
```

If `$OUTPUT_DIR` does not exist or `find` fails, treat as no-op — the rebuild is starting from a clean slate anyway, which is the desired outcome.

After the wipe, set `BASELINE_STATE=empty` in memory (the baseline no longer exists on disk). The orchestrator will therefore run as a first-ever full assessment: no baseline snapshot, fresh `v1` changelog entry, no T-ID stability, no Change Summary block in the completion summary.
