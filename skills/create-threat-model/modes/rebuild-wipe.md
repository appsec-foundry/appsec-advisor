# Rebuild Pre-flight Wipe (only when `REBUILD=true`)

> **Lazy-loaded mode file.** Read by `SKILL-impl.md` only when `REBUILD=true` and
> `DRY_RUN=false`. Kept out of `SKILL-impl.md` so the rebuild wipe never enters the
> resident full-run context — same just-in-time pattern as the lazy-loaded
> `agents/phases/phase-group-*.md` files. The control-flow position is the
> Rebuild-Pre-flight-Wipe anchor in `SKILL-impl.md` (after the Configuration Summary,
> before the Stage 1 Handoff Banner).

When `REBUILD=true` and `DRY_RUN=false`, wipe prior model and cached state **before** the Stage 1 handoff banner but **after** the Configuration Summary (so the user has already seen `Mode: rebuild (...)` and the `POST_SUMMARY_NOTE` warning).

Perform detection, narration, and wipe in a **single Bash call**. The narration is
honest about what was actually present: the `discarding prior threat model and all
cached state` header and the removal counts are printed only when something really
exists to remove. On a genuine clean slate (a first-ever `--rebuild`, or one where a
prior run already cleaned up) a single `clean slate — nothing to discard` line is
printed instead — the header is a *result*, not a promise. The trailing directory
list reflects only the runtime/cache directories that were actually present, never a
hard-coded suffix.

```bash
if [ ! -d "$OUTPUT_DIR" ]; then
  printf '\nRebuild: clean slate — no prior output directory, nothing to discard.\n'
else
  cd "$OUTPUT_DIR"
  # Archive the full change-log audit (threat-model-changelog.md / .jsonl) into
  # changelog-history/ BEFORE the find -delete below — those files match the
  # `threat-model-*.md` wipe glob and would otherwise be discarded. Archiving
  # (not deleting) keeps the prior audit trail across a rebuild; the fresh run
  # regenerates a new live pair from the reset changelog. No-op if absent.
  if ! python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_changelog_audit.py" \
      --output-dir "$OUTPUT_DIR" --archive 2>/dev/null; then
    printf 'Error: could not archive threat-model-changelog audit files; rebuild aborted before deletion.\n' >&2
    exit 2
  fi
  # Record which runtime/cache directories actually exist BEFORE wiping, so we
  # never claim to have removed a directory that was absent.
  REMOVED_DIRS=""
  for d in .fragments .appsec-cache .progress .taxonomy-slices; do
    [ -d "$d" ] && REMOVED_DIRS="$REMOVED_DIRS + $d/"
  done
  # Delete prior model + cached-state files; capture the real removed list so the
  # count reported is what happened, not what was promised.
  REMOVED_FILES=$(find . -maxdepth 1 \
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
    -print -delete 2>/dev/null)
  WIPED_COUNT=$(printf '%s\n' "$REMOVED_FILES" | grep -c .)
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
  if [ "$WIPED_COUNT" -eq 0 ] && [ -z "$REMOVED_DIRS" ]; then
    printf '\nRebuild: clean slate — nothing to discard.\n'
  else
    printf '\nRebuild: discarding prior threat model and all cached state.\n'
    printf '  Removed from %s: %s file(s)%s\n' "$OUTPUT_DIR" "$WIPED_COUNT" "$REMOVED_DIRS"
    printf '  Preserved: .agent-run.log, .hook-events.log, .activity-throttle, .appsec-lock\n'
    printf '  Note: --rebuild clears disk artifacts only. The in-process session\n'
    printf '    context (conversation history cached in the Claude process) cannot be\n'
    printf '    wiped by a script. If the cache_read bloat detector above fired, run\n'
    printf '    /clear before re-invoking for a genuinely clean start.\n'
  fi
fi
```

The single-call form means `$OUTPUT_DIR` not existing, or `find` matching nothing,
both resolve to the honest `clean slate` line — the rebuild is starting fresh, which
is the desired outcome.

After the wipe, set `BASELINE_STATE=empty` in memory (the baseline no longer exists on disk). The orchestrator will therefore run as a first-ever full assessment: no baseline snapshot, fresh `v1` changelog entry, no T-ID stability, no Change Summary block in the completion summary.
