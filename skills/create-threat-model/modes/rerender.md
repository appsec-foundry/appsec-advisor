# Re-Render Mode (`--rerender`) — skip Stage 1, re-render + re-QA from existing fragments

> **Lazy-loaded mode file.** Read by `SKILL-impl.md` only when `MODE=rerender`. Kept out
> of `SKILL-impl.md` so the rerender branch never enters the resident full-run context —
> same just-in-time pattern as `agents/phases/phase-group-*.md`. The control-flow position
> is the Re-Render anchor in `SKILL-impl.md` (before the Incremental Pre-Check / fast-path).

**When `RERENDER=true` (`MODE=rerender`), take this branch and SKIP Stage 1, Stage 1c, the Incremental Pre-Check, the Incremental Fast-Path (null-change abort), and the Resume-from-Checkpoint section** — everything between the Re-Render anchor and "## Stage 2 — Report Rendering" in `SKILL-impl.md`. Re-render mode trusts the on-disk Stage-1 artifacts as canonical, re-runs only the LLM-cheap render + the full Stage-3 QA gate (incl. the Re-Render Loop), and never re-analyzes source. It is the right tool when a fragment was hand-edited or the renderer/QA/contract logic changed; it is the **wrong** tool when source code changed (use `--incremental`/`--full` then).

**Why this branch exists / what it bypasses:** the Incremental Fast-Path runs "before anything else" and would null-change-abort an unchanged repo, and a `--full` run would re-run Stage 1 and regenerate every fragment. Re-render needs neither — it explicitly re-renders the existing fragments. This branch is therefore evaluated **before** the fast-path.

**Step R1 — precondition gate (hard).** Re-render needs a complete Stage-1 artifact set on disk. Verify all of the following exist; if any is missing, print the banner and exit 2 (do not fall through to Stage 1):

```bash
MISSING=""
for f in threat-model.yaml .threats-merged.json .triage-flags.json; do
  [ -f "$OUTPUT_DIR/$f" ] || MISSING="$MISSING $f"
done
FRAG_COUNT=$(find "$OUTPUT_DIR/.fragments" -maxdepth 1 -type f 2>/dev/null | wc -l)
[ "$FRAG_COUNT" -ge 3 ] || MISSING="$MISSING .fragments/(>=3)"
if [ -n "$MISSING" ]; then
  printf '\n✗ --rerender needs an existing assessment to re-render.\n' >&2
  printf '  Missing under %s:%s\n' "$OUTPUT_DIR" "$MISSING" >&2
  printf '  Run a full/standard assessment first; --rerender then re-renders\n' >&2
  printf '  its fragments. For source-code changes use --incremental or --full.\n\n' >&2
  exit 2
fi
```

**Step R2 — acquire the lock** exactly as a normal run does (the skill owns the lock across Stage 2 + Stage 3; same `acquire_lock.py` call + skill_watchdog spawn used before the Stage-2 dispatch below).

**Step R3 — proceed directly to "## Stage 2 — Report Rendering".** Dispatch `appsec-advisor:appsec-threat-renderer` with the **identical** prompt/config the normal post-Stage-1 flow uses (REPO_ROOT, OUTPUT_DIR, WRITE_SARIF, ASSESSMENT_DEPTH, models, etc.). The renderer reuses the existing `.fragments/`, `.threats-merged.json`, `.triage-flags.json`, `threat-model.yaml`, and `.abuse-case-verdicts.json` (it authors only the 2 MS JSON fragments + walkthroughs/posture and never regenerates analyst-authored fragments such as `security-architecture.md`). Then continue **unchanged** into the post-Stage-2 flow: pre-generation backstop + inline-shortcut hard gate + **Stage 3 QA + Re-Render Loop** (where a contract-drift triggers the `appsec-fragment-fixer`), then the Completion Summary.

**Do NOT** re-run the deterministic emitters (Phase 10 SCA etc.) — their outputs are already baked into the fragments/yaml (same rule as the Re-Render Loop, see §"AFTER the Stage-2 no-op gate"). **Do NOT** re-dispatch Stage 1c abuse-case verifiers — reuse the existing `.abuse-case-verdicts.json`.
