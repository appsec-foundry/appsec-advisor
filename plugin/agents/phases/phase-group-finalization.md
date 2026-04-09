# Phase Group: Output & Finalization (Phase 11)

This file is read by the orchestrator at runtime to load phase instructions.

## Phase 11: Finalization

### Checkpoint

Save a checkpoint before writing final output:
```bash
echo "CHECKPOINT phase=11 status=writing_output" > "$OUTPUT_DIR/.appsec-checkpoint"
```

### Write Output Files

**⚠ Log a STEP_START before each major substep below.** These entries provide real-time progress visibility in verbose mode. Batch each echo with the tool call it describes (zero extra turns).

**Substep 1 — Assemble report content:**

Log and print before starting report assembly:
```
  ↳ Assembling Table of Contents…
```
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] Assembling Table of Contents…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

Then for each major block, log before writing it:
- `[Phase 11] Writing Management Summary…`
- `[Phase 11] Writing Sections 1-7 (Architecture, Assets, Controls)…`
- `[Phase 11] Writing Section 8 — Threat Register (<n> threats)…`
- `[Phase 11] Writing Sections 9-11 (Critical Findings, Mitigations, Out of Scope)…`

**Substep 2 — Write threat-model.md:**

```
  ↳ Writing threat-model.md…
```
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] Writing threat-model.md…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

1. **`$OUTPUT_DIR/threat-model.md`** — always written. Section order:
   - Header metadata table
   - Table of Contents (including Management Summary and Section 7b if requirements enabled)
   - **Management Summary** — placed before Section 1
   - Section 1–7
   - **Section 7b — Requirements Compliance** (only when `CHECK_REQUIREMENTS=true`)
   - Section 8–11

**Substep 3 — Write YAML export (conditional):**

Only if `WRITE_YAML=true`:
```
  ↳ Writing threat-model.yaml…
```
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] Writing threat-model.yaml…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

2. **`$OUTPUT_DIR/threat-model.yaml`** — only if `WRITE_YAML=true`

**Substep 4 — Generate and write SARIF export (conditional):**

Only if `WRITE_SARIF=true`:
```
  ↳ Generating SARIF export (<n> results)…
```
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] Generating SARIF export (<n> results)…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

3. **`$OUTPUT_DIR/threat-model.sarif.json`** — only if `WRITE_SARIF=true`

### Lock Release & Duration

Log before releasing:
```
  ↳ Releasing lock…
```
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] Releasing lock…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

```bash
rm -f "$OUTPUT_DIR/.appsec-lock"
rm -f "$OUTPUT_DIR/.appsec-checkpoint"
END_EPOCH=$(date +%s)
ELAPSED=$(( END_EPOCH - START_EPOCH ))
DURATION=$(printf "%d min %02d s" $(( ELAPSED / 60 )) $(( ELAPSED % 60 )))
```

### Assessment Log Entry

Log before computing duration:
```
  ↳ Computing duration…
```
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] Computing duration…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

**⚠ MANDATORY — always log ASSESSMENT_END, even if earlier phases failed:**
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  ASSESSMENT_END   Assessment completed in ${DURATION}  threats=<N> mitigations=<N> files=[threat-model.md<, threat-model.yaml><, threat-model.sarif.json>] (CET: $(TZ=Europe/Berlin date '+%Y-%m-%d %H:%M:%S %Z'))" >> "$OUTPUT_DIR/.agent-run.log"
```
Replace `<N>` with actual counts. Include only files actually written in the `files=[...]` list.

### Print Final Summary

Log before printing:
```
  ↳ Printing assessment summary…
```
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  STEP_START   [Phase 11] Printing assessment summary…" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

```
══════════════════════════════════════════════════════════════
  Assessment Summary
══════════════════════════════════════════════════════════════

  Duration       : <DURATION>
  Started (CET)  : <CET start time>
  Finished (CET) : <CET end time>
  Mode           : <full | incremental | dry-run>
  Depth          : <quick | standard | thorough>
  Flags          : WITH_SCA=<true|false>  CHECK_REQUIREMENTS=<true|false>
                   WRITE_YAML=<true|false>  WRITE_SARIF=<true|false>

  Context Sources:
    External context : <provided|not configured|disabled|unavailable>
    Business context : <found|not found>
    Requirements     : <remote|cached|fallback|disabled|unavailable>
    Known threats    : <n entries (<n> open, <n> accepted)|not found>
    Repo files read  : <n from context-resolver>

  Pipeline (agent · model · maxTurns · status):
    context-resolver : <model> · <maxTurns> turns · .threat-modeling-context.md written
    recon-scanner    : <model> · <maxTurns> turns · .recon-summary.md written (<n> lines)
    dep-scanner      : <model> · <maxTurns> turns · .dep-scan.json (<n> vulnerable deps)
                       ← if WITH_SCA=false: "skipped (SCA not requested)"
                       ← if cache hit: "cache hit (age: <N>m)"
    stride-analyzer  : <model> · <maxTurns> turns × <n> components — <n> threats total
                       Components: <component-id-1>, <component-id-2>, …
    qa-reviewer      : <model> · <maxTurns> turns (runs next, skill-level)

  Results:
    Complexity tier  : <Simple|Moderate|Complex>
    Diagrams         : <n> (C4 + use case + tech arch)
    Requirements     : <n> checked (<n> PASS, <n> FAIL) | not checked
    Threats          : <n> (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
    Mitigations      : <n>
    Critical findings: <n>

  Paths:
    Repository   : <REPO_ROOT>
    Output       : <OUTPUT_DIR>

  Files Written:
    <OUTPUT_DIR>/threat-model.md          (<n> lines)
    <OUTPUT_DIR>/threat-model.yaml        (<n> lines)  ← only if WRITE_YAML
    <OUTPUT_DIR>/threat-model.sarif.json  (<n> bytes)  ← only if WRITE_SARIF

  Intermediate Files:
    <OUTPUT_DIR>/.threat-modeling-context.md  (<n> chars)
    <OUTPUT_DIR>/.recon-summary.md            (<n> chars)
    <OUTPUT_DIR>/.dep-scan.json               (<n> chars)  ← only if WITH_SCA
    <OUTPUT_DIR>/.stride-*.json               <n> files

  Tokens & Cost:
    Aggregated token/cost data is written automatically to
    <OUTPUT_DIR>/.hook-events.log (ASSESSMENT_SUMMARY / ASSESSMENT_TOKENS)
    and mirrored to <OUTPUT_DIR>/.agent-run.log after the session ends.
    Per-agent breakdowns are in the SESSION_STOP entries.

══════════════════════════════════════════════════════════════
```

**Note:** The QA review runs separately at the skill level after this agent completes.
