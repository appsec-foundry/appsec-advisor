# Shared Logging Standard

All sub-agents MUST follow this logging standard. Replace `<AGENT>` with the agent's short name (e.g. `stride-analyzer`, `recon-scanner`, `context-resolver`, `dep-scanner`, `qa-reviewer`) and `<MODEL>` with the model identifier.

## Log batching rule

**Never waste a turn on logging alone.** Always combine a log Bash command with another tool call in the same turn (parallel tool calls).

## Startup logging (MUST be the VERY FIRST Bash command)

Execute this IMMEDIATELY before any file reads, globs, or greps. Combine with `date +%s` to capture `START_EPOCH`:

```bash
REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}" && OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/docs/security}" && mkdir -p "$OUTPUT_DIR" && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   <AGENT>  AGENT_START   <AGENT> started (model: <MODEL>)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null && date +%s
```

## Step/check logging

Append at the **start** and **end** of each step or check:

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   <AGENT>  <EVENT>   <message>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

Event types by agent:
- **stride-analyzer:** `STEP_START` / `STEP_END`
- **recon-scanner:** `SCAN_START` / `SCAN_END`
- **context-resolver:** `STEP_START` / `STEP_END`
- **dep-scanner:** `SCAN_START` / `SCAN_END`
- **triage-validator:** `STEP_START` / `STEP_END`
- **qa-reviewer:** `CHECK_START` / `CHECK_END`

## File write logging

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   <AGENT>  FILE_WRITE   <filepath>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## Error logging

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  ERROR  <AGENT>  AGENT_ERROR   <description>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## Completion logging (MUST be the VERY LAST Bash command)

```bash
END_EPOCH=$(date +%s) && ELAPSED=$(( END_EPOCH - START_EPOCH )) && DURATION=$(printf "%d min %02d s" $(( ELAPSED / 60 )) $(( ELAPSED % 60 ))) && echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   <AGENT>  AGENT_END   <AGENT> completed in ${DURATION} (model: <MODEL>)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## Minimum log entries

Every agent MUST log at minimum: `AGENT_START`, each step/check start+end, file writes, errors, and `AGENT_END`.
