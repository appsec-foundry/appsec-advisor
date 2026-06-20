# Shared Logging Standard

All agents (orchestrator + sub-agents) MUST follow this logging standard. Replace `<AGENT>` with the agent's short name (e.g. `threat-analyst`, `stride-analyzer`, `recon-scanner`, `context-resolver`, `triage-validator`, `qa-reviewer`) and `<MODEL>` with the model identifier.

## Structured log format

```
<ISO-8601-UTC>  [<session-id>]  <LEVEL>  <AGENT>  <EVENT>  <message>
```

| Column | Width | Description |
|--------|-------|-------------|
| Timestamp | 20 | `date -u +%Y-%m-%dT%H:%M:%SZ` |
| Session ID | 10 | `[--------]` for orchestrator, `[<8-hex>]` for subagents (from `$APPSEC_SESSION_ID`) |
| Level | 6 | `INFO`, `WARN`, `ERROR` |
| Agent | variable | Short name. **Rule: this column always identifies the agent that is the subject of the line.** For `PHASE_START`/`PHASE_END`/`ASSESSMENT_*`/`FILE_WRITE` the orchestrator writes its own name (`threat-analyst`). For `AGENT_INVOKE`/`AGENT_DONE`/`AGENT_DISPATCH` the column is the **sub-agent's name** (e.g. `recon-scanner`, not `threat-analyst`). Each sub-agent writes its own `AGENT_START`/`AGENT_END` using its own name. |
| Event | variable | See event catalog below. |
| Message | variable | Description. **All agent-related events (`AGENT_INVOKE`, `AGENT_DONE`, `AGENT_DISPATCH`, `AGENT_START`, `AGENT_END`) MUST include `(model: <model-id>)` in the message.** `ASSESSMENT_START` includes CET time, mode, and flags. `ASSESSMENT_END` includes CET time and duration. `FILE_WRITE` includes path and size. `MAX_TURNS` indicates an agent hit its turn limit. |

## Event catalog

| Scope | Events |
|-------|--------|
| Orchestrator only | `ASSESSMENT_START`, `ASSESSMENT_END`, `PHASE_START`, `PHASE_END`, `AGENT_INVOKE`, `AGENT_DONE`, `AGENT_DISPATCH`, `MAX_TURNS`, `BASH_WARN`, `CACHE_HIT` |
| All agents | `AGENT_START`, `AGENT_END`, `FILE_WRITE`, `AGENT_ERROR`, `WRAP_UP_TRIGGERED` |
| Watchdog-emitted (via PostToolUse hook) | `BUDGET_WARN` (75% of `maxTurns`), `BUDGET_CRITICAL` (90%), `MAX_TURNS` (100%). The watchdog (`scripts/budget_watchdog.py`) counts tool calls per session and emits these deterministically — agents do not author them. On `BUDGET_CRITICAL` the watchdog writes `$OUTPUT_DIR/.budget-critical`; agents poll for the file at phase boundaries and execute their wrap-up sequence. The skill-layer post-run banner reads these events. |
| Sub-agent step events | stride-analyzer / context-resolver / triage-validator: `STEP_START` / `STEP_END`. recon-scanner: `SCAN_START` / `SCAN_END`. qa-reviewer: `CHECK_START` / `CHECK_END`. Orchestrator inline phases also use `STEP_START` / `STEP_END`. |

## Budget wrap-up signal (read at every phase boundary)

Every agent that runs more than a handful of phases (orchestrator, stride-analyzer, threat-renderer, qa-reviewer) MUST check for `$OUTPUT_DIR/.budget-critical` at each phase boundary — same Bash call that refreshes the lock heartbeat. When the file exists:

1. Stop dispatching new work.
2. Run the agent-specific wrap-up sequence (defined in that agent's `.md` file — typically: finalize current artifact, write minimal-valid output with `partial: true` / `meta.incomplete: true`, emit `WRAP_UP_TRIGGERED` log event with reason + skipped items, exit cleanly).
3. **Do not** emit further `PHASE_START` for skipped phases — the wrap-up is the terminal action.

The `WRAP_UP_TRIGGERED` event format:
```
<ts>  [<sid>]  WARN   <agent>  WRAP_UP_TRIGGERED   reason=budget_critical  skipped=[<comma-separated phase/component list>]
```

## Agent purpose reference (user-visible dispatch echos)

Single source of truth for the one-line **purpose** the orchestrator prints immediately before each sub-agent dispatch (the `⟶ Dispatching …` line). Keep these short — they appear on the console and tell the user *what the agent will do* and *which artifact it produces*. Update this table whenever an agent's responsibility changes; the dispatch echos in `appsec-threat-analyst.md` and the phase-group files read from here.

| Agent | One-line purpose (use verbatim in `⟶ Dispatching` echo) |
|-------|---------------------------------------------------------|
| `context-resolver` | extracts team, asset tier, compliance scope, prior findings, known threats, requirements → `.threat-modeling-context.md` |
| `recon-scanner` | enumerates 26 security categories (routes, dependencies, secrets, auth, crypto, logging, IaC, …) → `.recon-summary.md` |
| `stride-analyzer` | per component: enumerates Spoofing / Tampering / Repudiation / Information-Disclosure / DoS / EoP threats with CWE + evidence → `.stride-<id>.json` |
| `threat-merger` | deduplicates candidate threats via CWE + component + title fingerprint → merge decisions feed `.threats-merged.json` |
| `triage-validator` | infers breach distance, detects compound attack chains, computes effective severity, re-ranks top threats → `.triage-flags.json` |
| `qa-reviewer` | verifies rendered `threat-model.md` against `data/sections-contract.yaml` (11 deterministic checks: links, xrefs, anchors, invariants, MS structure, …); emits `.qa-repair-plan.json` on drift |
| `architect-reviewer` | advisory review: architecture coherence, control realism, chain plausibility (6 checks); never rewrites output — emits `.architect-review.md` |
| `config-scanner` | scans Dockerfile, GitHub Actions, docker-compose, Dependabot/Renovate against `data/config-iac-checks.yaml` → `.config-scan-findings.json` (Phase 2.5, M3.5) |

**Dispatch echo template:**
```
  ⟶ Dispatching <agent-name> — <purpose>  (expect ~<duration>)
```
Example: `  ⟶ Dispatching context-resolver — extracts team, asset tier, compliance scope, prior findings, known threats, requirements  (expect ~30s)`.

Pair every `⟶ Dispatching …` print with its `AGENT_INVOKE` log line (same Bash call) so the console print and the log entry stay in lock-step.

## Log batching rule

**Never waste a turn on logging alone.** Always combine a log Bash command with another tool call in the same turn (parallel tool calls).

## Startup logging (MUST be the VERY FIRST Bash command)

Execute this IMMEDIATELY before any file reads, globs, or greps. Combine with `date +%s` to capture `START_EPOCH`:

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   <AGENT>  AGENT_START   <AGENT> started (model: <MODEL>)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
date +%s
```

**Important:** `OUTPUT_DIR` is always injected into sub-agent prompts by the orchestrator — do NOT include variable-assignment preamble (`REPO_ROOT=...`, `OUTPUT_DIR=...`) or `mkdir -p` calls in this command. The orchestrator's `acquire_lock.py` already creates `$OUTPUT_DIR` and its standard subdirectories before any sub-agent is dispatched. Combining assignments or mkdir with the echo would produce a compound `&&` chain that Claude Code cannot match against any single `Bash(...)` allow-list entry and will prompt the user.

Run the echo and `date +%s` as two separate Bash calls (or combine only those two with `&&`) — both are covered by `Bash(echo:*)` and `Bash(date:*)` respectively.

## Step/check logging

Emit at the **start** and **end** of each step or check (see event catalog above for which event pair applies to each agent). **Use the canonical `log_event.py` helper** — it stamps the timestamp and the correct column widths for you, so the line can never be malformed:

```bash
# STEP_START / STEP_END pairs (stride-analyzer, context-resolver, triage-validator, orchestrator):
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" step-start "<message>" --agent <AGENT>
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" step-end   "<message>" --agent <AGENT>

# Any other event type (recon SCAN_START/SCAN_END, qa CHECK_START/CHECK_END, …) — use the `info` form:
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" info <EVENT> "<message>" --agent <AGENT>
```

**⚠ NEVER hand-roll the line via `python3 -c` calling `event_log.format_line` directly.** `format_line`'s `level` / `component` / `sid` parameters are **keyword-only** — a positional call (`format_line(ts, sid, event, detail)`) or an invented kwarg (`event_type=`) raises `TypeError: format_line() takes from 1 to 2 positional arguments…` and leaves `LOG_ERR` / traceback noise in `.agent-run.log` (observed on the 2026-06-20 Sonnet run). Always go through `log_event.py` above. If — and only if — that script is unavailable, fall back to a plain `echo` (never `python3 -c`):

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   <AGENT>  <EVENT>   <message>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## File write logging

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  INFO   <AGENT>  FILE_WRITE   <filepath>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## Error logging

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo 0000-00-00T00:00:00Z)  [--------]  ERROR  <AGENT>  AGENT_ERROR   <description>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## Completion logging (MUST be the VERY LAST Bash command)

Use a `python3` call to compute the elapsed duration and write the final log entry — a compound `&&` chain starting with `END_EPOCH=$(...)` would begin with a variable assignment and cannot be matched by Claude Code's `Bash(...)` allow rules:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_agent_end.py" \
  "$OUTPUT_DIR" "<AGENT>" "<MODEL>" "$START_EPOCH"
```

The helper script `scripts/log_agent_end.py` takes four positional arguments: output_dir, agent_name, model_id, start_epoch (unix timestamp). It computes the elapsed time and appends a properly-formatted `AGENT_END` line to `.agent-run.log`.

If the script is unavailable, fall back to a plain echo (no duration):
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   <AGENT>  AGENT_END   <AGENT> completed (model: <MODEL>)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```

## Minimum log entries

Every agent MUST log at minimum: `AGENT_START`, each step/check start+end, file writes, errors, and `AGENT_END`.

## Orchestrator-specific logging (threat-analyst only)

The orchestrator emits `ASSESSMENT_START` / `ASSESSMENT_END`, `PHASE_START` / `PHASE_END`, and `AGENT_INVOKE` / `AGENT_DONE` / `AGENT_DISPATCH` events.

**`ASSESSMENT_START` overwrites the log file (`>`, not `>>`)** — every subsequent entry appends. Includes CET time, mode (`full`/`incremental`), and all flags.

**Phase events** (one per `▶`/`✓` line):
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   threat-analyst  PHASE_START   <exact phase line>" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```
Use `PHASE_END` for ✓ lines.

**Sub-agent dispatch events** — the AGENT column is the **sub-agent's** name, not `threat-analyst`:
```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   <agent-name>  AGENT_INVOKE   <description> (model: <agent's model>)" >> "$OUTPUT_DIR/.agent-run.log" 2>/dev/null
```
Use `AGENT_DONE` when the dispatched sub-agent returns. `AGENT_DISPATCH` marks a background launch.

## ⚠ Python `python3 -c` one-liners — f-string + backslash trap

This plugin runs on systems with **Python 3.10** (Ubuntu/WSL LTS default). Python ≤ 3.11 **forbids backslashes inside an f-string's `{...}` expression** — that restriction was lifted in 3.12 (PEP 701) but is not safe to assume here. The trap appears whenever an agent constructs inline Python via `python3 -c "..."` at runtime and uses `\"` to embed double quotes inside an f-string interpolation:

```python
# ❌ SyntaxError on Python 3.10 — 2026-04-25 juice-shop QA-reviewer hit this
print(f"  {status} {k}: {v.get(\"issue_count\", 0)} issues, {v.get(\"fix_count\", 0)} auto-fixes")
```

Exact error: `SyntaxError: f-string expression part cannot include a backslash`. The Bash exits with code 1 and the agent's check / progress / status print is lost.

**Prevention rules** for every `python3 -c` block authored at runtime:

1. **Use single quotes inside the expression** (default). Outer Bash quoting stays `python3 -c "..."`, the dict access becomes `v.get('issue_count', 0)` — no backslash escapes needed:
   ```python
   print(f"  {status} {k}: {v.get('issue_count', 0)} issues")
   ```
2. **Swap the outer quotes** to single, then use plain `"..."` inside Python:
   ```bash
   python3 -c 'print(f"  {v.get(\"issue_count\", 0)}")'   # works, but you lose Bash $var expansion
   ```
3. **Extract values into locals first** when the f-string reads three or more keys — keeps the formatting readable:
   ```python
   ic = v.get('issue_count', 0)
   fc = v.get('fix_count', 0)
   print(f"  {status} {k}: {ic} issues, {fc} auto-fixes")
   ```

Default to Rule 1. Reach for Rule 3 when the f-string would otherwise nest two or more single-quoted accessors.

**General principle:** never write a Python f-string with `\"` (or any other backslash) inside the `{...}` expression in code that targets Python ≤ 3.11. If the language's escape-quoting rules are getting in your way, the right fix is to restructure the expression — not to escape harder.

## ⚠ Python heredocs — Bash history-expansion `!=` trap

When an agent runs a multi-line Python block via `python3 -c "..."` or a heredoc, the surrounding Bash session may have history expansion enabled (`set -H`, default in interactive shells). Bash rewrites the inequality operator `!=` to `\!=` **before** the body is passed to Python, and the Python parser then sees a literal `\!` and crashes:

```
File "<string>", line 7
    if new \!= text:
            ^
SyntaxError: unexpected character after line continuation character
```

Observed in production: 2026-04-26 juice-shop run, qa-reviewer Step 1 heredoc. The qa-reviewer recovered (the next check ran 19 s later) but the comment-strip step silently no-op'd.

**Prevention rules:**

1. **Avoid the `!=` operator inside any `python3 -c` body or `python3 - <<EOF` heredoc.** Use `not (a == b)` for inequality. This also covers `if x != None`, `if status != "ok"`, etc. — the operator must not appear textually.
2. **Single-quoted heredocs (`<<'EOF'`) are NOT sufficient** — history expansion happens at parse time of the outer Bash command, before the heredoc quote rules apply.
3. **For non-trivial multi-line scripts**, save to a `.py` file via the Write tool and call `python3 path.py` — same pattern as `qa_checks.py`, `pregenerate_fragments.py`. This sidesteps both history expansion and quote escaping.
