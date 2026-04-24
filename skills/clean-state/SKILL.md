---
name: clean-state
description: Explicitly remove stale run-state files (.appsec-lock, .appsec-checkpoint, .phase-epoch, .session-agent-map) left behind by a crashed or abruptly terminated threat-model assessment. Refuses to clean when an active run is still holding the lock. Use when the Claude Code UI shows the threat-modeling skill as "scanning" forever after a session crash.
---

You are cleaning orphaned assessment run-state. This skill is **not** a
threat-modeling run — it touches no source code, spawns no agents, and
writes no threat model artifacts. It only removes the transient run-state
files listed below.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:clean-state — Remove stale assessment run-state files.

USAGE
  /appsec-advisor:clean-state [--repo <path>] [--output <path>] [--force] [--dry-run] [--json]

FLAGS
  --repo <path>     Repository to clean (default: current working dir)
  --output <path>   Output directory to clean (default: <repo>/docs/security)
  --force           Clean even when an active run is detected (dangerous —
                    will kill the other session's lock; use only when you
                    are certain the other process is dead)
  --dry-run         Report what would be cleaned without removing anything
  --json            Emit the result as machine-readable JSON

WHAT IS CLEANED
  .appsec-lock              PID lock file
  .appsec-checkpoint        phase= status= timestamp= line
  .phase-epoch              Unix-timestamp anchor used by phase timers
  .session-agent-map        hook session tracking

WHAT IS PRESERVED
  threat-model.md           (your completed threat model)
  threat-model.yaml         (canonical data)
  threat-model.sarif.json   (if present)
  .fragments/               (composer input set)
  .appsec-cache/            (incremental baseline cache)
  .agent-run.log            (audit trail)
  .hook-events.log          (audit trail)
  All other files           (this skill only touches the four files above)

WHEN TO USE
  * The Claude Code UI shows the threat-modeling skill as "scanning" but no
    claude process is actually running.
  * /appsec-advisor:status reports a run in progress from an old session.
  * A ~/appsec-advisor:create-threat-model invocation bails out with
    LOCK_BLOCKED and you've verified the other session is dead.

The skill is safe to invoke at any time — if no stale state exists, it
reports "clean" and exits 0.
```

After printing the help block, exit. Do not proceed.

## Step 1 — Parse arguments

Recognized flags (and the values consumed by `--repo` / `--output`):

  `--repo <path>`  `--output <path>`  `--force`  `--dry-run`  `--json`  `--help` | `-h`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `FORCE_MODE`, `DRY_RUN_MODE`,
`JSON_MODE`.

- Default `REPO_ROOT` to the current working directory.
- Default `OUTPUT_DIR` to `$REPO_ROOT/docs/security`.
- `--repo <path>` overrides `REPO_ROOT`.
- `--output <path>` overrides `OUTPUT_DIR`.

### Reject unknown arguments (hard fail)

If the invocation contains **any** token that is not one of the recognized
flags above — or is not the value consumed by `--repo` / `--output` — DO NOT
proceed. Do not resolve `CLAUDE_PLUGIN_ROOT`, do not invoke the helper, do
not touch any state file. Print the following block verbatim to stderr,
substituting `<TOKEN>` with the first unknown token, then exit with status
`2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:clean-state accepts only:
  --repo <path>     Repository to clean (default: current working dir)
  --output <path>   Output directory to clean (default: <repo>/docs/security)
  --force           Clean even when an active run is detected
  --dry-run         Report what would be cleaned without removing anything
  --json            Emit the result as machine-readable JSON
  --help, -h        Show full help and exit

Run `/appsec-advisor:clean-state --help` for details.
```

A flag that takes a value (e.g. `--repo` or `--output`) counts as unknown
when its value is missing — treat the flag itself as the offending token in
that case. Repeated occurrences of the same flag are allowed; the last value
wins.

## Step 2 — Resolve `CLAUDE_PLUGIN_ROOT`

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/clean-state/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
```

## Step 3 — Dispatch to the helper

Branch on the `--dry-run` / `--force` flags:

### Dry-run (report only, no mutation)

```bash
ARGS="$OUTPUT_DIR"
[ "$JSON_MODE" = "true" ] && ARGS="$ARGS --json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_state.py" $ARGS
```

The script's exit code propagates — 0 when clean / active, 1 when stale
or orphan state was detected. In dry-run mode we never mutate, so exit 1
is informational ("run without `--dry-run` to clean").

### Normal cleanup (default)

```bash
ARGS="$OUTPUT_DIR --clean"
[ "$JSON_MODE" = "true" ] && ARGS="$ARGS --json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_state.py" $ARGS
EXIT=$?
```

Exit-code handling:
- `0` — cleaned successfully (or there was nothing to clean).
- `2` — refused because an active run holds the lock. Report the situation
  to the user and suggest `--force` if they are certain the other session
  is dead.
- Any other code — propagate as-is.

### Forced cleanup (`--force`)

When `--force` is passed, the skill removes the lock even when a live PID
is detected. This is dangerous — it invalidates any still-running assessment.
The skill MUST:

1. Print a warning line:
   ```
   ⚠ --force requested — removing lock regardless of PID liveness.
      Any still-running assessment will lose its lock and may crash.
   ```
2. Invoke the cleaner with the `--force` flag supplemented by a direct
   `rm -f` on the lock files. The Python helper refuses to clean active
   state by design (the state machine is the guarantor of correctness);
   the skill layer owns the escape hatch:
   ```bash
   rm -f "$OUTPUT_DIR/.appsec-lock"
   rm -f "$OUTPUT_DIR/.appsec-checkpoint"
   rm -f "$OUTPUT_DIR/.phase-epoch"
   rm -f "$OUTPUT_DIR/.session-agent-map"
   ```
3. Re-run the inspector (without `--clean`) so the user sees the final
   state:
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_state.py" "$OUTPUT_DIR"
   ```

## Step 4 — (No step 4)

The helper's output is the skill's output. Exit with the helper's exit code
(propagated from Step 3). Do not add commentary beyond the `--force` warning
described above.
