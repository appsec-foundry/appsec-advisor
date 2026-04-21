---
name: status
description: Read-only overview of the AppSec plugin — version, available capsules, last-run identity, configuration sources, and a fast-path preview that predicts whether the next incremental run would short-circuit. Does not analyze or modify anything.
---

You are printing a status overview for the AppSec plugin. This skill is **read-only** — do not analyze the repository, do not write files, do not dispatch sub-agents.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:status — Read-only plugin & repo status.

USAGE
  /appsec-advisor:status [--repo <path>] [--output <path>] [--json]

FLAGS
  --repo <path>     Repository to inspect (default: current working dir)
  --output <path>   Output directory to inspect (default: <repo>/docs/security)
  --json            Emit the status as machine-readable JSON

The command is safe to run at any time. It never writes files or dispatches
any agent.
```

After printing, exit.

## Step 1 — Parse arguments

Parse `--repo <path>`, `--output <path>`, and `--json` from the invocation.
Any remaining tokens are ignored. Default `REPO_ROOT` to the current working
directory; default `OUTPUT_DIR` to `$REPO_ROOT/docs/security`.

## Step 2 — Run the status helper

Delegate to the Python helper that owns the formatting:

```bash
ARGS="--repo-root $REPO_ROOT --output-dir $OUTPUT_DIR"
[ "$JSON_MODE" = "true" ] && ARGS="$ARGS --json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/appsec_status.py" $ARGS
```

Capture the helper's exit code and propagate it. Do not add any commentary to
the output — the helper's formatting is the deliverable.

## Step 3 — (No step 3)

The helper's output is the skill's output. Exit.
