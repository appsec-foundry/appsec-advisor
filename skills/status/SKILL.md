---
name: status
description: Read-only overview of the AppSec plugin — version, available features, last-run identity, and configuration sources. Does not analyze or modify anything.
---

You are printing a status overview for the AppSec plugin. This skill is **read-only** — do not analyze the repository, do not write files, do not dispatch sub-agents.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:status — Read-only plugin & repo status.

USAGE
  /appsec-advisor:status [--repo <path>] [--output <path>] [--json] [--live]

FLAGS
  --repo <path>     Repository to inspect (default: current working dir)
  --output <path>   Output directory to inspect (default: <repo>/docs/security)
  --json            Emit the status as machine-readable JSON
  --live            Print only the in-flight run snapshot (active tool calls,
                    per-component progress, heartbeat freshness). Honours --json.
                    Intended for fast, cron-style polling in a second terminal.

The command is safe to run at any time. It never writes files or dispatches
any agent.
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags:

  `--repo <path>`  `--output <path>`  `--json`  `--live`  `--help` | `-h`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `JSON_MODE`, `LIVE_MODE`. Default
`REPO_ROOT` to the current working directory; default `OUTPUT_DIR` to
`$REPO_ROOT/docs/security`. `--live` is a boolean toggle that consumes no value.

### Reject unknown arguments (hard fail)

If the invocation contains **any** token that is not one of the recognized
flags above — or is not the value consumed by `--repo` / `--output` — DO NOT
proceed. Do not resolve `CLAUDE_PLUGIN_ROOT`, do not invoke the helper.
Print the following block verbatim to stderr, substituting `<TOKEN>` with the
first unknown token, then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:status accepts only:
  --repo <path>     Repository to inspect (default: current working dir)
  --output <path>   Output directory to inspect (default: <repo>/docs/security)
  --json            Emit the status as machine-readable JSON
  --live            Print only the in-flight run snapshot (cron-style polling)
  --help, -h        Show full help and exit

Run `/appsec-advisor:status --help` for details.
```

A flag that takes a value (e.g. `--repo` or `--output`) counts as unknown
when its value is missing — treat the flag itself as the offending token in
that case. Repeated occurrences of the same flag are allowed; the last value
wins.

## Step 2 — Run the status helper

Delegate to the Python helper that owns the formatting:

```bash
ARGS="--repo-root $REPO_ROOT --output-dir $OUTPUT_DIR"
[ "$JSON_MODE" = "true" ] && ARGS="$ARGS --json"
[ "$LIVE_MODE" = "true" ] && ARGS="$ARGS --live"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/appsec_status.py" $ARGS
```

Capture the helper's exit code and propagate it. Do not add any commentary to
the output — the helper's formatting is the deliverable.

## Step 3 — (No step 3)

The helper's output is the skill's output. Exit.
