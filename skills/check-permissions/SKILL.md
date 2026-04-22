---
name: check-permissions
description: Preflight the Claude Code permission allow-list for the AppSec plugin. Reports which Bash/Write/Edit/Read rules from data/required-permissions.yaml are missing from the user's settings.json, so unattended /appsec-advisor:create-threat-model runs do not block on prompts. Read-only by default; --write merges missing entries into a chosen scope.
---

You are running a preflight check that tells the user which Claude Code permission rules are still needed for unattended AppSec runs, and optionally writes them into their settings.json. This skill does **not** analyze code, dispatch agents, or modify repository content. It only reads / writes `settings.json` files.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:check-permissions — Preflight Claude Code permissions.

USAGE
  /appsec-advisor:check-permissions [--repo <path>] [--output <path>]
                                    [--scope local|project|user]
                                    [--write] [--json]

FLAGS
  --repo <path>     Repo root (default: current working dir)
  --output <path>   Output dir for ${OUTPUT_DIR} placeholders
                    (default: <repo>/docs/security)
  --scope <scope>   Settings file to write into when --write is given:
                      local   → <repo>/.claude/settings.local.json  (default; gitignored)
                      project → <repo>/.claude/settings.json        (committed)
                      user    → ~/.claude/settings.json             (global)
  --write           Merge missing entries into --scope instead of reporting
  --json            Emit machine-readable JSON

EXIT CODES
  0   all required permissions already granted (or were just written)
  1   required permissions missing (read-only mode)
  2   usage or IO error

The default (read-only) invocation is safe at any time. It never writes
files and never dispatches an agent.
```

After printing, exit.

## Step 1 — Parse arguments

Parse `--repo <path>`, `--output <path>`, `--scope <scope>`, `--write`, and
`--json` from the invocation. Any remaining tokens are ignored. Default
`REPO_ROOT` to the current working directory; default `OUTPUT_DIR` to
`$REPO_ROOT/docs/security`; default `SCOPE` to `local`.

## Step 2 — Run the helper

Delegate to the Python helper that owns the formatting and JSON merging:

```bash
ARGS="--repo-root $REPO_ROOT --output-dir $OUTPUT_DIR --scope $SCOPE"
[ "$WRITE_MODE" = "true" ] && ARGS="$ARGS --write"
[ "$JSON_MODE"  = "true" ] && ARGS="$ARGS --json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_permissions.py" $ARGS
```

Capture the helper's exit code and propagate it. Do not add any commentary
to the output — the helper's formatting is the deliverable.

## Step 3 — (No step 3)

The helper's output is the skill's output. Exit.
