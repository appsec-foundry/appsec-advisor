---
name: check-permissions
description: Preflight the Claude Code permission allow-list for the AppSec plugin. Reports which Bash/Write/Edit/Read rules from data/required-permissions.yaml are missing from the user's settings.json, so unattended /appsec-advisor:create-threat-model runs do not block on prompts. Read-only by default; --update merges missing entries into a chosen scope.
---

You are running a preflight check that tells the user which Claude Code permission rules are still needed for unattended AppSec runs, and optionally writes them into their settings.json. This skill does **not** analyze code, dispatch agents, or modify repository content. It only reads / writes `settings.json` files.

## `--help` / `-h` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, delegate to the helper with `--help` and exit — the helper owns the canonical help text.

## Step 1 — Parse arguments

Parse `--repo <path>`, `--output <path>`, `--plugin-dir <path>`, `--scope <scope>`, `--update`, and
`--json` from the invocation. Any remaining tokens are ignored. Default
`REPO_ROOT` by resolving the git repository root (so that the skill works
correctly even when invoked from a subdirectory such as `docs/security`);
default `OUTPUT_DIR` to `$REPO_ROOT/docs/security`; default `SCOPE` to
`local`.

If `--repo` was **not** passed, resolve REPO_ROOT from the git repository root:

```bash
if [ -z "$REPO_ROOT" ]; then
  REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
fi
```

## Step 2 — Run the helper

Delegate to the Python helper that owns the formatting and JSON merging:

```bash
ARGS="--repo-root $REPO_ROOT --output-dir $OUTPUT_DIR --plugin-dir $CLAUDE_PLUGIN_ROOT --scope $SCOPE"
[ "$UPDATE_MODE" = "true" ] && ARGS="$ARGS --update"
[ "$JSON_MODE"  = "true" ] && ARGS="$ARGS --json"
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_permissions.py" $ARGS
```

Capture the helper's exit code and propagate it.

**IMPORTANT: print the helper's stdout verbatim and stop. Do NOT add any text before or after it — no summary, no paraphrase, no "All permissions are already configured" sentence, no closing remark of any kind. The helper's output is the complete and final response.**
