---
name: check-permissions
description: Preflight the Claude Code permission allow-list for the AppSec plugin. Reports which Bash/Write/Edit/Read rules from data/required-permissions.yaml are missing from the user's settings.json, so unattended /appsec-advisor:create-threat-model runs do not block on prompts. Read-only by default; --update merges missing entries into a chosen scope.
---

You are running a preflight check that tells the user which Claude Code permission rules are still needed for unattended AppSec runs, and optionally writes them into their settings.json. This skill does **not** analyze code, dispatch agents, or modify repository content. It only reads / writes `settings.json` files.

## `--help` / `-h` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, delegate to the helper with `--help` and exit — the helper owns the canonical help text.

## Step 1 — Parse arguments

Recognized flags:

  `--repo <path>`  `--output <path>`  `--plugin-dir <path>`  `--scope <scope>`
  `--update`  `--json`  `--help` | `-h`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `PLUGIN_DIR`, `SCOPE`,
`UPDATE_MODE`, `JSON_MODE`. Default `REPO_ROOT` by resolving the git
repository root (so that the skill works correctly even when invoked from a
subdirectory such as `docs/security`); default `OUTPUT_DIR` to
`$REPO_ROOT/docs/security`; default `SCOPE` to `local`.

### Reject unknown arguments (hard fail)

If the invocation contains **any** token that is not one of the recognized
flags above — or is not the value consumed by `--repo` / `--output` /
`--plugin-dir` / `--scope` — DO NOT proceed. Do not invoke the helper.
Print the following block verbatim to stderr, substituting `<TOKEN>` with
the first unknown token, then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:check-permissions accepts only:
  --repo <path>        Repository to inspect (default: git repo root of cwd)
  --output <path>      Output directory (default: <repo>/docs/security)
  --plugin-dir <path>  Plugin install directory (default: $CLAUDE_PLUGIN_ROOT)
  --scope <scope>      Settings scope: local | user | project (default: local)
  --update             Merge missing permission entries into settings.json
  --json               Emit the result as machine-readable JSON
  --help, -h           Show full help and exit

Run `/appsec-advisor:check-permissions --help` for details.
```

A flag that takes a value counts as unknown when its value is missing —
treat the flag itself as the offending token. Repeated occurrences of the
same flag are allowed; the last value wins.

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
