---
name: setup-target
description: Write the required Claude Code permission allow-list into a target repository so that /appsec-advisor:create-threat-model runs without permission prompts. One-shot setup; idempotent.
---

You are performing a one-shot setup that writes the required Claude Code permission rules into a target repository's `.claude/settings.json`. This skill does **not** analyse code, dispatch agents, or modify repository content beyond `.claude/settings.json`.

## Step 1 — Parse arguments

Recognized flags:

  `--repo <path>`  `--output <path>`  `--plugin-dir <path>`  `--scope <scope>`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `PLUGIN_DIR`, `SCOPE`.
Default `REPO_ROOT` to the current working directory (do NOT fall back to the
plugin repo root — this skill is always about a *target* repo, not the plugin
itself).  Default `OUTPUT_DIR` to `$REPO_ROOT/docs/security`. Default `SCOPE`
to `project` (writes `<repo>/.claude/settings.json` — committed by the repo
maintainer so all contributors get prompt-free runs automatically).

### Reject unknown arguments (hard fail)

If the invocation contains any token that is not one of the recognized flags
above — or is not the value consumed by `--repo` / `--output` /
`--plugin-dir` / `--scope` — DO NOT proceed. Print the block below verbatim
to stderr, substituting `<TOKEN>`, then exit with status 2:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:setup-target accepts only:
  --repo <path>        Target repository to configure (default: cwd)
  --output <path>      Output directory for scan artefacts (default: <repo>/docs/security)
  --plugin-dir <path>  Plugin install directory (default: $CLAUDE_PLUGIN_ROOT)
  --scope <scope>      Settings scope: project (default) | local | user
                         project → <repo>/.claude/settings.json        (committed, shared; default)
                         local   → <repo>/.claude/settings.local.json  (gitignored, personal)
                         user    → ~/.claude/settings.json             (global, all projects)

Run `/appsec-advisor:setup-target --help` for details.
```

## Step 2 — Create the .claude directory if absent

```bash
mkdir -p "$REPO_ROOT/.claude"
```

## Step 3 — Write the permissions

Call `check_permissions.py` with `--update` so it merges the required entries
(and promotes any user-only entries to project scope):

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_permissions.py" \
  --repo-root "$REPO_ROOT" \
  --output-dir "$OUTPUT_DIR" \
  --plugin-dir "$PLUGIN_DIR" \
  --scope "$SCOPE" \
  --update
```

Capture stdout, stderr, and exit code.

## Step 4 — Report

If the helper exited 0, print its stdout verbatim, then add exactly one line:

```
Restart Claude Code (or reload the session) in <REPO_ROOT> for the new permissions to take effect.
```

If the helper exited non-zero, print its stderr verbatim and exit with the
same code.

**Do NOT add any other text — no preamble, no summary, no closing remark.**
