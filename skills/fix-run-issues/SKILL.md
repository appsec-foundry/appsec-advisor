---
name: fix-run-issues
description: Identify and apply fixes for issues recorded in $OUTPUT_DIR/.run-issues.json by the previous create-threat-model run. Auto-applies safe well-bounded fixes (agent-frontmatter maxTurns bumps, etc.) with confirmation; prints manual-review guidance for everything else. Persists an audit trail in .run-issues-fixes.json so applied fixes are inspectable and reversible.
---

You are the **fix-run-issues** skill. Your job is to read
`$OUTPUT_DIR/.run-issues.json` (written by `aggregate_run_issues.py` +
`recommend_fixes.py` at the end of the previous create-threat-model run),
present each issue with its structured `fix_recommendation`, apply
auto-eligible fixes after confirmation, and write an audit trail.

This skill is **non-invasive by default**. It only modifies plugin files
when:

1. The issue's `fix_recommendation.auto_applicable == true` AND
2. The user confirmed the action (or `--yes` was passed) AND
3. The action's `type` is in the safe list (`edit_file` with explicit
   find/replace strings).

For every non-auto-applicable issue (or any auto-fix the user declines),
the skill prints the manual remediation guide and moves on.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block
verbatim and exit. Do not call any tools, do not read other files.

```
/appsec-advisor:fix-run-issues — Apply auto-eligible fixes from .run-issues.json

USAGE
  /appsec-advisor:fix-run-issues [--repo <path>] [--output <path>]
                                  [--yes] [--dry-run] [--only <category>]
                                  [--json]

FLAGS
  --repo <path>      Repository (default: current working dir)
  --output <path>    Output dir (default: <repo>/docs/security)
  --yes              Apply all auto-eligible fixes without per-fix
                     confirmation. Default is interactive (one [y/n/skip]
                     prompt per fix).
  --dry-run          Show what would be fixed without writing anything.
                     Implies --yes (no prompts since nothing is applied).
  --only <category>  Only apply fixes of the given category
                     (e.g. agent_def, config_tune). Manual-review issues
                     are still printed.
  --json             Emit the result as machine-readable JSON.

WHAT IS APPLIED AUTOMATICALLY
  Categories with auto_applicable=true AND confidence=high:
    agent_def    Bump <agent>.md maxTurns + matching test ceiling

WHAT IS PRINTED FOR MANUAL REVIEW (never auto-applied)
  investigate, user_action, skill_spec, yaml_edit (with confirm),
  no_fix (informational), rerun

OUTPUTS
  $OUTPUT_DIR/.run-issues-fixes.json
    Audit trail: every fix attempted (applied/declined/failed) with
    before/after diffs and the user's decision. Inspectable, useful for
    rollback (the file lists the exact reverse-edit per applied fix).

WHEN TO USE
  After a create-threat-model run that produced a §Run Issues appendix
  in threat-model.md (or a "-- Run Issues --" block in the completion
  summary). Run from the same directory the assessment was run in.
```

## Routine — non-help invocations

For any other arguments (including no arguments), follow these steps in order:

### Step 1 — Resolve paths

- `REPO_ROOT`: `--repo <path>` if given, else current working directory.
- `OUTPUT_DIR`: `--output <path>` if given, else `$REPO_ROOT/docs/security`.
- Verify both exist. If `OUTPUT_DIR` is missing, print:
  > Error: $OUTPUT_DIR does not exist. Run /appsec-advisor:create-threat-model first.
  ...and exit 1.

### Step 2 — Locate `.run-issues.json`

```bash
ISSUES_FILE="$OUTPUT_DIR/.run-issues.json"
if [ ! -f "$ISSUES_FILE" ]; then
  echo "No .run-issues.json found in $OUTPUT_DIR."
  echo "Either no run has been performed yet, or the previous run had no issues"
  echo "(in which case .run-issues.json was not written)."
  echo ""
  echo "Run /appsec-advisor:create-threat-model first."
  exit 0
fi
```

### Step 3 — Print summary

Read `.run-issues.json` and print a header showing the issue counts and
how many are auto-applicable.

```
═══════════════════════════════════════════════════════════════
  Fix Run Issues — auto-applicable fixes for the prior run
═══════════════════════════════════════════════════════════════

  Source        : $OUTPUT_DIR/.run-issues.json
  Issues        : N total (E errors · W warnings · P perf · R recovery)
  Auto-fixable  : K of N (will be applied after confirmation)
  Manual review : (N-K) of N (printed but not modified)

```

### Step 4 — Iterate over issues

For each issue in `.run-issues.json`:

1. Print a short summary block:
   ```
   ───────────────────────────────────────────────
   [ISSUE-XXX] <category> (<severity>)
     Title: <title>
     Evidence: <log_file>:<log_line>
     Fix: <fix.category> | auto=<bool> | confidence=<level>
   ```

2. Print the fix's `summary` and `rationale`.

3. **If auto-applicable AND confidence=high AND not `--dry-run`:**
   - Print "Actions to apply:" and list each action with find/replace
     content.
   - If `--yes` was not passed: ask `Apply this fix? [y/n/skip]`
     - `y` → apply
     - `n` → skip and record decision in audit trail
     - `skip` → same as `n` but mark as "deferred"
   - If applying: use the **Edit tool** (NOT Bash sed) to perform each
     `edit_file` action. For each action:
     - Open `target` (resolved relative to `$CLAUDE_PLUGIN_ROOT`).
     - If `find` matches a line in the file: Edit replace `find` → `replace`.
     - If `find` does NOT match but `fallback_find` is provided: try that.
     - On success: record applied action + before/after diff in audit trail.
     - On failure (e.g. file not found, find-string not present): record
       as `failed` with reason; continue with next action.
   - After all actions: run the `verification` commands. If any fails,
     mark the fix as `applied_with_verification_failure`.

4. **Otherwise (manual review, or auto-fix declined):**
   - Print "Manual review required:" + the actions list as guidance.
   - Record decision (`manual` or `declined`) in audit trail.

### Step 5 — Write audit trail

After iterating, write `$OUTPUT_DIR/.run-issues-fixes.json`:

```json
{
  "schema_version": 1,
  "generated": "<ISO 8601>",
  "applied":  [<list of issue_id + action_index + before/after diff>],
  "declined": [<list of issue_id + reason>],
  "manual":   [<list of issue_id>],
  "failed":   [<list of issue_id + error>]
}
```

This file is reaped by `runtime_cleanup.py` on the next successful skill
run (so it doesn't accumulate forever) but persists across one cycle so
the user can roll back if needed.

### Step 6 — Print final summary

```
───────────────────────────────────────────────
  Summary
───────────────────────────────────────────────
  Applied          : N fix(es)
  Declined         : N
  Manual review    : N (printed for user attention)
  Failed           : N (see .run-issues-fixes.json for details)

  Audit trail      : $OUTPUT_DIR/.run-issues-fixes.json

  Next steps:
    1. Review the applied fixes (git diff agents/ tests/)
    2. Run pytest tests/ to verify (already run for each fix's verification)
    3. Re-run /appsec-advisor:create-threat-model to confirm issues are fixed
```

## Safety rules

- **NEVER** apply a fix where `auto_applicable=false` (regardless of `--yes`).
- **NEVER** apply a fix where `confidence != "high"` (regardless of `--yes`).
- **NEVER** modify `threat-model.md`, `threat-model.yaml`, or any file
  outside the plugin root (`$CLAUDE_PLUGIN_ROOT`) — auto-fixes target
  plugin self-modification only.
- **NEVER** apply more than 5 auto-fixes in one invocation (rate limit).
  If more are pending, instruct the user to re-run.
- **ALWAYS** verify fixes with the `verification` commands before
  reporting success.

## Implementation notes for the LLM running this skill

- Use the `Read` tool on `.run-issues.json`, parse JSON in your head.
- Use the `Edit` tool for `edit_file` actions — pass exact `find` /
  `replace` strings from the action.
- Use the `Bash` tool to run `verification` commands (typically `pytest`).
- Use the `Write` tool to persist `.run-issues-fixes.json`.
- For `--json` output: emit a single JSON object on stdout instead of
  the human-readable per-issue blocks.
