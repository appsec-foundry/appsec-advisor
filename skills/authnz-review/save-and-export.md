# Saved report and pentest tasks

Loaded by SKILL.md Step 9 only when `SAVE_FILES=true` or `PENTEST_TASKS=true`. Run Step 9 when `SAVE_FILES=true`, then Step 9b when `PENTEST_TASKS=true`.

## Step 9 — Save files (only when --save)

Only when `SAVE_FILES=true`.

Write `$OUTPUT_DIR/authnz-report.md` using the same circles and bold/link
conventions as the console output, with full Markdown heading structure:

```markdown
# AuthN/AuthZ Review — <repo name>

**Repository:** <REPO_ROOT>
**Date:** <ISO date>
**Requirements:** <REQUIREMENTS_PATH or: none>

## Summary

| Severity  | Count |
|-----------|------:|
| 🔴 Critical | <N> |
| 🟠 High     | <N> |
| 🟡 Medium   | <N> |
| 🔵 Low      | <N> |

| Signal                 | Count |
|------------------------|------:|
| IDOR confirmed         | <N>   |
| Missing auth (routes)  | <N>   |
| JWT misconfigurations  | <N>   |
| Credential policy      | <N>   |
| Privilege escalation   | <N>   |

## AuthN → AuthZ Chains
<!-- omit section when no chains -->
...

## Critical and High Findings
...

## Medium Findings
...

## Low Findings
...
```

`$OUTPUT_DIR/.authnz-report.json` is already in place: the analyzer wrote it
and Step 6 validated it.

Print:
```
  Saved → docs/security/authnz-report.md
  Saved → docs/security/.authnz-report.json
```

---

## Step 9b — Pentest tasks (only when --pentest-tasks)

Only when `PENTEST_TASKS=true`. Run:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/renderers/render_pentest_tasks.py" \
  --authnz "$OUTPUT_DIR/.authnz-report.json" \
  --route-inventory "$OUTPUT_DIR/.route-inventory.json" \
  --output "$REPO_ROOT/docs/security/$PENTEST_FILE" \
  --dialect "$PENTEST_FORMAT" \
  --project "<repo name>"
```

Append `--target-url "$PENTEST_TARGET"` when `PENTEST_TARGET` is not `none`.
The exporter emits one verification task per finding whose CWE is on
`data/pentest-eligible-cwes.yaml` and whose evidence carries file **and**
line — design-level findings without code evidence are dropped, so the task
count is normally lower than the finding count. Every task carries a
`safety` block declaring the run read-only; the target URL is written to
`meta.target.base_url` and never contacted.

If non-zero exit, print the stderr and continue to Step 10 — a failed export
does not invalidate the review.

Print (task count from the exporter's `VALID: wrote <N> pentest tasks` line):
```
  Saved → docs/security/<PENTEST_FILE>  (<N> tasks, <PENTEST_FORMAT>, target <PENTEST_TARGET or: none>)
```
