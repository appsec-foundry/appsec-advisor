# Structured verdict and gate

Loaded by SKILL.md Step 2.5 only when `save_json` or `gate_mode` is set. Run Step 2.5 right after grading and Step 5 after Step 4.

## Step 2.5 — Persist the structured verdict

The verdict is the canonical output the saved reports and the
gate derive from. Build it directly with the `Write` tool — you already produced
these fields while grading; keep it quiet (no narration). A short one-off
serialisation script is acceptable here since an artifact was explicitly
requested, but the plain run must never reach this step.

**Assemble** one object per `schemas/requirements-audit.schema.json`:

```json
{
  "version": 1,
  "generated_at": "<ISO 8601 UTC>",
  "repository": "<git remote URL or directory name>",
  "requirements_source": "<remote|cached|local|demo>",
  "catalog": { "description": "<…>", "generated": "<…>", "url": "<…>", "count": <n> },
  "filter": "<category_filter or null>",
  "demo": <true|false>,
  "priority_floor": "<priority_floor>",
  "summary": { "total": 0, "pass": 0, "partial": 0, "fail": 0, "unverifiable": 0, "not_applicable": 0 },
  "results": [
    {
      "id": "SEC-SQL", "category": "...", "priority": "MUST",
      "status": "FAIL", "in_scope": true,
      "requirement_text": "<verbatim catalog text>", "title": "Parameterized SQL Queries",
      "evidence": [ { "file": "routes/search.ts", "line": 23 } ],
      "finding": "...", "risk": "...", "fix": "...", "effort": "M",
      "url": "<requirements[].url or null>",
      "blueprint": { "id": "...", "section": "...", "url": "..." },
      "threats": [ { "f_id": "F-014", "risk": "High", "title": "..." } ]
    }
  ]
}
```

- One `results[]` entry **per graded requirement** — every status, not only the open ones. `in_scope` is `true` except for `NOT_APPLICABLE` (then `false`).
- Leave `summary` as zeros; the script recomputes it. Pull `blueprint` from `blueprint_map[<id>]` and `threats` from `req_to_threats[<id>]` when present.

**Write** it to `$AUDIT_OUTPUT_DIR/.requirements-audit.json`, then validate +
recompute the summary deterministically:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/requirements/requirements_report.py" \
  --audit "$AUDIT_OUTPUT_DIR/.requirements-audit.json" --write
REPORT_EXIT=$?
```

- Exit `0`: the printed `total=… pass=… partial=… fail=… unverifiable=… not_applicable=…` line is **authoritative** — use exactly these numbers for the Result block in Step 3a (do not re-count).
- Exit `2`: the verdict is schema-invalid (a grading-output bug). Fix the offending `results[]` entry and re-write, then re-run — do not render counts you cannot validate.

## Step 5 — Gate (deterministic; advisory by default)

The **script**, not the model, decides whether the audit blocks. Run it on the
verdict — advisory (prints the summary, exit 0) unless `--gate` enforces it:

```bash
GATE_ARGS=(--verdict "$AUDIT_OUTPUT_DIR/.requirements-audit.json"
           --priority-floor "$PRIORITY_FLOOR" --gate-on "$GATE_ON")
[ "$GATE_MODE" = "true" ] && GATE_ARGS+=(--gate)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/requirements/requirements_gate.py" "${GATE_ARGS[@]}"
GATE_EXIT=$?
```

- The script prints `requirements-gate: PASS` or `… BLOCK/WARN — <n> gating requirement(s)` with the offending IDs. Surface that line as-is.
- When `GATE_MODE` is true, **propagate the exit code**: `exit "$GATE_EXIT"` (1 ⇒ a MUST-or-above in-scope requirement failed at/above the floor). In advisory mode the script always returns 0.
- A gating requirement is recomputed authoritatively as `in_scope AND status==FAIL (or PARTIAL with --gate-on partial) AND priority >= floor` — the model's `results[]` feed it; it never trusts model-side verdict flags.
