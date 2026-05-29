# Bug: appsec-qa-reviewer emits a `.qa-content-repair-plan.json` that always fails schema validation

**Plugin:** appsec-advisor 0.4.0-beta (analysis v2)
**Severity:** medium — silent functional gap (QA content-repair never applies)
**Found:** 2026-05-29, create-threat-model full run on OWASP Juice Shop

## Symptom

During Stage 3, `apply_content_repair.py` rejected the QA reviewer's plan:

```
error: plan failed validation:
  - schema_version mismatch: expected 1, got None
```

The plan the `appsec-qa-reviewer` agent wrote:

```json
{
  "plan_version": "1.0",
  "generated": "2026-05-29T00:00:00Z",
  "issue_category": "toc_closure",
  "issue_count": 4,
  "actions": [ { "check": "toc_closure", "type": "linkify_file_path", ... } ]
}
```

## Root cause

`schemas/qa-content-repair-plan.schema.json` requires the top-level envelope
`["schema_version", "generated", "status", "actions"]`, with
`schema_version` = integer const `1`.

`scripts/apply_content_repair.py:238` hard-rejects any plan whose
`schema_version != 1`.

But `agents/appsec-qa-reviewer.md` (§"Final step", item 5) only documents the
**action-item** fields (`check`, `type`, `fragment`, `operation`, `rationale`,
`evidence`) and points at the schema file by path. It never shows the required
**top-level envelope**. The only fully-spelled JSON example in that section is
for `.qa-status.json` (item 4). With no envelope example, the LLM invents its
own keys (`plan_version`, `issue_category`, `issue_count`) and omits both
`schema_version` and `status` — so the plan is structurally guaranteed to fail
validation every time.

## Impact

Every content-repair plan this agent emits is discarded by the applier. The
QA reviewer believes it queued a fix (reports `content-repair-plan=yes`), but
the fix never reaches `threat-model.md`. On this run it would have shipped 4
broken `#ci-cd-pipeline` anchors had the orchestrator not fixed the root cause
in YAML by other means.

## Proposed fix (source of truth = the prompt)

In `agents/appsec-qa-reviewer.md` §"Final step" item 5, add an explicit
top-level envelope example before the action-field description:

```json
{
  "schema_version": 1,
  "generated": "<ISO 8601 UTC>",
  "status": "repair_required",
  "actions": [
    {
      "check": "toc_closure",
      "type": "linkify_file_path",
      "fragment": ".fragments/<name>.md",
      "operation": "replace_string",
      "search_text": "...",
      "replace_text": "...",
      "rationale": "..."
    }
  ]
}
```

Emphasize: `schema_version` MUST be the integer `1` (not `plan_version`,
not a string), and `status` is required (`pass | repair_required | manual_review`).

### Optional defense-in-depth

`apply_content_repair.py` could accept a legacy `plan_version` alias and a
missing `status` (default `repair_required`) so older/sloppy plans still apply,
but the prompt fix above is the correct primary remedy.

## Note on /appsec-advisor:fix-run-issues

Not applicable to this defect: (a) `.run-issues.json` is reaped by
`runtime_cleanup.py --stage post-qa`, so there is no input left after a clean
run; (b) the aggregator's auto-fix scope is agent-frontmatter knobs
(e.g. maxTurns), not prompt/schema contract mismatches.
