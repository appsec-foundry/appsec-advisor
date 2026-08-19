# Compact Thin Stage 4

Run only for a controller action with `stage=stage4`. Require the canonical
Markdown and YAML; missing inputs are blocking rather than an architect skip.

Mark Stage 4 in progress, start the fixed heartbeat, and print the architect
handoff. Dispatch `appsec-advisor:appsec-architect-reviewer` with description
`Architect review of threat model` and explicit `ARCHITECT_MODEL`. Pass only
`REPO_ROOT`, `OUTPUT_DIR`, `CONTEXT_FILE`, `ASSESSMENT_DEPTH`, and `MODEL_ID`.
The reviewer may write `.architect-review.md`, `.architect-status.json`, and an
optional `.architect-repair-plan.json`; it is read-only for the report, YAML,
SARIF, and fragments.

An Agent error is non-fatal only when `.architect-status.json` already records
`status=pass` plus its error. An absent, unreadable, or unknown status aborts;
the runtime never synthesizes a pass status for a failed review.

When status is `repair_required`, use a fresh counter capped by
`MAX_REPAIR_ITERATIONS`. Dispatch only
`appsec-advisor:appsec-fragment-fixer` with `REPAIR_MODE=true` and the absolute
architect plan path. After each repair, run `SKILL-thin-stage3.md` in full so
the canonical compose order, secret gate, QA gate, and integrity gates cover
the new bytes, then repeat the architect review. Exhaustion is blocking and
preserves the final plan.

Record Stage-4 and repair usage under separate variants. Send the final
heartbeat, stop the watchdog, mark Stage 4 complete only for a pass status, and
call `orchestration_controller.py next`. Honor its returned instruction file.
