# Tasks

## Approval

- [x] Operator approves the `REQ-FLW-002` wording.
- [x] Operator approves the `P-1` wording.
- [x] Operator approves the IDs, titles, and text of `REQ-ANA-001` through `REQ-ANA-008`.

## After approval

- [x] Apply the `REQ-FLW-002` text (`specs/requirements.md`).
- [x] Apply the `P-1` text (`docs/internal/decisions.md`).
- [x] Add `REQ-ANA-003` with its binding (work package 2).
- [x] Add each remaining `REQ-ANA` requirement with its binding in the work package that creates its first bound file and guard (`specs/requirements.md`, `data/requirement-bindings.yaml`).
- [x] Resolve the exit-code review point against `P-7` and `OR-14`: `OR-14`'s reject code belongs to the assessment controller's boundary protocol, while `appsec-analyst-cli` is a user-facing CLI with its own documented exit contract (`docs/threat-analyst.md`), like `security-score`.
