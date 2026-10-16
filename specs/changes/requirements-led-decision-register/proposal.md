# Keep the decision register subordinate to product requirements

## Problem

The decision register contains 253 table entries, many of which repeat a local implementation rule or regression test. Its convention asks every guard to name a decision ID, and `test_register_exists_and_has_rows` requires more than 50 entries. Those rules encourage documentation growth independently of architectural value.

## Intended result

`requirements.md` remains the primary, concise product specification. Technical bindings connect requirements to contracts, implementation and tests. The decision register records only significant technical choices that those requirements leave open. Retiring duplicate documentation does not change product behavior or remove its implementation, contracts or regression tests.

## Approved admission rule

The operator approved the following exact rule, its meaning and the prepared cleanup on 2026-10-15.

> Requirements are the primary source of product behavior. Keep them simple and stable; derive technical contracts, implementation and tests from them through the requirement bindings.
>
> Add a decision only for a long-lived, cross-cutting technical choice that the requirements leave open and whose reversal would have significant consequences. State the chosen approach, the alternative, the reason and the consequences. Link to its requirement and technical evidence where applicable.
>
> Bug fixes, scanner rules, algorithms, local implementation details and invariants already explained by contracts or tests do not need decision entries. A code change or a new test alone never requires an entry. Keep those details at their authoritative source; do not move them into requirements when retiring entries.

## Register cleanup

Retain the existing wording and IDs of `CR-1`, `OR-1`, `OR-7`, `CE-5`, `FE-5`, `SA-4`, `IN-3`, `MR-1`, `MR-3`, `MR-8`, `EX-1` and `EX-2`, together with principles `P-1` through `P-7`. These cover control-plane ownership, configuration separation, observational telemetry, prompt caching, passive analysis, taxonomy separation, incremental-run cost trade-offs, isolated model exchanges, workspace and publication compatibility, and supported organization extensions.

Retire the remaining 241 table entries and record their IDs without reusing them. Their original text remains available in `docs/internal/decisions.md` at commit `338e5e7cb41355af963421507ad3c410d53df8b8`. Historical test references remain valid through that retirement record; active requirement bindings and retained decisions must not point at retired decisions as current technical context.

Keep requirement wording, binding paths, documents, coverage classifications and guard lists unchanged. Remove retired decision IDs from the bindings. Remove the register convention requiring every test to cite a decision ID. Align `AGENTS.md` and `specs/README.md` with the admission rule, preserving the existing approval requirement for exact requirement and decision wording.

## Verification

Replace the register's minimum size with a non-empty check. Accept explicitly retired IDs in historical assertion messages while continuing to reject unknown IDs for registered prefixes. Retain reference, uniqueness, retirement, guard-existence and path checks. Run the register checks, the affected specification checks, the caching-register reference check, and lint and format checks for the changed test file. Runtime tests and fixture replays are outside this documentation change.
