# Why specification approvals keep firing, and what actually earns one

Read-only audit of `specs/requirements.md`, `docs/internal/decisions.md`, `scripts/spec_guard.py`, `scripts/requirements_hook.py`, and `scripts/check_specs.py`. Measured at `522ab9a6`. It follows `analysis-spec-enforcement-and-genericity-2026-08-23.md`, whose genericity verdict was measured over a window in which the catalog did not change at all.

## Summary

The catalog is not the problem. The gates are: both of them hold a *path*, while the rule they enforce is about a *change to an existing entry*. Since the binding split, `docs/internal/decisions.md` was edited in 8 commits that added 11 rows, removed none and modified exactly 1. Eleven of those twelve entry changes are work the register's own rule does not ask the operator to approve, and every one of them cost an interactive prompt plus a CI proposal.

The second problem is the register's entry criterion: it has none. `decisions.md` says how to change an entry and how to find one, never when a new one is warranted. The result is a file that has grown to 137 rows, 22 of them under Orchestration, where the last seven entries are post-mortems of individual bugs.

## What triggers an approval

| Gate | Where | Fires on |
|---|---|---|
| `spec_guard.py` | `PreToolUse`, local dev | any recognizable write to `specs/requirements.md` |
| `requirements_hook.py` | `PreToolUse`, local dev | any recognizable write to `docs/internal/decisions.md` |
| `check_specs.py --changed-against` | CI, pull requests | either held file changed with no `specs/changes/*/proposal.md` in the same diff |

None of the three can distinguish adding an entry from weakening one. A `PreToolUse` hook sees the tool input before the write, and both hooks use the target path alone — although an `Edit` payload carries `old_string` and `new_string`, which is enough to tell a pure insertion from a rewrite. The CI gate compares against a base ref and could read the diff outright; it only checks which paths appear in it.

## Measurement since the binding split (`0361a758`, 197 commits)

| Path | Commits | Rows added | Rows modified |
|---|---|---|---|
| `specs/requirements.md` | 5 | 4 requirements | 2 texts |
| `docs/internal/decisions.md` | 8 | 11 | 1 |
| `data/requirement-bindings.yaml` | 12 | — | — |

The split did what it was meant to do: refactor churn now lands in the bindings, which changed more often than either held file. What it did not address is that both held files are gated as a whole, so an addition is charged the price of a rewrite.

## The decision register has no entry rule

The header states the change rule — "loosening an entry, widening a guard or raising a pinned value is not a judgement call you make on your own" — and a lookup rule. Nothing states what qualifies as an entry in the first place, so anything a bug fix establishes gets a row, and the register drifts from a set of standing choices toward a changelog of invariants.

Three symptoms are visible in the file:

Entries record the incident rather than the choice. 31 rows carry a date; `OR-17`, `OR-19`, `OR-20`, `OR-21`, and `OR-22` put the failure narrative, its measurements, and its date in the Rationale column, where the header asks for a pointer to where the reasoning lives. `OR-17` also pins 15 and 60 minutes in the decision text, against the header's own rule that values live in their own files.

Most rows are load-bearing nowhere else. 70 of 137 IDs are cited nowhere else in the repository. For a row like `OR-20` — "a stopped child owns no further turns" — the named guard `test_a_stopped_child_does_not_own_the_parents_later_turns` already fails when the rule is broken, and it says the same thing. The register adds approval weight to it, not detection.

The Orchestration section absorbs everything. It holds 22 of the 137 rows, and 7 of those were added between 2026-08-20 and 2026-09-05 from telemetry and lifecycle fixes. That is where the approval load is generated.

A workable entry test, stated as the register's own gate: a row belongs here when reversing it would be cheap, silent, and later expensive — a choice a maintainer could undo without a test going red, or one whose guard failure looks like a test worth editing. An invariant that a named guard already fails on, and whose name says what it protects, is recorded by that guard. The failure that prompted it belongs in the commit message or an analysis document.

## The requirements catalog is close to generic

29 active requirements, 18 retired, no paths, test names, or model names. The `TECHNICAL_FIELD_RE` check keeps the binding fields out. Three texts have drifted toward mechanism, all three added by a fix or a feature that had to touch them:

- `REQ-RPT-003` closes with a rule about one inline-code format across report sections. That is a renderer convention, owned by `agents/shared/prose-style.md` and the schema invariants; the promise a user would recognize is the sentence before it.
- `REQ-RPT-006` names the artifact shapes — canonical YAML, narrower exports, "native fields or bounded text". The promise is that exports preserve traceability; the field shapes belong to the export schemas.
- `REQ-CFG-003` specifies a maintenance command in six clauses, down to a refresh never being part of a release gate. That is a decision and a contract, not a promise a plugin user would miss.

Their common cause is the same as the decision register's: a requirement is written because a feature landed, not because a new promise was made to a user. A feature that keeps every existing promise intact needs a binding, not a requirement.

## Options

**A — Gate the change, not the path.** Teach `check_specs.py --changed-against` to require a proposal for the register only when an existing row changed, a row disappeared, or the text around the rows changed; a diff that only adds rows passes. Teach the register's hook the same rule for `Edit`: allow when everything the call replaces survives byte-identical in what it writes. A `Write`, a `replace_all`, and a shell write keep asking, and the catalog keeps its whole-file hold, because there the operator approves a new ID as well. This is the register's own stated rule, enforced where it can actually be checked, and it removes the eleven-of-twelve prompts without loosening the case the gate exists for.

**B — Give the register an entry rule.** Add the entry test above to the register header, move the incident narratives out of the Rationale column into the commit or an analysis document, and lift the pinned values in `OR-17` into the file that owns them. Cost is a header edit and a rewrite of five rows.

**C — Retire what the guards already carry.** Review the 70 uncited rows; where a named guard states the same rule and fails on it, drop the row and list the ID under `Retired IDs`. This is a separate pass and the only one that shrinks the file rather than slowing its growth.

A and B are independent. C is only worth doing after B, because B is what decides which rows fail the test.

## Status

A and B landed with this document, recorded in `specs/changes/gate-the-change-not-the-path/`. The CI gate compares register entries against the base revision, the register carries an entry rule, `OR-16` through `OR-22` are trimmed to the pointer their own header asks for, and the Orchestration table is one table again. The hook half of A ships as `requirements-hook.patch` in the same directory: `scripts/requirements_hook.py` and `scripts/spec_guard.py` are `Edit`-denied so the guard cannot rewrite itself, so an operator applies it from an ordinary terminal.

C is open, and so is the question of whether the three requirement texts named above are trimmed. Both remove or change normative text, which is the case the operator approves.
