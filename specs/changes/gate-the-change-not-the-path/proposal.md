# Gate the change, not the path

## Problem

The operator approves specification changes constantly, and almost none of those approvals are the ones the rules ask for.

Two gates hold `docs/internal/decisions.md`: `requirements_hook.py` asks before any recognizable write, and `check_specs.py --changed-against` requires a proposal whenever the path appears in a pull request's diff. Both hold the file. The rule they enforce holds an entry: the register's own header asks the operator before an entry is loosened, a guard widened, or a pinned value raised.

Measured over the 197 commits since the binding split `0361a758`, the register changed in 8 commits. They added 11 rows, removed none, and modified exactly one, `OR-10`. The prose around the rows did not change. Eleven of those twelve entry changes were additions, which the register's rule does not ask anyone to approve, and each of them still cost an interactive prompt and a CI proposal.

The catalog is a different case and is not part of this problem. `specs/requirements.md` changed in 5 of the same 197 commits, and `specs/README.md` states that the operator approves a requirement's ID, title, and normative text, so a new ID is a new promise that the gate is right to hold.

## Cause

A `PreToolUse` hook cannot see the file a call would produce, and both hooks decide on the target path alone. An `Edit` payload does carry `old_string` and `new_string`, which answers a narrower question that is enough here: does everything the call replaces survive it byte-identical? The CI gate has the base revision available and compares only path names.

Underneath that, the register has no entry rule. It states how to change an entry and how to find one, never when a new one is warranted, so every invariant a bug fix establishes becomes a row. The file now holds 137 rows, 22 of them under Orchestration, where 7 arrived in the last three weeks from telemetry and lifecycle fixes. 70 of the 137 IDs are cited in no binding, test, script, agent, contract, or changelog entry, and for several of them the named guard already states the same rule and fails on it.

## Goal

The approval load matches the rule: adding a decision is reviewed work, and changing, removing, or relaxing one needs the operator. The register keeps recording standing choices rather than accumulating one row per fixed bug.

## Non-goals

- Loosening the catalog gate. `specs/requirements.md` keeps asking on every write and requiring a proposal for every change.
- Retiring the rows that the guards already carry. That review is listed as open work; it removes decisions, which is exactly the case the operator approves.
- Closing the hooks' known blind spot. A path that reaches a writer through a variable, a heredoc, or an interpreted script is invisible to a pattern, as `spec_guard.py` documents. Diff review covers it, and this change does not widen or narrow it.

## Approach

`check_specs.py --changed-against <ref>` reads the register at the base revision and compares entries. A diff that only adds rows passes. A row whose text changed, a row that is gone, or a change to the prose around the rows needs a proposal. Without a readable base revision the register is held exactly as the catalog is.

`requirements_hook.py` allows an `Edit` or `MultiEdit` whose every replacement survives byte-identical in what it writes. `Write`, `replace_all`, and shell writes keep asking, because none of them can be read as additive from the payload alone.

The register gains the entry rule it was missing, and the seven Orchestration rows that carry an incident narrative are trimmed to the pointer their own header asks for. Each narrative was verified to survive at the code it points at before it was removed from the row; the one exception, `OR-22`, moved into the docstring of the test module that pins it.
