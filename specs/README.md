# How the plugin changes

`requirements.md` says what the plugin must do, in sentences a person writes.
Development happens against it: a change that contradicts a requirement is a
change to the requirement first.

The format follows `ai-secure-coding-baseline/specs/`. Two things differ,
because the product here is not one Markdown file: an entry names the paths it
applies to, and its evidence is a deterministic guard rather than a stochastic
model case.

- `requirements.md` — the catalog of current requirements.
- `changes/<name>/` — a change being worked on.
- `archive/<date>-<name>/` — a change that is finished.

## Where requirements come from

Three sources, and no fourth: what you asked for, what this repository already
documents, or a commit that established the behavior. Name the source in the
entry. If none of them settles a question, ask. Do not fill the gap with a rule,
a test obligation, or a scope extension of your own.

## Who writes what

You approve the requirement: the title and the sentence. Whoever writes the
test fills in the guard. An agent cannot edit anything under `specs/` silently;
`scripts/spec_guard.py` routes identifiable writes through a user permission
prompt.

## What belongs here, and what belongs in the decision register

A sentence belongs here when someone using the plugin would recognise it as a
promise and would be let down if it broke. It belongs in
`docs/internal/decisions.md` when it is a build decision: it could have gone
another way, and what matters is the choice and what holds it.

When both are true, the sentence stands here and the entry cites the decision ID
as its source. The register keeps the reasoning and the guard. The sentence has
one home.

Two things belong in neither. Values — numbers, vocabularies, paths, caps — live
in `data/` and `schemas/`; a requirement states the rule, never the value. And a
sentence that only refines an existing requirement goes to the register: the
register may grow, this file has to stay readable in one sitting.

## Entry format

```markdown
## Section name

### REQ-CLN-001 — Short title

The requirement, in one or two plain sentences. Written the way you would say
it to a colleague, without the mechanism.

**Applies to:** `scripts/runtime_cleanup.py`
**Source:** `docs/internal/contracts/cleanup-whitelist.md`, decision `RA-6`
**Guard:** `test_some_name`, `test_other_name`
```

`Applies to` takes repository-relative paths or globs and decides where the
requirement is surfaced. `Source` says where the rule is written. `Guard` takes
test function names or pytest node ids.

## Requirement IDs

`REQ-<AREA>-NNN`. The ID belongs to the behavior, not to the heading: reword the
requirement and it keeps its ID, split it and the new half gets a new one,
remove it and the ID retires. Never reuse one. The prefix collides with no
report anchor (`T`, `F`, `M`, `W`, `C`, `TH`) and no decision prefix.

## What is enforced

`python3 scripts/check_specs.py` runs inside `make check`, takes about a second,
and calls no model. It fails on a missing, duplicate, or malformed ID, a missing
field, a guard that no test defines, a decision ID the register does not carry,
and an applies-to path that matches nothing.

`python3 scripts/check_specs.py --for <path>` prints the requirements that apply
to a file. Run it before changing that file.

`python3 scripts/check_specs.py --changed-against <ref>` fails when this file or
the decision register changed with no change directory under `changes/`. It
belongs in CI, where the base ref is always resolvable.

`scripts/spec_guard.py` asks for user approval before an agent changes a file
under `specs/` through `Edit`, `Write`, `MultiEdit`, `NotebookEdit`, a
recognizable Bash or PowerShell writer, or a recognizable mutating MCP tool.
Malformed hook input fails closed. The hook is wired in this checkout's
`.claude/settings.json` and is not shipped with the plugin.

`scripts/requirements_hook.py` still surfaces the requirements that govern an
edited implementation file and separately holds the decision register. It is
also development-only.

## What is not enforced

A requirement no test expresses carries `— (no guard written)`, or
`— (guard not located)` when one may exist and was not found. The vocabulary is
the decision register's. Such an entry is advisory: it is surfaced, not held,
and the catalog says so rather than implying enforcement it does not have.

A deterministic check keeps the structure and the references honest. It cannot
tell whether a requirement is faithful to its source or whether a named guard
really bites. That stays a review.
