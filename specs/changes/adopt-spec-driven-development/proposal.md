# Adopt specification-driven development

## Problem

The repository states what must hold in four places — `AGENTS.md`, six contracts
under `docs/internal/contracts/`, the decision register, and the schemas — and
enforces a large part of it through tests. But enforcement is only visible from
the guard side. There is no list of what the plugin must do, so nothing shows
which requirement a test protects, and nothing fails when a requirement loses
its guard.

Measured on the register: of 121 rows, 69 name a test function, 27 name only a
test file, and 25 name no guard at all. Around 40 percent of the standing rules
are therefore unenforced or only vaguely enforced, and reading a row does not
reveal which case it is.

Two further gaps. A rule reaches an agent as text at session start, which is the
weakest place it could sit — the further a session runs, the less of it is left.
And approval is prose: `decisions.md:6` and `AGENTS.md:21` ask the agent to
consult the operator before changing a decision, and nothing checks that it did.

## Goal

A short catalog of central requirements written in plain language, each bound to
the files it governs and the test that fails when it breaks. A checker that
keeps those bindings real. A hook that denies an agent the catalog and the
register, and that puts the governing requirements in front of it at the moment
it edits a file.

## Non-goals

- Replacing or moving `docs/internal/decisions.md`. It keeps governing
  decisions; the catalog cites a decision instead of restating it.
- A second catalog of the same behavior. One sentence has one home.
- Cataloguing every rule the code follows. This is the short list, not an index.
- Migrating the existing `implplan-`, `fixplan-` and `plan-` documents into
  `specs/archive/`.
- Writing the missing guards. The catalog names the gaps; closing them is
  separate work.
- Any gate that calls a model or replays a run.

## What it breaks

Nothing at runtime. `specs/` is new, `make check` gains one step, and an agent
loses write access to two files. The development hook is wired in this
repository's `.claude/settings.json` and is deliberately absent from
`hooks/hooks.json`, so nothing here reaches an install.
