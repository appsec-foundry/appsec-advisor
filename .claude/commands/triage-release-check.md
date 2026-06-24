---
description: Triage a failed `make release-check` — read the captured log, identify the failing gate stage, and recommend the producer-side fix. Analysis only; applies nothing unless asked.
---

Triage the most recent `make release-check` failure. This is a maintainer dev
tool — project-local, never shipped with the plugin.

## Source of truth

Read `.cache/release-check.log` (written by the `release-check` target on every
run via `tee`). If it is missing or you suspect it is stale, run
`make release-check` yourself, then read the freshly written log.

Read the log **without dumping it into the conversation** — pull only the
failure region (the first failing stage's output, the pytest summary line, or
the `ERROR:` line). Keep the calling session lightweight.

## The gate is fail-fast

`make release-check` runs `make check` (6 sequential stages) then
`check_release_meta.py`, and aborts on the **first** non-zero stage. So a single
log shows only the first red stage. Triage that one, recommend its fix, and tell
the user to re-run `make release-check` — the next stage (if any) surfaces then.

## Classify the failing stage → producer-side fix

| Stage (in order) | What failed | Recommended fix |
|---|---|---|
| `ruff check` / `ruff format --check` | lint / formatting | Mechanical → `make fix` (auto-repairs). Do **not** hand-edit. |
| `validate_config.py` | a config field is invalid | Correct the offending field. **Never** relax the schema to pass (AGENTS.md §12). |
| `check_fragment_registry.py` | registry maps out of sync | Align the registry maps — see `docs/internal/runbooks/adding-a-section.md`. |
| `pytest` / coverage | test failure or coverage drop | The suite is **green by contract** (`make check` must be green on every commit). So treat every failure as **new / a regression** — name it and trace it to the working-tree change. If genuinely unsure whether it pre-existed, compare against clean HEAD in a throwaway worktree (`git worktree add -d /tmp/wt HEAD`; **not** `git stash` — settings.json lock). Never lower the coverage floor or add an xfail to make it pass. |
| `check_release_meta.py` | version / tag / changelog mismatch | Reconcile the three: `pyproject.toml` `version`, the git tag (`v<version>`, PEP 440-equal), and a `##` `CHANGELOG.md` heading for that version. Show the concrete diff. |

## Output

Report concisely:
1. **Which stage failed** and the key evidence (1–3 lines from the log).
2. **Why** it failed.
3. **The producer-side fix** from the table — concrete, not generic.

Then **stop**. Do not apply changes, do not run `make fix`, do not edit files —
unless the user explicitly asks you to fix it. Core rule: fix the producer, not
the symptom (AGENTS.md §12). No downstream hand-patches, no schema relaxation,
no QA post-processing to make invalid output pass.
