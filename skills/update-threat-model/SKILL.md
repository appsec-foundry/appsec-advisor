---
name: update-threat-model
description: >-
  Convenience alias for create-threat-model in incremental mode — re-analyzes
  only the components that changed since the last run. Unlike the bare
  create-threat-model, it does NOT bootstrap — it aborts with a clear message
  when no threat model exists yet, so an "update" can never silently turn into a
  first full assessment. An explicit mode flag the user passes (--full,
  --rebuild, --rerender, --resume) is honored instead of the injected
  --incremental. Everything else (flags, --repo, --output, behavior, output) is
  identical to create-threat-model.
---

## What this skill is

A thin alias. It injects `--incremental` and then hands off to
`create-threat-model` unchanged — there is **no** separate pipeline, config, or
logic here. `create-threat-model` is the single source of truth; this file only
decides the effective argument list and delegates.

Two behavioral facts follow for free from `--incremental`
(`scripts/resolve_config.py`, Rules 2/3):

- **Aborts when no model exists.** `--incremental` on an empty output dir
  (no `threat-model.yaml` and no `threat-model.md`) exits non-zero with a
  message telling the user to run `create-threat-model` first. That is exactly
  the "update never bootstraps" guarantee — do not re-implement it here.
- **Aborts on a legacy-only baseline** (a `threat-model.md` without the
  structured `threat-model.yaml`), pointing the user to one non-incremental run
  to bootstrap the yaml.

## Routing — read top to bottom, stop at the first matching case

**Case 1 — `--help` or `-h` in arguments:**
Run the following Bash command, output its stdout verbatim, then stop. Do not
read any other file. Do not dispatch agents.

```bash
cat "$CLAUDE_PLUGIN_ROOT/skills/update-threat-model/HELP.txt"
```

If `$CLAUDE_PLUGIN_ROOT` is unset, resolve it first the same way
`create-threat-model` does (search for `*/appsec-advisor/skills/update-threat-model/SKILL.md`).

**Case 2 — any other arguments (or no arguments):**

Compute the **effective argument list** by prepending `--incremental`, unless
the user already passed an explicit mode flag (in which case theirs wins and
nothing is injected):

```bash
_args=(<invocation-arguments>)
inject=1
for a in "${_args[@]}"; do
  case "$a" in
    --full|--rebuild|--rerender|--resume|--incremental) inject=0 ;;
  esac
done
if [ "$inject" = 1 ]; then
  EFFECTIVE_ARGS=(--incremental "${_args[@]}")
else
  EFFECTIVE_ARGS=("${_args[@]}")
fi
```

Then read `create-threat-model/SKILL.md` (the sibling skill) **in full from
Case 2 onward and follow it exactly**, substituting `EFFECTIVE_ARGS` everywhere
it refers to `<invocation-arguments>`. Honor its contract verbatim — the single
`🔧 Building …` status line, the session-model advisory, silent read, the
router hand-off, and the Pre-flight summary. Do not narrate this delegation and
do not add any output of your own on top of what `create-threat-model` emits.
