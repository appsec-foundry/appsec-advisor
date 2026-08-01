---
name: remove-baseline
description: >-
  Remove an installed secure-coding baseline from Claude Code's instruction files,
  so the rules stop loading at the next session start. Drops the import by default
  and leaves the file on disk; deleting the file is a separate step that is always
  confirmed first, because the plugin cannot tell a copy it wrote from one the
  repository already had. Use on a request to remove, uninstall, disable, unwire or
  get rid of the secure-coding baseline / secure coding rules / AI coding
  guardrails, or to undo /appsec-advisor:install-baseline.
---

You are removing a secure-coding baseline from Claude Code's instruction files.

Installing wired the baseline into a file Claude Code reads. Removing it undoes
that wiring, which is what `scripts/remove_baseline.py` does. Deleting the file
is a second, opt-in step — it is the part that can destroy something, so it is
never done without asking.

**Do not write or delete any file yourself.** No Write, no Edit, no `rm`. The
script is the only thing that touches `CLAUDE.md` or the baseline file, so the
removal stays line-exact and backed up.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:remove-baseline — Remove an installed secure-coding baseline.

USAGE
  /appsec-advisor:remove-baseline [--scope <scope>] [--repo <path>]
                                  [--dry-run] [--delete-file]

SCOPES  (omit --scope to pick from what is actually installed)
  user            Drops the import from ~/.claude/CLAUDE.md.
  project         Drops the import from <repo>/CLAUDE.md.
  project-rules   Deletes <repo>/.claude/rules/ — there is no import to drop
                  there, so this scope needs --delete-file.

FLAGS
  --repo <path>    Repository to remove from (default: current working dir)
  --dry-run        Report what would change, write nothing
  --delete-file    Also delete the baseline file, not just the import

WHAT IS REMOVED
  By default only the @import line and the note the installer wrote above it,
  so the rules stop loading and the file stays. Any instruction file that is
  edited is backed up to <file>.bak first, and only a line that is nothing but
  the import — or that note — is touched.

  The only file --delete-file can ever delete is the one this scope installs
  to, plus its .bak. An AGENTS.md or copilot-instructions.md that the install
  imported instead of copying is never deleted — it is your file.

A baseline deployed organization-wide through Claude Code's managed policy
cannot be removed locally, and this command will say so rather than try.

Related: /appsec-advisor:verify-baseline — check what is loaded, changes nothing.
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags:

  `--scope <user|project|project-rules>`  `--repo <path>`  `--dry-run`
  `--delete-file`  `--help` | `-h`

Default `REPO_ROOT` to the current working directory.

### Reject unknown arguments (hard fail)

If the invocation contains any token that is not one of the flags above — or is
not the value consumed by `--scope` / `--repo` — DO NOT proceed. Print this to
stderr, substituting `<TOKEN>`, and exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:remove-baseline accepts only:
  --scope <user|project|project-rules>   Which install to remove (default: ask)
  --repo <path>                          Repository (default: current dir)
  --dry-run                              Report changes, write nothing
  --delete-file                          Delete the file, not just the import
  --help, -h                             Show full help and exit

Run `/appsec-advisor:remove-baseline --help` for details.
```

An unknown value for `--scope` is rejected the same way.

## Step 2 — Find out what is actually installed

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_check.py" --repo "$REPO_ROOT" --json
```

Read `status` and `scopes` before offering anything — removing what is not
installed is the one way this command can only do harm.

- **`disabled`** — this build has no baseline configured. Print
  `No secure-coding baseline is configured for this build — nothing to remove.`
  and exit `0`.
- **`missing`** — nothing is loaded. Say so in one line and stop. If
  `present_unloaded` is non-empty, name those files and say they are on disk but
  already not loaded, so there is nothing to unwire. Do not offer to delete
  them; they may belong to another tool. Exit `0`.
- **`other`** — a different baseline is loaded, not the configured one. Name
  both ids and stop: this command removes the configured baseline, and deleting
  somebody else's rules is not what was asked. Exit `0`.
- **`installed`** — continue.

### `policy` in `scopes` — say it before anything else

The baseline was deployed organization-wide through Claude Code's managed
policy. It applies to every session on this machine and **cannot be removed
locally** — not by this command, not by editing a file in the repository.

If `policy` is the only scope, say that and exit `0`. If it appears next to
`user` or `project`, say it once up front: removing the local copy will not stop
the rules loading, and the user should know that before they decide.

## Step 3 — Choose the scope

If `--scope` was passed, use it — but if it is not in the reported `scopes`,
say so and stop rather than removing something that is not there.

Otherwise: if exactly one removable scope is installed, use it and name it. If
both `user` and `project` are installed, ask with `AskUserQuestion` — one
question, header `Scope`, one option per installed scope, described by who loses
the rules:

- **This machine** — `~/.claude/CLAUDE.md` stops importing it. Affects every
  repository you open, nothing for your team. → scope `user`
- **This repository** — the project `CLAUDE.md` stops importing it. Once you
  commit that, everyone who clones the repository loses the rules too.
  → scope `project`

For `project-rules`, the file is the wiring, so there is nothing to unwire —
that scope always goes through Step 5.

## Step 4 — Show the plan

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/remove_baseline.py" \
  --scope "$SCOPE" --repo "$REPO_ROOT" --dry-run
```

Print the script's output as-is. It names every file it would change, and every
line prefixed with `!` is a risk or something it refuses to touch — **relay
those, do not summarize them away**.

If the user passed `--dry-run`, stop here and exit with the script's status.

## Step 5 — Confirm before anything is deleted

Unwiring alone needs no confirmation: the import line is backed up and
re-running the install puts it back.

**Deleting the file does need one.** Before passing `--delete-file` — whether
the user asked for it or the scope is `project-rules`, which cannot work without
it — ask with `AskUserQuestion`, one question, header `Delete file`, and put the
**absolute path from the dry run** in the question text. Default to keeping:

- **Keep the file** — the rules stop loading either way. The file stays where it
  is, so nothing you may have edited into it is lost. → do not pass the flag
- **Delete it** — removes `<PATH>` and its `.bak`. → pass `--delete-file`

State these before the question, and any `!` line the dry run printed:

- The rules stop loading **either way**. Deleting is about the file on disk, not
  about the rules taking effect.
- **Local edits are lost.** The baseline is not backed up on delete, and the
  plugin cannot tell an edited copy from a current one.
- If the dry run reported that **git tracks the file**, lead with that: the file
  predates this install, so it is the repository's, not one the plugin wrote.

For `project-rules`, if the user chooses to keep the file, stop and say plainly
that the baseline still loads — `.claude/rules/` loads on its own, so keeping
the file means keeping the rules.

## Step 6 — Remove

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/remove_baseline.py" \
  --scope "$SCOPE" --repo "$REPO_ROOT" $DELETE_FLAG
```

Print the output as-is and propagate the exit status.

## Step 7 — Say what happens next

On success, close with what applies and nothing more:

1. **The rules stay in context for the rest of this session.** Claude Code reads
   instruction files at session start, so the removal takes effect at the next
   one.
2. **The edited file is backed up** to `<file>.bak`, named in the output.
   Re-running `/appsec-advisor:install-baseline` also restores the import.
3. **For `project` and `project-rules`, the change is uncommitted.** Name the
   paths so the user can review the diff. Do not commit them yourself.
4. **If the output says the baseline is still loaded**, name the scope it comes
   from — a second install or an org policy — so the user is not left thinking
   the removal failed.

Then stop. Do not offer to reinstall it, and do not comment on whether removing
it was a good idea.
