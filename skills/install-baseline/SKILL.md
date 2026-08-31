---
name: install-baseline
description: >-
  Install the secure-coding baseline into Claude Code's instruction files, so the
  coding rules are in context on every prompt instead of only the ones that mention
  security. Menu-driven: this machine (~/.claude/CLAUDE.md), this repository
  (project CLAUDE.md), or this repository without touching CLAUDE.md
  (.claude/rules/). Fetches the published baseline and falls back to the copy
  bundled in the plugin when the URL cannot be reached. Use when the session banner
  reports the baseline is not installed, or on a request to install, add, set up,
  refresh or update the secure-coding baseline / secure coding rules / AI coding
  guardrails.
---

You are installing a secure-coding baseline into Claude Code's instruction files.

A secure-coding baseline is an instruction file the assistant loads **before** it
writes code, so the rules apply on every prompt — not only the ones that mention
security. Installing it means putting it where Claude Code already looks and
importing it, which is what `scripts/install_baseline.py` does. Your job is the
menu and the explanation; the script owns every write.

**Do not write any file yourself.** No Write, no Edit. The script is the only
thing that touches `CLAUDE.md` or the baseline file, so the install stays
idempotent and append-only.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:install-baseline — Install the secure-coding baseline.

USAGE
  /appsec-advisor:install-baseline [--scope <scope>] [--repo <path>]
                                   [--dry-run] [--refresh] [--offline]

SCOPES  (omit --scope to pick from a menu)
  user            ~/.claude/CLAUDE.md imports it — applies to every repository
                  on this machine, and is not visible to your team.
  project         <repo>/CLAUDE.md imports it — committed, so everyone who
                  clones the repository gets the same rules.
  project-rules   <repo>/.claude/rules/ — loads automatically, leaves an
                  existing CLAUDE.md untouched.

FLAGS
  --repo <path>   Repository to install into (default: current working dir)
  --dry-run       Report what would change, write nothing
  --refresh       Re-fetch and overwrite an already-installed copy
  --offline       Skip the fetch, install the copy bundled in the plugin
  --no-reuse      Write a fresh copy instead of importing one the repo has

ALREADY HAVE IT?
  Nothing is installed twice. A baseline deployed organization-wide through
  Claude Code's managed policy already covers every session on the machine.
  One that a repository carries for another tool — AGENTS.md,
  .github/copilot-instructions.md — or a copy committed but never imported is
  wired up rather than duplicated, so there stays one file to keep current.

The baseline is fetched from the URL configured in the plugin; the bundled copy
is the fallback when that URL cannot be reached. Existing instruction files are
only appended to, never rewritten, and re-running is safe.

Related: /appsec-advisor:verify-baseline — check what is loaded, changes nothing.
         /appsec-advisor:update-baseline — refresh a copy that is already
         installed, wherever it is loaded from.
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags:

  `--scope <user|project|project-rules>`  `--repo <path>`  `--dry-run`
  `--refresh`  `--offline`  `--no-reuse`  `--help` | `-h`

Default `REPO_ROOT` to the current working directory.

### Reject unknown arguments (hard fail)

If the invocation contains any token that is not one of the flags above — or is
not the value consumed by `--scope` / `--repo` — DO NOT proceed. Print this to
stderr, substituting `<TOKEN>`, and exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:install-baseline accepts only:
  --scope <user|project|project-rules>   Where to install (default: ask)
  --repo <path>                          Repository (default: current dir)
  --dry-run                              Report changes, write nothing
  --refresh                              Re-fetch an installed copy
  --offline                              Use the plugin's bundled copy
  --no-reuse                             Write a copy instead of importing one
  --help, -h                             Show full help and exit

Run `/appsec-advisor:install-baseline --help` for details.
```

An unknown value for `--scope` is rejected the same way.

## Step 2 — Report what is loaded now

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_check.py" --repo "$REPO_ROOT" --json
```

Nothing is installed twice, so read the result before offering anything.

Read `status` from the JSON:

- **`disabled`** — this build has no baseline configured. Print
  `No secure-coding baseline is configured for this build — nothing to install.`
  and exit `0`. Do not offer to install one.
- **`installed`** — say so in one line, naming the id and the scopes in
  `scopes`. Then stop, unless the user passed `--refresh` or `--scope`: there is
  nothing to fix, and a second copy in another scope is a choice, not a default.
  Offer both as a next step in one sentence (`--refresh` to update the text,
  `--scope` to add another scope) and exit `0`.

  Two scopes need a word of their own:

  - **`policy`** — the baseline was deployed organization-wide through Claude
    Code's managed policy. It already applies to every session on this machine
    and cannot be switched off locally. Say that and stop. Do not offer to
    install a second copy; only continue if the user explicitly asks for one
    after being told, and say plainly that it adds a second file to maintain.
  - **`user`** — it applies on this machine only. Worth one sentence that a
    colleague cloning this repository gets no baseline, in case `project` was
    what they meant.

- **`other`** — a baseline is loaded, but not the configured one. Name both ids
  before the menu: the user is about to add a second set of rules, and needs to
  know that.
- **`missing`** — continue, but first check `present_unloaded`.

### `present_unloaded` — already on disk, just not wired up

Each entry is a file that carries the baseline where Claude Code does not read
it: `AGENTS.md` for Codex and Cursor, `.github/copilot-instructions.md` for
Copilot, or a copy committed to the repository that nothing imports.

When the list is non-empty, say so before the menu and name the file. The
install will **import that file** rather than write a second copy, so there
stays one file to keep current — which is the whole point, since two files with
the same rules diverge the day one of them is edited. Nothing is fetched in that
case either.

This applies to the `project` scope, the one that wires an import. `user` cannot
use it — an import of a repository path from `~/.claude/CLAUDE.md` resolves to
nothing in every other repository — and `project-rules` wires no import at all.
`--no-reuse` forces a fresh copy.

## Step 3 — Choose the scope

If `--scope` was passed, skip this step and use it.

Otherwise ask with `AskUserQuestion` — one question, header `Scope`, these three
options. Keep the descriptions to the trade-off; the user is choosing who gets
the rules, not a file path.

- **This machine** — `~/.claude/CLAUDE.md` imports it. Applies to every
  repository you open. Nothing is committed, so your team is unaffected.
  → scope `user`
- **This repository** — the project `CLAUDE.md` imports it and the baseline file
  is committed with it, so everyone who clones the repository gets the same
  rules. → scope `project`
- **This repository, leaving CLAUDE.md alone** — the baseline goes to
  `.claude/rules/`, which Claude Code loads on its own. Same reach as the
  previous option; use it when `CLAUDE.md` is maintained elsewhere or does not
  exist. → scope `project-rules`

## Step 4 — Show the plan

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/install_baseline.py" \
  --scope "$SCOPE" --repo "$REPO_ROOT" --dry-run $OFFLINE_FLAG
```

Print the script's output as-is. It names the source it will install from and
every file it will create or append to.

If the user passed `--dry-run`, stop here and exit with the script's status.

## Step 5 — Install

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/install_baseline.py" \
  --scope "$SCOPE" --repo "$REPO_ROOT" $REFRESH_FLAG $OFFLINE_FLAG
```

Print the output as-is and propagate the exit status.

If the output reports that the bundled copy was used because the URL could not
be reached, say plainly that the installed text may be older than the published
baseline and that `--refresh` updates it once the network is back. Do not
present that as a failure — the rules are installed and in context either way.

## Step 6 — Say what happens next

On success, close with these two facts and nothing more:

1. **The rules load at the next session start**, not in this one. Claude Code
   reads instruction files when a session begins.
2. **For the `project` scope, the changed files are uncommitted.** Name the
   paths the script reported so the user can review the diff and commit. Do not
   commit them yourself. When an existing file was reused, the only change is
   the import in `CLAUDE.md` and the note above it.

Then stop. Do not summarize the baseline's contents, do not review the
repository against it, and do not offer to fix anything it covers — this skill
installs a file, and `/appsec-advisor:verify-baseline` is what re-checks it.
