---
name: install-baseline
description: >-
  Install the secure-coding baseline into Claude Code's instruction files, so the
  coding rules are in context on every prompt instead of only the ones that mention
  security. Menu-driven: this machine (~/.claude/CLAUDE.md), this repository
  (project CLAUDE.md), or this repository without touching CLAUDE.md
  (.claude/rules/). Uses modular loading for new official aiscb installations, with explicit complete compatibility mode. Fetches the published baseline, installs a signed release only
  once its signature verifies, and falls back to the copy bundled in the plugin
  when the source cannot be used. Use when the session banner
  reports the baseline is not installed, or on a request to install, add, set up,
  refresh or update the secure-coding baseline / secure coding rules / AI coding
  guardrails.
---

You are installing a secure-coding baseline into Claude Code's instruction files.

The default official aiscb installation loads the core and catalog first and verifies selected module bodies through a local Python loader. `--complete` installs all rules as one compatibility file. Custom organization baselines remain complete. `scripts/install_baseline.py` owns installation and verification; your job is to explain its result.

Modular project installations use repository-relative loader paths. Commit the baseline carrier, its import, and `.appsec-baseline/releases/`; run the loader from the repository root. The `project-rules` scope stores snapshots outside `.claude/rules/` so unselected modules are not automatically loaded. User installations keep snapshots under `~/.claude/.appsec-baseline/`. The loader needs permitted Python execution; if unavailable, choose complete mode explicitly.

Existing complete installations stay complete during updates. Switching modes requires `--migrate`; modified or unrecorded complete text is refused. Other active baseline integrations must be migrated or removed first. Upstream aiscb installations remain owned by their installer. Close affected sessions before migration or activation and restart afterward.

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
                                   [--modular | --complete] [--migrate]

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
  --modular       Core and verified modules on demand (official default)
  --complete      All rules in one compatibility file
  --migrate       Explicitly switch a verified existing installation mode

ALREADY HAVE IT?
  Nothing is installed twice. A baseline deployed organization-wide through
  Claude Code's managed policy already covers every session on the machine.
  One that a repository carries for another tool — AGENTS.md,
  .github/copilot-instructions.md — or a copy committed but never imported is
  wired up rather than duplicated, so there stays one file to keep current.

The baseline is fetched from the source configured in the plugin; a signed
release is installed only once its signature and checksum verify. The bundled
copy is the fallback when that source cannot be used. Existing instruction
files are only appended to, never rewritten, and re-running is safe.

Related: /appsec-advisor:verify-baseline — check what is loaded, changes nothing.
         /appsec-advisor:update-baseline — refresh a copy that is already
         installed, wherever it is loaded from.
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags:

  `--scope <user|project|project-rules>`  `--repo <path>`  `--dry-run`
  `--refresh`  `--offline`  `--no-reuse`  `--modular` | `--complete`  `--migrate`  `--help` | `-h`

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
  --modular | --complete                 Select the installation mode
  --migrate                              Explicitly switch an existing mode
  --help, -h                             Show full help and exit

Run `/appsec-advisor:install-baseline --help` for details.
```

An unknown value for `--scope` is rejected the same way. Reject simultaneous `--modular` and `--complete`. Set `MODE_FLAG` to the selected mode flag or empty, `MIGRATE_FLAG` to `--migrate` only when supplied, and `REUSE_FLAG` to `--no-reuse` only when supplied. Forward these flags unchanged to both preview and installation.

## Step 2 — Report what is loaded now

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_check.py" --repo "$REPO_ROOT" --json
```

Nothing is installed twice, so read the result before offering anything.

Read `status` from the JSON. A requested `--migrate` proceeds to the script preview for a plugin-owned installation; never rewrite a foreign or upstream-owned integration yourself:

- **`invalid`** — a modular adapter or its pinned artifacts failed verification. Report the diagnostics and stop; do not replace or bypass the damaged installation.
- **`disabled`** — this build has no baseline configured. Print
  `No secure-coding baseline is configured for this build — nothing to install.`
  and exit `0`. Do not offer to install one.
- **`installed`** — say so in one line, naming the id and the scopes in
  `scopes`. Then stop, unless the user passed `--refresh`, `--scope`, or `--migrate`: there is
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

  When records in `matches`, `newer`, or `older` carry `managed_by: aiscb`, the AI Secure Coding Baseline's own installer set the baseline up and updates it, and this plugin writes none of its files: name that installer's update command instead of offering `--refresh` or plugin migration; modern user installs use `python3 ~/.aiscb/install.py --update`.

- **`outdated`** — the configured baseline is loaded, at an older version. This
  is not an install: the scope is already chosen and only the text is behind.
  Name both ids, point at `/appsec-advisor:update-baseline`, and exit `0` unless
  the user explicitly asked for another scope.
- **`newer`** — a later version of the configured baseline is loaded, usually a signed release newer than the id this build names. Treat it like `installed`: say so in one line, naming the loaded id and that it is ahead of the configured one, and stop unless the user passed `--refresh`, `--scope`, or `--migrate`.
- **`switched_off`** — the configured baseline comes from the AI Secure Coding Baseline's own installer (aiscb) and is switched off for this session with `AISCB_DISABLE=1`. Say so and exit `0`: a session started without the variable loads it again, and a copy installed here would load even while it is switched off.
- **`other`** — a baseline is loaded, but not the configured one. Name both ids
  before the menu: the user is about to add a second set of rules, and needs to
  know that.
- **`missing`** — continue, but first check `present_unloaded`.

### `present_unloaded` — already on disk, just not wired up

Each entry is a file that carries the baseline where Claude Code does not read
it: `AGENTS.md` for Codex and Cursor, `.github/copilot-instructions.md` for
Copilot, or a copy committed to the repository that nothing imports.

When the list is non-empty, name the file before the menu. Complete mode can reuse a complete carrier. Modular mode requires its own verified adapter and must not import a core or another client’s adapter as if it were complete.

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
  --scope "$SCOPE" --repo "$REPO_ROOT" --dry-run $REFRESH_FLAG $OFFLINE_FLAG $MODE_FLAG $MIGRATE_FLAG $REUSE_FLAG
```

Print the script's output as-is. It names the source it will install from and
every file it will create or append to.

If the user passed `--dry-run`, stop here and exit with the script's status.

## Step 5 — Install

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/install_baseline.py" \
  --scope "$SCOPE" --repo "$REPO_ROOT" $REFRESH_FLAG $OFFLINE_FLAG $MODE_FLAG $MIGRATE_FLAG $REUSE_FLAG
```

Print the output as-is and propagate the exit status.

If the output reports that the bundled copy was used because the configured source could not be used, say plainly that the installed text may be older than the published baseline and that `--refresh` updates it once the source can be read again. When the reason is a failed signature or manifest check, say that the published release was refused, not merely unreachable. A modular fallback must be a verified modular bundle, never the complete file alone. Successful installation applies to new sessions; do not claim the module bodies are already in context.

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
