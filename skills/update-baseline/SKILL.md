---
name: update-baseline
description: >-
  Refresh an already-installed secure-coding baseline from the source that
  publishes it, in place, wherever it is loaded from — this machine, the
  repository, or a file the repository already carried. Reports when the
  published baseline has moved to a new id, which arrives with a plugin release
  rather than with this command, and never overwrites a foreign baseline, a
  newer one, or a file that holds more than the rules. Use on a request to
  update, refresh or re-fetch the secure-coding baseline / secure coding rules,
  or to ask whether the installed copy is still current. Installs nothing —
  /appsec-advisor:install-baseline is what puts a baseline on a machine that has
  none.
---

You are refreshing an installed secure-coding baseline. The install already
decided where the rules live and what imports them; the only open question here
is whether the text on disk still matches the source that publishes it.

**Do not write any file yourself.** No Write, no Edit. `scripts/update_baseline.py`
owns every write, so the update stays confined to the file the rules are
actually loaded from.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:update-baseline — Refresh the installed secure-coding baseline.

USAGE
  /appsec-advisor:update-baseline [--repo <path>] [--dry-run] [--offline]

FLAGS
  --repo <path>   Repository to update in (default: current working dir)
  --dry-run       Report what would change, write nothing
  --offline       Update from the copy bundled in the plugin instead of
                  fetching the published one

WHAT IT UPDATES
  The file the baseline is loaded from — in ~/.claude/, in the repository, or
  in .claude/rules/ — rewritten from the configured source, with the previous
  text kept beside it as a .bak. Imports are left as they are: this changes
  the rules, not the wiring.

WHAT IT LEAVES ALONE
  A baseline nobody here configured, and one that is already ahead of this
  build: replacing either would be a downgrade, and which rules win is your
  call. A file that carries the rules among its own content — AGENTS.md, a
  team instruction file — is reported rather than rewritten, because the rest
  of that file would be lost. An unreachable source changes nothing at all.

EXIT CODES
  0  The state was reported, and anything this command owns is current.
  2  The update did not happen: the source could not be read, what it served
     was no baseline at all, or a file could not be written.
  3  The source now publishes a different baseline id than this build is
     configured for. Nothing was written — a new version arrives with the
     plugin release that vendors it.

Related: /appsec-advisor:verify-baseline — what is loaded, changes nothing.
         /appsec-advisor:install-baseline — put one on a machine that has none.
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags: `--repo <path>`  `--dry-run`  `--offline`  `--help` | `-h`

Default `REPO_ROOT` to the current working directory.

### Reject unknown arguments (hard fail)

If the invocation contains any token that is not one of the flags above — or is
not the value consumed by `--repo` — DO NOT proceed. Print this to stderr,
substituting `<TOKEN>`, and exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:update-baseline accepts only:
  --repo <path>   Repository to update in (default: current working dir)
  --dry-run       Report what would change, write nothing
  --offline       Update from the copy bundled in the plugin
  --help, -h      Show full help and exit

Run `/appsec-advisor:update-baseline --help` for details.
```

Note that `--scope` is not one of them. An update goes to the file the rules are
loaded from, which the check already knows; adding a scope is what
`/appsec-advisor:install-baseline` does.

## Step 2 — Run the update

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/update_baseline.py" \
  --repo "$REPO_ROOT" $DRY_RUN_FLAG $OFFLINE_FLAG
```

Print the output as-is and propagate the exit status. The script reports every
state it found, including the ones where it wrote nothing.

## Step 3 — One line of interpretation

Only where it tells the user something the output does not:

- **A file was updated** — the new text takes effect at the next session start,
  not in this one. Claude Code reads instruction files when a session begins.
- **A file in the repository was updated** — it is uncommitted. Name the path so
  the user can review the diff and commit it. Do not commit it yourself.
- **Exit `3`, a new published id** — the id is what the session banner and
  `verify-baseline` look for, so it moves when the plugin does. Say that
  updating the plugin is what brings the new version, and stop. Do not fetch it
  by hand, do not edit `config.json`, and do not write the newer text anywhere.
- **Nothing is installed** — `/appsec-advisor:install-baseline` is the command,
  and it asks which scope. Do not run it for them.
- **A foreign or newer baseline is loaded** — the output already names the ids.
  Which one should win is the user's call, not yours.

Then stop. Do not summarize the baseline's contents, do not review the
repository against it, and do not offer to fix anything it covers.
