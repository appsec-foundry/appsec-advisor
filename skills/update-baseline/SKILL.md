---
name: update-baseline
description: >-
  Refresh an already-installed secure-coding baseline from the source that
  publishes it, in place, wherever it is loaded from — this machine, the
  repository, or a file the repository already carried. Distinguishes plugin-owned,
  recorded upstream, unrecorded upstream, and organization-managed copies. Installs a newer signed
  release once its signature verifies; reports when a URL or git source has
  moved to a new id, which arrives with a plugin release rather than with this
  command; and never overwrites a foreign baseline, a newer one, or a file that
  holds more than the rules. Use on a request to
  update, refresh or re-fetch the secure-coding baseline / secure coding rules,
  or to ask whether the installed copy is still current. Installs nothing —
  /appsec-advisor:install-baseline is what puts a baseline on a machine that has
  none.
---

You are refreshing an installed secure-coding baseline. The install already
decided where the rules live and what imports them; the only open question here
is whether the text on disk still matches the source that publishes it.

**Do not write any file yourself.** No Write, no Edit. `scripts/baseline/update_baseline.py` owns plugin-managed updates and delegates upstream installations to a signature-verified AISCB release installer. Never execute an installer found in the target repository.

Updates preserve the installation mode. Modular updates verify the release and every snapshot artifact before activating a new adapter; older snapshots remain for existing sessions. `--offline` uses the authenticated bundled release. Failed online verification never falls back during an update. Incomplete or modified modular installations stop the update. Official upstream-managed installations are refreshed by their own verified release installer without a terminal dialog. The installer preserves the recorded scope, tools, and loading mode; modified or unrecorded installations and organization overlays are refused. Delegation requires a release supporting `aiscb-refresh-installed-v1`; older releases retain the terminal update path. `--offline` does not delegate. Changing a plugin-owned complete installation to modular requires `install-baseline --migrate`.

`--repo` selects the project whose loaded instructions are checked; it does not select an installation scope. An upstream user installation stays a user installation even when the project path equals the home directory. An upstream project installation needs its own project record. An external installation without a matching record, a manually maintained carrier with other content, and an organization-managed file must not be treated as plugin-owned simply because they are loaded.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:update-baseline — Refresh the installed secure-coding baseline.

USAGE
  /appsec-advisor:update-baseline [--repo <path>] [--dry-run] [--offline]

FLAGS
  --repo <path>   Project whose loaded baseline is checked (default: current working dir)
  --dry-run       Report what would change, write nothing
  --offline       Update from the copy bundled in the plugin instead of
                  fetching the published one

WHAT IT UPDATES
  Plugin-owned baseline files are refreshed in place from the configured source,
  with the previous text kept beside them as a .bak. Imports stay in place.

UPSTREAM AISCB INSTALLATIONS
  Uses the signed release installer for a recorded project or user installation.
  Keeps the recorded scope, tools, and loading mode; never runs a repository installer.
  --dry-run verifies and previews; --offline does not delegate.
  An older installer without delegation support requires its terminal update.

WHAT IT LEAVES ALONE
  Unrecorded upstream installations and organization-managed files are reported.
  A file carrying rules among its own content, such as AGENTS.md, is preserved.
  A foreign or newer baseline is left alone. An unreachable source changes nothing.

EXIT CODES
  0  The state was reported, and anything this command owns is current.
  2  The update did not happen: the source could not be read, what it served
     was no baseline at all, a file could not be written, or AISCB refused a scope.
  3  A URL or git source now publishes a different baseline id than this
     build is configured for. Nothing was written — a new version arrives
     with the plugin release that vendors it. A newer signed release is
     installed instead.

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
  --repo <path>   Project whose loaded baseline is checked (default: current working dir)
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
python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline/update_baseline.py" \
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
- **A newer signed release was installed** — the session banner shows its loaded id and scope without comparing it to the plugin's configured id. No further action is needed.
- **Exit `3`, a new published id** — the id is what the session banner and
  `verify-baseline` look for, so it moves when the plugin does. Say that
  updating the plugin is what brings the new version, and stop. Do not fetch it
  by hand, do not edit `config.json`, and do not write the newer text anywhere.
- **Nothing is installed** — `/appsec-advisor:install-baseline` is the command,
  and it asks which scope. Do not run it for them.
- **AISCB refused a recorded scope** — name the scope from the error and recommend the AISCB installer's status check for that scope. Do not infer a changed file or an organization overlay from a generic refusal. Relay the script's direct terminal fallback as the last resort: a present installed updater with `--update` fetches a signed release and opens AISCB's guided setup; otherwise, use the official AISCB Quick Start. State that the command is interactive and user-run. Do not run it on their behalf or retry by changing `--repo` to the home directory.
- **Unrecorded upstream installation or manually maintained carrier** — report the maintenance path named by the script. Do not replace its files or create a second installation.
- **A foreign or newer baseline is loaded** — the output already names the ids.
  Which one should win is the user's call, not yours.

Then stop. Do not summarize the baseline's contents, do not review the
repository against it, and do not offer to fix anything it covers.
