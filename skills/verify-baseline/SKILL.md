---
name: verify-baseline
description: >-
  Read-only check of whether the secure-coding baseline is actually loaded into
  Claude Code's instructions — which id, from which scope, through which file.
  Walks the project CLAUDE.md, .claude/CLAUDE.md, CLAUDE.local.md, .claude/rules/
  and ~/.claude/CLAUDE.md plus their @ imports, and exits non-zero when the
  configured baseline is not in context, so CI can gate on it. Use on a request to
  verify, check or confirm the secure-coding baseline / secure coding rules, or to
  answer whether the baseline is installed, loaded or up to date. Writes nothing.
---

You are checking whether the secure-coding baseline is loaded into Claude Code's
instruction files. This skill is **read-only** — do not write files, do not
install anything, do not dispatch sub-agents, and do not review the repository's
code against the baseline.

An instruction file that never loads fails silently: the assistant behaves as if
the rules do not exist and nothing reports the gap. That is the question here.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:verify-baseline — Read-only: is the secure-coding baseline loaded?

USAGE
  /appsec-advisor:verify-baseline [--repo <path>] [--json]

FLAGS
  --repo <path>   Repository to check (default: current working dir)
  --json          Emit the result as machine-readable JSON

EXIT CODES
  0  The configured baseline is loaded — or this build configures none.
  1  It is not loaded. Suitable as a CI gate.

WHAT IS CHECKED
  Claude Code's instruction files — project CLAUDE.md, .claude/CLAUDE.md,
  CLAUDE.local.md, .claude/rules/*.md, ~/.claude/CLAUDE.md,
  ~/.claude/rules/*.md, and the organization's managed-policy CLAUDE.md —
  plus every file they pull in with an @ import.

  Files another tool reads and Claude Code does not — AGENTS.md,
  .github/copilot-instructions.md — are reported separately, as is a copy in
  the repository that nothing imports. Those are not loaded, but they are the
  difference between installing the baseline and wiring up what is there.

  This confirms the rules are in context. Whether they were followed is a
  different question and this command does not answer it.

Related: /appsec-advisor:install-baseline — installs it.
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags: `--repo <path>`  `--json`  `--help` | `-h`

Default `REPO_ROOT` to the current working directory.

### Reject unknown arguments (hard fail)

If the invocation contains any token that is not one of the flags above — or is
not the value consumed by `--repo` — DO NOT proceed. Print this to stderr,
substituting `<TOKEN>`, and exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:verify-baseline accepts only:
  --repo <path>   Repository to check (default: current working dir)
  --json          Emit the result as machine-readable JSON
  --help, -h      Show full help and exit

Run `/appsec-advisor:verify-baseline --help` for details.
```

## Step 2 — Run the check

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_check.py" --repo "$REPO_ROOT" $JSON_FLAG
```

The helper's output is the deliverable. Print it as-is and propagate the exit
status. Add no commentary in `--json` mode.

## Step 3 — One line of interpretation

In text mode only, and only when it tells the user something the output does not:

- **Not loaded** — the helper already names the install command. Add nothing.
- **Loaded, `user` scope only** — worth saying that it applies on this machine
  and that a colleague cloning this repository gets no baseline.
- **Loaded, `policy` scope** — deployed organization-wide through Claude Code's
  managed policy. It applies to every session on this machine and cannot be
  switched off locally, so there is nothing for the user to install or maintain.
- **A derived id** (anything after a `+`, e.g. `aisec-0.1+acme`) — the rules were
  adapted by whoever derived them and are not the published text.
- **`other`** — some baseline is loaded but not the configured one. Name both ids
  and stop; which one should win is the user's call, not yours.
- **Not loaded, but listed under "on disk"** — the rules are already in the
  repository for another tool, or in a copy nothing imports. Say that installing
  will import that file rather than add a second one.

Then stop. Do not offer to run a threat model, do not grade the repository
against the baseline's rules, and do not propose code changes.
