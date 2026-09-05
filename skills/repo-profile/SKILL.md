---
name: repo-profile
description: >-
  Deterministic profile of a repository before it is scanned: working-tree size,
  language split by bytes, build manifests and how many roots they sit in,
  tracked versus untracked content. Runs the filesystem walk alone — no agents,
  no LLM, no network, nothing written into the target repository, and no
  security judgement of any kind. Use it to decide whether a repository is worth
  a full run, at which assessment depth, and whether it is one service or a
  monorepo; use /appsec-advisor:security-score for a scanner-based number and
  /appsec-advisor:create-threat-model for the assessment itself.
---

You are printing a repository profile. This skill is **read-only** — do not analyze the repository yourself, do not write files, do not dispatch sub-agents. Run the script and present its output.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:repo-profile — What is in this repository, before any scan.

USAGE
  /appsec-advisor:repo-profile [--repo <path>] [--json]

FLAGS
  --repo <path>   Repository to profile (default: current working dir)
  --json          Emit the profile as machine-readable JSON

WHAT IT REPORTS
  Size of the working tree, and how much of it is installed dependencies
  or build output rather than the repository's own code.

  The language split by bytes over that own code, so the dominant stack
  is visible without opening a file.

  Build manifests and their directories: one root is a service, several
  are a monorepo, and a scan covers each of them.

  Tracked against untracked content, because a scan reads the working
  tree while a fresh clone would carry only what git has.

WHAT IT IS NOT
  Not a security check. No findings, no severity, no risk. The numbers
  say what a run would have to read, not what is wrong with it.

  Nothing is read from file contents — sizes come from the directory
  entries alone, so the profile is fast and repeats exactly.

EXIT CODES
  0  profile printed
  1  error
```

## Run

Resolve the plugin root first, then run the script from it, passing the user's `--repo` and `--json` through unchanged:

```bash
PLUGIN_ROOT="$CLAUDE_PLUGIN_ROOT"
if [ -z "$PLUGIN_ROOT" ]; then
  # The skill's base directory is given to you at invocation; the plugin root is
  # two levels above it. Never search the filesystem for it — a machine can hold
  # several checkouts, and a search picks an arbitrary one.
  PLUGIN_ROOT=$(cd "<base-dir>/../.." && pwd)
fi
python3 "$PLUGIN_ROOT/scripts/repo_profile.py" [--repo <path>] [--json]
```

Use exactly `Profiling the repository` as the tool call's description.

Do not announce the run in prose beside it. The description line already says what is happening; "Let me profile the repository first" and its kin are forbidden even though they are true. Just run it.

The script walks the tree and reads no file content, so it finishes in well under a second on an ordinary repository and touches nothing.

## Present the result

Reprint the script's stdout **verbatim**, in a fenced code block, every line of it, and stop. The user does not see the tool output; what you print is the whole profile they get. It is already finished: the basis line, the three size rows, the language split, the manifests, and the notes that say what the numbers mean.

Nothing may be added after the block: no summary of the size, no verdict on the stack, no estimate of what a scan would cost, no recommendation of an assessment depth. None of that is in the data.

Two exceptions, both only when the user asks: point at `/appsec-advisor:create-threat-model` when they want the actual assessment, and at `/appsec-advisor:security-score` when they want a number about the repository's security rather than its shape.
