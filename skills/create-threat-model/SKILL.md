---
name: create-threat-model
description: Perform a threat assessment of a repository and produce a threat-model.md. Supports --repo to analyze external repos and --output to set the output directory. Optionally also writes threat-model.yaml with --yaml flag.
---

## Routing — read this file top to bottom, stop as soon as a case matches

**Case 1 — `--help` or `-h` in arguments:**
Output the following block verbatim, then stop. Do not call any tools. Do not read any other file. Do not dispatch agents.

```
/appsec-advisor:create-threat-model — STRIDE-based architectural threat modeling.

USAGE
  /appsec-advisor:create-threat-model [SCOPE] [FLAGS]

  SCOPE  Optional free-text to narrow the analysis, e.g. "focus on auth".
         Omit to analyze the entire repository.

EXAMPLES
  /appsec-advisor:create-threat-model
  /appsec-advisor:create-threat-model --assessment-depth thorough
  /appsec-advisor:create-threat-model "focus on payment service" --sarif
  /appsec-advisor:create-threat-model --repo ../other-repo --output /tmp/out

OUTPUT
  --yaml / --no-yaml           Write threat-model.yaml (default: on)
  --sarif                      Also write threat-model.sarif.json
  --pentest-tasks              Also write pentest-tasks.yaml
  --pentest-format <fmt>       Format for pentest-tasks: generic (default) | strix
  --pentest-target <url>       Base URL injected into pentest-tasks meta.target
  --verbose                    Append a Run Statistics section to the report
  --scan-manifest              Write a list of every file scanned to .scan-manifest.txt

DEPTH & MODEL
  --assessment-depth <level>   quick | standard (default) | thorough
                               quick ~15 min, standard ~25 min, thorough ~40 min
  --reasoning-model <mode>     Model tier for STRIDE analysis:
                               sonnet | opus-cheap (default) | opus
  --stride-model <model>       Override the STRIDE analyzer model directly
  --architect-review           Run an advisory architect review (Stage 3)
                               Auto-enabled at depth=thorough
  --no-architect-review        Disable Stage 3 even at depth=thorough
  --architect-model <m>        Model for Stage 3: sonnet | opus (default: opus)

SCAN OPTIONS
  --requirements [<url>]       Check tagged security requirements (e.g. [SEC-1])
  --no-requirements            Skip requirements check even if configured
  --with-sca                   Run a dependency CVE scan
  --repo <path>                Repository to analyze (default: current directory)
  --output <path>              Output directory (default: <repo>/docs/security)

INCREMENTAL / CI
  --incremental                Re-analyze only components changed since last run
  --full                       Re-analyze everything; preserve changelog history
  --rebuild                    Wipe all prior output and start completely fresh
  --resume                     Continue from the last saved checkpoint
  --base <ref>                 Git ref to diff against (default: prior scan commit)
  --pr-mode                    Focused delta report for an MR/PR (implies --incremental)
  --no-qa                      Skip the Stage-2 QA reviewer (faster, for CI)
  --dry-run                    Run the full pipeline but write nothing to the repo

CLEANUP
  --clean-cache                Delete intermediate/cache files, keep threat model
  --clean-all                  Delete everything in the output directory
  --force                      Skip confirmation prompt for --clean-all

ADVANCED
  --keep-runtime-files         Preserve transient files after a successful run
  --tracing                    Record per-agent token/cost/timing to .appsec-trace.log
  --qa-scan-repo               Deep-scan repo for unlinked file references in QA (slow)

See /appsec-advisor:status for plugin version and last-run info.
Full flag reference: docs/threat-model-skill.md
```

**Case 2 — any other arguments (or no arguments):**
Read `<base-dir>/SKILL-impl.md` in full (base-dir is on the `Base directory for this skill:` line in the invocation header), then follow all instructions in that file to run the assessment.
