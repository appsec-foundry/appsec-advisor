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
  /appsec-advisor:create-threat-model --thorough
  /appsec-advisor:create-threat-model "focus on payment service" --sarif
  /appsec-advisor:create-threat-model --repo ../other-repo --output /tmp/out

OUTPUT
  --yaml / --no-yaml           Write threat-model.yaml (default: on)
  --sarif                      Also write threat-model.sarif.json
  --pentest-tasks              Also write pentest-tasks.yaml
  --pentest-format <fmt>       Format for pentest-tasks: generic (default) | strix
  --pentest-target <url>       Base URL injected into pentest-tasks meta.target
  --pdf                        Also export threat-model.pdf
                               (requires pandoc + weasyprint; mmdc optional)
                               See /appsec-advisor:export-pdf for the standalone form
  --verbose                    Append a Run Statistics section to the report
  --scan-manifest              Write a list of every file scanned to .scan-manifest.txt

DEPTH & MODEL
  --assessment-depth <level>   quick | standard (default) | thorough
  --quick                      Shortcut for --assessment-depth quick
  --thorough                   Shortcut for --assessment-depth thorough
  --reasoning-model <mode>     Model tier for STRIDE analysis:
                               sonnet | opus-cheap | opus | haiku-economy
                               Defaults: haiku-economy at quick,
                                         opus-cheap at standard/thorough
  --stride-model <model>       Override the STRIDE analyzer model directly
  --architect-review           Run an advisory architect review (Stage 4)
                               Auto-enabled at depth=thorough
  --no-architect-review        Disable Stage 4 even at depth=thorough
  --architect-model <m>        Model for Stage 4: sonnet | opus (default: opus)
  --no-enrich-arch             Disable LLM enrichment of architecture fragments
                               (on by default at standard/thorough)
  --enrich-arch                Force architecture enrichment even at quick depth

TARGET & SCAN
  --repo <path>                Repository to analyze (default: current directory)
  --output <path>              Output directory (default: <repo>/docs/security)
  --requirements [<url>]       Check tagged security requirements (e.g. [SEC-1])
  --no-requirements            Skip requirements check even if configured
                               Deprecated aliases: --with-requirements,
                               --ignore-requirements, --requirements-url <url>
  --with-sca                   Run a dependency CVE scan

INCREMENTAL / CI
  --incremental                Re-analyze only components changed since last run
  --full                       Re-analyze everything; preserve changelog history
  --rebuild                    Wipe all prior output and start completely fresh
  --resume                     Continue from the last saved checkpoint
  --base <ref>                 Git ref to diff against (default: prior scan commit)
  --pr-mode                    Focused delta report for an MR/PR (implies --incremental)
  --no-qa                      Skip the Stage 3 QA reviewer (faster, for CI)
  --dry-run                    Run the full pipeline but write nothing to the repo
  --no-confirm / --yes         Skip interactive confirmation prompts

CLEANUP
  --clean-cache                Delete intermediate/cache files, keep threat model
  --clean-all                  Delete everything in the output directory
  --force                      Skip confirmation prompt for --clean-all

ADVANCED
  --keep-runtime-files         Preserve transient files after a successful run
  --no-tracing                 Disable per-agent token/cost/timing trace
                               (default: tracing ON, writes .appsec-trace.log)
  --no-walkthroughs            Skip per-finding attack walkthroughs in §3;
                               chain overview is still rendered
  --max-resumes <N>            Cap on Stage 1 auto-resume dispatches (default: 1;
                               0 disables resume)
  --max-wall-time <DURATION>   Hard wall-time deadline; watchdog aborts the run
                               when reached (e.g. 3600, 60m, 1h; default: none)
  --max-cost <USD>             Hard cost cap in USD; watchdog aborts when
                               cumulative cost exceeds this (e.g. 15.0; default: none)
  --qa-scan-repo               Deep-scan repo for unlinked file references in QA

PIPELINE
  Stage 1   Analysis & Triage
  Stage 2   Report Rendering
  Stage 3   QA Review
  Stage 4   Architect Review (depth=thorough only, or --architect-review)

  No malformed threat-model.md is ever persisted. The skill either produces a
  contract-clean document or aborts with a structured repair plan.

See /appsec-advisor:status for plugin version and last-run info.
Full flag reference: docs/threat-model-skill.md
```

**Case 2 — any other arguments (or no arguments):**
Read `<base-dir>/SKILL-impl.md` in full (base-dir is on the `Base directory for this skill:` line in the invocation header), then follow all instructions in that file to run the assessment.
